use crate::sanitize::ConfigSpan;
use crate::{GuardError, ABBREV_CANDIDATES, ABBREV_PREFERRED};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

#[derive(Debug, Clone)]
pub struct ArgState {
    pub subcommand: Option<String>,
    /// Raw subcommand token as typed (pre abbreviation resolution);
    /// sanitization matches this byte-exactly (REQ-GGUARD-043).
    pub subcommand_raw: Option<String>,
    pub has_amend: bool,
    /// Commit authorship is overridden or reused (`--author`,
    /// `--reset-author`, `-C`/`--reuse-message`, `-c`/`--reedit-message`).
    pub has_author_override: bool,
    /// Commit author date is overridden (`--date`). Enum-free: `--date`
    /// is not `--amend`, but it is still caller-supplied attribution.
    pub has_author_date_override: bool,
    pub has_force_flag: bool,
    pub has_force_with_lease_flag: bool,
    pub has_branch_d: bool,
    pub has_branch_force_rename: bool,
    pub safe_pull_flag: bool,
    pub has_rebase_safe_flag: bool,
    pub has_ff_only: bool,
    pub has_merge_abort: bool,
    pub has_cached: bool,
    pub has_delete_flag: bool,
    pub dangerous_config_keys: Vec<String>,
    /// Flagged config-option occurrences (flag and operand argv indexes)
    /// for the sanitizer to strip (REQ-GGUARD-044).
    pub config_spans: Vec<ConfigSpan>,
    /// Argv indexes of `-n`/`-N` tokens; blocked only when the resolved
    /// subcommand defines `-n` as `--no-verify` (REQ-GGUARD-030).
    pub no_verify_short_idxs: Vec<usize>,
    /// Leading global repository-location options (`-C`, `--git-dir`,
    /// `--work-tree`) in the exact tokens typed, so the ownership lock,
    /// toplevel resolution, workspace contract check, and real Git all
    /// target the same repository. Populated from this single parse
    /// (REQ-GGUARD-011); post-subcommand `-C` (commit message reuse) is
    /// never a location option.
    pub location_args: Vec<OsString>,
}

fn resolve_subcommand_abbreviation(raw: &str) -> String {
    let raw_lower = raw.to_lowercase();
    // ABBREV_CANDIDATES is sorted+deduped at build time, so all entries
    // with the given prefix form one contiguous range; partition_point
    // finds its start in O(log n).
    let start = ABBREV_CANDIDATES.partition_point(|c| *c < raw_lower.as_str());
    let range = &ABBREV_CANDIDATES[start..];
    let mut match_count = 0usize;
    let mut single_match = "";
    let mut preferred_count = 0usize;
    let mut preferred_match = "";
    for cand in range {
        if !cand.starts_with(&raw_lower) {
            break;
        }
        match_count += 1;
        single_match = cand;
        // Prefer porcelain (partial/sudo_gated) over plumbing (blocked)
        // when a prefix is ambiguous (e.g. "com" -> commit, not commit-tree).
        if ABBREV_PREFERRED.binary_search(cand).is_ok() {
            preferred_count += 1;
            preferred_match = cand;
        }
    }
    if match_count == 1 {
        return single_match.to_string();
    }
    if match_count > 1 && preferred_count == 1 {
        return preferred_match.to_string();
    }
    raw.to_string()
}

#[path = "args_scan.rs"]
pub(crate) mod scan;
use scan::{
    classify_leading_global, note_config_key, option_takes_operand, parse_config_key, scan_tokens,
    Leading,
};

pub fn parse_args(argv: &[&[u8]]) -> Result<ArgState, GuardError> {
    let mut state = ArgState {
        subcommand: None,
        subcommand_raw: None,
        has_amend: false,
        has_author_override: false,
        has_author_date_override: false,
        has_force_flag: false,
        has_force_with_lease_flag: false,
        has_branch_d: false,
        has_branch_force_rename: false,
        safe_pull_flag: false,
        has_rebase_safe_flag: false,
        has_ff_only: false,
        has_merge_abort: false,
        has_cached: false,
        has_delete_flag: false,
        dangerous_config_keys: Vec::new(),
        config_spans: Vec::new(),
        no_verify_short_idxs: Vec::new(),
        location_args: Vec::new(),
    };

    let mut past_separator = false;
    // Some(config flag argv index) while a separate `-c`/`--config-env`
    // payload is pending. Only meaningful before the subcommand: global
    // config options must precede the subcommand (REQ-GGUARD-031).
    let mut pending_config_flag: Option<usize> = None;
    let mut skip_operand = false;
    let mut i = 1;

    while i < argv.len() {
        let arg = argv[i];
        let arg_str = std::str::from_utf8(arg).unwrap_or("");

        if past_separator {
            break;
        }

        if arg == b"--" {
            past_separator = true;
            i += 1;
            continue;
        }

        if skip_operand {
            // The previous option consumed this token as its operand
            // (REQ-GGUARD-030): never classify a value as a policy flag.
            skip_operand = false;
            i += 1;
            continue;
        }

        if let Some(flag) = pending_config_flag {
            let key = parse_config_key(arg)?;
            note_config_key(&mut state, Some(flag), Some(i), &key);
            pending_config_flag = None;
            i += 1;
            continue;
        }

        // Global config options are parsed only before the subcommand;
        // afterward `-c`/`-C` are command-local (e.g. commit message reuse).
        if arg == b"-c" && state.subcommand.is_none() {
            pending_config_flag = Some(i);
            i += 1;
            continue;
        }

        if arg == b"-C" {
            // -C changes the working directory; it is never a config
            // option (REQ-GGUARD-011). Skip the directory operand. Only a
            // leading -C relocates the repository; after the subcommand it
            // is command-local (commit/tag message reuse) and excluded.
            if state.subcommand.is_none() {
                state.location_args.push(OsString::from_vec(arg.to_vec()));
                if let Some(v) = argv.get(i + 1) {
                    state.location_args.push(OsString::from_vec(v.to_vec()));
                }
            }
            i += 2;
            continue;
        }

        if state.subcommand.is_none()
            && arg.len() >= 3
            && arg[0] == b'-'
            && arg[1] == b'c'
            && arg[2] != b'\0'
        {
            let key = parse_config_key(&arg[2..])?;
            note_config_key(&mut state, Some(i), None, &key);
            i += 1;
            continue;
        }

        if arg.starts_with(b"--") {
            match arg_str {
                // REQ-GGUARD-030: no global "--hard" handling. It only means
                // something to `git reset`, which is an unconditionally
                // blocked subcommand; a bare `git --hard` is invalid syntax
                // that real Git rejects.
                "--no-verify" => {
                    return Err(GuardError::Blocked {
                        reason: "--no-verify flag".into(),
                        hint: "Remove --no-verify: hooks enforce policy".into(),
                    });
                }
                "--upload-pack" | "--receive-pack" | "--exec" => {
                    return Err(GuardError::Blocked {
                        reason: format!("dangerous flag: {}", arg_str),
                        hint: "Remove this flag: it enables arbitrary command execution".into(),
                    });
                }
                // `--config-env` is the real global option; the value is
                // `name=envvar`, so only the key before the first `=` is
                // retained. The nonstandard `--config`/`--config=` spellings
                // are no longer config options (REQ-GGUARD-031).
                "--config-env" if state.subcommand.is_none() => {
                    pending_config_flag = Some(i);
                    i += 1;
                    continue;
                }
                s if s.starts_with("--upload-pack=")
                    || s.starts_with("--receive-pack=")
                    || s.starts_with("--exec=") =>
                {
                    let flag_name = s.split('=').next().unwrap_or(s);
                    return Err(GuardError::Blocked {
                        reason: format!("dangerous flag: {}", flag_name),
                        hint: "Remove this flag: it enables arbitrary command execution".into(),
                    });
                }
                s if state.subcommand.is_none() && s.starts_with("--config-env=") => {
                    let key = parse_config_key(&s.as_bytes()["--config-env=".len()..])?;
                    note_config_key(&mut state, Some(i), None, &key);
                    i += 1;
                    continue;
                }
                _ => {}
            }
            // REQ-GGUARD-011: leading globals are resolved with an explicit
            // arity table before subcommand discovery. An option whose arity
            // is not known fails closed (exit 2); guessing could swallow a
            // later destructive subcommand name.
            if state.subcommand.is_none() {
                match classify_leading_global(arg, arg_str) {
                    Leading::Terminal => return Ok(state),
                    Leading::Modifier => {
                        if arg_str.starts_with("--git-dir=") || arg_str.starts_with("--work-tree=")
                        {
                            state.location_args.push(OsString::from_vec(arg.to_vec()));
                        }
                        i += 1;
                        continue;
                    }
                    Leading::Operand => {
                        if arg_str == "--git-dir" || arg_str == "--work-tree" {
                            state.location_args.push(OsString::from_vec(arg.to_vec()));
                            if let Some(v) = argv.get(i + 1) {
                                state.location_args.push(OsString::from_vec(v.to_vec()));
                            }
                        }
                        skip_operand = true;
                        i += 1;
                        continue;
                    }
                    Leading::Unknown => {
                        return Err(GuardError::InvalidInvocation(format!(
                            "unknown leading option: {}",
                            String::from_utf8_lossy(arg)
                        )));
                    }
                }
            }
            // REQ-GGUARD-030: consume the operand of a value-taking long
            // option (e.g. `--message`, `--author`) so a value such as
            // `--no-verify` is not misread as a policy flag. Dangerous
            // options were already rejected by the match above.
            if let Some(sub) = state.subcommand.as_deref() {
                if option_takes_operand(sub, arg_str) {
                    skip_operand = true;
                    i += 1;
                    continue;
                }
            }
            if arg_str == "--force" {
                state.has_force_flag = true;
            }
            // REQ-GGUARD-030: the bare and attached (`--force-with-lease=<ref>`)
            // spellings are the same destructive option; matching only the bare
            // form let the attached form evade the push block.
            if arg_str == "--force-with-lease" || arg_str.starts_with("--force-with-lease=") {
                state.has_force_with_lease_flag = true;
            }
            if arg_str.starts_with("--amend") {
                state.has_amend = true;
            }
            if arg_str.starts_with("--ff-only") || arg_str.starts_with("--rebase") {
                state.safe_pull_flag = true;
            }
            if arg_str == "--cached" {
                state.has_cached = true;
            }
            if arg_str == "--delete" {
                state.has_delete_flag = true;
            }
            i += 1;
            continue;
        }

        // REQ-GGUARD-011: short leading globals. `-c`/`-C` (attached or
        // separate) were consumed above; anything else is a known modifier
        // or terminal option, an attached `-C` directory, or fails closed.
        if state.subcommand.is_none() && arg.starts_with(b"-") && arg.len() > 1 {
            match classify_leading_global(arg, arg_str) {
                Leading::Terminal => return Ok(state),
                Leading::Modifier => {
                    // Attached directory form `-C<dir>` (the bare `-C` was
                    // consumed above); the directory is carried in the token.
                    if arg.len() > 2 && arg[1] == b'C' {
                        state.location_args.push(OsString::from_vec(arg.to_vec()));
                    }
                    i += 1;
                    continue;
                }
                Leading::Operand => {
                    skip_operand = true;
                    i += 1;
                    continue;
                }
                Leading::Unknown => {
                    return Err(GuardError::InvalidInvocation(format!(
                        "unknown leading option: {}",
                        String::from_utf8_lossy(arg)
                    )));
                }
            }
        }

        if arg.starts_with(b"-") && arg.len() > 1 {
            // `-x` is the short form of `rebase --exec`, which runs an
            // arbitrary command for each rewritten commit. Reject it for
            // rebase before any operand consumption so it cannot be hidden
            // behind the arity table.
            if state.subcommand.as_deref() == Some("rebase") && arg[1..].contains(&b'x') {
                return Err(GuardError::Blocked {
                    reason: "git rebase -x/--exec (runs an arbitrary command per commit)".into(),
                    hint: "Remove --exec/-x: it enables arbitrary command execution".into(),
                });
            }
            // REQ-GGUARD-030: a bundled short value-taker ending the token
            // (`-m`, `-am`) consumes the next token as its operand.
            if let Some(sub) = state.subcommand.as_deref() {
                if option_takes_operand(sub, arg_str) {
                    skip_operand = true;
                    i += 1;
                    continue;
                }
            }
            let flags = &arg[1..];
            for (idx, &ch) in flags.iter().enumerate() {
                match ch {
                    b'c' => {
                        // Config interpretation is disabled once the
                        // subcommand is known (REQ-GGUARD-031); the attached
                        // `-c<rest>` form was already handled above.
                        if state.subcommand.is_none() {
                            let remaining = &flags[idx + 1..];
                            if !remaining.is_empty() {
                                let key = parse_config_key(remaining)?;
                                note_config_key(&mut state, Some(i), None, &key);
                            } else {
                                pending_config_flag = Some(i);
                            }
                        }
                        break;
                    }
                    b'C' => break, // bundled -C: rest of the bundle is a directory path
                    b'f' => state.has_force_flag = true,
                    b'D' => state.has_branch_d = true,
                    b'M' => state.has_branch_force_rename = true,
                    b'd' => state.has_delete_flag = true,
                    b'n' | b'N' => {
                        // Blocked post-scan only where the command grammar
                        // defines -n as --no-verify (REQ-GGUARD-030).
                        state.no_verify_short_idxs.push(i);
                    }
                    _ => {}
                }
            }
            i += 1;
            continue;
        }

        if state.subcommand.is_none() && !arg_str.is_empty() && !arg_str.starts_with('-') {
            let resolved = resolve_subcommand_abbreviation(arg_str);
            state.subcommand = Some(resolved.clone());
            state.subcommand_raw = Some(arg_str.to_string());

            // Push's force/delete options are already classified by the main
            // option loop above (separator-aware and operand-aware), so the
            // former separate scan is gone (REQ-GGUARD-030).
            if resolved == "commit" {
                crate::commit::scan_commit_args(&argv[i + 1..], &mut state);
            }
            if resolved == "merge" {
                for &sarg in &scan_tokens("merge", &argv[i + 1..]) {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--ff-only" {
                        state.has_ff_only = true;
                    }
                    if s == "--abort" {
                        state.has_merge_abort = true;
                    }
                }
            }
            if resolved == "rebase" {
                for &sarg in &scan_tokens("rebase", &argv[i + 1..]) {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--continue" || s == "--abort" || s == "--skip" {
                        state.has_rebase_safe_flag = true;
                    }
                }
            }
        }

        i += 1;
    }

    // REQ-GGUARD-010: data after `--` is a pathspec or operand, never a
    // global option, so it is not re-scanned here. `git reset --hard` stays
    // blocked because `reset` is an unconditionally blocked subcommand, and
    // real Git remains the syntax authority for a bare `git --hard` or the
    // malformed `git -- --hard`.

    // REQ-GGUARD-030: `-n` is the `--no-verify` short alias only on the
    // subcommands whose grammar defines it (commit, am). Elsewhere it is
    // a different option (log -n <max-count>, push -n dry-run, tag -n,
    // revert/cherry-pick -n no-commit) and stays allowed. Category-
    // blocked subcommands keep the pinned -n block reason from the
    // attack surface matrix (the invocation is dead either way).
    let no_verify_sub = state
        .subcommand
        .as_deref()
        .map(|s| {
            crate::sanitize::NO_VERIFY_SHORT_SUBCOMMANDS.contains(&s)
                || crate::BLOCKED_SUBCOMMANDS.contains(&s)
        })
        .unwrap_or(false);
    if no_verify_sub && !state.no_verify_short_idxs.is_empty() {
        return Err(GuardError::Blocked {
            reason: "-n flag (short form of --no-verify)".into(),
            hint: "Remove -n: hooks enforce policy (commit/am)".into(),
        });
    }

    Ok(state)
}

/// The leading global options that change WHERE git locates the repository
/// (`-C <path>`, `-C<path>`, `--git-dir[=]`, `--work-tree[=]`), resolved by
/// the same parse that discovers the subcommand so the ownership lock,
/// toplevel resolution, workspace contract check, and real Git all target
/// the same repository (REQ-GGUARD-011). Post-subcommand `-C` is command
/// syntax (commit message reuse), not a location option, and is excluded.
pub fn repo_location_args(state: &ArgState) -> &[OsString] {
    &state.location_args
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "args_more_tests.rs"]
mod more_tests;
