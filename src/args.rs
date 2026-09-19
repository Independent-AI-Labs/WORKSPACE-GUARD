use crate::sanitize::ConfigSpan;
use crate::{is_config_key_blocked, GuardError, ABBREV_CANDIDATES, ABBREV_PREFERRED};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

#[derive(Debug, Clone)]
pub struct ArgState {
    pub subcommand: Option<String>,
    /// Raw subcommand token as typed (pre abbreviation resolution);
    /// sanitization matches this byte-exactly (REQ-GGUARD-043).
    pub subcommand_raw: Option<String>,
    pub has_amend: bool,
    pub has_force_flag: bool,
    pub has_force_with_lease_flag: bool,
    pub has_branch_d: bool,
    pub has_branch_force_rename: bool,
    pub has_stash_drop: bool,
    pub has_stash_clear: bool,
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

/// Record a blocked config key and, when the originating option token is
/// known, the span covering it for later stripping. `operand_idx` is set
/// for the separate-operand forms (`-c key=value`, `--config key=value`).
fn note_config_key(
    state: &mut ArgState,
    flag_idx: Option<usize>,
    operand_idx: Option<usize>,
    key: &str,
) {
    if key.is_empty() {
        return;
    }
    if !is_config_key_blocked(key, crate::is_config_privileged()) {
        return;
    }
    state.dangerous_config_keys.push(key.to_string());
    if let Some(f) = flag_idx {
        let post = state.subcommand_raw.is_some();
        match state.config_spans.iter_mut().find(|s| s.flag_idx == f) {
            Some(span) => span.keys.push(key.to_string()),
            None => state.config_spans.push(ConfigSpan {
                flag_idx: f,
                operand_idx,
                keys: vec![key.to_string()],
                post_subcommand: post,
            }),
        }
    }
}

pub fn check_null_bytes(argv: &[&[u8]]) -> Result<(), GuardError> {
    for arg in argv {
        if arg.contains(&0u8) {
            return Err(GuardError::NullByteInArg);
        }
    }
    Ok(())
}

pub fn parse_args(argv: &[&[u8]]) -> Result<ArgState, GuardError> {
    let mut state = ArgState {
        subcommand: None,
        subcommand_raw: None,
        has_amend: false,
        has_force_flag: false,
        has_force_with_lease_flag: false,
        has_branch_d: false,
        has_branch_force_rename: false,
        has_stash_drop: false,
        has_stash_clear: false,
        safe_pull_flag: false,
        has_rebase_safe_flag: false,
        has_ff_only: false,
        has_merge_abort: false,
        has_cached: false,
        has_delete_flag: false,
        dangerous_config_keys: Vec::new(),
        config_spans: Vec::new(),
        no_verify_short_idxs: Vec::new(),
    };

    let mut past_separator = false;
    let mut expecting_config = false;
    let mut pending_config_flag: Option<usize> = None;
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

        if expecting_config {
            if let Some(pos) = arg_str.find('=') {
                note_config_key(
                    &mut state,
                    pending_config_flag,
                    Some(i),
                    arg_str[..pos].trim(),
                );
            } else {
                note_config_key(&mut state, pending_config_flag, Some(i), arg_str.trim());
            }
            expecting_config = false;
            pending_config_flag = None;
            i += 1;
            continue;
        }

        if arg == b"-c" {
            expecting_config = true;
            pending_config_flag = Some(i);
            i += 1;
            continue;
        }

        if arg == b"-C" {
            // -C changes the working directory; it is never a config
            // option (REQ-GGUARD-011). Skip the directory operand.
            i += 2;
            continue;
        }

        if arg.len() >= 3 && arg[0] == b'-' && arg[1] == b'c' && arg[2] != b'\0' {
            let rest = &arg[2..];
            if let Ok(rest_str) = std::str::from_utf8(rest) {
                if let Some(eq_pos) = rest_str.find('=') {
                    note_config_key(&mut state, Some(i), None, rest_str[..eq_pos].trim());
                } else {
                    note_config_key(&mut state, Some(i), None, rest_str.trim());
                }
            }
            i += 1;
            continue;
        }

        if arg.starts_with(b"--") {
            match arg_str {
                "--hard" => {
                    return Err(GuardError::Blocked {
                        reason: "--hard flag".into(),
                        hint: "Remove --hard from the command".into(),
                    });
                }
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
                "--config" => {
                    expecting_config = true;
                    pending_config_flag = Some(i);
                    i += 1;
                    continue;
                }
                "--config-env" => {
                    expecting_config = true;
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
                s if s.starts_with("--config=") => {
                    let val = &s["--config=".len()..];
                    if let Some(eq) = val.find('=') {
                        note_config_key(&mut state, Some(i), None, val[..eq].trim());
                    }
                    i += 1;
                    continue;
                }
                s if s.starts_with("--config-env=") => {
                    let val = &s["--config-env=".len()..];
                    if let Some(eq) = val.find('=') {
                        note_config_key(&mut state, Some(i), None, val[..eq].trim());
                    }
                    i += 1;
                    continue;
                }
                _ => {}
            }
            if arg_str == "--force" {
                state.has_force_flag = true;
            }
            if arg_str == "--force-with-lease" {
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
            if arg_str.contains('=') && arg_str.starts_with("--") {
                let eq_pos = arg_str.find('=').unwrap();
                let flag_key = &arg_str[2..eq_pos];
                if flag_key == "c" {
                    let val = &arg_str[eq_pos + 1..];
                    if let Some(val_eq) = val.find('=') {
                        note_config_key(&mut state, Some(i), None, val[..val_eq].trim());
                    }
                }
            }
            i += 1;
            continue;
        }

        if arg.starts_with(b"-") && arg.len() > 1 {
            let flags = &arg[1..];
            for (idx, &ch) in flags.iter().enumerate() {
                match ch {
                    b'c' => {
                        let remaining = &flags[idx + 1..];
                        if !remaining.is_empty() {
                            if let Ok(rest_str) = std::str::from_utf8(remaining) {
                                if let Some(eq_pos) = rest_str.find('=') {
                                    note_config_key(
                                        &mut state,
                                        Some(i),
                                        None,
                                        rest_str[..eq_pos].trim(),
                                    );
                                }
                            }
                        } else {
                            expecting_config = true;
                            pending_config_flag = Some(i);
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

            if resolved == "stash" {
                let mut past_dash = false;
                for &sarg in &argv[i + 1..] {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--" {
                        past_dash = true;
                        continue;
                    }
                    if past_dash {
                        continue;
                    }
                    if s == "drop" {
                        state.has_stash_drop = true;
                    }
                    if s == "clear" {
                        state.has_stash_clear = true;
                    }
                }
            }
            if resolved == "push" {
                let mut past_dash = false;
                for &sarg in &argv[i + 1..] {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--" {
                        past_dash = true;
                        continue;
                    }
                    if past_dash {
                        continue;
                    }
                    if s == "--force" || s == "-f" {
                        state.has_force_flag = true;
                    }
                    if s == "--force-with-lease" {
                        state.has_force_with_lease_flag = true;
                    }
                    if s == "--delete" || s == "-d" {
                        state.has_delete_flag = true;
                    }
                }
            }
            if resolved == "commit" {
                let mut past_dash = false;
                for &sarg in &argv[i + 1..] {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--" {
                        past_dash = true;
                        continue;
                    }
                    if past_dash {
                        continue;
                    }
                    if s.starts_with("--amend") {
                        state.has_amend = true;
                    }
                }
            }
            if resolved == "merge" {
                let mut past_dash = false;
                for &sarg in &argv[i + 1..] {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--" {
                        past_dash = true;
                        continue;
                    }
                    if past_dash {
                        continue;
                    }
                    if s == "--ff-only" {
                        state.has_ff_only = true;
                    }
                    if s == "--abort" {
                        state.has_merge_abort = true;
                    }
                }
            }
            if resolved == "rebase" {
                let mut past_dash = false;
                for &sarg in &argv[i + 1..] {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--" {
                        past_dash = true;
                        continue;
                    }
                    if past_dash {
                        continue;
                    }
                    if s == "--continue" || s == "--abort" || s == "--skip" {
                        state.has_rebase_safe_flag = true;
                    }
                }
            }
        }

        i += 1;
    }

    // --hard must never pass, including after `--` (pathspec bypass).
    for arg in argv.iter().skip(1) {
        if arg == b"--hard" {
            return Err(GuardError::Blocked {
                reason: "--hard flag".into(),
                hint: "Remove --hard from the command".into(),
            });
        }
    }

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

/// Extract the leading global options that change WHERE git locates the
/// repository (-C <path>, --git-dir, --work-tree) so the lock resolves the
/// same git dir the real git child will operate on. Without this, a call
/// like `git -C /other/repo status` would lock the repo under the guard's
/// own cwd (or none) instead of the target repo (observed: post-exec
/// relock was a no-op for every `-C` invocation, errors discarded).
pub fn repo_location_args(argv_os: &[OsString]) -> Vec<OsString> {
    let mut out = Vec::new();
    let mut it = argv_os.iter().skip(1);
    while let Some(a) = it.next() {
        let bytes = a.as_bytes();
        if bytes == b"-C" || bytes == b"--git-dir" || bytes == b"--work-tree" {
            if let Some(v) = it.next() {
                out.push(a.clone());
                out.push(v.clone());
            }
        } else if bytes.starts_with(b"--git-dir=") || bytes.starts_with(b"--work-tree=") {
            out.push(a.clone());
        }
    }
    out
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
