//! Parser helpers for the git-guard argument scanner (REQ-GGUARD-030,
//! REQ-GGUARD-031, REQ-GGUARD-041, REQ-GGUARD-011).

use super::{ArgState, ConfigSpan};
use crate::{is_config_key_blocked, GuardError};

/// Split a config-option payload on its first `=` and return the exact
/// pre-`=` key bytes. Everything after the first `=` is an opaque value
/// that is never retained. A payload with no `=` is an implicit-true key
/// (both `-c key` and `-ckey`), so the attached form cannot evade policy by
/// omitting the `=` (REQ-GGUARD-041). An empty, non-ASCII, or non-UTF-8 key
/// is a malformed invocation (exit 2) before any subcommand runs; keys are
/// never lossily converted to an empty string. Case folding happens only in
/// the matcher, so the retained key (audit evidence) is byte-exact.
pub(super) fn parse_config_key(payload: &[u8]) -> Result<String, GuardError> {
    let key = match payload.iter().position(|&b| b == b'=') {
        Some(eq) => &payload[..eq],
        None => payload,
    };
    if key.is_empty() {
        return Err(GuardError::InvalidInvocation(
            "config option has an empty key".into(),
        ));
    }
    if !key.is_ascii() {
        return Err(GuardError::InvalidInvocation(
            "config option key is not ASCII".into(),
        ));
    }
    Ok(std::str::from_utf8(key)
        .expect("ASCII is valid UTF-8")
        .to_string())
}

/// Record a blocked config key and, when the originating option token is
/// known, the span covering it for later stripping. `operand_idx` is set
/// for the separate-operand forms (`-c key=value`, `--config-env key=env`).
/// Only normalized keys are retained; values and `--config-env` variable
/// names never enter parser state (REQ-GGUARD-031).
pub(super) fn note_config_key(
    state: &mut ArgState,
    flag_idx: Option<usize>,
    operand_idx: Option<usize>,
    key: &str,
) {
    if !is_config_key_blocked(key, crate::is_config_privileged()) {
        return;
    }
    state.dangerous_config_keys.push(key.to_string());
    if let Some(f) = flag_idx {
        match state.config_spans.iter_mut().find(|s| s.flag_idx == f) {
            Some(span) => span.keys.push(key.to_string()),
            None => state.config_spans.push(ConfigSpan {
                flag_idx: f,
                operand_idx,
                keys: vec![key.to_string()],
            }),
        }
    }
}

/// True when `token` takes a separate following operand in the grammar of
/// `sub`, so its operand must be consumed instead of classified as a policy
/// flag (REQ-GGUARD-030). Values carried inside the token (`-mMSG`,
/// `--message=MSG`) are never separate operands. This is the minimal
/// command-specific arity knowledge the scanner needs; real Git stays the
/// syntax authority for everything else.
pub(crate) fn option_takes_operand(sub: &str, token: &str) -> bool {
    if token.contains('=') {
        return false;
    }
    let message_sub = matches!(sub, "commit" | "tag" | "merge" | "cherry-pick" | "revert");
    match token {
        // `git branch -m/--move <newname>` and `-c/--copy <old> <new>` take a
        // name operand, which may itself begin with `-` (REQ-GGUARD-030).
        "-m" | "--move" | "-c" | "--copy" if sub == "branch" => true,
        "-m" | "--message" | "-F" | "--file" => message_sub,
        "--author" | "--date" | "--cleanup" | "--template" | "--trailer" | "--fixup"
        | "--squash" | "--reuse-message" | "--reedit-message" | "-C" | "-c" => sub == "commit",
        "--strategy" | "--strategy-option" | "-s" | "-X" => sub == "merge",
        "--mainline" => matches!(sub, "cherry-pick" | "revert"),
        "--push-option" | "-o" => sub == "push",
        "--onto" | "--exec" | "-x" => sub == "rebase",
        _ => {
            // Bundled short options whose value-taker is the final character,
            // e.g. `-am` (commit -a -m <msg>). A value-taker followed by more
            // characters carries its value inside the token.
            if let Some(body) = token.strip_prefix('-') {
                if !body.starts_with('-') && !body.is_empty() {
                    if let Some(pos) = body.find(['m', 'F']) {
                        return pos == body.len() - 1 && message_sub;
                    }
                }
            }
            false
        }
    }
}

/// The tokens after a subcommand, stopping at `--`, with the separate
/// operands of value-taking options removed (REQ-GGUARD-030). Option tokens
/// themselves are yielded so callers can still classify them.
pub(crate) fn scan_tokens<'a>(sub: &str, tokens: &'a [&'a [u8]]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut skip = false;
    for &token in tokens {
        if skip {
            skip = false;
            continue;
        }
        let s = std::str::from_utf8(token).unwrap_or("");
        if s == "--" {
            break;
        }
        if option_takes_operand(sub, s) {
            skip = true;
        }
        out.push(token);
    }
    out
}

/// Classification of a leading (pre-subcommand) global option (REQ-GGUARD-011).
pub(super) enum Leading {
    /// Terminal query option: stop scanning, leave no subcommand.
    Terminal,
    /// Known option that takes no operand.
    Modifier,
    /// Known option that consumes the following token as its operand.
    Operand,
    /// Unknown arity: fail closed.
    Unknown,
}

/// Classify a leading global option before subcommand discovery. The table
/// covers the pinned Git global options; real grammar changes require a
/// policy update rather than guessing.
pub(super) fn classify_leading_global(arg: &[u8], arg_str: &str) -> Leading {
    match arg_str {
        "--version" | "-v" | "--help" | "-h" | "--html-path" | "--man-path" | "--info-path"
        | "--exec-path" => return Leading::Terminal,
        "-p"
        | "--paginate"
        | "-P"
        | "--no-pager"
        | "--bare"
        | "--no-replace-objects"
        | "--literal-pathspecs"
        | "--glob-pathspecs"
        | "--noglob-pathspecs"
        | "--icase-pathspecs"
        | "--no-optional-locks"
        | "--no-advice" => return Leading::Modifier,
        // `--shallow-file <path>` is a hidden Git global option that
        // fetch-pack passes to the index-pack helper it spawns
        // (`git --shallow-file <file> index-pack ...`). It takes the
        // following token as its operand, so the same arity rule as the
        // other value-taking location options applies.
        "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix" | "--shallow-file" => {
            return Leading::Operand
        }
        s if s.starts_with("--git-dir=")
            || s.starts_with("--work-tree=")
            || s.starts_with("--namespace=")
            || s.starts_with("--super-prefix=")
            || s.starts_with("--attr-source=")
            || s.starts_with("--list-cmds=")
            || s.starts_with("--shallow-file=") =>
        {
            return Leading::Modifier
        }
        _ => {}
    }
    if arg.starts_with(b"-") && arg.len() > 1 {
        let body = &arg[1..];
        if body.iter().all(|&b| b == b'h' || b == b'v') {
            return Leading::Terminal;
        }
        if let Some(pos) = body.iter().position(|&b| b == b'C') {
            return if pos == body.len() - 1 {
                Leading::Operand
            } else {
                Leading::Modifier
            };
        }
        if body.iter().all(|&b| b == b'p' || b == b'P') {
            return Leading::Modifier;
        }
    }
    Leading::Unknown
}
