//! Commit-specific policy: amendment and authorship/attribution overrides.
//!
//! Extracted from `args`/`block` so those modules stay focused and within
//! the 512-line cap. REQ-GGUARD-054 gates `--amend`; REQ-GGUARD-056 gates
//! argument-level authorship and author-date overrides for non-root.

use crate::args::ArgState;
use crate::GuardError;

/// Scan the tokens following a `commit` subcommand and record amendment
/// (`REQ-GGUARD-054`) and attribution overrides (`REQ-GGUARD-056`).
///
/// Commit-local `-c`/`-C` are the authorship-reuse options; the global
/// forms precede the subcommand and never reach this scanner, so position
/// disambiguates them byte-exactly.
pub fn scan_commit_args(tokens: &[&[u8]], state: &mut ArgState) {
    // REQ-GGUARD-030: consume the separate operands of value-taking options
    // (`-m`, `-c`, `--author`, ...) so a message value such as `--amend` is
    // not misread as a policy flag.
    for token in crate::args::scan::scan_tokens("commit", tokens) {
        let s = std::str::from_utf8(token).unwrap_or("");
        if s.starts_with("--amend") {
            state.has_amend = true;
        }
        if matches!(
            s,
            "--author" | "--reset-author" | "-C" | "-c" | "--reuse-message" | "--reedit-message"
        ) || s.starts_with("--author=")
            || s.starts_with("--reuse-message=")
            || s.starts_with("--reedit-message=")
        {
            state.has_author_override = true;
        }
        if s == "--date" || s.starts_with("--date=") {
            state.has_author_date_override = true;
        }
    }
}

/// Non-root commits may not amend, override/reuse authorship, or backdate
/// the author. Root proceeds through the normal contract checks.
pub fn check_commit_attribution(state: &ArgState, operator_root: bool) -> Result<(), GuardError> {
    if operator_root {
        return Ok(());
    }
    if state.has_amend {
        return Err(GuardError::Blocked {
            reason: "git commit --amend".into(),
            hint: "Amends rewrite history: agent commits are forward-only. Operators may amend via sudo.".into(),
        });
    }
    if state.has_author_override {
        return Err(GuardError::Blocked {
            reason: "git commit author override (--author/--reset-author/-C/-c/--reuse-message/--reedit-message)".into(),
            hint: "Commit authorship is fixed per user by the guard; do not override or reuse another author. Operators may use sudo.".into(),
        });
    }
    if state.has_author_date_override {
        return Err(GuardError::Blocked {
            reason: "git commit --date (author date override)".into(),
            hint: "Backdating commits is forbidden for non-root; omit --date or let the guard timestamp it. Operators may use sudo.".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "commit_tests.rs"]
mod tests;
