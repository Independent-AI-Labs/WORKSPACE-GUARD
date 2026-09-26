//! Multi-call normalisation tests: `git-foo` argv must be rewritten to the
//! `git foo` dispatcher form so policy applies and real git resolves it.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

use super::normalize_multicall;

fn os(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

#[test]
fn plain_git_is_unchanged() {
    let input = os(&["/usr/bin/git", "commit", "-m", "x"]);
    assert_eq!(normalize_multicall(&input), input);
}

#[test]
fn multicall_helper_gets_subcommand_inserted() {
    let got = normalize_multicall(&os(&["/usr/lib/git-core/git-upload-pack", "repo"]));
    assert_eq!(
        got,
        os(&["/usr/lib/git-core/git-upload-pack", "upload-pack", "repo"])
    );
}

#[test]
fn relative_multicall_name_is_normalised() {
    let got = normalize_multicall(&os(&["git-receive-pack", "repo"]));
    assert_eq!(got, os(&["git-receive-pack", "receive-pack", "repo"]));
}

#[test]
fn real_git_original_is_not_multicall() {
    let input = os(&["/usr/bin/git.original", "status"]);
    assert_eq!(normalize_multicall(&input), input);
}

#[test]
fn bare_or_trailing_dash_is_unchanged() {
    assert_eq!(normalize_multicall(&os(&["git-"])), os(&["git-"]));
}

#[test]
fn multicall_commit_amend_maps_to_amend_policy() {
    let argv = normalize_multicall(&os(&["/usr/lib/git-core/git-commit", "--amend", "-F", "m"]));
    let bytes: Vec<&[u8]> = argv.iter().map(|a| a.as_bytes()).collect();
    let state = crate::args::parse_args(&bytes).expect("parse");
    assert_eq!(state.subcommand.as_deref(), Some("commit"));
    assert!(
        state.has_amend,
        "git-commit --amend must preserve amend state"
    );
}

#[test]
fn multicall_empty_repo_arg_does_not_panic() {
    let got = normalize_multicall(&os(&["git-", ""]));
    assert_eq!(got, os(&["git-", ""]));
}
