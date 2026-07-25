use crate::guard_config::{DANGEROUS_CONFIG_KEY_SEGMENTS, SUDO_GATED_CONFIG_KEY_SEGMENTS};

pub fn is_dangerous_config_key(key: &str) -> bool {
    let key_lower = key.trim().to_lowercase();
    let segments: Vec<&str> = key_lower.split('.').collect();

    DANGEROUS_CONFIG_KEY_SEGMENTS
        .iter()
        .any(|pat| glob_match_segments(&segments, pat))
}

pub fn is_config_key_blocked(key: &str, sudo: bool) -> bool {
    if is_dangerous_config_key(key) {
        return true;
    }
    if sudo {
        return false;
    }
    let key_lower = key.trim().to_lowercase();
    let segments: Vec<&str> = key_lower.split('.').collect();
    SUDO_GATED_CONFIG_KEY_SEGMENTS
        .iter()
        .any(|pat| glob_match_segments(&segments, pat))
}

/// Glob match on pre-split, pre-lowercased pattern segments. `*` matches
/// exactly one segment; `**` matches zero or more. Patterns are compiled
/// at build time (see build.rs emit_seg_list) and build.rs rejects any
/// pattern with more than one `**`, so this recursive matcher stays linear
/// in practice and allocates nothing.
fn glob_match_segments(segs: &[&str], pats: &[&str]) -> bool {
    if pats.is_empty() {
        return segs.is_empty();
    }
    if pats[0] == "**" {
        for skip in 0..=segs.len() {
            if glob_match_segments(&segs[skip..], &pats[1..]) {
                return true;
            }
        }
        return false;
    }
    if segs.is_empty() {
        return false;
    }
    if pats[0] == "*" || pats[0] == segs[0] {
        return glob_match_segments(&segs[1..], &pats[1..]);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{is_config_key_blocked, is_dangerous_config_key};

    #[test]
    fn exact_match_lowercase() {
        assert!(is_dangerous_config_key("core.hookspath"));
    }

    #[test]
    fn exact_match_case_insensitive() {
        assert!(is_dangerous_config_key("core.HooksPath"));
        assert!(is_dangerous_config_key("CORE.HOOKSPATH"));
    }

    #[test]
    fn exact_match_not_dangerous() {
        assert!(!is_dangerous_config_key("core.safepath"));
        assert!(!is_dangerous_config_key("user.signingkey2"));
    }

    #[test]
    fn wildcard_single_segment_filter_clean() {
        assert!(is_dangerous_config_key("filter.lfs.clean"));
        assert!(is_dangerous_config_key("filter.myfilter.clean"));
    }

    #[test]
    fn wildcard_single_segment_filter_smudge() {
        assert!(is_dangerous_config_key("filter.lfs.smudge"));
        assert!(is_dangerous_config_key("filter.anyname.smudge"));
    }

    #[test]
    fn wildcard_single_segment_alias() {
        assert!(is_dangerous_config_key("alias.push"));
        assert!(is_dangerous_config_key("alias.commit"));
        assert!(is_dangerous_config_key("alias.x"));
    }

    #[test]
    fn wildcard_single_segment_protocol_allow() {
        assert!(is_dangerous_config_key("protocol.file.allow"));
        assert!(is_dangerous_config_key("protocol.git.allow"));
        assert!(is_dangerous_config_key("protocol.ext.allow"));
    }

    #[test]
    fn wildcard_single_segment_url_insteadof() {
        assert!(is_dangerous_config_key("url.https://evil.com.insteadof"));
        assert!(is_dangerous_config_key("url.ssh://evil.insteadof"));
    }

    #[test]
    fn wildcard_single_segment_credential_helper() {
        assert!(is_dangerous_config_key("credential.helper"));
        assert!(is_dangerous_config_key(
            "credential.https://evil.com.helper"
        ));
    }

    #[test]
    fn wildcard_single_segment_gpg_program() {
        assert!(is_dangerous_config_key("gpg.program"));
        assert!(is_dangerous_config_key("gpg.ssh.program"));
        assert!(is_dangerous_config_key("gpg.openpgp.program"));
    }

    #[test]
    fn wildcard_segment_count_mismatch() {
        assert!(!is_dangerous_config_key("filter.clean"));
        assert!(!is_dangerous_config_key("alias"));
        assert!(!is_dangerous_config_key("protocol.allow.extra"));
    }

    #[test]
    fn trim_whitespace() {
        assert!(is_dangerous_config_key(" core.hookspath "));
        assert!(is_config_key_blocked("\tcore.editor\t", false));
        assert!(!is_config_key_blocked("\tcore.editor\t", true));
    }

    #[test]
    fn exact_match_without_wildcard_differing_segment() {
        assert!(!is_dangerous_config_key("filter.xyz.other"));
    }

    #[test]
    fn all_dangerous_keys_covered() {
        let test_keys = &[
            ("core.hookspath", true),
            ("core.sshcommand", true),
            ("core.editor", false),
            ("core.excludesfile", true),
            ("core.pager", true),
            ("core.askpass", true),
            ("core.fsmonitor", true),
            ("core.alternaterefscommand", true),
            ("core.gitproxy", true),
            ("diff.external", true),
            ("gpg.program", true),
            ("gpg.ssh.program", true),
            ("protocol.allow", true),
            ("protocol.ext.allow", true),
            ("protocol.file.allow", true),
            ("safe.directory", true),
            ("include.path", true),
            ("includeif.gitdir.path", true),
            ("alias.st", true),
            ("url.https://evil.insteadof", true),
            ("credential.helper", true),
            ("credential.https://foo.helper", true),
            ("http.proxy", true),
            ("https.proxy", true),
            ("http.sslverify", true),
            ("http.sslcainfo", true),
            ("http.sslcert", true),
            ("http.sslkey", true),
            ("http.sslcertpasswordprotected", true),
            ("http.extraheader", true),
            ("http.cookiefile", true),
            ("filter.lfs.clean", true),
            ("filter.lfs.smudge", true),
            ("diff.binary.textconv", true),
            ("diff.binary.cachetextconv", true),
            ("difftool.vimdiff.cmd", true),
            ("mergetool.vimdiff.cmd", true),
            ("mergetool.vimdiff.trustexitcode", true),
            ("browser.firefox.cmd", true),
            ("remote.origin.proxy", true),
            ("remote.origin.promisor", true),
            ("remote.origin.uploadpack", true),
            ("remote.origin.receivepack", true),
            ("submodule.mylib.url", true),
            ("submodule.mylib.update", true),
            ("submodule.recurse", true),
            ("commit.gpgsign", true),
            ("commit.template", true),
            ("commit.cleanup", true),
            ("rebase.autosquash", true),
            ("rebase.autostash", true),
            ("rebase.instructionformat", true),
            ("receive.denycurrentbranch", true),
            ("receive.denynonfastforwards", true),
            ("receive.denydeletes", true),
            ("receive.hiderefs", true),
            ("uploadpack.hiderefs", true),
            ("uploadpack.allowreachablesha1inwant", true),
            ("uploadpack.allowanysha1inwant", true),
            ("fetch.fsckobjects", true),
            ("transfer.fsckobjects", true),
            ("receive.fsckobjects", true),
            ("fetch.prune", true),
            ("clone.rejectshallow", true),
            ("push.default", true),
            ("push.followtags", true),
            ("push.gpgsign", true),
            ("merge.ff", true),
            ("merge.verifysignatures", true),
            ("pull.ff", true),
            ("pull.rebase", true),
            ("user.email", false),
            ("user.name", false),
            ("user.signingkey", false),
            ("format.signoff", true),
            ("sequence.editor", false),
            ("sendemail.smtpserver", true),
            ("help.autocorrect", true),
            ("safe.config", false),
        ];

        for (key, expected) in test_keys {
            assert_eq!(
                is_dangerous_config_key(key),
                *expected,
                "key='{}' expected={}",
                key,
                expected
            );
        }
    }

    #[test]
    fn sudo_gated_keys_blocked_only_for_non_root() {
        let gated = &[
            "core.editor",
            "sequence.editor",
            "user.email",
            "user.name",
            "user.signingkey",
        ];
        for &key in gated {
            assert!(
                is_config_key_blocked(key, false),
                "non-sudo should block {}",
                key
            );
            assert!(
                !is_config_key_blocked(key, true),
                "sudo should allow {}",
                key
            );
        }
        assert!(is_config_key_blocked("CORE.EDITOR", false));
        assert!(is_config_key_blocked("User.Name", false));
        assert!(is_config_key_blocked("core.hookspath", true));
        assert!(is_config_key_blocked("core.hookspath", false));
        assert!(!is_config_key_blocked("core.bare", false));
        assert!(!is_config_key_blocked("core.bare", true));
    }
}
