use super::*;

#[test]
fn excerpt_marks_matching_line_with_context() {
    let body = b"line one\npkill x\nline three\n";
    let start = 9;
    let out = report::excerpt(body, start, start + 7, true);
    assert!(out.contains(">     2 | pkill x"), "got: {}", out);
    assert!(out.contains("    1 | line one"), "got: {}", out);
    assert!(out.contains("    3 | line three"), "got: {}", out);
}

#[test]
fn fd_path_classification() {
    assert!(shg_fd::is_fd_path("/proc/self/fd/3"));
    assert!(shg_fd::is_fd_path("/dev/fd/63"));
    assert!(shg_fd::is_fd_path("/dev/stdin"));
    assert!(!shg_fd::is_fd_path("/tmp/script.sh"));
    assert!(!shg_fd::is_fd_path("relative.sh"));
}

#[test]
fn staged_memfd_roundtrip_verifies_seals_and_rewinds() {
    let path = shg_fd::memfd_exec_path(b"echo hello\n");
    let body = shg_fd::read_staged_fd(&path).expect("staged memfd must verify");
    assert_eq!(body, b"echo hello\n");
}

#[test]
fn read_staged_fd_rejects_regular_paths_and_pipes() {
    assert!(shg_fd::read_staged_fd("/tmp").is_none());
    assert!(shg_fd::read_staged_fd("/proc/self/fd/0").is_none());
}

fn rules() -> Vec<Rule> {
    compile_rules()
}

#[test]
fn all_patterns_compile() {
    assert_eq!(rules().len(), shell_config::SHELL_PATTERNS.len());
    assert!(!shell_config::SHELL_PATTERNS.is_empty());
}

#[derive(serde::Deserialize)]
struct MatrixCase {
    id: String,
    input: String,
    expect: String,
    rule: Option<String>,
    #[serde(default = "default_matrix_ctx")]
    ctx: String,
}

fn default_matrix_ctx() -> String {
    "command".to_string()
}

#[derive(serde::Deserialize)]
struct Matrix {
    cases: Vec<MatrixCase>,
}

#[test]
fn policy_matrix_agrees() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let text = fs::read_to_string(format!(
        "{}/config/shell_guard_policy_matrix.yaml",
        manifest
    ))
    .expect("matrix yaml readable");
    let matrix: Matrix = serde_yaml::from_str(&text).expect("matrix yaml parses");
    assert!(!matrix.cases.is_empty());
    let rules = rules();
    for case in &matrix.cases {
        assert!(
            case.ctx == "command" || case.ctx == "script" || case.ctx == "untrusted-script",
            "case {}: bad ctx {:?}",
            case.id,
            case.ctx
        );
        let hit = report::find_hit(case.input.as_bytes(), &rules, &case.ctx);
        match case.expect.as_str() {
            "blocked" => {
                let rule =
                    hit.unwrap_or_else(|| panic!("case {}: expected block, got allow", case.id));
                if let Some(want) = &case.rule {
                    assert_eq!(&rule.rule.id, want, "case {}: wrong rule matched", case.id);
                }
            }
            "allowed" => {
                assert!(
                    hit.is_none(),
                    "case {}: expected allow, got block by {}",
                    case.id,
                    hit.unwrap().rule.id
                );
            }
            other => panic!("case {}: bad expect {:?}", case.id, other),
        }
    }
}

#[test]
fn every_pattern_has_a_blocked_case() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let text = fs::read_to_string(format!(
        "{}/config/shell_guard_policy_matrix.yaml",
        manifest
    ))
    .expect("matrix yaml readable");
    let matrix: Matrix = serde_yaml::from_str(&text).expect("matrix yaml parses");
    for (id, _, _, scope) in shell_config::SHELL_PATTERNS {
        assert!(
            matrix.cases.iter().any(|c| {
                c.expect == "blocked"
                    && c.rule.as_deref() == Some(*id)
                    && (*scope == "both" || *scope == c.ctx)
            }),
            "pattern {} has no blocked matrix case in a context its scope {:?} applies to",
            id,
            scope
        );
    }
}

#[test]
fn ids_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for (id, _, _, _) in shell_config::SHELL_PATTERNS {
        assert!(seen.insert(id), "duplicate pattern id {}", id);
    }
}

#[test]
fn scopes_are_valid() {
    for (id, _, _, scope) in shell_config::SHELL_PATTERNS {
        assert!(
            *scope == "command"
                || *scope == "script"
                || *scope == "untrusted-script"
                || *scope == "both",
            "pattern {} has invalid scope {:?}",
            id,
            scope
        );
    }
}

#[test]
fn command_scoped_rule_is_invisible_in_script_context() {
    let rule = Rule {
        id: "t-cmd-only",
        re: Regex::new(r"\bzz-probe\b").unwrap(),
        hint: "h",
        scope: "command",
    };
    let rules = vec![rule];
    assert!(report::find_hit(b"zz-probe x", &rules, "command").is_some());
    assert!(report::find_hit(b"zz-probe x", &rules, "script").is_none());
}

#[test]
fn script_scoped_rule_is_invisible_in_command_context() {
    let rule = Rule {
        id: "t-script-only",
        re: Regex::new(r"\bzz-probe\b").unwrap(),
        hint: "h",
        scope: "script",
    };
    let rules = vec![rule];
    assert!(report::find_hit(b"zz-probe x", &rules, "script").is_some());
    assert!(report::find_hit(b"zz-probe x", &rules, "command").is_none());
}

#[test]
fn both_scoped_rule_matches_everywhere() {
    let rule = Rule {
        id: "t-both",
        re: Regex::new(r"\bzz-probe\b").unwrap(),
        hint: "h",
        scope: "both",
    };
    let rules = vec![rule];
    assert!(report::find_hit(b"zz-probe x", &rules, "command").is_some());
    assert!(report::find_hit(b"zz-probe x", &rules, "script").is_some());
}

static ENVP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn envp_preserves_ami_prefix_and_resets_path() {
    let _g = ENVP_LOCK.lock().unwrap();
    std::env::set_var("AMI_QUIET_MODE", "1");
    std::env::set_var("_CI_CAPS_SCRUBBED", "1");
    std::env::set_var("SHG_TEST_STRIP_ME", "x");
    std::env::set_var("SHG_SCRIPT_PATH", "/tmp/spoofed");
    let envp = build_envp(None);
    std::env::remove_var("AMI_QUIET_MODE");
    std::env::remove_var("_CI_CAPS_SCRUBBED");
    std::env::remove_var("SHG_TEST_STRIP_ME");
    std::env::remove_var("SHG_SCRIPT_PATH");
    let flat: Vec<String> = envp
        .iter()
        .map(|c| c.to_string_lossy().to_string())
        .collect();
    assert!(
        flat.iter().any(|e| e == "AMI_QUIET_MODE=1"),
        "AMI_* must survive the guard env allow-list (banner quiet mode): {:?}",
        flat
    );
    assert!(
        flat.iter().any(|e| e == "_CI_CAPS_SCRUBBED=1"),
        "_CI_* must survive the guard env allow-list (hook cap-scrub sentinel, \
         else the pre-commit re-exec loops): {:?}",
        flat
    );
    assert!(
        !flat.iter().any(|e| e.starts_with("SHG_TEST_STRIP_ME=")),
        "unlisted vars must be stripped"
    );
    assert!(
        flat.iter().any(|e| e == &format!("PATH={}", RESET_PATH)),
        "PATH must be reset"
    );
    assert!(
        !flat.iter().any(|e| e.starts_with("SHG_SCRIPT_PATH=")),
        "caller-supplied SHG_SCRIPT_PATH must be dropped (only the guard sets it)"
    );
}

#[test]
fn envp_injects_staged_script_path() {
    let envp = build_envp(Some(Path::new("/repo/scripts/tool.sh")));
    let flat: Vec<String> = envp
        .iter()
        .map(|c| c.to_string_lossy().to_string())
        .collect();
    assert!(
        flat.iter()
            .any(|e| e == "SHG_SCRIPT_PATH=/repo/scripts/tool.sh"),
        "staged scripts must learn their original path: {:?}",
        flat
    );
}

#[test]
fn sanitize_redacts_assignments() {
    assert_eq!(
        report::sanitize_cmd(b"FOO=secret make test"),
        "FOO=... make test"
    );
    assert_eq!(report::sanitize_cmd(b"echo A=1"), "echo A=...");
}

#[test]
fn sanitize_truncates_and_replaces_quotes() {
    let long = vec![b'x'; 500];
    assert_eq!(report::sanitize_cmd(&long).chars().count(), 200);
    assert_eq!(report::sanitize_cmd(b"it's"), "it\u{2019}s");
}

#[test]
fn tmpdir_checks() {
    assert!(!tmpdir_ok(&OsString::from("relative")));
    assert!(!tmpdir_ok(&OsString::from("/nonexistent-dir-xyz")));
}

#[test]
fn parents_of_tmp_are_not_root_locked() {
    let dir = std::env::temp_dir().join(format!("shg-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let f = dir.join("x.sh");
    fs::write(&f, b"echo hi\n").unwrap();
    assert!(!parents_root_locked_or_anchored(&f));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn tmpdir_is_not_immutable() {
    let dir = std::env::temp_dir().join(format!("shg-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    assert!(!dir_is_immutable(&dir));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn system_paths_pass_anchored_check() {
    if Path::new("/etc/hostname").exists() {
        assert!(parents_root_locked_or_anchored(Path::new("/etc/hostname")));
    }
}
