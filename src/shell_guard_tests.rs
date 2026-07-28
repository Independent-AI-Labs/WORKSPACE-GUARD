use super::*;

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
        let hit = scan(case.input.as_bytes(), &rules);
        match case.expect.as_str() {
            "blocked" => {
                let rule =
                    hit.unwrap_or_else(|| panic!("case {}: expected block, got allow", case.id));
                if let Some(want) = &case.rule {
                    assert_eq!(&rule.id, want, "case {}: wrong rule matched", case.id);
                }
            }
            "allowed" => {
                assert!(
                    hit.is_none(),
                    "case {}: expected allow, got block by {}",
                    case.id,
                    hit.unwrap().id
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
    for (id, _, _) in shell_config::SHELL_PATTERNS {
        assert!(
            matrix
                .cases
                .iter()
                .any(|c| c.expect == "blocked" && c.rule.as_deref() == Some(*id)),
            "pattern {} has no blocked matrix case",
            id
        );
    }
}

#[test]
fn ids_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for (id, _, _) in shell_config::SHELL_PATTERNS {
        assert!(seen.insert(id), "duplicate pattern id {}", id);
    }
}

#[test]
fn sanitize_redacts_assignments() {
    assert_eq!(sanitize_cmd(b"FOO=secret make test"), "FOO=... make test");
    assert_eq!(sanitize_cmd(b"echo A=1"), "echo A=...");
}

#[test]
fn sanitize_truncates_and_replaces_quotes() {
    let long = vec![b'x'; 500];
    assert_eq!(sanitize_cmd(&long).chars().count(), 200);
    assert_eq!(sanitize_cmd(b"it's"), "it\u{2019}s");
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
    assert!(!parents_root_locked(&f));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn system_paths_are_root_locked() {
    if Path::new("/etc/hostname").exists() {
        assert!(parents_root_locked(Path::new("/etc/hostname")));
    }
}
