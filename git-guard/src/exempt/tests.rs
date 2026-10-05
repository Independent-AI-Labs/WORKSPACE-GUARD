use super::*;

#[test]
fn parse_paths_collects_entries_and_stops_at_next_key() {
    let doc = "version: 1\nexemptions:\n  - path: /a/b\n    reason: x\n    added_by: op\n  - path: /c\n    reason: y\n    added_by: op\nother: 1\n  - path: /nope\n";
    assert_eq!(parse_paths(doc), vec!["/a/b".to_string(), "/c".to_string()]);
}

#[test]
fn parse_paths_indentless_sequence() {
    let doc = "exemptions:\n- path: /x\n- path: /y\n";
    assert_eq!(parse_paths(doc), vec!["/x".to_string(), "/y".to_string()]);
}

#[test]
fn parse_paths_bare_dash_then_path() {
    let doc = "exemptions:\n  -\n    path: /x\n";
    assert_eq!(parse_paths(doc), vec!["/x".to_string()]);
}

#[test]
fn parse_paths_empty_and_quoted() {
    assert!(parse_paths("version: 1\nexemptions: []\n").is_empty());
    assert_eq!(
        parse_paths("exemptions:\n  - path: \"/x y\"\n"),
        vec!["/x y".to_string()]
    );
    assert_eq!(
        parse_paths("exemptions:\n  - path: /x # note\n"),
        vec!["/x".to_string()]
    );
}

#[test]
fn parse_paths_never_reads_reason_as_path() {
    let doc = "exemptions:\n  - reason: /fake\n    added_by: op\n  - path: /real\n    reason: r\n";
    assert_eq!(parse_paths(doc), vec!["/real".to_string()]);
}

#[test]
fn path_matches_is_component_wise() {
    assert!(path_matches(Path::new("/w/proj/sub"), Path::new("/w/proj")));
    assert!(path_matches(Path::new("/w/proj"), Path::new("/w/proj")));
    assert!(!path_matches(Path::new("/w/proj2"), Path::new("/w/proj")));
    assert!(!path_matches(Path::new("/w"), Path::new("/w/proj")));
}

#[test]
fn untrusted_registry_grants_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let reg = dir.path().join("exempt-projects.yaml");
    std::fs::write(&reg, "exemptions:\n  - path: /x\n").unwrap();
    assert!(!registry_trusted(&reg));
}

#[test]
fn absent_registry_grants_nothing() {
    assert!(exempt_match("/tmp/does-not-exist-8b4c").is_none());
}
