use super::*;

const INLINE: &str = concat!("python", " -c");

fn rule(id: &'static str, pattern: &str, category: &'static str) -> Rule {
    Rule {
        id,
        re: Regex::new(pattern).unwrap(),
        hint: "hint",
        category,
        contexts: "file",
        mask: true,
        exemptible: true,
        mode: "block",
        reason: "reason",
    }
}

fn construct(
    language: &'static str,
    open: Option<&str>,
    close: Option<&str>,
    pattern: Option<&str>,
    category: Option<&'static str>,
) -> Construct {
    Construct {
        language,
        level: 1,
        open: open.map(compile_anchor),
        close: close.map(compile_anchor),
        pattern: pattern.map(compile_anchor),
        category,
    }
}

#[test]
fn reports_rule_identity_and_position() {
    let rules = vec![rule("interp", INLINE, "interp")];
    let text = format!("first\n{} pass\n", INLINE);
    let findings = scan_with("a.py", &text, "python", &rules, &[]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, "interp");
    assert_eq!(findings[0].line, 2);
    assert_eq!(findings[0].column, 1);
}

#[test]
fn masks_markdown_region() {
    let rules = vec![rule("interp", INLINE, "interp")];
    let constructs = vec![construct(
        "markdown",
        Some(r"^[ \t]{0,3}```"),
        Some(r"^[ \t]{0,3}```"),
        None,
        None,
    )];
    let text = format!("prose\n```\n{} pass\n```\n", INLINE);
    let findings = scan_with("a.md", &text, "markdown", &rules, &constructs);
    assert!(findings.is_empty());
}

#[test]
fn masks_markdown_inline_span() {
    let rules = vec![rule("interp", INLINE, "interp")];
    let constructs = vec![construct("markdown", None, None, Some(r"`[^`\n]+`"), None)];
    let text = format!("use `{}` in prose\n", INLINE);
    let findings = scan_with("a.md", &text, "markdown", &rules, &constructs);
    assert!(findings.is_empty());
}

#[test]
fn category_construct_excludes_only_its_category() {
    let rules = vec![
        rule("sql", "select", "sql"),
        rule("interp", INLINE, "interp"),
    ];
    let constructs = vec![construct("sql", None, None, None, Some("sql"))];
    let text = format!("select 1\n{} pass\n", INLINE);
    let findings = scan_with("a.sql", &text, "sql", &rules, &constructs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, "interp");
}

#[test]
fn normalized_view_removes_zero_width() {
    let rules = vec![rule("interp", INLINE, "interp")];
    let text = "python\u{200b} -c pass\n".to_string();
    let findings = scan_with_depth("a.txt", &text, "text", &rules, &[], 0);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].view, "normalized");
}

#[test]
fn decoded_hex_view_matches() {
    let rules = vec![rule("sql", "select from", "sql")];
    let findings = scan_with_depth("a.txt", "73656c6563742066726f6d", "text", &rules, &[], 2);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].view, "decoded");
}

#[test]
fn normalized_percent_escape_matches() {
    let rules = vec![rule("sql", "select from", "sql")];
    let text = "%73%65%6c%65%63%74%20%66%72%6f%6d";
    let findings = scan_with_depth("a.txt", text, "text", &rules, &[], 2);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].view, "normalized");
}

#[test]
fn scanner_rejects_schema_mismatch() {
    let raw = r#"{"schema":9,"files":[]}"#;
    assert!(process_request(raw).is_err());
}

#[test]
fn scanner_accepts_empty_batch() {
    let raw = r#"{"schema":1,"files":[]}"#;
    let response = process_request(raw).expect("empty batch");
    assert!(response.findings.expect("findings").is_empty());
}

#[test]
fn scanner_rejects_nul_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nul.txt");
    std::fs::write(&path, b"a\0b").expect("write");
    let raw = serde_json::json!({
        "schema": 1,
        "files": [{"path": path.to_string_lossy(), "language": "text"}],
    })
    .to_string();
    let error = process_request(&raw).expect_err("NUL must fail");
    assert!(error.contains("NUL"));
}

#[test]
fn scanner_rejects_invalid_utf8() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bad.txt");
    std::fs::write(&path, [0xff, 0xfe]).expect("write");
    let raw = serde_json::json!({
        "schema": 1,
        "files": [{"path": path.to_string_lossy(), "language": "text"}],
    })
    .to_string();
    let error = process_request(&raw).expect_err("invalid UTF-8 must fail");
    assert!(error.contains("UTF-8"));
}

#[test]
fn views_schema_returns_raw_and_normalized_views() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("payload.txt");
    std::fs::write(&path, "plain").expect("write");
    let raw = serde_json::json!({
        "schema": 2,
        "decode_depth": 0,
        "files": [{"path": path.to_string_lossy(), "language": "text"}],
    })
    .to_string();
    let response = process_request(&raw).expect("views scan");
    let files = response.files.expect("views");
    assert_eq!(files.len(), 1);
    let names: Vec<&str> = files[0]
        .views
        .iter()
        .map(|view| view.name.as_str())
        .collect();
    assert_eq!(names, ["raw", "normalized"]);
    assert_eq!(files[0].views[0].text, "plain");
    assert_eq!(files[0].views[0].offsets, [0, 1, 2, 3, 4]);
}

#[test]
fn views_schema_decodes_encoded_payload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("payload.txt");
    std::fs::write(&path, "73656c6563742066726f6d").expect("write");
    let raw = serde_json::json!({
        "schema": 2,
        "decode_depth": 2,
        "files": [{"path": path.to_string_lossy(), "language": "text"}],
    })
    .to_string();
    let response = process_request(&raw).expect("views scan");
    let files = response.files.expect("views");
    assert!(files[0]
        .views
        .iter()
        .any(|view| view.name == "decoded" && view.text == "select from"));
}
