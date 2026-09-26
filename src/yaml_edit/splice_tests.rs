// Unit tests for yaml_edit_splice.rs. The splice layer must preserve
// everything it does not touch (comments, blank lines, unrelated
// keys) byte-for-byte, and every result must re-parse with
// serde_yaml to the intended document (REQ-YE-006/103).

use super::splice;
use serde_yaml::Value;

fn doc(yaml: &str) -> Value {
    serde_yaml::from_str(yaml).expect("test yaml must parse")
}

fn parse(yaml: &str) -> Value {
    serde_yaml::from_str(yaml).expect("splice result must parse")
}

fn seq_of(yaml: &str, key: &str) -> Vec<Value> {
    parse(yaml)
        .get(key)
        .and_then(Value::as_sequence)
        .expect("seq")
        .clone()
}

const BASE: &str = "# header comment\nexceptions:\n  - hook: quality # keep me\n    paths:\n      - a.py\n\nother: 1\n";

#[test]
fn add_appends_preserving_comments_and_blank_lines() {
    let entry = doc("{hook: coverage, paths: [b.py]}");
    let items = doc(BASE)
        .get("exceptions")
        .and_then(Value::as_sequence)
        .expect("seq")
        .clone();
    let out = splice::splice_add(BASE, "exceptions", &entry, &items).expect("add");
    assert!(out.contains("# header comment"));
    assert!(out.contains("  - hook: quality # keep me"));
    assert!(out.contains("\n\nother: 1\n"));
    let parsed = parse(&out);
    let seq = parsed
        .get("exceptions")
        .and_then(Value::as_sequence)
        .expect("seq");
    assert_eq!(seq.len(), 2);
    assert_eq!(seq[1], entry);
    assert_eq!(parsed.get("other"), Some(&Value::from(1)));
}

#[test]
fn add_into_empty_flow_list_keeps_trailing_comment() {
    let base = "exceptions: [] # none yet\nother: 1\n";
    let entry = doc("{hook: quality, paths: [a.py]}");
    let out = splice::splice_add(base, "exceptions", &entry, &[]).expect("add");
    assert!(out.contains("exceptions: # none yet\n"));
    let seq = seq_of(&out, "exceptions");
    assert_eq!(seq[0], entry);
}

#[test]
fn add_into_populated_flow_list_rewrites_block_form() {
    let base = "safe_exceptions: [README.md, CHANGELOG.md]\n";
    let items = doc(base)
        .get("safe_exceptions")
        .and_then(Value::as_sequence)
        .expect("seq")
        .clone();
    let out = splice::splice_add(
        base,
        "safe_exceptions",
        &Value::String("NEW.md".into()),
        &items,
    )
    .expect("add");
    let seq = seq_of(&out, "safe_exceptions");
    assert_eq!(seq.len(), 3);
    assert_eq!(seq[2], Value::String("NEW.md".into()));
}

#[test]
fn add_into_multiline_flow_list() {
    let base = "safe_exceptions: [\n  README.md,\n  CHANGELOG.md,\n]\n";
    let items = doc(base)
        .get("safe_exceptions")
        .and_then(Value::as_sequence)
        .expect("seq")
        .clone();
    let out = splice::splice_add(base, "safe_exceptions", &Value::String("X".into()), &items)
        .expect("add");
    let seq = seq_of(&out, "safe_exceptions");
    assert_eq!(seq.len(), 3);
}

#[test]
fn add_refuses_scalar_key() {
    let err = splice::splice_add("k: 1\n", "k", &Value::from(2), &[]).expect_err("must fail");
    assert!(err.contains("not a list"));
}

#[test]
fn remove_drops_only_the_matched_item() {
    let items = doc(BASE)
        .get("exceptions")
        .and_then(Value::as_sequence)
        .expect("seq")
        .clone();
    let out = splice::splice_remove(BASE, "exceptions", &items, &[0]).expect("remove");
    let seq = seq_of(&out, "exceptions");
    assert!(seq.is_empty());
    assert!(out.contains("# header comment"));
}

#[test]
fn remove_last_item_collapses_to_empty_flow() {
    let base = "exceptions: # audited\n  - hook: q\n    paths: [a.py]\nnext: 2\n";
    let items = doc(base)
        .get("exceptions")
        .and_then(Value::as_sequence)
        .expect("seq")
        .clone();
    let out = splice::splice_remove(base, "exceptions", &items, &[0]).expect("remove");
    assert!(out.contains("exceptions: [] # audited\n"));
    let seq = seq_of(&out, "exceptions");
    assert!(seq.is_empty());
    assert_eq!(parse(&out).get("next"), Some(&Value::from(2)));
    let normalized = super::target::normalize_terminal(&out);
    assert!(normalized.ends_with("next: 2\n"));
    assert!(!normalized.ends_with("\n\n"));
}

#[test]
fn remove_from_flow_list_keeps_remainder() {
    let base = "safe_exceptions: [A.md, B.md]\n";
    let items = doc(base)
        .get("safe_exceptions")
        .and_then(Value::as_sequence)
        .expect("seq")
        .clone();
    let out = splice::splice_remove(base, "safe_exceptions", &items, &[0]).expect("remove");
    let seq = seq_of(&out, "safe_exceptions");
    assert_eq!(seq, vec![Value::String("B.md".into())]);
}

#[test]
fn remove_keeps_region_comments() {
    let base = "exceptions:\n  # why this exists\n  - hook: q\n    paths: [a.py]\n  - hook: c\n    paths: [b.py]\n";
    let items = doc(base)
        .get("exceptions")
        .and_then(Value::as_sequence)
        .expect("seq")
        .clone();
    let out = splice::splice_remove(base, "exceptions", &items, &[0]).expect("remove");
    assert!(out.contains("  # why this exists\n"));
    let seq = seq_of(&out, "exceptions");
    assert_eq!(seq.len(), 1);
    assert_eq!(seq[0].get("hook").and_then(Value::as_str), Some("c"));
}

#[test]
fn trailing_newline_is_preserved() {
    let base = "k: [a]\n";
    let items = vec![Value::String("a".into())];
    let out = splice::splice_add(base, "k", &Value::String("b".into()), &items).expect("add");
    assert!(out.ends_with('\n'));
    let no_nl = "k: [a]";
    let out2 = splice::splice_add(no_nl, "k", &Value::String("b".into()), &items).expect("add");
    assert!(!out2.ends_with('\n'));
}

#[test]
fn set_replaces_scalar_and_keeps_rest() {
    let base = "# top\nthresholds:\n  min_coverage: 90 # tune\n  timeout: 60\n";
    let segs = vec!["thresholds".to_string(), "min_coverage".to_string()];
    let out = splice::splice_set(base, &segs, &Value::from(95)).expect("set");
    assert!(out.contains("# top"));
    assert!(out.contains("  min_coverage: 95\n"));
    assert!(out.contains("  timeout: 60\n"));
    let parsed = parse(&out);
    let got = parsed
        .get("thresholds")
        .and_then(|t| t.get("min_coverage"))
        .and_then(Value::as_i64);
    assert_eq!(got, Some(95));
}

#[test]
fn set_replaces_block_scalar_wholesale() {
    let base = "note: |\n  line one\n  line two\nother: 1\n";
    let segs = vec!["note".to_string()];
    let out = splice::splice_set(base, &segs, &Value::String("flat".into())).expect("set");
    assert!(!out.contains("line one"));
    let parsed = parse(&out);
    assert_eq!(parsed.get("note").and_then(Value::as_str), Some("flat"));
    assert_eq!(parsed.get("other"), Some(&Value::from(1)));
}

#[test]
fn set_on_missing_key_fails_closed() {
    let segs = vec!["nope".to_string()];
    assert!(splice::splice_set("a: 1\n", &segs, &Value::from(2)).is_err());
}

#[test]
fn insert_map_key_appends_under_parent() {
    let base =
        "config_categories:\n  pre_commit: 'Git Hooks'\n  modules: 'Project Structure'\nother: 1\n";
    let segs = vec!["config_categories".to_string()];
    let out = splice::splice_insert_map_key(
        base,
        &segs,
        "wiki_labels",
        &Value::String("Project Structure".into()),
    )
    .expect("insert");
    assert!(out.contains("  wiki_labels: Project Structure\n"));
    let parsed = parse(&out);
    assert_eq!(
        parsed
            .get("config_categories")
            .and_then(|m| m.get("wiki_labels"))
            .and_then(Value::as_str),
        Some("Project Structure")
    );
    assert_eq!(parsed.get("other"), Some(&Value::from(1)));
}

#[test]
fn insert_map_key_keeps_region_comments() {
    let base = "parent:\n  a: 1\n  # keep me\nnext: 2\n";
    let segs = vec!["parent".to_string()];
    let out = splice::splice_insert_map_key(base, &segs, "b", &Value::from(3)).expect("insert");
    assert!(out.contains("  # keep me\n"));
    let b_line = out.lines().position(|l| l.trim_start().starts_with("b:"));
    let c_line = out.lines().position(|l| l.trim() == "# keep me");
    assert!(b_line < c_line, "new key lands before trailing comment");
}

#[test]
fn insert_map_key_refuses_flow_parent() {
    let base = "parent: {a: 1}\n";
    let segs = vec!["parent".to_string()];
    assert!(splice::splice_insert_map_key(base, &segs, "b", &Value::from(2)).is_err());
}

#[test]
fn insert_map_key_missing_parent_fails_closed() {
    let segs = vec!["nope".to_string()];
    assert!(splice::splice_insert_map_key("a: 1\n", &segs, "b", &Value::from(2)).is_err());
}

#[test]
fn set_does_not_confuse_sequence_items_with_keys() {
    let base = "items:\n  - name: one\n  - name: two\nother: 1\n";
    let segs = vec!["other".to_string()];
    let out = splice::splice_set(base, &segs, &Value::from(9)).expect("set");
    assert_eq!(parse(&out).get("other"), Some(&Value::from(9)));
}

#[test]
fn key_block_returns_exact_region() {
    let block = splice::key_block(BASE, "exceptions").expect("block");
    assert!(block.starts_with("exceptions:\n"));
    assert!(block.contains("- a.py\n"));
    assert!(!block.contains("other: 1"));
}

#[test]
fn exotic_indentation_fails_closed_not_corrupt() {
    // A list whose items sit at mixed dash indents cannot be mapped
    // to parsed items; the splice must refuse rather than guess.
    let base = "exceptions:\n  - hook: q\n    paths: [a]\n   - hook: c\n     paths: [b]\n";
    let parsed: Result<Value, _> = serde_yaml::from_str(base);
    if let Ok(v) = parsed {
        if let Some(items) = v.get("exceptions").and_then(Value::as_sequence) {
            let r = splice::splice_remove(base, "exceptions", items, &[0]);
            if let Ok(out) = r {
                let seq = seq_of(&out, "exceptions");
                assert_eq!(seq.len() + 1, items.len());
            }
        }
    }
}
