// Unit tests for yaml_edit_emit.rs. Every case asserts the emitted
// token re-parses (serde_yaml) to exactly the original Value, so a
// YAML 1.1 consumer downstream can never see a different type
// (audit findings 6, 14, 31).

use super::emit::{emit_dash_item, emit_kv, render_scalar};
use serde_yaml::Value;

fn roundtrip(v: &Value) {
    let token = render_scalar(v);
    let back: Value = serde_yaml::from_str(&token).expect("emitted token must parse");
    assert_eq!(&back, v, "token {token:?} must round-trip");
}

#[test]
fn plain_strings_stay_plain() {
    roundtrip(&Value::String("lib/check_banned_words.py".to_string()));
    roundtrip(&Value::String("workspace-guard".to_string()));
}

#[test]
fn yaml11_booleans_get_quoted() {
    for s in [
        "yes", "no", "on", "off", "y", "n", "true", "false", "Yes", "ON",
    ] {
        let v = Value::String(s.to_string());
        let token = render_scalar(&v);
        assert!(token.starts_with('\''), "{s} must be quoted, got {token}");
        roundtrip(&v);
    }
}

#[test]
fn null_like_strings_get_quoted() {
    for s in ["null", "~", "Null", ""] {
        roundtrip(&Value::String(s.to_string()));
    }
}

#[test]
fn numeric_strings_get_quoted() {
    for s in [
        "42", "-7", "3.14", "0x1f", "1e5", ".inf", ".nan", "1:30", "1_000",
    ] {
        let v = Value::String(s.to_string());
        let token = render_scalar(&v);
        assert!(token.starts_with('\''), "{s} must be quoted, got {token}");
        roundtrip(&v);
    }
}

#[test]
fn timestamp_strings_get_quoted() {
    for s in [
        "2026-09-07",
        "2001-12-15",
        "2026-09-07T10:30:00Z",
        "2026-09-07 10:30:00",
        "2026-09-07t10:30:00.5+02:00",
        "2026-9-7",
    ] {
        let v = Value::String(s.to_string());
        let token = render_scalar(&v);
        assert!(token.starts_with('\''), "{s} must be quoted, got {token}");
        roundtrip(&v);
    }
    for not_ts in ["2026-09-07x", "123-45-67"] {
        let v = Value::String(not_ts.to_string());
        roundtrip(&v);
    }
}

#[test]
fn indicator_strings_get_quoted() {
    for s in [
        "- dash", "[x]", "#hash", "a: b", "a # b", "key:", "*star", " lead", "trail ",
    ] {
        roundtrip(&Value::String(s.to_string()));
    }
}

#[test]
fn real_numbers_and_bools_stay_plain() {
    roundtrip(&Value::from(42));
    roundtrip(&Value::from(3.5));
    roundtrip(&Value::Bool(true));
    roundtrip(&Value::Bool(false));
}

#[test]
fn single_quotes_double_up() {
    roundtrip(&Value::String("it's".to_string()));
    roundtrip(&Value::String("''".to_string()));
}

#[test]
fn emit_kv_scalar() {
    let lines = emit_kv("min_coverage", &Value::from(95), 0);
    assert_eq!(lines, vec!["min_coverage: 95"]);
    let doc: Value = serde_yaml::from_str(&lines.join("\n")).expect("parse");
    assert_eq!(doc.get("min_coverage").and_then(Value::as_i64), Some(95));
}

#[test]
fn emit_kv_list_stays_a_list_with_one_item() {
    let items = Value::Sequence(vec![Value::String("only".to_string())]);
    let lines = emit_kv("paths", &items, 2);
    let doc: Value = serde_yaml::from_str(&lines.join("\n")).expect("parse");
    assert_eq!(doc.get("paths"), Some(&items));
}

#[test]
fn emit_kv_nested_mapping() {
    let inner: Value = serde_yaml::from_str("{version: 2, min_coverage: 95}").expect("parse");
    let lines = emit_kv("coverage_thresholds", &inner, 0);
    let doc: Value = serde_yaml::from_str(&lines.join("\n")).expect("parse");
    assert_eq!(doc.get("coverage_thresholds"), Some(&inner));
}

#[test]
fn emit_dash_item_mapping_first_pair_on_dash_line() {
    let entry: Value = serde_yaml::from_str("{hook: quality, reason: 'x'}").expect("parse");
    let lines = emit_dash_item(&entry, 2);
    assert_eq!(lines[0], "  - hook: quality");
    let doc: Value = serde_yaml::from_str(&format!("k:\n{}", lines.join("\n"))).expect("parse");
    let items = doc.get("k").and_then(Value::as_sequence).expect("seq");
    assert_eq!(items[0], entry);
}

#[test]
fn emit_dash_item_scalar() {
    let lines = emit_dash_item(&Value::String("yes".to_string()), 4);
    assert_eq!(lines, vec!["    - 'yes'"]);
}
