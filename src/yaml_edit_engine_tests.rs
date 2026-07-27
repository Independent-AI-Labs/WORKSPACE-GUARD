// Unit tests for yaml_edit_engine.rs: spec grammar, matching, and
// dotted-key resolution. Each test names the audit finding it
// regresses where one applies.

use super::yaml_edit_engine as engine;
use super::yaml_edit_engine::Spec;
use serde_yaml::Value;

fn sv(s: &str) -> Value {
    Value::String(s.to_string())
}

#[test]
fn scalar_value_is_literal_commas_included() {
    // Audit 2: the awk tool split values on commas; a path with a
    // comma must survive as one scalar.
    let spec = engine::parse_spec("reason=add src/a,b.py").expect("spec");
    match spec {
        Spec::Scalar { value, .. } => assert_eq!(value, sv("add src/a,b.py")),
        other => panic!("expected scalar, got {other:?}"),
    }
}

#[test]
fn list_items_parse_and_type() {
    let spec = engine::parse_spec("paths=[src/a.py,src/b.py]").expect("spec");
    match spec {
        Spec::List { items, .. } => assert_eq!(items, vec![sv("src/a.py"), sv("src/b.py")]),
        other => panic!("expected list, got {other:?}"),
    }
}

#[test]
fn single_element_list_stays_a_list() {
    // Audit 6: emitting [x] as a scalar broke list consumers.
    let spec = engine::parse_spec("paths=[src/a.py]").expect("spec");
    match &spec {
        Spec::List { items, .. } => assert_eq!(items, &vec![sv("src/a.py")]),
        other => panic!("expected list, got {other:?}"),
    }
    let entry = engine::entry_from_specs(&[spec]).expect("entry");
    assert!(matches!(entry.get("paths"), Some(Value::Sequence(_))));
}

#[test]
fn empty_list_is_allowed_for_named_fields() {
    let spec = engine::parse_spec("paths=[]").expect("spec");
    assert!(matches!(spec, Spec::List { items, .. } if items.is_empty()));
}

#[test]
fn empty_and_duplicate_items_rejected() {
    // Audit 31: empty items became match-everything entries.
    assert!(engine::parse_spec("paths=[a,,b]").is_err());
    assert!(engine::parse_spec("paths=[,a]").is_err());
    assert!(engine::parse_spec("paths=[a,a]").is_err());
}

#[test]
fn malformed_brackets_rejected() {
    assert!(engine::parse_spec("paths=[a,b").is_err());
    assert!(engine::parse_spec("paths=a,b]").is_err());
}

#[test]
fn bad_field_names_rejected() {
    assert!(engine::parse_spec("bad name=x").is_err());
    assert!(engine::parse_spec("=x").is_err());
}

#[test]
fn scalar_typing_numbers_bools_strings() {
    // Audit 4: values parse as YAML scalars so numbers stay numeric.
    match engine::parse_spec("timeout=120").expect("spec") {
        Spec::Scalar { value, .. } => assert_eq!(value, Value::from(120)),
        other => panic!("expected scalar, got {other:?}"),
    }
    match engine::parse_spec("pattern=eval").expect("spec") {
        Spec::Scalar { value, .. } => assert_eq!(value, sv("eval")),
        other => panic!("expected scalar, got {other:?}"),
    }
}

#[test]
fn empty_and_structured_values_rejected() {
    // Audit 4/31: no null scalars, no smuggled mappings/sequences.
    assert!(engine::parse_spec("reason=").is_err());
    assert!(engine::parse_spec("reason={a: b}").is_err());
}

#[test]
fn bare_spec_for_scalar_lists() {
    let specs = engine::parse_specs(&["README.md".to_string()]).expect("specs");
    let entry = engine::entry_from_specs(&specs).expect("entry");
    assert_eq!(entry, sv("README.md"));
}

#[test]
fn mixing_bare_with_named_fields_rejected() {
    assert!(engine::entry_from_specs(&[
        engine::parse_spec("bare").expect("spec"),
        engine::parse_spec("name=x").expect("spec"),
    ])
    .is_err());
}

#[test]
fn matching_is_semantic_not_textual() {
    // Audit 1: the CI consumer iterated a string as chars; matching
    // must compare parsed structures, not substrings.
    let entry: Value = serde_yaml::from_str("{hook: quality, paths: [b.py, a.py]}").expect("parse");
    let specs = engine::parse_specs(&["hook=quality".to_string(), "paths=[a.py,b.py]".to_string()])
        .expect("specs");
    assert!(engine::specs_match_entry(&entry, &specs));
}

#[test]
fn matching_rejects_subset_and_type_mismatch() {
    let entry: Value =
        serde_yaml::from_str("{hook: quality, paths: [a.py, b.py, c.py]}").expect("parse");
    let specs = engine::parse_specs(&["paths=[a.py,b.py]".to_string()]).expect("specs");
    assert!(!engine::specs_match_entry(&entry, &specs));
    let scalar: Value = serde_yaml::from_str("{paths: a.py}").expect("parse");
    assert!(!engine::specs_match_entry(&scalar, &specs));
}

#[test]
fn bare_matching_compares_typed_values() {
    let specs = engine::parse_specs(&["120".to_string()]).expect("specs");
    assert!(engine::specs_match_entry(&Value::from(120), &specs));
    assert!(!engine::specs_match_entry(&sv("120x"), &specs));
}

#[test]
fn list_items_distinguishes_errors() {
    let doc: Value = serde_yaml::from_str("exceptions: []\nscalar: 1\n").expect("parse");
    assert!(engine::list_items(&doc, "exceptions").is_ok());
    assert_eq!(
        engine::list_items(&doc, "missing"),
        Err(engine::KeyError::Missing)
    );
    assert_eq!(
        engine::list_items(&doc, "scalar"),
        Err(engine::KeyError::NotAList)
    );
    assert_eq!(
        engine::list_items(&Value::from(1), "exceptions"),
        Err(engine::KeyError::NotAMap)
    );
}

#[test]
fn dotted_keys_resolve_literal_first() {
    let doc: Value = serde_yaml::from_str("a.b: 1\na:\n  b: 2\n").expect("parse");
    let segs = engine::resolve_segments(&doc, "a.b").expect("segments");
    assert_eq!(segs, vec!["a.b".to_string()]);
    let v = engine::scalar_at(&doc, &segs).expect("scalar");
    assert_eq!(v, &Value::from(1));
}

#[test]
fn dotted_keys_resolve_nested() {
    let doc: Value = serde_yaml::from_str("outer:\n  inner: 7\n").expect("parse");
    let segs = engine::resolve_segments(&doc, "outer.inner").expect("segments");
    assert_eq!(segs, vec!["outer".to_string(), "inner".to_string()]);
    assert!(engine::resolve_segments(&doc, "outer.nope").is_none());
    assert!(engine::resolve_segments(&doc, "").is_none());
}

#[test]
fn set_typed_value_rules() {
    assert_eq!(
        engine::typed_value("95", false).expect("value"),
        Value::from(95)
    );
    assert_eq!(engine::typed_value("95", true).expect("value"), sv("95"));
    assert!(engine::typed_value("", true).is_err());
    assert!(engine::typed_value(" x", true).is_err());
    assert!(engine::typed_value("a\nb", false).is_err());
}
