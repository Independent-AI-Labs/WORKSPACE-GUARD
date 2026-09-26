// Tests for yaml_edit_shape.rs: indentless-sequence detection and the
// canonicalizing reindent. The indentless fixture reproduces the
// 2026-09-06 incident shape (Python yaml.safe_dump output) that made
// every list edit fail with "expected N entries, found none".

use crate::shape::{indentless_lists, reindent};

const INDENTLESS: &str = concat!(
    "# header comment\n",
    "exceptions:\n",
    "- rule: bsilent\n",
    "  path: ^lib/a\\.py$\n",
    "  rationale: quoted data\n",
    "- rule: bmock-b\n",
    "  path: ^tests/x\\.py$\n",
    "# between items comment\n",
    "- rule: bu2014\n",
    "  path: ^AGENTS\\.md$\n",
    "version: 2\n",
);

const CANONICAL: &str = concat!(
    "# header comment\n",
    "exceptions:\n",
    "  - rule: bsilent\n",
    "    path: ^lib/a\\.py$\n",
    "    rationale: quoted data\n",
    "  - rule: bmock-b\n",
    "    path: ^tests/x\\.py$\n",
    "# between items comment\n",
    "  - rule: bu2014\n",
    "    path: ^AGENTS\\.md$\n",
    "version: 2\n",
);

const ALREADY_INDENTED: &str = concat!(
    "version: 1\n",
    "hooks:\n",
    "  - id: a\n",
    "    kind: shell\n",
    "  - id: b\n",
    "    kind: shell\n",
);

const FLOW_LIST: &str = concat!(
    "version: 1\n",
    "stages: [pre-commit, commit-msg]\n",
    "hooks: []\n"
);

#[test]
fn detects_indentless_top_level_list() {
    let v = indentless_lists(INDENTLESS);
    assert_eq!(v.len(), 1, "violations: {v:?}");
    assert_eq!(v[0].key, "exceptions");
    assert_eq!(v[0].line, 3);
    assert_eq!(v[0].key_indent, 0);
    assert_eq!(v[0].dash_indent, 0);
}

#[test]
fn message_names_key_line_and_fix() {
    let v = indentless_lists(INDENTLESS);
    let msg = v[0].message("/x/y.yaml");
    assert!(msg.contains("key 'exceptions'"), "{msg}");
    assert!(msg.contains("line 3"), "{msg}");
    assert!(msg.contains("format"), "{msg}");
}

#[test]
fn indented_document_has_no_violations() {
    let v = indentless_lists(ALREADY_INDENTED);
    assert!(v.is_empty(), "violations: {v:?}");
}

#[test]
fn flow_lists_never_violate() {
    assert!(indentless_lists(FLOW_LIST).is_empty());
}

#[test]
fn reports_every_offending_key() {
    let raw = "a:\n- 1\n- 2\nb:\n  nested: ok\nc:\n- x\n";
    let v = indentless_lists(raw);
    let keys: Vec<&str> = v.iter().map(|x| x.key.as_str()).collect();
    assert_eq!(keys, ["a", "c"]);
}

#[test]
fn reindent_produces_canonical_form() {
    assert_eq!(
        reindent(INDENTLESS).expect("transform ok"),
        Some(CANONICAL.to_string())
    );
}

#[test]
fn reindent_is_idempotent() {
    let once = reindent(INDENTLESS).expect("first pass").expect("changed");
    assert_eq!(reindent(&once).expect("second pass"), None);
}

#[test]
fn reindent_preserves_semantics() {
    let once = reindent(INDENTLESS).expect("pass").expect("changed");
    let before: serde_yaml::Value = serde_yaml::from_str(INDENTLESS).expect("parse");
    let after: serde_yaml::Value = serde_yaml::from_str(&once).expect("reparse");
    assert_eq!(before, after);
}

#[test]
fn reindent_keeps_comments_and_trailing_newline() {
    let once = reindent(INDENTLESS).expect("pass").expect("changed");
    assert!(once.starts_with("# header comment\n"));
    assert!(once.contains("# between items comment\n"));
    assert!(once.ends_with("version: 2\n"));
}

#[test]
fn reindent_returns_none_for_clean_document() {
    assert_eq!(reindent(ALREADY_INDENTED).expect("ok"), None);
}

#[test]
fn splice_region_maps_after_reindent() {
    // The original incident: splice item mapping fails on indentless
    // input and succeeds after the canonicalizing reindent.
    let once = reindent(INDENTLESS).expect("pass").expect("changed");
    let lines: Vec<&str> = once.lines().collect();
    let (ki, kl) =
        crate::splice::find_top_key(&lines, "exceptions").expect("key found after reindent");
    let rend = crate::splice::region_end(&lines, ki, kl.indent);
    let dashes = lines[ki + 1..rend]
        .iter()
        .filter(|l| {
            let t = l.trim_start_matches(' ');
            crate::splice::leading_spaces(l) > kl.indent && (t == "-" || t.starts_with("- "))
        })
        .count();
    assert_eq!(dashes, 3);
}
