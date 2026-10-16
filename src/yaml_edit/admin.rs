use noyalib::compat::serde_yaml::Value;
use std::path::Path;

use crate::engine;
use crate::ops::{fail, key_err, mutate, Cli};
use crate::splice;

/// Read one list item from raw YAML text. The file must parse as
/// exactly one YAML mapping; anything else (scalar, sequence, multi-
/// document, parse error) fails closed before the target is touched.
fn parse_block(raw: &str, path: &Path) -> Value {
    let value: Value = noyalib::compat::serde_yaml::from_str(raw)
        .unwrap_or_else(|e| fail(1, &format!("{}: not valid YAML: {e}", path.display())));
    if !value.is_mapping() {
        fail(
            1,
            &format!("{}: block must be a single YAML mapping", path.display()),
        );
    }
    value
}

/// Append one list item whose value is a raw YAML block (e.g. a mapping
/// carrying nested policy such as `reject_patterns: [...]`), which the
/// scalar-only field-spec grammar of `add` cannot express. Insertion,
/// verification, schema validation, chattr handling, and audit are the
/// same path as `add`.
pub fn run_add_block(cli: &Cli) {
    let key = cli.key.as_deref().unwrap_or_default();
    let block_path = Path::new(cli.value.as_deref().unwrap_or_default());
    let raw = std::fs::read_to_string(block_path)
        .unwrap_or_else(|e| fail(2, &format!("cannot read {}: {e}", block_path.display())));
    let entry = parse_block(&raw, block_path);
    mutate(cli, &mut |doc, original| {
        let items = engine::list_items(doc, key).unwrap_or_else(|e| key_err(e, key));
        if items.iter().any(|v| v == &entry) {
            fail(4, &format!("duplicate entry in {key}"));
        }
        let mut expected = doc.clone();
        expected
            .as_mapping_mut()
            .and_then(|m| m.get_mut(key))
            .and_then(|v| v.as_sequence_mut())
            .map(|s| s.push(entry.clone()))
            .unwrap_or_else(|| fail(1, &format!("key is not a list: {key}")));
        splice::splice_add(original, key, &entry, items).map(|out| (out, expected))
    });
}

pub fn run_bootstrap(cli: &Cli) {
    let key = cli.key.as_deref().unwrap_or_default();
    if key.is_empty() || key.contains('.') {
        fail(2, "bootstrap requires a non-empty top-level key");
    }
    let raw_value = cli.value.clone().unwrap_or_default();
    mutate(cli, &mut |doc, original| {
        let root = doc
            .as_mapping()
            .ok_or(())
            .unwrap_or_else(|_| fail(1, "document root is not a mapping"));
        if root.contains_key(key) {
            fail(2, &format!("key already exists: {key}"));
        }
        // "[]" bootstraps a new empty top-level list so entries can be
        // appended with `add`; scalar parsing alone rejects sequences.
        let value = if raw_value == "[]" {
            Value::Sequence(Vec::new())
        } else {
            engine::typed_value(&raw_value, cli.force_string).unwrap_or_else(|e| fail(2, &e))
        };
        let mut expected = doc.clone();
        expected
            .as_mapping_mut()
            .expect("root checked")
            .insert(key.to_string(), value.clone());
        splice::splice_insert_top_level(original, key, &value).map(|out| (out, expected))
    });
}

/// Insert a previously absent key into an existing block mapping, with
/// the entry value built from `<field-spec>...` (a nested mapping). This
/// is the map-value counterpart to `add` (list entries) and to
/// `set --create` (scalar leaves); it shares `splice_insert_map_key`.
pub fn run_map_add(cli: &Cli) {
    let key = cli.key.as_deref().unwrap_or_default();
    let new_key = cli.new_key.as_deref().unwrap_or_default();
    if new_key.is_empty() {
        fail(2, "map-add requires a non-empty entry key");
    }
    let specs = engine::parse_specs(&cli.specs).unwrap_or_else(|e| fail(2, &e));
    let entry = engine::entry_from_specs(&specs).unwrap_or_else(|e| fail(2, &e));
    mutate(cli, &mut |doc, original| {
        let segs =
            engine::resolve_segments(doc, key).ok_or_else(|| format!("key not found: {key}"))?;
        let parent = engine::scalar_at(doc, &segs).map_err(|_| format!("key not found: {key}"))?;
        if parent.as_mapping().is_none() {
            return Err(format!("key is not a mapping: {key}"));
        }
        let mut expected = doc.clone();
        let mut node = &mut expected;
        for seg in &segs {
            node = node
                .as_mapping_mut()
                .and_then(|m| m.get_mut(seg.as_str()))
                .ok_or_else(|| format!("key not found: {key}"))?;
        }
        let map = node.as_mapping_mut().expect("parent checked");
        if map.contains_key(new_key) {
            fail(4, &format!("key already exists in {key}: {new_key}"));
        }
        map.insert(new_key.to_string(), entry.clone());
        splice::splice_insert_map_key(original, &segs, new_key, &entry).map(|out| (out, expected))
    });
}

pub fn run_unset(cli: &Cli) {
    let path = cli.key.as_deref().unwrap_or_default();
    let mut removed = 0;
    mutate(cli, &mut |doc, original| {
        let (expected, concrete) = engine::unset_fields(doc, path)?;
        removed = concrete.len();
        crate::unset::splice_unset(original, &concrete).map(|out| (out, expected))
    });
    println!("yaml-edit: removed {removed} fields");
}

pub fn run_remove_comment(cli: &Cli) {
    let text = cli.value.as_deref().unwrap_or_default();
    let mut removed = 0;
    mutate(cli, &mut |doc, original| {
        let (out, count) = crate::comment::remove_exact_comments(original, text)?;
        removed = count;
        Ok((out, doc.clone()))
    });
    println!("yaml-edit: removed {removed} comments");
}

pub fn run_delete(cli: &Cli) {
    crate::delete::run(cli);
}
