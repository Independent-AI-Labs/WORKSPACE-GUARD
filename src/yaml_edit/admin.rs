use serde_yaml::Value;

use crate::engine;
use crate::ops::{fail, mutate, Cli};
use crate::splice;

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
            .insert(Value::String(key.to_string()), value.clone());
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
        map.insert(Value::String(new_key.to_string()), entry.clone());
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
