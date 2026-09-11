use serde_yaml::Value;

use crate::yaml_edit_engine as engine;
use crate::yaml_edit_ops::{fail, mutate, Cli};
use crate::yaml_edit_splice as splice;

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

pub fn run_unset(cli: &Cli) {
    let path = cli.key.as_deref().unwrap_or_default();
    let mut removed = 0;
    mutate(cli, &mut |doc, original| {
        let (expected, concrete) = engine::unset_fields(doc, path)?;
        removed = concrete.len();
        crate::yaml_edit_unset::splice_unset(original, &concrete).map(|out| (out, expected))
    });
    println!("yaml-edit: removed {removed} fields");
}

pub fn run_remove_comment(cli: &Cli) {
    let text = cli.value.as_deref().unwrap_or_default();
    let mut removed = 0;
    mutate(cli, &mut |doc, original| {
        let (out, count) = crate::yaml_edit_comment::remove_exact_comments(original, text)?;
        removed = count;
        Ok((out, doc.clone()))
    });
    println!("yaml-edit: removed {removed} comments");
}

pub fn run_delete(cli: &Cli) {
    crate::yaml_edit_delete::run(cli);
}
