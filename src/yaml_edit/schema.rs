// src/yaml_edit_schema.rs
//
// Schema registry for workspace-yaml-edit (SPEC-YAML-EDIT section
// 5, REQ-YE-301). The retired awk tool validated exactly one
// basename, which let fail-open shapes ship in every other file.
// Here a compiled-in table covers the fleet's known policy files and
// an optional override file (yaml_edit_schemas.yaml, looked up next
// to the target file) lets consumers register new basenames without
// recompiling. Unknown basenames get structural verification only.
//
// Validators run against the parsed document (post-transform for
// mutations, as-is for `validate`), never against line text.

use serde::Deserialize;
use serde_yaml::Value;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    #[default]
    ListOfMaps,
    ScalarList,
}

#[derive(Debug, Clone, Default)]
pub struct Schema {
    pub basename: String,
    /// List key the entry rules apply to; empty = no list rules.
    pub key: String,
    pub kind: Kind,
    /// If present in an entry, must be a sequence.
    pub list_fields: Vec<String>,
    /// Must be present in every entry and be a non-empty sequence.
    pub required_lists: Vec<String>,
    /// Must be present in every entry and be a non-empty scalar.
    pub required: Vec<String>,
    /// Minimum string length per field.
    pub min_length: Vec<(String, usize)>,
    /// Leaf key names (any depth) whose values must be numeric.
    pub numeric_keys: Vec<String>,
}

fn s(v: &str) -> String {
    v.to_string()
}

/// Compiled-in schemas for the fleet's known policy files.
pub fn builtins() -> Vec<Schema> {
    vec![
        Schema {
            basename: s("quality_exceptions.yaml"),
            key: s("exceptions"),
            kind: Kind::ListOfMaps,
            required: vec![s("hook"), s("added_by"), s("reason")],
            min_length: vec![(s("reason"), 20)],
            required_lists: vec![s("paths")],
            ..Default::default()
        },
        Schema {
            basename: s("banned_words_exceptions.yaml"),
            key: s("exceptions"),
            kind: Kind::ListOfMaps,
            required: vec![
                s("rule"),
                s("path"),
                s("rationale"),
                s("owner"),
                s("review_date"),
                s("removal"),
            ],
            min_length: vec![(s("rationale"), 20), (s("removal"), 8)],
            ..Default::default()
        },
        Schema {
            basename: s("silent_swallow_exceptions.yaml"),
            key: s("exceptions"),
            kind: Kind::ListOfMaps,
            required: vec![
                s("path"),
                s("rationale"),
                s("owner"),
                s("review_date"),
                s("removal"),
            ],
            min_length: vec![(s("rationale"), 20), (s("removal"), 8)],
            ..Default::default()
        },
        Schema {
            basename: s(".markdown_docs_exceptions.yaml"),
            key: s("exceptions"),
            kind: Kind::ListOfMaps,
            list_fields: vec![s("paths")],
            ..Default::default()
        },
        Schema {
            basename: s("sensitive_files_exceptions.yaml"),
            key: s("safe_exceptions"),
            kind: Kind::ScalarList,
            ..Default::default()
        },
        Schema {
            basename: s("coverage_thresholds.yaml"),
            numeric_keys: vec![s("version"), s("min_coverage"), s("timeout")],
            ..Default::default()
        },
        Schema {
            basename: s("file_length_limits.yaml"),
            numeric_keys: vec![s("max_lines")],
            ..Default::default()
        },
    ]
}

#[derive(Debug, Deserialize)]
struct OverrideFile {
    #[allow(dead_code)]
    version: u32,
    #[serde(default)]
    schemas: Vec<OverrideSchema>,
}

#[derive(Debug, Deserialize)]
struct OverrideSchema {
    basename: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    list_fields: Vec<String>,
    #[serde(default)]
    required_lists: Vec<String>,
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    min_length: HashMap<String, usize>,
    #[serde(default)]
    numeric_keys: Vec<String>,
}

/// Load `yaml_edit_schemas.yaml` from the target file's directory and
/// merge over the builtins (override wins per basename). Absent file
/// is fine; a malformed file fails closed. Ownership (root:root) is
/// checked by the caller before any mutation.
pub fn registry_for(target: &Path) -> Result<Vec<Schema>, String> {
    let mut out = builtins();
    let Some(dir) = target.parent() else {
        return Ok(out);
    };
    let path = dir.join("yaml_edit_schemas.yaml");
    if !path.exists() {
        return Ok(out);
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let parsed: OverrideFile = serde_yaml::from_str(&raw)
        .map_err(|e| format!("{}: not valid YAML: {e}", path.display()))?;
    for o in parsed.schemas {
        let kind = match o.kind.as_deref() {
            None | Some("list-of-maps") => Kind::ListOfMaps,
            Some("scalar-list") => Kind::ScalarList,
            Some(other) => {
                return Err(format!(
                    "{}: schema {}: unknown kind: {other}",
                    path.display(),
                    o.basename
                ))
            }
        };
        let schema = Schema {
            basename: o.basename.clone(),
            key: o.key.unwrap_or_default(),
            kind,
            list_fields: o.list_fields,
            required_lists: o.required_lists,
            required: o.required,
            min_length: o.min_length.into_iter().collect(),
            numeric_keys: o.numeric_keys,
        };
        out.retain(|b| b.basename != o.basename);
        out.push(schema);
    }
    Ok(out)
}

fn non_empty_scalar(v: &Value) -> bool {
    match v {
        Value::Null | Value::Mapping(_) | Value::Sequence(_) => false,
        Value::String(t) => !t.is_empty(),
        _ => true,
    }
}

fn validate_entry(schema: &Schema, idx: usize, entry: &Value, errors: &mut Vec<String>) {
    let Some(map) = entry.as_mapping() else {
        errors.push(format!("{}: entry {idx} is not a mapping", schema.basename));
        return;
    };
    for f in &schema.required {
        match map.get(f.as_str()) {
            Some(v) if non_empty_scalar(v) => {}
            _ => errors.push(format!(
                "{}: entry {idx}: '{f}' is required and must be a non-empty scalar",
                schema.basename
            )),
        }
    }
    for f in &schema.required_lists {
        match map.get(f.as_str()) {
            Some(Value::Sequence(items)) if !items.is_empty() => {}
            _ => errors.push(format!(
                "{}: entry {idx}: '{f}' must be a list with >=1 item",
                schema.basename
            )),
        }
    }
    for f in &schema.list_fields {
        if let Some(v) = map.get(f.as_str()) {
            if !v.is_sequence() {
                errors.push(format!(
                    "{}: entry {idx}: '{f}' must be a list",
                    schema.basename
                ));
            }
        }
    }
    for (f, min) in &schema.min_length {
        if let Some(Value::String(t)) = map.get(f.as_str()) {
            if t.chars().count() < *min {
                errors.push(format!(
                    "{}: entry {idx}: '{f}' needs >= {min} chars",
                    schema.basename
                ));
            }
        }
    }
}

fn check_numeric(node: &Value, keys: &[String], path: &str, errors: &mut Vec<String>) {
    if let Value::Mapping(m) = node {
        for (k, v) in m {
            let name = k.as_str().unwrap_or_default();
            let here = if path.is_empty() {
                name.to_string()
            } else {
                format!("{path}.{name}")
            };
            if keys.iter().any(|n| n == name) && !v.is_number() {
                errors.push(format!("'{here}' must be numeric"));
            }
            check_numeric(v, keys, &here, errors);
        }
    } else if let Value::Sequence(items) = node {
        for (i, item) in items.iter().enumerate() {
            check_numeric(item, keys, &format!("{path}[{i}]"), errors);
        }
    }
}

/// Validate a parsed document against the schema for its basename.
/// Unknown basenames pass (structural verification covers them).
pub fn validate_document(basename: &str, doc: &Value, registry: &[Schema]) -> Result<(), String> {
    let Some(schema) = registry.iter().find(|sc| sc.basename == basename) else {
        return Ok(());
    };
    let mut errors = Vec::new();
    if !schema.key.is_empty() {
        match doc.get(schema.key.as_str()) {
            Some(Value::Sequence(items)) => match schema.kind {
                Kind::ListOfMaps => {
                    for (i, entry) in items.iter().enumerate() {
                        validate_entry(schema, i, entry, &mut errors);
                    }
                }
                Kind::ScalarList => {
                    for (i, item) in items.iter().enumerate() {
                        if !non_empty_scalar(item) {
                            errors.push(format!(
                                "{}: item {i} of '{}' must be a non-empty scalar",
                                schema.basename, schema.key
                            ));
                        }
                    }
                }
            },
            Some(_) => errors.push(format!(
                "{}: '{}' must be a list",
                schema.basename, schema.key
            )),
            None => errors.push(format!(
                "{}: list key '{}' is missing",
                schema.basename, schema.key
            )),
        }
    }
    check_numeric(doc, &schema.numeric_keys, "", &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}
