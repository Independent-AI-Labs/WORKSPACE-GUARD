// src/yaml_edit_engine.rs
//
// Semantic core of workspace-yaml-edit (SPEC-YAML-EDIT section 3):
// field-spec parsing, entry construction, matching, and dotted-key
// resolution. Everything here operates on serde_yaml::Value, never on
// raw text: meaning comes from the real parser (REQ-YE-006). Line
// scanning lives in yaml_edit_splice.rs and only locates byte ranges.
//
// Spec grammar (REQ-YE-200):
//   name=value    scalar field; value literal, commas included
//   name=[v1,v2]  list field; [x] is a single-element list, [] empty
//   value         bare item for scalar-list keys
//
// Rejected at parse time: empty items ([a,], [,]), duplicate items in
// one list spec, empty scalar values, scalars that parse as YAML
// mappings/sequences, values containing newlines, and field names
// outside [A-Za-z0-9_.-]+.

use serde_yaml::{Mapping, Value};

#[derive(Debug, Clone, PartialEq)]
pub enum Spec {
    Scalar { name: String, value: Value },
    List { name: String, items: Vec<Value> },
    Bare { value: Value },
}

/// Error kinds surfaced to the CLI with distinct messages (REQ-YE
/// exit-code table: key missing vs not-a-list vs not-a-scalar are
/// three different operator problems).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    Missing,
    NotAList,
    NotAMap,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Parse a spec value as a YAML scalar so numbers stay numeric
/// (REQ-YE-203). Strings that parse as mappings/sequences are
/// rejected: they indicate a quoting mistake, not a scalar.
fn typed_scalar(raw: &str, what: &str) -> Result<Value, String> {
    if raw.contains('\n') {
        return Err(format!("{what}: newlines in values are unsupported"));
    }
    let v: Value = serde_yaml::from_str(raw)
        .map_err(|e| format!("{what}: value does not parse as a YAML scalar: {e}"))?;
    let kind = if v.is_mapping() {
        Some("mapping")
    } else if v.is_sequence() {
        Some("sequence")
    } else {
        None
    };
    match v {
        Value::Null => Err(format!("{what}: empty value")),
        _ if kind.is_some() => Err(format!(
            "{what}: scalar value parses as YAML {}; check quoting",
            kind.unwrap_or_default()
        )),
        _ => Ok(v),
    }
}

/// Parse one command-line field spec (REQ-YE-200/202). The value is
/// taken verbatim; no quote or backslash stripping is applied.
pub fn parse_spec(arg: &str) -> Result<Spec, String> {
    match arg.split_once('=') {
        None => Ok(Spec::Bare {
            value: typed_scalar(arg, "bare item")?,
        }),
        Some((name, val)) => {
            if !valid_name(name) {
                return Err(format!("bad field name: {name}"));
            }
            if let Some(inner) = val.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
                if inner.is_empty() {
                    return Ok(Spec::List {
                        name: name.to_string(),
                        items: Vec::new(),
                    });
                }
                let mut items = Vec::new();
                for part in inner.split(',') {
                    if part.is_empty() {
                        return Err(format!("{name}: empty list item"));
                    }
                    let v = typed_scalar(part, name)?;
                    if items.contains(&v) {
                        return Err(format!("{name}: duplicate list item: {part}"));
                    }
                    items.push(v);
                }
                Ok(Spec::List {
                    name: name.to_string(),
                    items,
                })
            } else if val.starts_with('[') || val.ends_with(']') {
                Err(format!("{name}: malformed list brackets"))
            } else {
                if !val.starts_with(['"', '\''])
                    && val.split_whitespace().skip(1).any(|token| {
                        token
                            .split_once('=')
                            .is_some_and(|(field, _)| valid_name(field))
                    })
                {
                    return Err(format!(
                        "{name}: embedded field assignment; separate field specs with ';'"
                    ));
                }
                Ok(Spec::Scalar {
                    name: name.to_string(),
                    value: typed_scalar(val, name)?,
                })
            }
        }
    }
}

/// Scalar coercion for `set`: `--string` forces a YAML string,
/// otherwise `typed_scalar` typing applies (REQ-YE-203).
pub fn typed_value(raw: &str, force_string: bool) -> Result<Value, String> {
    if force_string {
        if raw.is_empty() || raw.trim() != raw {
            return Err("value is empty or has surrounding whitespace".to_string());
        }
        return Ok(Value::String(raw.to_string()));
    }
    typed_scalar(raw, "value")
}

pub fn parse_specs(args: &[String]) -> Result<Vec<Spec>, String> {
    if args.is_empty() {
        return Err("no field specs given".to_string());
    }
    args.iter().map(|a| parse_spec(a)).collect()
}

/// Build the entry Value for add from specs: a Mapping for named
/// fields, a scalar for a single bare item.
pub fn entry_from_specs(specs: &[Spec]) -> Result<Value, String> {
    let bare: Vec<&Value> = specs
        .iter()
        .filter_map(|s| match s {
            Spec::Bare { value } => Some(value),
            _ => None,
        })
        .collect();
    if !bare.is_empty() {
        if specs.len() > 1 {
            return Err("cannot mix a bare list item with named fields".to_string());
        }
        return Ok(bare[0].clone());
    }
    let mut m = Mapping::new();
    for s in specs {
        match s {
            Spec::Scalar { name, value } => {
                m.insert(Value::String(name.clone()), value.clone());
            }
            Spec::List { name, items } => {
                m.insert(Value::String(name.clone()), Value::Sequence(items.clone()));
            }
            Spec::Bare { .. } => unreachable!(),
        }
    }
    Ok(Value::Mapping(m))
}

/// Set-wise list comparison (order-insensitive, REQ-YE-201).
fn list_seteq(a: &[Value], b: &[Value]) -> bool {
    a.len() == b.len() && b.iter().all(|v| a.contains(v))
}

/// True when the parsed entry matches every spec (REQ-YE-201).
pub fn specs_match_entry(entry: &Value, specs: &[Spec]) -> bool {
    for s in specs {
        match s {
            Spec::Bare { value } => {
                if entry != value {
                    return false;
                }
            }
            Spec::Scalar { name, value } => {
                let got = entry.get(name.as_str());
                if got != Some(value) {
                    return false;
                }
            }
            Spec::List { name, items } => match entry.get(name.as_str()) {
                Some(Value::Sequence(got)) if list_seteq(got, items) => {}
                _ => return false,
            },
        }
    }
    true
}

/// Resolve a dotted key literally first (a key containing a dot at
/// the current level wins), then segment by segment (REQ-YE-204).
/// Returns the resolved per-level key names.
pub fn resolve_segments(doc: &Value, dotted: &str) -> Option<Vec<String>> {
    if dotted.is_empty() {
        return None;
    }
    let mut segments = Vec::new();
    let mut node = doc;
    let mut rest = dotted.to_string();
    loop {
        let map = node.as_mapping()?;
        if map.contains_key(rest.as_str()) {
            segments.push(rest);
            return Some(segments);
        }
        let (head, tail) = rest.split_once('.')?;
        if !map.contains_key(head) {
            return None;
        }
        segments.push(head.to_string());
        node = map.get(head)?;
        rest = tail.to_string();
    }
}

/// Fetch a top-level list key's items, with distinct errors.
pub fn list_items<'a>(doc: &'a Value, key: &str) -> Result<&'a Vec<Value>, KeyError> {
    let root = doc.as_mapping().ok_or(KeyError::NotAMap)?;
    match root.get(key) {
        None => Err(KeyError::Missing),
        Some(Value::Sequence(items)) => Ok(items),
        Some(_) => Err(KeyError::NotAList),
    }
}

/// Indexes of items matching all specs.
pub fn matching_indexes(items: &[Value], specs: &[Spec]) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter_map(|(i, e)| specs_match_entry(e, specs).then_some(i))
        .collect()
}

/// Resolve a scalar for get/set, with distinct errors.
pub fn scalar_at<'a>(doc: &'a Value, segments: &[String]) -> Result<&'a Value, KeyError> {
    let mut node = doc;
    for seg in segments {
        node = node
            .as_mapping()
            .and_then(|m| m.get(seg.as_str()))
            .ok_or(KeyError::Missing)?;
    }
    Ok(node)
}
