// src/yaml_edit_emit.rs
//
// YAML emission for workspace-yaml-edit (SPEC-YAML-EDIT section 4).
// Emission is the fail-open minefield of the retired awk engine: a
// single-element list emitted as a scalar, an unquoted `yes` that
// PyYAML (YAML 1.1) reads as a boolean, an empty string that becomes
// a match-everything regex downstream. All output here is produced by
// explicit type-aware rules, never by passing user text through:
//
//   - structural shape comes from the serde_yaml::Value, so a list is
//     always emitted as a list, even with one item;
//   - scalars are single-quoted whenever a YAML 1.1 consumer (PyYAML,
//     which the CI gates use) could resolve them as a non-string;
//   - non-string scalars (numbers, booleans) are emitted plain via
//     the serde_yaml emitter.
//
// Values containing newlines are rejected upstream at spec parse
// time, so every emitted line is exactly one output line.

use serde_yaml::Value;

/// True when `s` must be quoted so that a YAML 1.1 parser (PyYAML)
/// still reads it as a string. Conservative: anything resembling a
/// 1.1 boolean/null/number, anything with indicators or significant
/// whitespace, gets single quotes.
fn needs_quotes(s: &str) -> bool {
    if s.is_empty() || s != s.trim() {
        return true;
    }
    let first = s.as_bytes()[0] as char;
    if "-?:,[]{}#&*!|>'\"%@` ".contains(first) {
        return true;
    }
    if s.ends_with(':') || s.contains(": ") || s.contains(" #") {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "y" | "yes" | "n" | "no" | "true" | "false" | "on" | "off" | "null" | "~"
    ) {
        return true;
    }
    if looks_like_number(&lower) {
        return true;
    }
    if looks_like_timestamp(s) {
        return true;
    }
    false
}

/// YAML 1.1 timestamp shapes PyYAML's SafeLoader resolves implicitly:
/// `YYYY-M-D` dates (month/day may be single-digit) and the same with
/// a `[T ]hh:mm:ss...` time suffix.
fn looks_like_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    let digit = |i: usize| i < b.len() && b[i].is_ascii_digit();
    if !(digit(0) && digit(1) && digit(2) && digit(3) && b.get(4) == Some(&b'-')) {
        return false;
    }
    let mut i = 5;
    if !digit(i) {
        return false;
    }
    i += 1;
    if digit(i) {
        i += 1;
    }
    if b.get(i) != Some(&b'-') {
        return false;
    }
    i += 1;
    if !digit(i) {
        return false;
    }
    i += 1;
    if digit(i) {
        i += 1;
    }
    i == b.len() || matches!(b[i], b'T' | b't' | b' ')
}

/// YAML 1.1 numeric shapes: ints (dec/oct/hex, underscores), floats
/// with optional exponent, .inf/.nan, and sexagesimal (1:30).
fn looks_like_number(s: &str) -> bool {
    if matches!(s, ".inf" | "-.inf" | "+.inf" | ".nan") {
        return true;
    }
    let digits = |t: &str| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit() || c == '_');
    let body = s.strip_prefix(['-', '+']).unwrap_or(s);
    if body.starts_with("0x") && body.len() > 2 && body[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return true;
    }
    if body.contains(':') {
        return body.split(':').all(digits);
    }
    let core = body.split(['e', 'E']).next().unwrap_or(body);
    let exp_ok = match body.find(['e', 'E']) {
        Some(i) => {
            let e = &body[i + 1..];
            let e = e.strip_prefix(['-', '+']).unwrap_or(e);
            !e.is_empty() && e.chars().all(|c| c.is_ascii_digit())
        }
        None => true,
    };
    if !exp_ok {
        return false;
    }
    match core.split_once('.') {
        Some((a, b)) => {
            (!a.is_empty() || !b.is_empty()) && (a.is_empty() || digits(a)) && digits(b)
        }
        None => digits(core),
    }
}

/// Render any scalar Value as a single YAML token.
pub fn render_scalar(v: &Value) -> String {
    match v {
        Value::String(s) => render_string(s),
        other => {
            let raw = serde_yaml::to_string(other).unwrap_or_default();
            raw.trim_end().to_string()
        }
    }
}

/// Render a string as a plain or single-quoted YAML scalar.
fn render_string(s: &str) -> String {
    if needs_quotes(s) {
        format!("'{}'", s.replace('\'', "''"))
    } else {
        s.to_string()
    }
}

/// Emit `key: value` lines for one mapping pair at `indent` spaces.
/// Nested sequences and mappings open on the key line and emit their
/// items deeper, matching the fleet's existing block style.
pub fn emit_kv(key: &str, value: &Value, indent: usize) -> Vec<String> {
    let pad = " ".repeat(indent);
    let k = render_string(key);
    match value {
        Value::Sequence(items) if !items.is_empty() => {
            let mut out = vec![format!("{pad}{k}:")];
            for item in items {
                out.extend(emit_dash_item(item, indent + 2));
            }
            out
        }
        Value::Mapping(m) if !m.is_empty() => {
            let mut out = vec![format!("{pad}{k}:")];
            for (mk, mv) in m {
                let mk = mk.as_str().unwrap_or_default();
                out.extend(emit_kv(mk, mv, indent + 2));
            }
            out
        }
        _ => vec![format!("{pad}{k}: {}", render_scalar(value))],
    }
}

/// Emit one sequence item (`- ...`) at `indent` spaces. A mapping
/// item puts its first pair on the dash line; a scalar goes straight
/// after the dash.
pub fn emit_dash_item(v: &Value, indent: usize) -> Vec<String> {
    let pad = " ".repeat(indent);
    match v {
        Value::Mapping(m) if !m.is_empty() => {
            let mut out = Vec::new();
            for (i, (mk, mv)) in m.iter().enumerate() {
                let mk = mk.as_str().unwrap_or_default();
                let lines = emit_kv(mk, mv, indent + 2);
                for (j, line) in lines.into_iter().enumerate() {
                    if i == 0 && j == 0 {
                        out.push(format!("{pad}- {}", &line[indent + 2..]));
                    } else {
                        out.push(line);
                    }
                }
            }
            out
        }
        _ => vec![format!("{pad}- {}", render_scalar(v))],
    }
}
