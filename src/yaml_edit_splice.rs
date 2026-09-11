// src/yaml_edit_splice.rs
//
// Line-splice layer of workspace-yaml-edit (SPEC-YAML-EDIT section
// 4). The document has already parsed with serde_yaml before any
// function here runs; this layer only locates byte ranges to rewrite
// so that comments, blank lines, and unrelated keys survive
// byte-for-byte (REQ-YE-103). It never decides meaning: entry
// matching, typing, and verification live in yaml_edit_engine.rs.
//
// Indentation discipline: a top-level key sits at the document base
// indent; its block region runs until the next non-blank non-comment
// line at <= that indent. Sequence items of one list share one dash
// indent; nested content is always deeper, so the minimum dash indent
// inside a region is exactly the item indent.

use serde_yaml::Value;

use crate::yaml_edit_emit::{emit_dash_item, emit_kv};

/// One parsed `key: value # comment` line. `head` is the verbatim
/// text up to and including the colon, so rewrites keep the original
/// key spelling and spacing.
#[derive(Debug, Clone)]
pub struct KeyLine {
    pub indent: usize,
    pub key: String,
    pub head: String,
    pub rest: String,
    pub comment: String,
}

pub(crate) fn leading_spaces(s: &str) -> usize {
    s.len() - s.trim_start_matches(' ').len()
}

fn dequote_key(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2 && b[0] == b'\'' && b[b.len() - 1] == b'\'' {
        s[1..s.len() - 1].replace("''", "'")
    } else if b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Split `value text # comment` at the first comment marker outside
/// quotes. Returns (value, comment-with-hash).
fn split_comment(s: &str) -> (String, String) {
    let b = s.as_bytes();
    let mut i = 0;
    let mut in_sq = false;
    let mut in_dq = false;
    while i < b.len() {
        match b[i] {
            b'\'' if !in_dq => {
                if in_sq && i + 1 < b.len() && b[i + 1] == b'\'' {
                    i += 1;
                } else {
                    in_sq = !in_sq;
                }
            }
            b'"' if !in_sq => in_dq = !in_dq,
            b'#' if !in_sq && !in_dq && (i == 0 || b[i - 1] == b' ' || b[i - 1] == b'\t') => {
                return (s[..i].trim_end().to_string(), s[i..].trim().to_string());
            }
            _ => {}
        }
        i += 1;
    }
    (s.trim_end().to_string(), String::new())
}

/// Parse a mapping-key line. Returns None for blank lines, comments,
/// and sequence-item lines (`- ...`).
pub fn parse_key_line(line: &str) -> Option<KeyLine> {
    let indent = leading_spaces(line);
    let c = &line[indent..];
    if c.is_empty() || c.starts_with('#') || c == "-" || c.starts_with("- ") {
        return None;
    }
    let b = c.as_bytes();
    let mut i = 0;
    let mut in_sq = false;
    let mut in_dq = false;
    while i < b.len() {
        match b[i] {
            b'\'' if !in_dq => {
                if in_sq && i + 1 < b.len() && b[i + 1] == b'\'' {
                    i += 1;
                } else {
                    in_sq = !in_sq;
                }
            }
            b'"' if !in_sq => in_dq = !in_dq,
            b':' if !in_sq && !in_dq && (i + 1 == b.len() || b[i + 1] == b' ') => {
                let key = dequote_key(c[..i].trim_end());
                if key.is_empty() {
                    return None;
                }
                let (rest, comment) = split_comment(&c[i + 1..]);
                return Some(KeyLine {
                    indent,
                    key,
                    head: c[..=i].to_string(),
                    rest: rest.trim_start().to_string(),
                    comment,
                });
            }
            _ => {}
        }
        i += 1;
    }
    None
}

pub(crate) fn is_content(line: &str) -> bool {
    let t = line.trim_start_matches(' ');
    !t.is_empty() && !t.starts_with('#')
}

/// Exclusive end of the block region under a key line.
pub(crate) fn region_end(lines: &[&str], key_line: usize, indent: usize) -> usize {
    let mut i = key_line + 1;
    while i < lines.len() {
        if is_content(lines[i]) && leading_spaces(lines[i]) <= indent {
            break;
        }
        i += 1;
    }
    i
}

/// Last line index of a flow node (`[`, `{`, or an unterminated
/// quote) that may span multiple lines.
fn flow_end(lines: &[&str], key_line: usize, kl: &KeyLine) -> usize {
    let opens = kl.rest.matches('[').count() + kl.rest.matches('{').count();
    let closes = kl.rest.matches(']').count() + kl.rest.matches('}').count();
    let mut depth = opens as i64 - closes as i64;
    let quote_open = (kl.rest.starts_with('\'') && !kl.rest.ends_with('\''))
        || (kl.rest.starts_with('"') && !kl.rest.ends_with('"'));
    if depth <= 0 && !quote_open {
        return key_line;
    }
    let mut i = key_line + 1;
    while i < lines.len() {
        if depth > 0 {
            depth += (lines[i].matches('[').count() + lines[i].matches('{').count()) as i64;
            depth -= (lines[i].matches(']').count() + lines[i].matches('}').count()) as i64;
        }
        i += 1;
        if depth <= 0 {
            break;
        }
    }
    i - 1
}

/// Last line index of the node starting at `key_line` (block scalars
/// include their body; deeper-indented lines belong to the node).
fn node_end(lines: &[&str], key_line: usize, kl: &KeyLine) -> usize {
    if kl.rest.is_empty() {
        return key_line;
    }
    if kl.rest.starts_with('[')
        || kl.rest.starts_with('{')
        || kl.rest.starts_with('\'')
        || kl.rest.starts_with('"')
    {
        return flow_end(lines, key_line, kl);
    }
    if kl.rest.starts_with('|') || kl.rest.starts_with('>') {
        let mut end = key_line;
        let mut i = key_line + 1;
        while i < lines.len() {
            let l = lines[i];
            if l.trim().is_empty() {
                i += 1;
                continue;
            }
            if leading_spaces(l) <= kl.indent {
                break;
            }
            end = i;
            i += 1;
        }
        return end;
    }
    key_line
}

/// Locate a top-level key. Fail closed when the key line cannot be
/// found even though the document parsed (exotic key spellings).
pub fn find_top_key(lines: &[&str], key: &str) -> Result<(usize, KeyLine), String> {
    let base = lines
        .iter()
        .find(|l| is_content(l))
        .map(|l| leading_spaces(l))
        .unwrap_or(0);
    for (i, l) in lines.iter().enumerate() {
        if let Some(kl) = parse_key_line(l) {
            if kl.indent == base && kl.key == key {
                return Ok((i, kl));
            }
        }
    }
    Err(format!("cannot locate key line for: {key}"))
}

/// Map the parsed sequence items of a block list to line ranges.
/// The count must match exactly; mismatch means the file uses a
/// shape this layer cannot map, so fail closed.
fn item_ranges(
    lines: &[&str],
    key_line: usize,
    rend: usize,
    expect: usize,
) -> Result<Vec<(usize, usize)>, String> {
    let mut dashes: Vec<(usize, usize)> = Vec::new();
    for (i, l) in lines.iter().enumerate().take(rend).skip(key_line + 1) {
        let t = l.trim_start_matches(' ');
        if is_content(l) && (t == "-" || t.starts_with("- ")) {
            dashes.push((i, leading_spaces(l)));
        }
    }
    let Some(min) = dashes.iter().map(|d| d.1).min() else {
        return Err(format!("expected {expect} entries, found none"));
    };
    let starts: Vec<usize> = dashes.iter().filter(|d| d.1 == min).map(|d| d.0).collect();
    if starts.len() != expect {
        return Err(format!(
            "cannot map entries to lines: parsed {expect}, found {}",
            starts.len()
        ));
    }
    let mut out = Vec::new();
    for (n, s) in starts.iter().enumerate() {
        let e = if n + 1 < starts.len() {
            starts[n + 1] - 1
        } else {
            rend - 1
        };
        out.push((*s, e));
    }
    Ok(out)
}

fn dash_indent(lines: &[&str], key_line: usize, rend: usize, default_indent: usize) -> usize {
    lines
        .iter()
        .take(rend)
        .skip(key_line + 1)
        .filter(|l| {
            let t = l.trim_start_matches(' ');
            is_content(l) && (t == "-" || t.starts_with("- "))
        })
        .map(|l| leading_spaces(l))
        .min()
        .unwrap_or(default_indent)
}

fn join_lines(out: &[String], original: &str) -> String {
    let mut s = out.join("\n");
    if original.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Insert an entry into a list key, returning the transformed file.
/// `items` are the parsed existing items of the key.
pub fn splice_add(
    original: &str,
    key: &str,
    entry: &Value,
    items: &[Value],
) -> Result<String, String> {
    let lines: Vec<&str> = original.lines().collect();
    let (ki, kl) = find_top_key(&lines, key)?;
    let head = if kl.comment.is_empty() {
        kl.head.clone()
    } else {
        format!("{} {}", kl.head, kl.comment)
    };
    let mut out: Vec<String> = Vec::new();
    if kl.rest == "[]" {
        out.extend(lines[..ki].iter().map(|s| s.to_string()));
        out.push(head);
        out.extend(emit_dash_item(entry, kl.indent + 2));
        out.extend(lines[ki + 1..].iter().map(|s| s.to_string()));
    } else if kl.rest.starts_with('[') {
        let fe = flow_end(&lines, ki, &kl);
        out.extend(lines[..ki].iter().map(|s| s.to_string()));
        out.push(head);
        for item in items.iter().chain(std::iter::once(entry)) {
            out.extend(emit_dash_item(item, kl.indent + 2));
        }
        out.extend(lines[fe + 1..].iter().map(|s| s.to_string()));
    } else if kl.rest.is_empty() {
        let rend = region_end(&lines, ki, kl.indent);
        let mut lastc = ki;
        for (i, l) in lines.iter().enumerate().take(rend).skip(ki + 1) {
            if is_content(l) {
                lastc = i;
            }
        }
        out.extend(lines[..=lastc].iter().map(|s| s.to_string()));
        out.extend(emit_dash_item(
            entry,
            dash_indent(&lines, ki, rend, kl.indent + 2),
        ));
        out.extend(lines[lastc + 1..].iter().map(|s| s.to_string()));
    } else {
        return Err(format!("key {key} is not a list"));
    }
    Ok(join_lines(&out, original))
}

/// Remove the given item indexes from a list key. When every item is
/// removed the key line becomes `key: []` with any trailing comment
/// preserved; comments inside the region stay in place.
pub fn splice_remove(
    original: &str,
    key: &str,
    items: &[Value],
    remove_idx: &[usize],
) -> Result<String, String> {
    let lines: Vec<&str> = original.lines().collect();
    let (ki, kl) = find_top_key(&lines, key)?;
    let all = remove_idx.len() == items.len();
    let mut out: Vec<String> = Vec::new();
    if kl.rest.starts_with('[') && kl.rest != "[]" {
        let fe = flow_end(&lines, ki, &kl);
        out.extend(lines[..ki].iter().map(|s| s.to_string()));
        if all {
            let head = if kl.comment.is_empty() {
                format!("{} []", kl.head)
            } else {
                format!("{} [] {}", kl.head, kl.comment)
            };
            out.push(head);
        } else {
            out.push(if kl.comment.is_empty() {
                kl.head.clone()
            } else {
                format!("{} {}", kl.head, kl.comment)
            });
            for (i, item) in items.iter().enumerate() {
                if !remove_idx.contains(&i) {
                    out.extend(emit_dash_item(item, kl.indent + 2));
                }
            }
        }
        out.extend(lines[fe + 1..].iter().map(|s| s.to_string()));
        return Ok(join_lines(&out, original));
    }
    let rend = region_end(&lines, ki, kl.indent);
    let ranges = item_ranges(&lines, ki, rend, items.len())?;
    out.extend(lines[..ki].iter().map(|s| s.to_string()));
    if all {
        let head = if kl.comment.is_empty() {
            format!("{} []", kl.head)
        } else {
            format!("{} [] {}", kl.head, kl.comment)
        };
        out.push(head);
    } else {
        out.push(lines[ki].to_string());
    }
    for (i, line) in lines.iter().enumerate().take(rend).skip(ki + 1) {
        let dropped = remove_idx
            .iter()
            .any(|&r| i >= ranges[r].0 && i <= ranges[r].1);
        if !dropped {
            out.push(line.to_string());
        }
    }
    out.extend(lines[rend..].iter().map(|s| s.to_string()));
    Ok(join_lines(&out, original))
}

/// Locate a nested map key by its resolved per-level segment names.
/// Returns (line, node_end_line, indent). Sequence-item lines are
/// skipped: dotted keys address maps only, matching the resolver in
/// yaml_edit_engine.rs.
pub fn find_node(lines: &[&str], segments: &[String]) -> Result<(usize, usize, usize), String> {
    let mut stack: Vec<(usize, String)> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let Some(kl) = parse_key_line(l) else {
            continue;
        };
        while stack.last().is_some_and(|(ind, _)| *ind >= kl.indent) {
            stack.pop();
        }
        let mut path: Vec<&str> = stack.iter().map(|(_, k)| k.as_str()).collect();
        path.push(&kl.key);
        let matches_prefix = path.len() <= segments.len()
            && path
                .iter()
                .zip(segments.iter())
                .all(|(a, b)| *a == b.as_str());
        if matches_prefix && path.len() == segments.len() {
            return Ok((i, node_end(lines, i, &kl), kl.indent));
        }
        stack.push((kl.indent, kl.key));
    }
    Err(format!(
        "cannot locate key line for: {}",
        segments.join(".")
    ))
}

/// Raw lines of a top-level key's whole block (key line through the
/// end of its region), for `list <file> <key>`.
pub fn key_block(original: &str, key: &str) -> Result<String, String> {
    let lines: Vec<&str> = original.lines().collect();
    let (ki, kl) = find_top_key(&lines, key)?;
    let end = region_end(&lines, ki, kl.indent);
    let block: Vec<String> = lines[ki..end].iter().map(|s| s.to_string()).collect();
    Ok(join_lines(&block, original))
}

/// Replace a scalar node addressed by resolved segments with a new
/// value. The node's whole line range (block scalar body, multi-line
/// flow) is replaced wholesale, so no orphan body lines remain.
pub fn splice_set(original: &str, segments: &[String], value: &Value) -> Result<String, String> {
    let lines: Vec<&str> = original.lines().collect();
    let (line, end, indent) = find_node(&lines, segments)?;
    let key = segments
        .last()
        .ok_or_else(|| "empty key path".to_string())?;
    let mut out: Vec<String> = Vec::new();
    out.extend(lines[..line].iter().map(|s| s.to_string()));
    out.extend(emit_kv(key, value, indent));
    out.extend(lines[end + 1..].iter().map(|s| s.to_string()));
    Ok(join_lines(&out, original))
}

/// Append a previously absent scalar key under an existing block
/// mapping addressed by `parent_segments`. Fails closed when the
/// parent is flow style or otherwise not a plain block map.
pub fn splice_insert_map_key(
    original: &str,
    parent_segments: &[String],
    leaf: &str,
    value: &Value,
) -> Result<String, String> {
    let lines: Vec<&str> = original.lines().collect();
    let (line, _end, indent) = find_node(&lines, parent_segments)?;
    let kl = parse_key_line(lines[line]).ok_or("cannot locate parent key line")?;
    if !kl.rest.is_empty() {
        return Err(format!(
            "cannot insert into non-block mapping: {}",
            parent_segments.join(".")
        ));
    }
    let rend = region_end(&lines, line, indent);
    let mut lastc = line;
    for (i, l) in lines.iter().enumerate().take(rend).skip(line + 1) {
        if is_content(l) {
            lastc = i;
        }
    }
    let mut out: Vec<String> = Vec::new();
    out.extend(lines[..=lastc].iter().map(|s| s.to_string()));
    out.extend(emit_kv(leaf, value, indent + 2));
    out.extend(lines[lastc + 1..].iter().map(|s| s.to_string()));
    Ok(join_lines(&out, original))
}

/// Append a previously absent scalar key at the document's top level.
pub fn splice_insert_top_level(original: &str, key: &str, value: &Value) -> Result<String, String> {
    let mut lines: Vec<String> = original.lines().map(str::to_string).collect();
    let emitted = emit_kv(key, value, 0);
    lines.extend(emitted);
    Ok(join_lines(&lines, original))
}
