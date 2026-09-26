// src/yaml_edit_shape.rs
//
// Shape layer of workspace-yaml-edit (SPEC-YAML-EDIT section 4).
// Block sequences are splice-editable only when every dash indent is
// strictly deeper than its parent key indent (the 2026-08-25 indentless
// defect: `yaml.safe_dump`-style files place dashes at the key indent,
// terminate the splice region immediately, and fail every list edit
// with "expected N entries, found none"). This layer measures that
// discipline, reports violations precisely, and produces the
// canonicalizing reindent. serde_yaml owns all meaning; this layer
// only measures indentation and inserts spaces. Comments, blank lines,
// key order, and scalar spelling survive byte-for-byte except for the
// inserted indentation (REQ-YE-103).

use crate::splice::{is_content, leading_spaces, parse_key_line};

/// A top-level block sequence whose dash items sit at or above its key
/// indent and is therefore not splice-editable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeViolation {
    pub key: String,
    /// 1-based line number of the offending first dash item.
    pub line: usize,
    pub key_indent: usize,
    pub dash_indent: usize,
}

impl ShapeViolation {
    pub fn message(&self, path: &str) -> String {
        format!(
            "{path}: key '{}' has an indentless block sequence \
             (dash indent {} <= key indent {} at line {}); \
             run: workspace-yaml-edit format <file>",
            self.key, self.dash_indent, self.key_indent, self.line
        )
    }
}

fn dash_item(line: &str) -> bool {
    let t = line.trim_start_matches(' ');
    is_content(line) && (t == "-" || t.starts_with("- "))
}

/// End of a key's block region: the first content line at or above the
/// key indent that is not itself a dash item or deeper item content.
/// For well-formed indented sequences this is the documented region
/// end; for indentless sequences the at-indent dash lines keep the
/// region open, which is exactly what measurement needs.
fn region_end_for_measure(lines: &[&str], key_line: usize, key_indent: usize) -> usize {
    let mut i = key_line + 1;
    while i < lines.len() {
        let l = lines[i];
        if is_content(l) && leading_spaces(l) <= key_indent && !dash_item(l) {
            break;
        }
        i += 1;
    }
    i
}

/// All top-level block-sequence keys whose minimum dash indent is not
/// strictly deeper than the key indent. Flow lists (`key: []`, `key:
/// [a, b]`) have no dash items and never violate.
pub fn indentless_lists(raw: &str) -> Vec<ShapeViolation> {
    let lines: Vec<&str> = raw.lines().collect();
    let base = lines
        .iter()
        .find(|l| is_content(l))
        .map(|l| leading_spaces(l))
        .unwrap_or(0);
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let Some(kl) = parse_key_line(l) else {
            continue;
        };
        if kl.indent != base {
            continue;
        }
        let rend = region_end_for_measure(&lines, i, kl.indent);
        let mut min_dash: Option<(usize, usize)> = None; // (indent, line)
        for (j, inner) in lines.iter().enumerate().take(rend).skip(i + 1) {
            if dash_item(inner) {
                let ind = leading_spaces(inner);
                if min_dash.is_none_or(|(m, _)| ind < m) {
                    min_dash = Some((ind, j));
                }
            }
        }
        if let Some((dash_indent, line)) = min_dash {
            if dash_indent <= kl.indent {
                out.push(ShapeViolation {
                    key: kl.key,
                    line: line + 1,
                    key_indent: kl.indent,
                    dash_indent,
                });
            }
        }
    }
    out
}

/// Canonicalizing reindent: within each violating key's region, every
/// dash item at exactly the key indent and every line deeper than the
/// key indent gains two spaces; comments and blank lines at the key
/// indent stay byte-identical. Returns None when the document already
/// satisfies the discipline.
pub fn reindent(raw: &str) -> Result<Option<String>, String> {
    let violations = indentless_lists(raw);
    if violations.is_empty() {
        return Ok(None);
    }
    let lines: Vec<&str> = raw.lines().collect();
    let base = lines
        .iter()
        .find(|l| is_content(l))
        .map(|l| leading_spaces(l))
        .unwrap_or(0);

    // (region_start, region_end, key_indent) for every violating key.
    let mut regions: Vec<(usize, usize, usize)> = Vec::new();
    for v in &violations {
        let key_line = lines
            .iter()
            .position(|l| {
                parse_key_line(l)
                    .is_some_and(|kl| kl.indent == base && kl.key == v.key && kl.rest.is_empty())
            })
            .ok_or_else(|| format!("cannot relocate key line for: {}", v.key))?;
        let rend = region_end_for_measure(&lines, key_line, v.key_indent);
        regions.push((key_line, rend, v.key_indent));
    }

    let shift = |l: &str| format!("  {l}");
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    for (i, l) in lines.iter().enumerate() {
        let region = regions.iter().find(|(s, e, _)| i > *s && i < *e);
        let Some((_, _, key_indent)) = region else {
            out.push((*l).to_string());
            continue;
        };
        let ind = leading_spaces(l);
        if is_content(l) && (ind == *key_indent && dash_item(l) || ind > *key_indent) {
            out.push(shift(l));
        } else {
            out.push((*l).to_string());
        }
    }
    let mut joined = out.join("\n");
    if raw.ends_with('\n') {
        joined.push('\n');
    }
    // Idempotence guard: the transform must leave no violations behind.
    if !indentless_lists(&joined).is_empty() {
        return Err("reindent left indentless sequences behind".to_string());
    }
    Ok(Some(joined))
}
