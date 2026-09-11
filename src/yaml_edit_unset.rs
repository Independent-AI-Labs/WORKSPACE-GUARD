use crate::yaml_edit_engine::Access;
use crate::yaml_edit_splice::{is_content, leading_spaces, parse_key_line};

#[derive(Clone, Copy)]
struct Region {
    start: usize,
    end: usize,
    indent: usize,
}

#[derive(Clone, Copy)]
struct Located {
    line: usize,
    end: usize,
    indent: usize,
    dash: bool,
}

fn key_line(line: &str) -> Option<(crate::yaml_edit_splice::KeyLine, bool)> {
    if let Some(parsed) = parse_key_line(line) {
        return Some((parsed, false));
    }
    let indent = leading_spaces(line);
    let text = &line[indent..];
    let rest = text.strip_prefix("- ")?;
    let synthetic = format!("{}{}", " ".repeat(indent + 2), rest);
    parse_key_line(&synthetic).map(|parsed| (parsed, true))
}

fn node_end(lines: &[&str], line: usize, indent: usize) -> usize {
    let mut end = line;
    for (i, candidate) in lines.iter().enumerate().skip(line + 1) {
        if is_content(candidate) && leading_spaces(candidate) <= indent {
            break;
        }
        end = i;
    }
    end
}

fn find_key(lines: &[&str], region: Region, key: &str) -> Result<Located, String> {
    for (line, text) in lines.iter().enumerate().take(region.end).skip(region.start) {
        let Some((parsed, dash)) = key_line(text) else {
            continue;
        };
        if parsed.indent == region.indent && parsed.key == key {
            let end = if parsed.rest.is_empty() {
                node_end(lines, line, parsed.indent)
            } else {
                line
            };
            return Ok(Located {
                line,
                end,
                indent: parsed.indent,
                dash,
            });
        }
    }
    Err(format!("cannot locate field line for: {key}"))
}

fn sequence_item(lines: &[&str], region: Region, index: usize) -> Result<Region, String> {
    let mut starts = Vec::new();
    for (line, text) in lines.iter().enumerate().take(region.end).skip(region.start) {
        let trimmed = text.trim_start_matches(' ');
        if is_content(text) && (trimmed == "-" || trimmed.starts_with("- ")) {
            starts.push((line, leading_spaces(text)));
        }
    }
    let indent = starts
        .iter()
        .map(|(_, indent)| *indent)
        .min()
        .ok_or_else(|| "wildcard sequence has no line items".to_string())?;
    let direct: Vec<_> = starts.into_iter().filter(|(_, i)| *i == indent).collect();
    let (start, _) = direct
        .get(index)
        .copied()
        .ok_or_else(|| format!("cannot locate wildcard item {index}"))?;
    let end = direct.get(index + 1).map(|v| v.0).unwrap_or(region.end);
    Ok(Region {
        start,
        end,
        indent: indent + 2,
    })
}

fn locate(lines: &[&str], path: &[Access]) -> Result<Located, String> {
    let root_indent = lines
        .iter()
        .find(|line| is_content(line))
        .map(|line| leading_spaces(line))
        .unwrap_or(0);
    let mut region = Region {
        start: 0,
        end: lines.len(),
        indent: root_indent,
    };
    let mut current = None;
    for (position, access) in path.iter().enumerate() {
        match access {
            Access::Key(key) => {
                let found = find_key(lines, region, key)?;
                if position + 1 == path.len() {
                    return Ok(found);
                }
                region = Region {
                    start: found.line + 1,
                    end: found.end + 1,
                    indent: found.indent + 2,
                };
                current = Some(found);
            }
            Access::Index(index) => {
                let owner = current.ok_or_else(|| "index without sequence field".to_string())?;
                region = sequence_item(
                    lines,
                    Region {
                        start: owner.line + 1,
                        end: owner.end + 1,
                        indent: owner.indent + 2,
                    },
                    *index,
                )?;
            }
        }
    }
    Err("unset path did not end at a field".to_string())
}

fn dash_replacement(lines: &[&str], field: Located) -> (usize, Vec<String>) {
    let dash_indent = field.indent.saturating_sub(2);
    for text in lines.iter().skip(field.end + 1) {
        if !is_content(text) {
            continue;
        }
        if leading_spaces(text) == field.indent {
            return (field.end, vec![format!("{}-", " ".repeat(dash_indent))]);
        }
        if leading_spaces(text) < field.indent {
            break;
        }
    }
    (
        field.end,
        vec![format!("{}- {{}}", " ".repeat(dash_indent))],
    )
}

pub fn splice_unset(original: &str, paths: &[Vec<Access>]) -> Result<String, String> {
    let lines: Vec<&str> = original.lines().collect();
    let mut edits = Vec::new();
    for path in paths {
        let field = locate(&lines, path)?;
        let (end, replacement) = if field.dash {
            dash_replacement(&lines, field)
        } else {
            (field.end, Vec::new())
        };
        edits.push((field.line, end, replacement));
    }
    edits.sort_by_key(|edit| edit.0);
    for pair in edits.windows(2) {
        if pair[0].1 >= pair[1].0 {
            return Err("overlapping unset fields cannot be spliced safely".to_string());
        }
    }
    let mut out: Vec<String> = lines.iter().map(|line| line.to_string()).collect();
    for (start, end, replacement) in edits.into_iter().rev() {
        out.splice(start..=end, replacement);
    }
    Ok(out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::splice_unset;
    use crate::yaml_edit_engine;
    use crate::yaml_edit_target::normalize_terminal;
    use serde_yaml::Value;

    #[test]
    fn wildcard_splice_preserves_unrelated_bytes_and_valid_yaml() {
        let raw = "# header\nhooks:\n  - id: one # keep\n    safety: true\n    mandatory: true\n\n  - id: two\n    safety: false\n    mandatory: false\nother: 1\n\n";
        let doc: Value = serde_yaml::from_str(raw).expect("parse");
        let (expected, concrete) =
            yaml_edit_engine::unset_fields(&doc, "hooks[].safety").expect("semantic unset");
        let out = normalize_terminal(&splice_unset(raw, &concrete).expect("splice"));
        assert!(out.contains("# header\n"));
        assert!(out.contains("  - id: one # keep\n"));
        assert!(out.contains("    mandatory: true\n"));
        assert!(!out.contains("safety:"));
        assert_eq!(
            serde_yaml::from_str::<Value>(&out).expect("valid"),
            expected
        );
        assert!(out.ends_with("other: 1\n"));
    }

    #[test]
    fn dotted_map_splice_removes_only_the_field() {
        let raw = "outer:\n  remove: true\n  keep: 1\n";
        let doc: Value = serde_yaml::from_str(raw).expect("parse");
        let (expected, concrete) =
            yaml_edit_engine::unset_fields(&doc, "outer.remove").expect("unset");
        let out = normalize_terminal(&splice_unset(raw, &concrete).expect("splice"));
        assert_eq!(out, "outer:\n  keep: 1\n");
        assert_eq!(
            serde_yaml::from_str::<Value>(&out).expect("valid"),
            expected
        );
    }
}
