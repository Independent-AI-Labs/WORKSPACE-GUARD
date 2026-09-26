// src/yaml_edit_diff.rs
//
// Minimal unified diff for `workspace-yaml-edit --dry-run`
// (SPEC-YAML-EDIT section 6). LCS over lines, three lines of
// context, no external `diff` dependency.

/// Produce a unified diff of `old` -> `new` for display only.
pub fn unified(old: &str, new: &str, path: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let ops = diff_ops(&a, &b);
    let mut out = format!("--- a/{path}\n+++ b/{path}\n");
    const CTX: usize = 3;
    let mut i = 0;
    while i < ops.len() {
        if ops[i].0 == Op::Keep {
            i += 1;
            continue;
        }
        let start = i.saturating_sub(CTX);
        let mut end = i;
        while end + 1 < ops.len()
            && (ops[end + 1].0 != Op::Keep
                || ops[end + 1..]
                    .iter()
                    .take(2 * CTX + 1)
                    .any(|o| o.0 != Op::Keep))
        {
            end += 1;
        }
        let end = (end + CTX + 1).min(ops.len());
        let hunk = &ops[start..end];
        let a_start = hunk.iter().find_map(|o| o.1).map(|n| n + 1).unwrap_or(1);
        let b_start = hunk.iter().find_map(|o| o.2).map(|n| n + 1).unwrap_or(1);
        let a_len = hunk.iter().filter(|o| o.1.is_some()).count();
        let b_len = hunk.iter().filter(|o| o.2.is_some()).count();
        out.push_str(&format!("@@ -{a_start},{a_len} +{b_start},{b_len} @@\n"));
        for (op, ai, bi) in hunk {
            match op {
                Op::Keep => out.push_str(&format!(" {}\n", a[ai.unwrap_or(0)])),
                Op::Del => out.push_str(&format!("-{}\n", a[ai.unwrap_or(0)])),
                Op::Add => out.push_str(&format!("+{}\n", b[bi.unwrap_or(0)])),
            }
        }
        i = end;
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Keep,
    Del,
    Add,
}

/// Line op list: (op, old_line_index, new_line_index).
fn diff_ops(a: &[&str], b: &[&str]) -> Vec<(Op, Option<usize>, Option<usize>)> {
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut ops = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push((Op::Keep, Some(i), Some(j)));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            ops.push((Op::Del, Some(i), None));
            i += 1;
        } else {
            ops.push((Op::Add, None, Some(j)));
            j += 1;
        }
    }
    while i < n {
        ops.push((Op::Del, Some(i), None));
        i += 1;
    }
    while j < m {
        ops.push((Op::Add, None, Some(j)));
        j += 1;
    }
    ops
}
