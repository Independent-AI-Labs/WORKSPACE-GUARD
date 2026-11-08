//! Shared inline-detection engine and sealed scanner entrypoint.
//!
//! The shell guard uses the engine for command and script text. The scanner
//! entrypoint serves WORKSPACE-CI file scans. Both use the one compiled rule
//! table from `config/shell_guard_policy.yaml`.

use std::collections::HashSet;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process;

use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

use crate::shell_config;

#[path = "inline_views.rs"]
mod views;

pub struct Rule {
    pub id: &'static str,
    re: Regex,
    pub hint: &'static str,
    pub category: &'static str,
    contexts: &'static str,
    mask: bool,
    pub exemptible: bool,
    pub mode: &'static str,
    pub reason: &'static str,
}

struct Construct {
    language: &'static str,
    level: u32,
    open: Option<Regex>,
    close: Option<Regex>,
    pattern: Option<Regex>,
    category: Option<&'static str>,
}

#[derive(Serialize)]
pub struct Finding {
    pub path: String,
    pub rule: &'static str,
    pub category: &'static str,
    pub line: usize,
    pub column: usize,
    pub view: &'static str,
    pub matched: String,
    pub reason: &'static str,
    pub hint: &'static str,
    pub block: bool,
    pub exemptible: bool,
}

fn compile_rules() -> Vec<Rule> {
    shell_config::INLINE_RULES
        .iter()
        .map(
            |(id, pat, hint, category, contexts, mask, exemptible, mode, reason)| Rule {
                id,
                re: Regex::new(pat).unwrap_or_else(|e| {
                    panic!("inline engine: pattern {:?} does not compile: {}", id, e)
                }),
                hint,
                category,
                contexts,
                mask: *mask,
                exemptible: *exemptible,
                mode,
                reason,
            },
        )
        .collect()
}

fn compile_constructs() -> Vec<Construct> {
    shell_config::INLINE_CONSTRUCTS
        .iter()
        .map(
            |(_id, language, level, open, close, pattern, category, _reason)| Construct {
                language,
                level: *level,
                open: (!open.is_empty()).then(|| compile_anchor(open)),
                close: (!close.is_empty()).then(|| compile_anchor(close)),
                pattern: (!pattern.is_empty()).then(|| compile_anchor(pattern)),
                category: (!category.is_empty()).then_some(*category),
            },
        )
        .collect()
}

fn compile_anchor(pattern: &str) -> Regex {
    regex::bytes::RegexBuilder::new(pattern)
        .multi_line(true)
        .build()
        .unwrap_or_else(|e| {
            panic!(
                "inline engine: construct {:?} does not compile: {}",
                pattern, e
            )
        })
}

fn context_applies(contexts: &str, context: &str) -> bool {
    contexts.split(',').any(|candidate| candidate == context)
}

fn mask(bytes: &[u8], constructs: &[Construct], language: &str) -> (Vec<u8>, Vec<&'static str>) {
    let mut masked = bytes.to_vec();
    let mut excluded = Vec::new();
    for construct in constructs.iter().filter(|c| c.language == language) {
        if let Some(category) = construct.category {
            excluded.push(category);
            continue;
        }
        if let (Some(open), Some(close)) = (&construct.open, &construct.close) {
            let mut cursor = 0;
            while let Some(found) = open.find_at(bytes, cursor) {
                let after_open = found.end();
                let end = match close.find_at(bytes, after_open) {
                    Some(close_match) => close_match.end(),
                    None => break,
                };
                for byte in &mut masked[found.start()..end] {
                    if *byte != b'\n' {
                        *byte = b' ';
                    }
                }
                cursor = end;
            }
            let _ = construct.level;
            continue;
        }
        if let Some(pattern) = &construct.pattern {
            for found in pattern.find_iter(bytes) {
                for byte in &mut masked[found.start()..found.end()] {
                    if *byte != b'\n' {
                        *byte = b' ';
                    }
                }
            }
        }
    }
    (masked, excluded)
}

fn position(text: &[u8], offset: usize) -> (usize, usize) {
    let line = text[..offset].iter().filter(|&&b| b == b'\n').count() + 1;
    let line_start = text[..offset]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |pos| pos + 1);
    (line, offset - line_start + 1)
}

pub fn scan_text(path: &str, text: &str, language: &str) -> Vec<Finding> {
    let rules = compile_rules();
    let constructs = compile_constructs();
    scan_with(path, text, language, &rules, &constructs)
}

fn scan_with(
    path: &str,
    text: &str,
    language: &str,
    rules: &[Rule],
    constructs: &[Construct],
) -> Vec<Finding> {
    scan_with_depth(
        path,
        text,
        language,
        rules,
        constructs,
        shell_config::INLINE_DECODE_DEPTH,
    )
}

fn scan_with_depth(
    path: &str,
    text: &str,
    language: &str,
    rules: &[Rule],
    constructs: &[Construct],
    depth: u32,
) -> Vec<Finding> {
    let (masked, excluded) = mask(text.as_bytes(), constructs, language);
    let masked_text = std::str::from_utf8(&masked).expect("mask preserves UTF-8 boundaries");
    let original_views = views::build_views(text, depth);
    let masked_views = views::build_views(masked_text, depth);
    let original = text.as_bytes();
    let mut seen = HashSet::new();
    let mut findings = Vec::new();
    for rule in rules {
        if !context_applies(rule.contexts, "file") {
            continue;
        }
        if excluded.contains(&rule.category) {
            continue;
        }
        let rule_views = if rule.mask {
            &masked_views
        } else {
            &original_views
        };
        for view in rule_views {
            for found in rule.re.find_iter(&view.data) {
                let start = view.offsets.get(found.start()).copied().unwrap_or(0);
                if !seen.insert((rule.id, start)) {
                    continue;
                }
                let (line, column) = position(original, start);
                let matched = String::from_utf8(view.data[found.start()..found.end()].to_vec())
                    .expect("inline engine: a regex match must fall on UTF-8 boundaries");
                findings.push(Finding {
                    path: path.to_string(),
                    rule: rule.id,
                    category: rule.category,
                    line,
                    column,
                    view: view.name,
                    matched,
                    reason: rule.reason,
                    hint: rule.hint,
                    block: rule.mode != "report",
                    exemptible: rule.exemptible,
                });
            }
        }
    }
    findings
}

#[derive(Deserialize)]
struct Request {
    schema: u32,
    files: Vec<FileEntry>,
}

#[derive(Deserialize)]
struct FileEntry {
    path: String,
    language: String,
}

#[derive(Serialize)]
struct Response {
    schema: u32,
    findings: Vec<Finding>,
}

pub fn is_scanner_invocation(args: &[OsString]) -> bool {
    args.first()
        .and_then(|arg| Path::new(arg).file_name())
        .and_then(|name| name.to_str())
        == Some("inline-scan")
}

fn fail(message: &str) -> ! {
    eprintln!("inline-scan: {}", message);
    process::exit(2);
}

fn read_input() -> String {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        fail("request is not valid UTF-8");
    }
    raw
}

pub fn run_scanner() -> ! {
    let request: Request = match serde_json::from_str(&read_input()) {
        Ok(request) => request,
        Err(error) => fail(&format!("invalid request: {}", error)),
    };
    if request.schema != 1 {
        fail(&format!("unsupported request schema {}", request.schema));
    }
    let mut findings = Vec::new();
    for entry in &request.files {
        let bytes = match std::fs::read(Path::new(&entry.path)) {
            Ok(bytes) => bytes,
            Err(error) => fail(&format!("cannot read {}: {}", entry.path, error)),
        };
        if bytes.contains(&0) {
            fail(&format!("{} contains a NUL byte", entry.path));
        }
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => fail(&format!("{} is not valid UTF-8", entry.path)),
        };
        findings.extend(scan_text(&entry.path, text, &entry.language));
    }
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if serde_json::to_writer(
        &mut out,
        &Response {
            schema: 1,
            findings,
        },
    )
    .is_err()
    {
        fail("cannot write response");
    }
    if out.write_all(b"\n").is_err() {
        fail("cannot write response");
    }
    process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    const INLINE: &str = concat!("python", " -c");

    fn rule(id: &'static str, pattern: &str, category: &'static str) -> Rule {
        Rule {
            id,
            re: Regex::new(pattern).unwrap(),
            hint: "hint",
            category,
            contexts: "file",
            mask: true,
            exemptible: true,
            mode: "block",
            reason: "reason",
        }
    }

    fn construct(
        language: &'static str,
        open: Option<&str>,
        close: Option<&str>,
        pattern: Option<&str>,
        category: Option<&'static str>,
    ) -> Construct {
        Construct {
            language,
            level: 1,
            open: open.map(compile_anchor),
            close: close.map(compile_anchor),
            pattern: pattern.map(compile_anchor),
            category,
        }
    }

    #[test]
    fn reports_rule_identity_and_position() {
        let rules = vec![rule("interp", INLINE, "interp")];
        let text = format!("first\n{} pass\n", INLINE);
        let findings = scan_with("a.py", &text, "python", &rules, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "interp");
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].column, 1);
    }

    #[test]
    fn masks_markdown_region() {
        let rules = vec![rule("interp", INLINE, "interp")];
        let constructs = vec![construct(
            "markdown",
            Some(r"^[ \t]{0,3}```"),
            Some(r"^[ \t]{0,3}```"),
            None,
            None,
        )];
        let text = format!("prose\n```\n{} pass\n```\n", INLINE);
        let findings = scan_with("a.md", &text, "markdown", &rules, &constructs);
        assert!(findings.is_empty());
    }

    #[test]
    fn masks_markdown_inline_span() {
        let rules = vec![rule("interp", INLINE, "interp")];
        let constructs = vec![construct("markdown", None, None, Some(r"`[^`\n]+`"), None)];
        let text = format!("use `{}` in prose\n", INLINE);
        let findings = scan_with("a.md", &text, "markdown", &rules, &constructs);
        assert!(findings.is_empty());
    }

    #[test]
    fn category_construct_excludes_only_its_category() {
        let rules = vec![
            rule("sql", "select", "sql"),
            rule("interp", INLINE, "interp"),
        ];
        let constructs = vec![construct("sql", None, None, None, Some("sql"))];
        let text = format!("select 1\n{} pass\n", INLINE);
        let findings = scan_with("a.sql", &text, "sql", &rules, &constructs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "interp");
    }

    #[test]
    fn normalized_view_removes_zero_width() {
        let rules = vec![rule("interp", INLINE, "interp")];
        let text = "python\u{200b} -c pass\n".to_string();
        let findings = scan_with_depth("a.txt", &text, "text", &rules, &[], 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].view, "normalized");
    }

    #[test]
    fn decoded_hex_view_matches() {
        let rules = vec![rule("sql", "select from", "sql")];
        let findings = scan_with_depth("a.txt", "73656c6563742066726f6d", "text", &rules, &[], 2);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].view, "decoded");
    }

    #[test]
    fn normalized_percent_escape_matches() {
        let rules = vec![rule("sql", "select from", "sql")];
        let text = "%73%65%6c%65%63%74%20%66%72%6f%6d";
        let findings = scan_with_depth("a.txt", text, "text", &rules, &[], 2);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].view, "normalized");
    }
}
