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

#[derive(Debug, Serialize)]
pub struct Finding {
    pub path: String,
    pub rule: String,
    pub category: String,
    pub line: usize,
    pub column: usize,
    pub view: String,
    pub matched: String,
    pub reason: String,
    pub hint: String,
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
                    rule: rule.id.to_string(),
                    category: rule.category.to_string(),
                    line,
                    column,
                    view: view.name.to_string(),
                    matched,
                    reason: rule.reason.to_string(),
                    hint: rule.hint.to_string(),
                    block: rule.mode != "report",
                    exemptible: rule.exemptible,
                });
            }
        }
    }
    findings
}

#[derive(Debug, Serialize)]
struct ViewOut {
    name: String,
    text: String,
    offsets: Vec<usize>,
}

#[derive(Debug, Serialize)]
struct FileViews {
    path: String,
    views: Vec<ViewOut>,
}

#[derive(Deserialize)]
struct Request {
    schema: u32,
    files: Vec<FileEntry>,
    #[serde(default)]
    decode_depth: Option<u32>,
}

#[derive(Deserialize)]
struct FileEntry {
    path: String,
    language: String,
}

#[derive(Debug, Serialize)]
struct Response {
    schema: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    findings: Option<Vec<Finding>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    files: Option<Vec<FileViews>>,
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

fn process_request(raw: &str) -> Result<Response, String> {
    let request: Request =
        serde_json::from_str(raw).map_err(|error| format!("invalid request: {}", error))?;
    let schema = request.schema;
    if schema != 1 && schema != 2 {
        return Err(format!("unsupported request schema {}", schema));
    }
    let depth = request.decode_depth.unwrap_or(0);
    let mut findings = Vec::new();
    let mut file_views = Vec::new();
    for entry in &request.files {
        let bytes = std::fs::read(Path::new(&entry.path))
            .map_err(|error| format!("cannot read {}: {}", entry.path, error))?;
        if bytes.contains(&0) {
            return Err(format!("{} contains a NUL byte", entry.path));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| format!("{} is not valid UTF-8", entry.path))?;
        if schema == 1 {
            findings.extend(scan_text(&entry.path, text, &entry.language));
        } else {
            let views = views::build_views(text, depth)
                .into_iter()
                .map(|view| ViewOut {
                    name: view.name.to_string(),
                    text: String::from_utf8(view.data)
                        .expect("inline scanner: a view must remain valid UTF-8"),
                    offsets: view.offsets,
                })
                .collect();
            file_views.push(FileViews {
                path: entry.path.clone(),
                views,
            });
        }
    }
    Ok(Response {
        schema,
        findings: (schema == 1).then_some(findings),
        files: (schema == 2).then_some(file_views),
    })
}

pub fn run_scanner() -> ! {
    let response = match process_request(&read_input()) {
        Ok(response) => response,
        Err(message) => fail(&message),
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if serde_json::to_writer(&mut out, &response).is_err() {
        fail("cannot write response");
    }
    if out.write_all(b"\n").is_err() {
        fail("cannot write response");
    }
    process::exit(0);
}

#[cfg(test)]
#[path = "inline_tests.rs"]
mod tests;
