//! Block-report rendering for the shell guard: match spans, sanitized
//! offending excerpts, and a process-ancestry origin trace. Block
//! decisions print this report to stderr (and the controlling tty) and
//! write the same excerpt to the audit log, so operators see exactly
//! which text fired which rule and who invoked it.

use std::fs;
use std::process;

use crate::Rule;

pub struct ScanHit<'r> {
    pub rule: &'r Rule,
    pub start: usize,
    pub end: usize,
}

fn scope_applies(scope: &str, context: &str) -> bool {
    scope == "both" || scope == context || (scope == "script" && context == "untrusted-script")
}

/// First rule matching `text`, with the byte span of the match so the
/// report can quote the offending excerpt instead of the whole body.
pub fn find_hit<'r>(text: &[u8], rules: &'r [Rule], context: &str) -> Option<ScanHit<'r>> {
    rules.iter().find_map(|r| {
        if !scope_applies(r.scope, context) {
            return None;
        }
        r.re.find(text).map(|m| ScanHit {
            rule: r,
            start: m.start(),
            end: m.end(),
        })
    })
}

/// Mask `key=value` words (potential secrets) and squash whitespace so
/// excerpts are single-line safe. Replaces single quotes with the
/// typographic quote to keep wrapper quoting unambiguous.
pub fn sanitize_cmd(text: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(text);
    let mut out = String::new();
    for word in lossy.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        if let Some(eq) = word.find('=') {
            let (k, _) = word.split_at(eq);
            if !k.is_empty()
                && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && k.bytes().next().is_some_and(|b| !b.is_ascii_digit())
            {
                out.push_str(k);
                out.push_str("=...");
                continue;
            }
        }
        out.push_str(word);
    }
    let out = out.replace('\'', "\u{2019}");
    if out.len() > 200 {
        out.chars().take(200).collect()
    } else {
        out
    }
}

/// Quote the offending region. Script bodies get a line-numbered window
/// (matching line plus one of context on each side, marker `>` on the
/// match); `-c` command text gets a single-line window around the span.
pub fn excerpt(text: &[u8], start: usize, end: usize, is_script: bool) -> String {
    if is_script {
        return script_excerpt(text, start);
    }
    let ctx = 60usize;
    let lo = start.saturating_sub(ctx);
    let hi = (end + ctx).min(text.len());
    let mut s = String::new();
    if lo > 0 {
        s.push_str("...");
    }
    s.push_str(&sanitize_cmd(&text[lo..hi]));
    if hi < text.len() {
        s.push_str("...");
    }
    format!("       {}", s)
}

fn script_excerpt(text: &[u8], start: usize) -> String {
    let match_line = text[..start].iter().filter(|&&b| b == b'\n').count();
    let mut out = String::new();
    for (idx, line) in text.split(|&b| b == b'\n').enumerate() {
        if idx + 1 < match_line || idx > match_line + 1 {
            continue;
        }
        let marker = if idx == match_line { '>' } else { ' ' };
        let rendered = sanitize_cmd(line);
        out.push_str(&format!("  {}  {:4} | {}\n", marker, idx + 1, rendered));
    }
    out.trim_end().to_string()
}

/// Process-ancestry trace: pid, ppid chain walked from /proc (bounded
/// to 8 levels), plus uid and cwd. This is the guard equivalent of a
/// stack trace: it names every process between the operator and the
/// offending invocation.
pub fn origin() -> String {
    let uid = nix::unistd::getuid().as_raw();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "?".to_string());
    let mut chain = String::new();
    let mut pid = process::id();
    for _ in 0..8 {
        let status = match fs::read_to_string(format!("/proc/{}/status", pid)) {
            Ok(s) => s,
            Err(_) => break,
        };
        let name = status
            .lines()
            .find_map(|l| l.strip_prefix("Name:"))
            .map(str::trim)
            .unwrap_or("?");
        let cmdline = fs::read(format!("/proc/{}/cmdline", pid))
            .map(|b| {
                let flat: Vec<u8> = b
                    .into_iter()
                    .map(|c| if c == 0 { b' ' } else { c })
                    .collect();
                let s = String::from_utf8_lossy(&flat).trim().to_string();
                if s.chars().count() > 120 {
                    s.chars().take(120).collect()
                } else {
                    s
                }
            })
            .unwrap_or_default();
        if !chain.is_empty() {
            chain.push_str(" <- ");
        }
        chain.push_str(&format!("{}({})", pid, name));
        if !cmdline.is_empty() {
            chain.push_str(&format!(" [{}]", cmdline));
        }
        let ppid: u32 = match status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .and_then(|v| v.trim().parse().ok())
        {
            Some(p) if p > 0 => p,
            _ => break,
        };
        pid = ppid;
    }
    format!("uid={} cwd={} chain={}", uid, cwd, chain)
}

/// Collapse an excerpt to a single audit-log line.
pub fn flatten(text: &str) -> String {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > 200 {
        flat.chars().take(200).collect()
    } else {
        flat
    }
}

pub fn block_report(rule: &Rule, display: &str, excerpt: &str, ts: &str) -> String {
    format!(
        "BLOCKED: {} ({}) ({})\n  -> Hint: {}\n  -> Offending excerpt:\n{}\n  -> Origin: {}",
        display,
        rule.id,
        ts,
        rule.hint,
        excerpt,
        origin()
    )
}

/// fd/pipe-delivered script sources carry real content that never
/// touches a regular file, so they must never execute unscanned.
pub fn fd_block_report(path: &str, ts: &str) -> String {
    format!(
        "BLOCKED: bash {} (fd-script-source) ({})\n  -> Hint: run the script from a regular file path; fd/pipe delivery is unscannable and is never executed (only sealed guard-staged memfd sources are accepted)\n  -> Origin: {}",
        path,
        ts,
        origin()
    )
}
