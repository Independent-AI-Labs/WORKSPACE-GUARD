// Shell-guard codegen for build.rs.
//
// Parses config/shell_guard_policy.yaml into the compiled
// SHELL_PATTERNS table and validates config/shell_guard_policy_matrix.yaml
// against it (build fails on disagreement). The generated file contains
// ONLY the `pub const SHELL_PATTERNS: &[(&str, &str, &str, &str, &str)]`
// literal (id, regex, hint, scope, mode).
//
// `mode` is `block` (default: terminate the command) or `report` (log
// and notify, then continue; report hits never change exit status).

use std::env;
use std::fs;
use std::path::Path;

use serde::Deserialize;

fn default_scope() -> String {
    "both".to_string()
}

fn default_ctx() -> String {
    "command".to_string()
}

fn default_mode() -> String {
    "block".to_string()
}

fn default_category() -> String {
    "inline".to_string()
}

fn default_mask() -> bool {
    true
}

fn default_exemptible() -> bool {
    true
}

#[derive(Deserialize)]
struct ShellPolicyFile {
    #[serde(default = "crate::default_version")]
    _version: u32,
    patterns: Vec<ShellPattern>,
    #[serde(default)]
    allowed_constructs: Vec<AllowedConstruct>,
    #[serde(default)]
    decode: Option<DecodeConfig>,
}

#[derive(Deserialize)]
struct DecodeConfig {
    #[serde(default)]
    max_depth: u32,
}

#[derive(Deserialize)]
struct AllowedConstruct {
    id: String,
    language: String,
    #[serde(default = "default_level")]
    level: u32,
    #[serde(default)]
    open: String,
    #[serde(default)]
    close: String,
    #[serde(default)]
    pattern: String,
    #[serde(default)]
    category: String,
    reason: String,
}

fn default_level() -> u32 {
    1
}

#[derive(Deserialize)]
struct ShellPattern {
    id: String,
    regex: String,
    hint: String,
    #[serde(default = "default_scope")]
    scope: String,
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default = "default_category")]
    category: String,
    #[serde(default)]
    contexts: Option<Vec<String>>,
    #[serde(default = "default_mask")]
    mask: bool,
    #[serde(default = "default_exemptible")]
    exemptible: bool,
    #[serde(default)]
    reason: Option<String>,
}

fn scope_contexts(scope: &str) -> Vec<&'static str> {
    match scope {
        "both" => vec!["command", "script", "file"],
        "command" => vec!["command"],
        "script" | "untrusted-script" => vec!["script"],
        "file" => vec!["file"],
        _ => vec![],
    }
}

fn valid_context(context: &str) -> bool {
    matches!(context, "file" | "command" | "script")
}

fn effective_contexts(p: &ShellPattern) -> Vec<String> {
    match &p.contexts {
        Some(contexts) => contexts.clone(),
        None => scope_contexts(&p.scope)
            .into_iter()
            .map(str::to_string)
            .collect(),
    }
}

#[derive(Deserialize)]
struct ShellMatrixFile {
    #[serde(default = "crate::default_version")]
    _version: u32,
    cases: Vec<ShellMatrixCase>,
}

#[derive(Deserialize)]
struct ShellMatrixCase {
    id: String,
    #[allow(dead_code)]
    input: String,
    expect: String,
    rule: Option<String>,
    #[serde(default = "default_ctx")]
    #[allow(dead_code)]
    ctx: String,
}

pub fn emit_shell_guard_config(manifest: &Path, nofile_limit: u64, inline_path: &Path) {
    let config_dir = manifest.join("config");
    let policy_text = fs::read_to_string(config_dir.join("shell_guard_policy.yaml"))
        .expect("build.rs: failed to read shell_guard_policy.yaml");
    let mut policy: ShellPolicyFile = noyalib::compat::serde_yaml::from_str(&policy_text)
        .expect("build.rs: failed to parse shell_guard_policy.yaml");
    let inline_text = fs::read_to_string(inline_path).unwrap_or_else(|e| {
        panic!(
            "build.rs: failed to read inline policy {}: {}",
            inline_path.display(),
            e
        )
    });
    let inline: ShellPolicyFile = noyalib::compat::serde_yaml::from_str(&inline_text)
        .unwrap_or_else(|e| {
            panic!(
                "build.rs: failed to parse inline policy {}: {}",
                inline_path.display(),
                e
            )
        });
    policy.patterns.extend(inline.patterns);
    policy.allowed_constructs.extend(inline.allowed_constructs);
    if inline.decode.is_some() {
        policy.decode = inline.decode;
    }
    let matrix_text = fs::read_to_string(config_dir.join("shell_guard_policy_matrix.yaml"))
        .expect("build.rs: failed to read shell_guard_policy_matrix.yaml");
    let matrix: ShellMatrixFile = noyalib::compat::serde_yaml::from_str(&matrix_text)
        .expect("build.rs: failed to parse shell_guard_policy_matrix.yaml");

    assert!(
        !policy.patterns.is_empty(),
        "build.rs: shell_guard_policy.yaml has no patterns"
    );
    let mut seen = std::collections::HashSet::new();
    for p in &policy.patterns {
        assert!(
            seen.insert(p.id.clone()),
            "build.rs: duplicate shell-guard pattern id {:?}",
            p.id
        );
        assert!(
            !p.regex.is_empty() && !p.hint.is_empty(),
            "build.rs: shell-guard pattern {:?} needs non-empty regex and hint",
            p.id
        );
        assert!(
            p.scope == "command"
                || p.scope == "script"
                || p.scope == "untrusted-script"
                || p.scope == "both"
                || p.scope == "file",
            "build.rs: shell-guard pattern {:?} has invalid scope {:?} (command|script|untrusted-script|both|file)",
            p.id,
            p.scope
        );
        assert!(
            p.mode == "block" || p.mode == "report",
            "build.rs: shell-guard pattern {:?} has invalid mode {:?} (block|report)",
            p.id,
            p.mode
        );
        assert!(
            !p.category.is_empty(),
            "build.rs: shell-guard pattern {:?} has an empty category",
            p.id
        );
        if let Some(contexts) = &p.contexts {
            assert!(
                !contexts.is_empty(),
                "build.rs: shell-guard pattern {:?} declares no contexts",
                p.id
            );
            for context in contexts {
                assert!(
                    valid_context(context),
                    "build.rs: shell-guard pattern {:?} has invalid context {:?} (file|command|script)",
                    p.id,
                    context
                );
            }
        }
        regex::bytes::Regex::new(&p.regex).unwrap_or_else(|e| {
            panic!(
                "build.rs: shell-guard pattern {:?} does not compile: {}",
                p.id, e
            )
        });
    }
    let mut construct_ids = std::collections::HashSet::new();
    for c in &policy.allowed_constructs {
        assert!(
            construct_ids.insert(c.id.clone()),
            "build.rs: duplicate allowed-construct id {:?}",
            c.id
        );
        assert!(
            !c.language.is_empty() && !c.reason.is_empty(),
            "build.rs: allowed construct {:?} needs language and reason",
            c.id
        );
        assert!(
            c.level >= 1,
            "build.rs: allowed construct {:?} has level 0",
            c.id
        );
        let region = !c.open.is_empty() || !c.close.is_empty();
        let token = !c.pattern.is_empty();
        let category = !c.category.is_empty();
        let selectors = region as u8 + token as u8 + category as u8;
        assert!(
            selectors == 1,
            "build.rs: allowed construct {:?} needs exactly one region, token, or category selector",
            c.id
        );
        if region {
            assert!(
                !c.open.is_empty() && !c.close.is_empty(),
                "build.rs: allowed construct {:?} needs both open and close",
                c.id
            );
            for pat in [&c.open, &c.close] {
                regex::bytes::Regex::new(pat).unwrap_or_else(|e| {
                    panic!(
                        "build.rs: allowed construct {:?} region does not compile: {}",
                        c.id, e
                    )
                });
            }
        }
        if token {
            regex::bytes::Regex::new(&c.pattern).unwrap_or_else(|e| {
                panic!(
                    "build.rs: allowed construct {:?} token does not compile: {}",
                    c.id, e
                )
            });
        }
    }
    if let Some(decode) = &policy.decode {
        assert!(
            decode.max_depth <= 8,
            "build.rs: decode.max_depth {} exceeds 8",
            decode.max_depth
        );
    }

    for case in &matrix.cases {
        assert!(
            case.expect == "blocked" || case.expect == "allowed" || case.expect == "reported",
            "build.rs: shell matrix case {:?} has invalid expect {:?}",
            case.id,
            case.expect
        );
        assert!(
            case.ctx == "command" || case.ctx == "script" || case.ctx == "untrusted-script",
            "build.rs: shell matrix case {:?} has invalid ctx {:?} (command|script)",
            case.id,
            case.ctx
        );
        if let Some(rule) = &case.rule {
            assert!(
                seen.contains(rule),
                "build.rs: shell matrix case {:?} references unknown rule {:?}",
                case.id,
                rule
            );
        }
    }
    for p in &policy.patterns {
        if p.scope == "file" {
            continue;
        }
        let want = if p.mode == "report" {
            "reported"
        } else {
            "blocked"
        };
        assert!(
            matrix.cases.iter().any(|c| {
                c.expect == want
                    && c.rule.as_deref() == Some(p.id.as_str())
                    && (p.scope == "both" || p.scope == c.ctx)
            }),
            "build.rs: shell-guard pattern {:?} (mode {:?}) has no {:?} matrix case in a context its scope {:?} applies to",
            p.id,
            p.mode,
            want,
            p.scope
        );
    }

    let mut code = String::from(
        "// Auto-generated by build.rs from config/shell_guard_policy.yaml. DO NOT EDIT.\n",
    );
    code.push_str("pub const SHELL_PATTERNS: &[(&str, &str, &str, &str, &str)] = &[\n");
    for p in &policy.patterns {
        code.push_str(&format!(
            "    ({:?}, {:?}, {:?}, {:?}, {:?}),\n",
            p.id, p.regex, p.hint, p.scope, p.mode
        ));
    }
    code.push_str("];\n");

    code.push_str(
        "pub type InlineRuleDef = (&'static str, &'static str, &'static str, &'static str, &'static str, bool, bool, &'static str, &'static str);\n",
    );
    code.push_str("pub const INLINE_RULES: &[InlineRuleDef] = &[\n");
    for p in &policy.patterns {
        let reason = p.reason.as_deref().unwrap_or(&p.hint);
        code.push_str(&format!(
            "    ({:?}, {:?}, {:?}, {:?}, {:?}, {}, {}, {:?}, {:?}),\n",
            p.id,
            p.regex,
            p.hint,
            p.category,
            effective_contexts(p).join(","),
            p.mask,
            p.exemptible,
            p.mode,
            reason
        ));
    }
    code.push_str("];\n");

    code.push_str(
        "pub type InlineConstructDef = (&'static str, &'static str, u32, &'static str, &'static str, &'static str, &'static str, &'static str);\n",
    );
    code.push_str("pub const INLINE_CONSTRUCTS: &[InlineConstructDef] = &[\n");
    for c in &policy.allowed_constructs {
        code.push_str(&format!(
            "    ({:?}, {:?}, {}, {:?}, {:?}, {:?}, {:?}, {:?}),\n",
            c.id, c.language, c.level, c.open, c.close, c.pattern, c.category, c.reason
        ));
    }
    code.push_str("];\n");

    let decode_depth = policy.decode.as_ref().map_or(0, |d| d.max_depth);
    code.push_str(&format!(
        "pub const INLINE_DECODE_DEPTH: u32 = {};\n",
        decode_depth
    ));

    code.push_str("// --- git_guard_resource_limits.yaml ---\n");
    code.push_str(&format!(
        "pub const NOFILE_LIMIT: u64 = {};\n",
        nofile_limit
    ));

    let out_dir = env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out_dir).join("shell_guard_config.rs"), code).unwrap();

    println!("cargo:rerun-if-changed=config/shell_guard_policy.yaml");
    println!("cargo:rerun-if-changed=config/shell_guard_policy_matrix.yaml");
    println!("cargo:rerun-if-changed=config/git_guard_resource_limits.yaml");
}
