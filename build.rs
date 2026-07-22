use std::env;
use std::fs;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Deserialize;

fn default_version() -> u32 {
    1
}

#[derive(Deserialize)]
struct PolicyMatrixCase {
    id: String,
    argv: Vec<String>,
    expect: String,
}

#[derive(Deserialize)]
struct PolicyMatrixConfig {
    #[serde(default = "default_version")]
    _version: u32,
    cases: Vec<PolicyMatrixCase>,
}

#[derive(Deserialize)]
struct SubcommandsConfig {
    #[serde(default = "default_version")]
    _version: u32,
    blocked: Vec<String>,
    #[serde(default)]
    sudo_gated: Vec<String>,
    partial: Vec<String>,
    contract_check: Vec<String>,
}

#[derive(Deserialize)]
struct ConfigKeysConfig {
    #[serde(default = "default_version")]
    _version: u32,
    dangerous: Vec<String>,
    sudo_gated: Vec<String>,
    value_taking_opts: Vec<String>,
}

#[derive(Deserialize)]
struct ProtectedBranchesConfig {
    #[serde(default = "default_version")]
    _version: u32,
    branches: Vec<String>,
    prefixes: Vec<String>,
}

#[derive(Deserialize)]
struct GitSshAllowlistConfig {
    #[serde(default = "default_version")]
    _version: u32,
    hosts: Vec<String>,
    users: Vec<String>,
}

fn valid_host_or_user(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

#[derive(Deserialize)]
struct EnvironmentConfig {
    #[serde(default = "default_version")]
    _version: u32,
    allowed: Vec<String>,
    sudo_gated_identity: Vec<String>,
    sudo_gated_editor: Vec<String>,
    blocked_bypass: Vec<String>,
}

#[derive(Deserialize)]
struct ResourceLimitsConfig {
    #[serde(default = "default_version")]
    _version: u32,
    nofile: u64,
    core: u64,
    contract_timeout_ms: u64,
    contract_poll_ms: u64,
}

#[derive(Deserialize)]
struct LockedPathsConfig {
    #[serde(default = "default_version")]
    _version: u32,
    recursive_tree_paths: Vec<String>,
    #[serde(default)]
    recursive_tree_glob_patterns: Vec<String>,
    individual_file_paths: std::collections::HashMap<String, u32>,
    glob_patterns: std::collections::HashMap<String, u32>,
    #[serde(default)]
    absolute_file_paths: std::collections::HashMap<String, u32>,
    #[serde(default)]
    prune_dir_names: Vec<String>,
}

// --- binary-guard codegen structs ----------------------------------------
// These are ONLY used to deserialize res/binary-lock.yaml into a form that
// build.rs can emit as a const literal. The runtime structs (BinaryPolicy,
// RejectRule, RejectKind) live in src/binary_policy_types.rs and are never
// emitted by build.rs. The generated file contains ONLY the
// `pub const BINARY_POLICIES: &[BinaryPolicy] = &[ ... ];` literal.

#[derive(Deserialize)]
struct BinaryLockFile {
    #[serde(default = "default_version")]
    _version: u32,
    binaries: Vec<BinaryLockEntry>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct BinaryLockEntry {
    name: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    contained: bool,
    policy: String,
    #[serde(default)]
    allow_subcommands: Vec<String>,
    #[serde(default)]
    allow_self_username: bool,
    #[serde(default)]
    reject_patterns: Vec<RejectPatternYaml>,
    #[serde(default)]
    env_sanitise: Vec<String>,
}

#[derive(Deserialize)]
struct RejectPatternYaml {
    kind: String,
    #[serde(default)]
    flag: Option<String>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    subcommand: Option<String>,
    #[serde(default)]
    requires_flags: Vec<String>,
    reason: String,
}

#[derive(Deserialize)]
struct PathsConfig {
    #[serde(default = "default_version")]
    _version: u32,
    log_file: String,
    child_path: String,
    contract_script: String,
    enforcement_config: String,
    workspace_markers: Vec<String>,
}

fn read_yaml<T: DeserializeOwned>(config_dir: &Path, name: &str) -> T {
    let path = config_dir.join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("build.rs: failed to read {}: {}", path.display(), e));
    serde_yaml::from_str(&text)
        .unwrap_or_else(|e| panic!("build.rs: failed to parse {}: {}", path.display(), e))
}

fn emit_str_list(buf: &mut String, name: &str, items: &[String]) {
    if items.is_empty() {
        buf.push_str(&format!("pub const {}: &[&str] = &[];\n", name));
        return;
    }
    buf.push_str(&format!("pub const {}: &[&str] = &[\n", name));
    for item in items {
        buf.push_str(&format!("    {:?},\n", item));
    }
    buf.push_str("];\n\n");
}

fn emit_str_u32_pairs(buf: &mut String, name: &str, pairs: &[(&str, u32)]) {
    if pairs.is_empty() {
        buf.push_str(&format!("pub const {}: &[(&str, u32)] = &[];\n", name));
        return;
    }
    buf.push_str(&format!("pub const {}: &[(&str, u32)] = &[\n", name));
    for (s, n) in pairs {
        buf.push_str(&format!("    ({:?}, 0o{:o}),\n", s, n));
    }
    buf.push_str("];\n\n");
}

fn emit_str(buf: &mut String, name: &str, val: &str) {
    buf.push_str(&format!("pub const {}: &str = {:?};\n", name, val));
}

fn emit_u64(buf: &mut String, name: &str, val: u64) {
    buf.push_str(&format!("pub const {}: u64 = {};\n", name, val));
}

fn validate_policy_matrix(subcommands: &SubcommandsConfig, matrix: &PolicyMatrixConfig) {
    let mut covered: std::collections::HashSet<String> = std::collections::HashSet::new();
    for case in &matrix.cases {
        assert!(
            case.expect == "blocked" || case.expect == "allowed",
            "build.rs: policy matrix case {:?} has invalid expect {:?}",
            case.id,
            case.expect
        );
        if case.argv.is_empty() || case.argv[0] != "git" {
            panic!(
                "build.rs: policy matrix case {:?} argv must start with 'git'",
                case.id
            );
        }
        if let Some(sub) = case.argv.get(1) {
            if !sub.starts_with('-') {
                covered.insert(sub.clone());
            }
        }
    }

    for sub in subcommands
        .blocked
        .iter()
        .chain(subcommands.sudo_gated.iter())
        .chain(subcommands.partial.iter())
    {
        if !covered.contains(sub) {
            panic!(
                "build.rs: guard_policy_matrix.yaml missing case for subcommand {:?}",
                sub
            );
        }
    }
}

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let config_dir = Path::new(&manifest).join("config");

    let subcommands: SubcommandsConfig = read_yaml(&config_dir, "guard_subcommands.yaml");
    let policy_matrix: PolicyMatrixConfig = read_yaml(&config_dir, "guard_policy_matrix.yaml");
    validate_policy_matrix(&subcommands, &policy_matrix);
    let config_keys: ConfigKeysConfig = read_yaml(&config_dir, "guard_config_keys.yaml");
    let protected: ProtectedBranchesConfig =
        read_yaml(&config_dir, "guard_protected_branches.yaml");
    let environment: EnvironmentConfig = read_yaml(&config_dir, "guard_environment.yaml");
    let limits: ResourceLimitsConfig = read_yaml(&config_dir, "guard_resource_limits.yaml");
    let paths: PathsConfig = read_yaml(&config_dir, "guard_paths.yaml");
    let locked: LockedPathsConfig = read_yaml(&config_dir, "guard_locked_paths.yaml");

    let mut code = String::new();
    code.push_str("// Auto-generated by build.rs from config/guard_*.yaml. DO NOT EDIT.\n");
    code.push_str("// Edit the YAML source files and rebuild.\n\n");

    code.push_str("// --- guard_subcommands.yaml ---\n");
    emit_str_list(&mut code, "BLOCKED_SUBCOMMANDS", &subcommands.blocked);
    emit_str_list(&mut code, "SUDO_GATED_SUBCOMMANDS", &subcommands.sudo_gated);
    emit_str_list(
        &mut code,
        "SUBCOMMANDS_WITH_PARTIAL_BLOCKS",
        &subcommands.partial,
    );
    emit_str_list(
        &mut code,
        "CONTRACT_CHECK_SUBCOMMANDS",
        &subcommands.contract_check,
    );

    code.push_str("// --- guard_config_keys.yaml ---\n");
    emit_str_list(&mut code, "DANGEROUS_CONFIG_KEYS", &config_keys.dangerous);
    emit_str_list(&mut code, "SUDO_GATED_CONFIG_KEYS", &config_keys.sudo_gated);
    emit_str_list(
        &mut code,
        "VALUE_TAKING_OPTS",
        &config_keys.value_taking_opts,
    );

    code.push_str("// --- guard_protected_branches.yaml ---\n");
    emit_str_list(&mut code, "PROTECTED_BRANCHES", &protected.branches);
    emit_str_list(&mut code, "PROTECTED_BRANCH_PREFIXES", &protected.prefixes);

    code.push_str("// --- guard_environment.yaml ---\n");
    emit_str_list(&mut code, "ALLOWED_VARS", &environment.allowed);
    emit_str_list(
        &mut code,
        "SUDO_GATED_IDENTITY_ENV_VARS",
        &environment.sudo_gated_identity,
    );
    emit_str_list(
        &mut code,
        "SUDO_GATED_EDITOR_ENV_VARS",
        &environment.sudo_gated_editor,
    );
    emit_str_list(
        &mut code,
        "BLOCKED_BYPASS_VARS",
        &environment.blocked_bypass,
    );

    code.push_str("// --- guard_resource_limits.yaml ---\n");
    emit_u64(&mut code, "NOFILE_LIMIT", limits.nofile);
    emit_u64(&mut code, "CORE_LIMIT", limits.core);
    emit_u64(&mut code, "CONTRACT_TIMEOUT_MS", limits.contract_timeout_ms);
    emit_u64(&mut code, "CONTRACT_POLL_MS", limits.contract_poll_ms);
    code.push('\n');

    code.push_str("// --- guard_paths.yaml ---\n");
    emit_str(&mut code, "LOG_FILE", &paths.log_file);
    emit_str(&mut code, "CHILD_PATH", &paths.child_path);
    emit_str(&mut code, "CONTRACT_SCRIPT", &paths.contract_script);
    emit_str(&mut code, "ENFORCEMENT_CONFIG", &paths.enforcement_config);
    emit_str_list(&mut code, "WORKSPACE_MARKERS", &paths.workspace_markers);

    code.push_str("// --- guard_locked_paths.yaml ---\n");
    emit_str_list(
        &mut code,
        "LOCKED_RECURSIVE_TREE_PATHS",
        &locked.recursive_tree_paths,
    );
    emit_str_list(
        &mut code,
        "LOCKED_RECURSIVE_TREE_GLOB_PATTERNS",
        &locked.recursive_tree_glob_patterns,
    );
    let mut individual: Vec<(&str, u32)> = locked
        .individual_file_paths
        .iter()
        .map(|(k, v)| (k.as_str(), *v))
        .collect();
    individual.sort_by(|a, b| a.0.cmp(b.0));
    emit_str_u32_pairs(&mut code, "LOCKED_INDIVIDUAL_FILE_PATHS", &individual);
    let mut globs: Vec<(&str, u32)> = locked
        .glob_patterns
        .iter()
        .map(|(k, v)| (k.as_str(), *v))
        .collect();
    globs.sort_by(|a, b| a.0.cmp(b.0));
    emit_str_u32_pairs(&mut code, "LOCKED_GLOB_PATTERNS", &globs);
    emit_str_list(&mut code, "LOCK_PRUNE_DIR_NAMES", &locked.prune_dir_names);
    let mut absolute: Vec<(&str, u32)> = locked
        .absolute_file_paths
        .iter()
        .map(|(k, v)| (k.as_str(), *v))
        .collect();
    absolute.sort_by(|a, b| a.0.cmp(b.0));
    emit_str_u32_pairs(&mut code, "LOCKED_ABSOLUTE_FILE_PATHS", &absolute);

    let out_dir = env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out_dir).join("guard_config.rs"), code).unwrap();

    let ssh_allowlist: GitSshAllowlistConfig = read_yaml(&config_dir, "git_ssh_allowlist.yaml");
    if ssh_allowlist.hosts.is_empty() || ssh_allowlist.users.is_empty() {
        panic!("build.rs: git_ssh_allowlist.yaml needs non-empty hosts and users");
    }
    for entry in ssh_allowlist.hosts.iter().chain(ssh_allowlist.users.iter()) {
        if !valid_host_or_user(entry) {
            panic!("build.rs: git_ssh_allowlist.yaml bad entry {:?}", entry);
        }
    }
    let mut ssh_code =
        String::from("// Auto-generated by build.rs from config/git_ssh_allowlist.yaml.\n");
    emit_str_list(&mut ssh_code, "GIT_SSH_ALLOWED_HOSTS", &ssh_allowlist.hosts);
    emit_str_list(&mut ssh_code, "GIT_SSH_ALLOWED_USERS", &ssh_allowlist.users);
    fs::write(Path::new(&out_dir).join("git_ssh_config.rs"), ssh_code).unwrap();

    let config_files = [
        "guard_subcommands.yaml",
        "guard_policy_matrix.yaml",
        "guard_config_keys.yaml",
        "guard_protected_branches.yaml",
        "guard_environment.yaml",
        "guard_resource_limits.yaml",
        "guard_paths.yaml",
        "guard_locked_paths.yaml",
        "git_ssh_allowlist.yaml",
    ];
    for name in &config_files {
        println!("cargo:rerun-if-changed=config/{}", name);
    }

    // Binary-guard codegen. Gated on the cargo feature so the default git
    // guard build does not require res/binary-lock.yaml to exist. Emits
    // ONLY the BINARY_POLICIES const literal; no struct/fn/enum.
    if env::var_os("CARGO_FEATURE_BINARY_GUARD").is_some() {
        emit_binary_guard_config(Path::new(&manifest));
    }
}

/// Emit OUT_DIR/binary_policies.rs containing ONLY the
/// `pub const BINARY_POLICIES: &[BinaryPolicy] = &[ ... ];` literal.
///
/// The structs the literal references (BinaryPolicy, RejectRule, RejectKind)
/// are defined in hand-written src/binary_policy_types.rs. build.rs emits
/// no type definitions and no function bodies: baking logic into generated
/// strings breaks IDE support and diffs readably; the codegen smell this
/// split is designed to prevent.
fn emit_binary_guard_config(manifest: &Path) {
    let res_dir = manifest.join("res");
    let lock_path = res_dir.join("binary-lock.yaml");
    let text = fs::read_to_string(&lock_path).unwrap_or_else(|e| {
        panic!(
            "build.rs: failed to read {}: {}. Run `make sync-gtfobins` to regenerate. {}",
            lock_path.display(),
            e,
            "res/binary-lock.yaml is the generated build input for the binary guard.",
        )
    });
    let lock: BinaryLockFile = serde_yaml::from_str(&text)
        .unwrap_or_else(|e| panic!("build.rs: failed to parse {}: {}", lock_path.display(), e));

    let mut code = String::new();
    code.push_str("// Auto-generated by build.rs from res/binary-lock.yaml. DO NOT EDIT.\n");
    code.push_str("// Run `make sync-gtfobins` to regenerate. This file contains ONLY the\n");
    code.push_str("// BINARY_POLICIES const literal; the structs it references live in\n");
    code.push_str(
        "// src/binary_policy_types.rs (hand-written). build.rs emits no fn/struct/enum.\n\n",
    );
    code.push_str("pub const BINARY_POLICIES: &[BinaryPolicy] = &[\n");
    for b in &lock.binaries {
        code.push_str("    BinaryPolicy {\n");
        code.push_str(&format!("        name: {:?},\n", b.name));
        code.push_str(&format!("        policy: {},\n", policy_variant(&b.policy)));
        code.push_str("        allow_subcommands: &[");
        emit_str_literals_inline(&mut code, &b.allow_subcommands);
        code.push_str("],\n");
        code.push_str(&format!(
            "        allow_self_username: {},\n",
            b.allow_self_username
        ));
        code.push_str("        reject_patterns: &[\n");
        for rp in &b.reject_patterns {
            code.push_str("            RejectRule {\n");
            code.push_str(&format!(
                "                kind: {},\n",
                reject_kind_variant(&rp.kind)
            ));
            match &rp.flag {
                Some(f) => code.push_str(&format!("                flag: Some({:?}),\n", f)),
                None => code.push_str("                flag: None,\n"),
            }
            match &rp.pattern {
                Some(p) => code.push_str(&format!("                pattern: Some({:?}),\n", p)),
                None => code.push_str("                pattern: None,\n"),
            }
            match &rp.subcommand {
                Some(s) => code.push_str(&format!("                subcommand: Some({:?}),\n", s)),
                None => code.push_str("                subcommand: None,\n"),
            }
            code.push_str("                requires_flags: &[");
            emit_str_literals_inline(&mut code, &rp.requires_flags);
            code.push_str("],\n");
            code.push_str(&format!("                reason: {:?},\n", rp.reason));
            code.push_str("            },\n");
        }
        code.push_str("        ],\n");
        code.push_str("        env_sanitise: &[");
        emit_str_literals_inline(&mut code, &b.env_sanitise);
        code.push_str("],\n");
        code.push_str("    },\n");
    }
    code.push_str("];\n");

    let out_dir = env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out_dir).join("binary_policies.rs"), code).unwrap();
    println!("cargo:rerun-if-changed=res/binary-lock.yaml");
}

fn emit_str_literals_inline(buf: &mut String, items: &[String]) {
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            buf.push_str(", ");
        }
        buf.push_str(&format!("{:?}", item));
    }
}

/// Map a policy string from the YAML into the enum variant identifier emitted
/// in the generated const literal. A const context cannot call `from_str`, so
/// build.rs converts the wire string to the variant path at codegen time.
/// Panics on an unknown policy string (fail-closed at build time, not runtime).
fn policy_variant(s: &str) -> &'static str {
    match s {
        "deny-non-root" => "PolicyKind::DenyNonRoot",
        "deny-all-non-root" => "PolicyKind::DenyAllNonRoot",
        "arg-validate" => "PolicyKind::ArgValidate",
        "pass-through" => "PolicyKind::PassThrough",
        other => panic!(
            "build.rs: unknown policy string {:?} in res/binary-lock.yaml",
            other
        ),
    }
}

/// Map a reject-kind string from the YAML into the enum variant identifier.
fn reject_kind_variant(s: &str) -> &'static str {
    match s {
        "flag" => "RejectKind::Flag",
        "regex" => "RejectKind::Regex",
        other => panic!(
            "build.rs: unknown reject kind {:?} in res/binary-lock.yaml",
            other
        ),
    }
}
