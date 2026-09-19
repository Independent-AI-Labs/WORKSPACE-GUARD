use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Deserialize;

mod build_binary_guard;
mod build_shell_guard;

pub(crate) fn default_version() -> u32 {
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
    /// Read-only subcommands eligible for dangerous-config sanitization
    /// (REQ-GGUARD-043). Empty until the operator populates it: the
    /// compiled empty list keeps today's block-everything behavior.
    #[serde(default)]
    read_only: Vec<String>,
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

// The binary-guard codegen structs and emit logic live in
// build_binary_guard.rs (keeps build.rs under the 512-line gate).

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

/// Emit glob patterns pre-split on '.' and pre-lowercased as
/// `&[&[&str]]` so the runtime matcher never splits or lowercases per
/// call (F18). Patterns with more than one `**` are build-fatal: the
/// runtime matcher is a recursive segment walk that stays linear only
/// under that constraint.
fn emit_seg_list(buf: &mut String, name: &str, patterns: &[String]) {
    if patterns.is_empty() {
        buf.push_str(&format!("pub const {}: &[&[&str]] = &[];\n\n", name));
        return;
    }
    buf.push_str(&format!("pub const {}: &[&[&str]] = &[\n", name));
    for pat in patterns {
        let segs: Vec<String> = pat.split('.').map(|s| s.to_lowercase()).collect();
        if segs.iter().filter(|s| s.as_str() == "**").count() > 1 {
            panic!(
                "build.rs: config-key pattern {:?} has more than one '**' segment",
                pat
            );
        }
        buf.push_str("    &[");
        buf.push_str(
            &segs
                .iter()
                .map(|s| format!("{:?}", s))
                .collect::<Vec<_>>()
                .join(", "),
        );
        buf.push_str("],\n");
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

/// Subcommand named by a matrix case argv: first plain token, skipping
/// global config options and their operands (`-c key=value`).
fn case_subcommand(argv: &[String]) -> Option<&str> {
    let mut skip_operand = false;
    for t in argv.iter().skip(1) {
        if skip_operand {
            skip_operand = false;
        } else if t == "-c" || t == "--config" || t == "--config-env" {
            skip_operand = true;
        } else if !t.starts_with('-') {
            return Some(t);
        }
    }
    None
}

fn validate_policy_matrix(subcommands: &SubcommandsConfig, matrix: &PolicyMatrixConfig) {
    let all_categorized: Vec<&String> = subcommands
        .blocked
        .iter()
        .chain(subcommands.sudo_gated.iter())
        .chain(subcommands.partial.iter())
        .collect();
    for sub in subcommands.read_only.iter() {
        assert!(
            !all_categorized.contains(&sub),
            "build.rs: read_only subcommand {:?} also appears in a policy category",
            sub
        );
    }
    let mut covered: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut sanitized_covered: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut has_dangerous_c_block = false;
    for case in &matrix.cases {
        assert!(
            case.expect == "blocked" || case.expect == "allowed" || case.expect == "sanitized",
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
        if case.expect == "sanitized" {
            let sub = case_subcommand(&case.argv)
                .unwrap_or_else(|| panic!("build.rs: case {:?} names no subcommand", case.id));
            assert!(
                subcommands.read_only.iter().any(|s| s == sub),
                "build.rs: sanitized case {:?} targets non-read-only subcommand {:?}",
                case.id,
                sub
            );
            sanitized_covered.insert(sub.to_string());
        }
        if case.expect == "blocked" && case.argv.get(1).map(String::as_str) == Some("-c") {
            has_dangerous_c_block = true;
        }
        if let Some(sub) = case_subcommand(&case.argv) {
            covered.insert(sub.to_string());
        }
    }

    for sub in all_categorized {
        if !covered.contains(sub) {
            panic!(
                "build.rs: git_guard_policy_matrix.yaml missing case for subcommand {:?}",
                sub
            );
        }
    }
    if !subcommands.read_only.is_empty() {
        for sub in subcommands.read_only.iter() {
            assert!(
                sanitized_covered.contains(sub),
                "build.rs: read_only subcommand {:?} needs a sanitized policy matrix case",
                sub
            );
        }
        assert!(
            has_dangerous_c_block,
            "build.rs: read_only list needs a negative matrix case: dangerous -c on a non-read-only subcommand expecting blocked"
        );
    }
}

/// Fail-closed provenance backstop (REQ-GGUARD-177): refuse to
/// compile when any guard policy config is not owned by uid 0. The
/// configs are compiled INTO the binary; an agent-owned config would
/// let the agent rewrite guard policy and rebuild. Root ownership is
/// asserted here so a missed reconcile halts the build instead of
/// passing without a diagnostic.
fn check_config_provenance(config_dir: &Path, files: &[&str]) {
    let mut offenders: Vec<String> = Vec::new();
    for name in files {
        let path = config_dir.join(name);
        match fs::metadata(&path) {
            Ok(meta) if meta.uid() == 0 => {}
            Ok(meta) => offenders.push(format!("{} (uid {})", path.display(), meta.uid())),
            Err(e) => offenders.push(format!("{} (unreadable: {})", path.display(), e)),
        }
    }
    if !offenders.is_empty() {
        panic!(
            "build.rs: refusing to compile: guard policy configs not owned by uid 0:\n  {}\n\
             Repair ownership via the operator relock path (see AGENTS.md).",
            offenders.join("\n  ")
        );
    }
}

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let config_dir = Path::new(&manifest).join("config");

    let config_files = [
        "git_guard_subcommands.yaml",
        "git_guard_policy_matrix.yaml",
        "git_guard_config_keys.yaml",
        "git_guard_protected_branches.yaml",
        "git_guard_environment.yaml",
        "git_guard_resource_limits.yaml",
        "shared_paths.yaml",
        "shared_locked_paths.yaml",
        "git_ssh_allowlist.yaml",
        "shell_guard_policy.yaml",
        "shell_guard_policy.schema.yaml",
        "shell_guard_policy_matrix.yaml",
    ];
    check_config_provenance(&config_dir, &config_files);

    let subcommands: SubcommandsConfig = read_yaml(&config_dir, "git_guard_subcommands.yaml");
    let policy_matrix: PolicyMatrixConfig = read_yaml(&config_dir, "git_guard_policy_matrix.yaml");
    validate_policy_matrix(&subcommands, &policy_matrix);
    let config_keys: ConfigKeysConfig = read_yaml(&config_dir, "git_guard_config_keys.yaml");
    let protected: ProtectedBranchesConfig =
        read_yaml(&config_dir, "git_guard_protected_branches.yaml");
    let environment: EnvironmentConfig = read_yaml(&config_dir, "git_guard_environment.yaml");
    let limits: ResourceLimitsConfig = read_yaml(&config_dir, "git_guard_resource_limits.yaml");
    let paths: PathsConfig = read_yaml(&config_dir, "shared_paths.yaml");
    let locked: LockedPathsConfig = read_yaml(&config_dir, "shared_locked_paths.yaml");
    let ssh_allowlist: GitSshAllowlistConfig = read_yaml(&config_dir, "git_ssh_allowlist.yaml");
    if ssh_allowlist.hosts.is_empty() || ssh_allowlist.users.is_empty() {
        panic!("build.rs: git_ssh_allowlist.yaml needs non-empty hosts and users");
    }
    for entry in ssh_allowlist.hosts.iter().chain(ssh_allowlist.users.iter()) {
        if !valid_host_or_user(entry) {
            panic!("build.rs: git_ssh_allowlist.yaml bad entry {:?}", entry);
        }
    }

    let mut code = String::new();
    code.push_str("// Auto-generated by build.rs from config/guard_*.yaml. DO NOT EDIT.\n");
    code.push_str("// Edit the YAML source files and rebuild.\n\n");

    code.push_str("// --- git_guard_subcommands.yaml ---\n");
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
    emit_str_list(&mut code, "READ_ONLY_SUBCOMMANDS", &subcommands.read_only);

    // F19: abbreviation resolution tables. ABBREV_CANDIDATES is the
    // sorted, deduped union of every policy-bearing subcommand list so
    // the runtime resolver is a partition_point + range scan with no
    // Vec build, sort, or dedup per call. ABBREV_PREFERRED is the
    // sorted partial+sudo_gated set the resolver prefers when a raw
    // prefix matches several candidates.
    let mut abbrev_candidates: Vec<String> = subcommands
        .blocked
        .iter()
        .chain(subcommands.sudo_gated.iter())
        .chain(subcommands.partial.iter())
        .cloned()
        .collect();
    abbrev_candidates.sort();
    abbrev_candidates.dedup();
    emit_str_list(&mut code, "ABBREV_CANDIDATES", &abbrev_candidates);
    let mut abbrev_preferred: Vec<String> = subcommands
        .partial
        .iter()
        .chain(subcommands.sudo_gated.iter())
        .cloned()
        .collect();
    abbrev_preferred.sort();
    abbrev_preferred.dedup();
    emit_str_list(&mut code, "ABBREV_PREFERRED", &abbrev_preferred);

    code.push_str("// --- git_guard_config_keys.yaml ---\n");
    emit_str_list(&mut code, "DANGEROUS_CONFIG_KEYS", &config_keys.dangerous);
    emit_str_list(&mut code, "SUDO_GATED_CONFIG_KEYS", &config_keys.sudo_gated);
    emit_str_list(
        &mut code,
        "VALUE_TAKING_OPTS",
        &config_keys.value_taking_opts,
    );
    // F18: pre-split, pre-lowercased segment tables for the glob matcher.
    emit_seg_list(
        &mut code,
        "DANGEROUS_CONFIG_KEY_SEGMENTS",
        &config_keys.dangerous,
    );
    emit_seg_list(
        &mut code,
        "SUDO_GATED_CONFIG_KEY_SEGMENTS",
        &config_keys.sudo_gated,
    );

    code.push_str("// --- git_guard_protected_branches.yaml ---\n");
    emit_str_list(&mut code, "PROTECTED_BRANCHES", &protected.branches);
    emit_str_list(&mut code, "PROTECTED_BRANCH_PREFIXES", &protected.prefixes);

    code.push_str("// --- git_guard_environment.yaml ---\n");
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

    code.push_str("// --- git_guard_resource_limits.yaml ---\n");
    emit_u64(&mut code, "NOFILE_LIMIT", limits.nofile);
    emit_u64(&mut code, "CORE_LIMIT", limits.core);
    emit_u64(&mut code, "CONTRACT_TIMEOUT_MS", limits.contract_timeout_ms);
    emit_u64(&mut code, "CONTRACT_POLL_MS", limits.contract_poll_ms);
    code.push('\n');

    code.push_str("// --- shared_paths.yaml ---\n");
    emit_str(&mut code, "LOG_FILE", &paths.log_file);
    emit_str(&mut code, "CHILD_PATH", &paths.child_path);
    emit_str(&mut code, "CONTRACT_SCRIPT", &paths.contract_script);
    emit_str(&mut code, "ENFORCEMENT_CONFIG", &paths.enforcement_config);
    emit_str_list(&mut code, "WORKSPACE_MARKERS", &paths.workspace_markers);

    code.push_str("// --- git_ssh_allowlist.yaml ---\n");
    emit_str_list(&mut code, "GIT_SSH_ALLOWED_HOSTS", &ssh_allowlist.hosts);

    code.push_str("// --- shared_locked_paths.yaml ---\n");
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

    let mut ssh_code =
        String::from("// Auto-generated by build.rs from config/git_ssh_allowlist.yaml.\n");
    emit_str_list(&mut ssh_code, "GIT_SSH_ALLOWED_HOSTS", &ssh_allowlist.hosts);
    emit_str_list(&mut ssh_code, "GIT_SSH_ALLOWED_USERS", &ssh_allowlist.users);
    fs::write(Path::new(&out_dir).join("git_ssh_config.rs"), ssh_code).unwrap();

    for name in &config_files {
        println!("cargo:rerun-if-changed=config/{}", name);
    }
    // Binary-guard codegen. Gated on the cargo feature so the default git
    // guard build does not require res/binary-lock.yaml to exist. Emits
    // ONLY the BINARY_POLICIES const literal; no struct/fn/enum.
    if env::var_os("CARGO_FEATURE_BINARY_GUARD").is_some() {
        build_binary_guard::emit_binary_guard_config(Path::new(&manifest));
    }

    build_shell_guard::emit_shell_guard_config(Path::new(&manifest), limits.nofile);
}
