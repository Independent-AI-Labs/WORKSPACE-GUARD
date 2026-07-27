// workspace-yaml-edit: sudo-gated secure YAML policy editor
// (SPEC-YAML-EDIT). The only supported mechanism for scripted edits
// to guard-locked YAML policy files. Files stay root:root at all
// times; mutations are atomic (temp + verify + rename), serialized
// by a global flock, schema-validated, chattr-preserving, and
// audited. All semantics come from serde_yaml; line scanning only
// locates splice regions.
//
// Exit codes: 0 ok; 1 transform/parse/validation failure; 2 usage,
// preflight, not-root, or wrong key kind; 3 remove matched nothing;
// 4 add would duplicate an existing entry.

use std::process;

#[path = "yaml_edit_diff.rs"]
mod yaml_edit_diff;
#[path = "yaml_edit_emit.rs"]
mod yaml_edit_emit;
#[path = "yaml_edit_engine.rs"]
mod yaml_edit_engine;
#[path = "yaml_edit_install.rs"]
mod yaml_edit_install;
#[path = "yaml_edit_ops.rs"]
mod yaml_edit_ops;
#[path = "yaml_edit_schema.rs"]
mod yaml_edit_schema;
#[path = "yaml_edit_splice.rs"]
mod yaml_edit_splice;

use yaml_edit_ops as ops;

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
         workspace-yaml-edit add      <file> <list-key> <field-spec>... [--dry-run]\n  \
         workspace-yaml-edit remove   <file> <list-key> <field-spec>... [--dry-run] [--allow-no-match]\n  \
         workspace-yaml-edit set      <file> <dotted.key> <value> [--string] [--dry-run]\n  \
         workspace-yaml-edit get      <file> <dotted.key>\n  \
         workspace-yaml-edit list     <file> [<list-key>]\n  \
         workspace-yaml-edit validate <file>\n\
         field-spec: name=value | name=[v1,v2] | bare-value"
    );
    process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = ops::parse_cli(&args).unwrap_or_else(|_| usage());
    match cli.intent {
        ops::Intent::Add => ops::run_add(&cli),
        ops::Intent::Remove => ops::run_remove(&cli),
        ops::Intent::Set => ops::run_set(&cli),
        ops::Intent::Get => ops::run_get(&cli),
        ops::Intent::List => ops::run_list(&cli),
        ops::Intent::Validate => ops::run_validate(&cli),
    }
}

#[cfg(test)]
#[path = "yaml_edit_emit_tests.rs"]
mod emit_tests;
#[cfg(test)]
#[path = "yaml_edit_engine_tests.rs"]
mod engine_tests;
#[cfg(test)]
#[path = "yaml_edit_schema_tests.rs"]
mod schema_tests;
#[cfg(test)]
#[path = "yaml_edit_splice_tests.rs"]
mod splice_tests;

#[cfg(test)]
mod tests {
    use super::ops;
    use serde_yaml::Value;

    #[test]
    fn audit_log_name_matches_guard_config() {
        let raw = include_str!("../config/guard_paths.yaml");
        let doc: Value = serde_yaml::from_str(raw).expect("guard_paths.yaml must parse");
        let configured = doc
            .get("log_file")
            .and_then(Value::as_str)
            .expect("guard_paths.yaml must define log_file");
        assert_eq!(configured, ops::LOG_FILE_NAME);
    }
}
