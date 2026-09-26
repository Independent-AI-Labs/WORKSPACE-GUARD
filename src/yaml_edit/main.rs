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

mod admin;
mod comment;
mod delete;
mod diff;
mod emit;
mod engine;
mod install;
mod ops;
mod query;
mod schema;
mod shape;
mod splice;
mod target;
mod unset;

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
         workspace-yaml-edit add      <file> <list-key> <field-spec>... [--dry-run]\n  \
         workspace-yaml-edit remove   <file> <list-key> <field-spec>... [--dry-run] [--allow-no-match]\n  \
         workspace-yaml-edit set      <file> <dotted.key> <value> [--string] [--create] [--dry-run]\n  \
         workspace-yaml-edit bootstrap <file> <top-level-key> <value> [--string] [--dry-run]\n  \
         workspace-yaml-edit unset    <file> <dotted.path> [--dry-run]\n  \
         workspace-yaml-edit remove-comment <file> <exact-comment-text> [--dry-run]\n  \
         workspace-yaml-edit delete   <file> --expected-sha256 <digest>\n  \
         workspace-yaml-edit get      <file> <dotted.key>\n  \
         workspace-yaml-edit list     <file> [<list-key>]\n  \
         workspace-yaml-edit validate <file>\n  \
         workspace-yaml-edit check    <file>\n  \
         workspace-yaml-edit format   <file> [--dry-run]\n\
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
        ops::Intent::Bootstrap => admin::run_bootstrap(&cli),
        ops::Intent::Unset => admin::run_unset(&cli),
        ops::Intent::RemoveComment => admin::run_remove_comment(&cli),
        ops::Intent::Delete => admin::run_delete(&cli),
        ops::Intent::Get => query::run_get(&cli),
        ops::Intent::List => query::run_list(&cli),
        ops::Intent::Validate => query::run_validate(&cli),
        ops::Intent::Check => query::run_check(&cli),
        ops::Intent::Format => query::run_format(&cli),
    }
}

#[cfg(test)]
mod emit_tests;
#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod ops_tests;
#[cfg(test)]
mod schema_tests;
#[cfg(test)]
mod shape_tests;
#[cfg(test)]
mod splice_tests;

#[cfg(test)]
mod tests {
    use super::ops;
    use serde_yaml::Value;

    #[test]
    fn audit_log_name_matches_guard_config() {
        let raw = include_str!("../../config/shared_paths.yaml");
        let doc: Value = serde_yaml::from_str(raw).expect("shared_paths.yaml must parse");
        let configured = doc
            .get("log_file")
            .and_then(Value::as_str)
            .expect("shared_paths.yaml must define log_file");
        assert_eq!(configured, ops::LOG_FILE_NAME);
    }
}
