use serde_yaml::Value;
use std::process;

use crate::yaml_edit_diff as diff;
use crate::yaml_edit_engine as engine;
use crate::yaml_edit_install::install;
use crate::yaml_edit_ops::{
    acquire_lock, audit, basename, check_override_owner, check_schema, fail, key_err, parse_doc,
    require_root, verify, Cli,
};
use crate::yaml_edit_schema as schema;
use crate::yaml_edit_shape as shape;
use crate::yaml_edit_splice as splice;
use crate::yaml_edit_target::{normalize_terminal, Target};

pub fn run_get(cli: &Cli) {
    let target = Target::open(&cli.file, false).unwrap_or_else(|e| fail(2, &e));
    let raw = target.read_string().unwrap_or_else(|e| fail(1, &e));
    let doc = parse_doc(&raw, &cli.file);
    let dotted = cli.key.as_deref().unwrap_or_default();
    let segs = engine::resolve_segments(&doc, dotted)
        .unwrap_or_else(|| fail(1, &format!("key not found: {dotted}")));
    let node = engine::scalar_at(&doc, &segs).unwrap_or_else(|e| key_err(e, dotted));
    match node {
        Value::String(s) => println!("{s}"),
        Value::Number(_) | Value::Bool(_) => {
            println!(
                "{}",
                serde_yaml::to_string(node)
                    .unwrap_or_else(|e| fail(1, &format!("cannot render value: {e}")))
                    .trim()
            )
        }
        _ => fail(2, &format!("key is not a scalar: {dotted}")),
    }
}

pub fn run_list(cli: &Cli) {
    let target = Target::open(&cli.file, false).unwrap_or_else(|e| fail(2, &e));
    let raw = target.read_string().unwrap_or_else(|e| fail(1, &e));
    match &cli.key {
        None => print!("{raw}"),
        Some(key) => {
            let doc = parse_doc(&raw, &cli.file);
            engine::list_items(&doc, key).unwrap_or_else(|e| key_err(e, key));
            let block = splice::key_block(&raw, key).unwrap_or_else(|e| fail(1, &e));
            print!("{block}");
        }
    }
}

pub fn run_validate(cli: &Cli) {
    let target = Target::open(&cli.file, false).unwrap_or_else(|e| fail(2, &e));
    let raw = target.read_string().unwrap_or_else(|e| fail(1, &e));
    let doc = parse_doc(&raw, &cli.file);
    let reg = schema::registry_for(&cli.file).unwrap_or_else(|e| fail(1, &e));
    match schema::validate_document(basename(&cli.file), &doc, &reg) {
        Ok(()) => println!("yaml-edit: ok: {}", cli.file.display()),
        Err(errors) => {
            for e in errors.lines() {
                eprintln!("yaml-edit: ERROR: {e}");
            }
            process::exit(1);
        }
    }
}

/// Read-only preflight: syntax, schema, and splice-editability shape.
/// Reports every indentless block sequence with the exact key, line,
/// and indents, plus schema errors. Exits 1 on any finding.
pub fn run_check(cli: &Cli) {
    let target = Target::open(&cli.file, false).unwrap_or_else(|e| fail(2, &e));
    let raw = target.read_string().unwrap_or_else(|e| fail(1, &e));
    let doc = parse_doc(&raw, &cli.file);
    let mut failed = false;
    for v in &shape::indentless_lists(&raw) {
        eprintln!(
            "yaml-edit: ERROR: {}",
            v.message(&cli.file.display().to_string())
        );
        failed = true;
    }
    if let Ok(reg) = schema::registry_for(&cli.file) {
        if let Err(errors) = schema::validate_document(basename(&cli.file), &doc, &reg) {
            for e in errors.lines() {
                eprintln!("yaml-edit: ERROR: {e}");
            }
            failed = true;
        }
    }
    if failed {
        process::exit(1);
    }
    println!("yaml-edit: ok: check {}", cli.file.display());
}

/// Separate audited formatting step: canonicalize indentless block
/// sequences to the splice discipline (dash at key indent + 2).
/// Comments, blank lines, key order, and scalar spelling survive
/// byte-for-byte except for inserted indentation; the result must
/// re-parse to the identical document (verify) and pass the schema.
pub fn run_format(cli: &Cli) {
    if !cli.dry_run {
        require_root();
        check_override_owner(&cli.file);
    }
    let _lock = if cli.dry_run {
        None
    } else {
        Some(acquire_lock())
    };
    let target = Target::open(&cli.file, !cli.dry_run).unwrap_or_else(|e| fail(2, &e));
    let original = target.read_string().unwrap_or_else(|e| fail(1, &e));
    let expected = parse_doc(&original, &cli.file);
    let new_content = match shape::reindent(&original) {
        Ok(Some(c)) => c,
        Ok(None) => {
            eprintln!("yaml-edit: unchanged");
            process::exit(0);
        }
        Err(e) => fail(1, &format!("{}: {e}", cli.file.display())),
    };
    let new_content = normalize_terminal(&new_content);
    verify(&new_content, &expected, &cli.file);
    check_schema(&cli.file, &expected);
    if cli.dry_run {
        print!(
            "{}",
            diff::unified(&original, &new_content, &cli.file.display().to_string())
        );
        return;
    }
    audit(cli, "format").unwrap_or_else(|e| fail(1, &e));
    install(&target, &new_content);
    println!("yaml-edit: ok: format {}", cli.file.display());
}
