// src/yaml_edit_ops.rs
//
// Operation layer of workspace-yaml-edit (SPEC-YAML-EDIT section 6):
// CLI parsing, preflight, locking, the mutation pipeline
// (parse, transform, verify, schema, audit, install), and the
// read-only intents. Kept separate from the bin entry point so
// every file stays within the repository line budget.

use crate::yaml_edit_install::install;
use serde_yaml::Value;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process;

use crate::yaml_edit_diff as diff;
use crate::yaml_edit_engine as engine;
use crate::yaml_edit_schema as schema;
use crate::yaml_edit_splice as splice;

/// Mirrors `log_file` in config/guard_paths.yaml; a unit test keeps
/// the two in sync.
pub const LOG_FILE_NAME: &str = ".workspace-guard.log";
const LOCK_PATH: &str = "/var/lib/workspace-guard/yaml-edit.lock";

#[derive(Debug, PartialEq)]
pub enum Intent {
    Add,
    Remove,
    Set,
    Get,
    List,
    Validate,
}

pub struct Cli {
    pub intent: Intent,
    pub file: PathBuf,
    pub key: Option<String>,
    pub specs: Vec<String>,
    pub value: Option<String>,
    pub dry_run: bool,
    pub allow_no_match: bool,
    pub force_string: bool,
}

pub fn fail(code: i32, msg: &str) -> ! {
    eprintln!("yaml-edit: ERROR: {msg}");
    process::exit(code);
}

pub fn parse_cli(args: &[String]) -> Result<Cli, String> {
    let intent = match args.first().map(String::as_str) {
        Some("add") => Intent::Add,
        Some("remove") => Intent::Remove,
        Some("set") => Intent::Set,
        Some("get") => Intent::Get,
        Some("list") => Intent::List,
        Some("validate") => Intent::Validate,
        _ => return Err("unknown intent".to_string()),
    };
    let mut positional: Vec<String> = Vec::new();
    let mut dry_run = false;
    let mut allow_no_match = false;
    let mut force_string = false;
    for a in &args[1..] {
        match a.as_str() {
            "--dry-run" => dry_run = true,
            "--allow-no-match" => allow_no_match = true,
            "--string" => force_string = true,
            _ => positional.push(a.clone()),
        }
    }
    let need = match intent {
        Intent::Add | Intent::Remove => 3,
        Intent::Set => 3,
        Intent::Get => 2,
        Intent::List => 1,
        Intent::Validate => 1,
    };
    if positional.len() < need {
        return Err("missing arguments".to_string());
    }
    let file = PathBuf::from(&positional[0]);
    let (key, specs, value) = match intent {
        Intent::Add | Intent::Remove => {
            (Some(positional[1].clone()), positional[2..].to_vec(), None)
        }
        Intent::Set => (
            Some(positional[1].clone()),
            Vec::new(),
            Some(positional[2].clone()),
        ),
        Intent::Get => (Some(positional[1].clone()), Vec::new(), None),
        Intent::List => (positional.get(1).cloned(), Vec::new(), None),
        Intent::Validate => (None, Vec::new(), None),
    };
    Ok(Cli {
        intent,
        file,
        key,
        specs,
        value,
        dry_run,
        allow_no_match,
        force_string,
    })
}

fn require_root() {
    if !nix::unistd::geteuid().is_root() {
        fail(
            2,
            "needs root: sudo workspace-yaml-edit (or sudo make yaml-*)",
        );
    }
}

/// Textual normalization of `.` and `..` so the canonical-path
/// comparison detects symlinked parents without requiring them.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Preflight (REQ-YE-102): regular file, no symlink anywhere in the
/// path, and root:root for mutations.
fn preflight(path: &Path, mutation: bool) {
    let md = std::fs::symlink_metadata(path)
        .unwrap_or_else(|_| fail(2, &format!("file not found: {}", path.display())));
    if md.file_type().is_symlink() {
        fail(2, &format!("refusing symlink: {}", path.display()));
    }
    if !md.is_file() {
        fail(2, &format!("not a regular file: {}", path.display()));
    }
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| fail(1, "cannot read current directory"))
            .join(path)
    };
    let canon = std::fs::canonicalize(&abs)
        .unwrap_or_else(|_| fail(2, &format!("cannot resolve: {}", path.display())));
    if canon != normalize(&abs) {
        fail(2, &format!("refusing symlinked path: {}", path.display()));
    }
    if mutation && (md.uid() != 0 || md.gid() != 0) {
        fail(
            2,
            &format!(
                "refusing non-root-owned file ({}:{}): {}",
                md.uid(),
                md.gid(),
                path.display()
            ),
        );
    }
}

/// Held until the install completes; drop releases the lock.
struct LockGuard {
    _flock: nix::fcntl::Flock<std::fs::File>,
}

/// Global mutation lock (REQ-YE-104).
fn acquire_lock() -> LockGuard {
    let dir = Path::new("/var/lib/workspace-guard");
    if !dir.exists() {
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| fail(1, &format!("cannot create {}: {e}", dir.display())));
        let mut perms = std::fs::metadata(dir)
            .unwrap_or_else(|e| fail(1, &format!("cannot stat {}: {e}", dir.display())))
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
        std::fs::set_permissions(dir, perms)
            .unwrap_or_else(|e| fail(1, &format!("cannot chmod {}: {e}", dir.display())));
    }
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(LOCK_PATH)
        .unwrap_or_else(|e| fail(1, &format!("cannot open {LOCK_PATH}: {e}")));
    let flock = nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, e)| e)
        .unwrap_or_else(|e| fail(1, &format!("cannot lock {LOCK_PATH}: {e}")));
    LockGuard { _flock: flock }
}

/// One audit line per mutation, appended to the operator's guard
/// log. Operator home resolves via SUDO_UID, never $HOME
/// (REQ-YE-600). Write failure aborts before install (REQ-YE-601).
fn audit(cli: &Cli, intent: &str) -> Result<(), String> {
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .map(nix::unistd::Uid::from_raw)
        .unwrap_or_else(nix::unistd::geteuid);
    let user = nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .ok_or_else(|| format!("cannot resolve uid {}", uid.as_raw()))?;
    let ts = process::Command::new("date")
        .arg("-u")
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output()
        .map_err(|e| format!("cannot run date: {e}"))
        .and_then(|o| {
            if o.status.success() {
                Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                Err("date -u failed".to_string())
            }
        })?;
    let key = cli.key.clone().unwrap_or_default();
    let fields = if cli.intent == Intent::Set {
        format!("value={}", cli.value.clone().unwrap_or_default())
    } else {
        cli.specs.join(";")
    };
    let line = format!(
        "{ts} yaml-edit {intent} user={} file={} key={key} fields={fields} result=ok\n",
        user.name,
        cli.file.display()
    );
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(user.dir.join(LOG_FILE_NAME))
        .map_err(|e| format!("audit log open failed in {}: {e}", user.dir.display()))?;
    f.write_all(line.as_bytes())
        .map_err(|e| format!("audit log write failed: {e}"))
}

fn parse_doc(raw: &str, path: &Path) -> Value {
    serde_yaml::from_str(raw)
        .unwrap_or_else(|e| fail(1, &format!("{}: not valid YAML: {e}", path.display())))
}

fn key_err(e: engine::KeyError, key: &str) -> ! {
    match e {
        engine::KeyError::Missing => fail(2, &format!("key not found: {key}")),
        engine::KeyError::NotAList => fail(2, &format!("key is not a list: {key}")),
        engine::KeyError::NotAMap => fail(1, "document root is not a mapping"),
    }
}

fn set_node(doc: &mut Value, segs: &[String], val: Value) {
    let mut node = doc;
    for seg in segs {
        // Segments were resolved against this document, so every
        // level exists; a miss here is unreachable in practice.
        let Some(next) = node
            .as_mapping_mut()
            .and_then(|m| m.get_mut(Value::String(seg.clone())))
        else {
            return;
        };
        node = next;
    }
    *node = val;
}

/// Parse the new content and require it to be exactly the expected
/// document (REQ-YE-006): serde_yaml is the sole arbiter of what
/// the splice produced.
fn verify(new_content: &str, expected: &Value, path: &Path) {
    let parsed = parse_doc(new_content, path);
    if &parsed != expected {
        fail(
            1,
            &format!(
                "post-edit verification failed: splice result does not match the \
                 semantic expectation for {}; refusing to install",
                path.display()
            ),
        );
    }
}

fn basename(path: &Path) -> &str {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
}

/// The schema override file participates in validation decisions,
/// so mutations refuse a non-root-owned override (fail closed).
fn check_override_owner(path: &Path) {
    let Some(dir) = path.parent() else { return };
    let reg = dir.join("yaml_edit_schemas.yaml");
    let Ok(md) = std::fs::symlink_metadata(&reg) else {
        return;
    };
    if md.file_type().is_symlink() || md.uid() != 0 || md.gid() != 0 {
        fail(
            2,
            &format!("refusing non-root-owned schema registry: {}", reg.display()),
        );
    }
}

fn check_schema(path: &Path, doc: &Value) {
    let reg = schema::registry_for(path).unwrap_or_else(|e| fail(2, &e));
    schema::validate_document(basename(path), doc, &reg).unwrap_or_else(|e| fail(1, &e));
}

pub fn run_add(cli: &Cli) {
    let key = cli.key.as_deref().unwrap_or_default();
    let specs = engine::parse_specs(&cli.specs).unwrap_or_else(|e| fail(2, &e));
    let entry = engine::entry_from_specs(&specs).unwrap_or_else(|e| fail(2, &e));
    mutate(cli, &mut |doc, original| {
        let items = engine::list_items(doc, key).unwrap_or_else(|e| key_err(e, key));
        if items.iter().any(|v| engine::specs_match_entry(v, &specs)) {
            fail(4, &format!("duplicate entry in {key}"));
        }
        let mut expected = doc.clone();
        expected
            .as_mapping_mut()
            .and_then(|m| m.get_mut(Value::String(key.to_string())))
            .and_then(|v| v.as_sequence_mut())
            .map(|s| s.push(entry.clone()))
            .unwrap_or_else(|| fail(1, &format!("key is not a list: {key}")));
        splice::splice_add(original, key, &entry, items).map(|out| (out, expected))
    });
}

pub fn run_remove(cli: &Cli) {
    let key = cli.key.as_deref().unwrap_or_default();
    let specs = engine::parse_specs(&cli.specs).unwrap_or_else(|e| fail(2, &e));
    mutate(cli, &mut |doc, original| {
        let items = engine::list_items(doc, key).unwrap_or_else(|e| key_err(e, key));
        let idx = engine::matching_indexes(items, &specs);
        if idx.is_empty() {
            if cli.allow_no_match {
                eprintln!("yaml-edit: unchanged (no match, --allow-no-match)");
                process::exit(0);
            }
            fail(3, &format!("no matching entry in {key}"));
        }
        let mut expected = doc.clone();
        let seq = expected
            .as_mapping_mut()
            .and_then(|m| m.get_mut(Value::String(key.to_string())))
            .and_then(|v| v.as_sequence_mut())
            .unwrap_or_else(|| fail(1, &format!("key is not a list: {key}")));
        for i in idx.iter().rev() {
            seq.remove(*i);
        }
        splice::splice_remove(original, key, items, &idx).map(|out| (out, expected))
    });
}

pub fn run_set(cli: &Cli) {
    let dotted = cli.key.as_deref().unwrap_or_default();
    let raw_value = cli.value.clone().unwrap_or_default();
    mutate(cli, &mut |doc, original| {
        let segs = engine::resolve_segments(doc, dotted)
            .ok_or(())
            .unwrap_or_else(|_| fail(1, &format!("key not found: {dotted}")));
        let node = engine::scalar_at(doc, &segs).unwrap_or_else(|e| key_err(e, dotted));
        if matches!(node, Value::Mapping(_) | Value::Sequence(_)) {
            fail(2, &format!("refusing set on block/list key: {dotted}"));
        }
        let value =
            engine::typed_value(&raw_value, cli.force_string).unwrap_or_else(|e| fail(2, &e));
        let mut expected = doc.clone();
        set_node(&mut expected, &segs, value.clone());
        splice::splice_set(original, &segs, &value).map(|out| (out, expected))
    });
}

/// Shared mutation pipeline: preflight, lock, parse, transform,
/// verify, schema-validate, audit, install (REQ-YE-105).
/// Transform result: new file content plus the expected document
/// the verification step compares it against.
type Transform = Result<(String, Value), String>;

fn mutate(cli: &Cli, op: &mut dyn FnMut(&Value, &str) -> Transform) {
    if !cli.dry_run {
        require_root();
        check_override_owner(&cli.file);
    }
    preflight(&cli.file, !cli.dry_run);
    let _lock = if cli.dry_run {
        None
    } else {
        Some(acquire_lock())
    };
    let original = std::fs::read_to_string(&cli.file)
        .unwrap_or_else(|e| fail(1, &format!("cannot read {}: {e}", cli.file.display())));
    let doc = parse_doc(&original, &cli.file);
    let (new_content, expected) = match op(&doc, &original) {
        Ok(v) => v,
        Err(e) => fail(1, &format!("{}: {e}", cli.file.display())),
    };
    if new_content == original {
        eprintln!("yaml-edit: unchanged");
        process::exit(0);
    }
    verify(&new_content, &expected, &cli.file);
    check_schema(&cli.file, &expected);
    if cli.dry_run {
        print!(
            "{}",
            diff::unified(&original, &new_content, &cli.file.display().to_string())
        );
        return;
    }
    let intent = match cli.intent {
        Intent::Add => "add",
        Intent::Remove => "remove",
        Intent::Set => "set",
        _ => "?",
    };
    audit(cli, intent).unwrap_or_else(|e| fail(1, &e));
    install(&cli.file, &new_content);
    println!("yaml-edit: ok: {} {}", intent, cli.file.display());
}

pub fn run_get(cli: &Cli) {
    preflight(&cli.file, false);
    let raw = std::fs::read_to_string(&cli.file)
        .unwrap_or_else(|e| fail(1, &format!("cannot read {}: {e}", cli.file.display())));
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
    preflight(&cli.file, false);
    let raw = std::fs::read_to_string(&cli.file)
        .unwrap_or_else(|e| fail(1, &format!("cannot read {}: {e}", cli.file.display())));
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
    preflight(&cli.file, false);
    let raw = std::fs::read_to_string(&cli.file)
        .unwrap_or_else(|e| fail(1, &format!("cannot read {}: {e}", cli.file.display())));
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
