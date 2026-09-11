use crate::yaml_edit_install::install;
use serde_yaml::Value;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process;

use crate::yaml_edit_diff as diff;
use crate::yaml_edit_engine as engine;
use crate::yaml_edit_schema as schema;
use crate::yaml_edit_shape as shape;
use crate::yaml_edit_splice as splice;
use crate::yaml_edit_target::{normalize_terminal, Target};

pub const LOG_FILE_NAME: &str = ".workspace-guard.log";
const LOCK_PATH: &str = "/var/lib/workspace-guard/yaml-edit.lock";

#[derive(Debug, PartialEq)]
pub enum Intent {
    Add,
    Remove,
    Set,
    Bootstrap,
    Unset,
    RemoveComment,
    Delete,
    Get,
    List,
    Validate,
    Check,
    Format,
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
    pub create: bool,
    pub expected_sha256: Option<String>,
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
        Some("bootstrap") => Intent::Bootstrap,
        Some("unset") => Intent::Unset,
        Some("remove-comment") => Intent::RemoveComment,
        Some("delete") => Intent::Delete,
        Some("get") => Intent::Get,
        Some("list") => Intent::List,
        Some("validate") => Intent::Validate,
        Some("check") => Intent::Check,
        Some("format") => Intent::Format,
        _ => return Err("unknown intent".to_string()),
    };
    let mut positional: Vec<String> = Vec::new();
    let mut dry_run = false;
    let mut allow_no_match = false;
    let mut force_string = false;
    let mut create = false;
    let mut expected_sha256 = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => dry_run = true,
            "--allow-no-match" => allow_no_match = true,
            "--string" => force_string = true,
            "--create" => create = true,
            "--expected-sha256" => {
                i += 1;
                expected_sha256 = args.get(i).cloned();
                if expected_sha256.is_none() {
                    return Err("missing digest".to_string());
                }
            }
            _ => positional.push(args[i].clone()),
        }
        i += 1;
    }
    let need = match intent {
        Intent::Add | Intent::Remove => 3,
        Intent::Set | Intent::Bootstrap => 3,
        Intent::Unset | Intent::RemoveComment => 2,
        Intent::Delete => 1,
        Intent::Get => 2,
        Intent::List => 1,
        Intent::Validate => 1,
        Intent::Check => 1,
        Intent::Format => 1,
    };
    if positional.len() < need {
        return Err("missing arguments".to_string());
    }
    let valid_len = match intent {
        Intent::Add | Intent::Remove => positional.len() >= 3,
        Intent::List => positional.len() <= 2,
        Intent::Set | Intent::Bootstrap => positional.len() == 3,
        Intent::Unset | Intent::RemoveComment | Intent::Get => positional.len() == 2,
        Intent::Delete | Intent::Validate | Intent::Check | Intent::Format => positional.len() == 1,
    };
    if !valid_len || (intent == Intent::Delete && expected_sha256.is_none()) {
        return Err("wrong arguments".to_string());
    }
    if intent != Intent::Delete && expected_sha256.is_some() {
        return Err("--expected-sha256 is only valid for delete".to_string());
    }
    if intent == Intent::Delete && (dry_run || allow_no_match || force_string) {
        return Err("unsupported delete flag".to_string());
    }
    if create && intent != Intent::Set {
        return Err("--create is only valid for set".to_string());
    }
    if intent == Intent::Check && (dry_run || allow_no_match || force_string) {
        return Err("check is read-only; flags are not supported".to_string());
    }
    if intent == Intent::Format && (allow_no_match || force_string || create) {
        return Err("format supports only --dry-run".to_string());
    }
    let file = PathBuf::from(&positional[0]);
    let (key, specs, value) = match intent {
        Intent::Add | Intent::Remove => {
            (Some(positional[1].clone()), positional[2..].to_vec(), None)
        }
        Intent::Set | Intent::Bootstrap => (
            Some(positional[1].clone()),
            Vec::new(),
            Some(positional[2].clone()),
        ),
        Intent::Unset => (Some(positional[1].clone()), Vec::new(), None),
        Intent::RemoveComment => (None, Vec::new(), Some(positional[1].clone())),
        Intent::Delete => (None, Vec::new(), None),
        Intent::Get => (Some(positional[1].clone()), Vec::new(), None),
        Intent::List => (positional.get(1).cloned(), Vec::new(), None),
        Intent::Validate => (None, Vec::new(), None),
        Intent::Check | Intent::Format => (None, Vec::new(), None),
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
        create,
        expected_sha256,
    })
}

pub(crate) fn require_root() {
    if !nix::unistd::geteuid().is_root() {
        fail(
            2,
            "needs root: sudo workspace-yaml-edit (or sudo make yaml-*)",
        );
    }
}

pub(crate) struct LockGuard {
    _flock: nix::fcntl::Flock<std::fs::File>,
}

pub(crate) fn acquire_lock() -> LockGuard {
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

pub(crate) fn audit(cli: &Cli, intent: &str) -> Result<(), String> {
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
    let fields = if matches!(
        cli.intent,
        Intent::Set | Intent::Bootstrap | Intent::RemoveComment
    ) {
        format!("value={}", cli.value.clone().unwrap_or_default())
    } else if cli.intent == Intent::Delete {
        format!("sha256={}", cli.expected_sha256.clone().unwrap_or_default())
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

pub(crate) fn parse_doc(raw: &str, path: &Path) -> Value {
    serde_yaml::from_str(raw)
        .unwrap_or_else(|e| fail(1, &format!("{}: not valid YAML: {e}", path.display())))
}

pub(crate) fn key_err(e: engine::KeyError, key: &str) -> ! {
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

pub(crate) fn verify(new_content: &str, expected: &Value, path: &Path) {
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

pub(crate) fn basename(path: &Path) -> &str {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
}

pub(crate) fn check_override_owner(path: &Path) {
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

pub(crate) fn check_schema(path: &Path, doc: &Value) {
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
        let segs = match engine::resolve_segments(doc, dotted) {
            Some(s) => s,
            None if cli.create => {
                return create_node(doc, original, dotted, &raw_value, cli.force_string);
            }
            None => fail(1, &format!("key not found: {dotted}")),
        };
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

/// Insert a previously absent leaf key under an existing mapping
/// (`set --create`). The parent path must resolve to a block
/// mapping; anything else fails closed.
fn create_node(
    doc: &Value,
    original: &str,
    dotted: &str,
    raw_value: &str,
    force_string: bool,
) -> Transform {
    let value = engine::typed_value(raw_value, force_string)?;
    let (parent_dotted, leaf) = dotted
        .rsplit_once('.')
        .ok_or_else(|| format!("key not found: {dotted} (use bootstrap for top-level keys)"))?;
    let parent_segs = engine::resolve_segments(doc, parent_dotted)
        .ok_or_else(|| format!("parent key not found: {parent_dotted}"))?;
    let parent = engine::scalar_at(doc, &parent_segs)
        .map_err(|_| format!("parent key not found: {parent_dotted}"))?;
    if parent.as_mapping().is_none() {
        return Err(format!("parent is not a mapping: {parent_dotted}"));
    }
    let mut expected = doc.clone();
    let mut node = &mut expected;
    for seg in &parent_segs {
        node = node
            .as_mapping_mut()
            .and_then(|m| m.get_mut(seg.as_str()))
            .ok_or_else(|| format!("parent key not found: {parent_dotted}"))?;
    }
    node.as_mapping_mut()
        .expect("parent checked")
        .insert(Value::String(leaf.to_string()), value.clone());
    splice::splice_insert_map_key(original, &parent_segs, leaf, &value).map(|out| (out, expected))
}

pub(crate) type Transform = Result<(String, Value), String>;

pub(crate) fn mutate(cli: &Cli, op: &mut dyn FnMut(&Value, &str) -> Transform) {
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
    let doc = parse_doc(&original, &cli.file);
    // Operator ruling 2026-09-06: syntax + format are separate
    // pre-mutation steps. Indentless block sequences are not
    // splice-editable (SPEC-YAML-EDIT 4.1); mutations refuse such
    // targets instead of failing cryptically mid-splice. Formatting is
    // its own audited command: workspace-yaml-edit format <file>.
    let violations = shape::indentless_lists(&original);
    if !violations.is_empty() {
        for v in &violations {
            eprintln!(
                "yaml-edit: ERROR: {}",
                v.message(&cli.file.display().to_string())
            );
        }
        fail(
            2,
            "target is not splice-editable; run: workspace-yaml-edit format <file>",
        );
    }
    let (new_content, expected) = match op(&doc, &original) {
        Ok(v) => v,
        Err(e) => fail(1, &format!("{}: {e}", cli.file.display())),
    };
    let new_content = normalize_terminal(&new_content);
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
        Intent::Bootstrap => "bootstrap",
        Intent::Unset => "unset",
        Intent::RemoveComment => "remove-comment",
        Intent::Delete => "delete",
        _ => "?",
    };
    audit(cli, intent).unwrap_or_else(|e| fail(1, &e));
    install(&target, &new_content);
    println!("yaml-edit: ok: {} {}", intent, cli.file.display());
}
