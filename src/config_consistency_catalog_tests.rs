//! Sandbox and CVE catalog consistency tests (split from config_consistency_tests).

use serde_yaml::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

fn repo_path(rel: &str) -> String {
    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel)
}

fn load_yaml(rel: &str) -> Value {
    let raw =
        fs::read_to_string(repo_path(rel)).unwrap_or_else(|e| panic!("failed to read {rel}: {e}"));
    serde_yaml::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {rel} as YAML: {e}"))
}

fn seq_strings<'a>(root: &'a Value, key: &str, field: &str) -> Vec<&'a str> {
    let seq = root
        .get(key)
        .unwrap_or_else(|| panic!("missing key: {key}"))
        .as_sequence()
        .unwrap_or_else(|| panic!("`{key}` is not a sequence"));
    seq.iter()
        .filter_map(|e| e.get(field).and_then(|v| v.as_str()))
        .collect()
}

const VALID_PROFILES: &[&str] = &["rootless", "gvisor", "firecracker"];

const VALID_CVE_LAYERS: &[&str] = &["binary-lock", "capability-throttle", "sandbox"];

#[test]
fn sandbox_profiles_parses_with_entries() {
    let doc = load_yaml("config/sandbox/profiles.yaml");
    let seq = doc
        .get("profiles")
        .and_then(|p| p.as_sequence())
        .expect("profiles is a non-empty sequence");
    assert!(!seq.is_empty(), "profiles list is empty");
}

#[test]
fn sandbox_profile_names_are_known() {
    let doc = load_yaml("config/sandbox/profiles.yaml");
    let seq = doc.get("profiles").unwrap().as_sequence().unwrap();
    for entry in seq {
        let prof = entry
            .get("profile")
            .and_then(|p| p.as_str())
            .expect("entry has a profile");
        assert!(
            VALID_PROFILES.contains(&prof),
            "unknown sandbox profile: {prof}"
        );
    }
}

#[test]
fn sandbox_patterns_are_nonempty_regex_strings() {
    let doc = load_yaml("config/sandbox/profiles.yaml");
    let seq = doc.get("profiles").unwrap().as_sequence().unwrap();
    for entry in seq {
        let pat = entry
            .get("pattern")
            .and_then(|p| p.as_str())
            .expect("entry has a pattern");
        assert!(!pat.is_empty(), "empty pattern");
        assert!(
            pat.contains('*') || pat.chars().all(|c| !c.is_whitespace()),
            "pattern looks malformed: {pat}"
        );
    }
}

#[test]
fn sandbox_last_entry_is_catch_all_rootless() {
    let doc = load_yaml("config/sandbox/profiles.yaml");
    let seq = doc.get("profiles").unwrap().as_sequence().unwrap();
    let last = seq.last().expect("profiles non-empty");
    assert_eq!(last.get("pattern").unwrap().as_str().unwrap(), ".+");
    assert_eq!(last.get("profile").unwrap().as_str().unwrap(), "rootless");
}

#[test]
fn sandbox_profile_files_exist_on_disk() {
    let doc = load_yaml("config/sandbox/profiles.yaml");
    let seq = doc.get("profiles").unwrap().as_sequence().unwrap();
    for entry in seq {
        let prof = entry.get("profile").unwrap().as_str().unwrap();
        let yaml = repo_path(&format!("config/sandbox/{prof}.yaml"));
        let json = repo_path(&format!("config/sandbox/{prof}.json"));
        assert!(
            Path::new(&yaml).exists() || Path::new(&json).exists(),
            "no config/sandbox/{prof}.{{yaml,json}} file for profile `{prof}`"
        );
    }
}

#[test]
fn cve_catalog_parses_with_entries() {
    let doc = load_yaml("res/cve-catalog.yaml");
    let seq = doc
        .get("cves")
        .and_then(|c| c.as_sequence())
        .expect("cves is a sequence");
    assert!(!seq.is_empty(), "cve catalog is empty");
}

#[test]
fn cve_ids_are_unique() {
    let doc = load_yaml("res/cve-catalog.yaml");
    let ids: Vec<&str> = seq_strings(&doc, "cves", "id");
    let mut seen = HashSet::new();
    for id in &ids {
        assert!(seen.insert(id), "duplicate cve id: {id}");
    }
}

#[test]
fn cve_cvss_in_valid_range() {
    let doc = load_yaml("res/cve-catalog.yaml");
    let seq = doc.get("cves").unwrap().as_sequence().unwrap();
    for entry in seq {
        let cvss = entry
            .get("cvss")
            .and_then(|v| v.as_f64())
            .or_else(|| entry.get("cvss").and_then(|v| v.as_i64().map(|i| i as f64)))
            .expect("entry has a numeric cvss");
        assert!((0.0..=10.0).contains(&cvss), "cvss {cvss} outside [0,10]");
    }
}

#[test]
fn cve_layers_are_known() {
    let doc = load_yaml("res/cve-catalog.yaml");
    let seq = doc.get("cves").unwrap().as_sequence().unwrap();
    for entry in seq {
        let layer = entry
            .get("layer")
            .and_then(|l| l.as_str())
            .expect("entry has a layer");
        assert!(
            VALID_CVE_LAYERS.contains(&layer),
            "unknown cve layer: {layer}"
        );
    }
}

#[test]
fn cve_binary_paths_when_absolute_are_valid() {
    let doc = load_yaml("res/cve-catalog.yaml");
    let seq = doc.get("cves").unwrap().as_sequence().unwrap();
    for entry in seq {
        let Some(b) = entry.get("binary").and_then(|v| v.as_str()) else {
            continue;
        };
        if b.contains('/') {
            assert!(b.starts_with('/'), "cve binary not absolute: {b}");
        }
    }
}
