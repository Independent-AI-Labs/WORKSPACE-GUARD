use std::ffi::OsString;

use crate::GuardError;

/// L4 (SECURITY-AUDIT-2026-07-18-EXEMPTION-TAMPERING): `git fetch` used to
/// accept unrestricted refspecs, so an agent could pull arbitrary object
/// IDs into the object database and reference them from planted refs.
/// Refspecs are now limited to ref names and refs/... paths; raw object
/// IDs (40-64 hex) and empty refspec sides are rejected. --upload-pack
/// stays blocked globally by the flag parser.
fn is_hex_oid(s: &str) -> bool {
    (40..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn check_fetch_refspecs(argv_os: &[OsString]) -> Result<(), GuardError> {
    // Fetch flags that consume the following argv element as a value.
    const VALUE_FLAGS: &[&str] = &[
        "--depth",
        "--deepen",
        "--shallow-since",
        "--shallow-exclude",
        "--filter",
        "--negotiation-tip",
        "--server-option",
        "-o",
        "-j",
        "--jobs",
    ];
    let mut seen_remote = false;
    let mut skip_next = false;
    for arg in argv_os.iter().skip(1) {
        let s = arg.to_string_lossy();
        if skip_next {
            skip_next = false;
            continue;
        }
        if s == "fetch" {
            continue;
        }
        if let Some(rest) = s.strip_prefix("--") {
            // --flag=value forms never consume the next element.
            if !rest.contains('=') && VALUE_FLAGS.contains(&s.as_ref()) {
                skip_next = true;
            }
            continue;
        }
        if s.starts_with('-') && s.len() > 1 {
            if VALUE_FLAGS.contains(&s.as_ref()) {
                skip_next = true;
            }
            continue;
        }
        if !seen_remote {
            seen_remote = true;
            continue;
        }
        validate_fetch_refspec(&s)?;
    }
    Ok(())
}

fn validate_fetch_refspec(spec: &str) -> Result<(), GuardError> {
    let body = spec.strip_prefix('+').unwrap_or(spec);
    let (src, dst) = match body.split_once(':') {
        Some((s, d)) => (s, Some(d)),
        None => (body, None),
    };
    let reject = |what: &str| -> Result<(), GuardError> {
        Err(GuardError::Blocked {
            reason: format!("git fetch: {} in refspec '{}'", what, spec),
            hint: "Fetch refs by branch/tag name (e.g. git fetch origin main); raw object IDs and empty refspec sides are not allowed.".into(),
        })
    };
    if src.is_empty() {
        return reject("empty source");
    }
    if is_hex_oid(src) {
        return reject("raw object ID source");
    }
    if let Some(d) = dst {
        if d.is_empty() {
            return reject("empty destination");
        }
        if is_hex_oid(d) {
            return reject("raw object ID destination");
        }
    }
    Ok(())
}
