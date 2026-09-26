use crate::install::{is_immutable, set_immutable};
use crate::ops::{acquire_lock, audit, check_override_owner, fail, parse_doc, require_root, Cli};
use crate::target::Target;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};

fn sha256(file: &std::fs::File) -> Result<String, String> {
    let mut reader = file
        .try_clone()
        .map_err(|e| format!("cannot clone file for hashing: {e}"))?;
    reader
        .rewind()
        .map_err(|e| format!("cannot rewind file for hashing: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|e| format!("cannot hash file: {e}"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn run(cli: &Cli) {
    require_root();
    check_override_owner(&cli.file);
    let expected = cli.expected_sha256.as_deref().unwrap_or_default();
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        fail(
            2,
            "expected SHA-256 must be exactly 64 hexadecimal characters",
        );
    }
    let expected = expected.to_ascii_lowercase();
    let _lock = acquire_lock();
    let mut target = Target::open(&cli.file, true).unwrap_or_else(|e| fail(2, &e));
    let raw = target.read_string().unwrap_or_else(|e| fail(1, &e));
    parse_doc(&raw, &cli.file);
    let was_immutable = is_immutable(&target.path);
    if was_immutable {
        set_immutable(&target.path, false).unwrap_or_else(|e| fail(1, &e));
    }
    let result = (|| {
        target.refresh_identity()?;
        let actual = sha256(&target.file)?;
        target.check_stable()?;
        if actual != expected {
            return Err(format!(
                "SHA-256 mismatch: expected {expected}, got {actual}"
            ));
        }
        audit(cli, "delete")?;
        target.unlink()?;
        Ok(actual)
    })();
    let actual = match result {
        Ok(actual) => actual,
        Err(error) => {
            if was_immutable {
                let _ = set_immutable(&target.path, true);
            }
            fail(1, &error);
        }
    };
    println!(
        "yaml-edit: deleted {} sha256={actual}",
        target.path.display()
    );
}
