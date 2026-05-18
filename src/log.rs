use std::fs;
use std::io::Write;
use std::path::Path;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::LOG_FILE;

pub fn block(reason: &str, hint: &str) -> ! {
    let ts = timestamp();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "?".to_string());
    let uid = unsafe { libc::getuid() };

    let msg = format!("BLOCKED: git {} ({})\n  → Hint: {}", reason, ts, hint);

    eprintln!("{}", msg);

    if let Ok(tty) = fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = writeln!(&tty, "{}", msg);
    }

    if let Ok(home) = std::env::var("HOME") {
        let log_path = Path::new(&home).join(LOG_FILE);
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = writeln!(f, "{}|{}|git {}|{}|uid={}", ts, cwd, reason, reason, uid);
        }
    }

    process::exit(1);
}

fn timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs() as libc::time_t;

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&secs, &mut tm);
    }

    let mut buf = [0i8; 64];
    let len = unsafe {
        libc::strftime(
            buf.as_mut_ptr(),
            buf.len(),
            c"%Y-%m-%dT%H:%M:%S%z".as_ptr(),
            &tm,
        )
    };

    if len > 0 {
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len) };
        String::from_utf8_lossy(bytes).to_string()
    } else {
        "1970-01-01T00:00:00+0000".to_string()
    }
}
