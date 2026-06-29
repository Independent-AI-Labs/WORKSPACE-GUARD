use std::ffi::CStr;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::LOG_FILE;

pub fn block(reason: &str, hint: &str, cmd: &str) -> ! {
    let ts = timestamp();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "?".to_string());

    let uid = unsafe { libc::getuid() };

    let msg = format!("BLOCKED: {} ({})\n  -> Hint: {}", cmd, ts, hint);

    eprintln!("{}", msg);

    if let Ok(tty) = fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = writeln!(&tty, "{}", msg);
    }

    let home = get_user_home(uid);
    if let Some(ref home_dir) = home {
        let log_path = Path::new(home_dir).join(LOG_FILE);
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&log_path)
        {
            let _ = writeln!(f, "{}|{}|{}|{}|uid={}", ts, cwd, cmd, reason, uid);
        }
    }

    process::exit(1);
}

fn get_user_home(uid: u32) -> Option<String> {
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return None;
        }
        let dir = (*pw).pw_dir;
        if dir.is_null() {
            return None;
        }
        Some(CStr::from_ptr(dir).to_string_lossy().to_string())
    }
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

    let mut buf = [0 as libc::c_char; 64];
    let len = unsafe {
        libc::strftime(
            buf.as_mut_ptr(),
            buf.len(),
            c"%Y-%m-%dT%H:%M:%S%z".as_ptr(),
            &tm,
        )
    };

    if len > 0 {
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr(), len) };
        String::from_utf8_lossy(bytes).to_string()
    } else {
        "1970-01-01T00:00:00+0000".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::get_user_home;

    #[test]
    fn get_home_for_current_user() {
        let actual_uid = unsafe { libc::getuid() };
        let home = get_user_home(actual_uid);
        assert!(home.is_some());
        assert!(!home.unwrap().is_empty());
    }

    #[test]
    fn get_home_for_root() {
        let home = get_user_home(0);
        assert!(home.is_some());
    }

    #[test]
    fn get_home_for_nonexistent_uid() {
        let home = get_user_home(u32::MAX);
        assert!(home.is_none());
    }
}
