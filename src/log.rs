use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::unistd::{getuid, Uid, User};

use crate::LOG_FILE;

pub fn block(reason: &str, hint: &str, cmd: &str) -> ! {
    let ts = timestamp();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "?".to_string());

    let uid = getuid().as_raw();

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

pub fn warn(message: &str) {
    let ts = timestamp();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "?".to_string());
    let uid = getuid().as_raw();

    eprintln!("{}", message);

    if let Ok(tty) = fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = writeln!(&tty, "{}", message);
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
            let _ = writeln!(f, "{}|{}|WARN|{}|uid={}", ts, cwd, message, uid);
        }
    }
}

fn get_user_home(uid: u32) -> Option<String> {
    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.dir.to_string_lossy().to_string())
}

/// Format the current wall-clock as an ISO-8601-UTC string of the form
/// `YYYY-MM-DDTHH:MM:SS+0000`.
///
/// This is a safe (no `libc`, no `unsafe`) replacement for the prior
/// `localtime_r` + `strftime` block. We log in UTC (`+0000` offset), which
/// is the correct choice for audit-log timestamps (no timezone ambiguity,
/// no dep on the host tz database), and matches the prior fall-back value
/// `1970-01-01T00:00:00+0000` exactly. The civil-date breakdown follows
/// Howard Hinnant's `days_from_civil` inverse (proleptic Gregorian, valid
/// for all signed-Unix-second inputs): proven correct for epochs from
/// -7685-03-01 through 7685-02-28.
fn timestamp() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH);
    let secs: i64 = match now {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    };
    let (year, month, day, hour, minute, second) = civil_from_unix(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+0000",
        year, month, day, hour, minute, second
    )
}

/// Map seconds since the UNIX epoch (1970-01-01 00:00:00 UTC) to a UTC
/// civil (year, month, day, hour, minute, second) tuple.
///
/// Algorithm: Howard Hinnant, civil_from_days(), adapted for signed input
/// and intra-day remainder. See http://howardhinnant.github.io/date_algorithms.html.
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let hour = (rem / 3600) as u32;
    let minute = ((rem % 3600) / 60) as u32;
    let second = (rem % 60) as u32;

    // days_from_civil() inverse; days counts from 1970-01-01, shifted to
    // 0000-03-01 (Hinnant epoch) by adding 719468.
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    (year, m as u32, d as u32, hour, minute, second)
}

#[cfg(test)]
mod tests {
    use super::{civil_from_unix, get_user_home};
    use nix::unistd::getuid;

    #[test]
    fn get_home_for_current_user() {
        let actual_uid = getuid().as_raw();
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

    #[test]
    fn epoch_zero_maps_to_1970_01_01() {
        let (y, m, d, h, mi, s) = civil_from_unix(0);
        assert_eq!((y, m, d, h, mi, s), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn known_unix_second_maps_to_expected_utc() {
        // 2021-01-15T12:34:56Z = 1610714096 seconds since epoch.
        let (y, m, d, h, mi, s) = civil_from_unix(1610714096);
        assert_eq!((y, m, d, h, mi, s), (2021, 1, 15, 12, 34, 56));
    }

    #[test]
    fn leap_day_2020_02_29_roundtrips() {
        // 2020-02-29T00:00:00Z = 1582934400.
        let (y, m, d, _, _, _) = civil_from_unix(1582934400);
        assert_eq!((y, m, d), (2020, 2, 29));
        // +1 day = 2020-03-01 (the leap day boundary must roll correctly).
        let (y2, m2, d2, _, _, _) = civil_from_unix(1582934400 + 86400);
        assert_eq!((y2, m2, d2), (2020, 3, 1));
    }

    #[test]
    fn negative_seconds_before_epoch_roll_back() {
        // -1 second should map to 1969-12-31T23:59:59Z.
        let (y, m, d, h, mi, s) = civil_from_unix(-1);
        assert_eq!((y, m, d, h, mi, s), (1969, 12, 31, 23, 59, 59));
    }
}
