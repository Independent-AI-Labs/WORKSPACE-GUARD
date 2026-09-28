// REQ-GGUARD-053: /proc/self/stat foreground-push parser fixtures.

use super::{parse_stat_process_groups, push_is_backgrounded};

fn stat(comm: &str, tail: &str) -> String {
    format!("1234 ({comm}) {tail}")
}

#[test]
fn foreground_group_parses() {
    // fields after comm: state ppid pgrp session tty_nr tpgid
    assert_eq!(
        parse_stat_process_groups(&stat("bash", "S 1 100 100 0 100")),
        Ok((100, 100))
    );
    assert!(!push_is_backgrounded(100, 100));
}

#[test]
fn background_group_is_detected() {
    assert_eq!(
        parse_stat_process_groups(&stat("bash", "S 1 100 100 0 200")),
        Ok((100, 200))
    );
    assert!(push_is_backgrounded(100, 200));
}

#[test]
fn no_controlling_terminal_and_zero_are_foreground() {
    assert_eq!(
        parse_stat_process_groups(&stat("bash", "S 1 100 100 0 -1")),
        Ok((100, -1))
    );
    assert!(!push_is_backgrounded(100, -1));
    assert_eq!(
        parse_stat_process_groups(&stat("bash", "S 1 100 100 0 0")),
        Ok((100, 0))
    );
    assert!(!push_is_backgrounded(100, 0));
}

#[test]
fn comm_with_spaces_and_parens_uses_final_delimiter() {
    assert_eq!(
        parse_stat_process_groups(&stat("weird ) name", "R 1 42 42 0 42")),
        Ok((42, 42))
    );
}

#[test]
fn missing_comm_delimiter_fails() {
    assert!(parse_stat_process_groups("1234 bash S 1 100 100").is_err());
}

#[test]
fn truncated_fields_fail() {
    assert!(parse_stat_process_groups(&stat("bash", "S 1 100 100")).is_err());
}

#[test]
fn non_numeric_fields_fail() {
    assert!(parse_stat_process_groups(&stat("bash", "S 1 x 100 0 100")).is_err());
    assert!(parse_stat_process_groups(&stat("bash", "S 1 100 100 0 y")).is_err());
}

#[test]
fn signed_integer_overflow_fails() {
    assert!(parse_stat_process_groups(&stat("bash", "S 1 99999999999 100 0 100")).is_err());
    assert!(parse_stat_process_groups(&stat("bash", "S 1 100 100 0 -99999999999")).is_err());
}
