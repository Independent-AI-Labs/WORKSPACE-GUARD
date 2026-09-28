//! Byte-exact argv conversion tests (REQ-GGUARD-014).

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use crate::exec::argv_to_cstrings;
use crate::GuardError;

#[test]
fn every_argument_survives_in_order_and_bytes() {
    let args: Vec<OsString> = ["git", "push", "origin", "main"]
        .iter()
        .map(OsString::from)
        .collect();
    let converted = argv_to_cstrings(&args).expect("no NUL");
    let got: Vec<&[u8]> = converted.iter().map(|c| c.as_bytes()).collect();
    let want: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
    assert_eq!(got, want);
}

#[test]
fn non_utf8_argument_survives_byte_for_byte() {
    let raw = vec![0x66, 0x6f, 0xff, 0x80, 0x6f];
    let args = vec![
        OsString::from("git"),
        OsString::from_vec(raw.clone()),
        OsString::from(""),
    ];
    let converted = argv_to_cstrings(&args).expect("no NUL");
    assert_eq!(converted[1].as_bytes(), raw.as_slice());
    assert_eq!(converted[2].as_bytes(), b"");
}

#[test]
fn embedded_nul_is_a_typed_exit_2_without_substitution() {
    let bad = OsString::from_vec(vec![b'a', 0, b'b']);
    let err = argv_to_cstrings(&[OsString::from("git"), bad]).unwrap_err();
    assert!(matches!(err, GuardError::InvalidInvocation(_)));
    assert_eq!(err.exit_code(), 2);
}
