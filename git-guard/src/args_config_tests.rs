use super::*;

fn bytes<'a>(args: &[&'a str]) -> Vec<&'a [u8]> {
    args.iter().map(|s| s.as_bytes()).collect()
}

#[test]
fn parse_args_config_implicit_true_forms_are_checked() {
    // REQ-GGUARD-041: no `=` means implicit boolean true; both the separate
    // and attached no-value forms must still be matched against policy.
    let separate = parse_args(&bytes(&["git", "-c", "core.hooksPath", "commit"])).unwrap();
    assert!(!separate.dangerous_config_keys.is_empty());
    let attached = parse_args(&bytes(&["git", "-ccore.hooksPath", "commit"])).unwrap();
    assert!(!attached.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_config_malformed_key_is_exit_2() {
    // REQ-GGUARD-041: empty, non-ASCII, or non-UTF-8 keys are malformed
    // invocations, never lossily collapsed to an empty string.
    for args in [
        bytes(&["git", "-c", "=evil", "commit"]),
        bytes(&["git", "-c", "", "commit"]),
        bytes(&["git", "-c", "caf\u{e9}=evil", "commit"]),
    ] {
        assert!(matches!(
            parse_args(&args),
            Err(GuardError::InvalidInvocation(_))
        ));
    }
    let raw: Vec<Vec<u8>> = vec![b"git".to_vec(), b"-c".to_vec(), vec![0xff, 0xfe]];
    let refs: Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
    assert!(matches!(
        parse_args(&refs),
        Err(GuardError::InvalidInvocation(_))
    ));
}

#[test]
fn parse_args_config_key_case_folded_only_for_matching() {
    // Stored key is byte-exact (audit evidence); the matcher folds ASCII case.
    let state = parse_args(&bytes(&["git", "-c", "CORE.HOOKSPATH=/evil", "commit"])).unwrap();
    assert_eq!(
        state.dangerous_config_keys,
        vec!["CORE.HOOKSPATH".to_string()]
    );
}
