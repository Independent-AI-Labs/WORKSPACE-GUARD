use super::*;

fn bytes<'a>(args: &[&'a str]) -> Vec<&'a [u8]> {
    args.iter().map(|s| s.as_bytes()).collect()
}

#[test]
fn tag_message_operand_is_not_a_force_flag() {
    // REQ-GGUARD-030: `-m`/`--message` take the message, even when the
    // message text begins with `-`.
    let state = parse_args(&bytes(&["git", "tag", "-m", "--force", "v1"])).unwrap();
    assert!(!state.has_force_flag);
}

#[test]
fn branch_move_and_copy_operands_are_not_flags() {
    let moved = parse_args(&bytes(&["git", "branch", "-m", "--force"])).unwrap();
    assert!(!moved.has_force_flag);
    let copied = parse_args(&bytes(&["git", "branch", "--copy", "-D", "old", "new"])).unwrap();
    assert!(!copied.has_branch_d);
}

#[test]
fn real_force_flags_are_still_recorded() {
    assert!(
        parse_args(&bytes(&["git", "branch", "--force", "main"]))
            .unwrap()
            .has_force_flag
    );
    assert!(
        parse_args(&bytes(&["git", "tag", "-f", "v1"]))
            .unwrap()
            .has_force_flag
    );
    assert!(
        parse_args(&bytes(&["git", "branch", "-D", "main"]))
            .unwrap()
            .has_branch_d
    );
}
