use super::*;

#[test]
fn glob_trees_does_not_crash_on_large_dir_hierarchy() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    for i in 0..10 {
        let sub = root.join(format!("depth{}", i));
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("file.txt"), b"x").unwrap();
    }

    lock_glob_trees(root, ".boot*");
}

#[test]
fn glob_trees_multiple_matching_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let b1 = root.join(".boot-one");
    fs::create_dir_all(&b1).unwrap();
    fs::write(b1.join("a.bin"), b"x").unwrap();

    let b2 = root.join(".boot-two");
    fs::create_dir_all(&b2).unwrap();
    fs::write(b2.join("b.bin"), b"x").unwrap();

    let nested = root.join("sub").join(".boot-three");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("c.bin"), b"x").unwrap();

    lock_glob_trees(root, ".boot*");

    assert!(b1.join("a.bin").exists());
    assert!(b2.join("b.bin").exists());
    assert!(nested.join("c.bin").exists());
}

#[test]
fn glob_trees_does_not_match_non_dot_boot_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let normal = root.join("boot");
    fs::create_dir_all(&normal).unwrap();
    fs::write(normal.join("x.txt"), b"x").unwrap();

    let partial = root.join("myboot-extra");
    fs::create_dir_all(&partial).unwrap();
    fs::write(partial.join("y.txt"), b"x").unwrap();

    lock_glob_trees(root, ".boot*");

    assert!(normal.join("x.txt").exists());
    assert!(partial.join("y.txt").exists());
}

#[test]
fn glob_trees_handles_empty_root() {
    let dir = tempfile::tempdir().unwrap();
    lock_glob_trees(dir.path(), ".boot*");
}

#[test]
fn glob_trees_handles_root_is_file() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("not_a_dir");
    fs::write(&f, b"x").unwrap();
    lock_glob_trees(&f, ".boot*");
}

#[test]
fn glob_trees_exec_bits_preserved_on_binary_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let boot_dir = root.join(".boot-test");
    fs::create_dir_all(&boot_dir).unwrap();
    fs::write(boot_dir.join("node"), b"x").unwrap();
    fs::write(boot_dir.join("script.sh"), b"#!/bin/sh\necho hi\n").unwrap();

    std::process::Command::new("chmod")
        .args(["+x", &boot_dir.join("node").to_string_lossy()])
        .output()
        .unwrap();
    std::process::Command::new("chmod")
        .args(["+x", &boot_dir.join("script.sh").to_string_lossy()])
        .output()
        .unwrap();

    lock_glob_trees(root, ".boot*");

    let node_mode = fs::symlink_metadata(boot_dir.join("node"))
        .unwrap()
        .st_mode()
        & 0o111;
    let script_mode = fs::symlink_metadata(boot_dir.join("script.sh"))
        .unwrap()
        .st_mode()
        & 0o111;

    assert!(node_mode != 0, "node lost all execute bits");
    assert!(script_mode != 0, "script.sh lost all execute bits");
}
