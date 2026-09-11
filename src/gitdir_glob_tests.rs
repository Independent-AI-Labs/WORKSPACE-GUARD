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

    lock_worktree_globs(root);
}

#[test]
fn glob_trees_handles_empty_root() {
    let dir = tempfile::tempdir().unwrap();
    lock_worktree_globs(dir.path());
}

#[test]
fn glob_trees_handles_root_is_file() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("not_a_dir");
    fs::write(&f, b"x").unwrap();
    lock_worktree_globs(&f);
}
