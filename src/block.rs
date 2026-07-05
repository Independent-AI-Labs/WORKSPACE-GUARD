use std::ffi::OsString;
use std::fs;
use std::os::unix::process::ExitStatusExt;

use crate::{
    args::ArgState, is_config_key_blocked, GuardError, BLOCKED_BYPASS_VARS, BLOCKED_SUBCOMMANDS,
    CHILD_PATH, PROTECTED_BRANCHES, PROTECTED_BRANCH_PREFIXES, SUDO_GATED_SUBCOMMANDS,
    VALUE_TAKING_OPTS,
};

pub fn check_blocked(
    state: &ArgState,
    subcommand: &str,
    argv_os: &[OsString],
    git_path: &str,
    cwd: Option<&str>,
) -> Result<(), GuardError> {
    let sudo = crate::is_sudo();
    if subcommand == "config" {
        // Only block git config when setting a dangerous key.
        // Legitimate git config (user.name, user.email, etc.) is allowed.
        // Dangerous keys (core.hookspath, filter.*.smudge, etc.) are blocked.
        // Checks both -c flags (parsed during arg processing) and positional
        // key argument (the first non-flag arg after "config").
        if !state.dangerous_config_keys.is_empty() {
            let keys = state.dangerous_config_keys.join(", ");
            return Err(GuardError::Blocked {
                reason: format!("git config: dangerous config key(s): {}", keys),
                hint: "Remove the -c flag with the dangerous config key".into(),
            });
        }
        // Check positional key argument (git config <key> <value>)
        // Also catches keys after value-taking options like --file <path> <key>
        let mut skip_next = false;
        for arg in argv_os.iter().skip(1) {
            let s = arg.to_string_lossy();
            if s == "config" {
                continue;
            }
            if skip_next {
                skip_next = false;
                continue;
            }
            if s.starts_with('-') {
                let opt = s.split('=').next().unwrap_or(&s);
                if VALUE_TAKING_OPTS.contains(&opt) {
                    skip_next = true;
                }
                continue;
            }
            if is_config_key_blocked(&s, sudo) {
                return Err(GuardError::Blocked {
                    reason: format!("git config: dangerous config key: {}", s),
                    hint: "Use a non-dangerous config key instead".into(),
                });
            }
        }
    } else if SUDO_GATED_SUBCOMMANDS.contains(&subcommand) {
        if !sudo {
            return Err(GuardError::Blocked {
                reason: format!(
                    "sudo-gated subcommand: git {} (non-root denied)",
                    subcommand
                ),
                hint: format!(
                    "Run with sudo: 'sudo git {}' (root-only operation)",
                    subcommand
                ),
            });
        }
    } else if BLOCKED_SUBCOMMANDS.contains(&subcommand) {
        return Err(GuardError::Blocked {
            reason: format!("destructive subcommand: git {}", subcommand),
            hint: format!(
                "Use a non-destructive git command instead of {}",
                subcommand
            ),
        });
    }

    if subcommand == "rm" && !state.has_cached {
        return Err(GuardError::Blocked {
            reason: "git rm (destructive - removes files from index + disk)".into(),
            hint: "Use 'git rm --cached' to remove from index only (keeps files on disk)".into(),
        });
    }

    if subcommand == "stash" && (state.has_stash_drop || state.has_stash_clear) && !sudo {
        let what = if state.has_stash_drop {
            "drop"
        } else {
            "clear"
        };
        return Err(GuardError::Blocked {
            reason: format!("git stash {}", what),
            hint: "Use 'git stash pop' to restore without losing, or 'git stash list' to review"
                .into(),
        });
    }

    if subcommand == "branch" && state.has_branch_d {
        return Err(GuardError::Blocked {
            reason: "git branch -D (force delete)".into(),
            hint: "Use 'git branch -d' for safe delete (only merged branches)".into(),
        });
    }

    if subcommand == "branch" && state.has_branch_force_rename {
        return Err(GuardError::Blocked {
            reason: "git branch -M (force rename)".into(),
            hint: "Use 'git branch -m' for safe rename (refuses to overwrite existing)".into(),
        });
    }

    if subcommand == "tag" && state.has_force_flag {
        return Err(GuardError::Blocked {
            reason: "git tag -f (force move tag)".into(),
            hint: "Tags are immutable: create a new tag instead of force-moving".into(),
        });
    }

    if subcommand == "tag" && state.has_branch_d {
        return Err(GuardError::Blocked {
            reason: "git tag -d / -D (delete tag)".into(),
            hint: "Tags are immutable: archive rather than delete".into(),
        });
    }

    if subcommand == "push" && (state.has_force_flag || state.has_force_with_lease_flag) {
        return Err(GuardError::Blocked {
            reason: "git push --force".into(),
            hint:
                "Use 'git push' without --force, or --force-with-lease if you understand the risks"
                    .into(),
        });
    }

    if subcommand == "push" && state.has_delete_flag {
        return Err(GuardError::Blocked {
            reason: "git push --delete / -d (delete remote branch)".into(),
            hint: "Deleting remote branches is forbidden: archive or rename instead".into(),
        });
    }

    if subcommand == "push" {
        if let Ok(stat) = fs::read_to_string("/proc/self/stat") {
            if let Some(pos) = stat.rfind(')') {
                let fields: Vec<&str> = stat[pos + 1..].split_whitespace().collect();
                if fields.len() > 4 {
                    let pgrp: i32 = fields[1].parse().unwrap_or(0);
                    let tpgid: i32 = fields[4].parse().unwrap_or(0);
                    if tpgid > 0 && pgrp != tpgid {
                        return Err(GuardError::Blocked {
                            reason: "git push from background process".into(),
                            hint: "Run 'git push' in the foreground so hooks can interact".into(),
                        });
                    }
                }
            }
        }
    }

    if subcommand == "commit" && state.has_amend {
        return Err(GuardError::Blocked {
            reason: "git commit --amend".into(),
            hint: "Make a new commit instead: history is immutable, amends are forbidden".into(),
        });
    }

    if subcommand == "revert" {
        let target = extract_revert_target(argv_os);
        if let Ok(branch) = get_current_branch(git_path, cwd) {
            if branch != "HEAD" && !branch.is_empty() {
                let exists = run_git(
                    git_path,
                    cwd,
                    &[
                        "git",
                        "rev-parse",
                        "--verify",
                        &format!("{}^{{commit}}", target),
                    ],
                );
                let on_remote = run_git(
                    git_path,
                    cwd,
                    &[
                        "git",
                        "merge-base",
                        "--is-ancestor",
                        &target,
                        &format!("origin/{}", branch),
                    ],
                );
                if exists.success() && !on_remote.success() {
                    return Err(GuardError::Blocked {
                        reason: format!(
                            "git revert on {} which is not on origin/{}",
                            target, branch
                        ),
                        hint: "Edit forward with a new commit instead of reverting un-pushed work"
                            .into(),
                    });
                }
            }
        }
    }

    if subcommand == "pull" && is_protected_branch(git_path, cwd) && !state.safe_pull_flag {
        return Err(GuardError::Blocked {
            reason: "git pull on protected branch without --ff-only or --rebase".into(),
            hint: "Use 'git pull --ff-only' or 'git pull --rebase' to avoid merge commits".into(),
        });
    }

    if subcommand == "merge"
        && !sudo
        && is_protected_branch(git_path, cwd)
        && !state.has_ff_only
        && !state.has_merge_abort
    {
        return Err(GuardError::Blocked {
            reason: "git merge on protected branch without --ff-only".into(),
            hint: "Use 'git merge --ff-only' to avoid creating merge commits, or 'git merge --abort' to cancel an in-progress merge".into(),
        });
    }

    if subcommand == "rebase" && !state.has_rebase_safe_flag {
        return Err(GuardError::Blocked {
            reason: "git rebase (destructive rewrite of history)".into(),
            hint: "Use 'git rebase --continue/--abort/--skip' to complete an in-progress rebase, or use 'git pull --rebase' instead".into(),
        });
    }

    for &var in BLOCKED_BYPASS_VARS {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                return Err(GuardError::Blocked {
                    reason: format!("{} environment variable set (hook bypass)", var),
                    hint: format!("Unset {} before running git commands", var),
                });
            }
        }
    }

    Ok(())
}

fn git_cmd(git_path: &str, cwd: Option<&str>) -> std::process::Command {
    let mut cmd = std::process::Command::new(git_path);
    cmd.env_clear().env("PATH", CHILD_PATH).env("HOME", "/");
    crate::apply_safe_directory(&mut cmd);
    for (k, v) in crate::gitdir::hardened_git_env() {
        cmd.env(k, v);
    }
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    cmd
}

fn get_current_branch(git_path: &str, cwd: Option<&str>) -> Result<String, ()> {
    let output = git_cmd(git_path, cwd)
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .map_err(|_| ())?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(())
    }
}

fn is_protected_branch(git_path: &str, cwd: Option<&str>) -> bool {
    match get_current_branch(git_path, cwd) {
        Ok(ref b) => {
            let lower = b.to_lowercase();
            PROTECTED_BRANCHES.contains(&lower.as_str())
                || PROTECTED_BRANCH_PREFIXES
                    .iter()
                    .any(|p| lower.starts_with(p))
        }
        Err(_) => false,
    }
}

fn extract_revert_target(argv_os: &[OsString]) -> String {
    for arg in argv_os.iter().skip(1) {
        let s = arg.to_string_lossy();
        if !s.starts_with('-') && s != "revert" {
            return s.to_string();
        }
    }
    "HEAD".to_string()
}

fn run_git(git_path: &str, cwd: Option<&str>, args: &[&str]) -> std::process::ExitStatus {
    git_cmd(git_path, cwd)
        .args(&args[1..])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap_or_else(|_| std::process::ExitStatus::from_raw(1))
}

#[cfg(test)]
#[path = "block_tests.rs"]
mod tests;
