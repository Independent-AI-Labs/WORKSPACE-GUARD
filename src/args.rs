use crate::{
    is_config_key_blocked, GuardError, BLOCKED_SUBCOMMANDS, SUBCOMMANDS_WITH_PARTIAL_BLOCKS,
};

pub struct ArgState {
    pub subcommand: Option<String>,
    pub has_amend: bool,
    pub has_force_flag: bool,
    pub has_force_with_lease_flag: bool,
    pub has_branch_d: bool,
    pub has_branch_force_rename: bool,
    pub has_stash_drop: bool,
    pub has_stash_clear: bool,
    pub safe_pull_flag: bool,
    pub has_rebase_safe_flag: bool,
    pub has_ff_only: bool,
    pub has_cached: bool,
    pub has_delete_flag: bool,
    pub dangerous_config_keys: Vec<String>,
}

fn resolve_subcommand_abbreviation(raw: &str) -> String {
    let raw_lower = raw.to_lowercase();
    let all_candidates: Vec<&&str> = BLOCKED_SUBCOMMANDS
        .iter()
        .chain(SUBCOMMANDS_WITH_PARTIAL_BLOCKS.iter())
        .collect();

    let mut matches: Vec<&&str> = all_candidates
        .iter()
        .filter(|c| c.starts_with(&raw_lower))
        .copied()
        .collect();
    matches.sort();
    matches.dedup();

    if matches.len() == 1 {
        return matches[0].to_string();
    }
    raw.to_string()
}

fn check_and_record_dangerous_config(key: &str, dangerous_keys: &mut Vec<String>) {
    if key.is_empty() {
        return;
    }
    let sudo = crate::is_sudo();
    if is_config_key_blocked(key, sudo) {
        dangerous_keys.push(key.to_string());
    }
}

pub fn check_null_bytes(argv: &[&[u8]]) -> Result<(), GuardError> {
    for arg in argv {
        if arg.contains(&0u8) {
            return Err(GuardError::NullByteInArg);
        }
    }
    Ok(())
}

pub fn parse_args(argv: &[&[u8]]) -> Result<ArgState, GuardError> {
    let mut state = ArgState {
        subcommand: None,
        has_amend: false,
        has_force_flag: false,
        has_force_with_lease_flag: false,
        has_branch_d: false,
        has_branch_force_rename: false,
        has_stash_drop: false,
        has_stash_clear: false,
        safe_pull_flag: false,
        has_rebase_safe_flag: false,
        has_ff_only: false,
        has_cached: false,
        has_delete_flag: false,
        dangerous_config_keys: Vec::new(),
    };

    let mut past_separator = false;
    let mut expecting_config = false;
    let mut i = 1;

    while i < argv.len() {
        let arg = argv[i];
        let arg_str = std::str::from_utf8(arg).unwrap_or("");

        if past_separator {
            break;
        }

        if arg == b"--" {
            past_separator = true;
            i += 1;
            continue;
        }

        if expecting_config {
            if let Some(pos) = arg_str.find('=') {
                let key = arg_str[..pos].trim();
                check_and_record_dangerous_config(key, &mut state.dangerous_config_keys);
            } else if is_config_key_blocked(arg_str.trim(), crate::is_sudo()) {
                state.dangerous_config_keys.push(arg_str.to_string());
            }
            expecting_config = false;
            i += 1;
            continue;
        }

        if arg == b"-c" || arg == b"-C" {
            expecting_config = true;
            i += 1;
            continue;
        }

        if arg.len() >= 3
            && (arg[0] == b'-' && (arg[1] == b'c' || arg[1] == b'C') && arg[2] != b'\0')
        {
            let rest = &arg[2..];
            if let Ok(rest_str) = std::str::from_utf8(rest) {
                if let Some(eq_pos) = rest_str.find('=') {
                    let key = rest_str[..eq_pos].trim();
                    check_and_record_dangerous_config(key, &mut state.dangerous_config_keys);
                }
            }
            i += 1;
            continue;
        }

        if arg.starts_with(b"--") {
            match arg_str {
                "--hard" => {
                    return Err(GuardError::Blocked {
                        reason: "--hard flag".into(),
                        hint: "Remove --hard from the command".into(),
                    });
                }
                "--no-verify" => {
                    return Err(GuardError::Blocked {
                        reason: "--no-verify flag".into(),
                        hint: "Remove --no-verify: hooks enforce policy".into(),
                    });
                }
                "--upload-pack" | "--receive-pack" | "--exec" => {
                    return Err(GuardError::Blocked {
                        reason: format!("dangerous flag: {}", arg_str),
                        hint: "Remove this flag: it enables arbitrary command execution".into(),
                    });
                }
                "--config" => {
                    expecting_config = true;
                    i += 1;
                    continue;
                }
                "--config-env" => {
                    expecting_config = true;
                    i += 1;
                    continue;
                }
                s if s.starts_with("--upload-pack=")
                    || s.starts_with("--receive-pack=")
                    || s.starts_with("--exec=") =>
                {
                    let flag_name = s.split('=').next().unwrap_or(s);
                    return Err(GuardError::Blocked {
                        reason: format!("dangerous flag: {}", flag_name),
                        hint: "Remove this flag: it enables arbitrary command execution".into(),
                    });
                }
                s if s.starts_with("--config=") => {
                    let val = &s["--config=".len()..];
                    if let Some(eq) = val.find('=') {
                        let key = val[..eq].trim();
                        check_and_record_dangerous_config(key, &mut state.dangerous_config_keys);
                    }
                    i += 1;
                    continue;
                }
                s if s.starts_with("--config-env=") => {
                    let val = &s["--config-env=".len()..];
                    if let Some(eq) = val.find('=') {
                        let key = val[..eq].trim();
                        check_and_record_dangerous_config(key, &mut state.dangerous_config_keys);
                    }
                    i += 1;
                    continue;
                }
                _ => {}
            }
            if arg_str == "--force" {
                state.has_force_flag = true;
            }
            if arg_str == "--force-with-lease" {
                state.has_force_with_lease_flag = true;
            }
            if arg_str.starts_with("--amend") {
                state.has_amend = true;
            }
            if arg_str.starts_with("--ff-only") || arg_str.starts_with("--rebase") {
                state.safe_pull_flag = true;
            }
            if arg_str == "--cached" {
                state.has_cached = true;
            }
            if arg_str == "--delete" {
                state.has_delete_flag = true;
            }
            if arg_str.contains('=') && arg_str.starts_with("--") {
                let eq_pos = arg_str.find('=').unwrap();
                let flag_key = &arg_str[2..eq_pos];
                if flag_key == "c" || flag_key == "C" {
                    let val = &arg_str[eq_pos + 1..];
                    if let Some(val_eq) = val.find('=') {
                        let cfg_key = val[..val_eq].trim();
                        check_and_record_dangerous_config(
                            cfg_key,
                            &mut state.dangerous_config_keys,
                        );
                    }
                }
            }
            i += 1;
            continue;
        }

        if arg.starts_with(b"-") && arg.len() > 1 {
            let flags = &arg[1..];
            for (idx, &ch) in flags.iter().enumerate() {
                match ch {
                    b'c' | b'C' => {
                        let remaining = &flags[idx + 1..];
                        if !remaining.is_empty() {
                            if let Ok(rest_str) = std::str::from_utf8(remaining) {
                                if let Some(eq_pos) = rest_str.find('=') {
                                    let key = rest_str[..eq_pos].trim();
                                    check_and_record_dangerous_config(
                                        key,
                                        &mut state.dangerous_config_keys,
                                    );
                                }
                            }
                        } else {
                            expecting_config = true;
                        }
                        break;
                    }
                    b'f' => state.has_force_flag = true,
                    b'D' => state.has_branch_d = true,
                    b'M' => state.has_branch_force_rename = true,
                    b'd' => state.has_delete_flag = true,
                    b'n' | b'N' => {
                        return Err(GuardError::Blocked {
                            reason: "-n flag (short form of --no-verify)".into(),
                            hint: "Remove -n: hooks enforce policy".into(),
                        });
                    }
                    _ => {}
                }
            }
            i += 1;
            continue;
        }

        if state.subcommand.is_none() && !arg_str.is_empty() && !arg_str.starts_with('-') {
            let resolved = resolve_subcommand_abbreviation(arg_str);
            state.subcommand = Some(resolved.clone());

            if resolved == "stash" {
                let mut past_dash = false;
                for &sarg in &argv[i + 1..] {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--" {
                        past_dash = true;
                        continue;
                    }
                    if past_dash {
                        continue;
                    }
                    if s == "drop" {
                        state.has_stash_drop = true;
                    }
                    if s == "clear" {
                        state.has_stash_clear = true;
                    }
                }
            }
            if resolved == "push" {
                let mut past_dash = false;
                for &sarg in &argv[i + 1..] {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--" {
                        past_dash = true;
                        continue;
                    }
                    if past_dash {
                        continue;
                    }
                    if s == "--force" || s == "-f" {
                        state.has_force_flag = true;
                    }
                    if s == "--force-with-lease" {
                        state.has_force_with_lease_flag = true;
                    }
                    if s == "--delete" || s == "-d" {
                        state.has_delete_flag = true;
                    }
                }
            }
            if resolved == "commit" {
                let mut past_dash = false;
                for &sarg in &argv[i + 1..] {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--" {
                        past_dash = true;
                        continue;
                    }
                    if past_dash {
                        continue;
                    }
                    if s.starts_with("--amend") {
                        state.has_amend = true;
                    }
                }
            }
            if resolved == "merge" {
                let mut past_dash = false;
                for &sarg in &argv[i + 1..] {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--" {
                        past_dash = true;
                        continue;
                    }
                    if past_dash {
                        continue;
                    }
                    if s == "--ff-only" {
                        state.has_ff_only = true;
                    }
                }
            }
            if resolved == "rebase" {
                let mut past_dash = false;
                for &sarg in &argv[i + 1..] {
                    let s = std::str::from_utf8(sarg).unwrap_or("");
                    if s == "--" {
                        past_dash = true;
                        continue;
                    }
                    if past_dash {
                        continue;
                    }
                    if s == "--continue" || s == "--abort" || s == "--skip" {
                        state.has_rebase_safe_flag = true;
                    }
                }
            }
        }

        i += 1;
    }

    Ok(state)
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
