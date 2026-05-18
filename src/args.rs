use crate::{GuardError, DANGEROUS_CONFIG_KEYS};

pub struct ArgState {
    pub subcommand: Option<String>,
    pub has_amend: bool,
    pub has_force_flag: bool,
    pub has_force_with_lease_flag: bool,
    pub has_branch_d: bool,
    pub has_stash_drop: bool,
    pub has_stash_clear: bool,
    pub safe_pull_flag: bool,
    pub has_ff_only: bool,
    pub dangerous_config_keys: Vec<String>,
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
        has_stash_drop: false,
        has_stash_clear: false,
        safe_pull_flag: false,
        has_ff_only: false,
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
                let key = &arg_str[..pos];
                if DANGEROUS_CONFIG_KEYS.contains(&key.to_lowercase().as_str()) {
                    state.dangerous_config_keys.push(key.to_string());
                }
            } else if DANGEROUS_CONFIG_KEYS.contains(&arg_str.to_lowercase().as_str()) {
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
                        hint: "Remove --no-verify — hooks enforce policy".into(),
                    });
                }
                _ => {}
            }
            if arg_str == "--force" || arg_str == "-f" {
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
            if arg_str.contains('=') && arg_str.starts_with("--") {
                let eq_pos = arg_str.find('=').unwrap();
                let flag_key = &arg_str[2..eq_pos];
                if flag_key == "c" || flag_key == "C" {
                    let val = &arg_str[eq_pos + 1..];
                    if let Some(val_eq) = val.find('=') {
                        let cfg_key = &val[..val_eq];
                        if DANGEROUS_CONFIG_KEYS.contains(&cfg_key.to_lowercase().as_str()) {
                            state.dangerous_config_keys.push(cfg_key.to_string());
                        }
                    }
                }
            }
            i += 1;
            continue;
        }

        if arg.starts_with(b"-") && arg.len() > 1 {
            let flags = &arg[1..];
            for &ch in flags {
                match ch {
                    b'c' | b'C' => {
                        expecting_config = true;
                        break;
                    }
                    b'f' => state.has_force_flag = true,
                    b'D' => state.has_branch_d = true,
                    _ => {}
                }
            }
            i += 1;
            continue;
        }

        if state.subcommand.is_none() && !arg_str.is_empty() && !arg_str.starts_with('-') {
            state.subcommand = Some(arg_str.to_string());
            if arg_str == "stash" {
                for &arg in &argv[i + 1..] {
                    let sarg = std::str::from_utf8(arg).unwrap_or("");
                    if sarg == "drop" {
                        state.has_stash_drop = true;
                    }
                    if sarg == "clear" {
                        state.has_stash_clear = true;
                    }
                }
            }
            if arg_str == "push" {
                for &arg in &argv[i + 1..] {
                    let sarg = std::str::from_utf8(arg).unwrap_or("");
                    if sarg == "--force" || sarg == "-f" {
                        state.has_force_flag = true;
                    }
                    if sarg == "--force-with-lease" {
                        state.has_force_with_lease_flag = true;
                    }
                }
            }
            if arg_str == "commit" {
                for &arg in &argv[i + 1..] {
                    let sarg = std::str::from_utf8(arg).unwrap_or("");
                    if sarg.starts_with("--amend") {
                        state.has_amend = true;
                    }
                }
            }
            if arg_str == "merge" {
                for &arg in &argv[i + 1..] {
                    let sarg = std::str::from_utf8(arg).unwrap_or("");
                    if sarg == "--ff-only" {
                        state.has_ff_only = true;
                    }
                }
            }
        }

        i += 1;
    }

    Ok(state)
}
