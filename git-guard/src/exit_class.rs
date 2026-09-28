//! Guard failure exit-class contract (REQ-GGUARD-004, REQ-GGUARD-103).
//!
//! Every guard-originated failure maps to exactly one exit class, so a
//! caller can distinguish a malformed invocation from an unavailable guard
//! or a rejected contract:
//!
//! - exit 1: policy denial, delivered through `log::block`
//! - exit 2: malformed invocation (the caller's own argv)
//! - exit 3: guard unavailable / privilege or integrity setup failure
//! - exit 4: contract rejection or unavailable contract deployment

use crate::GuardError;

impl GuardError {
    /// Process exit class for a guard-originated failure.
    ///
    /// `Blocked` is normally delivered by `log::block` (exit 1); it is
    /// listed here to keep the match exhaustive if a denial is ever
    /// returned as an error instead.
    pub fn exit_code(&self) -> i32 {
        match self {
            GuardError::Blocked { .. } => 1,
            GuardError::InvalidInvocation(_) => 2,
            GuardError::MissingCap
            | GuardError::MissingCapabilities(_)
            | GuardError::GitOriginalMissing
            | GuardError::GitOriginalBadPerms
            | GuardError::GuardUnavailable(_) => 3,
            GuardError::ContractFailed(_) => 4,
        }
    }
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::MissingCap => write!(
                f,
                "FATAL: missing workload capabilities (needs \
                 cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid); \
                 run make install-guard-host-exec"
            ),
            GuardError::MissingCapabilities(msg) => write!(f, "{msg}"),
            GuardError::GitOriginalMissing => write!(
                f,
                "FATAL: /usr/bin/git.original is missing or not a regular file; \
                 run make install-guard-host-exec"
            ),
            GuardError::GitOriginalBadPerms => write!(
                f,
                "FATAL: /usr/bin/git.original has unsafe ownership or mode \
                 (need root:root 0700); run make install-guard-host-exec"
            ),
            GuardError::InvalidInvocation(msg) => write!(f, "FATAL: {msg}"),
            GuardError::Blocked { .. } => write!(f, "BLOCKED"),
            GuardError::ContractFailed(msg) => write!(f, "{msg}"),
            GuardError::GuardUnavailable(msg) => write!(f, "FATAL: {msg}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::GuardError;

    #[test]
    fn policy_block_is_exit_1() {
        let e = GuardError::Blocked {
            reason: String::new(),
            hint: String::new(),
        };
        assert_eq!(e.exit_code(), 1);
    }

    #[test]
    fn malformed_invocation_is_exit_2() {
        assert_eq!(GuardError::InvalidInvocation(String::new()).exit_code(), 2);
    }

    #[test]
    fn guard_unavailable_carriers_are_exit_3() {
        let cases = [
            GuardError::MissingCap,
            GuardError::MissingCapabilities(String::new()),
            GuardError::GitOriginalMissing,
            GuardError::GitOriginalBadPerms,
            GuardError::GuardUnavailable(String::new()),
        ];
        for e in cases {
            assert_eq!(e.exit_code(), 3, "{e:?}");
        }
    }

    #[test]
    fn contract_failure_is_exit_4() {
        assert_eq!(GuardError::ContractFailed(String::new()).exit_code(), 4);
    }
}
