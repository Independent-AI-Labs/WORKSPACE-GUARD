// Hand-written policy types and lookup for the generic binary guard.
//
// The DO_NOT_EDIT file emitted by build.rs (OUT_DIR/binary_policies.rs)
// contains ONLY a single const literal:
//
//     pub const BINARY_POLICIES: &[BinaryPolicy] = &[ ... ];
//
// Every struct, enum, and function below is hand-written under full IDE
// support. build.rs is forbidden from emitting logic (fn bodies) or type
// definitions as generated strings; that was the maintainability failure
// this split is designed to prevent.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyKind {
    DenyNonRoot,
    DenyAllNonRoot,
    ArgValidate,
    #[allow(dead_code)]
    PassThrough,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectKind {
    #[allow(dead_code)]
    Flag,
    #[allow(dead_code)]
    Regex,
}

/// A single reject rule. `flag` rejects any argv containing the literal
/// token (e.g. `-R`). `regex` rejects when the joined argv matches the
/// pattern, optionally gated on subcommand and required-flags.
#[derive(Debug, Clone)]
pub struct RejectRule {
    pub kind: RejectKind,
    pub flag: Option<&'static str>,
    pub pattern: Option<&'static str>,
    pub subcommand: Option<&'static str>,
    pub requires_flags: &'static [&'static str],
    pub reason: &'static str,
}

/// One policy entry for one binary, keyed by `name`. The same entry serves
/// the binary and any symlinks listed in `allow_subcommands`: e.g. a sudo
/// entry with `allow_subcommands: [sudo, sudoedit]` is matched when
/// `basename(argv[0])` is either `sudo` or `sudoedit`.
#[derive(Debug, Clone)]
pub struct BinaryPolicy {
    pub name: &'static str,
    pub policy: PolicyKind,
    pub allow_subcommands: &'static [&'static str],
    #[allow(dead_code)]
    pub allow_self_username: bool,
    pub reject_patterns: &'static [RejectRule],
    pub env_sanitise: &'static [&'static str],
}

/// First-match-wins lookup. Walks the compiled-in table in order; returns
/// the entry whose `name` equals `invoked_name` exactly OR whose
/// `allow_subcommands` contains `invoked_name`. The symlink-alias rule
/// means `sudoedit` resolves to the `sudo` entry without a duplicate row.
pub fn find_policy(invoked_name: &str) -> Option<&'static BinaryPolicy> {
    BINARY_POLICIES
        .iter()
        .find(|p| p.name == invoked_name)
        .or_else(|| {
            BINARY_POLICIES
                .iter()
                .find(|p| p.allow_subcommands.contains(&invoked_name))
        })
}

// The generated table. build.rs writes this file into OUT_DIR; it contains
// only the const literal declared above (no fn, no struct, no enum).
include!(concat!(env!("OUT_DIR"), "/binary_policies.rs"));
