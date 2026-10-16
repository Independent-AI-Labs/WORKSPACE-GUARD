// sealed_paths.rs: the single definition of the sealed-binary tree.
//
// Every guard resolves its frozen real binary through this file. It is
// `include!`d by each guard crate, so the layout has exactly one source of
// truth. See docs/specifications and the sealed-binary migration audit.
//
// Layout:
//   /usr/lib/workspace-guard/sealed/<basename>       frozen real binary
//   /usr/lib/workspace-guard/sealed/pkg/<basename>   package-manager slot
//
// Directory 0700 root:root; frozen binaries 0700 root:root and immutable.

pub const SEALED_DIR: &str = "/usr/lib/workspace-guard/sealed";
pub const SEALED_PKG_DIR: &str = "/usr/lib/workspace-guard/sealed/pkg";

pub const SEALED_BASH: &str = "/usr/lib/workspace-guard/sealed/bash";
pub const SEALED_GIT: &str = "/usr/lib/workspace-guard/sealed/git";
pub const SEALED_GIT_NUL: &str = "/usr/lib/workspace-guard/sealed/git\0";

/// Frozen real binary for a guard invoked as `basename`.
pub fn sealed_path(basename: &str) -> String {
    format!("{SEALED_DIR}/{basename}")
}

/// Package-manager slot for `basename` (the dpkg-divert target).
pub fn sealed_pkg_path(basename: &str) -> String {
    format!("{SEALED_PKG_DIR}/{basename}")
}