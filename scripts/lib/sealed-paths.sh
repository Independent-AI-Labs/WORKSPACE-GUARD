# scripts/lib/sealed-paths.sh
#
# Single definition of the sealed-binary tree shared by the host guards.
# The Rust guards resolve the same paths (sealed_paths.rs); keep the two in
# lockstep. Sourced by the root installers/checkers.
#
#   /usr/lib/workspace-guard/sealed/<basename>      sealed real binary
#   /usr/lib/workspace-guard/sealed/pkg/<basename>   diverted package copy
#
# WORKSPACE_GUARD_SEALED_DIR overrides the tree root (test fixtures).

SEALED_DIR="${WORKSPACE_GUARD_SEALED_DIR:-/usr/lib/workspace-guard/sealed}"
SEALED_PKG_DIR="$SEALED_DIR/pkg"

sealed_bin_name() { printf '%s' "${1##*/}"; }
sealed_path()     { printf '%s/%s' "$SEALED_DIR" "$(sealed_bin_name "$1")"; }
sealed_pkg_path() { printf '%s/%s' "$SEALED_PKG_DIR" "$(sealed_bin_name "$1")"; }
export SEALED_DIR SEALED_PKG_DIR