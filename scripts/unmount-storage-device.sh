#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <mount-point>" >&2
    exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: unmount-storage-device.sh needs root" >&2
    exit 2
fi
if [[ "$1" != /* ]]; then
    echo "ERROR: mount point must be absolute: $1" >&2
    exit 2
fi

target="$(readlink -f -- "$1")"
if [[ "$target" == / ]]; then
    echo "ERROR: refusing to unmount /" >&2
    exit 2
fi
if ! source="$(findmnt --noheadings --output SOURCE --mountpoint "$target")"; then
    echo "ERROR: not a mount point: $target" >&2
    exit 1
fi

umount -- "$target"
echo "Unmounted $source from $target"
