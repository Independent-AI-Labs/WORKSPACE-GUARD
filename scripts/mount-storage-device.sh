#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 <device> <mount-point> [mount-options]" >&2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
    exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: mount-storage-device.sh needs root" >&2
    exit 2
fi

target="$2"
options="${3:-rw,nosuid,nodev,noexec}"

if [[ "$target" != /* ]]; then
    echo "ERROR: mount point must be absolute: $target" >&2
    exit 2
fi
device="$(readlink -f -- "$1")"
if [[ ! -b "$device" ]]; then
    echo "ERROR: not a block device: $1" >&2
    exit 2
fi

umask 022
mkdir -p -- "$target"
target="$(readlink -f -- "$target")"
if [[ "$target" == / ]]; then
    echo "ERROR: refusing to mount over /" >&2
    exit 2
fi

if current_target="$(findmnt --noheadings --output TARGET --source "$device")"; then
    if [[ "$current_target" == "$target" ]]; then
        echo "$device already mounted at $target"
        exit 0
    fi
    echo "ERROR: $device already mounted at $current_target" >&2
    exit 1
fi
if current_source="$(findmnt --noheadings --output SOURCE --mountpoint "$target")"; then
    echo "ERROR: $target already contains $current_source" >&2
    exit 1
fi

mount --options "$options" -- "$device" "$target"
echo "Mounted $device at $target"
