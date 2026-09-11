#!/usr/bin/env bash

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

@test "storage scripts are valid bash and reject incomplete arguments" {
    run bash -n "$GUARD_ROOT/scripts/mount-storage-device.sh"
    assert_success
    run bash -n "$GUARD_ROOT/scripts/unmount-storage-device.sh"
    assert_success

    run bash "$GUARD_ROOT/scripts/mount-storage-device.sh"
    [ "$status" -eq 2 ]
    assert_output --partial "Usage:"
    run bash "$GUARD_ROOT/scripts/unmount-storage-device.sh"
    [ "$status" -eq 2 ]
    assert_output --partial "Usage:"
}

@test "mount script rejects non-block devices and relative targets" {
    run bash "$GUARD_ROOT/scripts/mount-storage-device.sh" "$TEST_TMPDIR/file" /mnt/test
    [ "$status" -eq 2 ]
    assert_output --partial "not a block device"

    run bash "$GUARD_ROOT/scripts/mount-storage-device.sh" /dev/null relative
    [ "$status" -eq 2 ]
    assert_output --partial "mount point must be absolute"
}

@test "WS-BACKUP Makefile wrappers use UUID and agent ownership" {
    run make -n mount-ws-backup
    assert_success
    assert_output --partial "/dev/disk/by-uuid/3466BD2C66BCF02A"
    assert_output --partial "scripts/mount-storage-device.sh"
    assert_output --partial "uid=\$uid,gid=\$gid,umask=0077"

    run make -n unmount-ws-backup
    assert_success
    assert_output --partial "scripts/unmount-storage-device.sh"
    assert_output --partial "/mnt/ws-backup"
}
