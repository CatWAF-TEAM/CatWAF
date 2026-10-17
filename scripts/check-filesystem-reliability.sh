#!/usr/bin/env bash
set -euo pipefail
# This wrapper never mounts over a user's data. Mount propagation is private
# and the child runs as the invoking non-root account (or CATWAF_TEST_USER).
if test "$(id -u)" -ne 0; then echo 'Run with sudo; only the isolated mount setup needs root.' >&2; exit 1; fi
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
test_user=${CATWAF_TEST_USER:-${SUDO_USER:-}}
test -n "$test_user" && test "$(id -u "$test_user")" -ne 0
fault_dir=$(mktemp -d /tmp/catwaf-fs-fault-XXXXXXXX)
trap 'rmdir -- "$fault_dir"' EXIT
export CATWAF_FAULT_ROOT="$fault_dir" CATWAF_FAULT_REPO="$repo" CATWAF_FAULT_USER="$test_user"
unshare --mount --propagation private bash -euo pipefail <<'CHILD'
mount -t tmpfs -o size=32m,nosuid,nodev,noexec,mode=0700 tmpfs "$CATWAF_FAULT_ROOT"
trap 'umount -- "$CATWAF_FAULT_ROOT"' EXIT
chown "$CATWAF_FAULT_USER" "$CATWAF_FAULT_ROOT"
cd "$CATWAF_FAULT_REPO"
runuser -u "$CATWAF_FAULT_USER" -- node scripts/check-filesystem-reliability.js
CHILD
