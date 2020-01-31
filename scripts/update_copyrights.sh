#!/usr/bin/env bash
set -euo pipefail

# An idempotent script that serves as the source-of-truth for
# the copyright state of Rust files in this project.

# This should be run with `./scripts/update_copyrights.sh` from the
# top of reverie directory.

# This script is not very robust and assumes there are no spaces in
# the filenames.

# ------------------------------------------------------------------------------
# The copyright text:

ORIG_HDR=$(mktemp -t origXXXX)
MODIFIED_HDR=$(mktemp -t modifiedXXXX)
NEW_HDR=$(mktemp -t newXXXX)

cat > $ORIG_HDR <<EOF
/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * 
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

EOF

cat > $MODIFIED_HDR <<EOF
/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * Copyright (c) 2020-, Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

EOF

cat > $NEW_HDR <<EOF
/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * 
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

EOF

# ------------------------------------------------------------------------------

# Files touched before Facebook use of this library:
ORIG_FILES=$(cat <<EOF
./reverie-preloader/build.rs
./reverie-preloader/src/lib.rs
./reverie-preloader/src/relink.rs
./rfcs/shared_api_v1/src/main.rs
./reverie-api/src/event.rs
./reverie-api/src/task.rs
./reverie-api/src/mod.rs
./reverie-seccomp/src/lib.rs
./reverie-seccomp/src/seccomp_bpf.rs
./reverie-common/src/consts.rs
./reverie-common/src/profiling.rs
./reverie-common/src/state.rs
./reverie-common/src/local_state.rs
./examples/echo/src/dpc.rs
./examples/echo/src/show/types.rs
./examples/echo/src/show/mod.rs
./examples/echo/src/show/fcntl.rs
./examples/echo/src/show/ioctl.rs
./examples/echo/src/show/args.rs
./examples/echo/src/entry.rs
./examples/echo/src/macros.rs
./examples/hostecho/src/consts.rs
./examples/hostecho/src/show/types.rs
./examples/hostecho/src/show/mod.rs
./examples/hostecho/src/show/fcntl.rs
./examples/hostecho/src/show/ioctl.rs
./examples/hostecho/src/show/args.rs
./examples/hostecho/src/state.rs
./examples/hostecho/src/entry.rs
./examples/hostecho/src/macros.rs
./examples/none/src/lib.rs
./reverie/src/ns.rs
./reverie/src/strace.rs
./reverie/src/block_events.rs
./reverie/src/sched_wait.rs
./reverie/src/util.rs
./reverie/src/traced_task.rs
./reverie/src/config.rs
./reverie/src/lib.rs
./reverie/src/auxv.rs
./reverie/src/hooks.rs
./reverie/src/aux.rs
./reverie/src/rpc_ptrace.rs
./reverie/src/remote_rwlock.rs
./reverie/src/main.rs
./reverie/src/sched.rs
./reverie/src/patcher.rs
./reverie/src/debug.rs
./reverie/src/macros.rs
./reverie/src/stubs.rs
./reverie-helper/build.rs
./reverie-helper/src/counter.rs
./reverie-helper/src/ffi.rs
./reverie-helper/src/spinlock.rs
EOF
)

# Modified at Facebook
MODIFIED_FILES=$(cat <<EOF
./examples/counter/src/lib.rs
./examples/det/src/lib.rs
./examples/echo/src/lib.rs
./examples/hostecho/src/lib.rs
./reverie-api/src/remote.rs
./reverie-common/src/lib.rs
./reverie-helper/src/lib.rs
./reverie-helper/src/logger.rs
./reverie-seccomp/build.rs
./reverie/src/vdso.rs
EOF
)
# Also:
# reverie-api/Cargo.toml
# reverie-common/Cargo.toml
# reverie-helper/Cargo.toml
# reverie-preloader/Cargo.toml
# reverie-seccomp/Cargo.toml
# reverie/Cargo.toml

# Created at Facebook:
NEW_FILES=$(cat <<EOF
EOF
)

# These come from elsewhere and have a custom copyright:
OTHER_FILES=$(cat <<EOF
./reverie-helper/src/memrchr.rs
EOF
)

# ALL_FILES="${ORIG_FILES} ${MODIFIED_FILES} ${NEW_FILES} ${OTHER_FILES}"
ALL_FILES=$(cat ${ORIG_FILES} ${MODIFIED_FILES} ${NEW_FILES} ${OTHER_FILES})

# ------------------------------------------------------------------------------

# TODO: check that ALL Rust files are addressed by the above lists.
# Using a Hash will require Bash 4:
# declare -A files_hash
# for f in $ALL_FILES; do
#     files_hash[$f]=1
# done
# echo done populating

# TODO: replace license files even if already present.
# This script is idempotent but only because it skips anything with a copyright.

function update_hdr() {
    local file=$1
    local hdr=$2
    if head -n 20 $file | grep -q Copyright ; then
	echo "Skipping, copyright already present: $file"
    else
	local newfile=$(mktemp)
	echo "Adding header to orig file: $file"
	cat $hdr $file > $newfile
	mv $newfile $file
    fi
}

for f in $ORIG_FILES; do
    update_hdr $f $ORIG_HDR
done

for f in $MODIFIED_FILES; do
    update_hdr $f $MODIFIED_HDR
done

for f in $NEW_FILES; do
    update_hdr $f $NEW_HDR
done
