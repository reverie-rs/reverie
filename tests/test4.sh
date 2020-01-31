#!/bin/bash

set -e

MUSL_VER=1.1.21
MUSL_SOURCE_WORK_DIR=$(mktemp -d)

trap cleanup EXIT

function cleanup {
	echo "cleanup.." && rm -fr "${MUSL_SOURCE_WORK_DIR}"
}

function prepare {
	mkdir -p "${MUSL_SOURCE_WORK_DIR}" && cd "${MUSL_SOURCE_WORK_DIR}"
	curl "http://git.musl-libc.org/cgit/musl/snapshot/musl-${MUSL_VER}.tar.gz" | tar -zxf -
}

prepare
