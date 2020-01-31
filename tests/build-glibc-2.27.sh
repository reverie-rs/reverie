#!/bin/bash

set -e

GLIBC_VER=2.27
GLIBC_SOURCE_WORK_DIR=$(mktemp -d)
GLIBC_BUILD_DIR=""

trap cleanup EXIT

function cleanup {
	echo "cleanup.." && rm -fr "${GLIBC_SOURCE_WORK_DIR}"
}

function prepare {
	mkdir -p "${GLIBC_SOURCE_WORK_DIR}" && cd "${GLIBC_SOURCE_WORK_DIR}"
	curl "https://ftp.gnu.org/gnu/glibc/glibc-${GLIBC_VER}.tar.xz" | tar -Jxf -
	mkdir -p "glibc-${GLIBC_VER}-build" && cd "glibc-${GLIBC_VER}-build"
	GLIBC_BUILD_DIR=$(pwd)
}

function build {
	if [ "${GLIBC_BUILD_DIR}" != "" ]; then
		cd "${GLIBC_BUILD_DIR}"
		../glibc-${GLIBC_VER}/configure --prefix=""
		${SYSTRACE} make -j5
	fi
}

prepare && build
