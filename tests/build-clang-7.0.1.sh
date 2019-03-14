#!/bin/bash

LLVM_VER=7.0.1
LLVM_SOURCE_WORK_DIR=`mktemp -d -p .`
LLVM_BUILD_DIR=llvm-${LLVM_VER}-build

trap cleanup EXIT

function cleanup {
	echo "cleanup.." && rm -fr ${LLVM_SOURCE_WORK_DIR}
}

function prepare {
	mkdir -p ${LLVM_SOURCE_WORK_DIR} && cd ${LLVM_SOURCE_WORK_DIR}
	curl http://releases.llvm.org/${LLVM_VER}/cfe-${LLVM_VER}.src.tar.xz | tar -Jxf -
	ln -s cfe-${LLVM_VER}.src clang
	curl http://releases.llvm.org/${LLVM_VER}/llvm-${LLVM_VER}.src.tar.xz | tar -Jxf -
	mkdir -p ${LLVM_BUILD_DIR}
}

function build {
	if [ "X"${LLVM_BUILD_DIR} != "X" ]; then
		cd ${LLVM_BUILD_DIR}
		cmake -DLLVM_ENABLE_PROJECTS=clang -G "Unix Makefiles" ../llvm-${LLVM_VER}.src
		# -j5 can easily consumes 16GB+ RAM, even -j2 failed..
		make -j1
	fi
}

prepare && build
