#!/bin/bash

TOPDIR=`realpath $(dirname $0)/..`

REVERIE=${TOPDIR}/target/debug/reverie
PRELOADER=${TOPDIR}/target/debug/libreverie_preloader.so
ECHO=${TOPDIR}/target/debug/libecho.so

unshare --mount-proc -Umpf ${REVERIE} --preloader=${PRELOADER} --tool=${ECHO} -- $*
