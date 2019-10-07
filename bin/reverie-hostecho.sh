#!/bin/bash

TOPDIR=`realpath $(dirname $0)/..`

REVERIE=${TOPDIR}/bin/reverie-hostecho

unshare --mount-proc -Umpf ${REVERIE} --debug=${DEBUG} -- $*
