#!/bin/bash

set -e

TARFILE=$(mktemp --suffix=".tar")
TARGZ=${TARFILE}.gz
SRCDIR=/usr/share/man/man2
DESTDIR=$(mktemp -d)

trap cleanup EXIT

function cleanup {
	echo "cleanup.."
	rm -fr "${DESTDIR}"
	rm -fr "${TARFILE}"
	rm -fr "${TARGZ}"
}

echo "creating tarball ${TARFILE}.." && tar cf "${TARFILE}" "${SRCDIR}"
gzip "${TARFILE}"
echo "checking ${TARGZ}"
tar tf "${TARGZ}"
echo "extracting ${TARGZ} into ${DESTDIR}.."
zcat "${TARGZ}" | tar -C "${DESTDIR}" -xf -
echo "success"
