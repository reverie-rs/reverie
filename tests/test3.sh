#!/bin/bash

TARFILE=`mktemp --suffix=".tar"`
TARGZ=${TARFILE}.gz
DESTDIR=`mktemp -d`

trap cleanup EXIT

function cleanup {
	echo "cleanup.."
	rm -fr ${DESTDIR}
	rm -fr ${TARFILE}
	rm -fr ${TARGZ}
}

echo "creating tarball ${TARFILE}.." && tar cf ${TARFILE} .
gzip ${TARFILE}
echo "checking ${TARGZ}"
tar tf ${TARGZ}
echo "extracting ${TARGZ} into ${DESTDIR}.."
zcat ${TARGZ} | tar -C ${DESTDIR} -xf -
echo "success"
