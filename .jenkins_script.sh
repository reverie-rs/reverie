#!/usr/bin/env bash

set -xe

echo "Running on machine: "`hostname -a || echo env says $HOSTNAME`
uname -a

echo "Git commit:"
(git log | head) || echo ok
echo "Git commit depth: "
(git log --pretty=oneline | wc -l) || echo ok

top=`pwd`

# This testing mode assumes that nix/docker integration is OFF by default:
export STACKARGS="--no-system-ghc"

if [ "$DOCKER" == "1" ]; then
elif [ "$USE_NIX" == "1" ]; then
else
    make && make tests
fi
