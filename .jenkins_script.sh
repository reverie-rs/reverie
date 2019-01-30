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
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

rustup update
make && make tests
