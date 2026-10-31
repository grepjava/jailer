#!/bin/sh
# Copy the source tree to a FreeBSD host and build/test it there.
#
#   scripts/freebsd-build.sh user@freebsd-host [cargo args...]
#   scripts/freebsd-build.sh user@freebsd-host test
set -eu

host=${1:?usage: $0 user@host [cargo args...]}
shift
[ $# -eq 0 ] && set -- build --release

cd "$(dirname "$0")/.."
remote='export PATH=$HOME/.cargo/bin:$PATH
command -v rustup >/dev/null && ! rustup default >/dev/null 2>&1 &&
    export RUSTUP_TOOLCHAIN=$(rustup toolchain list | head -1 | cut -d" " -f1)
mkdir -p jailer && tar xzf - -C jailer && cd jailer && cargo'
tar czf - --exclude=./target --exclude=./.git . | ssh "$host" "$remote $*"

