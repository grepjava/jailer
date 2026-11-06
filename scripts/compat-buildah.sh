#!/bin/sh
# Builds tests/compat/cases with podman, which is Buildah underneath, on a
# FreeBSD host, for scripts/compat-reference.py buildah. Needs root for podman.
#
#   scripts/compat-buildah.sh DIR
set -eu

out=${1:?usage: $0 DIR}
cd "$(dirname "$0")/../tests/compat/cases"
mkdir -p "$out"
for case in *; do
	args=
	[ ! -f "$case/target" ] || args="--target $(cat "$case/target")"
	# shellcheck disable=SC2086
	if podman build -q --no-cache --format docker $args -t "compat/$case" \
	    -f "$case/Containerfile" "$case/ctx" >"$out/$case.log" 2>&1; then
		podman save -q --format oci-archive -o "$out/$case.tar" "compat/$case"
		podman rmi -f "compat/$case" >/dev/null
	else
		touch "$out/$case.error"
	fi
done
podman --version >"$out/VERSIONS"
freebsd-version -k >>"$out/VERSIONS"
