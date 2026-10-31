#!/bin/sh
# Build release tarballs of a tagged version on FreeBSD hosts, one per
# architecture, and attach them to the tag's GitHub release.
#
#   scripts/release.sh [-n] v0.1.0 user@amd64-host user@arm64-host
#
# Each tarball holds bin/jailer, man/man1/jailer.1, LICENSE and README.md,
# built from the tag with the locked dependencies, and is left in
# dist/<tag>/ with a SHA256SUMS file. -n stops there, without uploading.
# Needs `gh` here and cargo on the hosts.
set -eu

usage="usage: $0 [-n] TAG user@host..."
upload=yes
if [ "${1:-}" = -n ]; then
	upload=
	shift
fi
tag=${1:?$usage}
shift
[ $# -gt 0 ] || { echo "$usage" >&2; exit 2; }
cd "$(dirname "$0")/.."
git rev-parse -q --verify "refs/tags/$tag" >/dev/null ||
	{ echo "$0: no tag $tag" >&2; exit 1; }
version=${tag#v}

out=dist/$tag
rm -rf "$out"
mkdir -p "$out"
for host in "$@"; do
	platform=$(ssh "$host" 'echo freebsd$(uname -r | cut -d. -f1)-$(uname -p)')
	dir=jailer-$version-$platform
	echo "building $dir on $host" >&2
	git archive --prefix="$dir/" "$tag" | ssh "$host" "set -e
		export PATH=\$HOME/.cargo/bin:\$PATH
		command -v rustup >/dev/null && ! rustup default >/dev/null 2>&1 &&
		    export RUSTUP_TOOLCHAIN=\$(rustup toolchain list | head -1 | cut -d' ' -f1)
		w=\$(mktemp -d)
		trap 'rm -rf \$w' EXIT
		cd \$w && tar xf -
		(cd $dir && cargo build --release --locked) >&2
		mkdir -p pkg/$dir/bin pkg/$dir/man/man1
		cp $dir/target/release/jailer pkg/$dir/bin/
		strip pkg/$dir/bin/jailer
		cp $dir/man/jailer.1 pkg/$dir/man/man1/
		cp $dir/LICENSE $dir/README.md pkg/$dir/
		tar czf - -C pkg $dir" >"$out/$dir.tar.gz"
done

(
	cd "$out"
	if command -v sha256sum >/dev/null; then
		sha256sum -- *.tar.gz
	else
		sha256 -r -- *.tar.gz | sed 's/ / */'
	fi >SHA256SUMS
	cat SHA256SUMS
)
[ -n "$upload" ] || exit 0
gh release view "$tag" >/dev/null 2>&1 ||
	gh release create "$tag" --verify-tag --title "jailer $version" --generate-notes
gh release upload "$tag" --clobber "$out"/*.tar.gz "$out/SHA256SUMS"
