#!/bin/sh
# Regenerate the port's crate list from Cargo.lock, crates from git (Legion's)
# as the ports framework names them: NAME,NAME...@git+URL#COMMIT, one entry
# for each repository. Then, on a host with a ports tree, run `make makesum`
# in ports/sysutils/jailer to update distinfo (it fetches the git sources).
#
#   scripts/port-crates.sh
set -eu

cd "$(dirname "$0")/.."
out=ports/sysutils/jailer/Makefile.crates
awk '
/^\[\[package\]\]/      { name = ""; version = "" }
/^name = /              { name = $3; gsub(/"/, "", name) }
/^version = /           { version = $3; gsub(/"/, "", version) }
/^source = "registry\+/ { crates[++n] = name "-" version }
/^source = "git\+/ {
	src = $3; gsub(/"/, "", src); sub(/#/, "\\#", src)
	if (!(src in git)) order[++m] = src
	git[src] = (src in git) ? git[src] "," name : name
}
END {
	for (j = 1; j <= m; j++)
		crates[++n] = git[order[j]] "@" order[j]
	for (i = 1; i <= n; i++)
		printf "%s%s%s\n", (i == 1 ? "CARGO_CRATES=\t" : "\t\t"),
		    crates[i], (i < n ? " \\" : "")
}' Cargo.lock >"$out"
echo "wrote $out ($(wc -l <"$out" | tr -d ' ') crates)"
