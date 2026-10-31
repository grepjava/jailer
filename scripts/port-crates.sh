#!/bin/sh
# Regenerate the port's crate list from Cargo.lock. Then, on a host with a
# ports tree, run `make makesum` in ports/sysutils/jailer to update distinfo.
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
END {
	for (i = 1; i <= n; i++)
		printf "%s%s%s\n", (i == 1 ? "CARGO_CRATES=\t" : "\t\t"),
		    crates[i], (i < n ? " \\" : "")
}' Cargo.lock >"$out"
echo "wrote $out ($(wc -l <"$out" | tr -d ' ') crates)"
