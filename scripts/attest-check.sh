#!/bin/sh
# jailer's signatures and attestations against real cosign, and its SBOM
# against an SPDX validator, in Docker. Each result is printed for reading.
#
#   scripts/attest-check.sh path/to/jailer EMPTY-DIR
export MSYS_NO_PATHCONV=1
J=$(realpath "${1:?usage: $0 JAILER DIR}")
dir=${2:?usage: $0 JAILER DIR}
mkdir -p "$dir/ctx"; cd "$dir" || exit 1
W=$(pwd -W 2>/dev/null || pwd)
docker rm -f jreg >/dev/null 2>&1
docker run -d --name jreg -p 127.0.0.1:5055:5000 registry:2 >/dev/null || exit 1
sleep 2
R=127.0.0.1:5055
j() { "$J" --no-zfs --plain-http "$R" --state-dir "$W/state" "$@"; }
printf 'hello\n' > ctx/f
printf 'FROM scratch\nCOPY f /f\n' > ctx/Containerfile
j key generate "$W/k" | tail -1 | cut -c1-70
j build -t app:1 --record "$W/r.json" "$W/ctx" | tail -1 | cut -c1-70
j push --record "$W/r.json" --sign-key "$W/k.key" app:1 $R/app:1 > push.out; cut -c1-90 push.out
P=$(python -c "import json;print(json.load(open('r.json'))['published'][0]['pinned'])")
echo "pinned: $P"
j attest --key "$W/k.key" --type provenance --record "$W/r.json" "$P" | cut -c1-110
j attest --key "$W/k.key" --type sbom --image app:1 --record "$W/r.json" "$P" 2>&1 | cut -c1-110
j sbom -o "$W/sbom.json" app:1 2>&1 | cut -c1-100
C="docker run --rm --add-host=reg:host-gateway -v $W:/w -e COSIGN_PASSWORD= ghcr.io/sigstore/cosign/cosign:latest"
Q=$(echo "$P" | sed "s/127.0.0.1:5055/host.docker.internal:5055/")
echo "--- cosign verify (signature)"
$C verify --key /w/k.pub --insecure-ignore-tlog --allow-http-registry "$Q" 2>&1 | tail -3 | cut -c1-200
for t in slsaprovenance1 spdxjson; do
	echo "--- cosign verify-attestation $t"
	$C verify-attestation --key /w/k.pub --type $t --insecure-ignore-tlog --allow-http-registry "$Q" > out.$t 2> err.$t
	echo "exit $?"; tail -2 err.$t | cut -c1-200
	python - out.$t <<'E'
import sys,json,base64
for l in open(sys.argv[1]):
    l=l.strip()
    if not l.startswith('{'): continue
    s=json.loads(base64.b64decode(json.loads(l)['payload']))
    print('  statement',s['_type'],s['predicateType'],s['subject'][0]['digest']['sha256'][:12])
E
done
echo "--- wrong key"
j key generate "$W/other" >/dev/null
$C verify-attestation --key /w/other.pub --type slsaprovenance1 --insecure-ignore-tlog --allow-http-registry "$Q" 2>&1 | tail -1 | cut -c1-140
echo "--- spdx validator"
docker run --rm -v "$W:/w" python:3.12-slim sh -c 'pip install -q spdx-tools 2>/dev/null && pyspdxtools -i /w/sbom.json && echo SPDX-VALID' 2>&1 | tail -6 | cut -c1-200
docker rm -f jreg >/dev/null 2>&1
