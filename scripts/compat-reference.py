#!/usr/bin/env python3
"""Records what a reference builder makes of tests/compat/cases, for
tests/compat_test.rs to compare jailer with.

    scripts/compat-reference.py buildkit
    scripts/compat-reference.py buildah DIR
    scripts/compat-reference.py read IMAGE.tar > CASE.json

`buildkit` builds each case with `docker buildx`, writing
tests/compat/expected/buildkit/CASE.json, or CASE.error for one it refuses,
and the versions used to VERSIONS. A context goes as a tar with fixed modes,
so the host's file system does not show in the result. `buildah` does the same
from DIR, of what scripts/compat-buildah.sh left on a FreeBSD host: for each
case CASE.tar, or CASE.error, and VERSIONS. `read` prints the same form for any
OCI archive, such as `podman save --format oci-archive` makes.
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "compat")
KEYS = ["Cmd", "Entrypoint", "Env", "ExposedPorts", "Labels", "OnBuild", "Shell",
        "StopSignal", "User", "Volumes", "WorkingDir", "Healthcheck"]


def context(case):
    """The case's context and Containerfile as a tar, with fixed modes."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        def add(path, name):
            info = tarfile.TarInfo(name)
            with open(path, "rb") as f:
                body = f.read()
            info.size, info.mode = len(body), 0o644
            tar.addfile(info, io.BytesIO(body))
        ctx = os.path.join(case, "ctx")
        for dirpath, dirs, files in os.walk(ctx):
            rel = os.path.relpath(dirpath, ctx).replace("\\", "/")
            if rel != ".":
                info = tarfile.TarInfo(rel)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            for f in sorted(files):
                add(os.path.join(dirpath, f), f if rel == "." else f"{rel}/{f}")
        add(os.path.join(case, "Containerfile"), "Containerfile")
    return out.getvalue()


def read_archive(path):
    """The normal form of the one image in an OCI archive."""
    files = {}
    with tarfile.open(path) as oci:
        def blob(digest):
            return oci.extractfile("blobs/sha256/" + digest.split(":")[1]).read()
        desc = json.load(oci.extractfile("index.json"))["manifests"][0]
        manifest = json.loads(blob(desc["digest"]))
        if "manifests" in manifest:
            manifest = json.loads(blob(manifest["manifests"][0]["digest"]))
        image = json.loads(blob(manifest["config"]["digest"]))
        config = image.get("config") or {}
        author = image.get("author")
        for layer in manifest.get("layers") or []:
            data = blob(layer["digest"])
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                for m in tar:
                    name = m.name.lstrip("./").rstrip("/")
                    base = os.path.basename(name)
                    if not name:
                        continue
                    if base.startswith(".wh."):
                        files.pop(os.path.join(os.path.dirname(name), base[4:]), None)
                    elif m.isdir():
                        files[name] = f"dir {m.mode & 0o7777:o}"
                    elif m.issym():
                        files[name] = f"link {m.linkname}"
                    else:
                        body = tar.extractfile(m).read()
                        files[name] = f"file {m.mode & 0o7777:o} {hashlib.sha256(body).hexdigest()}"
    normal = {"config": {k: config[k] for k in KEYS if config.get(k)}, "files": files}
    if author:
        normal["author"] = author
    return normal


def write(path, value):
    with open(path, "w", newline="\n") as f:
        json.dump(value, f, indent=1, sort_keys=True)
        f.write("\n")


def buildkit():
    out_dir = os.path.join(ROOT, "expected", "buildkit")
    os.makedirs(out_dir, exist_ok=True)
    for name in sorted(os.listdir(os.path.join(ROOT, "cases"))):
        case = os.path.join(ROOT, "cases", name)
        args = ["docker", "buildx", "build", "--provenance=false", "--sbom=false",
                "--no-cache", "-f", "Containerfile"]
        target = os.path.join(case, "target")
        if os.path.exists(target):
            args += ["--target", open(target).read().strip()]
        for old in (name + ".json", name + ".error"):
            if os.path.exists(os.path.join(out_dir, old)):
                os.remove(os.path.join(out_dir, old))
        # An ignore file applies only to a context given as a directory,
        # whose modes are this host's: there, files are taken as 644.
        ignored = os.path.exists(os.path.join(case, "ctx", ".dockerignore"))
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "image.tar")
            output = ["--output", f"type=oci,dest={dest}"]
            if ignored:
                args[args.index("Containerfile")] = os.path.join(case, "Containerfile")
                run = subprocess.run(args + output + [os.path.join(case, "ctx")],
                                     capture_output=True)
            else:
                run = subprocess.run(args + output + ["-"], input=context(case),
                                     capture_output=True)
            if run.returncode == 0:
                image = read_archive(dest)
                if ignored:
                    image["files"] = {k: v.replace("file 755 ", "file 644 ")
                                      for k, v in image["files"].items()}
                write(os.path.join(out_dir, name + ".json"), image)
                print(name, "built")
            else:
                last = [l for l in run.stderr.decode(errors="replace").splitlines() if "ERROR" in l]
                with open(os.path.join(out_dir, name + ".error"), "w", newline="\n") as f:
                    f.write("refused\n")
                print(name, "refused:", last[-1] if last else "")
    versions = subprocess.run(["docker", "buildx", "version"], capture_output=True, text=True).stdout
    server = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                            capture_output=True, text=True).stdout
    with open(os.path.join(out_dir, "VERSIONS"), "w", newline="\n") as f:
        f.write(f"docker {server.strip()}\n{versions.strip()}\n")


def buildah(source):
    out_dir = os.path.join(ROOT, "expected", "buildah")
    os.makedirs(out_dir, exist_ok=True)
    for old in os.listdir(out_dir):
        os.remove(os.path.join(out_dir, old))
    for name in sorted(os.listdir(os.path.join(ROOT, "cases"))):
        tar = os.path.join(source, name + ".tar")
        if os.path.exists(tar):
            write(os.path.join(out_dir, name + ".json"), read_archive(tar))
        else:
            with open(os.path.join(out_dir, name + ".error"), "w", newline="\n") as f:
                f.write("refused\n")
    with open(os.path.join(source, "VERSIONS")) as f, \
            open(os.path.join(out_dir, "VERSIONS"), "w", newline="\n") as v:
        v.write(f.read())


if __name__ == "__main__":
    if sys.argv[1:] == ["buildkit"]:
        buildkit()
    elif len(sys.argv) == 3 and sys.argv[1] == "buildah":
        buildah(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "read":
        json.dump(read_archive(sys.argv[2]), sys.stdout, indent=1, sort_keys=True)
        print()
    else:
        sys.exit(__doc__)
