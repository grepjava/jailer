use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::Arc;

use jailer::Reference;
use jailer::build::{BuildBackend, BuildOptions, build};
use jailer::init::{InitOptions, Template, scaffold};
use jailer::registry::{Client, Credentials, sha256};
use jailer::runtime::{Config, JailRuntime};
use jailer::sys::FakeSys;

mod common;
use common::start_mock_registry;

#[tokio::test]
async fn end_to_end_init_build_export_push_and_pull() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("demo");
    std::fs::create_dir_all(&project_dir).unwrap();

    // 1. Test `jailer init`
    let init_res = scaffold(&InitOptions {
        dir: project_dir.clone(),
        template: Some(Template::Runtime),
        release: Some("15.1".to_owned()),
        name: Some("demo".to_owned()),
        force: false,
    })
    .unwrap();
    assert!(init_res.containerfile.exists());

    // Create a minimal self-contained Containerfile using FROM scratch with /etc/passwd and binary
    std::fs::create_dir_all(project_dir.join("etc")).unwrap();
    std::fs::create_dir_all(project_dir.join("bin")).unwrap();
    std::fs::write(
        project_dir.join("etc/passwd"),
        "root:*:0:0:root:/root:/bin/sh\nnobody:*:65534:65534:Unprivileged:/nonexistent:/usr/sbin/nologin\n",
    )
    .unwrap();
    std::fs::write(
        project_dir.join("etc/group"),
        "wheel:*:0:root\nnobody:*:65534:\n",
    )
    .unwrap();
    let bin_path = project_dir.join("bin/demo");
    std::fs::write(&bin_path, "#!/bin/sh\necho hello\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    std::fs::write(
        project_dir.join("Containerfile"),
        r#"
FROM scratch
COPY etc/passwd /etc/passwd
COPY etc/group /etc/group
COPY --chown=nobody:nobody --chmod=0755 bin/demo /usr/local/bin/demo
ENV APP_ENV=production
WORKDIR /
USER nobody
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/demo"]
CMD ["--serve"]
"#,
    )
    .unwrap();

    let (addr, _) = start_mock_registry().await;
    let registry_host = format!("127.0.0.1:{}", addr.port());

    let sys = Arc::new(FakeSys::new());
    let client = Client::new().unwrap().plain_http(&registry_host);
    let store_dir = tmp.path().join("store1");
    let store = Arc::new(jailer::store::open(sys.clone(), None, &store_dir, client).unwrap());
    let runtime = JailRuntime::new(
        sys,
        store.clone(),
        Config {
            state_dir: tmp.path().join("containers1"),
            dataset: None,
            shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
            prune_images: false,
        },
    )
    .unwrap();

    // 2. Test `jailer build`
    let built = build(
        &store,
        &runtime,
        &BuildOptions {
            context_dir: project_dir.clone(),
            containerfile: None,
            tag: "demo:1.0".to_owned(),
            build_args: BTreeMap::new(),
            target: None,
            backend: BuildBackend::Native,
            creds: Default::default(),
            strict_lint: true,
            no_cache: false,
            squash: false,
            cache_max: None,
            secrets: BTreeMap::new(),
            ssh: BTreeMap::new(),
            jail_params: Vec::new(),
            labels: BTreeMap::new(),
            timestamp: None,
            limits: Default::default(),
            compression: Default::default(),
            cpuset: None,
            annotations: BTreeMap::new(),
            cache_from: Vec::new(),
            cache_to: None,
        },
    )
    .await
    .unwrap();
    assert!(!built.report.has_errors(), "{:?}", built.report.findings);
    assert_eq!(built.image.references, ["localhost/demo:1.0"]);
    assert_eq!(built.image.config.config.user, "nobody");
    assert_eq!(
        built.image.config.config.entrypoint,
        ["/usr/local/bin/demo"]
    );
    assert_eq!(built.image.config.config.cmd, ["--serve"]);

    // 3. Test `jailer export` -> `app.tar` and `Store::load` into a second store
    let archive_path = tmp.path().join("demo.tar");
    store
        .export("demo:1.0", &archive_path, Some("localhost/demo:1.0"))
        .await
        .unwrap();
    assert!(archive_path.exists());
    // Docker's manifest names files the archive holds.
    let mut names = Vec::new();
    let mut docker_manifest = serde_json::Value::Null;
    for entry in tar::Archive::new(std::fs::File::open(&archive_path).unwrap())
        .entries()
        .unwrap()
    {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_string_lossy().into_owned();
        let name = name.trim_start_matches("./").to_owned();
        if name == "manifest.json" {
            docker_manifest = serde_json::from_reader(&mut entry).unwrap();
        }
        names.push(name);
    }
    let m = &docker_manifest[0];
    assert_eq!(m["RepoTags"], serde_json::json!(["localhost/demo:1.0"]));
    let layers = m["Layers"].as_array().unwrap();
    assert_eq!(layers.len(), built.image.layers.len());
    for p in layers.iter().chain([&m["Config"]]) {
        assert!(names.contains(&p.as_str().unwrap().to_owned()), "{p}");
    }

    let sys2 = Arc::new(FakeSys::new());
    let client2 = Client::new().unwrap().plain_http(&registry_host);
    let store2 =
        Arc::new(jailer::store::open(sys2, None, &tmp.path().join("store2"), client2).unwrap());
    let loaded = store2.load(&archive_path, None).await.unwrap();
    assert_eq!(loaded.id, built.image.id);
    assert_eq!(loaded.references, ["localhost/demo:1.0"]);

    // 4. Test `jailer push` to mock OCI registry and `Store::pull` into a third store
    let push_target = Reference::parse(&format!("{registry_host}/me/app:1.0")).unwrap();
    let creds = Credentials {
        username: "me".to_owned(),
        password: "secret".to_owned(),
    };
    let manifest_digest = store
        .push("demo:1.0", &push_target, Some(&creds))
        .await
        .unwrap();
    assert!(manifest_digest.starts_with("sha256:"));

    let sys3 = Arc::new(FakeSys::new());
    let client3 = Client::new().unwrap().plain_http(&registry_host);
    let store3 = Arc::new(
        jailer::store::open(
            sys3,
            Some("zroot/test-jailer/images"),
            &tmp.path().join("store3"),
            client3,
        )
        .unwrap(),
    );
    let pulled = store3
        .pull(&push_target.to_string(), Some(&creds), "me")
        .await
        .unwrap();
    assert_eq!(pulled.id, built.image.id);
    assert_eq!(pulled.digest, manifest_digest);

    // 5. Removing the last image also removes its cached blobs
    let blobs = tmp.path().join("store2/blobs/sha256");
    assert!(std::fs::read_dir(&blobs).unwrap().next().is_some());
    assert!(store2.remove("localhost/demo:1.0").await.unwrap());
    assert_eq!(std::fs::read_dir(&blobs).unwrap().count(), 0);

    // 6. A build's pin keeps what it uses through a concurrent `rmi`
    let blobs = store_dir.join("blobs/sha256");
    let pin = store.pin().unwrap();
    assert!(store.pin_image(&pin, "demo:1.0").await.unwrap().is_some());
    assert!(jailer::store::remove(&store, "demo:1.0").await.unwrap());
    assert!(std::fs::read_dir(&blobs).unwrap().next().is_some());
    drop(pin);
    assert!(!jailer::store::remove(&store, "demo:1.0").await.unwrap());
    assert_eq!(std::fs::read_dir(&blobs).unwrap().count(), 0);
}

#[tokio::test]
async fn manifest_push_publishes_one_image_per_platform() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = tmp.path().join("ctx");
    std::fs::create_dir_all(ctx.join("bin")).unwrap();
    std::fs::write(ctx.join("bin/app"), "#!/bin/sh\n").unwrap();
    std::fs::write(
        ctx.join("Containerfile"),
        "FROM scratch\nCOPY bin/app /app\nENTRYPOINT [\"/app\"]\n",
    )
    .unwrap();

    let (addr, _) = start_mock_registry().await;
    let host = format!("127.0.0.1:{}", addr.port());
    let creds = Credentials {
        username: "me".to_owned(),
        password: "secret".to_owned(),
    };
    let open = |dir: &str| {
        let sys = Arc::new(FakeSys::new());
        let client = Client::new().unwrap().plain_http(&host);
        let store = Arc::new(
            jailer::store::open(sys.clone(), None, &tmp.path().join(dir), client).unwrap(),
        );
        let runtime = JailRuntime::new(
            sys,
            store.clone(),
            Config {
                state_dir: tmp.path().join(format!("{dir}-containers")),
                dataset: None,
                shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
                prune_images: false,
            },
        )
        .unwrap();
        (store, runtime)
    };

    // A build for this host, and the same image marked as the other architecture
    let (store, runtime) = open("store");
    let native = build(
        &store,
        &runtime,
        &BuildOptions {
            context_dir: ctx.clone(),
            containerfile: None,
            tag: "app:native".to_owned(),
            build_args: BTreeMap::new(),
            target: None,
            backend: BuildBackend::Native,
            creds: Default::default(),
            strict_lint: false,
            no_cache: false,
            squash: false,
            cache_max: None,
            secrets: BTreeMap::new(),
            ssh: BTreeMap::new(),
            jail_params: Vec::new(),
            labels: BTreeMap::new(),
            timestamp: None,
            limits: Default::default(),
            compression: Default::default(),
            cpuset: None,
            annotations: BTreeMap::new(),
            cache_from: Vec::new(),
            cache_to: None,
        },
    )
    .await
    .unwrap()
    .image;
    let other_arch = if jailer::oci::arch() == "amd64" {
        "arm64"
    } else {
        "amd64"
    };
    let mut config = native.config.clone();
    config.architecture = other_arch.to_owned();
    let pin = store.pin().unwrap();
    let other = store
        .register_built_image(
            &pin,
            &Reference::parse_local_tag("app:other").unwrap(),
            config,
            native.layers.clone(),
            native.layer_descriptors.clone(),
        )
        .await
        .unwrap();
    drop(pin);

    // Two local images
    let target = Reference::parse(&format!("{host}/me/app:1.0")).unwrap();
    let sources = ["app:native".to_owned(), "app:other".to_owned()];
    let index_digest = store
        .push_index(&target, &sources, Some(&creds))
        .await
        .unwrap();
    let (digest, doc) = store
        .client()
        .document(&target, "1.0", Some(&creds))
        .await
        .unwrap();
    assert_eq!(digest, index_digest);
    let archs: Vec<_> = doc
        .manifests
        .unwrap()
        .iter()
        .map(|d| d.platform.clone().unwrap().architecture)
        .collect();
    assert_eq!(archs, [jailer::oci::arch(), other_arch]);

    // A local image and one already in the repository
    let other_tag = Reference::parse(&format!("{host}/me/app:other")).unwrap();
    store
        .push("app:other", &other_tag, Some(&creds))
        .await
        .unwrap();
    let mixed = Reference::parse(&format!("{host}/me/app:mixed")).unwrap();
    let sources = ["app:native".to_owned(), other_tag.to_string()];
    store
        .push_index(&mixed, &sources, Some(&creds))
        .await
        .unwrap();

    // One image per platform
    let dup = ["app:native".to_owned(), "app:native".to_owned()];
    let err = store
        .push_index(&mixed, &dup, Some(&creds))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("two images for"), "{err}");

    // A node pulls the entry for its own architecture
    let (fresh, _) = open("fresh");
    for r in [&target, &mixed] {
        let pulled = fresh
            .pull(&r.to_string(), Some(&creds), "me")
            .await
            .unwrap();
        assert_eq!(pulled.id, native.id);
        assert_ne!(pulled.id, other.id);
    }
}

#[tokio::test]
async fn copy_heredocs_parents_exclude_url_onbuild_and_platform() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = tmp.path().join("ctx");
    for d in ["src/a", "src/b", "src/c", "docs/sub"] {
        std::fs::create_dir_all(ctx.join(d)).unwrap();
    }
    for f in [
        "src/a/Cargo.toml",
        "src/b/Cargo.toml",
        "docs/guide.txt",
        "docs/README.md",
        "docs/sub/x.md",
        "onbuild.txt",
    ] {
        std::fs::write(ctx.join(f), f).unwrap();
    }
    let (addr, _) = start_mock_registry().await;
    let sum = sha256(b"downloaded\n");
    let write_cf = |text: String| std::fs::write(ctx.join("Containerfile"), text).unwrap();
    write_cf(format!(
        r#"# syntax=docker/dockerfile:1
ARG NAME=world
FROM --platform=$BUILDPLATFORM scratch
ARG NAME
ARG TARGETARCH
ONBUILD COPY onbuild.txt /from-onbuild.txt
COPY <<greeting.txt <<"raw.txt" /etc/
hello $NAME on $TARGETARCH
greeting.txt
$NAME
raw.txt
COPY --parents src/*/Cargo.toml /parents/
COPY src/[ab]/Cargo.toml /flat/
COPY --exclude=*.md docs /docs/
ADD --checksum={sum} http://127.0.0.1:{}/files/data.bin /dl/
"#,
        addr.port()
    ));

    let sys = Arc::new(FakeSys::new());
    let client = Client::new().unwrap();
    let store = Arc::new(
        jailer::store::open(sys.clone(), None, &tmp.path().join("store"), client).unwrap(),
    );
    let runtime = JailRuntime::new(
        sys,
        store.clone(),
        Config {
            state_dir: tmp.path().join("containers"),
            dataset: None,
            shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
            prune_images: false,
        },
    )
    .unwrap();
    let opts = |tag: &str| BuildOptions {
        context_dir: ctx.clone(),
        containerfile: None,
        tag: tag.to_owned(),
        build_args: BTreeMap::new(),
        target: None,
        backend: BuildBackend::Native,
        creds: Default::default(),
        strict_lint: false,
        no_cache: false,
        squash: false,
        cache_max: None,
        secrets: BTreeMap::new(),
        ssh: BTreeMap::new(),
        jail_params: Vec::new(),
        labels: BTreeMap::new(),
        timestamp: None,
        limits: Default::default(),
        compression: Default::default(),
        cpuset: None,
        annotations: BTreeMap::new(),
        cache_from: Vec::new(),
        cache_to: None,
    };
    let files = |image: &jailer::store::Image| {
        let root = tmp.path().join(format!("root-{}", &image.id[7..19]));
        store.prepare_rootfs(image, &root, None).unwrap();
        let mut out = BTreeMap::new();
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    let rel = p
                        .strip_prefix(&root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.insert(rel, std::fs::read_to_string(&p).unwrap());
                }
            }
        }
        out
    };

    let base = build(&store, &runtime, &opts("base:1"))
        .await
        .unwrap()
        .image;
    assert_eq!(
        base.config.config.on_build,
        ["COPY onbuild.txt /from-onbuild.txt"]
    );
    let got = files(&base);
    let want: BTreeMap<String, String> = [
        (
            "etc/greeting.txt",
            format!("hello world on {}\n", jailer::oci::arch()),
        ),
        ("etc/raw.txt", "$NAME\n".to_owned()),
        ("parents/src/a/Cargo.toml", "src/a/Cargo.toml".to_owned()),
        ("parents/src/b/Cargo.toml", "src/b/Cargo.toml".to_owned()),
        ("flat/Cargo.toml", "src/b/Cargo.toml".to_owned()),
        ("docs/guide.txt", "docs/guide.txt".to_owned()),
        ("dl/data.bin", "downloaded\n".to_owned()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    assert_eq!(got, want);

    // The base's trigger runs in the child's build and is not passed on.
    write_cf("FROM base:1\nCOPY docs/guide.txt /guide.txt\n".to_owned());
    let child = build(&store, &runtime, &opts("child:1"))
        .await
        .unwrap()
        .image;
    assert!(child.config.config.on_build.is_empty());
    let got = files(&child);
    assert_eq!(got["from-onbuild.txt"], "onbuild.txt");
    assert_eq!(got["guide.txt"], "docs/guide.txt");

    // `--squash` leaves the same files in one layer.
    assert!(child.layers.len() > 1);
    let squashed = build(
        &store,
        &runtime,
        &BuildOptions {
            squash: true,
            ..opts("squashed:1")
        },
    )
    .await
    .unwrap()
    .image;
    assert_eq!(squashed.layers.len(), 1);
    assert_eq!(squashed.config.rootfs.diff_ids.len(), 1);
    assert_eq!(files(&squashed), got);

    // A later ARG default replaces an earlier one, an ENV's values see the
    // variables as they were before it, and a global ARG reaches a stage
    // only through an ARG of the stage's own.
    write_cf(
        "ARG G=global\nFROM scratch\nARG X=first\nARG X=second\nENV A=old\nENV A=new B=$A\nLABEL x=$X b=$B before=[$G]\nARG G\nLABEL after=$G\n"
            .to_owned(),
    );
    let vars = build(&store, &runtime, &opts("vars:1"))
        .await
        .unwrap()
        .image;
    let labels = &vars.config.config.labels;
    assert_eq!(labels["x"], "second");
    assert_eq!(labels["b"], "old");
    assert_eq!(labels["before"], "[]");
    assert_eq!(labels["after"], "global");
    assert!(vars.config.config.env.contains(&"B=old".to_owned()));

    // A global ARG's default sees the ones before it; a stage built on a
    // stage has its ARGs; an ENV goes over an ARG of its name; one ARG line
    // may name several.
    write_cf(
        "ARG A=hello\nARG B=${A}-world\nFROM scratch AS parent\nARG B\nARG P=inherited\nFROM parent\nENV E=env\nARG E=arg\nARG X Y=two\nLABEL b=$B p=$P e=$E y=$Y\n"
            .to_owned(),
    );
    let scoped = build(&store, &runtime, &opts("scoped:1"))
        .await
        .unwrap()
        .image;
    let labels = &scoped.config.config.labels;
    assert_eq!(labels["b"], "hello-world");
    assert_eq!(labels["p"], "inherited");
    assert_eq!(labels["e"], "env");
    assert_eq!(labels["y"], "two");

    // Many matches of one source go into a directory, as several sources
    // do, rather than over one another.
    write_cf("FROM scratch\nCOPY docs/*.* /result\n".to_owned());
    let many = build(&store, &runtime, &opts("many:1"))
        .await
        .unwrap()
        .image;
    let got = files(&many);
    assert!(got.contains_key("result/guide.txt"), "{got:?}");
    assert!(got.contains_key("result/README.md"), "{got:?}");

    // A `!` pattern takes a file back from a directory left out.
    std::fs::write(ctx.join(".containerignore"), "docs\n!docs/guide.txt\n").unwrap();
    write_cf("FROM scratch\nCOPY . /out/\n".to_owned());
    let taken_back = build(&store, &runtime, &opts("taken-back:1"))
        .await
        .unwrap()
        .image;
    let got = files(&taken_back);
    assert_eq!(got["out/docs/guide.txt"], "docs/guide.txt");
    assert!(!got.contains_key("out/docs/README.md"), "{got:?}");
    std::fs::remove_file(ctx.join(".containerignore")).unwrap();

    // `COPY --from` an image, not a stage, named by an ARG.
    write_cf(
        "FROM scratch AS tools\nFROM scratch\nARG SRC=base:1\nCOPY --from=$SRC /etc/raw.txt /docs/ /copied/\nCOPY --from=tools / /empty/\n"
            .to_owned(),
    );
    let copied = build(&store, &runtime, &opts("copied:1"))
        .await
        .unwrap()
        .image;
    let got = files(&copied);
    assert_eq!(got["copied/raw.txt"], "$NAME\n");
    assert_eq!(got["copied/guide.txt"], "docs/guide.txt");
    write_cf("FROM scratch\nCOPY --from=localhost/nowhere:1 /a /a\n".to_owned());
    assert!(build(&store, &runtime, &opts("nowhere:2")).await.is_err());

    // `--label` goes over `LABEL`; `--timestamp` dates the config and this
    // build's history, and an image built twice with it is the same image.
    write_cf("FROM scratch\nLABEL a=file b=file\nCOPY onbuild.txt /o.txt\n".to_owned());
    let stamped = |tag: &'static str| BuildOptions {
        labels: BTreeMap::from([("b".to_owned(), "flag".to_owned())]),
        timestamp: Some(1_700_000_000),
        annotations: BTreeMap::from([("org.example.note".to_owned(), "hi".to_owned())]),
        ..opts(tag)
    };
    let first = build(&store, &runtime, &stamped("stamped:1"))
        .await
        .unwrap()
        .image;
    let labels = &first.config.config.labels;
    assert_eq!(
        (labels["a"].as_str(), labels["b"].as_str()),
        ("file", "flag")
    );
    assert_eq!(first.config.created, "2023-11-14T22:13:20Z");
    // --annotation goes in the manifest.
    let manifest = std::fs::read_to_string(store.blob_path(&first.digest).unwrap()).unwrap();
    assert!(
        manifest.contains("\"org.example.note\": \"hi\""),
        "{manifest}"
    );
    assert!(
        first
            .config
            .history
            .iter()
            .all(|h| h.created == "2023-11-14T22:13:20Z")
    );
    let again = build(&store, &runtime, &stamped("stamped:2"))
        .await
        .unwrap()
        .image;
    assert_eq!(again.id, first.id);

    // zstd layers: their own media type and blobs, the same files, and no
    // gzip layer from the cache.
    let zstd = build(
        &store,
        &runtime,
        &BuildOptions {
            compression: jailer::layer::Compression::Zstd,
            ..opts("zstd:1")
        },
    )
    .await
    .unwrap()
    .image;
    assert!(!zstd.layer_descriptors.is_empty());
    for d in &zstd.layer_descriptors {
        assert_eq!(d.media_type, "application/vnd.oci.image.layer.v1.tar+zstd");
        let blob = std::fs::read(store.blob_path(&d.digest).unwrap()).unwrap();
        assert_eq!(blob[..4], [0x28, 0xb5, 0x2f, 0xfd], "a zstd frame");
    }
    let gzipped = build(&store, &runtime, &opts("gzip:1"))
        .await
        .unwrap()
        .image;
    assert_eq!(files(&zstd), files(&gzipped));
    assert_eq!(zstd.config.rootfs.diff_ids, gzipped.config.rootfs.diff_ids);
    assert!(
        gzipped
            .layer_descriptors
            .iter()
            .all(|d| d.media_type.ends_with("tar+gzip"))
    );
    // One config with other blobs is another image: the zstd build keeps
    // its own.
    let kept = store.get("localhost/zstd:1").unwrap().unwrap();
    assert_eq!(kept.digest, zstd.digest);
    assert!(
        kept.layer_descriptors
            .iter()
            .all(|d| d.media_type.ends_with("tar+zstd"))
    );

    // `ADD` unpacks an archive from the context, compressed or not.
    let pack = tmp.path().join("pack");
    std::fs::create_dir_all(pack.join("inner")).unwrap();
    std::fs::write(pack.join("inner/packed.txt"), "packed").unwrap();
    for (name, flag) in [("plain.tar", "-cf"), ("zipped.tar.gz", "-czf")] {
        let status = std::process::Command::new("tar")
            .arg(flag)
            .arg(ctx.join(name))
            .arg("-C")
            .arg(&pack)
            .arg("inner")
            .status()
            .unwrap();
        assert!(status.success());
    }
    write_cf("FROM scratch\nADD plain.tar /plain/\nADD zipped.tar.gz /zipped/\n".to_owned());
    let unpacked = build(&store, &runtime, &opts("unpacked:1"))
        .await
        .unwrap()
        .image;
    let got = files(&unpacked);
    assert_eq!(got["plain/inner/packed.txt"], "packed");
    assert_eq!(got["zipped/inner/packed.txt"], "packed");

    // A `.wh.` name in an archive is unpacked, then refused: a layer would
    // hold it as a whiteout.
    std::fs::write(pack.join("inner/.wh.keep"), "").unwrap();
    let status = std::process::Command::new("tar")
        .arg("-cf")
        .arg(ctx.join("wh.tar"))
        .arg("-C")
        .arg(&pack)
        .arg("inner")
        .status()
        .unwrap();
    assert!(status.success());
    write_cf("FROM scratch\nADD wh.tar /wh/\n".to_owned());
    let err = build(&store, &runtime, &opts("wh:1"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("wh/inner/.wh.keep"), "{err}");

    // `--exclude` is matched below the source; a source .containerignore
    // leaves out is not found, and `/` anchors a pattern at the top.
    write_cf("FROM scratch\nCOPY --exclude=sub/x.md docs /docs/\n".to_owned());
    let excluded = build(&store, &runtime, &opts("excluded:1"))
        .await
        .unwrap()
        .image;
    let got = files(&excluded);
    assert!(got.contains_key("docs/README.md"));
    assert!(!got.contains_key("docs/sub/x.md"));
    std::fs::write(ctx.join(".containerignore"), "/guide.txt\nonbuild.txt\n").unwrap();
    write_cf("FROM scratch\nCOPY docs /docs/\n".to_owned());
    let anchored = build(&store, &runtime, &opts("anchored:1"))
        .await
        .unwrap()
        .image;
    assert!(files(&anchored).contains_key("docs/guide.txt"));
    write_cf("FROM scratch\nCOPY onbuild.txt /o.txt\n".to_owned());
    let err = build(&store, &runtime, &opts("ignored:1"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not found"), "{err}");
    std::fs::remove_file(ctx.join(".containerignore")).unwrap();

    // Failures name the problem.
    for (cf, msg) in [
        (
            "FROM --platform=linux/riscv64 scratch\n",
            "jailer builds for freebsd/",
        ),
        (
            &format!(
                "FROM scratch\nADD --checksum=sha256:{} http://127.0.0.1:{}/files/data.bin /x\n",
                "0".repeat(64),
                addr.port()
            ),
            "checksum is sha256:",
        ),
        (
            &format!(
                "FROM scratch\nADD http://127.0.0.1:{}/files/gone /x\n",
                addr.port()
            ),
            "HTTP 404",
        ),
    ] {
        write_cf(cf.to_owned());
        let err = build(&store, &runtime, &opts("bad:1")).await.unwrap_err();
        assert!(err.to_string().contains(msg), "{err}");
    }
}

#[tokio::test]
async fn cache_trim_drops_least_recently_used_layers() {
    use jailer::store::{CachedLayer, CachedStep};
    let tmp = tempfile::tempdir().unwrap();
    let ctx = tmp.path().join("ctx");
    std::fs::create_dir_all(&ctx).unwrap();
    let sys = Arc::new(FakeSys::new());
    let store = Arc::new(
        jailer::store::open(
            sys.clone(),
            None,
            &tmp.path().join("store"),
            Client::new().unwrap(),
        )
        .unwrap(),
    );
    let runtime = JailRuntime::new(
        sys,
        store.clone(),
        Config {
            state_dir: tmp.path().join("containers"),
            dataset: None,
            shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
            prune_images: false,
        },
    )
    .unwrap();

    // Two one-layer images, each also named by a cache entry; `a` used longer ago.
    let mut built = Vec::new();
    for name in ["a", "b"] {
        std::fs::write(ctx.join(name), name.repeat(1000)).unwrap();
        let cf = ctx.join(format!("{name}.Containerfile"));
        std::fs::write(&cf, format!("FROM scratch\nCOPY {name} /{name}\n")).unwrap();
        let image = build(
            &store,
            &runtime,
            &BuildOptions {
                context_dir: ctx.clone(),
                containerfile: Some(cf),
                tag: format!("{name}:1"),
                build_args: BTreeMap::new(),
                target: None,
                backend: BuildBackend::Native,
                creds: Default::default(),
                strict_lint: false,
                no_cache: false,
                squash: false,
                cache_max: None,
                secrets: BTreeMap::new(),
                ssh: BTreeMap::new(),
                jail_params: Vec::new(),
                labels: BTreeMap::new(),
                timestamp: None,
                limits: Default::default(),
                compression: Default::default(),
                cpuset: None,
                annotations: BTreeMap::new(),
                cache_from: Vec::new(),
                cache_to: None,
            },
        )
        .await
        .unwrap()
        .image;
        jailer::store::record_step(
            &store,
            name,
            &CachedStep {
                layer: Some(CachedLayer {
                    chain: image.layers[0].clone(),
                    diff_id: image.config.rootfs.diff_ids[0].clone(),
                    descriptor: image.layer_descriptors[0].clone(),
                }),
            },
        )
        .unwrap();
        assert!(
            jailer::store::remove(&store, &format!("{name}:1"))
                .await
                .unwrap()
        );
        built.push(image);
    }
    std::fs::File::options()
        .append(true)
        .open(store.dir().join("cache/a"))
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
        .unwrap();
    let layer = |i: usize| store.dir().join("layers").join(&built[i].layers[0]);
    assert!(layer(0).exists() && layer(1).exists());

    assert_eq!(
        jailer::store::trim_cache(&store, u64::MAX).await.unwrap(),
        0
    );
    let b_size = built[1].layer_descriptors[0].size;
    assert_eq!(jailer::store::trim_cache(&store, b_size).await.unwrap(), 1);
    assert!(!layer(0).exists() && layer(1).exists());
    assert_eq!(jailer::store::trim_cache(&store, 0).await.unwrap(), 1);
    assert!(!layer(1).exists());
}

#[tokio::test]
async fn registry_cache_carries_steps_to_another_store() {
    use jailer::cache::{Imported, Remote, export};
    use jailer::store::{CachedLayer, CachedStep, cached_step};
    let tmp = tempfile::tempdir().unwrap();
    let (addr, _) = start_mock_registry().await;
    let host = format!("127.0.0.1:{}", addr.port());
    let open = |dir: &str| {
        let sys = Arc::new(FakeSys::new());
        let store = Arc::new(
            jailer::store::open(
                sys.clone(),
                None,
                &tmp.path().join(dir),
                Client::new().unwrap().plain_http(&host),
            )
            .unwrap(),
        );
        let runtime = JailRuntime::new(
            sys,
            store.clone(),
            Config {
                state_dir: tmp.path().join(dir).join("containers"),
                dataset: None,
                shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
                prune_images: false,
            },
        )
        .unwrap();
        (store, runtime)
    };

    // A layer in the first store, standing for what a RUN step left.
    let (store, runtime) = open("a");
    let ctx = tmp.path().join("ctx");
    std::fs::create_dir_all(&ctx).unwrap();
    std::fs::write(ctx.join("made"), "by a step\n").unwrap();
    std::fs::write(ctx.join("Containerfile"), "FROM scratch\nCOPY made /made\n").unwrap();
    let image = build(
        &store,
        &runtime,
        &BuildOptions {
            context_dir: ctx.clone(),
            containerfile: None,
            tag: "made:1".to_owned(),
            build_args: BTreeMap::new(),
            target: None,
            backend: BuildBackend::Native,
            creds: Default::default(),
            strict_lint: false,
            no_cache: false,
            squash: false,
            cache_max: None,
            secrets: BTreeMap::new(),
            ssh: BTreeMap::new(),
            jail_params: Vec::new(),
            labels: BTreeMap::new(),
            timestamp: None,
            limits: Default::default(),
            compression: Default::default(),
            cpuset: None,
            annotations: BTreeMap::new(),
            cache_from: Vec::new(),
            cache_to: None,
        },
    )
    .await
    .unwrap()
    .image;
    let layer = CachedLayer {
        chain: image.layers[0].clone(),
        diff_id: image.config.rootfs.diff_ids[0].clone(),
        descriptor: image.layer_descriptors[0].clone(),
    };
    let remote = Remote {
        reference: Reference::parse(&format!("{host}/me/cache:main")).unwrap(),
        creds: None,
    };
    let steps = [
        (
            "made".to_owned(),
            CachedStep {
                layer: Some(layer.clone()),
            },
        ),
        ("empty".to_owned(), CachedStep { layer: None }),
    ];
    export(store.client(), &store, &remote, &steps)
        .await
        .unwrap();

    // Another store takes both steps from the registry, the layer included.
    let (other, _) = open("b");
    let imported = Imported::read(other.client(), std::slice::from_ref(&remote)).await;
    assert!(!imported.is_empty());
    let pin = other.pin().unwrap();
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    for key in ["made", "empty"] {
        assert!(
            imported
                .fetch(&other, &pin, key, &[], None, &work)
                .await
                .unwrap()
        );
    }
    let got = cached_step(&other, &pin, "made").await.unwrap().unwrap();
    let got = got.layer.unwrap();
    assert_eq!((got.chain, got.diff_id), (layer.chain, layer.diff_id));
    assert!(other.has_layer(&image.layers[0]).unwrap());
    assert!(
        cached_step(&other, &pin, "empty")
            .await
            .unwrap()
            .unwrap()
            .layer
            .is_none()
    );
    // A step the cache lacks is not taken.
    assert!(
        !imported
            .fetch(&other, &pin, "other", &[], None, &work)
            .await
            .unwrap()
    );

    // A cache that is not there is left out.
    let missing = Remote {
        reference: Reference::parse(&format!("{host}/me/cache:none")).unwrap(),
        creds: None,
    };
    assert!(Imported::read(other.client(), &[missing]).await.is_empty());
}

#[tokio::test]
async fn pushed_images_are_signed_and_verified() {
    use jailer::sign::{generate, sign, signature_ref, signing_key, verify, verifying_key};
    let tmp = tempfile::tempdir().unwrap();
    let (addr, registry) = start_mock_registry().await;
    let host = format!("127.0.0.1:{}", addr.port());
    let sys = Arc::new(FakeSys::new());
    let store = Arc::new(
        jailer::store::open(
            sys.clone(),
            None,
            &tmp.path().join("store"),
            Client::new().unwrap().plain_http(&host),
        )
        .unwrap(),
    );
    let runtime = JailRuntime::new(
        sys,
        store.clone(),
        Config {
            state_dir: tmp.path().join("containers"),
            dataset: None,
            shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
            prune_images: false,
        },
    )
    .unwrap();
    let ctx = tmp.path().join("ctx");
    std::fs::create_dir_all(&ctx).unwrap();
    std::fs::write(ctx.join("Containerfile"), "FROM scratch\nLABEL a=b\n").unwrap();
    build(
        &store,
        &runtime,
        &BuildOptions {
            context_dir: ctx.clone(),
            containerfile: None,
            tag: "signed:1".to_owned(),
            build_args: BTreeMap::new(),
            target: None,
            backend: BuildBackend::Native,
            creds: Default::default(),
            strict_lint: false,
            no_cache: false,
            squash: false,
            cache_max: None,
            secrets: BTreeMap::new(),
            ssh: BTreeMap::new(),
            jail_params: Vec::new(),
            labels: BTreeMap::new(),
            timestamp: None,
            limits: Default::default(),
            compression: Default::default(),
            cpuset: None,
            annotations: BTreeMap::new(),
            cache_from: Vec::new(),
            cache_to: None,
        },
    )
    .await
    .unwrap();
    let client = store.client();
    let target = Reference::parse(&format!("{host}/me/app:1")).unwrap();
    let digest = store.push("signed:1", &target, None).await.unwrap();

    // Unsigned, then signed by one key and not another.
    let (private, public) = generate().unwrap();
    let (other_private, other_public) = generate().unwrap();
    let key = verifying_key(&public).unwrap();
    let other = verifying_key(&other_public).unwrap();
    let err = verify(client, &target, &key, None).await.unwrap_err();
    assert!(err.to_string().contains("not signed"), "{err}");
    sign(
        client,
        &target,
        &digest,
        &signing_key(&private).unwrap(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(verify(client, &target, &key, None).await.unwrap(), digest);
    let err = verify(client, &target, &other, None).await.unwrap_err();
    assert!(
        err.to_string().contains("no signature by this key"),
        "{err}"
    );

    // A second signer adds to the signatures; signing again changes nothing.
    sign(
        client,
        &target,
        &digest,
        &signing_key(&other_private).unwrap(),
        None,
    )
    .await
    .unwrap();
    sign(
        client,
        &target,
        &digest,
        &signing_key(&private).unwrap(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(verify(client, &target, &other, None).await.unwrap(), digest);
    assert_eq!(verify(client, &target, &key, None).await.unwrap(), digest);
    let sig_tag = signature_ref(&target, &digest).tag.unwrap();
    let (_, sig) = registry.manifests.lock().unwrap()[&sig_tag].clone();
    let sig: serde_json::Value = serde_json::from_slice(&sig).unwrap();
    assert_eq!(sig["layers"].as_array().unwrap().len(), 2, "{sig}");
    assert_eq!(
        sig["layers"][0]["mediaType"],
        "application/vnd.dev.cosign.simplesigning.v1+json"
    );
}

#[tokio::test]
async fn login_checks_credentials_with_the_registry() {
    let (addr, _) = start_mock_registry().await;
    let registry = addr.to_string();
    let creds = |password: &str| Credentials {
        username: "me".to_owned(),
        password: password.to_owned(),
    };
    jailer::auth::check_credentials(&registry, &creds("secret"), true)
        .await
        .unwrap();
    let err = jailer::auth::check_credentials(&registry, &creds("bad"), true)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("login refused for me"), "{err}");
}

#[cfg(unix)]
#[tokio::test]
async fn copy_follows_links_only_inside_the_root() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let ctx = tmp.path().join("ctx");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&ctx).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret"), "host\n").unwrap();
    std::fs::write(ctx.join("f"), "f\n").unwrap();
    // Links to the host's directory, absolute and relative.
    symlink(&outside, ctx.join("escape")).unwrap();
    symlink("../../../../../../../../..", ctx.join("up")).unwrap();

    let sys = Arc::new(FakeSys::new());
    let store = Arc::new(
        jailer::store::open(
            sys.clone(),
            None,
            &tmp.path().join("store"),
            Client::new().unwrap(),
        )
        .unwrap(),
    );
    let runtime = JailRuntime::new(
        sys,
        store.clone(),
        Config {
            state_dir: tmp.path().join("containers"),
            dataset: None,
            shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
            prune_images: false,
        },
    )
    .unwrap();
    let opts = |tag: &str| BuildOptions {
        context_dir: ctx.clone(),
        containerfile: None,
        tag: tag.to_owned(),
        build_args: BTreeMap::new(),
        target: None,
        backend: BuildBackend::Native,
        creds: Default::default(),
        strict_lint: false,
        no_cache: false,
        squash: false,
        cache_max: None,
        secrets: BTreeMap::new(),
        ssh: BTreeMap::new(),
        jail_params: Vec::new(),
        labels: BTreeMap::new(),
        timestamp: None,
        limits: Default::default(),
        compression: Default::default(),
        cpuset: None,
        annotations: BTreeMap::new(),
        cache_from: Vec::new(),
        cache_to: None,
    };
    let write_cf = |text: &str| std::fs::write(ctx.join("Containerfile"), text).unwrap();

    // Written through a link the image has, the file stays in the image.
    write_cf("FROM scratch\nCOPY escape up /\nCOPY f /escape/f\nCOPY f /up/g\n");
    let image = build(&store, &runtime, &opts("in:1")).await.unwrap().image;
    assert!(!outside.join("f").exists());
    let root = tmp.path().join("root");
    store.prepare_rootfs(&image, &root, None).unwrap();
    let rel = outside.strip_prefix("/").unwrap();
    assert_eq!(
        std::fs::read_to_string(root.join(rel).join("f")).unwrap(),
        "f\n"
    );
    // `..` stops at the root.
    assert_eq!(std::fs::read_to_string(root.join("g")).unwrap(), "f\n");

    // Read through a link in the context, the host's files are not found.
    let secret = format!("up{}/secret", outside.display());
    write_cf(&format!("FROM scratch\nCOPY {secret} /s\n"));
    let err = build(&store, &runtime, &opts("out:1")).await.unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");
    write_cf("FROM scratch\nCOPY escape/secret /s\n");
    assert!(build(&store, &runtime, &opts("out:2")).await.is_err());

    // `ADD` opens an archive: one that is a link to the host's is not.
    {
        let mut b = tar::Builder::new(std::fs::File::create(outside.join("x.tar")).unwrap());
        b.append_path_with_name(outside.join("secret"), "secret")
            .unwrap();
        b.finish().unwrap();
    }
    symlink(outside.join("x.tar"), ctx.join("backup.tar")).unwrap();
    write_cf("FROM scratch\nADD backup.tar /x/\n");
    let err = build(&store, &runtime, &opts("out:3")).await.unwrap_err();
    assert!(err.to_string().contains("not found"), "{err}");

    // A directory the build makes is in a layer: `WORKDIR`'s, and a
    // copied one, with its source's mode.
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(ctx.join("private/inner")).unwrap();
    std::fs::set_permissions(ctx.join("private"), std::fs::Permissions::from_mode(0o700)).unwrap();
    write_cf("FROM scratch\nCOPY f /seed\nWORKDIR /empty\nCOPY private /private\n");
    let image = build(&store, &runtime, &opts("dirs:1"))
        .await
        .unwrap()
        .image;
    let root = tmp.path().join("dirs");
    store.prepare_rootfs(&image, &root, None).unwrap();
    assert!(root.join("empty").is_dir());
    assert_eq!(image.config.config.working_dir, "/empty");
    let mode = |p: &str| {
        std::fs::metadata(root.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert!(root.join("private/inner").is_dir());
    assert_eq!(mode("private"), 0o700);

    // An image's /etc/passwd and /etc/group may be links, by absolute
    // paths: its users are found through them, not in the host's files.
    {
        let mut b = tar::Builder::new(std::fs::File::create(ctx.join("accounts.tar")).unwrap());
        let mut add = |path: &str, body: &str| {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, path, body.as_bytes()).unwrap();
        };
        add("usr/local/etc/passwd", "jlrtest:*:4242:4243::/:/bin/sh\n");
        add("usr/local/etc/group", "jlrgroup:*:4243:\n");
        for f in ["passwd", "group"] {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            b.append_link(&mut h, format!("etc/{f}"), format!("/usr/local/etc/{f}"))
                .unwrap();
        }
        b.finish().unwrap();
    }
    write_cf(
        "FROM scratch\nADD accounts.tar /\nCOPY --chown=jlrtest:jlrgroup f /owned\n\
         USER jlrtest\nWORKDIR /made\n",
    );
    let image = build(&store, &runtime, &opts("accounts:1"))
        .await
        .unwrap()
        .image;
    let root = tmp.path().join("accounts");
    store.prepare_rootfs(&image, &root, None).unwrap();
    let report = jailer::check::check_image(&image.config, Some(&root));
    assert!(
        !report.findings.iter().any(|f| f.code == "LEGION008"),
        "the image's USER is in its linked /etc/passwd: {:?}",
        report.findings
    );
}

/// `CMD`, `ENTRYPOINT`, `SHELL`, `WORKDIR` and `ENV` as Docker keeps them.
#[cfg(unix)]
#[tokio::test]
async fn config_instructions_follow_docker() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let ctx = tmp.path().join("ctx");
    std::fs::create_dir_all(&ctx).unwrap();
    let sys = Arc::new(FakeSys::new());
    let store = Arc::new(
        jailer::store::open(
            sys.clone(),
            None,
            &tmp.path().join("store"),
            Client::new().unwrap(),
        )
        .unwrap(),
    );
    let runtime = JailRuntime::new(
        sys,
        store.clone(),
        Config {
            state_dir: tmp.path().join("containers"),
            dataset: None,
            shim: vec![OsString::from("jailer"), OsString::from("jail-shim")],
            prune_images: false,
        },
    )
    .unwrap();
    let opts = |tag: &str| BuildOptions {
        context_dir: ctx.clone(),
        containerfile: None,
        tag: tag.to_owned(),
        build_args: BTreeMap::new(),
        target: None,
        backend: BuildBackend::Native,
        creds: Default::default(),
        strict_lint: false,
        no_cache: false,
        squash: false,
        cache_max: None,
        secrets: BTreeMap::new(),
        ssh: BTreeMap::new(),
        jail_params: Vec::new(),
        labels: BTreeMap::new(),
        timestamp: None,
        limits: Default::default(),
        compression: Default::default(),
        cpuset: None,
        annotations: BTreeMap::new(),
        cache_from: Vec::new(),
        cache_to: None,
    };
    let write_cf = |text: &str| std::fs::write(ctx.join("Containerfile"), text).unwrap();

    write_cf(concat!(
        "FROM scratch\n",
        "SHELL [\"/bin/sh\", \"-e\", \"-c\"]\n",
        // A CMD of this stage stays after its ENTRYPOINT.
        "CMD [\"--serve\"]\n",
        "ENTRYPOINT [\"/app\"]\n",
        "USER 1001:1002\n",
        "WORKDIR /app/src\n",
        "WORKDIR ..\n",
        "WORKDIR ../../../srv/./data\n",
        "ENV K=na\n",
        "ENV ${K}me=v\n",
        "LABEL \"my.key\" a value\n",
    ));
    let image = build(&store, &runtime, &opts("parent:1"))
        .await
        .unwrap()
        .image;
    let c = &image.config.config;
    assert_eq!(c.cmd, ["--serve"]);
    assert_eq!(c.entrypoint, ["/app"]);
    assert_eq!(c.working_dir, "/srv/data");
    assert_eq!(c.extra["Shell"], serde_json::json!(["/bin/sh", "-e", "-c"]));
    assert!(c.env.contains(&"name=v".to_owned()), "{:?}", c.env);
    assert_eq!(c.labels["my.key"], "a value");
    let root = tmp.path().join("root");
    store.prepare_rootfs(&image, &root, None).unwrap();
    // The directories WORKDIR made are the USER's.
    if unsafe { libc::geteuid() } == 0 {
        for d in ["app", "app/src", "srv", "srv/data"] {
            let m = std::fs::metadata(root.join(d)).unwrap();
            assert_eq!((m.uid(), m.gid()), (1001, 1002), "{d}");
        }
    }

    // The SHELL carries over to an image built on it; an ENTRYPOINT
    // there resets the CMD it inherits.
    write_cf("FROM parent:1\nCMD echo hi\n");
    let image = build(&store, &runtime, &opts("child:1"))
        .await
        .unwrap()
        .image;
    assert_eq!(image.config.config.cmd, ["/bin/sh", "-e", "-c", "echo hi"]);
    write_cf("FROM parent:1\nENTRYPOINT [\"/x\"]\n");
    let image = build(&store, &runtime, &opts("child:2"))
        .await
        .unwrap()
        .image;
    assert!(image.config.config.cmd.is_empty());

    // As in BuildKit, a directory is not copied over a file: the build
    // says where.
    std::fs::write(ctx.join("config"), "file").unwrap();
    std::fs::create_dir_all(ctx.join("tree/config")).unwrap();
    std::fs::write(ctx.join("tree/config/a"), "a").unwrap();
    write_cf("FROM scratch\nCOPY config /app/config\nCOPY tree /app/\n");
    let err = build(&store, &runtime, &opts("over:1"))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("cannot copy to non-directory: /app/config"),
        "{err}"
    );
    // Nor a file over a directory, which would take what is in it.
    std::fs::create_dir_all(ctx.join("d1/a")).unwrap();
    std::fs::write(ctx.join("d1/a/keep"), "k").unwrap();
    std::fs::create_dir_all(ctx.join("d2")).unwrap();
    std::fs::write(ctx.join("d2/a"), "file").unwrap();
    write_cf("FROM scratch\nCOPY d1 /x/\nCOPY d2 /x/\n");
    let err = build(&store, &runtime, &opts("over:2"))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("cannot replace directory /x/a with a file"),
        "{err}"
    );

    // A directory .containerignore leaves out is there only with a file put
    // back in it; the directories made for one have their own modes.
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(ctx.join("docs")).unwrap();
    std::fs::write(ctx.join("docs/drop.txt"), "d").unwrap();
    std::fs::create_dir_all(ctx.join("deep/b")).unwrap();
    std::fs::write(ctx.join("deep/b/c.txt"), "c").unwrap();
    std::fs::set_permissions(ctx.join("deep"), std::fs::Permissions::from_mode(0o750)).unwrap();
    std::fs::set_permissions(ctx.join("deep/b"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        ctx.join(".containerignore"),
        "docs\n!docs/keep.txt\ndeep\n!deep/b/c.txt\n",
    )
    .unwrap();
    write_cf("FROM scratch\nCOPY docs /docs\n");
    let err = build(&store, &runtime, &opts("ign:1"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("source \"docs\" not found"), "{err}");
    write_cf("FROM scratch\nCOPY deep /deep\n");
    let image = build(&store, &runtime, &opts("ign:2")).await.unwrap().image;
    let root = tmp.path().join("root-ign");
    store.prepare_rootfs(&image, &root, None).unwrap();
    let mode = |p: &str| {
        std::fs::metadata(root.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!((mode("deep"), mode("deep/b")), (0o750, 0o700));
    assert_eq!(
        std::fs::read_to_string(root.join("deep/b/c.txt")).unwrap(),
        "c"
    );
}
