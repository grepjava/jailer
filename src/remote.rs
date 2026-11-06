//! `jailer publish`: one image for several platforms, each built natively on
//! a host of its own over ssh. Every host gets the same context, builds it,
//! and pushes to a staging tag of the target. Only when all of them have, each
//! the platform it was named for and from the same source, is the index
//! pushed under the target's tag: a failed host leaves that tag as it was.
//! Credentials stay where they are: each host logs in to the registry itself.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::containerfile::IgnoreMatcher;
use crate::record::{Build, Record, context_files};
use crate::registry::Credentials;
use crate::store::Store;
use crate::{Error, Reference};

/// What to build, and where.
#[derive(Debug, Clone)]
pub struct Publish {
    pub target: Reference,
    /// Platform (`freebsd/amd64`) to `ssh` destination.
    pub hosts: BTreeMap<String, String>,
    pub context: PathBuf,
    /// The Containerfile, relative to the context, if not the default.
    pub containerfile: Option<String>,
    pub build_stage: Option<String>,
    pub build_args: Vec<String>,
    /// The program on the hosts.
    pub remote_jailer: String,
    /// The local program standing for `ssh`.
    pub ssh: String,
}

/// `s`, as one word to a POSIX shell.
fn quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The tag a platform's image is staged under.
fn staging(target: &Reference, platform: &str) -> Result<Reference, Error> {
    let tag = target
        .tag
        .as_deref()
        .ok_or_else(|| Error::Runtime(format!("{target}: give a tag to publish to")))?;
    Ok(Reference {
        tag: Some(format!("{tag}-{}", platform.replace('/', "-"))),
        digest: None,
        ..target.clone()
    })
}

/// What a host runs, with the context as a tar on standard input. Only the
/// record goes to standard output. Its work goes with it however it ends.
fn script(p: &Publish, stage: &Reference) -> String {
    let jailer = quoted(&p.remote_jailer);
    let mut build = format!("{jailer} build -t jailer-publish:latest --record r.json");
    if let Some(file) = &p.containerfile {
        build += &format!(" -f {}", quoted(&format!("ctx/{file}")));
    }
    if let Some(stage) = &p.build_stage {
        build += &format!(" --target {}", quoted(stage));
    }
    for arg in &p.build_args {
        build += &format!(" --build-arg {}", quoted(arg));
    }
    format!(
        "set -eu\n\
         w=$(mktemp -d)\n\
         trap 'rm -rf \"$w\"' EXIT\n\
         trap 'exit 129' HUP INT TERM\n\
         cd \"$w\"\n\
         mkdir ctx\n\
         tar -xf - -C ctx\n\
         {build} ctx >&2\n\
         {jailer} push --record r.json jailer-publish:latest {} >&2\n\
         cat r.json\n",
        quoted(&stage.to_string())
    )
}

/// The context as a tar at `out`: what a build sees of it.
fn pack_context(dir: &Path, ignore: &IgnoreMatcher, out: &Path) -> Result<(), Error> {
    let mut tar = tar::Builder::new(std::fs::File::create(out)?);
    tar.follow_symlinks(false);
    for (rel, path) in context_files(dir, ignore)? {
        tar.append_path_with_name(&path, &rel)?;
    }
    tar.finish()?;
    Ok(())
}

/// Builds on one host: its record, or why not.
async fn build_on(
    p: &Publish,
    platform: &str,
    dest: &str,
    context: &Path,
    stage: &Reference,
) -> Result<Record, String> {
    let tar = std::fs::File::open(context).map_err(|e| e.to_string())?;
    println!("Building {platform} on {dest}");
    let out = tokio::process::Command::new(&p.ssh)
        .args(["-o", "BatchMode=yes", dest])
        .arg(format!("sh -c {}", quoted(&script(p, stage))))
        .stdin(Stdio::from(tar))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| format!("running {}: {e}", p.ssh))?;
    if !out.status.success() {
        return Err(format!("the build ended with {}", out.status));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("its record: {e}"))
}

/// Checks what the hosts built: each the platform it was for, all from the
/// same source. Returns the staged references to make an index of.
fn check_builds(
    builds: &BTreeMap<String, Record>,
    local_context: Option<&str>,
) -> Result<Vec<String>, Error> {
    let mut problems = Vec::new();
    let mut sources = builds.values().filter_map(|r| r.source.as_ref());
    let first = sources.next().cloned();
    let mut pinned = Vec::new();
    for (platform, record) in builds {
        let built = record.image.as_ref().map(|i| i.platform.as_str());
        if built != Some(platform.as_str()) {
            problems.push(format!("{platform}: the host built {built:?}"));
        }
        if record.source != first {
            problems.push(format!("{platform}: built from another source"));
        }
        if let (Some(local), Some(source)) = (local_context, &record.source)
            && source.context != local
        {
            problems.push(format!("{platform}: its context is not this one"));
        }
        match record.published.first() {
            Some(p) => pinned.push(p.pinned.clone()),
            None => problems.push(format!("{platform}: nothing was pushed")),
        }
    }
    if problems.is_empty() {
        Ok(pinned)
    } else {
        Err(Error::Runtime(format!(
            "nothing published: {}",
            problems.join("; ")
        )))
    }
}

/// Builds on every host and, if all went well, pushes the index: the record
/// of it all.
pub async fn publish(
    store: &Store,
    p: &Publish,
    creds: Option<&Credentials>,
) -> Result<Record, Error> {
    if p.hosts.is_empty() {
        return Err(Error::Runtime("give at least one --host".to_owned()));
    }
    let stages = p
        .hosts
        .keys()
        .map(|platform| Ok((platform.clone(), staging(&p.target, platform)?)))
        .collect::<Result<BTreeMap<_, _>, Error>>()?;
    let ignore = IgnoreMatcher::from_context_dir(&p.context)?;
    let tmp = tempfile::tempdir()?;
    let packed = tmp.path().join("context.tar");
    pack_context(&p.context, &ignore, &packed)?;

    let builds = futures::future::join_all(p.hosts.iter().map(|(platform, dest)| {
        let packed = &packed;
        let stages = &stages;
        async move {
            let built = build_on(p, platform, dest, packed, &stages[platform]).await;
            (platform.clone(), built)
        }
    }))
    .await;
    let mut records = BTreeMap::new();
    let mut failed = Vec::new();
    for (platform, built) in builds {
        match built {
            Ok(record) => {
                records.insert(platform, record);
            }
            Err(why) => failed.push(format!("{platform}: {why}")),
        }
    }
    if !failed.is_empty() {
        return Err(Error::Runtime(format!(
            "nothing published: {}",
            failed.join("; ")
        )));
    }
    // A client without file modes packs the same context under other modes.
    let local = crate::record::context_digest(&p.context, &ignore)?;
    let local = cfg!(unix).then_some(local.as_str());
    let pinned = check_builds(&records, local)?;

    let digest = store.push_index(&p.target, &pinned, creds).await?;
    let (_, doc) = store.client().document(&p.target, &digest, creds).await?;
    let mut record = Record {
        source: records.values().find_map(|r| r.source.clone()),
        builds: records
            .into_iter()
            .filter_map(|(platform, r)| {
                Some((
                    platform,
                    Build {
                        image: r.image?,
                        bases: r.bases,
                        builder: r.builder,
                    },
                ))
            })
            .collect(),
        ..Record::default()
    };
    let pin = Reference {
        tag: None,
        digest: Some(digest.clone()),
        ..p.target.clone()
    };
    record.pushed_index(
        p.target.to_string(),
        &digest,
        pin.to_string(),
        crate::record::platforms_of(&serde_json::to_value(&doc)?),
    )?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Built, Published, Source};

    fn built(platform: &str, context: &str) -> Record {
        Record {
            image: Some(Built {
                config: "sha256:c".to_owned(),
                manifest: "sha256:m".to_owned(),
                platform: platform.to_owned(),
            }),
            source: Some(Source {
                containerfile: "sha256:f".to_owned(),
                context: context.to_owned(),
            }),
            published: vec![Published {
                reference: "r".to_owned(),
                digest: "sha256:m".to_owned(),
                pinned: format!("r@{platform}"),
                platforms: BTreeMap::new(),
                signature: None,
            }],
            ..Record::default()
        }
    }

    #[test]
    fn words_reach_the_host_as_given() {
        assert_eq!(quoted("a b"), "'a b'");
        assert_eq!(quoted("it's"), r"'it'\''s'");
    }

    #[test]
    fn a_platform_is_staged_beside_the_target() {
        let target = Reference::parse("ghcr.io/me/app:1").unwrap();
        let stage = staging(&target, "freebsd/arm64").unwrap();
        assert_eq!(stage.to_string(), "ghcr.io/me/app:1-freebsd-arm64");
        let digest = format!("ghcr.io/me/app@sha256:{}", "a".repeat(64));
        assert!(staging(&Reference::parse(&digest).unwrap(), "x").is_err());
    }

    #[test]
    fn builds_must_be_their_platforms_and_of_one_source() {
        let good = BTreeMap::from([
            (
                "freebsd/amd64".to_owned(),
                built("freebsd/amd64", "sha256:x"),
            ),
            (
                "freebsd/arm64".to_owned(),
                built("freebsd/arm64", "sha256:x"),
            ),
        ]);
        assert_eq!(check_builds(&good, Some("sha256:x")).unwrap().len(), 2);
        let err = check_builds(&good, Some("sha256:y")).unwrap_err();
        assert!(err.to_string().contains("not this one"), "{err}");

        let mut wrong = good.clone();
        wrong.insert(
            "freebsd/arm64".to_owned(),
            built("freebsd/amd64", "sha256:x"),
        );
        let err = check_builds(&wrong, None).unwrap_err();
        assert!(err.to_string().contains("the host built"), "{err}");

        let mut other = good;
        other.insert(
            "freebsd/arm64".to_owned(),
            built("freebsd/arm64", "sha256:z"),
        );
        let err = check_builds(&other, None).unwrap_err();
        assert!(err.to_string().contains("another source"), "{err}");
    }

    #[test]
    fn a_host_gets_what_it_needs_and_prints_only_its_record() {
        let p = Publish {
            target: Reference::parse("ghcr.io/me/app:1").unwrap(),
            hosts: BTreeMap::new(),
            context: PathBuf::from("."),
            containerfile: Some("build/Containerfile".to_owned()),
            build_stage: Some("final".to_owned()),
            build_args: vec!["V=a b".to_owned()],
            remote_jailer: "/opt/jailer".to_owned(),
            ssh: "ssh".to_owned(),
        };
        let stage = staging(&p.target, "freebsd/amd64").unwrap();
        let s = script(&p, &stage);
        assert!(s.contains("--build-arg 'V=a b'"), "{s}");
        assert!(s.contains("-f 'ctx/build/Containerfile'"), "{s}");
        assert!(s.contains("--target 'final'"), "{s}");
        assert!(s.contains("'ghcr.io/me/app:1-freebsd-amd64' >&2"), "{s}");
        assert!(s.ends_with("cat r.json\n"), "{s}");
    }
}
