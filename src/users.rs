//! The container's user from the image's `/etc/passwd` and `/etc/group`,
//! read as text: FreeBSD images keep them beside their hashed databases,
//! and Linux images have nothing else. Aligned with `legion-jail`.

/// Who a container's process runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
    /// The primary group first, then those listing the user as a member.
    pub groups: Vec<u32>,
    pub home: String,
}

/// `spec` (`user[:group]`, by name or number, empty for root) against the
/// image's `passwd` and `group` files. A number the image does not know
/// runs with gid 0 and no other groups, as with Docker.
pub fn resolve(spec: &str, passwd: &str, group: &str) -> Result<Account, String> {
    let (user, wanted_group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let user = if user.is_empty() { "0" } else { user };
    let number = user.parse::<u32>().ok();
    let entry = entries(passwd).find(|f| match number {
        Some(uid) => f.get(2).and_then(|u| u.parse().ok()) == Some(uid),
        None => f.first() == Some(&user),
    });
    let (uid, mut gid, name, home) = match entry {
        Some(f) => {
            let id = |i: usize, what: &str| {
                f.get(i)
                    .and_then(|v| v.parse::<u32>().ok())
                    .ok_or_else(|| format!("the image's /etc/passwd: no {what} for {}", f[0]))
            };
            (
                id(2, "uid")?,
                id(3, "gid")?,
                Some(f[0]),
                f.get(5)
                    .filter(|h| !h.is_empty())
                    .unwrap_or(&"/")
                    .to_string(),
            )
        }
        None => match number {
            Some(uid) => (uid, 0, None, "/".to_owned()),
            None => return Err(format!("no user {user:?} in the image")),
        },
    };
    if let Some(g) = wanted_group {
        gid = match g.parse() {
            Ok(n) => n,
            Err(_) => entries(group)
                .find(|f| f.first() == Some(&g))
                .and_then(|f| f.get(2)?.parse().ok())
                .ok_or_else(|| format!("no group {g:?} in the image"))?,
        };
    }
    let mut groups = vec![gid];
    if let Some(name) = name {
        for f in entries(group) {
            let member = f.get(3).is_some_and(|m| m.split(',').any(|m| m == name));
            if let Some(id) = f.get(2).and_then(|g| g.parse().ok())
                && member
                && !groups.contains(&id)
            {
                groups.push(id);
            }
        }
    }
    Ok(Account {
        uid,
        gid,
        groups,
        home,
    })
}

/// The colon-separated fields of each entry, without comments and NIS
/// `+`/`-` lines.
fn entries(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty() && !l.starts_with(['#', '+', '-']))
        .map(|l| l.split(':').collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "\
# comment
root:x:0:0:root:/root:/bin/sh
nginx:x:101:101:nginx:/var/cache/nginx:/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
nohome:x:7:7::
";
    const GROUP: &str = "\
root:x:0:root
wheel:*:0:root
www:*:80:
nginx:x:101:nginx
cache:x:300:www,nginx
tty:x:5
";

    #[test]
    fn users_by_name_and_number() {
        let a = resolve("nginx", PASSWD, GROUP).unwrap();
        assert_eq!(
            (a.uid, a.gid, a.home.as_str()),
            (101, 101, "/var/cache/nginx")
        );
        assert_eq!(a.groups, [101, 300]);
        assert_eq!(resolve("80", PASSWD, GROUP).unwrap().groups, [80, 300]);
        let root = resolve("", PASSWD, GROUP).unwrap();
        assert_eq!((root.uid, root.gid, root.groups), (0, 0, vec![0]));
        assert_eq!(resolve("nohome", PASSWD, GROUP).unwrap().home, "/");
    }

    #[test]
    fn groups_given() {
        let a = resolve("nginx:cache", PASSWD, GROUP).unwrap();
        assert_eq!((a.gid, a.groups), (300, vec![300, 101]));
        assert_eq!(resolve("www:5", PASSWD, GROUP).unwrap().gid, 5);
        let e = resolve("www:nope", PASSWD, GROUP).unwrap_err();
        assert!(e.contains("no group \"nope\""), "{e}");
    }
}
