//! Parser and variable expander for `Containerfile` / `Dockerfile` and
//! `.containerignore` / `.dockerignore`.

use std::collections::BTreeMap;
use std::path::Path;

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Containerfile {
    /// `ARG` instructions before the first `FROM`.
    pub global_args: Vec<(String, Option<String>)>,
    pub stages: Vec<Stage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    pub index: usize,
    pub name: Option<String>,
    pub base: String,
    pub platform: Option<String>,
    pub line: usize,
    pub instructions: Vec<SpannedInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpannedInstruction {
    pub line: usize,
    pub raw: String,
    pub instruction: Instruction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandForm {
    Shell(String),
    Exec(Vec<String>),
}

impl CommandForm {
    pub fn to_argv(&self, shell: &[String]) -> Vec<String> {
        match self {
            CommandForm::Exec(v) => v.clone(),
            CommandForm::Shell(s) => {
                let mut out = if shell.is_empty() {
                    vec!["/bin/sh".to_owned(), "-c".to_owned()]
                } else {
                    shell.to_vec()
                };
                out.push(s.clone());
                out
            }
        }
    }
}

/// `RUN` flags: `--mount=...` (repeatable) and `--network=...`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOptions {
    pub mounts: Vec<RunMount>,
    /// `--network=none` runs the step without network.
    pub no_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunMount {
    /// A directory kept between builds, never part of a layer.
    Cache {
        id: String,
        target: String,
        read_only: bool,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    /// The build context, or an earlier stage with `from`; read-only unless
    /// `rw`, whose writes are discarded.
    Bind {
        from: Option<String>,
        source: String,
        target: String,
        rw: bool,
    },
    /// A file from `build --secret`, never part of a layer.
    Secret {
        id: String,
        target: String,
        required: bool,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    Tmpfs {
        target: String,
        size: Option<u64>,
    },
}

impl RunMount {
    pub fn target(&self) -> &str {
        match self {
            RunMount::Cache { target, .. }
            | RunMount::Bind { target, .. }
            | RunMount::Secret { target, .. }
            | RunMount::Tmpfs { target, .. } => target,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopySpec {
    pub from: Option<String>,
    pub chown: Option<String>,
    pub chmod: Option<u32>,
    pub sources: Vec<String>,
    pub destination: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    Arg {
        name: String,
        default: Option<String>,
    },
    Env(Vec<(String, String)>),
    Workdir(String),
    User(String),
    Copy(CopySpec),
    Add(CopySpec),
    Run(CommandForm, RunOptions),
    Cmd(CommandForm),
    Entrypoint(CommandForm),
    Label(Vec<(String, String)>),
    Expose(Vec<String>),
    Volume(Vec<String>),
    Stopsignal(String),
    Healthcheck(String),
    Shell(Vec<String>),
    Onbuild(String),
}

impl Containerfile {
    pub fn parse_file(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Build(format!("reading {}: {e}", path.display())))?;
        Self::parse(&text)
    }

    pub fn parse(input: &str) -> Result<Self, Error> {
        let logical = join_logical_lines(input);
        let mut global_args = Vec::new();
        let mut stages: Vec<Stage> = Vec::new();

        for (line_no, raw) in logical {
            let Some((verb, rest)) = split_verb(&raw) else {
                continue;
            };
            let verb_upper = verb.to_ascii_uppercase();
            if verb_upper == "FROM" {
                let (platform, from_spec, alias) = parse_from(rest, line_no)?;
                let idx = stages.len();
                stages.push(Stage {
                    index: idx,
                    name: alias,
                    base: from_spec,
                    platform,
                    line: line_no,
                    instructions: Vec::new(),
                });
                continue;
            }
            if stages.is_empty() {
                if verb_upper == "ARG" {
                    let (k, v) = parse_arg(rest, line_no)?;
                    global_args.push((k, v));
                    continue;
                }
                return Err(Error::Build(format!(
                    "line {line_no}: instruction `{verb_upper}` must appear after `FROM`"
                )));
            }
            let instruction = parse_instruction(&verb_upper, rest, line_no)?;
            stages
                .last_mut()
                .expect("stage")
                .instructions
                .push(SpannedInstruction {
                    line: line_no,
                    raw,
                    instruction,
                });
        }

        if stages.is_empty() {
            return Err(Error::Build(
                "Containerfile has no `FROM` instruction".to_owned(),
            ));
        }

        Ok(Self {
            global_args,
            stages,
        })
    }
}

/// Joins lines ending with `\` while tracking the starting line number (1-based)
/// and stripping comment lines.
fn join_logical_lines(input: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut start_line = 1usize;

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim();
        if current.is_empty() {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            start_line = line_no;
        } else if trimmed.starts_with('#') {
            // Comment line inside a multi-line continuation is skipped.
            continue;
        }
        if let Some(without_bs) = line.trim_end().strip_suffix('\\') {
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(without_bs.trim());
        } else {
            if !current.is_empty() {
                current.push(' ');
                current.push_str(trimmed);
                out.push((start_line, std::mem::take(&mut current)));
            } else {
                out.push((start_line, trimmed.to_owned()));
            }
        }
    }
    if !current.is_empty() {
        out.push((start_line, current));
    }
    out
}

fn split_verb(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let idx = line.find(char::is_whitespace)?;
    Some((&line[..idx], line[idx..].trim()))
}

fn parse_from(
    rest: &str,
    line_no: usize,
) -> Result<(Option<String>, String, Option<String>), Error> {
    let tokens = tokenize_words(rest);
    let mut idx = 0;
    let mut platform = None;
    while idx < tokens.len() && tokens[idx].starts_with("--") {
        let flag = &tokens[idx];
        if let Some(p) = flag.strip_prefix("--platform=") {
            platform = Some(p.to_owned());
        } else {
            return Err(Error::Build(format!(
                "line {line_no}: unknown FROM flag `{flag}`"
            )));
        }
        idx += 1;
    }
    let Some(base) = tokens.get(idx).cloned() else {
        return Err(Error::Build(format!(
            "line {line_no}: `FROM` needs an image"
        )));
    };
    idx += 1;
    let alias = if idx < tokens.len() {
        if !tokens[idx].eq_ignore_ascii_case("AS") || idx + 1 >= tokens.len() {
            return Err(Error::Build(format!(
                "line {line_no}: expected `AS <name>` in `FROM`"
            )));
        }
        Some(tokens[idx + 1].clone())
    } else {
        None
    };
    Ok((platform, base, alias))
}

fn parse_arg(rest: &str, line_no: usize) -> Result<(String, Option<String>), Error> {
    let rest = rest.trim();
    if rest.is_empty() {
        return Err(Error::Build(format!("line {line_no}: empty `ARG`")));
    }
    match rest.split_once('=') {
        Some((k, v)) => Ok((k.trim().to_owned(), Some(unquote(v.trim())))),
        None => Ok((rest.to_owned(), None)),
    }
}

fn parse_instruction(verb: &str, rest: &str, line_no: usize) -> Result<Instruction, Error> {
    match verb {
        "ARG" => {
            let (name, default) = parse_arg(rest, line_no)?;
            Ok(Instruction::Arg { name, default })
        }
        "ENV" => Ok(Instruction::Env(parse_key_values(rest, line_no, "ENV")?)),
        "LABEL" => Ok(Instruction::Label(parse_key_values(
            rest, line_no, "LABEL",
        )?)),
        "WORKDIR" => Ok(Instruction::Workdir(unquote(rest.trim()))),
        "USER" => Ok(Instruction::User(unquote(rest.trim()))),
        "COPY" => Ok(Instruction::Copy(parse_copy(rest, line_no, true)?)),
        "ADD" => Ok(Instruction::Add(parse_copy(rest, line_no, false)?)),
        "RUN" => {
            let (opts, command) = parse_run_flags(rest, line_no)?;
            Ok(Instruction::Run(parse_command_form(command), opts))
        }
        "CMD" => Ok(Instruction::Cmd(parse_command_form(rest))),
        "ENTRYPOINT" => Ok(Instruction::Entrypoint(parse_command_form(rest))),
        "EXPOSE" => Ok(Instruction::Expose(tokenize_words(rest))),
        "VOLUME" => {
            if let Some(arr) = try_parse_json_array(rest) {
                Ok(Instruction::Volume(arr))
            } else {
                Ok(Instruction::Volume(tokenize_words(rest)))
            }
        }
        "STOPSIGNAL" => Ok(Instruction::Stopsignal(unquote(rest.trim()))),
        "HEALTHCHECK" => Ok(Instruction::Healthcheck(rest.trim().to_owned())),
        "SHELL" => {
            let arr = try_parse_json_array(rest).ok_or_else(|| {
                Error::Build(format!(
                    "line {line_no}: `SHELL` requires a JSON array (e.g. [\"/bin/sh\", \"-c\"])"
                ))
            })?;
            Ok(Instruction::Shell(arr))
        }
        "ONBUILD" => Ok(Instruction::Onbuild(rest.trim().to_owned())),
        other => Err(Error::Build(format!(
            "line {line_no}: unknown Containerfile instruction `{other}`"
        ))),
    }
}

/// Splits `--mount=...` and `--network=...` off the front of a `RUN`.
fn parse_run_flags(rest: &str, line_no: usize) -> Result<(RunOptions, &str), Error> {
    let mut opts = RunOptions::default();
    let mut rest = rest.trim_start();
    while rest.starts_with("--") {
        let (flag, tail) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        rest = tail.trim_start();
        if let Some(spec) = flag.strip_prefix("--mount=") {
            opts.mounts.push(parse_mount(spec, line_no)?);
        } else if let Some(net) = flag.strip_prefix("--network=") {
            opts.no_network = match net {
                "none" => true,
                "default" | "host" => false,
                other => {
                    return Err(Error::Build(format!(
                        "line {line_no}: --network={other}: use none, default or host"
                    )));
                }
            };
        } else {
            return Err(Error::Build(format!(
                "line {line_no}: unsupported RUN flag `{flag}`"
            )));
        }
    }
    if rest.is_empty() {
        return Err(Error::Build(format!(
            "line {line_no}: `RUN` needs a command"
        )));
    }
    Ok((opts, rest))
}

fn parse_mount(spec: &str, line_no: usize) -> Result<RunMount, Error> {
    let bad = |msg: String| Error::Build(format!("line {line_no}: --mount={spec}: {msg}"));
    let mut kv: BTreeMap<&str, &str> = BTreeMap::new();
    for part in spec.split(',').filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=').unwrap_or((part, "true"));
        let k = match k {
            "dst" | "destination" => "target",
            "src" => "source",
            "readonly" => "ro",
            "readwrite" => "rw",
            k => k,
        };
        if kv.insert(k, v).is_some() {
            return Err(bad(format!("`{k}` given twice")));
        }
    }
    let flag = |kv: &BTreeMap<&str, &str>, k: &str| -> Result<bool, Error> {
        match kv.get(k).copied() {
            None | Some("false") => Ok(false),
            Some("true") => Ok(true),
            Some(v) => Err(bad(format!("`{k}={v}`: give true or false"))),
        }
    };
    let num = |kv: &BTreeMap<&str, &str>, k: &str, radix: u32, def: u32| -> Result<u32, Error> {
        kv.get(k).map_or(Ok(def), |v| {
            u32::from_str_radix(v, radix).map_err(|_| bad(format!("`{k}={v}` is not a number")))
        })
    };
    let target = kv.get("target").map(|t| (*t).to_owned());
    let need_target = || {
        target
            .clone()
            .ok_or_else(|| bad("give target=<path in the container>".to_owned()))
    };
    let kind = kv.get("type").copied().unwrap_or("bind");
    let allowed: &[&str] = match kind {
        "cache" => &[
            "type", "target", "id", "ro", "sharing", "mode", "uid", "gid",
        ],
        "bind" => &["type", "target", "source", "from", "rw", "ro"],
        "secret" => &["type", "target", "id", "required", "mode", "uid", "gid"],
        "tmpfs" => &["type", "target", "size"],
        other => return Err(bad(format!("type={other} is not supported"))),
    };
    if let Some(k) = kv.keys().find(|k| !allowed.contains(k)) {
        return Err(bad(format!("`{k}` does not apply to type={kind}")));
    }
    Ok(match kind {
        "cache" => {
            let target = need_target()?;
            RunMount::Cache {
                id: kv
                    .get("id")
                    .map_or_else(|| target.clone(), |v| (*v).to_owned()),
                target,
                read_only: flag(&kv, "ro")?,
                mode: num(&kv, "mode", 8, 0o755)?,
                uid: num(&kv, "uid", 10, 0)?,
                gid: num(&kv, "gid", 10, 0)?,
            }
        }
        "bind" => RunMount::Bind {
            from: kv.get("from").map(|v| (*v).to_owned()),
            source: kv
                .get("source")
                .map_or_else(|| ".".to_owned(), |v| (*v).to_owned()),
            target: need_target()?,
            rw: flag(&kv, "rw")?,
        },
        "secret" => {
            let id = kv
                .get("id")
                .map(|v| (*v).to_owned())
                .or_else(|| {
                    target
                        .as_deref()
                        .and_then(|t| t.rsplit('/').next())
                        .map(str::to_owned)
                })
                .ok_or_else(|| bad("give id=<secret id>".to_owned()))?;
            RunMount::Secret {
                target: target
                    .clone()
                    .unwrap_or_else(|| format!("/run/secrets/{id}")),
                id,
                required: flag(&kv, "required")?,
                mode: num(&kv, "mode", 8, 0o400)?,
                uid: num(&kv, "uid", 10, 0)?,
                gid: num(&kv, "gid", 10, 0)?,
            }
        }
        _ => RunMount::Tmpfs {
            target: need_target()?,
            size: kv
                .get("size")
                .map(|v| parse_size(v).ok_or_else(|| bad(format!("size={v}"))))
                .transpose()?,
        },
    })
}

/// `1024`, `64k`, `512m`, `2g` (optionally with a trailing `b`) in bytes.
fn parse_size(v: &str) -> Option<u64> {
    let lower = v.to_ascii_lowercase();
    let s = lower.strip_suffix('b').unwrap_or(&lower);
    let (num, mult) = match s.chars().last()? {
        'k' => (&s[..s.len() - 1], 1u64 << 10),
        'm' => (&s[..s.len() - 1], 1 << 20),
        'g' => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

fn parse_command_form(rest: &str) -> CommandForm {
    if let Some(arr) = try_parse_json_array(rest) {
        CommandForm::Exec(arr)
    } else {
        CommandForm::Shell(rest.trim().to_owned())
    }
}

fn try_parse_json_array(s: &str) -> Option<Vec<String>> {
    let s = s.trim();
    if s.starts_with('[') && s.ends_with(']') {
        serde_json::from_str::<Vec<String>>(s).ok()
    } else {
        None
    }
}

fn parse_copy(rest: &str, line_no: usize, allow_from: bool) -> Result<CopySpec, Error> {
    let mut tokens = tokenize_words(rest);
    let mut from = None;
    let mut chown = None;
    let mut chmod = None;

    while tokens.first().is_some_and(|t| t.starts_with("--")) {
        let flag = tokens.remove(0);
        if allow_from && let Some(v) = flag.strip_prefix("--from=") {
            from = Some(v.to_owned());
        } else if let Some(v) = flag.strip_prefix("--chown=") {
            chown = Some(v.to_owned());
        } else if let Some(v) = flag.strip_prefix("--chmod=") {
            let mode = u32::from_str_radix(v, 8)
                .ok()
                .filter(|m| *m <= 0o7777)
                .ok_or_else(|| {
                    Error::Build(format!("line {line_no}: invalid --chmod mode `{v}`"))
                })?;
            chmod = Some(mode);
        } else {
            return Err(Error::Build(format!(
                "line {line_no}: unsupported flag `{flag}`"
            )));
        }
    }

    if tokens.len() < 2 {
        return Err(Error::Build(format!(
            "line {line_no}: requires at least one source and a destination"
        )));
    }
    let destination = tokens.pop().unwrap();
    Ok(CopySpec {
        from,
        chown,
        chmod,
        sources: tokens,
        destination,
    })
}

fn parse_key_values(
    rest: &str,
    line_no: usize,
    what: &str,
) -> Result<Vec<(String, String)>, Error> {
    let rest = rest.trim();
    if rest.is_empty() {
        return Err(Error::Build(format!("line {line_no}: empty `{what}`")));
    }
    let tokens = tokenize_words(rest);
    if tokens.first().is_some_and(|t| !t.contains('=')) {
        // Legacy `ENV KEY value with spaces` form
        let Some((k, v)) = split_verb(rest) else {
            return Err(Error::Build(format!(
                "line {line_no}: `{what}` needs a key and value"
            )));
        };
        return Ok(vec![(k.to_owned(), unquote(v))]);
    }
    let mut out = Vec::new();
    for tok in tokens {
        let Some((k, v)) = tok.split_once('=') else {
            return Err(Error::Build(format!(
                "line {line_no}: expected KEY=VALUE in `{what}`, got `{tok}`"
            )));
        };
        out.push((k.to_owned(), unquote(v)));
    }
    Ok(out)
}

fn tokenize_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' {
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                } else if c.is_whitespace() {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                } else if c == '\\' {
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                } else {
                    cur.push(c);
                }
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_owned()
    } else {
        s.to_owned()
    }
}

/// Expands `$VAR`, `${VAR}`, `${VAR:-default}`, and `${VAR:+alt}` using `vars`.
pub fn expand_vars(input: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'$') {
            out.push(chars.next().unwrap());
            continue;
        }
        if c != '$' {
            out.push(c);
            continue;
        }
        if chars.peek() == Some(&'{') {
            chars.next();
            let mut expr = String::new();
            while let Some(&nc) = chars.peek() {
                chars.next();
                if nc == '}' {
                    break;
                }
                expr.push(nc);
            }
            if let Some((name, def)) = expr.split_once(":-") {
                let val = vars.get(name).map(String::as_str).unwrap_or("");
                out.push_str(if val.is_empty() { def } else { val });
            } else if let Some((name, alt)) = expr.split_once(":+") {
                let val = vars.get(name).map(String::as_str).unwrap_or("");
                if !val.is_empty() {
                    out.push_str(alt);
                }
            } else if let Some(val) = vars.get(&expr) {
                out.push_str(val);
            }
        } else {
            let mut name = String::new();
            while let Some(&nc) = chars.peek() {
                if nc.is_ascii_alphanumeric() || nc == '_' {
                    name.push(nc);
                    chars.next();
                } else {
                    break;
                }
            }
            if name.is_empty() {
                out.push('$');
            } else if let Some(val) = vars.get(&name) {
                out.push_str(val);
            }
        }
    }
    out
}

/// Rules loaded from `.containerignore` or `.dockerignore`.
#[derive(Debug, Clone, Default)]
pub struct IgnoreMatcher {
    rules: Vec<IgnoreRule>,
}

#[derive(Debug, Clone)]
struct IgnoreRule {
    negated: bool,
    pattern: String,
}

impl IgnoreMatcher {
    pub fn from_context_dir(dir: &Path) -> Self {
        for name in [".containerignore", ".dockerignore"] {
            let p = dir.join(name);
            if let Ok(text) = std::fs::read_to_string(&p) {
                return Self::parse(&text);
            }
        }
        Self::default()
    }

    pub fn parse(text: &str) -> Self {
        let mut rules = Vec::new();
        for line in text.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let (negated, pat) = match t.strip_prefix('!') {
                Some(rest) => (true, rest.trim()),
                None => (false, t),
            };
            let pat = pat.trim_matches('/').replace('\\', "/");
            if !pat.is_empty() {
                rules.push(IgnoreRule {
                    negated,
                    pattern: pat,
                });
            }
        }
        Self { rules }
    }

    pub fn is_ignored(&self, rel_path: &str) -> bool {
        let rel = rel_path.trim_matches('/').replace('\\', "/");
        if rel.is_empty() {
            return false;
        }
        let mut ignored = false;
        for rule in &self.rules {
            if matches_ignore(&rule.pattern, &rel) {
                ignored = !rule.negated;
            }
        }
        ignored
    }
}

fn matches_ignore(pattern: &str, path: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }
    if path == pattern || path.starts_with(&format!("{pattern}/")) {
        return true;
    }
    // Match basename if pattern has no `/`
    if !pattern.contains('/') {
        let base = path.rsplit('/').next().unwrap_or(path);
        if glob_match(pattern, base) {
            return true;
        }
    }
    glob_match(pattern, path)
}

pub fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_rec(&p, &t)
}

fn glob_rec(p: &[char], t: &[char]) -> bool {
    match (p.first(), t.first()) {
        (None, None) => true,
        (Some('*'), _) => glob_rec(&p[1..], t) || (!t.is_empty() && glob_rec(p, &t[1..])),
        (Some('?'), Some(c)) if *c != '/' => glob_rec(&p[1..], &t[1..]),
        (Some(pc), Some(tc)) if pc == tc => glob_rec(&p[1..], &t[1..]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multistage_and_continuations() {
        let cf = Containerfile::parse(
            r#"
ARG RELEASE=15.1
FROM docker.io/freebsd/freebsd-notoolchain:${RELEASE} AS builder
WORKDIR /src
COPY . .
RUN env ASSUME_ALWAYS_YES=yes pkg bootstrap -f \
 && pkg install -y ca_root_nss

FROM docker.io/freebsd/freebsd-runtime:${RELEASE}
COPY --from=builder --chown=nobody:nobody /src/app /usr/local/bin/app
USER nobody
ENTRYPOINT ["/usr/local/bin/app"]
CMD ["--serve"]
"#,
        )
        .unwrap();
        assert_eq!(cf.global_args.len(), 1);
        assert_eq!(cf.stages.len(), 2);
        assert_eq!(cf.stages[0].name.as_deref(), Some("builder"));
        assert_eq!(cf.stages[0].instructions.len(), 3);
        assert_eq!(cf.stages[1].instructions.len(), 4);
    }

    #[test]
    fn variable_expansion_and_ignore() {
        let vars = BTreeMap::from([("REL".to_owned(), "15.1".to_owned())]);
        assert_eq!(
            expand_vars("freebsd-runtime:${REL}", &vars),
            "freebsd-runtime:15.1"
        );
        assert_eq!(expand_vars("${MISSING:-fallback}", &vars), "fallback");

        let ig = IgnoreMatcher::parse("target/\n*.log\n!keep.log\n");
        assert!(ig.is_ignored("target/debug/app"));
        assert!(ig.is_ignored("build.log"));
        assert!(!ig.is_ignored("keep.log"));
        assert!(!ig.is_ignored("src/main.rs"));
    }

    #[test]
    fn run_flags() {
        let parse = |s: &str| parse_instruction("RUN", s, 1);
        let Instruction::Run(CommandForm::Shell(cmd), opts) = parse(
            "--mount=type=cache,target=/var/cache/pkg --mount=type=secret,id=tok \
             --mount=type=bind,from=builder,source=/out,target=/in,rw \
             --mount=type=tmpfs,dst=/scratch,size=64m --network=none pkg install -y curl",
        )
        .unwrap() else {
            panic!("not a shell-form RUN")
        };
        assert_eq!(cmd, "pkg install -y curl");
        assert!(opts.no_network);
        assert_eq!(
            opts.mounts,
            [
                RunMount::Cache {
                    id: "/var/cache/pkg".to_owned(),
                    target: "/var/cache/pkg".to_owned(),
                    read_only: false,
                    mode: 0o755,
                    uid: 0,
                    gid: 0,
                },
                RunMount::Secret {
                    id: "tok".to_owned(),
                    target: "/run/secrets/tok".to_owned(),
                    required: false,
                    mode: 0o400,
                    uid: 0,
                    gid: 0,
                },
                RunMount::Bind {
                    from: Some("builder".to_owned()),
                    source: "/out".to_owned(),
                    target: "/in".to_owned(),
                    rw: true,
                },
                RunMount::Tmpfs {
                    target: "/scratch".to_owned(),
                    size: Some(64 << 20),
                },
            ]
        );
        let Instruction::Run(CommandForm::Exec(argv), _) =
            parse("--network=host [\"/bin/echo\", \"hi\"]").unwrap()
        else {
            panic!("not an exec-form RUN")
        };
        assert_eq!(argv, ["/bin/echo", "hi"]);

        for bad in [
            "--mount=type=cache echo",
            "--mount=type=ssh,target=/x echo",
            "--mount=type=tmpfs,target=/x,from=a echo",
            "--mount=type=cache,target=/x,ro=maybe echo",
            "--network=bridge echo",
            "--privileged echo",
            "--mount=type=tmpfs,target=/x",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn chmod_modes() {
        for (v, want) in [("0", 0), ("0000", 0), ("755", 0o755), ("04755", 0o4755)] {
            assert_eq!(
                parse_copy(&format!("--chmod={v} a /b"), 1, true)
                    .unwrap()
                    .chmod,
                Some(want)
            );
        }
        for v in ["", "8", "10000", "u+x"] {
            assert!(
                parse_copy(&format!("--chmod={v} a /b"), 1, true).is_err(),
                "{v}"
            );
        }
    }
}
