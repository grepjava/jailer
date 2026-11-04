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
    /// Things the parser accepted but does not act on.
    pub warnings: Vec<String>,
}

/// A here-document given to `RUN`, `COPY` or `ADD` (`<<EOF ... EOF`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heredoc {
    pub name: String,
    /// The text, without leading tabs for `<<-`.
    pub body: String,
    /// False when the delimiter was quoted: the text is taken as is.
    pub expand: bool,
    /// The lines as written, through the closing delimiter.
    raw: String,
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
        sharing: Sharing,
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
    /// An SSH agent from `build --ssh`, as a socket at `target`.
    Ssh {
        id: String,
        target: String,
        required: bool,
        mode: u32,
        uid: u32,
        gid: u32,
    },
}

/// How builds at the same time use one cache mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sharing {
    /// All of them at once.
    #[default]
    Shared,
    /// One at a time; the others wait.
    Locked,
    /// One; the others get an empty cache of their own.
    Private,
}

impl RunMount {
    /// The mount with build arguments and `ENV` expanded in its names and
    /// paths.
    pub fn expanded(&self, vars: &BTreeMap<String, String>) -> RunMount {
        let x = |s: &String| expand_word(s, vars);
        let mut m = self.clone();
        match &mut m {
            RunMount::Cache { id, target, .. }
            | RunMount::Secret { id, target, .. }
            | RunMount::Ssh { id, target, .. } => {
                *id = x(id);
                *target = x(target);
            }
            RunMount::Bind {
                from,
                source,
                target,
                ..
            } => {
                *from = from.as_ref().map(x);
                *source = x(source);
                *target = x(target);
            }
            RunMount::Tmpfs { target, .. } => *target = x(target),
        }
        m
    }

    pub fn target(&self) -> &str {
        match self {
            RunMount::Cache { target, .. }
            | RunMount::Bind { target, .. }
            | RunMount::Secret { target, .. }
            | RunMount::Tmpfs { target, .. }
            | RunMount::Ssh { target, .. } => target,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopySpec {
    pub from: Option<String>,
    pub chown: Option<String>,
    pub chmod: Option<u32>,
    pub sources: Vec<String>,
    /// Files written from here-documents, named by their delimiters.
    pub heredocs: Vec<Heredoc>,
    pub destination: String,
    /// `--exclude` patterns, matched against paths below each source.
    pub exclude: Vec<String>,
    /// `--parents`: keep each source's path below the destination.
    pub parents: bool,
    /// `ADD --checksum=sha256:...` for a URL source.
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    /// Names, each with its default if given.
    Arg(Vec<(String, Option<String>)>),
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
        let mut warnings = Vec::new();
        let mut escape = '\\';
        for (line_no, key, value) in parser_directives(input) {
            match key.as_str() {
                "escape" => {
                    escape = match value.as_str() {
                        "\\" => '\\',
                        "`" => '`',
                        other => {
                            return Err(Error::Build(format!(
                                "line {line_no}: `# escape={other}`: use \\ or `"
                            )));
                        }
                    }
                }
                "syntax" => warnings.push(format!(
                    "line {line_no}: `# syntax={value}` is ignored: jailer parses the Containerfile itself"
                )),
                _ => {}
            }
        }
        let logical = join_logical_lines(input, escape)?;
        let mut global_args = Vec::new();
        let mut stages: Vec<Stage> = Vec::new();

        for Logical {
            line: line_no,
            text: raw,
            heredocs,
        } in logical
        {
            let Some((verb, rest)) = split_verb(&raw) else {
                continue;
            };
            let verb_upper = verb.to_ascii_uppercase();
            if verb_upper == "FROM" {
                let (platform, from_spec, alias) = parse_from(rest, line_no, escape)?;
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
                    global_args.extend(parse_arg(rest, line_no, escape)?);
                    continue;
                }
                return Err(Error::Build(format!(
                    "line {line_no}: instruction `{verb_upper}` must appear after `FROM`"
                )));
            }
            let instruction = parse_instruction(&verb_upper, rest, line_no, escape, heredocs)?;
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
            warnings,
        })
    }
}

/// Parses a base image's `ONBUILD` trigger, run as if at `line`.
pub fn parse_trigger(trigger: &str, line: usize) -> Result<SpannedInstruction, Error> {
    let (verb, rest) = split_verb(trigger)
        .ok_or_else(|| Error::Build(format!("line {line}: empty ONBUILD trigger")))?;
    if verb.eq_ignore_ascii_case("ONBUILD") {
        return Err(Error::Build(format!(
            "base image's `ONBUILD {trigger}`: ONBUILD cannot be nested"
        )));
    }
    let instruction =
        parse_instruction(&verb.to_ascii_uppercase(), rest, line, '\\', Vec::new())
            .map_err(|e| Error::Build(format!("base image's `ONBUILD {trigger}`: {e}")))?;
    Ok(SpannedInstruction {
        line,
        raw: trigger.to_owned(),
        instruction,
    })
}

/// The `# key=value` lines at the top of the file, before any blank line,
/// comment or instruction, with lowercased keys.
fn parser_directives(input: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let Some((key, value)) = line
            .trim()
            .strip_prefix('#')
            .and_then(|l| l.split_once('='))
        else {
            break;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
            break;
        }
        out.push((idx + 1, key.to_ascii_lowercase(), value.trim().to_owned()));
    }
    out
}

/// One instruction: its first line number, its text with continuation
/// lines joined, and the here-documents that follow it.
struct Logical {
    line: usize,
    text: String,
    heredocs: Vec<Heredoc>,
}

/// Joins lines ending with the escape character, drops comment lines, and
/// reads the bodies of the here-documents `RUN`, `COPY` and `ADD` open.
fn join_logical_lines(input: &str, escape: char) -> Result<Vec<Logical>, Error> {
    let lines: Vec<&str> = input.lines().map(|l| l.trim_end_matches('\r')).collect();
    let mut out = Vec::new();
    let mut current = String::new();
    let mut continued = false;
    let mut start_line = 1usize;
    let mut idx = 0;

    while idx < lines.len() {
        let line = lines[idx];
        idx += 1;
        let trimmed = line.trim();
        // As in Docker: a continued line goes on with the next as it is,
        // its leading space kept, the text before the escape too; comment
        // and blank lines in between are skipped.
        let piece = if continued {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            line.trim_end()
        } else {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            start_line = idx;
            trimmed
        };
        if let Some(without_escape) = piece.strip_suffix(escape) {
            current.push_str(without_escape);
            continued = true;
            continue;
        }
        current.push_str(piece);
        continued = false;
        let text = std::mem::take(&mut current);
        let mut heredocs = Vec::new();
        let verb = text.split_whitespace().next().unwrap_or("");
        if ["RUN", "COPY", "ADD"].contains(&verb.to_ascii_uppercase().as_str()) {
            for (name, strip_tabs, expand) in heredoc_markers(&text) {
                let mut body = String::new();
                let mut raw = String::new();
                loop {
                    let Some(l) = lines.get(idx) else {
                        return Err(Error::Build(format!(
                            "line {start_line}: here-document `{name}` is not closed"
                        )));
                    };
                    idx += 1;
                    raw.push_str(l);
                    raw.push('\n');
                    let l = if strip_tabs {
                        l.trim_start_matches('\t')
                    } else {
                        l
                    };
                    if l == name {
                        break;
                    }
                    body.push_str(l);
                    body.push('\n');
                }
                heredocs.push(Heredoc {
                    name,
                    body,
                    expand,
                    raw,
                });
            }
        }
        out.push(Logical {
            line: start_line,
            text,
            heredocs,
        });
    }
    if !current.is_empty() {
        // Continued at the end of the file: a here-document it opens has
        // no body at all.
        let verb = current.split_whitespace().next().unwrap_or("");
        if ["RUN", "COPY", "ADD"].contains(&verb.to_ascii_uppercase().as_str())
            && let Some((name, ..)) = heredoc_markers(&current).into_iter().next()
        {
            return Err(Error::Build(format!(
                "line {start_line}: here-document `{name}` is not closed"
            )));
        }
        out.push(Logical {
            line: start_line,
            text: current,
            heredocs: Vec::new(),
        });
    }
    Ok(out)
}

/// The here-documents a line opens, in order: words outside quotes of the
/// form `<<NAME`, `<<-NAME`, `<<"NAME"` or `<<'NAME'`, as name, whether
/// leading tabs are stripped, and whether the text is expanded.
fn heredoc_markers(text: &str) -> Vec<(String, bool, bool)> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let chars: Vec<char> = text.chars().collect();
    // Open parentheses of a `$((...))`, where `<<` is a shift.
    let mut arith = 0usize;
    let mut skip = 0;
    for (i, &c) in chars.iter().enumerate() {
        if skip > 0 {
            skip -= 1;
            continue;
        }
        if arith > 0 {
            match c {
                '(' => arith += 1,
                ')' => arith -= 1,
                _ => {}
            }
            continue;
        }
        if quote.is_none() && c == '$' && chars[i + 1..].starts_with(&['(', '(']) {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            arith = 2;
            skip = 2;
            continue;
        }
        // A backslash, but in single quotes, takes the next character as
        // it is: `\"` does not end a quote, and `\<<` starts no document.
        if c == '\\' && quote != Some('\'') {
            word.push(c);
            if let Some(&next) = chars.get(i + 1) {
                word.push(next);
                skip = 1;
            }
            continue;
        }
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            // A word ends at a space or an operator, as in `cat<<EOF>/f`.
            None if c.is_whitespace() || "|;&()>".contains(c) => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
                continue;
            }
            None if c == '<'
                && chars.get(i + 1) == Some(&'<')
                && (i == 0 || chars[i - 1] != '<')
                && !word.is_empty() =>
            {
                words.push(std::mem::take(&mut word));
            }
            None => {}
        }
        word.push(c);
    }
    words.push(word);
    let mut out = Vec::new();
    for w in words {
        let Some(rest) = w.strip_prefix("<<") else {
            continue;
        };
        let (strip_tabs, rest) = match rest.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, rest),
        };
        let (name, expand) = match rest.chars().next() {
            Some(q @ ('"' | '\'')) if rest.len() >= 2 && rest.ends_with(q) => {
                (&rest[1..rest.len() - 1], false)
            }
            _ => (rest, true),
        };
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-./".contains(c))
        {
            out.push((name.to_owned(), strip_tabs, expand));
        }
    }
    out
}

fn split_verb(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    // A word alone is an instruction too, with no arguments: one the parser
    // turns down, as BuildKit does, rather than a line it skips.
    match line.find(char::is_whitespace) {
        Some(idx) => Some((&line[..idx], line[idx..].trim())),
        None => Some((line, "")),
    }
}

fn parse_from(
    rest: &str,
    line_no: usize,
    escape: char,
) -> Result<(Option<String>, String, Option<String>), Error> {
    let tokens = tokenize_words(rest, escape);
    let mut idx = 0;
    let mut platform = None;
    while idx < tokens.len() && tokens[idx].starts_with("--") {
        let flag = &tokens[idx];
        if let Some(p) = flag.strip_prefix("--platform=") {
            platform = Some(p.to_owned());
        } else {
            return Err(Error::Build(format!(
                "line {line_no}: unknown FROM flag `{}`",
                literal_word(flag)
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
        Some(literal_word(&tokens[idx + 1]))
    } else {
        None
    };
    Ok((platform, base, alias))
}

/// `ARG NAME[=default] ...`: one or more names on a line.
fn parse_arg(
    rest: &str,
    line_no: usize,
    escape: char,
) -> Result<Vec<(String, Option<String>)>, Error> {
    let tokens = tokenize_words(rest.trim(), escape);
    if tokens.is_empty() {
        return Err(Error::Build(format!("line {line_no}: empty `ARG`")));
    }
    Ok(tokens
        .into_iter()
        .map(|t| match t.split_once('=') {
            Some((k, v)) => (literal_word(k), Some(v.to_owned())),
            None => (literal_word(&t), None),
        })
        .collect())
}

fn parse_instruction(
    verb: &str,
    rest: &str,
    line_no: usize,
    escape: char,
    heredocs: Vec<Heredoc>,
) -> Result<Instruction, Error> {
    if !heredocs.is_empty() && !matches!(verb, "RUN" | "COPY" | "ADD") {
        return Err(Error::Build(format!(
            "line {line_no}: here-documents are for RUN, COPY and ADD"
        )));
    }
    if rest.is_empty()
        && matches!(
            verb,
            "ARG"
                | "ENV"
                | "LABEL"
                | "WORKDIR"
                | "USER"
                | "COPY"
                | "ADD"
                | "RUN"
                | "CMD"
                | "ENTRYPOINT"
                | "EXPOSE"
                | "VOLUME"
                | "STOPSIGNAL"
                | "HEALTHCHECK"
                | "SHELL"
                | "ONBUILD"
        )
    {
        return Err(Error::Build(format!(
            "line {line_no}: {verb} needs arguments"
        )));
    }
    match verb {
        "ARG" => Ok(Instruction::Arg(parse_arg(rest, line_no, escape)?)),
        "ENV" => Ok(Instruction::Env(parse_key_values(
            rest, line_no, "ENV", escape,
        )?)),
        "LABEL" => Ok(Instruction::Label(parse_key_values(
            rest, line_no, "LABEL", escape,
        )?)),
        "WORKDIR" => Ok(Instruction::Workdir(unquote_word(rest, escape))),
        "USER" => Ok(Instruction::User(unquote_word(rest, escape))),
        "COPY" => Ok(Instruction::Copy(parse_copy(
            rest, line_no, true, escape, heredocs,
        )?)),
        "ADD" => Ok(Instruction::Add(parse_copy(
            rest, line_no, false, escape, heredocs,
        )?)),
        "RUN" => {
            let (opts, command) = parse_run_flags(rest, line_no, escape)?;
            let form = run_heredocs(parse_command_form(command), heredocs, line_no)?;
            Ok(Instruction::Run(form, opts))
        }
        "CMD" => Ok(Instruction::Cmd(parse_command_form(rest))),
        "ENTRYPOINT" => Ok(Instruction::Entrypoint(parse_command_form(rest))),
        "EXPOSE" => Ok(Instruction::Expose(tokenize_words(rest, escape))),
        "VOLUME" => {
            if let Some(arr) = try_parse_json_array(rest) {
                Ok(Instruction::Volume(arr))
            } else {
                Ok(Instruction::Volume(tokenize_words(rest, escape)))
            }
        }
        "STOPSIGNAL" => Ok(Instruction::Stopsignal(unquote_word(rest, escape))),
        "HEALTHCHECK" => Ok(Instruction::Healthcheck(rest.trim().to_owned())),
        "SHELL" => {
            let arr = try_parse_json_array(rest).ok_or_else(|| {
                Error::Build(format!(
                    "line {line_no}: `SHELL` requires a JSON array (e.g. [\"/bin/sh\", \"-c\"])"
                ))
            })?;
            Ok(Instruction::Shell(arr))
        }
        "ONBUILD" => {
            let trigger = rest.trim();
            let Some((inner, inner_rest)) = split_verb(trigger) else {
                return Err(Error::Build(format!(
                    "line {line_no}: `ONBUILD` needs an instruction"
                )));
            };
            let inner = inner.to_ascii_uppercase();
            if matches!(inner.as_str(), "ONBUILD" | "FROM" | "MAINTAINER") {
                return Err(Error::Build(format!(
                    "line {line_no}: `ONBUILD {inner}` is not allowed"
                )));
            }
            parse_instruction(&inner, inner_rest, line_no, escape, Vec::new())?;
            Ok(Instruction::Onbuild(trigger.to_owned()))
        }
        other => Err(Error::Build(format!(
            "line {line_no}: unknown Containerfile instruction `{other}`"
        ))),
    }
}

/// Gives a shell-form `RUN` its here-documents. A command that is only a
/// here-document runs its text, with the interpreter a `#!` line names;
/// otherwise the shell reads the here-documents itself.
fn run_heredocs(
    form: CommandForm,
    heredocs: Vec<Heredoc>,
    line_no: usize,
) -> Result<CommandForm, Error> {
    if heredocs.is_empty() {
        return Ok(form);
    }
    let CommandForm::Shell(cmd) = form else {
        return Err(Error::Build(format!(
            "line {line_no}: here-documents need the shell form of `RUN`"
        )));
    };
    let only = cmd.trim();
    if heredocs.len() == 1 && only.starts_with("<<") && !only.contains(char::is_whitespace) {
        let h = &heredocs[0];
        if let Some(rest) = h.body.strip_prefix("#!") {
            let (interp, script) = rest.split_once('\n').unwrap_or((rest, ""));
            return Ok(CommandForm::Shell(format!(
                "{} <<'{name}'\n{script}{name}\n",
                interp.trim(),
                name = h.name
            )));
        }
        return Ok(CommandForm::Shell(h.body.clone()));
    }
    let mut text = cmd;
    text.push('\n');
    for h in &heredocs {
        text.push_str(&h.raw);
    }
    Ok(CommandForm::Shell(text))
}

/// Splits the first word, a flag, off `rest` at a space outside quotes:
/// the flag with its quotes and escapes taken away, and the rest.
fn split_flag(rest: &str, escape: char) -> (String, &str) {
    let mut quote = None;
    let mut chars = rest.char_indices();
    let mut end = rest.len();
    while let Some((i, c)) = chars.next() {
        match quote {
            Some(q) if c == q => quote = None,
            Some('"') if c == escape => {
                chars.next();
            }
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == escape => {
                chars.next();
            }
            None if c.is_whitespace() => {
                end = i;
                break;
            }
            None => {}
        }
    }
    (unquote_word(&rest[..end], escape), rest[end..].trim_start())
}

/// Splits `--mount=...` and `--network=...` off the front of a `RUN`.
fn parse_run_flags(rest: &str, line_no: usize, escape: char) -> Result<(RunOptions, &str), Error> {
    let mut opts = RunOptions::default();
    let mut rest = rest.trim_start();
    while rest.starts_with("--") {
        let (flag, tail) = split_flag(rest, escape);
        rest = tail;
        let flag = flag.as_str();
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
                "line {line_no}: unsupported RUN flag `{}`",
                literal_word(flag)
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
    let bad = |msg: String| {
        Error::Build(format!(
            "line {line_no}: --mount={}: {msg}",
            literal_word(spec)
        ))
    };
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
        "ssh" => &["type", "target", "id", "required", "mode", "uid", "gid"],
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
                sharing: match kv.get("sharing").copied() {
                    None | Some("shared") => Sharing::Shared,
                    Some("locked") => Sharing::Locked,
                    Some("private") => Sharing::Private,
                    Some(other) => {
                        return Err(bad(format!(
                            "sharing={other}: give shared, locked or private"
                        )));
                    }
                },
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
        "ssh" => RunMount::Ssh {
            id: kv.get("id").copied().unwrap_or("default").to_owned(),
            target: target
                .clone()
                .unwrap_or_else(|| "/run/buildkit/ssh_agent.0".to_owned()),
            required: flag(&kv, "required")?,
            mode: num(&kv, "mode", 8, 0o600)?,
            uid: num(&kv, "uid", 10, 0)?,
            gid: num(&kv, "gid", 10, 0)?,
        },
        _ => RunMount::Tmpfs {
            target: need_target()?,
            size: kv
                .get("size")
                .map(|v| parse_size(v).ok_or_else(|| bad(format!("size={v}"))))
                .transpose()?,
        },
    })
}

/// A size such as `512`, `64k`, `100m` or `10g` (a trailing `b` is allowed).
pub fn parse_size(v: &str) -> Option<u64> {
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

fn parse_copy(
    rest: &str,
    line_no: usize,
    is_copy: bool,
    escape: char,
    heredocs: Vec<Heredoc>,
) -> Result<CopySpec, Error> {
    let what = if is_copy { "COPY" } else { "ADD" };
    let bad = |msg: String| Error::Build(format!("line {line_no}: {what} {msg}"));
    let switch = |flag: &str, v: Option<&str>| match v {
        None | Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(v) => Err(bad(format!("--{flag}={v}: give true or false"))),
    };
    let mut spec = CopySpec {
        from: None,
        chown: None,
        chmod: None,
        sources: Vec::new(),
        heredocs,
        destination: String::new(),
        exclude: Vec::new(),
        parents: false,
        checksum: None,
    };
    let mut rest = rest.trim_start();
    while rest.starts_with("--") {
        let (flag, tail) = split_flag(rest, escape);
        rest = tail;
        let flag = flag.as_str();
        let (name, value) = match flag[2..].split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (&flag[2..], None),
        };
        let need = || {
            value
                .clone()
                .ok_or_else(|| bad(format!("--{name} needs a value")))
        };
        match name {
            "from" if is_copy => spec.from = Some(need()?),
            "chown" => spec.chown = Some(need()?),
            "chmod" => {
                let v = need()?;
                let mode = u32::from_str_radix(&v, 8)
                    .ok()
                    .filter(|m| *m <= 0o7777)
                    .ok_or_else(|| bad(format!("invalid --chmod mode `{}`", literal_word(&v))))?;
                spec.chmod = Some(mode);
            }
            "exclude" => spec.exclude.push(need()?),
            "parents" if is_copy => spec.parents = switch(name, value.as_deref())?,
            // Layers are always rebuilt from content here, so `--link`
            // changes nothing.
            "link" => {
                switch(name, value.as_deref())?;
            }
            "checksum" if !is_copy => {
                let v = need()?;
                // One from a build argument is checked when expanded.
                spec.checksum = Some(if v.contains('$') {
                    v.to_owned()
                } else {
                    checksum(&literal_word(&v)).map_err(bad)?
                });
            }
            _ => {
                return Err(bad(format!("does not support `{}`", literal_word(flag))));
            }
        }
    }

    let mut words = try_parse_json_array(rest).unwrap_or_else(|| tokenize_words(rest, escape));
    // Words naming here-documents stand for the files `spec.heredocs` holds;
    // another word may begin with `<<`, as a quoted `"<<name"`.
    let mut docs: Vec<&str> = spec.heredocs.iter().map(|h| h.name.as_str()).collect();
    words.retain(|w| {
        let name = w
            .strip_prefix("<<")
            .map(|n| n.strip_prefix('-').unwrap_or(n));
        match name.and_then(|n| docs.iter().position(|d| *d == n)) {
            Some(i) => {
                docs.remove(i);
                false
            }
            None => true,
        }
    });
    if words.is_empty() || words.len() + spec.heredocs.len() < 2 {
        return Err(bad(
            "requires at least one source and a destination".to_owned()
        ));
    }
    spec.destination = words.pop().unwrap();
    spec.sources = words;
    Ok(spec)
}

/// An `ADD --checksum` value, checked and in lower case.
pub fn checksum(v: &str) -> Result<String, String> {
    let hex = v.strip_prefix("sha256:").unwrap_or("");
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("--checksum={v}: give sha256:<64 hex digits>"));
    }
    Ok(v.to_ascii_lowercase())
}

fn parse_key_values(
    rest: &str,
    line_no: usize,
    what: &str,
    escape: char,
) -> Result<Vec<(String, String)>, Error> {
    let rest = rest.trim();
    if rest.is_empty() {
        return Err(Error::Build(format!("line {line_no}: empty `{what}`")));
    }
    let tokens = tokenize_words(rest, escape);
    if tokens.first().is_some_and(|t| !t.contains('=')) {
        // Legacy `ENV KEY value with spaces` form
        let Some((k, v)) = split_verb(rest) else {
            return Err(Error::Build(format!(
                "line {line_no}: `{what}` needs a key and value"
            )));
        };
        return Ok(vec![(unquote_word(k, escape), unquote_word(v, escape))]);
    }
    let mut out = Vec::new();
    for tok in tokens {
        let Some((k, v)) = tok.split_once('=') else {
            return Err(Error::Build(format!(
                "line {line_no}: expected KEY=VALUE in `{what}`, got `{}`",
                literal_word(&tok)
            )));
        };
        // The tokens' quotes are already gone: `A="\"x\""` keeps `"x"`.
        out.push((k.to_owned(), v.to_owned()));
    }
    Ok(out)
}

/// Stands for a `$` that is not to expand, escaped or in single quotes,
/// in the words the parser keeps: [`expand_word`] gives it back as `$`. A
/// `\` could not mark it, as a word may hold a real `\` before a `$`.
const LITERAL_DOLLAR: char = '\u{E000}';

/// Splits `s` into words, taking quotes and escapes away; expand them with
/// [`expand_word`].
fn tokenize_words(s: &str, escape: char) -> Vec<String> {
    scan_words(s, escape, true)
}

/// `s` as one word, its quotes and escapes taken away, as `WORKDIR` and
/// the like take it; expand it with [`expand_word`].
fn unquote_word(s: &str, escape: char) -> String {
    scan_words(s.trim(), escape, false)
        .pop()
        .unwrap_or_default()
}

fn scan_words(s: &str, escape: char, split: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars();
    let mut quote: Option<char> = None;
    // A word of quotes alone, as `""`, is a word: an empty one.
    let mut quoted = false;
    let literal = |cur: &mut String, c: char| {
        cur.push(if c == '$' { LITERAL_DOLLAR } else { c });
    };

    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == escape && q == '"' {
                    // As in Docker, only `"`, `$` and the escape itself
                    // are escaped in double quotes: `"\d"` keeps its `\`.
                    match chars.clone().next() {
                        Some(next) if next == '"' || next == '$' || next == escape => {
                            chars.next();
                            literal(&mut cur, next);
                        }
                        _ => cur.push(c),
                    }
                } else if q == '\'' {
                    literal(&mut cur, c);
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                    quoted = true;
                } else if split && c.is_whitespace() {
                    if !cur.is_empty() || quoted {
                        out.push(std::mem::take(&mut cur));
                    }
                    quoted = false;
                } else if c == escape {
                    if let Some(next) = chars.next() {
                        literal(&mut cur, next);
                    }
                } else {
                    cur.push(c);
                }
            }
        }
    }
    if !cur.is_empty() || quoted {
        out.push(cur);
    }
    out
}

/// Expands a word the parser kept (from [`tokenize_words`] and the like):
/// its escapes are gone, so a `\` in it is a character like any other.
pub fn expand_word(word: &str, vars: &BTreeMap<String, String>) -> String {
    expand(word, vars, false).replace(LITERAL_DOLLAR, "$")
}

/// A word the parser kept, as it reads with no variables expanded: for
/// messages, and for words, like stage names, that are not expanded.
pub fn literal_word(word: &str) -> String {
    word.replace(LITERAL_DOLLAR, "$")
}

/// Expands text as written, such as a here-document's: there, as in
/// BuildKit, a `\` escapes the character after it, so `\$` is a `$` that
/// does not expand and `\\` is a `\`.
pub fn expand_vars(input: &str, vars: &BTreeMap<String, String>) -> String {
    expand(input, vars, true)
}

/// Expands `$VAR`, `${VAR}`, `${VAR:-word}`, `${VAR-word}`, `${VAR:+word}`
/// and `${VAR+word}` using `vars`; with `escapes`, a `\` takes the next
/// character as it is.
fn expand(input: &str, vars: &BTreeMap<String, String>, escapes: bool) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut at = 0;
    expand_to(&chars, &mut at, vars, escapes, false)
}

/// Expands `chars` from `at` to their end or, `in_braces`, to the `}`
/// closing a `${`, which is left at `at`. The word of a `${VAR:-word}` is
/// expanded in turn, so it may hold variables, `${...}` among them.
fn expand_to(
    chars: &[char],
    at: &mut usize,
    vars: &BTreeMap<String, String>,
    escapes: bool,
    in_braces: bool,
) -> String {
    let mut out = String::new();
    while let Some(&c) = chars.get(*at) {
        if c == '}' && in_braces {
            return out;
        }
        *at += 1;
        // As in BuildKit's lexer, an escape takes the next character as it
        // is, whatever it is: `\\$A` is a `\` and A's value.
        if escapes && c == '\\' {
            if let Some(&next) = chars.get(*at) {
                out.push(next);
                *at += 1;
            }
            continue;
        }
        if c != '$' {
            out.push(c);
            continue;
        }
        let name_len = |from: usize| {
            chars[from..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                .count()
        };
        if chars.get(*at) != Some(&'{') {
            let n = name_len(*at);
            if n == 0 {
                out.push('$');
            } else {
                let name: String = chars[*at..*at + n].iter().collect();
                *at += n;
                if let Some(val) = vars.get(&name) {
                    out.push_str(val);
                }
            }
            continue;
        }
        *at += 1;
        let n = name_len(*at);
        let name: String = chars[*at..*at + n].iter().collect();
        *at += n;
        let val = vars.get(&name).map(String::as_str);
        let op: String = chars[*at..]
            .iter()
            .take(2)
            .take_while(|c| **c == ':' || **c == '-' || **c == '+')
            .collect();
        let op = match op.as_str() {
            ":-" | ":+" => op,
            o if o.starts_with('-') || o.starts_with('+') => o[..1].to_owned(),
            _ => String::new(),
        };
        *at += op.len();
        let at_close = chars.get(*at) == Some(&'}');
        let word = expand_to(chars, at, vars, escapes, true);
        if chars.get(*at) == Some(&'}') {
            *at += 1;
        }
        let set = val.is_some_and(|v| !v.is_empty());
        let pick = match op.as_str() {
            ":-" if set => val.unwrap_or(""),
            ":-" => word.as_str(),
            "-" => val.unwrap_or(word.as_str()),
            ":+" if set => word.as_str(),
            "+" if val.is_some() => word.as_str(),
            "" if at_close => val.unwrap_or(""),
            // `${A:+...}` unset, or a form not known, as `${A:?msg}`.
            _ => "",
        };
        out.push_str(pick);
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
    /// Begun with `/`: matched from the context's top only.
    anchored: bool,
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
            let pat = pat.replace('\\', "/");
            let anchored = pat.starts_with('/');
            let pat = pat.trim_matches('/');
            if !pat.is_empty() {
                rules.push(IgnoreRule {
                    negated,
                    anchored,
                    pattern: pat.to_owned(),
                });
            }
        }
        Self { rules }
    }

    /// Whether a `!` pattern may take back something below the directory
    /// `dir_rel`, so that a walk must look in it although it is left out.
    pub fn may_reinclude(&self, dir_rel: &str) -> bool {
        let dir = format!("{}/", dir_rel.trim_matches('/').replace('\\', "/"));
        self.rules.iter().filter(|r| r.negated).any(|r| {
            if !r.anchored && !r.pattern.contains('/') {
                return true;
            }
            let fixed = &r.pattern[..r.pattern.find(['*', '?', '[']).unwrap_or(r.pattern.len())];
            fixed.starts_with(&dir) || dir.starts_with(fixed)
        })
    }

    pub fn is_ignored(&self, rel_path: &str) -> bool {
        let rel = rel_path.trim_matches('/').replace('\\', "/");
        if rel.is_empty() {
            return false;
        }
        let mut ignored = false;
        for rule in &self.rules {
            if matches_ignore(rule, &rel) {
                ignored = !rule.negated;
            }
        }
        ignored
    }
}

/// Whether `rule` matches `path` or a directory it is in. A pattern
/// without `/`, unless anchored, matches a name at any depth.
fn matches_ignore(rule: &IgnoreRule, path: &str) -> bool {
    let pattern = rule.pattern.as_str();
    let by_name = !rule.anchored && !pattern.contains('/');
    let mut prefix_end = 0;
    for comp in path.split('/') {
        prefix_end += comp.len();
        if glob_match(pattern, &path[..prefix_end]) || (by_name && glob_match(pattern, comp)) {
            return true;
        }
        prefix_end += 1;
    }
    false
}

pub fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_rec(&p, &t)
}

fn glob_rec(p: &[char], t: &[char]) -> bool {
    match (p.first(), t.first()) {
        (None, None) => true,
        // `**` crosses directories, and `**/` may stand for none.
        (Some('*'), _) if p.get(1) == Some(&'*') => {
            let mut rest = &p[2..];
            while rest.first() == Some(&'*') {
                rest = &rest[1..];
            }
            if rest.first() == Some(&'/') && glob_rec(&rest[1..], t) {
                return true;
            }
            (0..=t.len()).any(|i| glob_rec(rest, &t[i..]))
        }
        // `*` stays within a name.
        (Some('*'), _) => {
            glob_rec(&p[1..], t) || (t.first().is_some_and(|c| *c != '/') && glob_rec(p, &t[1..]))
        }
        (Some('?'), Some(c)) if *c != '/' => glob_rec(&p[1..], &t[1..]),
        (Some('['), Some(c)) if *c != '/' => match glob_class(&p[1..], *c) {
            Some((hit, rest)) => hit && glob_rec(rest, &t[1..]),
            None => *c == '[' && glob_rec(&p[1..], &t[1..]),
        },
        (Some(pc), Some(tc)) if pc == tc => glob_rec(&p[1..], &t[1..]),
        _ => false,
    }
}

/// Matches `c` against a `[...]` class whose text follows the `[`: whether
/// it matched and the pattern after the `]`, or None if the class is not
/// closed.
fn glob_class(p: &[char], c: char) -> Option<(bool, &[char])> {
    let (negated, mut i) = match p.first() {
        Some('^' | '!') => (true, 1),
        _ => (false, 0),
    };
    let mut hit = false;
    let mut first = true;
    while let Some(&lo) = p.get(i) {
        if lo == ']' && !first {
            return Some((hit != negated, &p[i + 1..]));
        }
        first = false;
        if p.get(i + 1) == Some(&'-') && p.get(i + 2).is_some_and(|hi| *hi != ']') {
            hit |= (lo..=p[i + 2]).contains(&c);
            i += 3;
        } else {
            hit |= lo == c;
            i += 1;
        }
    }
    None
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
    fn env_values_keep_quotes_inside_quotes() {
        let cf =
            Containerfile::parse("FROM scratch\nENV A=\"\\\"x\\\"\" B='\"y\"' C=\"a b\" D=plain\n")
                .unwrap();
        let Instruction::Env(kv) = &cf.stages[0].instructions[0].instruction else {
            panic!("not ENV");
        };
        let got: Vec<(&str, &str)> = kv.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        assert_eq!(
            got,
            [("A", "\"x\""), ("B", "\"y\""), ("C", "a b"), ("D", "plain")]
        );
    }

    #[test]
    fn variable_expansion_and_ignore() {
        let vars = BTreeMap::from([("REL".to_owned(), "15.1".to_owned())]);
        assert_eq!(
            expand_vars("freebsd-runtime:${REL}", &vars),
            "freebsd-runtime:15.1"
        );
        assert_eq!(expand_vars("${MISSING:-fallback}", &vars), "fallback");

        // An escaped `$`, or one in single quotes, is not expanded.
        let Instruction::Env(pairs) = parse_instruction(
            "ENV",
            r#"A=\$REL B='$REL' C="\$REL" D="$REL""#,
            1,
            '\\',
            vec![],
        )
        .unwrap() else {
            panic!("not ENV")
        };
        let values: Vec<String> = pairs.iter().map(|(_, v)| expand_word(v, &vars)).collect();
        assert_eq!(values, ["$REL", "$REL", "$REL", "15.1"]);
        // A real backslash before a variable is kept and the variable
        // expands: `\\` is one, and so is `\` when a backtick is the escape.
        let env = |text: &str, escape: char| match parse_instruction("ENV", text, 1, escape, vec![])
            .unwrap()
        {
            Instruction::Env(pairs) => expand_word(&pairs[0].1, &vars),
            other => panic!("{other:?}"),
        };
        assert_eq!(env(r"P=a\\$REL", '\\'), r"a\15.1");
        assert_eq!(env(r"P=C:\$REL", '`'), r"C:\15.1");
        assert_eq!(env(r"P=C:`$REL", '`'), "C:$REL");
        // The legacy form, one value with spaces.
        assert_eq!(env(r"P a\\$REL b", '\\'), r"a\15.1 b");
        let Instruction::Workdir(wd) =
            parse_instruction("WORKDIR", "'/$REL'", 1, '\\', vec![]).unwrap()
        else {
            panic!("not WORKDIR")
        };
        assert_eq!(expand_word(&wd, &vars), "/$REL");

        let ig = IgnoreMatcher::parse("target/\n*.log\n!keep.log\n");
        assert!(ig.is_ignored("target/debug/app"));
        assert!(ig.is_ignored("build.log"));
        assert!(!ig.is_ignored("keep.log"));
        assert!(!ig.is_ignored("src/main.rs"));

        // `/` anchors; `*` stays within a name, `**` does not; a directory
        // matched leaves out what is in it.
        let ig = IgnoreMatcher::parse("/build\na/*.txt\nlogs/**/*.log\nsecret\n");
        assert!(ig.is_ignored("build/out"));
        assert!(!ig.is_ignored("src/build"));
        assert!(ig.is_ignored("a/b.txt"));
        assert!(!ig.is_ignored("a/b/c.txt"));
        assert!(ig.is_ignored("logs/x.log"));
        assert!(ig.is_ignored("logs/1/2/x.log"));
        assert!(ig.is_ignored("deep/secret/key"));

        let ig = IgnoreMatcher::parse("sub\n!sub/keep\n");
        assert!(ig.may_reinclude("sub"));
        assert!(!ig.may_reinclude("other"));
        assert!(!IgnoreMatcher::parse("sub\n").may_reinclude("sub"));
        assert!(IgnoreMatcher::parse("*\n!**/keep\n").may_reinclude("a/b"));
    }

    #[test]
    fn several_args_on_a_line_and_heredocs_next_to_operators() {
        let cf = Containerfile::parse("FROM scratch\nARG A B=\"two words\"\n").unwrap();
        assert_eq!(
            cf.stages[0].instructions[0].instruction,
            Instruction::Arg(vec![
                ("A".to_owned(), None),
                ("B".to_owned(), Some("two words".to_owned())),
            ])
        );
        let names = |t: &str| -> Vec<String> {
            heredoc_markers(t).into_iter().map(|(n, _, _)| n).collect()
        };
        assert_eq!(names("cat<<EOF>/file"), ["EOF"]);
        assert_eq!(names("cat <<A | tr a b && cat <<-'B';"), ["A", "B"]);
        assert!(names("cat <<<word").is_empty());
        // Escaped, neither a quote nor `<<` is what it would be.
        assert!(names(r#"echo "foo \" <<EOF \" bar""#).is_empty());
        assert!(names(r"echo \<<EOF").is_empty());
        assert_eq!(names(r"echo \\ <<EOF"), ["EOF"]);
        assert_eq!(names(r"echo '\' <<EOF"), ["EOF"]);
    }

    #[test]
    fn run_flags() {
        let parse = |s: &str| parse_instruction("RUN", s, 1, '\\', Vec::new());
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
                    sharing: Sharing::Shared,
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
            "--mount=type=nfs,target=/x echo",
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
                copy(&format!("--chmod={v} a /b")).unwrap().chmod,
                Some(want)
            );
        }
        for v in ["", "8", "10000", "u+x"] {
            assert!(copy(&format!("--chmod={v} a /b")).is_err(), "{v}");
        }
    }

    fn copy(rest: &str) -> Result<CopySpec, Error> {
        parse_copy(rest, 1, true, '\\', Vec::new())
    }

    fn only_stage(text: &str) -> Vec<Instruction> {
        let cf = Containerfile::parse(text).unwrap();
        cf.stages[0]
            .instructions
            .iter()
            .map(|i| i.instruction.clone())
            .collect()
    }

    #[test]
    fn copy_flags_and_json_form() {
        let spec = copy("--exclude=*.md --exclude=tmp --parents --link a/./b c /d/").unwrap();
        assert_eq!(spec.exclude, ["*.md", "tmp"]);
        assert!(spec.parents);
        assert_eq!(spec.sources, ["a/./b", "c"]);
        assert_eq!(spec.destination, "/d/");
        let spec = copy(r#"--chown=1:1 ["a b", "/c d/"]"#).unwrap();
        assert_eq!(spec.sources, ["a b"]);
        assert_eq!(spec.destination, "/c d/");
        assert!(copy("--checksum=sha256:00 a /b").is_err());
        assert!(copy("--parents=maybe a /b").is_err());
        let sum = format!("sha256:{}", "A".repeat(64));
        let add = parse_copy(
            &format!("--checksum={sum} https://x/y /z"),
            1,
            false,
            '\\',
            Vec::new(),
        )
        .unwrap();
        assert_eq!(add.checksum, Some(sum.to_ascii_lowercase()));
        // One from a build argument is checked once expanded.
        let add = parse_copy("--checksum=$SUM https://x/y /z", 1, false, '\\', Vec::new());
        assert_eq!(add.unwrap().checksum.as_deref(), Some("$SUM"));
        assert!(parse_copy("--parents a /b", 1, false, '\\', Vec::new()).is_err());
    }

    #[test]
    fn heredocs() {
        let ins = only_stage(
            "FROM scratch
RUN <<EOF
echo one
# not a comment here
EOF
RUN <<-EOT
\techo two
\tEOT
RUN python3 <<'PY' > /out && cat <<A <<B
print(1)
PY
a $x
A
b
B
RUN <<EOF
#!/usr/local/bin/python3
print(3)
EOF
COPY --chmod=600 <<cfg.ini <<\"raw.txt\" /etc/app/
k=$v
cfg.ini
$kept
raw.txt
RUN echo $((1<<2)) \"<<NOT\"
",
        );
        let shell = |i: usize| match &ins[i] {
            Instruction::Run(CommandForm::Shell(s), _) => s.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(shell(0), "echo one\n# not a comment here\n");
        assert_eq!(shell(1), "echo two\n");
        assert_eq!(
            shell(2),
            "python3 <<'PY' > /out && cat <<A <<B\nprint(1)\nPY\na $x\nA\nb\nB\n"
        );
        assert_eq!(shell(3), "/usr/local/bin/python3 <<'EOF'\nprint(3)\nEOF\n");
        let Instruction::Copy(spec) = &ins[4] else {
            panic!("{:?}", ins[4]);
        };
        assert!(spec.sources.is_empty());
        assert_eq!(spec.destination, "/etc/app/");
        let docs: Vec<_> = spec
            .heredocs
            .iter()
            .map(|h| (h.name.as_str(), h.body.as_str(), h.expand))
            .collect();
        assert_eq!(
            docs,
            [("cfg.ini", "k=$v\n", true), ("raw.txt", "$kept\n", false)]
        );
        assert_eq!(shell(5), "echo $((1<<2)) \"<<NOT\"");
        assert!(Containerfile::parse("FROM scratch\nRUN <<EOF\necho\n").is_err());
    }

    #[test]
    fn parser_directives() {
        let cf = Containerfile::parse(
            "# syntax=docker/dockerfile:1
# escape=`
FROM scratch
COPY a\\b `
  c /d
",
        )
        .unwrap();
        assert_eq!(cf.warnings.len(), 1);
        let Instruction::Copy(spec) = &cf.stages[0].instructions[0].instruction else {
            panic!();
        };
        assert_eq!(spec.sources, ["a\\b", "c"]);
        // Directives only count before anything else.
        let cf = Containerfile::parse("\n# escape=`\nFROM scratch\nRUN a \\\n b\n").unwrap();
        assert_eq!(
            cf.stages[0].instructions[0].instruction,
            Instruction::Run(CommandForm::Shell("a  b".into()), RunOptions::default())
        );
        // As in Docker, a line goes on with the next as it is: a word split
        // across lines is one word, and blank and comment lines in between
        // are skipped.
        let cf = Containerfile::parse(
            "FROM scratch\nRUN fetch http://x/lo\\\nng/path \\\n\n# note\n  && done\n",
        )
        .unwrap();
        assert_eq!(
            cf.stages[0].instructions[0].instruction,
            Instruction::Run(
                CommandForm::Shell("fetch http://x/long/path   && done".into()),
                RunOptions::default()
            )
        );
        assert!(Containerfile::parse("# escape=x\nFROM scratch\n").is_err());
    }

    #[test]
    fn onbuild_triggers_are_checked() {
        assert!(Containerfile::parse("FROM scratch\nONBUILD RUN make\n").is_ok());
        for bad in ["ONBUILD ONBUILD RUN x", "ONBUILD FROM x", "ONBUILD BOGUS"] {
            assert!(
                Containerfile::parse(&format!("FROM scratch\n{bad}\n")).is_err(),
                "{bad}"
            );
        }
        assert!(parse_trigger("ONBUILD RUN x", 1).is_err());
        assert_eq!(parse_trigger("COPY . /src", 3).unwrap().raw, "COPY . /src");
    }

    #[test]
    fn ssh_mounts() {
        let mount = |spec: &str| parse_mount(spec, 1);
        assert_eq!(
            mount("type=ssh").unwrap(),
            RunMount::Ssh {
                id: "default".into(),
                target: "/run/buildkit/ssh_agent.0".into(),
                required: false,
                mode: 0o600,
                uid: 0,
                gid: 0,
            }
        );
        let RunMount::Ssh {
            id,
            target,
            required,
            uid,
            ..
        } = mount("type=ssh,id=gh,target=/tmp/a.sock,required,uid=65534").unwrap()
        else {
            panic!();
        };
        assert_eq!(
            (id.as_str(), target.as_str(), required, uid),
            ("gh", "/tmp/a.sock", true, 65534)
        );
        assert!(mount("type=ssh,source=x").is_err());
    }

    #[test]
    fn glob_classes() {
        assert!(glob_match("[ab]*.rs", "a1.rs"));
        assert!(!glob_match("[ab]*.rs", "c1.rs"));
        assert!(glob_match("v[0-9]", "v7"));
        assert!(glob_match("v[!0-9]", "vx"));
        assert!(!glob_match("v[^0-9]", "v1"));
        assert!(glob_match("[]]", "]"));
        assert!(glob_match("a[", "a["));
    }

    #[test]
    fn docker_quoting_and_nested_defaults() {
        let vars = BTreeMap::from([
            ("INNER".to_owned(), "value".to_owned()),
            ("EMPTY".to_owned(), String::new()),
        ]);
        let env = |text: &str| {
            let Instruction::Env(pairs) = parse_instruction("ENV", text, 1, '\\', vec![]).unwrap()
            else {
                panic!("not ENV")
            };
            pairs
                .iter()
                .map(|(k, v)| (expand_word(k, &vars), expand_word(v, &vars)))
                .collect::<Vec<_>>()
        };
        // In double quotes only `"`, `$` and `\` are escaped.
        assert_eq!(env(r#"R="\d+\s" Q="a\"b\\c\$x""#)[0].1, r"\d+\s");
        assert_eq!(env(r#"R="\d+\s" Q="a\"b\\c\$x""#)[1].1, r#"a"b\c$x"#);
        // The word of a default is expanded, `${...}` in it too.
        for (text, want) in [
            ("O=${MISSING:-${INNER}}", "value"),
            ("O=${MISSING:-a${INNER}b}", "avalueb"),
            ("O=${MISSING:-$INNER/x}", "value/x"),
            ("O=${INNER:+[${INNER}]}", "[value]"),
            ("O=${EMPTY:-d}", "d"),
            ("O=${EMPTY-d}", ""),
            ("O=${MISSING-d}", "d"),
            ("O=${EMPTY+set}", "set"),
            ("O=${EMPTY:+set}", ""),
            ("O=${MISSING:-'$INNER'}", "$INNER"),
            ("O=${INNER}}", "value}"),
        ] {
            assert_eq!(env(text)[0].1, want, "{text}");
        }
        assert_eq!(expand_vars(r"${MISSING:-a\$b\}}", &vars), "a$b}");
        // A key is expanded as well; a legacy one has its quotes taken away.
        assert_eq!(env("${INNER}=1")[0].0, "value");
        assert_eq!(
            env("\"my.key\" a b")[0],
            ("my.key".to_owned(), "a b".to_owned())
        );

        // Words nothing expands read with their `$`.
        let cf = Containerfile::parse("FROM scratch AS a\\$b\nSTOPSIGNAL \\$SIGTERM\n").unwrap();
        assert_eq!(cf.stages[0].name.as_deref(), Some("a$b"));
        let report = crate::check::check_containerfile(&cf, None);
        assert!(
            report.findings.iter().any(|f| f
                .message
                .contains("STOPSIGNAL \"$SIGTERM\" is not supported")),
            "{report:?}"
        );
        let err = Containerfile::parse("FROM scratch\nADD --checksum=\\$x http://h/f /f\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("--checksum=$x:"), "{err}");
    }

    #[test]
    fn quoted_flags_and_heredoc_words() {
        let parse = |verb: &str, s: &str| parse_instruction(verb, s, 1, '\\', Vec::new());
        let Instruction::Run(_, opts) = parse(
            "RUN",
            r#"--mount=type=cache,target="/var/cache/pkg",id='$x' --mount="type=tmpfs,target=/a b" true"#,
        )
        .unwrap() else {
            panic!("not RUN")
        };
        let vars = BTreeMap::new();
        let m = opts.mounts[0].expanded(&vars);
        assert_eq!(m.target(), "/var/cache/pkg");
        let RunMount::Cache { id, .. } = m else {
            panic!("not a cache")
        };
        assert_eq!(id, "$x");
        assert_eq!(opts.mounts[1].target(), "/a b");
        let Instruction::Copy(spec) = parse("COPY", r#"--chown="1:2" "<<file" /dst"#).unwrap()
        else {
            panic!("not COPY")
        };
        assert_eq!(spec.chown.as_deref(), Some("1:2"));
        assert_eq!(spec.sources, ["<<file"]);

        // A here-document opened on a line continued at the file's end is
        // not closed.
        let err = Containerfile::parse("FROM scratch\nRUN cat <<EOF \\")
            .unwrap_err()
            .to_string();
        assert!(err.contains("`EOF` is not closed"), "{err}");
    }

    #[test]
    fn heredoc_escapes_empty_words_and_messages() {
        let vars = BTreeMap::from([("A".to_owned(), "x".to_owned())]);
        // As BuildKit expands an unquoted COPY here-document: `\` takes the
        // next character, whatever it is.
        assert_eq!(expand_vars(r"\\$A \$A \q ${A}\", &vars), r"\x $A q x");
        // A word of quotes alone is an empty word.
        assert_eq!(tokenize_words(r#""" /dst"#, '\\'), ["", "/dst"]);
        assert_eq!(tokenize_words(r#"a '' "" b"#, '\\'), ["a", "", "", "b"]);
        assert_eq!(tokenize_words("a  b ", '\\'), ["a", "b"]);
        let Instruction::Copy(spec) =
            parse_instruction("COPY", r#""" /dst"#, 1, '\\', vec![]).unwrap()
        else {
            panic!("not COPY")
        };
        assert_eq!(spec.sources, [""]);
        // A word alone on a line is an instruction with no arguments.
        for (text, want) in [
            ("FROM scratch\nx\n", "unknown Containerfile instruction"),
            ("FROM scratch\nRUN\n", "RUN needs arguments"),
            ("FROM scratch\nRUN \\\n\n", "RUN needs arguments"),
            ("FROM\n", "line 1"),
        ] {
            let err = Containerfile::parse(text).unwrap_err().to_string();
            assert!(err.contains(want), "{text:?}: {err}");
        }
        // An escaped `$` reads as one in messages.
        for (text, want) in [
            (
                "FROM scratch\nCOPY --chmod=\\$x a /b\n",
                "--chmod mode `$x`",
            ),
            ("FROM scratch\nCOPY --nope=\\$x a /b\n", "`--nope=$x`"),
            ("FROM scratch\nLABEL a=1 \\$b\n", "got `$b`"),
        ] {
            let err = Containerfile::parse(text).unwrap_err().to_string();
            assert!(err.contains(want) && !err.contains(LITERAL_DOLLAR), "{err}");
        }
    }
}
