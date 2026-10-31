//! A container's output as the supervisor keeps it: one record per line,
//! `<seconds>.<nanos> <stdout|stderr> <F|P> <text>`, matching `legion-jail`.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;

const PIECE: usize = 16 << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub stream: Output,
    pub data: Bytes,
}

pub struct Writer {
    path: PathBuf,
    file: File,
    size: u64,
    max: u64,
    partial: [Vec<u8>; 2],
}

fn index(stream: Output) -> usize {
    match stream {
        Output::Stdout => 0,
        Output::Stderr => 1,
    }
}

fn name(stream: Output) -> &'static str {
    match stream {
        Output::Stdout => "stdout",
        Output::Stderr => "stderr",
    }
}

impl Writer {
    pub fn open(path: &Path, max: u64) -> std::io::Result<Writer> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        Ok(Writer {
            path: path.to_owned(),
            file,
            size,
            max,
            partial: [Vec::new(), Vec::new()],
        })
    }

    pub fn write(&mut self, stream: Output, mut data: &[u8]) -> std::io::Result<()> {
        while let Some(nl) = data.iter().position(|b| *b == b'\n') {
            let mut line = std::mem::take(&mut self.partial[index(stream)]);
            line.extend_from_slice(&data[..nl]);
            self.record(stream, true, &line)?;
            data = &data[nl + 1..];
        }
        let held = &mut self.partial[index(stream)];
        held.extend_from_slice(data);
        if held.len() >= PIECE {
            let piece = std::mem::take(held);
            self.record(stream, false, &piece)?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        for stream in [Output::Stdout, Output::Stderr] {
            let piece = std::mem::take(&mut self.partial[index(stream)]);
            if !piece.is_empty() {
                self.record(stream, false, &piece)?;
            }
        }
        self.file.flush()
    }

    fn record(&mut self, stream: Output, full: bool, text: &[u8]) -> std::io::Result<()> {
        if self.size >= self.max {
            self.rotate()?;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut line = format!(
            "{}.{:09} {} {} ",
            now.as_secs(),
            now.subsec_nanos(),
            name(stream),
            if full { 'F' } else { 'P' }
        )
        .into_bytes();
        line.extend_from_slice(text);
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.size += line.len() as u64;
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.file.flush()?;
        std::fs::rename(&self.path, rotated(&self.path))?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

pub fn rotated(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".1");
    PathBuf::from(p)
}

pub fn parse(line: &[u8]) -> Option<Chunk> {
    let mut parts = line.splitn(4, |b| *b == b' ');
    let _time = parts.next()?;
    let stream = match parts.next()? {
        b"stdout" => Output::Stdout,
        b"stderr" => Output::Stderr,
        _ => return None,
    };
    let full = match parts.next()? {
        b"F" => true,
        b"P" => false,
        _ => return None,
    };
    let mut data = parts.next()?.to_vec();
    if full {
        data.push(b'\n');
    }
    Some(Chunk {
        stream,
        data: Bytes::from(data),
    })
}

pub fn read_from(path: &Path, offset: u64) -> std::io::Result<(Vec<Chunk>, u64)> {
    use std::io::{Seek, SeekFrom};
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), offset)),
        Err(e) => return Err(e),
    };
    file.seek(SeekFrom::Start(offset))?;
    let mut reader = BufReader::new(file);
    let mut out = Vec::new();
    let mut at = offset;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 || line.last() != Some(&b'\n') {
            break;
        }
        at += n as u64;
        line.pop();
        out.extend(parse(&line));
    }
    Ok((out, at))
}

pub fn read_all(path: &Path, tail: Option<usize>) -> std::io::Result<Vec<Chunk>> {
    let (mut chunks, _) = read_from(&rotated(path), 0)?;
    chunks.extend(read_from(path, 0)?.0);
    if let Some(n) = tail {
        let mut ends = 0;
        let mut start = chunks.len();
        for (i, c) in chunks.iter().enumerate().rev() {
            if c.data.ends_with(b"\n") {
                ends += 1;
                if ends > n {
                    break;
                }
            }
            start = i;
        }
        chunks.drain(..start);
    }
    Ok(chunks)
}
