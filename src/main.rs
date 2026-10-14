//! ULZEXE — restores DOS executables compressed with LZEXE 0.90 / 0.91.
//!
//! Rust port of UNLZEXE (`unlzexe.c` v0.9) by Mitugu (Kou) Kurizono and
//! contributors; original: <https://github.com/thbar/demomaking/blob/master/tools/unlzexe/UNLZEXE.C>.
//! LZEXE itself was written by Fabrice Bellard (<https://bellard.org/lzexe>).
//!
//! History:
//! - v0.5  Kou (PC-VAN UTJ44266): initial release.
//! - v0.6  David Kirschbaum, Jul 1991: fixed DOS country-info call (`isjapan`).
//! - v0.7  Alan Modra, Nov 1991: large-file fixes; correct MinBSS/MaxBSS.
//! - v0.8  Vesselin Bontchev, Aug 1992: accept `ZM`; detect by decompressor code.
//! - v0.9  Stian Skjelstad, Aug 2019: POSIX/portable fixes.
//! - v1.0  jasimmk, Oct 2026: Rust port — in-memory, bounds-checked, cross-platform, no deps.
//!
//! The whole file is processed in memory, so every read is bounds-checked and
//! malformed input yields an error instead of undefined behaviour.
//!
//! Usage: `ulzexe packedfile[.exe] [unpackedfile[.exe]]`
//!
//! With a single argument the original file is kept as `<name>.olz` and the
//! unpacked executable replaces it.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BACKUP_EXT: &str = "olz";
const DEFAULT_EXT: &str = "exe";

/// Size of the MZ header that LZEXE emits (16 little-endian words).
const HEADER_LEN: usize = 0x20;
/// Number of header words written back to the unpacked file.
const OUT_HEADER_WORDS: usize = 0x0e;
/// Offset of the relocation table in both the packed and unpacked file.
const RELOC_TABLE_OFFSET: u16 = 0x1c;
/// Largest image an MZ header can describe (`e_cp` is a 16-bit page count).
const MAX_IMAGE_LEN: usize = 0xffff * 0x200;

// Header word indices.
const H_MAGIC: usize = 0x00;
const H_CBLP: usize = 0x01;
const H_CP: usize = 0x02;
const H_CRLC: usize = 0x03;
const H_CPARHDR: usize = 0x04;
const H_MINALLOC: usize = 0x05;
const H_MAXALLOC: usize = 0x06;
const H_SS: usize = 0x07;
const H_SP: usize = 0x08;
const H_IP: usize = 0x0a;
const H_CS: usize = 0x0b;
const H_LFARLC: usize = 0x0c;
const H_OVNO: usize = 0x0d;

static SIG90: [u8; 232] = [
    0x06, 0x0E, 0x1F, 0x8B, 0x0E, 0x0C, 0x00, 0x8B, 0xF1, 0x4E, 0x89, 0xF7, 0x8C, 0xDB, 0x03, 0x1E,
    0x0A, 0x00, 0x8E, 0xC3, 0xB4, 0x00, 0x31, 0xED, 0xFD, 0xAC, 0x01, 0xC5, 0xAA, 0xE2, 0xFA, 0x8B,
    0x16, 0x0E, 0x00, 0x8A, 0xC2, 0x29, 0xC5, 0x8A, 0xC6, 0x29, 0xC5, 0x39, 0xD5, 0x74, 0x0C, 0xBA,
    0x91, 0x01, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0xFF, 0x4C, 0xCD, 0x21, 0x53, 0xB8, 0x53, 0x00, 0x50,
    0xCB, 0x2E, 0x8B, 0x2E, 0x08, 0x00, 0x8C, 0xDA, 0x89, 0xE8, 0x3D, 0x00, 0x10, 0x76, 0x03, 0xB8,
    0x00, 0x10, 0x29, 0xC5, 0x29, 0xC2, 0x29, 0xC3, 0x8E, 0xDA, 0x8E, 0xC3, 0xB1, 0x03, 0xD3, 0xE0,
    0x89, 0xC1, 0xD1, 0xE0, 0x48, 0x48, 0x8B, 0xF0, 0x8B, 0xF8, 0xF3, 0xA5, 0x09, 0xED, 0x75, 0xD8,
    0xFC, 0x8E, 0xC2, 0x8E, 0xDB, 0x31, 0xF6, 0x31, 0xFF, 0xBA, 0x10, 0x00, 0xAD, 0x89, 0xC5, 0xD1,
    0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5, 0xB2, 0x10, 0x73, 0x03, 0xA4, 0xEB, 0xF1, 0x31, 0xC9,
    0xD1, 0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5, 0xB2, 0x10, 0x72, 0x22, 0xD1, 0xED, 0x4A, 0x75,
    0x05, 0xAD, 0x89, 0xC5, 0xB2, 0x10, 0xD1, 0xD1, 0xD1, 0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5,
    0xB2, 0x10, 0xD1, 0xD1, 0x41, 0x41, 0xAC, 0xB7, 0xFF, 0x8A, 0xD8, 0xE9, 0x13, 0x00, 0xAD, 0x8B,
    0xD8, 0xB1, 0x03, 0xD2, 0xEF, 0x80, 0xCF, 0xE0, 0x80, 0xE4, 0x07, 0x74, 0x0C, 0x88, 0xE1, 0x41,
    0x41, 0x26, 0x8A, 0x01, 0xAA, 0xE2, 0xFA, 0xEB, 0xA6, 0xAC, 0x08, 0xC0, 0x74, 0x40, 0x3C, 0x01,
    0x74, 0x05, 0x88, 0xC1, 0x41, 0xEB, 0xEA, 0x89,
];

static SIG91: [u8; 232] = [
    0x06, 0x0E, 0x1F, 0x8B, 0x0E, 0x0C, 0x00, 0x8B, 0xF1, 0x4E, 0x89, 0xF7, 0x8C, 0xDB, 0x03, 0x1E,
    0x0A, 0x00, 0x8E, 0xC3, 0xFD, 0xF3, 0xA4, 0x53, 0xB8, 0x2B, 0x00, 0x50, 0xCB, 0x2E, 0x8B, 0x2E,
    0x08, 0x00, 0x8C, 0xDA, 0x89, 0xE8, 0x3D, 0x00, 0x10, 0x76, 0x03, 0xB8, 0x00, 0x10, 0x29, 0xC5,
    0x29, 0xC2, 0x29, 0xC3, 0x8E, 0xDA, 0x8E, 0xC3, 0xB1, 0x03, 0xD3, 0xE0, 0x89, 0xC1, 0xD1, 0xE0,
    0x48, 0x48, 0x8B, 0xF0, 0x8B, 0xF8, 0xF3, 0xA5, 0x09, 0xED, 0x75, 0xD8, 0xFC, 0x8E, 0xC2, 0x8E,
    0xDB, 0x31, 0xF6, 0x31, 0xFF, 0xBA, 0x10, 0x00, 0xAD, 0x89, 0xC5, 0xD1, 0xED, 0x4A, 0x75, 0x05,
    0xAD, 0x89, 0xC5, 0xB2, 0x10, 0x73, 0x03, 0xA4, 0xEB, 0xF1, 0x31, 0xC9, 0xD1, 0xED, 0x4A, 0x75,
    0x05, 0xAD, 0x89, 0xC5, 0xB2, 0x10, 0x72, 0x22, 0xD1, 0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5,
    0xB2, 0x10, 0xD1, 0xD1, 0xD1, 0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5, 0xB2, 0x10, 0xD1, 0xD1,
    0x41, 0x41, 0xAC, 0xB7, 0xFF, 0x8A, 0xD8, 0xE9, 0x13, 0x00, 0xAD, 0x8B, 0xD8, 0xB1, 0x03, 0xD2,
    0xEF, 0x80, 0xCF, 0xE0, 0x80, 0xE4, 0x07, 0x74, 0x0C, 0x88, 0xE1, 0x41, 0x41, 0x26, 0x8A, 0x01,
    0xAA, 0xE2, 0xFA, 0xEB, 0xA6, 0xAC, 0x08, 0xC0, 0x74, 0x34, 0x3C, 0x01, 0x74, 0x05, 0x88, 0xC1,
    0x41, 0xEB, 0xEA, 0x89, 0xFB, 0x83, 0xE7, 0x0F, 0x81, 0xC7, 0x00, 0x20, 0xB1, 0x04, 0xD3, 0xEB,
    0x8C, 0xC0, 0x01, 0xD8, 0x2D, 0x00, 0x02, 0x8E, 0xC0, 0x89, 0xF3, 0x83, 0xE6, 0x0F, 0xD3, 0xEB,
    0x8C, 0xD8, 0x01, 0xD8, 0x8E, 0xD8, 0xE9, 0x72,
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Error {
    Usage,
    NotLzexe(&'static str),
    Truncated(&'static str),
    BadBackReference { distance: usize, available: usize },
    TooManyRelocations,
    ImageTooLarge,
    BadFilename(PathBuf),
    Io { context: String, source: io::Error },
}

impl Error {
    fn io(context: impl Into<String>, source: io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage => write!(f, "usage: ulzexe packedfile[.exe] [unpackedfile[.exe]]"),
            Error::NotLzexe(why) => write!(f, "not an LZEXE 0.90/0.91 file ({why})"),
            Error::Truncated(what) => write!(f, "file is truncated or corrupt ({what})"),
            Error::BadBackReference { distance, available } => write!(
                f,
                "corrupt compressed data: back-reference of {distance} bytes with only {available} bytes decoded"
            ),
            Error::TooManyRelocations => write!(f, "relocation table has more than 65535 entries"),
            Error::ImageTooLarge => write!(f, "unpacked image is too large for an MZ executable"),
            Error::BadFilename(p) => write!(f, "'{}': bad filename", p.display()),
            Error::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Byte reader
// ---------------------------------------------------------------------------

/// Bounds-checked little-endian reader over a byte slice.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader positioned at `pos`; fails if `pos` is past the end.
    fn at(data: &'a [u8], pos: u64, what: &'static str) -> Result<Self> {
        match usize::try_from(pos) {
            Ok(pos) if pos <= data.len() => Ok(Reader { data, pos }),
            _ => Err(Error::Truncated(what)),
        }
    }

    fn u8(&mut self, what: &'static str) -> Result<u8> {
        let b = *self.data.get(self.pos).ok_or(Error::Truncated(what))?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self, what: &'static str) -> Result<u16> {
        let bytes = self
            .data
            .get(self.pos..self.pos + 2)
            .ok_or(Error::Truncated(what))?;
        self.pos += 2;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
}

// ---------------------------------------------------------------------------
// Unpacker
// ---------------------------------------------------------------------------

/// LZEXE format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    V090,
    V091,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Version::V090 => "0.90",
            Version::V091 => "0.91",
        })
    }
}

/// Result of a successful unpack.
#[derive(Debug)]
struct Unpacked {
    version: Version,
    relocations: usize,
    exe: Vec<u8>,
}

/// Decompresses an LZEXE-packed executable held entirely in memory.
fn unpack(input: &[u8]) -> Result<Unpacked> {
    let ihead = read_header(input)?;
    let version = detect_version(input, &ihead)?;

    // CS:0000 of the decompressor holds its parameter block.
    let cs_pos = (u64::from(ihead[H_CS]) + u64::from(ihead[H_CPARHDR])) << 4;
    let mut r = Reader::at(input, cs_pos, "decompressor parameters")?;
    let mut inf = [0u16; 8];
    for w in &mut inf {
        *w = r.u16("decompressor parameters")?;
    }

    let mut ohead = ihead;
    ohead[H_IP] = inf[0];
    ohead[H_CS] = inf[1];
    ohead[H_SP] = inf[2];
    ohead[H_SS] = inf[3];
    ohead[H_LFARLC] = RELOC_TABLE_OFFSET;

    // Relocation table directly follows the 0x1c-byte header.
    let mut out = vec![0u8; usize::from(RELOC_TABLE_OFFSET)];
    let relocations = match version {
        Version::V090 => reloc90(input, cs_pos + 0x19d, &mut out)?,
        Version::V091 => reloc91(input, cs_pos + 0x158, &mut out)?,
    };
    ohead[H_CRLC] = u16::try_from(relocations).map_err(|_| Error::TooManyRelocations)?;

    // Pad header to a 512-byte boundary.
    let header_len = out.len().next_multiple_of(0x200);
    out.resize(header_len, 0);
    ohead[H_CPARHDR] = u16::try_from(header_len >> 4).map_err(|_| Error::ImageTooLarge)?;

    // Compressed load module starts inf[4] paragraphs before CS.
    let data_para = i64::from(ihead[H_CS]) - i64::from(inf[4]) + i64::from(ihead[H_CPARHDR]);
    let data_pos = u64::try_from(data_para << 4)
        .map_err(|_| Error::NotLzexe("compressed data offset is negative"))?;
    let load_len = decompress(input, data_pos, &mut out)?;

    // Fix up memory requirements (v0.7 logic).
    if ihead[H_MAXALLOC] != 0 {
        let decomp_paras = inf[5]
            .wrapping_add(((u32::from(inf[6]) + 15) >> 4) as u16)
            .wrapping_add(9);
        ohead[H_MINALLOC] = ohead[H_MINALLOC].wrapping_sub(decomp_paras);
        if ihead[H_MAXALLOC] != 0xffff {
            ohead[H_MAXALLOC] =
                ohead[H_MAXALLOC].wrapping_sub(ihead[H_MINALLOC].wrapping_sub(ohead[H_MINALLOC]));
        }
    }

    let total = load_len + header_len;
    if total > MAX_IMAGE_LEN {
        return Err(Error::ImageTooLarge);
    }
    ohead[H_CBLP] = (total & 0x1ff) as u16;
    ohead[H_CP] = total.div_ceil(0x200) as u16;

    for (i, w) in ohead.iter().take(OUT_HEADER_WORDS).enumerate() {
        out[i * 2..i * 2 + 2].copy_from_slice(&w.to_le_bytes());
    }

    Ok(Unpacked {
        version,
        relocations,
        exe: out,
    })
}

fn read_header(input: &[u8]) -> Result<[u16; 16]> {
    let raw = input
        .get(..HEADER_LEN)
        .ok_or(Error::NotLzexe("file smaller than an MZ header"))?;
    let mut head = [0u16; 16];
    for (w, c) in head.iter_mut().zip(raw.chunks_exact(2)) {
        *w = u16::from_le_bytes([c[0], c[1]]);
    }
    if head[H_MAGIC] != 0x5a4d && head[H_MAGIC] != 0x4d5a {
        return Err(Error::NotLzexe("missing MZ signature"));
    }
    if head[H_OVNO] != 0 || head[H_LFARLC] != RELOC_TABLE_OFFSET {
        return Err(Error::NotLzexe("unexpected header layout"));
    }
    Ok(head)
}

fn detect_version(input: &[u8], ihead: &[u16; 16]) -> Result<Version> {
    let entry =
        ((u64::from(ihead[H_CPARHDR]) + u64::from(ihead[H_CS])) << 4) + u64::from(ihead[H_IP]);
    let code = usize::try_from(entry)
        .ok()
        .and_then(|start| input.get(start..start.checked_add(SIG90.len())?))
        .ok_or(Error::NotLzexe("entry point outside file"))?;
    if code == SIG90 {
        Ok(Version::V090)
    } else if code == SIG91 {
        Ok(Version::V091)
    } else {
        Err(Error::NotLzexe("decompressor signature not found"))
    }
}

fn push_reloc(out: &mut Vec<u8>, off: u16, seg: u16) {
    out.extend_from_slice(&off.to_le_bytes());
    out.extend_from_slice(&seg.to_le_bytes());
}

/// LZEXE 0.90: 16 groups (one per 64 KiB segment), each a count + offsets.
fn reloc90(input: &[u8], pos: u64, out: &mut Vec<u8>) -> Result<usize> {
    const WHAT: &str = "relocation table";
    let mut r = Reader::at(input, pos, WHAT)?;
    let mut count = 0usize;
    for seg in (0..16u16).map(|i| i << 12) {
        let n = r.u16(WHAT)?;
        for _ in 0..n {
            push_reloc(out, r.u16(WHAT)?, seg);
            count += 1;
        }
    }
    Ok(count)
}

/// LZEXE 0.91: delta-encoded linear addresses.
fn reloc91(input: &[u8], pos: u64, out: &mut Vec<u8>) -> Result<usize> {
    const WHAT: &str = "relocation table";
    let mut r = Reader::at(input, pos, WHAT)?;
    let (mut off, mut seg) = (0u16, 0u16);
    let mut count = 0usize;
    loop {
        let mut span = u16::from(r.u8(WHAT)?);
        if span == 0 {
            span = r.u16(WHAT)?;
            match span {
                0 => {
                    seg = seg.wrapping_add(0x0fff);
                    continue;
                }
                1 => break,
                _ => {}
            }
        }
        off = off.wrapping_add(span);
        seg = seg.wrapping_add((off & !0x0f) >> 4);
        off &= 0x0f;
        push_reloc(out, off, seg);
        count += 1;
        if count > usize::from(u16::MAX) {
            return Err(Error::TooManyRelocations);
        }
    }
    Ok(count)
}

/// Bit reader that shares its byte source with literal reads, exactly as the
/// original decompressor does: a new 16-bit word is fetched eagerly as soon as
/// the previous one is exhausted.
struct BitReader<'a> {
    r: Reader<'a>,
    buf: u16,
    count: u8,
    exhausted: bool,
}

impl<'a> BitReader<'a> {
    const WHAT: &'static str = "compressed data";

    fn new(mut r: Reader<'a>) -> Result<Self> {
        let buf = r.u16(Self::WHAT)?;
        Ok(BitReader {
            r,
            buf,
            count: 16,
            exhausted: false,
        })
    }

    fn bit(&mut self) -> Result<bool> {
        if self.exhausted {
            return Err(Error::Truncated(Self::WHAT));
        }
        let b = self.buf & 1 != 0;
        self.count -= 1;
        if self.count == 0 {
            // A refill past EOF is only an error if another bit is requested.
            match self.r.u16(Self::WHAT) {
                Ok(w) => {
                    self.buf = w;
                    self.count = 16;
                }
                Err(_) => self.exhausted = true,
            }
        } else {
            self.buf >>= 1;
        }
        Ok(b)
    }

    fn byte(&mut self) -> Result<u8> {
        self.r.u8(Self::WHAT)
    }
}

/// Decodes the LZ77 stream at `pos` and appends it to `out`.
/// Returns the number of bytes produced.
fn decompress(input: &[u8], pos: u64, out: &mut Vec<u8>) -> Result<usize> {
    let mut bits = BitReader::new(Reader::at(input, pos, BitReader::WHAT)?)?;
    let start = out.len();
    loop {
        if bits.bit()? {
            out.push(bits.byte()?);
            continue;
        }
        let (len, span) = if !bits.bit()? {
            let len = (usize::from(bits.bit()?) << 1 | usize::from(bits.bit()?)) + 2;
            (len, u16::from(bits.byte()?) | 0xff00)
        } else {
            let lo = u16::from(bits.byte()?);
            let hi = u16::from(bits.byte()?);
            let span = lo | ((hi & !0x07) << 5) | 0xe000;
            let len = match (hi & 0x07) + 2 {
                2 => match bits.byte()? {
                    0 => break,    // end of compressed load module
                    1 => continue, // segment change marker
                    n => usize::from(n) + 1,
                },
                n => usize::from(n),
            };
            (len, span)
        };

        // `span` is a negative 16-bit displacement (1..=8192 bytes back).
        let distance = usize::from(span.wrapping_neg());
        let available = out.len() - start;
        if distance > available {
            return Err(Error::BadBackReference {
                distance,
                available,
            });
        }
        if out.len() + len > MAX_IMAGE_LEN {
            return Err(Error::ImageTooLarge);
        }
        // Byte-by-byte copy: source and destination may overlap (RLE-style).
        for _ in 0..len {
            out.push(out[out.len() - distance]);
        }
    }
    Ok(out.len() - start)
}

// ---------------------------------------------------------------------------
// File handling
// ---------------------------------------------------------------------------

fn has_ext(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// Appends `.exe` when the path has no extension and doesn't exist as given.
fn with_default_ext(path: &Path) -> PathBuf {
    if path.extension().is_none() && !path.exists() {
        let mut s = path.as_os_str().to_owned();
        s.push(".");
        s.push(DEFAULT_EXT);
        PathBuf::from(s)
    } else {
        path.to_path_buf()
    }
}

/// Paths derived from the command line.
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    input: PathBuf,
    output: PathBuf,
    /// Set when unpacking in place: original is moved here first.
    backup: Option<PathBuf>,
}

fn plan(args: &[OsString]) -> Result<Plan> {
    let (input, output) = match args {
        [i] => (with_default_ext(Path::new(i)), None),
        [i, o] => (
            with_default_ext(Path::new(i)),
            Some(with_default_ext(Path::new(o))),
        ),
        _ => return Err(Error::Usage),
    };
    if input.file_name().is_none() {
        return Err(Error::BadFilename(input));
    }
    let (output, backup) = match output {
        Some(o) if !same_file(&input, &o) => (o, None),
        _ => {
            if has_ext(&input, BACKUP_EXT) {
                return Err(Error::BadFilename(input));
            }
            (input.clone(), Some(input.with_extension(BACKUP_EXT)))
        }
    };
    if output.file_name().is_none() || has_ext(&output, BACKUP_EXT) {
        return Err(Error::BadFilename(output));
    }
    Ok(Plan {
        input,
        output,
        backup,
    })
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Temporary file next to `target`, so the final rename stays on one volume.
fn temp_path(target: &Path) -> PathBuf {
    let name = target.file_name().unwrap_or_default().to_string_lossy();
    target.with_file_name(format!(".{name}.{}.ulzexe.tmp", std::process::id()))
}

/// Rename that also replaces an existing destination on Windows.
fn replace(from: &Path, to: &Path) -> io::Result<()> {
    if cfg!(windows) && to.exists() {
        fs::remove_file(to)?;
    }
    fs::rename(from, to)
}

fn write_output(plan: &Plan, data: &[u8]) -> Result<()> {
    let tmp = temp_path(&plan.output);
    let write = || -> io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(Error::io(format!("can't write '{}'", tmp.display()), e));
    }

    if let Some(backup) = &plan.backup {
        if let Err(e) = replace(&plan.input, backup) {
            let _ = fs::remove_file(&tmp);
            return Err(Error::io(format!("can't make '{}'", backup.display()), e));
        }
        println!(
            "'{}' is renamed to '{}'.",
            plan.input.display(),
            backup.display()
        );
    }

    if let Err(e) = replace(&tmp, &plan.output) {
        let _ = fs::remove_file(&tmp);
        if let Some(backup) = &plan.backup {
            let _ = fs::rename(backup, &plan.input);
        }
        return Err(Error::io(
            format!("can't make '{}'", plan.output.display()),
            e,
        ));
    }
    Ok(())
}

fn run(args: &[OsString]) -> Result<Unpacked> {
    let plan = plan(args)?;
    let input = fs::read(&plan.input)
        .map_err(|e| Error::io(format!("can't read '{}'", plan.input.display()), e))?;
    let unpacked = unpack(&input)?;
    println!(
        "file '{}' is compressed by LZEXE Ver. {}",
        plan.input.display(),
        unpacked.version
    );
    write_output(&plan, &unpacked.exe)?;
    println!(
        "unpacked file '{}' is generated ({} bytes, {} relocations).",
        plan.output.display(),
        unpacked.exe.len(),
        unpacked.relocations
    );
    Ok(unpacked)
}

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    if matches!(
        args.first().and_then(|a| a.to_str()),
        Some("-h" | "--help" | "-V" | "--version")
    ) {
        println!("ULZEXE Ver. {VERSION}");
        println!("{}", Error::Usage);
        return ExitCode::SUCCESS;
    }
    println!("ULZEXE Ver. {VERSION}");
    match run(&args) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal LZEXE-compatible encoder used to synthesise test inputs.
    struct Encoder {
        out: Vec<u8>,
        slot: usize,
        buf: u16,
        nbits: u8,
    }

    enum Tok {
        Lit(u8),
        Short { len: usize, dist: usize },
        Long { len: usize, dist: usize },
        SegChange,
    }

    impl Encoder {
        fn new() -> Self {
            Encoder {
                out: vec![0, 0],
                slot: 0,
                buf: 0,
                nbits: 0,
            }
        }
        fn bit(&mut self, b: bool) {
            self.buf |= u16::from(b) << self.nbits;
            self.nbits += 1;
            if self.nbits == 16 {
                self.out[self.slot..self.slot + 2].copy_from_slice(&self.buf.to_le_bytes());
                self.slot = self.out.len();
                self.out.extend_from_slice(&[0, 0]);
                self.buf = 0;
                self.nbits = 0;
            }
        }
        fn byte(&mut self, b: u8) {
            self.out.push(b);
        }
        fn long_header(&mut self, dist: usize, lenbits: u8) {
            let span = (dist as u16).wrapping_neg();
            self.bit(false);
            self.bit(true);
            self.byte(span as u8);
            self.byte((((span >> 5) & 0xf8) as u8) | lenbits);
        }
        fn tok(&mut self, t: &Tok) {
            match *t {
                Tok::Lit(b) => {
                    self.bit(true);
                    self.byte(b);
                }
                Tok::Short { len, dist } => {
                    assert!((2..=5).contains(&len) && (1..=256).contains(&dist));
                    let l = len - 2;
                    self.bit(false);
                    self.bit(false);
                    self.bit(l & 2 != 0);
                    self.bit(l & 1 != 0);
                    self.byte((dist as u16).wrapping_neg() as u8);
                }
                Tok::Long { len, dist } => {
                    assert!((3..=256).contains(&len) && (1..=8192).contains(&dist));
                    if len <= 9 {
                        self.long_header(dist, (len - 2) as u8);
                    } else {
                        self.long_header(dist, 0);
                        self.byte((len - 1) as u8);
                    }
                }
                Tok::SegChange => {
                    self.long_header(1, 0);
                    self.byte(1);
                }
            }
        }
        fn finish(mut self) -> Vec<u8> {
            self.long_header(1, 0);
            self.byte(0);
            self.out[self.slot..self.slot + 2].copy_from_slice(&self.buf.to_le_bytes());
            self.out
        }
    }

    fn encode(toks: &[Tok]) -> Vec<u8> {
        let mut e = Encoder::new();
        toks.iter().for_each(|t| e.tok(t));
        e.finish()
    }

    /// Builds a packed EXE: header | compressed data | CS segment.
    fn build_exe(version: Version, stream: &[u8], reloc: &[u8]) -> Vec<u8> {
        let paras = stream.len().div_ceil(16);
        let mut f = vec![0u8; HEADER_LEN];
        f.extend_from_slice(stream);
        f.resize(HEADER_LEN + paras * 16, 0);
        let cs = f.len();
        let inf: [u16; 8] = [0x100, 0x10, 0x200, 0x20, paras as u16, 3, 0x200, 0];
        for w in inf {
            f.extend_from_slice(&w.to_le_bytes());
        }
        f.extend_from_slice(match version {
            Version::V090 => &SIG90,
            Version::V091 => &SIG91,
        });
        let rel_at = cs
            + if version == Version::V090 {
                0x19d
            } else {
                0x158
            };
        f.resize(rel_at, 0);
        f.extend_from_slice(reloc);
        f.extend_from_slice(&[0; 16]);

        let head: [u16; 16] = [
            0x5a4d,
            0,
            0,
            0,
            2,
            0x50,
            0xffff,
            0,
            0,
            0,
            0x10,
            paras as u16,
            0x1c,
            0,
            u16::from_le_bytes(*b"LZ"),
            u16::from_le_bytes(if version == Version::V090 {
                *b"09"
            } else {
                *b"91"
            }),
        ];
        for (i, w) in head.iter().enumerate() {
            f[i * 2..i * 2 + 2].copy_from_slice(&w.to_le_bytes());
        }
        f
    }

    fn reloc90_none() -> Vec<u8> {
        vec![0; 32]
    }

    fn reloc91_none() -> Vec<u8> {
        vec![0, 1, 0]
    }

    fn word(d: &[u8], i: usize) -> u16 {
        u16::from_le_bytes([d[i * 2], d[i * 2 + 1]])
    }

    fn body(u: &Unpacked) -> &[u8] {
        &u.exe[usize::from(word(&u.exe, H_CPARHDR)) << 4..]
    }

    #[test]
    fn literals_roundtrip() {
        let toks: Vec<Tok> = b"Hello, DOS!".iter().map(|&b| Tok::Lit(b)).collect();
        let u = unpack(&build_exe(Version::V091, &encode(&toks), &reloc91_none())).unwrap();
        assert_eq!(u.version, Version::V091);
        assert_eq!(body(&u), b"Hello, DOS!");
    }

    #[test]
    fn matches_and_overlap() {
        use Tok::*;
        let toks = [
            Lit(b'a'),
            Lit(b'b'),
            Lit(b'c'),
            Short { len: 5, dist: 3 },  // abcab
            Long { len: 4, dist: 8 },   // abca
            Long { len: 200, dist: 1 }, // run of 'a'
            SegChange,
            Short { len: 2, dist: 200 },
        ];
        let u = unpack(&build_exe(Version::V090, &encode(&toks), &reloc90_none())).unwrap();
        let mut want = b"abcabcababca".to_vec();
        want.extend(std::iter::repeat_n(b'a', 200));
        let n = want.len();
        want.extend_from_within(n - 200..n - 198);
        assert_eq!(body(&u), &want[..]);
    }

    #[test]
    fn long_distance_match() {
        let mut toks: Vec<Tok> = (0..8192u32).map(|i| Tok::Lit((i * 7) as u8)).collect();
        toks.push(Tok::Long {
            len: 256,
            dist: 8192,
        });
        let u = unpack(&build_exe(Version::V091, &encode(&toks), &reloc91_none())).unwrap();
        let b = body(&u);
        assert_eq!(b.len(), 8192 + 256);
        assert_eq!(&b[8192..], &b[..256]);
    }

    #[test]
    fn header_fields_describe_file() {
        let toks: Vec<Tok> = (0..1000u32).map(|i| Tok::Lit(i as u8)).collect();
        let u = unpack(&build_exe(Version::V091, &encode(&toks), &reloc91_none())).unwrap();
        let e = &u.exe;
        assert_eq!(word(e, H_MAGIC), 0x5a4d);
        assert_eq!((word(e, H_IP), word(e, H_CS)), (0x100, 0x10));
        assert_eq!((word(e, H_SP), word(e, H_SS)), (0x200, 0x20));
        assert_eq!(word(e, H_LFARLC), 0x1c);
        assert_eq!(word(e, H_CPARHDR), 0x20);
        let pages = usize::from(word(e, H_CP));
        let last = usize::from(word(e, H_CBLP));
        assert_eq!(
            (pages - 1) * 512 + if last == 0 { 512 } else { last },
            e.len()
        );
        // minalloc: 0x50 - (3 + 0x20 + 9)
        assert_eq!(word(e, H_MINALLOC), 0x50 - (3 + 0x20 + 9));
        assert_eq!(word(e, H_MAXALLOC), 0xffff);
    }

    #[test]
    fn reloc90_table() {
        let mut rel = vec![0u8; 32];
        rel[0..2].copy_from_slice(&2u16.to_le_bytes());
        rel.splice(2..2, [0x34, 0x12, 0x78, 0x56]);
        // segment 1 (0x1000) has one entry
        rel[6..8].copy_from_slice(&1u16.to_le_bytes());
        rel.splice(8..8, [0xcd, 0xab]);
        let u = unpack(&build_exe(Version::V090, &encode(&[Tok::Lit(1)]), &rel)).unwrap();
        assert_eq!(u.relocations, 3);
        assert_eq!(word(&u.exe, H_CRLC), 3);
        let t = &u.exe[0x1c..0x1c + 12];
        assert_eq!(
            t,
            [0x34, 0x12, 0, 0, 0x78, 0x56, 0, 0, 0xcd, 0xab, 0x00, 0x10]
        );
    }

    #[test]
    fn reloc91_table() {
        // span 0x25 -> 0002:0005 ; seg skip ; span 0x1234 (word form)
        let rel = [0x25, 0, 0, 0, 0, 0x34, 0x12, 0, 1, 0];
        let u = unpack(&build_exe(Version::V091, &encode(&[Tok::Lit(1)]), &rel)).unwrap();
        assert_eq!(u.relocations, 2);
        let t = &u.exe[0x1c..0x1c + 8];
        let seg2 = 0x0002u16 + 0x0fff + ((5 + 0x1234) >> 4);
        let off2 = (5 + 0x1234) & 0xf;
        let mut want = vec![0x05, 0, 0x02, 0];
        want.extend_from_slice(&(off2 as u16).to_le_bytes());
        want.extend_from_slice(&seg2.to_le_bytes());
        assert_eq!(t, &want[..]);
    }

    #[test]
    fn zm_magic_accepted() {
        let mut f = build_exe(Version::V091, &encode(&[Tok::Lit(9)]), &reloc91_none());
        f[0..2].copy_from_slice(b"ZM");
        assert!(unpack(&f).is_ok());
    }

    #[test]
    fn rejects_non_lzexe() {
        assert!(matches!(unpack(&[]), Err(Error::NotLzexe(_))));
        assert!(matches!(unpack(&[0u8; 64]), Err(Error::NotLzexe(_))));
        let mut f = build_exe(Version::V091, &encode(&[Tok::Lit(9)]), &reloc91_none());
        let cs = usize::from(word(&f, H_CS) + 2) << 4;
        f[cs + 0x10 + 5] ^= 0xff;
        assert!(matches!(unpack(&f), Err(Error::NotLzexe(_))));
        let mut f = build_exe(Version::V091, &encode(&[Tok::Lit(9)]), &reloc91_none());
        f[H_CS * 2..H_CS * 2 + 2].copy_from_slice(&0xffffu16.to_le_bytes());
        assert!(matches!(unpack(&f), Err(Error::NotLzexe(_))));
    }

    #[test]
    fn truncated_relocations() {
        let mut f = build_exe(Version::V091, &encode(&[Tok::Lit(9)]), &[0x10; 4]);
        f.truncate(f.len() - 16);
        assert!(matches!(unpack(&f), Err(Error::Truncated(_))));
        let mut f = build_exe(Version::V090, &encode(&[Tok::Lit(9)]), &[]);
        f.truncate(f.len() - 16);
        assert!(matches!(unpack(&f), Err(Error::Truncated(_))));
    }

    #[test]
    fn bad_back_reference() {
        let s = encode(&[Tok::Lit(1), Tok::Short { len: 2, dist: 2 }]);
        let r = unpack(&build_exe(Version::V091, &s, &reloc91_none()));
        assert!(matches!(
            r,
            Err(Error::BadBackReference {
                distance: 2,
                available: 1
            })
        ));
    }

    #[test]
    fn negative_data_offset() {
        let mut f = build_exe(Version::V091, &encode(&[Tok::Lit(1)]), &reloc91_none());
        let cs = usize::from(word(&f, H_CS) + 2) << 4;
        f[cs + 8..cs + 10].copy_from_slice(&0xfff0u16.to_le_bytes());
        assert!(matches!(unpack(&f), Err(Error::NotLzexe(_))));
    }

    #[test]
    fn unterminated_stream() {
        // Only literals, no end marker: decoder must hit EOF, not loop or panic.
        let mut e = Encoder::new();
        e.tok(&Tok::Lit(1));
        e.out[e.slot..e.slot + 2].copy_from_slice(&0xffffu16.to_le_bytes());
        let mut f = vec![0u8; HEADER_LEN];
        f.extend_from_slice(&e.out);
        let r = decompress(&f, HEADER_LEN as u64, &mut Vec::new());
        assert!(matches!(r, Err(Error::Truncated(_))));
    }

    #[test]
    fn bitreader_errors_only_when_bits_needed() {
        // Exactly one word, 16 bits consumed: refill fails silently.
        let data = [0xff, 0xff];
        let mut b = BitReader::new(Reader {
            data: &data,
            pos: 0,
        })
        .unwrap();
        for _ in 0..16 {
            assert!(b.bit().unwrap());
        }
        assert!(matches!(b.bit(), Err(Error::Truncated(_))));
    }

    #[test]
    fn plan_paths() {
        let p = plan(&["/nonexistent/dir/GAME".into()]).unwrap();
        assert_eq!(p.input, PathBuf::from("/nonexistent/dir/GAME.exe"));
        assert_eq!(p.output, p.input);
        assert_eq!(p.backup, Some(PathBuf::from("/nonexistent/dir/GAME.olz")));

        let p = plan(&["a.EXE".into(), "b".into()]).unwrap();
        assert_eq!(
            (p.input, p.output, p.backup),
            ("a.EXE".into(), "b.exe".into(), None)
        );

        assert!(matches!(plan(&[]), Err(Error::Usage)));
        assert!(matches!(
            plan(&["a".into(), "b".into(), "c".into()]),
            Err(Error::Usage)
        ));
        assert!(matches!(
            plan(&["a.exe".into(), "b.OLZ".into()]),
            Err(Error::BadFilename(_))
        ));
        assert!(matches!(
            plan(&["a.olz".into()]),
            Err(Error::BadFilename(_))
        ));
        assert!(matches!(plan(&["..".into()]), Err(Error::BadFilename(_))));
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let d = env::temp_dir().join(format!("ulzexe-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn end_to_end_in_place() {
        let dir = scratch_dir("inplace");
        let packed = build_exe(Version::V091, &encode(&[Tok::Lit(b'x')]), &reloc91_none());
        fs::write(dir.join("prog.exe"), &packed).unwrap();
        // Stale backup must be replaced.
        fs::write(dir.join("prog.olz"), b"old").unwrap();

        run(&[dir.join("prog").into_os_string()]).unwrap();

        assert_eq!(fs::read(dir.join("prog.olz")).unwrap(), packed);
        let out = fs::read(dir.join("prog.exe")).unwrap();
        assert_eq!(out, unpack(&packed).unwrap().exe);
        let leftovers: Vec<_> = fs::read_dir(&dir).unwrap().collect();
        assert_eq!(leftovers.len(), 2, "temp file left behind");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn end_to_end_separate_output() {
        let dir = scratch_dir("separate");
        let packed = build_exe(Version::V090, &encode(&[Tok::Lit(b'y')]), &reloc90_none());
        fs::write(dir.join("in.exe"), &packed).unwrap();
        fs::write(dir.join("out.exe"), b"overwrite me").unwrap();

        run(&[dir.join("in.exe").into(), dir.join("out.exe").into()]).unwrap();

        assert_eq!(fs::read(dir.join("in.exe")).unwrap(), packed);
        assert_eq!(
            fs::read(dir.join("out.exe")).unwrap(),
            unpack(&packed).unwrap().exe
        );
        assert!(!dir.join("in.olz").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failure_leaves_files_untouched() {
        let dir = scratch_dir("fail");
        fs::write(dir.join("bad.exe"), b"MZ not really").unwrap();
        assert!(run(&[dir.join("bad.exe").into()]).is_err());
        assert_eq!(fs::read(dir.join("bad.exe")).unwrap(), b"MZ not really");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        assert!(matches!(
            run(&[dir.join("missing.exe").into()]),
            Err(Error::Io { .. })
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    // ----- additional coverage -------------------------------------------

    fn set_word(d: &mut [u8], i: usize, v: u16) {
        d[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn unpack_toks(toks: &[Tok]) -> Vec<u8> {
        let u = unpack(&build_exe(Version::V091, &encode(toks), &reloc91_none())).unwrap();
        body(&u).to_vec()
    }

    #[test]
    fn empty_stream() {
        let u = unpack(&build_exe(Version::V091, &encode(&[]), &reloc91_none())).unwrap();
        assert!(body(&u).is_empty());
        assert_eq!(u.exe.len(), 512);
        assert_eq!((word(&u.exe, H_CP), word(&u.exe, H_CBLP)), (1, 0));
    }

    #[test]
    fn segment_change_only() {
        assert!(unpack_toks(&[Tok::SegChange, Tok::SegChange]).is_empty());
    }

    #[test]
    fn every_literal_value() {
        let toks: Vec<Tok> = (0..=255u8).map(Tok::Lit).collect();
        let want: Vec<u8> = (0..=255u8).collect();
        assert_eq!(unpack_toks(&toks), want);
    }

    #[test]
    fn bit_word_boundaries() {
        // Varying token sizes push bit-word refills to every possible position.
        for n in 1..=40 {
            let mut toks: Vec<Tok> = (0..n).map(|i| Tok::Lit(i as u8)).collect();
            toks.push(Tok::Short { len: 3, dist: 1 });
            toks.push(Tok::Long { len: 12, dist: 2 });
            let out = unpack_toks(&toks);
            let mut want: Vec<u8> = (0..n).map(|i| i as u8).collect();
            for d in [1; 3].into_iter().chain([2; 12]) {
                want.push(want[want.len() - d]);
            }
            assert_eq!(out, want, "n = {n}");
        }
    }

    #[test]
    fn short_match_lengths() {
        for len in 2..=5 {
            let mut toks: Vec<Tok> = b"abcde".iter().map(|&b| Tok::Lit(b)).collect();
            toks.push(Tok::Short { len, dist: 5 });
            let mut want = b"abcde".to_vec();
            want.extend_from_slice(&b"abcde"[..len]);
            assert_eq!(unpack_toks(&toks), want, "len = {len}");
        }
    }

    #[test]
    fn long_match_lengths() {
        let seed: Vec<u8> = (0..=255u8).collect();
        for len in (3..=12).chain([255, 256]) {
            let mut toks: Vec<Tok> = seed.iter().map(|&b| Tok::Lit(b)).collect();
            toks.push(Tok::Long { len, dist: 256 });
            let mut want = seed.clone();
            want.extend_from_slice(&seed[..len]);
            assert_eq!(unpack_toks(&toks), want, "len = {len}");
        }
    }

    #[test]
    fn maximum_short_distance() {
        let seed: Vec<u8> = (0..=255u8).collect();
        let mut toks: Vec<Tok> = seed.iter().map(|&b| Tok::Lit(b)).collect();
        toks.push(Tok::Short { len: 4, dist: 256 });
        assert_eq!(&unpack_toks(&toks)[256..], &[0, 1, 2, 3]);
    }

    #[test]
    fn back_reference_into_empty_output() {
        let s = encode(&[Tok::Long { len: 3, dist: 1 }]);
        let r = unpack(&build_exe(Version::V091, &s, &reloc91_none()));
        assert!(matches!(
            r,
            Err(Error::BadBackReference {
                distance: 1,
                available: 0
            })
        ));
    }

    #[test]
    fn image_too_large() {
        let mut toks = vec![Tok::Lit(0)];
        toks.extend((0..MAX_IMAGE_LEN / 256 + 1).map(|_| Tok::Long { len: 256, dist: 1 }));
        let r = unpack(&build_exe(Version::V091, &encode(&toks), &reloc91_none()));
        assert!(matches!(r, Err(Error::ImageTooLarge)));
    }

    #[test]
    fn truncated_compressed_data() {
        let mut s = encode(&[Tok::Lit(1), Tok::Lit(2), Tok::Lit(3)]);
        s.truncate(s.len() - 4); // cut into the end marker
        let r = decompress(&s, 0, &mut Vec::new());
        assert!(matches!(r, Err(Error::Truncated(_))));
        // Start offset past EOF and a single dangling byte.
        assert!(matches!(
            decompress(&s, 1000, &mut Vec::new()),
            Err(Error::Truncated(_))
        ));
        assert!(matches!(
            decompress(&[0], 0, &mut Vec::new()),
            Err(Error::Truncated(_))
        ));
    }

    #[test]
    fn reader_bounds() {
        let d = [1u8, 2, 3];
        assert!(Reader::at(&d, 3, "x").is_ok());
        assert!(Reader::at(&d, 4, "x").is_err());
        assert!(Reader::at(&d, u64::MAX, "x").is_err());
        let mut r = Reader::at(&d, 0, "x").unwrap();
        assert_eq!(r.u16("x").unwrap(), 0x0201);
        assert!(r.u16("x").is_err());
        assert_eq!(r.u8("x").unwrap(), 3);
        assert!(r.u8("x").is_err());
    }

    #[test]
    fn signature_cut_short() {
        let f = build_exe(Version::V091, &encode(&[Tok::Lit(1)]), &reloc91_none());
        let cs = usize::from(word(&f, H_CS) + 2) << 4;
        let cut = &f[..cs + 0x10 + SIG91.len() - 1];
        assert!(matches!(unpack(cut), Err(Error::NotLzexe(_))));
    }

    #[test]
    fn header_rejections() {
        let base = build_exe(Version::V091, &encode(&[Tok::Lit(1)]), &reloc91_none());
        assert!(matches!(
            unpack(&base[..HEADER_LEN - 1]),
            Err(Error::NotLzexe(_))
        ));
        for (idx, val) in [(H_MAGIC, 0x1234), (H_OVNO, 1), (H_LFARLC, 0x40)] {
            let mut f = base.clone();
            set_word(&mut f, idx, val);
            assert!(
                matches!(unpack(&f), Err(Error::NotLzexe(_))),
                "word {idx:#x}"
            );
        }
    }

    #[test]
    fn alloc_adjustments() {
        let base = build_exe(Version::V091, &encode(&[Tok::Lit(1)]), &reloc91_none());
        // inf[5]=3, inf[6]=0x200 -> decompressor uses 3 + 0x20 + 9 = 0x2c paragraphs.
        let mut f = base.clone();
        set_word(&mut f, H_MINALLOC, 0x100);
        set_word(&mut f, H_MAXALLOC, 0x200);
        let e = unpack(&f).unwrap().exe;
        assert_eq!(word(&e, H_MINALLOC), 0xd4);
        assert_eq!(word(&e, H_MAXALLOC), 0x1d4);

        let mut f = base.clone();
        set_word(&mut f, H_MAXALLOC, 0);
        let e = unpack(&f).unwrap().exe;
        assert_eq!((word(&e, H_MINALLOC), word(&e, H_MAXALLOC)), (0x50, 0));

        // Underflow must wrap like the 16-bit original, not panic.
        let mut f = base;
        set_word(&mut f, H_MINALLOC, 0);
        set_word(&mut f, H_MAXALLOC, 0x10);
        let e = unpack(&f).unwrap().exe;
        assert_eq!(word(&e, H_MINALLOC), 0u16.wrapping_sub(0x2c));
    }

    fn reloc91_ones(n: usize) -> Vec<u8> {
        let mut r = vec![1u8; n];
        r.extend_from_slice(&[0, 1, 0]);
        r
    }

    #[test]
    fn header_padding_boundary() {
        // 0x1c + 121*4 == 512 exactly; one more entry spills into a 2nd block.
        for (n, paras) in [(121, 0x20), (122, 0x40)] {
            let f = build_exe(Version::V091, &encode(&[Tok::Lit(7)]), &reloc91_ones(n));
            let u = unpack(&f).unwrap();
            assert_eq!(u.relocations, n);
            assert_eq!(word(&u.exe, H_CPARHDR), paras);
            assert_eq!(body(&u), [7]);
        }
    }

    #[test]
    fn reloc91_limits() {
        let f = build_exe(
            Version::V091,
            &encode(&[Tok::Lit(1)]),
            &reloc91_ones(0xffff),
        );
        assert_eq!(word(&unpack(&f).unwrap().exe, H_CRLC), 0xffff);
        let f = build_exe(
            Version::V091,
            &encode(&[Tok::Lit(1)]),
            &reloc91_ones(0x10000),
        );
        assert!(matches!(unpack(&f), Err(Error::TooManyRelocations)));
    }

    #[test]
    fn reloc91_offset_normalisation() {
        // Offsets carry into the segment; segment skips wrap around 16 bits.
        let mut rel = vec![0xff, 0xff];
        rel.extend(std::iter::repeat_n([0, 0, 0], 17).flatten());
        rel.extend_from_slice(&[0, 1, 0]);
        let u = unpack(&build_exe(Version::V091, &encode(&[Tok::Lit(1)]), &rel)).unwrap();
        // 0xff -> 000F:000F ; +0xff -> 0x0f+0xff=0x10e -> seg 0x1f, off 0xe
        assert_eq!(&u.exe[0x1c..0x24], &[0x0f, 0, 0x0f, 0, 0x0e, 0, 0x1f, 0]);
        assert_eq!(u.relocations, 2);
    }

    #[test]
    fn reloc90_last_segment_and_limits() {
        let mut rel = vec![0u8; 30];
        rel.extend_from_slice(&1u16.to_le_bytes()); // group 15 (0xF000)
        rel.extend_from_slice(&0xbeefu16.to_le_bytes());
        let u = unpack(&build_exe(Version::V090, &encode(&[Tok::Lit(1)]), &rel)).unwrap();
        assert_eq!(&u.exe[0x1c..0x20], &[0xef, 0xbe, 0x00, 0xf0]);

        let mut rel = 0xffffu16.to_le_bytes().to_vec();
        rel.resize(2 + 0xffff * 2, 0);
        rel.extend_from_slice(&1u16.to_le_bytes());
        rel.extend_from_slice(&[0, 0]);
        rel.resize(rel.len() + 14 * 2, 0);
        let f = build_exe(Version::V090, &encode(&[Tok::Lit(1)]), &rel);
        assert!(matches!(unpack(&f), Err(Error::TooManyRelocations)));
    }

    #[test]
    fn output_is_not_lzexe_again() {
        let packed = build_exe(Version::V090, &encode(&[Tok::Lit(1)]), &reloc90_none());
        let out = unpack(&packed).unwrap().exe;
        assert!(matches!(unpack(&out), Err(Error::NotLzexe(_))));
    }

    #[test]
    fn display_strings() {
        assert_eq!(Version::V090.to_string(), "0.90");
        assert_eq!(Version::V091.to_string(), "0.91");
        assert!(Error::Usage.to_string().starts_with("usage: ulzexe"));
        assert!(Error::TooManyRelocations.to_string().contains("65535"));
        let e = Error::io("ctx", io::Error::other("boom"));
        assert_eq!(e.to_string(), "ctx: boom");
        assert!(std::error::Error::source(&e).is_some());
        assert!(std::error::Error::source(&Error::Usage).is_none());
    }

    #[test]
    fn path_helpers() {
        assert!(has_ext(Path::new("A.OLZ"), "olz"));
        assert!(!has_ext(Path::new("olz"), "olz"));
        assert_eq!(
            with_default_ext(Path::new("/nonexistent/v1.2/GAME")),
            PathBuf::from("/nonexistent/v1.2/GAME.exe")
        );
        assert_eq!(with_default_ext(Path::new("x.com")), PathBuf::from("x.com"));
        let t = temp_path(Path::new("dir/out.exe"));
        assert_eq!(t.parent(), Some(Path::new("dir")));
        assert!(t
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".out.exe."));
    }

    #[test]
    fn plan_with_existing_files() {
        let dir = scratch_dir("plan");
        let noext = dir.join("PROG");
        fs::write(&noext, b"").unwrap();
        // Existing extension-less file is used as-is.
        assert_eq!(plan(&[noext.clone().into()]).unwrap().input, noext);
        // Same path twice means in-place with backup.
        let p = plan(&[noext.clone().into(), noext.clone().into()]).unwrap();
        assert_eq!(p.backup, Some(dir.join("PROG.olz")));
        // A .olz input is fine when an explicit output is given.
        let olz = dir.join("old.olz");
        fs::write(&olz, b"").unwrap();
        assert!(plan(&[olz.into(), dir.join("new").into()]).is_ok());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unwritable_output_leaves_input() {
        let dir = scratch_dir("unwritable");
        let packed = build_exe(Version::V091, &encode(&[Tok::Lit(1)]), &reloc91_none());
        fs::write(dir.join("in.exe"), &packed).unwrap();
        let r = run(&[
            dir.join("in.exe").into(),
            dir.join("no/such/dir/out.exe").into(),
        ]);
        assert!(matches!(r, Err(Error::Io { .. })));
        assert_eq!(fs::read(dir.join("in.exe")).unwrap(), packed);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn non_ascii_filenames() {
        let dir = scratch_dir("unicode");
        let packed = build_exe(Version::V091, &encode(&[Tok::Lit(1)]), &reloc91_none());
        fs::write(dir.join("ゲーム.exe"), &packed).unwrap();
        run(&[dir.join("ゲーム").into()]).unwrap();
        assert!(dir.join("ゲーム.olz").exists());
        fs::remove_dir_all(dir).unwrap();
    }
}
