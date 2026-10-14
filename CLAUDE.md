# CLAUDE.md

Rust port of UNLZEXE: unpacks DOS executables compressed with LZEXE 0.90/0.91.

## Commands

```sh
cargo test                                   # all tests (unit + end-to-end on temp files)
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings    # CI treats warnings as errors
cargo build --release                        # target/release/ulzexe
```

Run all three checks before considering a change done. CI runs them on Linux, macOS and Windows, plus tests on the MSRV (Rust 1.87).

## Project rules

- **Single file.** All code and tests live in `src/main.rs`. Don't split it into modules or add `tests/`.
- **No external dependencies**, including dev-dependencies. Use std only.
- **Must build and behave the same on macOS, Linux and Windows.** Use `Path`/`OsString`, never string paths. Gate platform code with `#[cfg(...)]`.
- `package/` holds the original C reference (`unlzexe.c`). It's git-ignored and read-only. Use it to check format behaviour, never edit it.

## Code invariants

- Parse from the in-memory `&[u8]` through `Reader` / `BitReader` only. Every read is bounds-checked and returns `Error::Truncated` / `Error::NotLzexe`. Never index input directly or `unwrap` on input-derived data.
- Header arithmetic copies the 16-bit C semantics: use `wrapping_*` where the original wraps (memory fields), and checked or widened math for file offsets.
- `BitReader` refills **eagerly**, as the original does. Bit and byte reads share one stream, so the order matters. A refill past EOF only errors when another bit is requested.
- Unpacking must never be able to destroy the input: write to a temp file next to the output, then `fs::rename` (it replaces atomically on all OSes). In-place mode renames the input to `.olz` first and restores it on failure.
- Print user messages with `say!`, never `println!`. A panic on a closed stdout between renames would lose files (`panic = "abort"` in release).

## Tests

- Inputs are built with the test-only `Encoder` / `build_exe` helpers; there are no binary fixtures. Add a test for every bug fix and every new error path.
- File-system tests use `scratch_dir(name)` with a unique name per test, and clean up afterwards.

## Releases

- SemVer, automated by release-please from Conventional Commits on `main`: `fix:` → patch, `feat:` → minor, `feat!:` → major. Use these prefixes in commit messages.
- Pushing a `vX.Y.Z` tag or running the Release workflow manually builds the binaries for 8 targets. The tag must match `version` in `Cargo.toml`.
- Never edit `CHANGELOG.md` or the version in `.release-please-manifest.json` by hand.

## Credits & license

MIT (jasimmk). Keep the version-history comment at the top of `main.rs`, the README table and the LICENSE notice crediting the original C authors in sync.
