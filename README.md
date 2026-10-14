# ulzexe

Unpacks DOS executables compressed with **LZEXE 0.90 / 0.91**. This is a single-file Rust port of
[UNLZEXE](https://github.com/thbar/demomaking/blob/master/tools/unlzexe/UNLZEXE.C) (the C original
is in `package/`). It has no external dependencies and runs on macOS, Linux and Windows.

## Build

```sh
cargo build --release          # binary: target/release/ulzexe(.exe)
cargo test
# cross-compile, e.g.
rustup target add x86_64-pc-windows-gnu && cargo build --release --target x86_64-pc-windows-gnu
```

## Usage

```sh
ulzexe GAME            # GAME.exe -> unpacked in place, original kept as GAME.olz
ulzexe GAME.EXE OUT    # writes OUT.exe, input untouched
```

If a path has no extension and doesn't exist, `.exe` is appended. The output is written to a
temporary file first and then renamed into place, so a failed run never leaves a half-written file.

## Releases

Versions follow [SemVer](https://semver.org) and are automated with
[release-please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org) on `main`:
`fix:` → patch, `feat:` → minor, `feat!:` / `BREAKING CHANGE:` → major.
Merging the generated release PR tags `vX.Y.Z` and publishes binaries for
Linux (x86_64/aarch64, gnu + static musl), macOS (Intel/Apple Silicon) and
Windows (x64/ARM64), each with a `.sha256` checksum.

## Version history

| Version | Author | Notes |
|---|---|---|
| 0.5 | Mitugu (Kou) Kurizono | Original release |
| 0.6 | David Kirschbaum (1991) | DOS country-info call fix |
| 0.7 | Alan Modra (1991) | Large files, MinBSS/MaxBSS fix |
| 0.8 | Vesselin Bontchev (1992) | `ZM` magic, detection by decompressor code |
| 0.9 | Stian Skjelstad (2019) | POSIX portability |
| 1.0 | jasimmk (2026) | Rust port: in-memory, bounds-checked, cross-platform |

LZEXE was written by Fabrice Bellard — https://bellard.org/lzexe

## License

MIT, see [LICENSE](LICENSE). The original UNLZEXE C code was released as freeware with no
license statement. Its authors are credited in the LICENSE notice.
