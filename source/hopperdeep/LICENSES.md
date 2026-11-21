# hopperdeep — dependency licences

Generated from `Cargo.lock` (every package present in the pinned graph). Direct dependencies are
marked ★. This crate itself is Apache-2.0.

## Direct dependencies

| Crate | Version | Licence |
|---|---|---|
| ★ preflate-rs | 0.7.6 | Apache-2.0 |
| ★ lepton_jpeg | 0.5.8 | Apache-2.0 |
| ★ zstd | 0.13.3 | MIT (bundled C library: BSD-3-Clause / BSD-2-Clause) |
| ★ rayon | 1.11.0 | MIT OR Apache-2.0 |
| ★ jni | 0.21.1 | MIT OR Apache-2.0 |
| ★ sha2 | 0.10.9 | MIT OR Apache-2.0 |
| ★ flate2 (test/CLI fixtures only) | 1.1.11 | MIT OR Apache-2.0 |

## Transitive dependencies (Apache-2.0 / MIT / BSD / permissive)

adler2 (0BSD OR MIT OR Apache-2.0), arrayvec (MIT OR Apache-2.0), bitcode (MIT OR Apache-2.0),
bitcode_derive (MIT OR Apache-2.0), bitflags (MIT OR Apache-2.0), block-buffer (MIT OR Apache-2.0),
bytemuck (Zlib OR Apache-2.0 OR MIT), byteorder (Unlicense OR MIT), bytes (MIT), cc (MIT OR
Apache-2.0), cesu8 (Apache-2.0/MIT), cfg-if (MIT OR Apache-2.0), combine (MIT), cpu-time
(MIT/Apache-2.0), cpufeatures (MIT OR Apache-2.0), crc32fast (MIT OR Apache-2.0), crossbeam-deque
(MIT OR Apache-2.0), crossbeam-epoch (MIT OR Apache-2.0), crossbeam-utils (MIT OR Apache-2.0),
crypto-common (MIT OR Apache-2.0), default-boxed (MIT), default-boxed-derive (MIT), deranged
(MIT OR Apache-2.0), digest (MIT OR Apache-2.0), either (MIT OR Apache-2.0), find-msvc-tools
(MIT OR Apache-2.0), generic-array (MIT), getrandom (MIT OR Apache-2.0), git-version
(BSD-2-Clause), git-version-macro (BSD-2-Clause), glam (MIT OR Apache-2.0), jni-sys
(MIT OR Apache-2.0), jni-sys-macros (MIT OR Apache-2.0), jobserver (MIT OR Apache-2.0), libc
(MIT OR Apache-2.0), log (MIT OR Apache-2.0), memchr (Unlicense OR MIT), miniz_oxide (MIT OR
Zlib OR Apache-2.0), pkg-config (MIT OR Apache-2.0), proc-macro2 (MIT OR Apache-2.0), quote
(MIT OR Apache-2.0), rayon-core (MIT OR Apache-2.0), rustversion (MIT OR Apache-2.0), safe_arch
(Zlib OR Apache-2.0 OR MIT), same-file (Unlicense/MIT), serde (MIT OR Apache-2.0), serde_core
(MIT OR Apache-2.0), serde_derive (MIT OR Apache-2.0), sha2 (see direct), shlex
(MIT OR Apache-2.0), simd-adler32 (MIT), syn (MIT OR Apache-2.0), thiserror
(MIT OR Apache-2.0), thiserror-impl (MIT OR Apache-2.0), thread-priority (MIT), typenum
(MIT OR Apache-2.0), version_check (MIT/Apache-2.0), walkdir (Unlicense/MIT), wide (Zlib OR
Apache-2.0 OR MIT), winapi (MIT/Apache-2.0), winapi-util (Unlicense OR MIT), windows-sys
(MIT OR Apache-2.0), windows-targets (MIT OR Apache-2.0), unicode-ident
((MIT OR Apache-2.0) AND Unicode-3.0).

## Licence exceptions — READ BEFORE SHIPPING

The pinned versions required by the v0.7 plan pull in two licences that are **not**
Apache-2.0/MIT/BSD. They are recorded here rather than hidden:

- **`cabac` 0.15.0 — LGPL-3.0-or-later.** Required transitively by both `preflate-rs` and
  `lepton_jpeg` (their corrections stream uses the CABAC arithmetic coder). It is statically linked into
  `libhopperdeep.so`, so the LGPL obligations apply: `README-SOURCE.md` gives the corresponding source,
  the exact toolchain and the relink instructions, `licenses/` holds the LGPL-3.0 and GPL-3.0 texts, and the
  app's Settings > About > Open-source licences screen names it and points to the source. No alternative
  version is available for the pinned crate versions. (C1 requirement "Apache-2.0/MIT/BSD only" cannot be met
  with these two crates.) `cabac`'s own NOTICE also records parts derived from libde265 (LGPL-3.0) and
  libwebp (BSD-3-Clause).
- **`zlib-rs` 0.6.8 — Zlib** and **`r-efi` 6.0.0 — (MIT OR Apache-2.0 OR LGPL-2.1-or-later)**.
  Both are permissive/Optional and `r-efi` is not compiled for Android targets.
- The zstd C library included by `zstd-sys` is BSD-2-Clause/BSD-3-Clause, which is in scope.

## Notable notices

- preflate-rs and lepton_jpeg are © Microsoft Corporation, Apache-2.0, and incorporate third-party
  material; their `NOTICE.txt` files ship in the crates.
- The bundled zstd C sources are © Meta Platforms, Inc. and contributors, BSD-3-Clause.

## Build notes (v0.7 C2)

- The release profile adds `strip = "symbols"` so the shipped cdylibs carry no debug symbols;
  JNI exports live in `.dynsym` and survive stripping. The codec behaviour is unchanged.
- `cargo ndk` cross-compiles `hopperdeep` for **armeabi-v7a**, **arm64-v8a** and **x86_64** (armeabi-v7a was
  dropped for a while in C2 to save APK size and is restored: 32-bit ARM phones keep native zstd and deep1;
  the APK size is reported in `docs/plans/v0.7-C-log.md`). Exact toolchain and commands: `README-SOURCE.md`.
- The libs link only against system `libc.so`/`libdl.so`; no bundled C++ runtime is required.
- Generated `.so` files under `android/app/src/main/jniLibs/` and the host lib under
  `android/deep/target/` are build outputs and are git-ignored. The LGPL `cabac` blocker above
  remains open and is not affected by any of these build choices.
