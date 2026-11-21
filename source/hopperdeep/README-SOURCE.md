# libhopperdeep: corresponding source and how to rebuild it

`libhopperdeep.so` (the deep1 compression library inside the Hopper APK, one copy per ABI) statically links
the Rust crate **`cabac` 0.15.0, licensed LGPL-3.0-or-later**. This directory is the complete corresponding
source for that library. It is offered under the terms of the LGPL: you may modify `cabac` (or any other
part), rebuild the library with the steps below, and use your build in place of ours.

- Source of this library (the `hopperdeep` crate, `Cargo.toml` and the pinned `Cargo.lock`):
  <https://github.com/Morexxe-sudo/wasl-ios/tree/main/source/hopperdeep>
- `cabac` itself: <https://github.com/mcroomp/cabac>, or crates.io `cabac 0.15.0`
  (checksum `606873b80c9b424f9b6ed0cd03da139edc26d325eb9b31969ebf27c2bdd98f68` in `Cargo.lock`).
- Licence texts: [`licenses/LGPL-3.0.txt`](licenses/LGPL-3.0.txt) and [`licenses/GPL-3.0.txt`](licenses/GPL-3.0.txt)
  (the LGPL is written as an addition to the GPL, so both are provided). Licences of every other crate in the
  build are listed in [`LICENSES.md`](LICENSES.md).

## Exact toolchain used for the shipped build

| Tool | Version |
|---|---|
| rustc / cargo | 1.98.1 (48a229cea 2026-09-01), installed with rustup |
| cargo-ndk | 4.1.2 (`cargo install cargo-ndk --version 4.1.2 --locked`) |
| Android NDK | **27.2.12479018** (`$HOME/Android/Sdk/ndk/27.2.12479018`) |
| Rust targets | `armv7-linux-androideabi`, `aarch64-linux-android`, `x86_64-linux-android` |
| Host test target | `x86_64-unknown-linux-gnu` |

```sh
rustup target add armv7-linux-androideabi aarch64-linux-android x86_64-linux-android
export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/27.2.12479018"
```

## Reproducible dependency versions

`Cargo.toml` pins every direct dependency with `=x.y.z`, and `Cargo.lock` pins the whole graph (including
`cabac 0.15.0`) with checksums. Always build with `--locked` so cargo refuses to change either file:

```sh
cd android/deep
cargo build --release --locked                       # host library, bin/hopperdeep CLI
cargo test --locked                                  # unit, round-trip, hostile-input and memory-bomb tests
```

## Building the Android libraries

The release profile (in `Cargo.toml`) is `lto = true`, `opt-level = 3`, `codegen-units = 1`, `panic = "unwind"`,
`strip = "symbols"`. From `android/deep`:

```sh
cargo ndk -t armeabi-v7a -t arm64-v8a -t x86_64 \
    -o ../app/src/main/jniLibs build --release --locked
```

This writes `jniLibs/<abi>/libhopperdeep.so` for the three ABIs. The Gradle task `buildDeep` in
`android/app/build.gradle.kts` runs the same command (with `CARGO_BUILD_JOBS=4`), and `./gradlew assembleDebug`
or `assembleRelease` packages the result into the APK.

## Using a modified `cabac`

1. Get the `cabac` source (link above) and edit it.
2. In `android/deep/Cargo.toml` add
   ```toml
   [patch.crates-io]
   cabac = { path = "/path/to/your/cabac" }
   ```
3. Rebuild as above (without `--locked` for the first run, so the lock file can record the patched path).
4. Replace `lib/<abi>/libhopperdeep.so` in the APK (or rebuild the APK through Gradle) and sign it with your own key.
   The JNI entry points (`Java_app_wasl_core_Deep_*`) are unchanged, so the rest of the app needs no changes.

The wire format (`HDP1`) is documented in `docs/PROTOCOL-v2.md` section M.
