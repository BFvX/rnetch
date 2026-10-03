# Repository Guidelines

## Structure

`rnetch` is a Windows x64 Rust process-selective SOCKS5 proxy with NetFilter and WinDivert backends. `src/` contains only Rust: `src/main.rs` is the CLI entry; `src/config.rs`, `src/socks5.rs`, and `src/metrics.rs` are shared code; `src/backend/` contains driver FFI, ownership and forwarding. `ui/` contains Electron/React. Historical C++ source/headers, tools and notes live in `legacy/cpp/` for reference only and are not built. NetFilter ABI reference headers live in `deps/netfilter/include/`. `Cargo.toml` / `Cargo.lock` define the production core; CMake delegates to `scripts/build.ps1`.

Runtime configuration is local, ignored `config.xml`; tracked defaults are `config.example.xml` and `config.gpux.example.xml`. Process rules live in XML. Old `ps_options.txt` and `ps_ws/` were machine-specific Polyspace analysis output and are retained under ignored `.local/polyspace/`. SDK binaries are provisioned locally in `deps/` and `deps/windivert/` and excluded from Git. NetFilter SDK headers in `deps/netfilter/include/` are also local, ignored references because SDK source redistribution is restricted; preserve their notices and tracked provenance records. Build products live in `target/`, `build/`, `ui/dist/`, and `ui/release/`; do not edit generated artifacts by hand.

## Build and validation

Use Rust MSVC x64 and Visual Studio Build Tools / Windows SDK.

```powershell
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
powershell -ExecutionPolicy Bypass -File scripts/build.ps1
.\target\release\rnetch.exe .\config.example.xml --check-config
cd ui
npm test
npm run build
```

Run `.\target\release\rnetch.exe .\config.xml --backend netfilter` or `--backend windivert` from an elevated terminal. Enter / stdin EOF / Ctrl+C stops the core. `--check-config` must never load a driver. Driver smoke tests affect host networking; document the selected backend, configuration rules, SOCKS5 endpoint, TCP/UDP and IP families, and prior driver state. See `docs/RUST_MIGRATION.md` for the manual matrix.

Fresh checkouts can run Cargo/UI checks without SDK binaries. To build with runtime files, follow `deps/README.md`; select `-Backend windivert` explicitly if only that runtime is prepared. Development UI initializes a missing `config.xml` from `config.example.xml`; packaging always uses the tracked example, never the local config.

## Style and safety

Use `cargo fmt`, snake_case functions/locals and PascalCase types. Prefer RAII, bounded queues, explicit worker shutdown/join and small documented unsafe FFI boundaries. Match ABI packing, calling convention and buffer lifetimes to the vendored SDK headers or official WinDivert headers. Never unwind through C callbacks. Avoid network operations in driver callbacks; preserve per-flow packet order. Keep UI configuration and CLI validation consistent.

## Changes and releases

Project-owned code and documentation are MIT-licensed (root `LICENSE`). Third-party code retains its own terms. Do not apply MIT to NetFilter SDK headers/binaries, WinDivert or TinyXML2. Include project and applicable third-party notices when distributing; see `THIRD_PARTY_NOTICES.md`.

Use concise imperative commit messages. PRs explain changed behavior, implementation, commands run, test limits, and any replaced SDK source/checksum. No Git history was present at migration time. Do not commit real SOCKS5 credentials. Do not replace SDK binaries silently; preserve their license notices and record provenance. Packaging defaults to both backends and must fail if their required runtime files are absent; a single-backend package must be explicitly selected.

