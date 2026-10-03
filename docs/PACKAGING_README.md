# Rust / Electron packaging

The runtime core is Rust. Install the x64 MSVC Rust toolchain, Visual Studio Build Tools / Windows SDK, and Node.js. CMake and Ninja are not required by the packaging workflow.

## Prepare and build

From the repository root:

```powershell
# On a fresh checkout only; preserve an existing local config:
if (-not (Test-Path -LiteralPath config.xml)) { Copy-Item config.example.xml config.xml }
# Provision NetFilter locally as described in deps/README.md before building both.
powershell -ExecutionPolicy Bypass -File scripts/setup-windivert.ps1
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Backend both
cargo test --all-targets --locked
.\target\release\rnetch.exe .\config.xml --check-config
cd ui
npm ci
npm test
npm run pack:release
```

`build.ps1` defaults to `auto`: it requires NetFilter and copies WinDivert when its pair is present. Explicit values are `netfilter`, `windivert`, and `both`. No build or setup step loads a kernel driver. `setup-windivert.ps1` accepts a local archive and optional expected hash; verifies the driver signature and records the official source, version, actual SHA-256 and verification method. An observed download hash is not represented as an independently published checksum.

SDK DLL/SYS files are local dependencies excluded from Git. See [dependency preparation](../deps/README.md). A fresh checkout with only WinDivert must build with `-Backend windivert`; plain Cargo builds and CI checks need no SDK files.

`pack:release` defaults to **both** and fails if required files are missing. To distribute only one backend, explicitly use:

```powershell
npm run pack:release -- -Backend netfilter
npm run pack:release -- -Backend windivert
npm run pack:installer
```

The packaging script builds the Rust core and frontend, stages a fresh selected set in `build/package-resources/`, and packages that directory. The staged default always comes from tracked `config.example.xml`, never the user's local `config.xml`. A single-backend package selects its backend in the staged default XML. Existing user-data configurations are retained.

## Artifacts

The ZIP at `ui/release/Rnetch-Control-<version>-win-x64-both.zip` contains the Electron application and:

```text
resources/app.asar
resources/config.xml
resources/LICENSE-rnetch
resources/THIRD_PARTY_NOTICES.md
resources/native/rnetch.exe
resources/native/nfapi.dll               # NetFilter selection
resources/native/nfdriver.sys            # NetFilter selection
resources/native/NetFilter-NOTICE.txt
resources/native/NetFilter-SOURCE.json
resources/native/WinDivert.dll           # WinDivert selection
resources/native/WinDivert64.sys         # WinDivert selection
resources/native/WinDivert-LICENSE
resources/native/WinDivert-README
resources/native/WinDivert-VERSION
resources/native/WinDivert-CHANGELOG
resources/native/WinDivert-SOURCE.json
resources/native/WinDivert-CORRESPONDING_SOURCE.json
resources/native/WinDivert-2.2.2-source.zip
resources/native/licenses/INDEX.txt
```

Single-backend filenames end with `-netfilter.zip` or `-windivert.zip`. NSIS output ends with `-<backend>-setup.exe`. ZIP creation uses electron-builder's unpacked directory output, Windows SDK `mt.exe` to set `requireAdministrator`, then `scripts/create-zip.ps1`. The ZIP writer includes hidden files and clamps timestamps to ZIP's supported range without modifying input files. Every external command is checked for failure. Keep Vite `base: './'` for packaged `file://` assets.

Development launches `target/release/rnetch.exe` with root `config.xml`, initialized from `config.example.xml` when missing. Packaged execution launches the resource copy and uses `%APPDATA%/Rnetch Control/config.xml` (copied from the packaged default only on first run). DLLs and their matching driver files must remain together.

Before distribution, run the driver acceptance matrix in [RUST_MIGRATION.md](RUST_MIGRATION.md), inspect native files and licenses, check UAC elevation and start/stop behavior, and verify that packaged configuration contains no real proxy credentials. Existing archives under `ui/release/` are not automatically evidence of the current Rust build; rebuild them with the command above.

Project-owned code is [MIT-licensed](../LICENSE). The core build copies `rnetch-LICENSE` and `THIRD_PARTY_NOTICES.md` to `target/release/`; Electron packaging includes the same project license and third-party notice in `resources/`. WinDivert packages include its corresponding source, license and replacement instructions. NetFilter packages include the vendor copyright notice and pinned runtime provenance. See [third-party notices](../THIRD_PARTY_NOTICES.md).

## GitHub Releases

After creating the portable package, prepare the CLI package, source archive and checksums from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/prepare-release.ps1 -ReleaseTag v0.2.2
```

Artifacts are written to `build/release-assets/`. The core version, UI version and release tag must agree. The source archive uses the current Git commit; commit release changes before preparing the final archives.

Pushing a `v<version>` tag runs `.github/workflows/release.yml`. It prepares fixed, checksum-verified runtimes, runs Cargo and UI checks, builds both-backend packages and publishes a prerelease with the notes in `docs/releases/v<version>.md`. Every uploaded asset is checked against GitHub's recorded size and SHA-256 before publication. The workflow does not install or load either capture driver.

The workflow also records its result and verified Release metadata in Git notes. Maintainers using SSH can inspect the result without an API token:

```powershell
git fetch origin refs/notes/rnetch-releases:refs/notes/rnetch-releases
git notes --ref=rnetch-releases show 'v0.2.2^{}'
```

