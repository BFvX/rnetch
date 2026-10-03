# Web UI Implementation and Runtime Fixes

> Historical C++ implementation notes. The current native core is Rust, launched from
> `target/release/rnetch.exe`; the UI also saves `<backend type="netfilter|windivert"/>`.
> See [Rust migration](../../../docs/RUST_MIGRATION.md) and [current packaging](../../../docs/PACKAGING_README.md)
> for maintained build/run instructions. C++ file references below describe the prior implementation.

This document records the work done to add the Electron Web UI and the related native/runtime fixes made during implementation.

## Scope

The UI adds a desktop control surface for `rnetch.exe` with:

- Start and stop controls for the native process.
- Editable `config.xml` SOCKS5 settings and process rules.
- Recursive folder scanning for `.exe` process rules with case-insensitive deduplication.
- Live TCP/UDP/total speed and byte counters.
- Runtime log display with status/error messages.
- Release-aware packaged app support added later in the packaging work.

## Files Added

The Electron app lives in `ui/`.

- `ui/package.json`: npm scripts, React/Electron/Vite dependencies, packaging config.
- `ui/scripts/dev.mjs`: starts Vite and Electron together for development.
- `ui/electron/main.js`: Electron main process, config IO, process lifecycle, native stdout parsing.
- `ui/electron/preload.js`: safe renderer bridge exposed as `window.rnetch`.
- `ui/src/App.jsx`: React UI, config editor, metrics, logs, process rules.
- `ui/src/styles.css`: desktop layout and responsive UI styling.
- `ui/vite.config.js`, `ui/index.html`, `ui/src/main.jsx`: renderer build setup.

## Native Telemetry Changes

`src/rnetch.cpp` now emits machine-readable JSON lines to stdout:

- `{"type":"status", ...}` for lifecycle and error state.
- `{"type":"metrics", ...}` once per second for TCP/UDP rates and totals.

The Electron main process consumes these events and forwards them to the renderer. Metrics are not appended to the visible runtime log, which keeps the log readable.

## Start and Stop Behavior

The UI launches:

```powershell
build\msvc-ninja-release\rnetch.exe config.xml
```

In development, paths are repo-relative. In packaged builds, paths are resolved through Electron resources and user data.

`rnetch::start` was changed from `void` to `bool` in `src/rnetch.h`, `include/rnetch/rnetch.h`, and `src/main.cpp` so startup failures can be reported cleanly.

## Configuration Defaults

The default SOCKS5 configuration was set to:

```xml
<socks5 host="127.0.0.1" port="10808" user="" pass="" />
```

The UI edits the same structure and validates:

- Host is required.
- Port must be `1` to `65535`.
- Each rule must use an `.exe` basename.
- TCP, UDP, or both must be enabled per rule.

The **Scan Folder** action searches the selected directory and all regular subdirectories. It adds
unique executable basenames without replacing existing TCP/UDP choices, skips symbolic links to
avoid recursion loops, and reports any unreadable subdirectories. Executable names containing a
comma or leading/trailing whitespace are skipped because the current XML/native rule format cannot
represent them without changing the process name.

## Driver Startup Fixes

`src/driver.cpp` was hardened for Windows service behavior:

- Existing `netfilter2` service is opened and reconfigured instead of treated as automatically valid.
- Service path/start mode is repaired with `ChangeServiceConfigA`.
- Stop/start pending states are waited on.
- `ERROR_SERVICE_MARKED_FOR_DELETE` is detected and reported as requiring reboot.
- Normal stop no longer uninstalls the driver, reducing service deletion races.

These changes addressed startup failures such as service error `1072`.

## Log Window Fixes

The runtime log originally kept receiving metrics lines and did not remain pinned to the bottom. The final behavior is:

- Metrics JSON is filtered out of the visible log.
- Log auto-scrolls while the user is at the bottom.
- Manual scrolling up freezes the view.
- Scrolling back to the bottom re-enables auto-scroll.

This is implemented with `logPinned` and `logListRef` in `ui/src/App.jsx`.

## TCP Acceleration Fixes

The EA Desktop hang was caused by local/private TCP traffic being captured by broad process rules. NetFilter rule insertion used `nf_addRuleEx(..., TRUE)`, which inserts at the head. The bypass rules were added first, then process rules were added above them, so local/private bypasses lost priority.

Fixes in `src/rnetch.cpp`:

- Local/private bypass rules are inserted after process rules so they win priority.
- Added `169.254.0.0/16` link-local bypass.
- TCP connect handling directly bypasses loopback, private, link-local, multicast, and broadcast destinations.
- TCP connect logs now include the target address for diagnosis.

This preserves UDP behavior while preventing EA local service and IPC traffic from being routed through SOCKS.

## UI Layout Fixes

Metric values could overflow their cards at narrow widths. The CSS now uses shrinkable grid tracks, `min-width: 0`, bounded rate text, and responsive font sizing in `ui/src/styles.css`.

## Development Commands

Build native:

```powershell
cmake --build build\msvc-ninja-release --parallel
```

Run the UI in development:

```powershell
cd ui
npm run dev
```

Build renderer:

```powershell
cd ui
npm run build
```

Run the UI from an elevated PowerShell or accept UAC when using a packaged build, because driver installation/start requires administrator privileges.

## Manual Verification Checklist

1. Start sing-box or another SOCKS5 server on `127.0.0.1:10808`.
2. Start the UI with `npm run dev`.
3. Click Start and verify status becomes started.
4. Confirm speed cards update during traffic.
5. Confirm runtime log does not fill with metrics.
6. Scroll log up, generate messages, and confirm it does not jump.
7. Scroll back to bottom and confirm auto-scroll resumes.
8. Launch EA Desktop and confirm local/private TCP is bypassed.
9. Stop rnetch and confirm the driver service stops without uninstalling.
10. Scan a folder containing nested `.exe` files and confirm unique names are added with TCP and UDP enabled.
11. Scan the same folder again and confirm no duplicate rules are added.
