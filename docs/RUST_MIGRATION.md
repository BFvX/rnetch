# Rust migration and driver acceptance

## Implementation

The production executable is built by Cargo from `src/main.rs` and `src/lib.rs`. No C++ shim, C++ compiler or NetFilter import library is used by the Rust core. Visual Studio's MSVC linker and Windows SDK remain build prerequisites. Historical C++ files and notes are retained under `legacy/cpp/` solely for comparison; CMake delegates to the Rust build script. NetFilter ABI reference headers, when provisioned locally, are in ignored `deps/netfilter/include/`; they are not needed for Cargo builds or tests.

Shared Rust modules cover XML configuration, process matching, SOCKS5 authentication / CONNECT / UDP ASSOCIATE, byte counters and line-delimited JSON telemetry. Both driver backends use bounded connection queues, owned socket/driver handles and explicit worker shutdown. DLLs are dynamically loaded from explicit absolute paths.

NetFilter uses the bundled SDK's packed C API. It pends connection requests while SOCKS5 connects on workers, redirects selected TCP connections to per-flow local listeners, forwards UDP using copied SDK options, and releases workers before unloading the DLL. TCP uses ordinary Winsock streams with bounded duplex buffers and half-close propagation; it does not depend on `NF_OFFLINE` or TCP data injection. SDK process-name rules prefilter candidates, with Rust matching as the final decision. Existing running `netfilter2` services are retained; a service started by this instance is stopped when it exits. A callback panic marks the runtime failed and requests shutdown.

WinDivert uses the NETWORK layer with IP Helper TCP/UDP tables to identify process ownership. TCP SYNs create distinct translation entries and are reflected into local IPv4/IPv6 listeners; responses are reverse-translated and checksummed. Each selected UDP endpoint has a SOCKS5 association; responses are reconstructed as IP/UDP packets and injected inbound. Process ownership is checked without a UDP port cache to avoid reusing a stale PID. The local SOCKS5 process is identified from its TCP connection and bypassed to prevent recursive proxying under broad rules.

The Electron UI persists the backend as `<backend type="netfilter|windivert"/>`, launches `target/release/rnetch.exe`, and consumes the original traffic fields. Missing backend elements default to NetFilter. An explicit CLI override takes precedence over the selected valid XML backend.

## Boundaries

- Windows x64 only for interception. Standard TCP/UDP IPv4 and IPv6 paths are implemented.
- Local/private/link-local/multicast destinations and the core's own traffic bypass proxying. Process lookup failure and ambiguous shared UDP ownership also bypass.
- Start WinDivert before the target establishes TCP connections. Existing TCP connections are not migrated mid-stream.
- IP fragments, unsupported IPv6 extensions/IPsec and jumbo datagrams bypass packet proxying. This is an acceleration tool, not a no-leak firewall.
- NetFilter preserves legacy TCP direct fallback when SOCKS5 connection/authentication fails. Failed selected UDP associations discard queued stale datagrams, then retry on fresh traffic with a bounded backoff (250 ms to 2 s), retaining the application's endpoint. WinDivert does not fall back to direct transmission after a flow has been selected.
- SOCKS5 supports no-authentication or username/password. It does not implement GSSAPI or SOCKS5 UDP fragment reassembly. Invalid/fragmented UDP frames are discarded without closing a healthy association; reply sources must be IP addresses. The relay IP family must match the advertised UDP client endpoint.
- A WinDivert UDP association expires after 60 seconds without traffic. State and queues are bounded; overload may drop UDP datagrams or refuse new proxy connections.

## Automated validation

```powershell
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Backend both
.\target\release\rnetch.exe .\config.xml --check-config
.\target\release\rnetch.exe .\config.xml --backend windivert --check-config
cd ui
npm test
npm run build
```

Tests cover legacy XML and backend validation, process matching and private bypass, fragmented SOCKS5 replies and authentication downgrade rejection, local mock TCP/UDP proxies, malformed UDP framing, TCP half-close, NetFilter packed ABI, WinDivert address ABI, IP/UDP packet parsing, TCP address translation, flow isolation/expiry and Windows process-owner lookup. These tests do not install or start either driver.

WinDivert runtime provenance is recorded in `deps/windivert/SOURCE.json`; retain its accompanying license and notices when distributing. Setup verifies Authenticode, and validates an independent expected hash if supplied or published. The recorded observed hash alone is not claimed as independent verification.

## Driver smoke tests (administrator terminal)

Use an isolated machine or development environment with no other Rnetch instance running. The optional smoke harness launches a separate local mock SOCKS5 process, selects only its test executable, and checks TCP/UDP echo against TEST-NET destinations. It does not depend on a real Internet echo endpoint.

```powershell
cargo run --example driver_smoke -- --help
cargo run --example driver_smoke -- --self-test
# Build runtime assets first; the following commands actually load the selected driver:
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Backend both
cargo run --example driver_smoke -- --run --backend netfilter
cargo run --example driver_smoke -- --run --backend windivert
```

Inspect the harness help for its exact core path and options. The live test must confirm positive TCP/UDP byte metrics, stop by Enter, and a zero exit status. Repeat after a previous run to detect lingering handles or services. A missing elevation / unsupported driver error is not a passing live test.

For broader acceptance, use this matrix with your real SOCKS5 service:

| Scenario | Configuration / action | Expected evidence |
| --- | --- | --- |
| TCP and UDP for each backend | `game.exe`, TCP+UDP, SOCKS5 `127.0.0.1:10808` | Proxy-side logs, correct echoed payloads, nonzero upload/download counters |
| IPv6 | Same rule, routed public IPv6 target | Correct IPv6 destination and response source, no truncation |
| Authentication | Correct credentials, then deliberately invalid credentials | Correct case connects; invalid case reports rejection with documented fallback behavior |
| Rule isolation | Enable only TCP, then only UDP; run another executable | Only enabled protocol for selected process is proxied |
| Local traffic | Connect selected process to LAN/loopback | Local connection succeeds directly; no proxy byte increment |
| Proxy loop prevention | Broad process pattern including local proxy process | Upstream proxy connections are not recursively intercepted |
| Lifecycle | Close target sockets, restart target, press Enter during traffic, restart core | Bounded shutdown, no crash or orphan worker; subsequent start works |
| Driver state | Run once with service absent/stopped, then with it prestarted | Record prior/after service state; pre-existing service is not deleted |
| Failure | Missing DLL, no elevation, unavailable proxy, closed UDP control socket | Clear error, appropriate flow failure, no misleading successful lifecycle status |
| UI/package | Switch backend, save/reload, start/stop from packaged app | Chosen backend persists; status stays active and metrics update |

At migration validation time (2026-10-02) the host execution token was not an administrator, both inside and outside the execution sandbox. All 27 Rust tests (including the smoke example's mock test), strict Clippy, formatting, Release build, original 33-rule config checks for both backend selections, and 14 frontend tests passed. The isolated child-process SOCKS5 self-test passed with positive TCP/UDP byte counts and no driver loaded. Startup was also attempted with an isolated `rnetch-validation-sentinel.exe` rule: both runtimes loaded their API symbols and correctly returned Windows error 5 (access denied), with nonzero exit status, before any forwarding began. This verifies the non-administrator error path; it is not a passing driver smoke test. Elevated real-driver forwarding remains a separate acceptance step.

The completed release is `ui/release/Rnetch-Control-0.2.0-win-x64-both.zip` (122,540,200 bytes; SHA-256 `c3b4fac00876719db7b13082156994bf95fd99733868d2e008b25c1bbe445349`). The packaged Rust version, both backend configuration checks, runtime/license entries, WinDivert driver signature and Electron administrator manifest were verified. NSIS is supported by the script but was not built during this migration.

## NetFilter stability follow-up (0.2.1)

The user reports stable BF6 lobby/matches with WinDivert, but intermittent lobby entry and disconnects after a few seconds with NetFilter, without frontend warnings. Code inspection found several NetFilter transport defects; these are not yet a confirmed root cause of the live game failure:

- TCP forwarding began before the SDK's `tcpConnected` event. Wait for this event before injecting server-first data, and report a bounded timeout if it never arrives.
- Application EOF only shut down the SOCKS socket. Acknowledge it with `nf_tcpPostSend(id, NULL, 0)` after all earlier bytes are written; continue receiving through the peer's EOF. Do not call `nf_tcpClose` on graceful completion, because the SDK documents that it aborts pending I/O. Keep session state until `tcpClosed` so late callbacks cannot forward an offline stream directly.
- A small, fixed message queue could overflow on bursts of tiny writes. Suspend/resume SDK indications at high/low watermarks based on both bytes and message count, retaining bounded headroom for in-flight callbacks.
- UDP replies reused the last outgoing packet's opaque SDK options regardless of peer. Keep a bounded per-peer route/options cache and restore mapped IPv6 addresses for dual-stack endpoints. Normalize mapped IPv4 destinations to native IPv4 in SOCKS requests.
- A single UDP association error permanently marked the game's socket closed. Keep the endpoint alive and allow subsequent datagrams to re-establish SOCKS, with failure/recovery logs and cancellable bounded backoff.

The SDK contracts used for TCP shutdown and backpressure are [nf_tcpClose](https://www.netfiltersdk.com/help/nfsdk2/nfapi_nf_tcpClose.htm), [nf_tcpPostSend](https://www.netfiltersdk.com/help/nfsdk2/nfapi_nf_tcpPostSend.htm), and [nf_tcpSetConnectionState](https://www.netfiltersdk.com/help/nfsdk2/nfapi_nf_tcpSetConnectionState.htm). No SDK binary was replaced. The official 1.7.8.2 sample archive was inspected under `build/` only; it is not a runtime or package input.

New driver-free tests exercise actual NetFilter callbacks/workers against local SOCKS peers and a mock SDK boundary: delayed connection readiness, application half-close with a 100 KB trailing response, receive backpressure, absence of an abort on graceful completion, burst ordering/suspension, per-peer IPv4/IPv6 options, and recovery on the same UDP endpoint after control-socket closure. These checks cannot verify real SDK/kernel delivery or BF6 stability; repeat the game lobby/match scenario using the same rules and SOCKS endpoint, after starting the updated NetFilter core and relaunching the game.

Validation on 2026-10-03: formatting, all 31 Rust tests, strict Clippy, all 14 frontend tests, Release core build, Vite production build, and both 33-rule configuration checks passed. The current execution token remains non-administrator; no live driver/game test was performed for this update. The new package is `ui/release/Rnetch-Control-0.2.1-win-x64-both.zip` (119,038,399 bytes; SHA-256 `65262d3db6640e98eba04b89354fd4058489806b6673f80782e01a9668141227`). Its core reports version 0.2.1; both backend configuration checks pass. Packaged runtime hashes match the build/vendored files, and the administrator manifest and required ZIP entries were verified. Portable unpacked output is now staged per version/backend so an older running UI need not be stopped to build a new package.

## Live investigation and TCP redirection (0.2.2)

The user subsequently reported `NetFilter TCP 404 -> 54.229.241.81:443: Timed out waiting for NetFilter tcpConnected` at 07:46:59 on 2026-10-03. That warning is generated after SOCKS CONNECT succeeded: the 0.2.1 readiness gate then waited ten seconds and aborted the flow. It is not evidence that the SOCKS server refused the connection. The mocked SDK tests in 0.2.1 could not establish whether the real bundled driver would emit this event on every offline connection.

Read-only inspection of the running system established:

- The active UI/core were from the 0.2.1 package, using NetFilter, 33 process rules, and SOCKS5 `127.0.0.1:10808` without authentication. `bf6.exe` enabled both TCP and UDP. The SDK process-name lookup successfully identified the running game.
- The current game process started at 07:48:22; the current core started at 07:49:37. The UI showed cumulative 0 B, and socket snapshots around 08:00 found three game TCP connections and two game UDP endpoints but no core TCP/UDP sockets. This means that snapshot did not show successful interception; it cannot identify why an earlier connection failed. Existing game sockets and restarting the core complicate reproduction.
- The active `netfilter2` service path pointed at the same bundled driver as the package. SYS version is 1.6.3.0; DLL version is 1.5.1.7. SYS SHA-256 is `4af6f672119f4f13e33b8914630eedea97d299b5c92c2105a4015dd0ca6e933e`; DLL SHA-256 is `f0519b24f076f52f12353d955ef89863963b5988130233673f2f4a4445e842cc`.
- The signed SYS contains `driver_wfp\\msvc\\Win8ReleaseDemo\\x64\\netfilter2.pdb`. This is evidence of a demo build. The [vendor's download page](https://www.netfiltersdk.com/download.html) documents TCP/UDP endpoint limits and recovery only after a system reboot. Neither endpoint ID 404 nor this marker proves that the limit was reached in this run. Replacing application code cannot remove a driver licensing limit.
- A Leigod `nfwfp.sys` driver and an older WinDivert service were also loaded. Their presence alone does not prove a conflict. Neither was stopped or modified, and the game was not closed during inspection.

The new TCP path follows the vendor's WFP `SocksRedirector` sample: connect SOCKS on the worker, bind a local listener of the original address family, complete the pending request with its remote address pointing at that listener, set the process ID to the relay owner and filtering flag to `NF_ALLOW`, then relay real sockets. It no longer waits for `tcpConnected` or injects offline TCP data. Mapped IPv6 listeners explicitly disable `IPV6_V6ONLY`, accepted peers are checked against the original local endpoint, and both relay directions retain at most 32 KiB. Tests cover server-first data, both directions of half-close, backpressure, cancellation, source rejection, mapped IPv6, and integration with a real mock SOCKS peer without SDK connected/data callbacks.

Driver rules now contain per-protocol process-name masks instead of broad system-wide filtering. The SDK's tail-mask semantics are documented in [NF_RULE_EX](https://www.netfiltersdk.com/help/nfsdk_wfp/ref_NF_RULE_EX.html); path patterns are conservatively reduced to basenames and `?` is widened to `*`, then Rust performs the exact final match. This is normal process isolation, not a workaround for demo limits. The driver marker is reported at startup, and low-frequency callback/selection/redirection/accept counters expose where forwarding stops.

Electron saves existing visible log entries to `%APPDATA%/rnetch-ui/logs/rnetch.log` (5 MiB plus one rotated `.1` file). It serializes only time, level and line, not configuration objects or metrics. Logging is asynchronous, bounded and failure-isolated. A future game test should start the new core before creating game connections and retain this log. Real WFP/game acceptance remains separate from driver-free tests; the diagnostic shell still has a non-administrator Windows token.

Validation on 2026-10-03: formatting, all 41 Rust tests (39 library, one CLI, one smoke-example mock), strict Clippy, all 20 frontend tests, Release core build, Vite production build, and both 33-rule configuration checks passed. The release is `ui/release/Rnetch-Control-0.2.2-win-x64-both.zip` (119,046,341 bytes; SHA-256 `f8fdf644b9d154f2bb1f2b94e001834f7db5a503dfefa9a65a46f25e9cef8aaf`). The packaged core reports 0.2.2; required archive entries, runtime hashes against build inputs, and the administrator manifest were verified. Neither SDK binary was replaced, and neither the running game nor driver services were stopped. The 0.2.2 path has not yet been tested with the real driver/game.
