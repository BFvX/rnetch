# Rust core and driver acceptance

## Implementation

The production executable is built by Cargo from `src/main.rs` and `src/lib.rs`. No C++ shim, C++ compiler or NetFilter import library is used by the Rust core. Visual Studio's MSVC linker and Windows SDK remain build prerequisites. Historical C++ files and notes are retained under `legacy/cpp/` solely for comparison; CMake delegates to the Rust build script. NetFilter ABI reference headers, when provisioned locally, are in ignored `deps/netfilter/include/`; they are not needed for Cargo builds or tests.

Shared Rust modules cover XML configuration, process matching, SOCKS5 authentication / CONNECT / UDP ASSOCIATE, byte counters and line-delimited JSON telemetry. Both driver backends use bounded connection queues, owned socket/driver handles and explicit worker shutdown. DLLs are dynamically loaded from explicit absolute paths.

NetFilter uses the bundled SDK's packed C API. It pends connection requests while SOCKS5 connects on workers, redirects selected TCP connections to per-flow local listeners, forwards UDP using copied SDK options, and releases workers before unloading the DLL. TCP uses ordinary Winsock streams with bounded duplex buffers and half-close propagation; it does not depend on `NF_OFFLINE` or TCP data injection. SDK process-name rules prefilter candidates, with Rust matching as the final decision. Existing running `netfilter2` services are retained; a service started by this instance is stopped when it exits. A callback panic marks the runtime failed and requests shutdown.

WinDivert uses the NETWORK layer with IP Helper TCP/UDP tables to identify process ownership. TCP SYNs create distinct translation entries and are reflected into local IPv4/IPv6 listeners; responses are reverse-translated and checksummed. Each selected UDP endpoint has a SOCKS5 association or GPUX session according to the configured UDP transport; responses are reconstructed as IP/UDP packets and injected inbound. Process ownership is checked without a UDP port cache to avoid reusing a stale PID. The local SOCKS5 process is identified from its TCP connection and bypassed to prevent recursive proxying under broad rules.

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
