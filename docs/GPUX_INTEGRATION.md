# GPUX 接入

## 结构与配置

`src/backend/` 负责 NetFilter / WinDivert 捕获、进程筛选、流量回注；`src/upstream.rs` 负责统一的 UDP 会话接口。`src/gpux/` 在 Rust 中实现兼容 `rnetch_cmd_gpux` 的 GPUX/1 协议，不链接历史 C++ 核心，也不新增驱动后端。SDK 的 endpoint/options 和 WinDivert 的包元数据留在各自适配层。

UI 分开保存 Capture driver 与 UDP transport。旧 XML 默认 SOCKS5，新增 `<udp_transport type="gpux"/>` 后 UDP 走 GPUX，TCP 仍走 `<socks5>`。仅 UDP 的 GPUX 规则可省略 SOCKS5；混合 TCP/UDP 规则须配置二者。示例为根目录 `config.gpux.example.xml`；正常 `config.xml` 不会被接入过程替换。

配置参数与 CLI/UI 校验一致：

| 字段 | 默认值 | 范围/含义 |
| --- | --- | --- |
| host / port | 127.0.0.1 / 40000 | GPUX 服务端地址；端口 1..65535 |
| token | 空，启用 GPUX 时必填 | 1..255 UTF-8 字节，无 NUL |
| encryption | chacha20-poly1305 | 与服务器一致；plaintext 用于本地验证 |
| mtu_payload | 1200 | 完整隧道 UDP 负载上限，128..65507 字节 |
| deadline_ms | 8 | 从驱动截获时计算的本地发送预算，1..1000 ms |
| batch_window_us | 0 | 微批处理窗口，0..1000000 µs |
| pacing_interval_us | 0 | DATA 发送间隔，0..1000000 µs |
| queue_limit | 512 | 有界队列限制，1..65536 |
| fec_uplink | 0 | 0 关闭，1 启用上行最多 4+1 XOR FEC |
| fec_group_max_us | 2000 | 部分 FEC 组刷新窗口，1..1000000 µs |

下行 FEC 由服务器决定，客户端可解码。每次隧道启动生成随机 connection ID；加密格式、nonce 域、SHA-256 派生和包布局与原 C++ 服务端一致。所有 socket I/O 在一个专用 worker 中执行，停止时先释放捕获与转发 worker，再关闭隧道并 join。

## 无驱动互通验证

原 C++ 服务端只作为外部验证对象，不是当前客户端的运行时依赖。测试仅绑定回环地址，不加载驱动，不读取个人配置或连接公网服务器：

```powershell
cargo build --example gpux_probe --locked
python tools/verify_gpux_interop.py --server-exe C:\path\to\gpux_server.exe
```

验证程序启动 IPv4/IPv6 UDP echo、一个隧道中继和原版服务端，再运行 Rust probe。每轮两个本地会话各联系两个目标，检查 48 个原样响应与来源、会话隔离和 FLOW_CLOSE/CLOSE 生命周期。矩阵包含明文、加密、批处理/pacing，以及明文/加密两种 FEC 模式；FEC 轮次主动在上下行每组丢弃一个 DATA 源包。

也可连接已启动的本地服务器和 echo 目标：

```powershell
cargo run --example gpux_probe -- config.gpux.example.xml 127.0.0.1:50000 "[::1]:50001"
```

先将示例中的服务器地址/端口/token 修改为该测试服务的值。不要把真实 token 写入版本管理或公开日志。

## 限制与真实验收

GPUX 当前仅承载 UDP，DATA 不做 ARQ 重传，也不实现隧道分片；超过 MTU 的单个数据报会丢弃。FEC 额外保留校验包元数据所需空间，因此启用 FEC 时可承载的单个游戏数据报更小。TTL 包含本地排队和接收恢复等待，不是跨主机同步时钟的绝对到达期限。

本地 deadline 可能丢弃建立新 flow 时等待控制确认的旧游戏帧，这是时效策略的一部分。客户端在目标闲置 30 秒后重开 flow，以适配原服务端默认 45 秒的静默清理；服务端应保留至少这一默认闲置窗口。共享隧道 worker 的致命错误会终止核心并在 UI 报错，需要重启核心；当前不自动重连整个隧道。真实配置需根据目标游戏和链路测试，不能由本地 echo 成功推断低延迟收益或稳定性。

管理员真实验收时分别记录捕获驱动、进程规则、SOCKS5/GPUX 节点、TCP/UDP、IPv4/IPv6 和原驱动状态。检查游戏登录 TCP、UDP 对局、进程隔离、回环/私网旁路、重启和停止；不要在已经运行的游戏中途切换驱动作为唯一验证。参照 `docs/RUST_MIGRATION.md` 的手工矩阵。

## 2026-10-03 接入验证

- `cargo fmt --all -- --check`、`cargo test --all-targets --locked`（64 个库测试、1 个 CLI 测试、1 个原 SOCKS5 smoke mock）、`cargo clippy --all-targets --locked -- -D warnings` 通过。
- `powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Backend both` 通过，Release 核心与两个既有驱动运行文件已准备好；未替换 SDK 来源文件。
- UI 的 `npm test` 25 项通过，`npm run build` 通过。
- 正常 33 条规则配置与 GPUX 示例分别以 NetFilter/WinDivert 执行 `--check-config`，四次通过；配置检查不解析节点、不加载驱动。
- Rust 客户端与 `rnetch_cmd_gpux/build/msvc-ninja-release/gpux_server.exe` 的五轮回环互通全部通过，每轮 48 个响应。明文与加密 FEC 轮次均在上下行主动丢弃 DATA 源包并完整恢复。
- 原版未修改的 C++ 协议代码生成的固定字节向量验证 Rust 帧格式、密钥/nonce、IPv4/IPv6 与完整/部分 XOR FEC。NetFilter mock SDK 回归验证同一端点多目标的 SDK options 和原始地址族。
- 本次未加载捕获驱动、未连接公网 GPUX 节点、未执行真实游戏或延迟收益测试。根目录原 `config.xml` 保持原运行配置。原先打出的 0.2.2 安装包不包含这次源码改动；试用当前构建请在 `ui` 目录运行 `npm run dev`。
