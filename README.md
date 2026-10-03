# Rnetch

Windows x64 按进程转发网络流量的桌面工具。TCP 使用 SOCKS5，UDP 可选择 SOCKS5 或 GPUX。代理核心使用 Rust，控制界面使用 Electron / React；可选择 NetFilter 或 WinDivert 捕获驱动。

## 源码结构

```text
src/                       # 现行 Rust 核心（Cargo 标准布局）
ui/                        # 现行 Electron / React 界面
examples/                  # Rust 协议探测和驱动验收工具
scripts/                   # 核心构建与驱动文件准备
tools/                     # 当前协议互通验证工具
deps/netfilter/            # NetFilter 来源记录；SDK 头文件仅作本地参考
deps/windivert/            # WinDivert 许可证、版本与来源记录
docs/                      # 当前实现、打包与上传说明
legacy/cpp/                # 迁移前的 C++ 源码、头文件及历史文档
.github/                   # Windows CI 与 PR 模板
config.example.xml         # 不含真实凭据的默认配置
config.gpux.example.xml    # GPUX 配置示例
```

`src/` 只保存 Rust 源码。旧实现集中在 [历史 C++ 目录](legacy/cpp/README.md)，不参与现行构建。根目录 `CMakeLists.txt` 保留为转调 Rust 的兼容入口。完整文档见 [文档索引](docs/README.md)，贡献流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 构建与运行

安装 Rust 的 `stable-x86_64-pc-windows-msvc` 工具链及 Visual Studio C++ Build Tools / Windows SDK（用于链接 Windows 程序）。在仓库根目录执行：

```powershell
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
# 首次检出时创建本地配置；已有 config.xml 时保留原文件：
if (-not (Test-Path -LiteralPath config.xml)) { Copy-Item config.example.xml config.xml }
# 准备并选择 WinDivert，文件来源与校验记录由脚本保存：
powershell -ExecutionPolicy Bypass -File scripts/setup-windivert.ps1
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Backend windivert
.\target\release\rnetch.exe .\config.xml --check-config
# 在管理员终端运行，事先启动 SOCKS5 服务：
.\target\release\rnetch.exe .\config.xml --backend windivert
```

`build.ps1` 构建 Release 并复制所选运行时 DLL/驱动到 `target/release/`。SDK 二进制不进入 Git；选择 NetFilter 时需先按 [依赖说明](deps/README.md) 准备 `deps/nfapi.dll` 和 `deps/nfdriver.sys`，再使用 `-Backend netfilter`；双后端使用 `-Backend both`。单独执行 `cargo build --release --locked` 只构建 Rust 程序，无需 SDK。程序支持 Enter、标准输入 EOF、Ctrl+C 停止。配置检查、帮助和单元测试均不加载驱动。

## 驱动选择

旧配置默认 `netfilter`。在 `config.xml` 中增加后端元素，或使用命令行临时覆盖：

```xml
<config>
    <backend type="windivert" />
    <socks5 host="127.0.0.1" port="10808" user="" pass="" />
    <rules>
        <rule names="game.exe,launcher.exe" tcp="1" udp="1" />
    </rules>
</config>
```

```powershell
.\target\release\rnetch.exe .\config.xml --backend windivert
.\target\release\rnetch.exe --help
```

| 后端 | 所需文件 | 工作方式 |
| --- | --- | --- |
| NetFilter | `nfapi.dll`、`nfdriver.sys`（仓库 `deps/`） | Rust 直接调用 SDK C 接口，管理 `netfilter2` 服务，转发 TCP 流和 UDP 数据报 |
| WinDivert | x64 `WinDivert.dll`、`WinDivert64.sys`（`deps/windivert/`） | IP Helper 查询进程归属，TCP 本地转发与双向地址转换，UDP 上游转发与回注 |

两种驱动按选择动态加载，构建无需 SDK 导入库或 C++ 桥接。缺少所选后端的运行时文件时明确报错。WinDivert 文件必须来自[官方发布](https://github.com/basil00/WinDivert/releases/tag/v2.2.2)，与 DLL 同目录；`WinDivertOpen` 负责按需启动驱动，要求管理员权限。参见[官方文档](https://reqrypt.org/windivert-doc.html)。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-windivert.ps1
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Backend both
```

安装脚本只下载、校验并复制文件，不加载驱动；支持 `-ArchivePath` 和 `-ArchiveSha256` 校验指定归档。来源及实际 SHA-256 写入 `deps/windivert/SOURCE.json`。

## GPUX UDP 传输

GPUX 与 SOCKS5 属于上游传输层，两个捕获驱动共用。使用 [示例配置](config.gpux.example.xml)，或在 UI 中将 `UDP transport` 选择为 `GPUX`，填写 GPUX 服务端地址、端口和 token。客户端使用原 `rnetch_cmd_gpux` 的 GPUX/1 协议，可连接其 `gpux_server`；默认启用 ChaCha20-Poly1305，服务端须使用相同 token 和加密模式。

```xml
<udp_transport type="gpux" />
<gpux host="127.0.0.1" port="40000" token="replace-with-your-token"
      encryption="chacha20-poly1305" deadline_ms="8" mtu_payload="1200"
      batch_window_us="0" pacing_interval_us="0" queue_limit="512"
      fec_uplink="0" fec_group_max_us="2000" />
```

TCP 规则继续使用 `<socks5>`；仅启用 UDP 的 GPUX 配置可省略该元素。缺少 `<udp_transport>` 的旧配置仍使用 SOCKS5。GPUX 先完成握手，再启动捕获驱动；握手失败会报错。它使用一个共享 UDP 隧道、独立 flow 映射、有界队列、原始捕获时间计算的本地 deadline、可选批处理/pacing 和 XOR FEC。上行 FEC 由 `fec_uplink` 控制，下行 FEC 由服务端控制。默认关闭批处理、pacing 和上行 FEC，便于先验证基础链路。

超过隧道 MTU 的数据报会丢弃，当前不实现 GPUX 分片或 TCP 隧道。游戏 DATA 不进行重传；控制消息有有限重试。`plaintext` 供本地协议验证。驱动和真实游戏验收仍需管理员终端，详见 [GPUX 接入说明](docs/GPUX_INTEGRATION.md)。

## 控制界面与打包

```powershell
cd ui
npm ci
npm test
npm run dev
# 默认将两个后端一起打包；缺文件会终止：
npm run pack:release
# 也可明确只打包一种后端：
npm run pack:release -- -Backend netfilter
npm run pack:installer
```

界面保存捕获驱动、UDP 传输协议、SOCKS5/GPUX 参数和进程规则，启动 Rust 核心并显示每秒流量与状态。开发模式使用根目录 `config.xml`，发布模式在用户数据目录保存配置。详见 [打包说明](docs/PACKAGING_README.md)。

开发模式首次读取配置时会从 `config.example.xml` 创建 `config.xml`，已有配置保留。打包始终使用示例配置；本地 `config.xml`、SDK 二进制、日志和构建产物由 `.gitignore` 排除。首次上传流程见 [GitHub 上传说明](docs/GITHUB_PUBLICATION.md)。

## 行为与验证

- 保留 `name` / `names`、TCP/UDP 开关、无认证与用户名/密码认证。协议按 [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) / [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) 实现，校验消息长度与认证方法，处理分段 TCP 响应。
- 进程名忽略大小写；Rust 配置支持 `*` / `?`，包含路径的模式匹配完整路径。界面规则编辑使用 `.exe` 文件名。
- 私网、回环、链路本地、组播及核心自身流量直连；只转发规则启用的协议。
- WinDivert 应在目标程序建立连接前启动；已建立的 TCP 连接需重连。IP 分片、IPsec 传输以及无法唯一归属进程的共享 UDP 端口直连。
- SOCKS5 UDP 分片不受支持；UDP 响应需要 IPv4/IPv6 来源地址。UDP ASSOCIATE 控制连接关闭后终止该关联。
- NetFilter 保留原有 TCP 代理连接失败后直连的行为；UDP 上游失败会丢弃旧数据报，保持应用端点并在新数据到来时有界重试。WinDivert 已选中的代理连接不会因上游失败自动改为直连。
- JSON `status` / `metrics` 字段兼容原界面。Rust 测试覆盖配置、协议帧、本地模拟 SOCKS5 服务器、驱动 ABI 和数据包转换；真实驱动链路需执行 [手工验收](docs/RUST_MIGRATION.md)。

Rust 入口为 `src/main.rs`，协议和配置为 `src/{socks5,config,metrics}.rs`，UDP 上游接口在 `src/upstream.rs`，GPUX 实现在 `src/gpux/`，驱动在 `src/backend/`。禁止把真实代理凭据写入提交或发布配置。

## 许可与第三方依赖

项目自有 Rust、Electron/React、历史 C++、脚本及文档采用 [MIT 许可证](LICENSE)，允许商用、修改和闭源再分发，要求保留版权及许可声明。许可选择以维护者确认这些实现独立编写、仅参考外部接口或行为为依据；第三方组件继续遵循各自许可，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

NetFilter SDK 原始头文件和二进制仅在本地准备，不进入公开源码包。其官方协议限制 SDK 源码再分发；现存文件的取得来源及适用授权仍需补齐。WinDivert 随包分发时须另行满足其 LGPLv3 等适用条款，MIT 不替代这些义务。

