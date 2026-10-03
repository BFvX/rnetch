# Rnetch

Rnetch 是面向 Windows x64 的按进程代理工具，使用 Rust 核心和 Electron / React 桌面界面。TCP 流量通过 SOCKS5 转发，UDP 可使用 SOCKS5 或 GPUX，支持 NetFilter 和 WinDivert 捕获后端。

## 功能

- 按进程名称配置规则，分别启用 TCP 和 UDP 代理。
- 支持 SOCKS5 无认证及用户名/密码认证。
- 支持 IPv4 / IPv6，以及 GPUX/1 UDP 隧道。
- 提供桌面配置界面、可执行文件扫描、流量图表和运行日志。
- 支持命令行运行、配置校验、便携包和安装包。

## 环境要求

- Windows x64；启动捕获驱动时需要管理员权限。
- Rust MSVC 工具链（Rust 1.85 或更高版本）。
- Visual Studio Build Tools 和 Windows SDK。
- Node.js 22，用于界面开发和打包。
- 可用的 SOCKS5 服务；使用 GPUX 时还需支持 GPUX/1 的服务端。

## 快速开始

使用编译好的程序，可从 [Releases](https://github.com/BFvX/rnetch/releases) 下载 Windows x64 桌面便携包或 CLI 包。解压后设置代理参数与进程规则，再以管理员权限启动。双后端运行包已包含 NetFilter、WinDivert 驱动和配套动态库。

以下示例使用 WinDivert。在仓库根目录执行：

~~~powershell
# 创建本地配置，保留已有文件
if (-not (Test-Path -LiteralPath config.xml)) {
    Copy-Item config.example.xml config.xml
}

# 准备驱动文件并构建核心
powershell -ExecutionPolicy Bypass -File scripts/setup-windivert.ps1
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Backend windivert

# 检查配置
.\target\release\rnetch.exe .\config.xml --backend windivert --check-config
~~~

编辑配置中的代理地址和进程规则，启动 SOCKS5 服务，再从管理员终端运行：

~~~powershell
.\target\release\rnetch.exe .\config.xml --backend windivert
~~~

按 Enter 或 Ctrl+C 停止。命令行选项可通过 `rnetch.exe --help` 查看；`--check-config` 不加载驱动。

### 桌面界面

先按上述步骤构建核心，然后执行：

~~~powershell
cd ui
npm ci
npm run dev
~~~

在界面中选择已准备的捕获后端，填写代理参数并添加进程规则，即可启动核心和查看流量。开发模式使用仓库根目录的 `config.xml`；首次运行会从示例初始化，已有配置保留。发布版在用户数据目录保存配置。

## 配置

默认配置示例为 [config.example.xml](config.example.xml)。本地 `config.xml` 已被 Git 忽略。

~~~xml
<config>
    <backend type="windivert" />
    <udp_transport type="socks5" />
    <socks5 host="127.0.0.1" port="10808" user="" pass="" />
    <rules>
        <rule names="game.exe,launcher.exe" tcp="1" udp="1" />
    </rules>
</config>
~~~

`name` 指定单个进程，`names` 可列出逗号分隔的多个进程。进程名称匹配忽略大小写；核心支持 `*`、`?` 通配符及路径模式，界面规则使用 `.exe` 文件名。命令行 `--backend` 可覆盖配置中的捕获后端。

### 捕获后端

| 后端 | 本地依赖位置 | 准备方式 |
| --- | --- | --- |
| WinDivert | `deps/windivert/WinDivert.dll`、`WinDivert64.sys` | 运行 `scripts/setup-windivert.ps1` |
| NetFilter | `deps/nfapi.dll`、`deps/nfdriver.sys` | 运行 `scripts/setup-netfilter.ps1`，或准备自备 SDK 运行时 |

驱动文件不包含在源码仓库中。构建时使用 `-Backend windivert`、`-Backend netfilter` 或 `-Backend both` 选择要复制的运行时文件。详情见 [依赖说明](deps/README.md)。

### GPUX UDP

使用 [GPUX 配置示例](config.gpux.example.xml)，或在界面中将 UDP 传输方式设为 GPUX。客户端和服务端的 token 与加密模式须一致，默认使用 ChaCha20-Poly1305。TCP 继续使用 SOCKS5。

协议配置、MTU、批处理和 FEC 参数见 [GPUX 接入说明](docs/GPUX_INTEGRATION.md)。

## 使用说明

- 在目标程序建立连接前启动 Rnetch；切换代理后重新建立连接。
- 私网、回环、链路本地、组播和核心自身流量直连。
- WinDivert 对 IP 分片和无法明确归属进程的共享 UDP 端口采用直连处理。
- SOCKS5 UDP 分片和 GPUX 数据报分片不受支持。

## 构建与打包

仅编译核心、不复制驱动文件：

~~~powershell
cargo build --release --locked
~~~

准备好两种后端的运行时文件后，可在 `ui/` 目录打包：

~~~powershell
npm ci
npm run pack:release
npm run pack:installer
~~~

默认发布包包含两个后端，缺少运行时文件会终止。单后端包须显式选择，例如 `npm run pack:release -- -Backend windivert`。打包配置来自不含真实凭据的 `config.example.xml`。详情见 [打包说明](docs/PACKAGING_README.md)。

## 项目结构

~~~text
src/                    Rust 核心、协议与捕获后端
ui/                     Electron / React 桌面界面
examples/               Rust 示例和验收工具
scripts/                核心构建与依赖准备脚本
tools/                  协议互通验证工具
deps/                   第三方许可和来源记录
docs/                   使用与开发文档
legacy/cpp/             历史 C++ 实现及文档
.github/                CI 和 PR 模板
~~~

Cargo 定义核心构建；根目录 CMake 入口转调 Rust 构建脚本。历史 C++ 实现独立保存在 `legacy/cpp/`，不参与现行产品的构建和打包。

## 文档与贡献

- [构建与打包](docs/PACKAGING_README.md)
- [GPUX 接入](docs/GPUX_INTEGRATION.md)
- [贡献指南](CONTRIBUTING.md)
- [文档索引](docs/README.md)

## 许可证

项目自有代码和文档采用 [MIT 许可证](LICENSE)。第三方组件遵循各自许可，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
