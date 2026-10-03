# 贡献指南

当前维护的程序核心位于 `src/`，使用 Rust；Electron / React 界面位于 `ui/`。迁移前的 C++ 实现保存在 `legacy/cpp/`，仅供历史参考，不参与构建。`deps/netfilter/include/` 是驱动 ABI 参考头文件，不属于旧程序实现。

## 开发环境

使用 Windows x64、Rust MSVC 工具链（Rust 1.85 或更高版本）、Visual Studio Build Tools / Windows SDK 和 Node.js 22。依赖版本由 `Cargo.lock` 和 `ui/package-lock.json` 固定；更新依赖时一并提交对应锁文件。

首次检出时从示例建立本地配置，再填写自己的代理和进程规则；已有 `config.xml` 时保留原文件：

```powershell
if (-not (Test-Path -LiteralPath config.xml)) { Copy-Item config.example.xml config.xml }
cd ui
npm ci
```

`config.xml` 为本地文件，不应提交。提交问题或测试结果时请隐藏 SOCKS5 凭据、密钥和个人路径。

## 验证改动

在仓库根目录执行无需驱动的核心检查：

```powershell
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
.\target\release\rnetch.exe .\config.example.xml --check-config
.\target\release\rnetch.exe .\config.gpux.example.xml --check-config
```

界面检查：

```powershell
cd ui
npm ci
npm test
npm run build
```

GitHub Actions 执行这些检查，不安装或启动驱动。实际运行前按 [README](README.md) 准备后端运行文件。使用 WinDivert 的本地构建示例：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-windivert.ps1
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Backend windivert
```

驱动测试需要提升权限并会影响主机网络。参照 [迁移与测试矩阵](docs/RUST_MIGRATION.md) 记录所选后端、配置规则、SOCKS5 端点、TCP/UDP、IPv4/IPv6 和测试前驱动状态。`--check-config` 必须保持不加载驱动。

## 代码与提交

- Rust 使用 `cargo fmt`，优先使用 RAII、有限容量队列和明确的工作线程退出与等待。
- FFI 与 SDK 头文件保持 ABI、调用约定和缓冲区生命周期一致；不得从 C 回调中展开 panic，不在驱动回调中执行网络操作。
- UI 配置校验与 CLI 保持一致，涉及行为变化时覆盖相关边界场景。
- 提交信息使用简洁的祈使句；PR 说明行为变化、实现、已执行的验证及测试限制。
- 不提交本地配置、凭据、缓存、依赖安装目录或构建产物；不手工修改 `target/`、`build/`、`ui/dist/`、`ui/release/`。
- 不提交驱动或 SDK 二进制；新增或替换第三方依赖时保留许可证，记录来源、版本和 SHA-256。

项目自有代码及文档采用 [MIT 许可证](LICENSE)。提交贡献前应确认自己有权按该许可授权贡献内容；第三方组件保留原有许可及版权声明，不能将其改标为 MIT。NetFilter SDK 原始头文件和二进制为本地依赖，不提交到公开源码仓库。
