# 源码与发布管理

源码采用常规 Cargo / Electron 布局：`src/` 是现行 Rust 核心，`ui/` 是现行界面，`legacy/cpp/` 是迁移前归档。保留 `Cargo.lock`、`ui/package-lock.json`、示例配置、项目许可证、可再分发的第三方文件及来源记录；构建产物通过 GitHub Releases 单独分发。

`.gitignore` 排除本地 `config.xml`、`.env`、机器配置、`.local/`、SDK 二进制、NetFilter SDK 原始头文件、Rust/UI 构建目录和依赖缓存。本地配置及旧分析文件仍保留在磁盘上。打包固定读取 `config.example.xml`；开发 UI 首次启动从示例创建本地 `config.xml`，已有配置继续保留。

## 首次检出与验证

无需 SDK 文件也可执行 Cargo 的格式检查、单元测试、Clippy 和 Release 编译，以及 UI 的测试和构建。运行前从示例复制配置；准备所选驱动的运行时文件，见 [依赖说明](../deps/README.md)。纯 WinDivert 构建需要显式选择：

```powershell
if (-not (Test-Path -LiteralPath config.xml)) { Copy-Item config.example.xml config.xml }
powershell -ExecutionPolicy Bypass -File scripts/setup-windivert.ps1
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Backend windivert
.\target\release\rnetch.exe .\config.xml --backend windivert --check-config
```

复制命令用于首次检出；已有 `config.xml` 时不要覆盖。默认双后端发布仍要求两种后端文件齐全，缺少文件会失败。

## 发布版本

更新 `Cargo.toml`、`ui/package.json` 和 npm 锁文件中的版本，添加对应的 `docs/releases/v<version>.md` 发布说明，完成检查并提交后创建版本标签：

```powershell
git tag -a v0.2.2 -m "Rnetch 0.2.2"
git push origin main
git push origin v0.2.2
```

标签触发 Release workflow，生成桌面便携包、CLI 包、源码包、WinDivert 对应源码和 SHA-256 校验文件，并上传到 GitHub Releases。运行包包含两套驱动及配套库；源码包不包含 SDK 二进制或 NetFilter 原始头文件。构建和验证步骤见 [打包说明](PACKAGING_README.md)。

## 许可与来源

项目自有代码及文档采用 [MIT 许可证](../LICENSE)。第三方组件保留原许可。NetFilter 原始头文件、DLL、SYS 和旧导入库不进入源码 Git；完整应用包附带固定版本运行时、厂商版权和来源说明。WinDivert 运行包附带许可证、对应源码及替换说明。具体状态见 [第三方依赖清单](../THIRD_PARTY_NOTICES.md)。
