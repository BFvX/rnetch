# GitHub 上传说明

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

## 首次提交

整理时根目录 `.git/` 为空，没有可读取的 Git 历史。准备创建本地仓库时可执行：

```powershell
git init -b main
git status --short --untracked-files=all
git add .
git diff --cached --stat
git diff --cached
# 完成暂存内容审查后：
git commit -m "Organize Rust core and archive legacy C++ sources"
```

重点检查暂存列表中的配置、日志、二进制、截图和个人绝对路径。忽略规则对已经跟踪的文件无效；若在已有仓库中沿用此布局，需检查跟踪状态。GitHub 远端地址由维护者指定。

## 许可与来源

项目自有代码及文档采用 [MIT 许可证](../LICENSE)。第三方组件保留原许可，MIT 不授予这些组件的额外权利。NetFilter 官方协议限制 SDK 源码再分发，原始头文件、DLL、SYS 和旧导入库默认不进入 Git；现存资产的准确取得来源及适用授权仍需维护者补充。WinDivert 许可证与来源记录、TinyXML2 头文件许可均已保留。具体状态见 [第三方依赖清单](../THIRD_PARTY_NOTICES.md)。
