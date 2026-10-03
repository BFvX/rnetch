# 第三方驱动与 SDK 文件

Rust 核心通过动态加载使用 NetFilter 或 WinDivert。正常编译不需要 C++ SDK 导入库；本目录的 SDK 头文件只用于核对 FFI ABI。第三方文件的许可与来源记录见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。

运行时 `.dll`、`.sys`、NetFilter SDK 原始头文件与历史 `.lib` 文件在本机保留，但不提交到源码仓库。新克隆的仓库需先准备所选后端的运行时文件；Rust 构建和测试不读取这些 SDK 头文件。

## WinDivert

推荐从官方发布获取固定版本的 x64 运行时。在仓库根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-windivert.ps1
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Backend windivert
# 首次检出时创建本地配置；已有 config.xml 时保留原文件：
if (-not (Test-Path -LiteralPath config.xml)) { Copy-Item config.example.xml config.xml }
.\target\release\rnetch.exe .\config.xml --backend windivert --check-config
```

`setup-windivert.ps1` 获取 WinDivert 2.2.2，校验驱动签名，并在可用时校验官方发布资产摘要。脚本把实际来源、版本、校验方式和 SHA-256 写入 [windivert/SOURCE.json](windivert/SOURCE.json)。这些命令不加载驱动。使用自备归档时可传入 `-ArchivePath` 与 `-ArchiveSha256`。

需要的运行时文件是 `windivert/WinDivert.dll` 和 `windivert/WinDivert64.sys`。保留随包的 [LICENSE](windivert/LICENSE)、[README](windivert/README)、[VERSION](windivert/VERSION)、[CHANGELOG](windivert/CHANGELOG) 和来源记录；构建脚本会复制这些说明。

## NetFilter

本机保留的 NetFilter 文件缺少可核实的原始下载来源、SDK 发布版本和适用授权。[官方许可协议](https://www.netfiltersdk.com/license.html) 对 SDK 源码再分发设有限制；项目的 MIT 许可不覆盖 SDK 文件。记录在 [netfilter/SOURCE.json](netfilter/SOURCE.json) 中的哈希和 PE 版本字段仅描述这些现存文件，不代表官方校验或再分发授权。

自行取得具有适用使用授权、配套且适用于 Windows x64 的 SDK 运行时文件，放入以下位置：

```text
deps/nfapi.dll
deps/nfdriver.sys
```

然后在仓库根目录运行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Backend netfilter
```

本地 `netfilter/include/` 保留迁移时使用的 `nfapi.h`、`nfdriver.h`、`nfevents.h` 及其版权声明，供 Rust ABI 对照，目录已由 Git 忽略。需要编译历史 C++ 回归测试时，须自行合法取得这些头文件并放在该目录。替换运行时或头文件时，应记录取得来源、版本、适用许可与新哈希；不能将旧记录用于不同文件。

## 历史 C++ 依赖

`legacy/cpp/lib/nfapi.lib` 和 `legacy/cpp/lib/tinyxml2.lib` 是迁移前的本地导入库/静态库存档，不参与 Rust 构建，也不随源码仓库提交。[TinyXML2 头文件](../legacy/cpp/src/tinyxml2.h) 保留在 C++ 存档中，头文件版本宏为 11.0.0；现存库文件的来源和对应版本没有核实。

## 打包

默认发布包包含两个后端，因此必须同时准备两套运行时。只有 WinDivert 的新克隆可以明确选择单后端：

```powershell
cd ui
npm ci
npm run pack:release -- -Backend windivert
```

参见 [打包说明](../docs/PACKAGING_README.md)。公开分发包含 NetFilter 的包之前，需补齐该 SDK 的取得来源和适用再分发许可记录。
