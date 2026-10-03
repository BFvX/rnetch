# 第三方组件说明

项目自有代码及文档采用根目录 [MIT 许可证](LICENSE)。此许可不改变第三方组件的许可；以下 SDK、驱动和历史依赖保留各自的版权声明、许可及来源记录。

| 组件 | 用途与位置 | 许可与来源证据 |
| --- | --- | --- |
| WinDivert 2.2.2 | Rust 捕获后端；运行时位于 `deps/windivert/`，二进制在本机准备 | 随包 [LICENSE](deps/windivert/LICENSE) 明确为 LGPL Version 3 或 GPL Version 2 双重许可；保留完整许可文本、README、VERSION、CHANGELOG 与 [SOURCE.json](deps/windivert/SOURCE.json) |
| NetFilter SDK | Rust 捕获后端；运行时位于 `deps/nfapi.dll`、`deps/nfdriver.sys`；SDK 头文件仅作本地 ABI 参考 | 运行时与 Netch 1.9.7 文件完全一致，见 [SOURCE.json](deps/netfilter/SOURCE.json)；[厂商协议](https://www.netfiltersdk.com/license.html) 分别规定可执行产品与 SDK 源码的分发；版权和分发说明见 [NOTICE.txt](deps/netfilter/NOTICE.txt) |
| TinyXML2 | 迁移前 C++ XML 解析；头文件在 `legacy/cpp/src/tinyxml2.h`，本地库在 `legacy/cpp/lib/tinyxml2.lib` | 头文件保留 Lee Thomason 的 zlib 风格许可说明及 11.0.0 版本宏；现存库的取得来源及对应版本未知 |

## WinDivert

本地安装脚本使用的发布页与归档地址记录在 [deps/windivert/SOURCE.json](deps/windivert/SOURCE.json)。实际下载哈希用于识别已取得的文件，独立校验的方式另行记录，不把自行计算的哈希表述为官方公布的摘要。构建与打包应保留随包许可及来源说明。

本项目使用 WinDivert 的 LGPLv3 许可选项，Rust 通过动态加载使用 DLL；项目自有代码仍按 MIT 授权。[官方 FAQ](https://www.reqrypt.org/windivert-faq.html) 允许在满足 LGPLv3 条款时用于闭源程序。发布包附带完整许可文本与未修改的 v2.2.2 对应源码归档，源码提交、下载地址、哈希和构建入口见 [CORRESPONDING_SOURCE.json](deps/windivert/CORRESPONDING_SOURCE.json)。

用户可将运行目录中的 `WinDivert.dll` 和 `WinDivert64.sys` 替换为 ABI 兼容的构建；Rnetch 不对 DLL 强制校验哈希或签名。Windows 对内核驱动签名的要求仍适用。完整条款保留在 `deps/windivert/LICENSE`。

## NetFilter SDK

本地 `deps/netfilter/include/{nfapi,nfdriver,nfevents}.h` 中的原始声明均予以保留，包括：

```text
NetFilterSDK
Copyright (C) Vitaly Sidorov
All rights reserved.
```

现存运行时和历史导入库的实测 SHA-256、文件长度与可用 PE 版本字段记录在 [deps/netfilter/SOURCE.json](deps/netfilter/SOURCE.json)。PE 文件版本字段不是已核实的 SDK 发布版本。[官方许可协议](https://www.netfiltersdk.com/license.html) 将 SDK 可执行产品分发和源码分发区别处理，对大量派生自 SDK 的源码分发设有限制。

`nfapi.dll` 和 `nfdriver.sys` 已通过 Git blob 标识与 Netch 1.9.7 的固定提交逐一比对，文件内容完全一致。原始取得记录和 SDK 发布版本仍无记录；PE 版本字段只用于识别文件。完整应用发布包按厂商协议的 “Distribution In Executable Form” 条款附带未修改的运行时及版权说明，不按项目 MIT 再授权。原始 SDK 头文件、历史导入库和独立 SDK 源码不随发布包分发，源码 Git 仍忽略运行时二进制。

## TinyXML2 原始声明

以下声明随 [历史头文件](legacy/cpp/src/tinyxml2.h) 保留；历史库文件不参与现行 Rust 构建：

```text
Original code by Lee Thomason (www.grinninglizard.com)

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any
damages arising from the use of this software.

Permission is granted to anyone to use this software for any
purpose, including commercial applications, and to alter it and
redistribute it freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must
not claim that you wrote the original software. If you use this
software in a product, an acknowledgment in the product documentation
would be appreciated but is not required.

2. Altered source versions must be plainly marked as such, and
must not be misrepresented as being the original software.

3. This notice may not be removed or altered from any source
distribution.
```

## Cargo 与 npm 依赖

Rust 与 Electron/React 的直接依赖列在 [Cargo.toml](Cargo.toml) 和 [ui/package.json](ui/package.json)，解析后的依赖版本由 [Cargo.lock](Cargo.lock) 和 [ui/package-lock.json](ui/package-lock.json) 固定。打包时从实际 Windows Cargo 依赖和已安装 npm 运行依赖中收集原始许可文件，写入运行包的 `licenses/` 目录；`INDEX.txt` 列出组件、版本和位置。桌面包另保留 Electron 与 Chromium 的许可文件。
