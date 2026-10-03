# 第三方组件说明

项目自有代码及文档采用根目录 [MIT 许可证](LICENSE)。此许可不改变第三方组件的许可；以下 SDK、驱动和历史依赖保留各自的版权声明、许可及来源记录。

| 组件 | 用途与位置 | 许可与来源证据 |
| --- | --- | --- |
| WinDivert 2.2.2 | Rust 捕获后端；运行时位于 `deps/windivert/`，二进制在本机准备 | 随包 [LICENSE](deps/windivert/LICENSE) 明确为 LGPL Version 3 或 GPL Version 2 双重许可；保留完整许可文本、README、VERSION、CHANGELOG 与 [SOURCE.json](deps/windivert/SOURCE.json) |
| NetFilter SDK | Rust 捕获后端；本地运行时位于 `deps/nfapi.dll`、`deps/nfdriver.sys`；本地 ABI 参考头文件在 `deps/netfilter/include/`；均不进入公开源码包 | [官方协议](https://www.netfiltersdk.com/license.html) 限制 SDK 源码再分发；原头文件声明 Vitaly Sidorov 版权所有；现存文件的取得来源、SDK 发布版本及适用授权仍未知，见 [SOURCE.json](deps/netfilter/SOURCE.json) |
| TinyXML2 | 迁移前 C++ XML 解析；头文件在 `legacy/cpp/src/tinyxml2.h`，本地库在 `legacy/cpp/lib/tinyxml2.lib` | 头文件保留 Lee Thomason 的 zlib 风格许可说明及 11.0.0 版本宏；现存库的取得来源及对应版本未知 |

## WinDivert

本地安装脚本使用的发布页与归档地址记录在 [deps/windivert/SOURCE.json](deps/windivert/SOURCE.json)。实际下载哈希用于识别已取得的文件，独立校验的方式另行记录，不把自行计算的哈希表述为官方公布的摘要。构建与打包应保留随包许可及来源说明。

本项目使用 WinDivert 的 LGPLv3 许可选项，Rust 通过动态加载使用 DLL；项目自有代码仍按 MIT 授权。[官方 FAQ](https://www.reqrypt.org/windivert-faq.html) 允许在满足 LGPLv3 条款时用于闭源程序。分发者仍须满足对应源码提供、允许用户替换适用库版本等条款；仅复制许可证或提供上游网页链接不意味着已满足所有分发义务。完整条款保留在 `deps/windivert/LICENSE`。

## NetFilter SDK

本地 `deps/netfilter/include/{nfapi,nfdriver,nfevents}.h` 中的原始声明均予以保留，包括：

```text
NetFilterSDK
Copyright (C) Vitaly Sidorov
All rights reserved.
```

现存运行时和历史导入库的实测 SHA-256、文件长度与可用 PE 版本字段记录在 [deps/netfilter/SOURCE.json](deps/netfilter/SOURCE.json)。PE 文件版本字段不是已核实的 SDK 发布版本。[官方许可协议](https://www.netfiltersdk.com/license.html) 将 SDK 可执行产品分发和源码分发区别处理，对大量派生自 SDK 的源码分发设有限制。

现存文件没有原始取得记录，不能据此认定具有适用授权。原始 SDK 头文件和二进制均保留为本地依赖并由 Git 忽略，不按项目 MIT 再授权；发布含 NetFilter 的软件包前，应补齐适用许可和来源证据。

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

Rust 与 Electron/React 的直接依赖列在 [Cargo.toml](Cargo.toml) 和 [ui/package.json](ui/package.json)，解析后的依赖版本由 [Cargo.lock](Cargo.lock) 和 [ui/package-lock.json](ui/package-lock.json) 固定。各依赖遵循其上游包所附的许可证；发布时还应保留 Electron、Chromium 以及其他随包组件的许可文件。
