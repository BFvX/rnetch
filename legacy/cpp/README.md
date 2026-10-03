# 历史 C++ 实现

本目录保存迁移到 Rust 前的 C++ 实现及相关开发资料。现行核心位于仓库根目录的 `src/`，由 Cargo 构建。本目录不参与现行产品的构建、CI 或打包。

## 目录结构

| 目录 | 内容 |
| --- | --- |
| `src/` | C++ 实现、内部工具头文件和 TinyXML2 头文件 |
| `include/` | 原公开头文件 |
| `tests/` | 独立 mock / loopback 回归测试及运行脚本 |
| `tools/` | 旧命令行规则字符串生成脚本 |
| `docs/` | 历史开发日志、实现记录和路线图 |
| `lib/` | 本地历史导入库，已排除 Git 跟踪 |

NetFilter SDK 头文件位于本地 `deps/netfilter/include/`，不包含在源码仓库中。历史文档中的 `src/`、`include/` 指迁移前的 C++ 目录布局。

## 独立回归测试

需要 Windows x64、MSVC、Windows SDK，以及合法取得的 NetFilter SDK 头文件。依赖准备方式见 [依赖说明](../../deps/README.md#netfilter)。

在仓库根目录运行：

~~~powershell
powershell -ExecutionPolicy Bypass -File legacy/cpp/tests/run.ps1
~~~

脚本使用 `/std:c++17 /W4 /WX` 检查源码，并执行 TCP、SOCKS5、UDP、代理进程识别、驱动服务所有权和 SDK 回调测试。网络测试仅使用本机 loopback，SDK / SCM 调用采用 mock，不加载实际驱动。测试产物写入 `build/legacy-cpp-tests/`；实际内核驱动链路需另行验收。

## 许可证

项目自有实现采用根目录 [MIT 许可证](../../LICENSE)。TinyXML2 头文件保留原许可声明，NetFilter SDK 文件遵循其适用授权。详见 [第三方组件说明](../../THIRD_PARTY_NOTICES.md)。
