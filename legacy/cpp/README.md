# 历史 C++ 实现

这里保存迁移到 Rust 前的实现，供代码比对和追溯。现行核心在仓库根目录的 `src/`，由 Cargo 构建；本目录不参与现行产品的构建、CI 或打包。下述独立回归测试只验证归档代码，没有恢复旧 C++ 产品的构建入口。

| 目录 | 内容 |
| --- | --- |
| `src/` | 原 `.cpp` / `.h`、内部工具头文件和 TinyXML2 头文件 |
| `include/` | 原公开头文件，保留与内部头文件的历史差异 |
| `docs/` | C++ 开发日志、当时的路线图和早期 UI 实现记录 |
| `tools/` | 旧命令行规则字符串生成脚本；当前 XML 规则由核心/UI 处理 |
| `tests/` | 后补的 C++ mock/loopback 回归测试及独立运行脚本 |
| `lib/` | 本机保留的旧导入库，已排除 Git 跟踪 |

NetFilter SDK 头文件已集中到本地 `deps/netfilter/include/`，作为 Rust FFI 的 ABI 参考；该目录因 SDK 源码再分发限制而不进入公开仓库，准备方式见 [依赖说明](../../deps/README.md#netfilter)。TinyXML2 的原许可说明保留在 `src/tinyxml2.h`。本目录的项目自有实现采用根目录 [MIT 许可证](../../LICENSE)，第三方许可状态见 [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md)。

归档时只移动 C++ 源码和头文件，没有修改其内容。历史文档中的 `src/`、`include/` 指迁移前的 C++ 布局；文中编译命令、故障分析和“当前”状态仅反映当时记录。现行行为与验收方法见 [`docs/RUST_MIGRATION.md`](../../docs/RUST_MIGRATION.md)。

机器专用的 clangd、Polyspace 配置及未使用截图保存在根目录 `.local/`，不上传 GitHub。现行根目录 `CMakeLists.txt` 仅兼容转调 Rust 构建脚本。

## 2026-10-03：同步 NetFilter 转发修正

用户反馈 Rust 0.2.2 的 BF6 连接表现恢复后，复核发现归档 C++ 仍有同类实现缺陷。旧 C++ **没有** Rust 0.2.1 新增的 `Timed out waiting for NetFilter tcpConnected` 等待或日志；它直接使用 `NF_FILTER | NF_OFFLINE`，在 SDK 回调内连接代理和发送数据，代理返回 EOF 时直接 `nf_tcpClose`，应用的零长度 TCP 回调则被忽略。因此不能把两份实现称为同一个超时分支，但它们共用的离线 TCP 注入方式及关闭语义问题需要一起修正。

本次修改仅在 `legacy/cpp/`：

- `rnetch.cpp`、`tcp_relay.*`：回调挂起连接请求，工作线程完成 SOCKS 后重定向到本地监听 socket，使用 `NF_ALLOW` 和中继所属 PID。TCP 规则仅指示连接请求；中继不依赖 `tcpConnected`，也不注入离线 TCP 数据。每方向最多缓存 32 KiB，支持 IPv4、IPv6、mapped IPv4、服务端先发数据和双向半关闭。回调不等待工作线程，完成线程由 owner 回收。
- `udp_relay.*`：回调只复制并入队，工作线程建联和收发。按目标保存 SDK options，恢复 mapped 地址族，处理超过旧 4 KiB 限制的报文，校验 SOCKS RSV/FRAG。队列限制 256 包及 8 MiB，路由缓存限制 256 项及 2 MiB。控制连接失败后，原端点可以在后续报文到来时重建关联。
- `socks5.*`：精确读取分片回复，保留与 CONNECT 回复一同到达的应用数据；严格校验认证方法、字段长度和地址族。连接、解析和每次握手/命令均有期限和取消检查。异步 DNS 上下文保留到完成回调，按 [Microsoft 的 GetAddrInfoExW 合约](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexw) 处理同步完成和取消。
- `proxy_process.*`：在发出 SOCKS 握手前识别本机代理进程，并以进程创建时间校验其身份，防止通配规则递归代理 SOCKS 守护进程。
- `driver.cpp`：保留既有服务的配置和运行状态，只停止本次启动的服务；SDK 初始化失败不再停止别人已经运行的驱动。`main.cpp` 的等待也响应内部停止信号，让异常之后能够进入解绑和回收流程。

SDK 头文件、DLL/SYS、Rust 核心和 Electron 均未因本次修正而改变。驱动本身的许可/试用限制不受这些源码修改影响。历史开发日志保留原貌，其中早期故障归因不能视为本次验证结论。

## 独立验证

在仓库根目录运行，需要 MSVC x64、Windows SDK 和自行合法取得的 NetFilter SDK 头文件（本地 `deps/netfilter/include/`），不需要 SDK 二进制或管理员权限：

```powershell
powershell -ExecutionPolicy Bypass -File legacy/cpp/tests/run.ps1
```

脚本使用 `/std:c++17 /W4 /WX` 编译检查归档源文件，运行 TCP、SOCKS5、UDP、代理进程识别、驱动服务所有权和 SDK 回调集成测试。网络测试只连接本机 loopback；SDK/SCM 调用使用 mock，不加载或停止实际驱动。产物写入忽略的 `build/legacy-cpp-tests/`。

集成测试特意不触发 `tcpConnected` 或 SDK TCP 数据回调，验证实际本地 socket 中继、server-first、半关闭后完整尾包及取消。它验证的是 C++ 传输和回调边界，不是实际内核驱动重定向或 C++ 版本的 BF6 实测。

2026-10-03 最终验证：七个源文件的 MSVC x64 `/W4 /WX` 编译检查全部通过。统一运行脚本的实际结果如下，未将失败跳过或算作通过：

| 测试组 | 结果 |
| --- | --- |
| TCP 中继 | 9/10；纯 IPv6 `::1` 连接失败 |
| SOCKS5 | 8/9；纯 IPv6 本机代理连接失败 |
| UDP 转发 | 通过，包括多目标上下文、大报文、断线恢复和队列/取消 |
| 本机代理进程识别 | 4/5；纯 IPv6 连接失败，IPv4、两种 mapped 模式及独立进程生命周期通过 |
| 驱动服务所有权 | mock SCM 回归通过 |
| SDK 回调集成 | 6/6 通过 |

上述三个失败都发生在本机纯 IPv6 `connect(::1)`，错误为 Winsock 10013。另行编译的独立原生 WinSock 对照程序完全不使用本项目 helper 或 NetFilter API：IPv4 与 mapped IPv4 连接成功，纯 IPv6 在 `IPV6_V6ONLY` 为 0 和 1 时都被拒绝；独立 .NET Socket 对照结果相同。因此当前主机的纯 IPv6 loopback 验证受到环境限制，具体拒绝策略尚未定位，不能宣称本轮纯 IPv6 验收通过。运行脚本保留非零退出状态，并继续其他独立测试以保留覆盖。

最终日志位于 `build/legacy-cpp-tests/*.stdout.log` / `*.stderr.log`，原生对照证据位于 `build/legacy-cpp-tcp-debug/native-loopback-result.log`。认证拒绝、取消以及注入的回调异常属于负向测试场景，是否通过以用例断言和退出状态为准。此次没有修改主机网络策略或进行真实驱动/游戏测试。
