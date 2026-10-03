# GPUX UDP 隧道

Rnetch 支持使用 GPUX/1 隧道转发 UDP 流量。捕获后端可选择 NetFilter 或 WinDivert；TCP 流量继续通过 SOCKS5 转发。GPUX 服务端需要单独部署。

## 配置与启动

复制 [GPUX 配置示例](../config.gpux.example.xml) 到本地 `config.xml`，设置服务端地址、端口和 token。客户端与服务端的加密模式必须一致，默认使用 ChaCha20-Poly1305。

```xml
<config>
    <backend type="windivert" />
    <udp_transport type="gpux" />
    <socks5 host="127.0.0.1" port="10808" user="" pass="" />
    <gpux host="127.0.0.1" port="40000" token="replace-with-your-token"
          encryption="chacha20-poly1305" mtu_payload="1200" deadline_ms="8"
          batch_window_us="0" pacing_interval_us="0" queue_limit="512"
          fec_uplink="0" fec_group_max_us="2000" />
    <rules>
        <rule name="game.exe" tcp="1" udp="1" />
    </rules>
</config>
```

在桌面界面中选择捕获后端，将 UDP 传输方式设为 GPUX，并填写对应参数。仅代理 UDP 的规则可设置 `tcp="0"` 并省略 `<socks5>`；同时代理 TCP 和 UDP 时需要配置 SOCKS5。

检查配置后，从管理员终端启动核心：

```powershell
.\target\release\rnetch.exe .\config.xml --check-config
.\target\release\rnetch.exe .\config.xml
```

`--check-config` 只校验配置，不连接服务端或加载驱动。按 Enter 或 Ctrl+C 停止核心。构建和驱动准备步骤见 [构建与打包](PACKAGING_README.md)。

## 参数

以下参数均为 `<gpux>` 元素的属性。

| 字段 | 默认值 | 范围/含义 |
| --- | --- | --- |
| host / port | 127.0.0.1 / 40000 | GPUX 服务端地址；端口 1..65535 |
| token | 空，启用 GPUX 时必填 | 1..255 UTF-8 字节，无 NUL |
| encryption | chacha20-poly1305 | `chacha20-poly1305` 或 `plaintext`；明文模式仅适合可信测试环境 |
| mtu_payload | 1200 | 完整隧道 UDP 负载上限，128..65507 字节；须至少容纳 `80 + token 的 UTF-8 字节数` |
| deadline_ms | 8 | 从驱动截获时计算的本地发送预算，1..1000 ms |
| batch_window_us | 0 | 微批处理窗口，0..1000000 µs |
| pacing_interval_us | 0 | DATA 发送间隔，0..1000000 µs |
| queue_limit | 512 | 有界队列限制，1..65536 |
| fec_uplink | 0 | 0 关闭，1 启用上行最多 4+1 XOR FEC |
| fec_group_max_us | 2000 | 部分 FEC 组刷新窗口，1..1000000 µs |

真实 token 应只保存在本地配置中。Rnetch 的 `config.xml` 已由 Git 忽略。

## MTU、发送预算与 FEC

`mtu_payload` 包含 GPUX 协议和加密开销，可转发的应用数据报会小于该值。客户端不对数据报进行隧道分片；超过可用负载上限的数据报会被丢弃。

`deadline_ms` 包含本地排队和等待 flow 建立的时间。过期数据报会被丢弃，DATA 包不进行 ARQ 重传。协议中的 TTL 用于本地发送与接收恢复等待，不表示跨主机同步时钟上的绝对到达期限。

启用上行 FEC 后，每组最多使用 4 个 DATA 源包和 1 个 XOR 校验包，可恢复组内单个源包的丢失。下行是否发送 FEC 由服务端决定，客户端支持解码。FEC 会增加带宽和元数据开销，并进一步降低单个应用数据报的可用空间。

批处理、pacing 和 FEC 的刷新窗口均会消耗发送预算。应根据数据报大小和链路情况调整参数；默认值不保证适合所有游戏或网络。

## 会话与连接行为

每次隧道启动都会生成随机 connection ID。一个隧道可承载多个 UDP 会话与目标，保留各自的流标识和响应来源地址。

目标闲置 30 秒后，客户端会重新建立 flow。服务端的静默清理窗口应大于这一间隔；参考服务端的默认值为 45 秒。整个隧道发生致命错误时，核心停止并报告错误，需重新启动；当前没有整个隧道的自动重连。

## 开发验证

无需加载捕获驱动即可运行协议测试：

```powershell
cargo test --all-targets --locked
```

使用已有的 GPUX 服务端程序进行回环互通验证：

```powershell
cargo build --example gpux_probe --locked
python tools/verify_gpux_interop.py --server-exe C:\path\to\gpux_server.exe
```

验证工具启动本地 IPv4 / IPv6 UDP echo 和中继，检查明文、加密、批处理、pacing、FEC 恢复及会话关闭。服务端程序作为外部测试依赖提供。

也可连接已启动的本地服务器和 echo 目标：

```powershell
cargo run --example gpux_probe -- config.gpux.example.xml 127.0.0.1:50000 "[::1]:50001"
```

运行前使配置中的地址、端口、token 和加密模式与测试服务匹配。驱动捕获、进程规则、TCP / UDP 和 IPv4 / IPv6 的系统验收见 [驱动验收说明](RUST_MIGRATION.md)。
