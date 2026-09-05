# SNI 字段名事故：转换后订阅 REALITY 节点全挂（2026-09）

## 现象

- 用户路由器（OpenClash/mihomo）使用机场官方订阅一切正常；经本项目转换后的同一订阅，
  全部 vless REALITY 节点不可用。
- mihomo 日志大量刷 TLS 证书错误：`x509: certificate is valid for *.bilibili.com..., not <节点域名>`。
  即客户端拿到了机场 REALITY 伪装站（bilibili）的真证书，而不是完成 REALITY 握手。

## 排查过程（关键证据链）

1. 最初按"机场服务端问题"排查（证书错误指向伪装站），一度误判为服务端密钥更换。
2. 决定性对照：**官方订阅直连可用，仅经本项目转换的订阅故障** → 问题锁定在转换器输出差异。
3. 对比两份配置的 vless 节点块：机场原始输出用 `servername` 传 SNI，本项目输出的是 `sni`。
4. 查 mihomo 源码（proxy tag 结构体）确认字段归属，再对照 git 历史定位引入点。

## 根因

mihomo（Clash.Meta）各协议的 TLS SNI 字段名**不统一**：

| 协议 | SNI 字段名 |
|---|---|
| vless / vmess | `servername` |
| trojan / hysteria2 / anytls | `sni` |

commit `1efa4a4` 引入 `clashSNIField()`（受 `new_name` 参数控制，默认返回 `sni`），
把 vless/vmess 的 SNI 写成了 `sni`。mihomo 对未知字段不报错、静默忽略，
于是 ClientHello 的 SNI 落到节点域名 → REALITY 服务端按回落处理 → 返回伪装站真证书
→ x509 报错刷屏。9月2日的初版实现（`1774672`）本来是对的。

这和 2026-09 之前的 Loon 输出是同一类问题：**字段名写错不报错，直接丢功能**。

## 修复

### Clash（本事故根因）

- `internal/render/clash.go`：vless/vmess 统一输出 `servername`；删除 `clashSNIField()`
  与 `Config.NewName`（该开关建立在错误字段名上，无保留价值）。
- `internal/server/handler.go`：删除 `new_name` 参数（前端确认无引用）。
- 回归测试 `clash_test.go`：vless/vmess 必须输出 `servername`，且**不得输出 `sni` 字段**。

### Loon（同一模式的全量排查收获）

对照 Loon 3.x 官方文档（nsloon.app/docs/Node）逐键核对 `loon.go`，修正：

| 位置 | 原输出（错误/废弃） | 修正后 |
|---|---|---|
| vmess SNI | `tls-name=` | `sni=` |
| trojan SNI | `tls-name=` | `sni=` |
| vless TLS 开关 | `tls=`（不存在的键，TLS 永远开不了） | `over-tls=` |
| vless REALITY | `publicKey=` / `shortId=` | `public-key=` / `short-id=` |
| vless ws | `ws-path=` / `ws-headers=Host:`（Surge 键名） | `path=` / `host=` |
| hysteria2 混淆 | `obfs=salamander,obfs-password=` | `salamander-password=` |

另补字段缺失：vmess 非 AEAD 节点（alterId>0）显式输出 `alterId=N`，否则 Loon 按 0 处理会握手失败。

### 已核对无坑的部分

- `singbox.go`：全部字段对照 sing-box schema 正确（`server_name`、`reality.enabled/public_key`、
  `utls.enabled/fingerprint`、`alter_id`、时长字段的 `"s"` 后缀等）。
- clash 其余协议：trojan/hysteria2/anytls 用 `sni` 本来就正确。
- 解析端：vmess cipher 空/`auto` 有兜底；vless URI 与 Clash YAML 的 REALITY 字段解析齐全。

## 验证

- `go build ./...`、`go vet ./...`、`go test ./...` 全部通过。
- 测试断言：23 个 REALITY 样本节点（testdata/subscription.txt）全部输出 `servername`
  且无 `sni` 字段；Loon 输出含 `over-tls=`/`public-key=`/`short-id=`，且全文件禁止出现
  `tls-name=`、`obfs=`、`publicKey=`、`ws-path=` 等废弃键。
- 线上验证（待部署后）：重建部署转换服务 → OpenClash 更新订阅并重启 → 节点存活数
  应回到与官方订阅同一水平。

## 教训（防再犯）

- 每个渲染器的字段名必须对照**目标客户端的官方文档或源码**，不能从其他客户端类推、
  也不能沿用 C++ 旧版的键名（`tls-name` 即 C++ 沿用下来的废弃键）。
- 客户端对未知字段静默忽略，字段名错误不会有任何报错，只会表现为"节点挂了/证书错"。
  排查此类问题的最快路径是拿一份**已知可用的同协议配置**逐字段 diff。

## 遗留（unverified）

- Loon 是否支持 vmess/vless 的 `transport=grpc`：官方文档传输层仅列 tcp/ws/http，
  但社区配置广泛使用 `grpc-service-name`，无法本地验证，保留输出未删。
- 独立次要问题：机场部分节点域名 DNS 污染（解析到 Akamai），与本项目无关。
