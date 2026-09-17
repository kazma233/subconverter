# Snell 协议支持（2026-09-18）

## 背景

C++ 版的 Snell 支持是残缺的：输入只有 Clash YAML（`psk`/`obfs-opts.{mode,host}`/`version`）和
Surge conf 两种载体，**没有 `snell://` URI 解析**；输出只有 Clash YAML 和 Surge conf，
sing-box 与 Loon 侧无实现（default 分支直接丢弃节点）。

Go 版本次补齐：`snell://` URI + Clash YAML 两种输入，clash / loon / singbox 三端输出。

## 决策

### `snell://` URI 格式（社区约定）

Snell 链接没有权威 spec（C++ 无先例），按 Shadowrocket / Sub-Store 的通行约定实现，
与 trojan 链接同构：

```
snell://psk@host:port?version=4&obfs=http&obfs-host=bing.com#备注
```

- psk 放 userinfo（空则报错）；version 非数字视为未设置，不报错
- snell 基于 PSK 加密而非 TLS，不读 sni / alpn / insecure
- `internal/parser/snell.go`，registry 注册 scheme `snell`

### 模型字段

`model.Proxy` 新增 Snell 专属分区 `SnellVersion` / `SnellObfs` / `SnellObfsHost`，
不复用 C++ 的 `OBFS`/`Host` 通用字段（Go 版各协议专属字段一律带前缀，如 Hysteria2）。
Password 复用现有共享字段。SnellVersion 为 0 表示未指定。

### 三端输出

| 端 | 行为 |
| -- | ---- |
| Clash (mihomo) | `psk`（纯数字强制双引号）、`version` 非 0 输出、`obfs-opts.{mode,host}`、udp / fast-open 正常三态输出；不输出 sni/alpn/skip-cert-verify（非 TLS 协议） |
| Loon | Surge 风格行 `snell,host,port,psk=...[,version=n][,obfs=http][,obfs-host=...]`；`obfs=off` 视为无混淆不输出 |
| sing-box | version 4/6 正常输出（`obfs_mode`/`obfs_host` 仅 v4）；**其余版本在 `RenderSingBox` 入口统一剔除并记日志** |

### sing-box 过滤必须在渲染入口

组展开（`expandGroupItems`）和 proxy selector 都引用**完整**节点列表，
若只在 `sbRenderNodeOutbounds` 循环里 continue 跳过，组里会留下指向不存在 tag 的悬空引用，
sing-box 校验直接失败。因此过滤收敛在 `filterSingBoxNodes`（入口、返回新切片）。

## 取舍

- **不沿用 C++ 的 "version≥4 跳过"**：那是旧 clash premium 的限制；本版 Clash 渲染目标已对齐
  mihomo（官方 wiki 支持 `version: 4`），v4 节点照常输出。
- **不沿用 C++ 的 "snell 不输出 udp"**：同样针对旧 clash；mihomo 的 snell v3+ 支持 udp，
  按通用三态照常输出。
- **sing-box 仅 4/6**：sing-box 1.14.0 起才有 snell outbound 且 version 只接受 4 或 6
  （v6 新增 traffic shaping，obfs 仅 v4 有效）。v1/2/3 无法表达，剔除而非报错，
  与 Loon 侧"不支持即跳过"的既有策略一致。
- **Clash YAML 输入 psk 为空跳过节点**：与 ss 缺 cipher 跳过同策略（C++ 未校验，本版收紧）。

## 验证

- `go test ./...` 全绿：parser（URI 基本字段/obfs/version/缺 psk/默认名）、subscription
  （YAML snell + 缺 psk 跳过）、三渲染端（clash 字段断言、loon 行断言、singbox v4 输出 +
  v2 过滤且 selector 无悬空引用）。
- 端到端冒烟：`snell://` v4 与 YAML v2 混合输入 → clash/loon 均输出两节点，
  singbox 剔除 v2 并打日志 `singbox 跳过 snell 节点 ... 仅支持 4/6`。
