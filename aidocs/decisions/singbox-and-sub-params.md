# sing-box 输出格式 + /sub 参数补齐

## 背景

Go 版 subconverter 相对 C++ 原版存在两大缺口：

1. **输出格式**：仅支持 Clash YAML 和 Loon conf，缺少 sing-box JSON（当前移动端/旁路由主流客户端）
2. **/sub 参数**：仅支持 target/url/config/filename/ua/include/exclude 7 个参数，缺少 emoji/udp/tfo/scv/list/new\_name/sort/depr/proxy/folder 等常用开关

本次迭代补齐这两块，不引入配置系统/脚本/cron 等更大范围功能。

## 决策

### sing-box 渲染器（`internal/render/singbox.go`）

- **顶层结构**：最小化 base（log + dns + mixed inbound）+ outbounds 数组 + route.rules

- **节点出站**：6 种协议（SS/VMess/Trojan/VLESS/AnyTLS/Hysteria2），字段对齐 sing-box 1.10 schema

- **Hysteria2 完整字段**：server\_ports（逗号/冒号/范围解析）、up/down\_mbps、obfs（salamander + password）、hop\_interval（秒→自动补 s 后缀）、cwnd、tls（insecure/server\_name/alpn/certificate\_path）

- **REALITY**：VLESS 写 `tls.reality.{public_key, short_id}` + `tls.utls.{enabled, fingerprint}`

- **策略组**：Select→selector；URLTest/Fallback→urltest；LoadBalance→selector 退避（sing-box 1.10 无 loadbalance 出站）

- **规则**：复用 `renderRules(cfg.ACL)` 展开 Clash 文本规则，再经 `sbBuildRule` 转为 sing-box `route.rules` 结构（DOMAIN/SUFFIX/KEYWORD、IP-CIDR、GEOIP、PORT、PROCESS-NAME）

- **nodelist 模式**：`list=true` 只输出 `[]outbounds` 纯数组

### /sub 参数（10 个）

| 参数        | 行为                                                         | 实现位置                              |
| --------- | ---------------------------------------------------------- | --------------------------------- |
| emoji     | true = 先去旧 emoji 再按 24 条区域/用途规则加国旗                         | preprocess.go `ApplySubOverrides` |
| udp       | 三态 \*bool：nil 不覆盖；非 nil 强制覆盖所有节点                           | preprocess.go                     |
| tfo       | 三态，Clash 输出 fast-open、Loon 输出 fast-open=, sing-box 走各节点    | clash.go/loon.go                  |
| scv       | 三态（别名 skip-cert-verify），输出 skip-cert-verify / tls.insecure | clash.go/loon.go/singbox.go       |
| list      | true 只输出节点段，跳过 base/groups/rules                           | clash.go/loon.go/singbox.go       |
| new\_name | nil/true → Clash 写 sni（新字段）；false → servername（旧兼容）        | clash.go `clashSNIField`          |
| sort      | true 按节点名字典序升序                                             | preprocess.go                     |
| depr      | true（别名 fdn）过滤 SS chacha20 等废弃加密                           | preprocess.go                     |
| proxy     | 非空时作为 HTTP/SOCKS5 代理拉取订阅                                   | fetch.go `FetchSubscription`      |
| folder    | 非空时所有节点名加前缀 `"{folder} - 原名"`                              | preprocess.go                     |
| rename    | `pattern@replacement@@pattern2@replacement2` 自定义重命名        | preprocess.go `RenameRule`        |

### 三态覆盖优先级（对齐 C++ tribool）

```
节点 URI 自带参数 > /sub 全局参数 > 不写（客户端默认）
```

model.Proxy 的 UDP/TCPFastOpen/SkipCertVerify 改为 `*bool`：

- parser 只在 URI 有显式值时赋指针，否则 nil

- ApplySubOverrides 在 Config 非 nil 时覆盖

- 渲染层 nil 不输出该字段

## 取舍

- **不做本地 pref 配置系统**：config 参数仍只接受 http(s) URL，不读本地文件

- **不做规则集本地 .list 文件**：`loadRulesetContent` 只支持 http(s) URL，本地路径报错跳过

- **不做脚本引擎**：排序/过滤/重命名用内置规则表实现，不支持 QuickJS/ChaiScript

- **rename 参数**：用 `pattern@replacement` 简写语法，不走正则捕获组之外的复杂逻辑

- **emoji 规则表**：内置 24 条常见区域/用途关键词，不支持自定义规则文件

