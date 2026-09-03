# Go 版与 C++ 版完整差异对照

> 基准：C++ 版 `archive/src/` 全量功能 vs Go 版当前实现（2026-09-03）

## 一、输入侧（协议解析）

### C++ 支持的协议类型（14 种）

| 协议 | C++ 函数 | Go 版状态 |
|------|----------|-----------|
| Shadowsocks (SS) | `explodeSS` / `explodeSSConf` | 已实现 |
| ShadowsocksR (SSR) | `explodeSSR` / `explodeSSRConf` | 缺失 |
| VMess | `explodeStdVMess` / `explodeVMessConf` | 已实现 |
| VLESS (含 REALITY) | `explodeStdVLESS` | 已实现 |
| Trojan | `explodeTrojan` | 已实现 |
| Hysteria2 | `explodeStdHysteria2` | 已实现 |
| AnyTLS | `explodeStdAnyTLS` | 已实现 |
| Snell | `snellConstruct` | 缺失 |
| HTTP/HTTPS | `httpConstruct` | 缺失 |
| SOCKS5 | `socksConstruct` | 缺失 |
| WireGuard | `explodeWireGuard` | 缺失 |
| Hysteria (v1) | `hysteriaConstruct` | 缺失（机场已基本迁到 v2） |
| TUIC | `tuicConstruct` | 缺失 |

### C++ 支持的订阅/链接格式

| 格式 | C++ 函数 | Go 版状态 |
|------|----------|-----------|
| base64 列表 | `explode` + base64 解码 | 已实现 |
| 明文逐行链接 | `explode` | 已实现 |
| Clash YAML | `explodeSub` (proxy/proxies 双键名) | 已实现 |
| Quantumult 格式 | `explodeQuan` | 缺失 |
| 标准 vmess:// | `explodeStdVMess` (V2RayN JSON base64) | 已实现 |
| Shadowrocket 格式 | `explodeShadowrocket` | 缺失 |
| Kitsunebi 格式 | `explodeKitsunebi` | 缺失 |
| SSD 订阅 | `explodeSSD` (一次展开多节点) | 缺失 |
| 本地配置文件 | `explodeConf` / `explodeConfContent` (gui-config.json / .ini / .conf) | 缺失 |

### Proxy 结构体字段差异

C++ `proxy.h` 定义了约 150 个字段，Go 版已收录核心子集。缺失的字段：

- WireGuard 全套：SelfIP/SelfIPv6/PrivateKey/PublicKey/PreSharedKey/DnsServers/Mtu/AllowedIPs/KeepAlive/TestUrl/ClientId
- Hysteria v1：Ports/UpSpeed/DownSpeed/AuthStr/QUICSecure/QUICSecret/RecvWindow/DisableMtuDiscovery/HopInterval
- TUIC 全套：DisableSNI/ReduceRTT/RequestTimeout/UdpRelayMode/CongestionController/MaxUdpRelayPacketSize/MaxDatagramFrameSize/FastOpen/MaxOpenStreams
- Snell 全套：SnellVersion/OBFS
- HTTP/SOCKS5：Username/Password/TLS
- mihomo 新字段：IpVersion/ECH/SMUX/mTLS/VlessEncryption/WebSocket max-early-data/HTTP Method+多路径/TrojanSS 子加密
- VLESS XTLS：PacketEncoding/PacketAddr/GlobalPadding/AuthenticatedLength/XUDP

### 三态布尔字段

C++ 用 tribool（未设置/true/false），Go 版 UDP/TCPFastOpen/SkipCertVerify 已改为 *bool 对齐三态语义。其余布尔字段（如 TLSSecure）仍用普通 bool。

---

## 二、输出侧（目标格式）

| C++ 输出格式 | C++ 函数 | Go 版状态 |
|-------------|----------|-----------|
| Clash (mihomo YAML) | `proxyToClash` | 已实现 |
| ClashR | `proxyToClash` (clashR 变种字段) | 不区分 clash/clashr |
| Loon (conf) | `proxyToLoon` | 已实现 |
| sing-box (JSON) | `proxyToSingBox` + `rulesetToSingBox` | 已实现 |
| Surge (conf) | `proxyToSurge` + `rulesetToSurge` | 缺失 |
| Mellow (INI) | `proxyToMellow` | 缺失 |
| Quantumult X (conf) | `proxyToQuanX` | 缺失 |
| Quantumult (老版 conf) | `proxyToQuan` | 缺失 |
| SS 订阅 (JSON) | `proxyToSSSub` | 缺失 |
| SSD 订阅 (JSON) | `proxyToSSD` | 缺失 |
| 单节点 URI | `proxyToSingle` | 缺失 |

---

## 三、HTTP 路由

| C++ 端点 | 用途 | Go 版状态 |
|---------|------|-----------|
| GET /version | 版本信息 | 已实现 |
| GET /sub | 订阅转换 | 已实现 |
| HEAD /sub | 探活 | 缺失 |
| GET / | 内嵌订阅链接生成页 | 已实现 |
| GET /refreshrules?token= | 手动刷新规则集缓存 | 缺失 |
| GET /readconf?token= | 重载 pref 配置 | 缺失 |
| POST /updateconf?token= | 写入并更新 pref 文件 | 缺失 |
| GET /flushcache?token= | 清空订阅缓存 | 缺失 |
| GET /sub2clashr | 简化版 ClashR 转换 | 缺失 |
| GET /surge2clash | Surge conf -> Clash | 缺失 |
| GET /getruleset | 单规则集转换下载 | 缺失 |
| GET /getprofile | 按 profile 名称生成配置 | 缺失 |
| GET /render | Jinja2 模板渲染接口 | 缺失 |
| GET /get?url= | 通用 HTTP 代理抓取（非 API 模式） | 缺失 |
| GET /getlocal?path= | 读取本地文件（非 API 模式） | 缺失 |

### /sub 参数对比

| 参数 | C++ | Go 版 |
|------|-----|-------|
| target / url / config / ua / filename | 有 | 有 |
| include / exclude | 有 | 有 |
| emoji / add_emoji / remove_emoji | 有 | 有 |
| udp / tfo / scv | tribool | *bool 三态 |
| list (nodelist) | 有 | 有 |
| new_name | 有 | 有 |
| sort / fdn (filter_deprecated) | 有 | 有 |
| proxy (拉取代理) | 有 | 有 |
| folder (分组前缀) | 有 | 有 |
| rename | RegexMatchConfig | 简写 pattern@replacement |
| expand | 有 | 缺失 |
| insert | 有 | 缺失 |
| clash.depr / clash.use_new_field | 全局 pref | 仅 URL 参数级 |
| tls13 | 有 | 缺失 |

---

## 四、配置系统

| C++ 能力 | 说明 | Go 版状态 |
|---------|------|-----------|
| pref.toml/yml/ini 三级回退 | 本地配置文件，优先 toml -> yml -> ini | 完全缺失 |
| 外配置 include/exclude/rename/emoji/base | 全局列表从 pref 读 | 仅 URL 参数传入 |
| base/ 目录本地基础配置 | clashBase/surgeBase/loonBase/singBoxBase 等 | 代码内模板字符串 |
| 多级缓存 TTL | cacheSubscription 60s / cacheConfig 300s / cacheRuleset 21600s | 进程内缓存无 TTL |
| serveCacheOnFetchFail | 拉取失败时返回旧缓存 | 缺失 |
| 限速 | maxAllowedDownloadSize / maxAllowedRulesets / maxAllowedRules | 缺失 |
| API_MODE / accessToken | API 模式开关 + token 鉴权 | 缺失 |
| managedConfigPrefix / writeManagedConfig | 托管配置前缀 + 写入文件 | 缺失 |
| updateInterval | 订阅更新间隔写入配置 | 缺失 |
| clashProxiesStyle / clashProxyGroupsStyle | Clash 输出风格控制 | 缺失 |
| singBoxAddClashModes | sing-box 附加 Clash 模式 | 缺失 |
| clashUseNewField / filterDeprecated / appendType | 全局开关 | 仅 URL 参数级 |

---

## 五、脚本引擎

| C++ 能力 | 说明 | Go 版状态 |
|---------|------|-----------|
| QuickJS | JS 排序/过滤/重命名脚本（nodemanip preprocessNodes） | 完全缺失 |
| ChaiScript | 自定义重命名/emoji 规则脚本（script: 前缀） | 完全缺失 |
| Duktape | 备用 JS 引擎 | 完全缺失 |
| sort_script / filter_script | Settings 全局脚本字段 | 缺失 |
| template_webGet / parse_hostname | Jinja2 自定义函数 | 缺失 |

---

## 六、Cron 定时任务

| C++ 能力 | 说明 | Go 版状态 |
|---------|------|-----------|
| CronTaskConfig | cron 表达式 + 脚本路径 + 超时 | 完全缺失 |
| refresh_schedule() | 启动时注册定时任务 | 缺失 |
| cron_tick() | 触发执行，输出到指定 Path | 缺失 |

---

## 七、规则集系统

| C++ 能力 | 说明 | Go 版状态 |
|---------|------|-----------|
| 远程 http(s) URL 规则集 | 下载 + 缓存 | 已实现 |
| 本地 base/ 目录 .list 文件 | find_local=true 分支 | 拒绝非 http(s) 路径 |
| 规则类型互转 | Surge <-> QuanX <-> Clash(Domain/IPCIDR/Classical) | 缺失 |
| RULE-SET provider 写法 | clash-classical-ruleset 模式 | 仅展开为 rules 序列 |
| 规则集并发预取 | shared_future 异步 + TTL 缓存 | sync.WaitGroup + 内存缓存 |
| 订阅/外配置/规则集共享缓存层 | 统一 TTL 缓存 | 各有各的 client |
| 缓存过期 | TTL 过期自动刷新 | 进程内永久缓存 |

---

## 八、策略组类型

| C++ 类型 | 说明 | Go 版状态 |
|---------|------|-----------|
| Select | 手动选择 | 已实现 |
| URLTest | 自动测速选最快 | 已实现 |
| Fallback | 故障转移 | 已实现 |
| LoadBalance | 负载均衡 | 已实现（sing-box 退避为 selector） |
| Relay | 链式中继 | 缺失 |
| SSID | 按 Wi-Fi SSID 切换 | 缺失 |
| Smart | 智能选择 | 缺失 |
| URLTest.Lazy | 延迟测速 | 缺失 |
| URLTest.EvaluateBeforeUse | 使用前评估 | 缺失 |
| URLTest.DisableUdp | 禁用 UDP | 缺失 |
| LoadBalance.Persistent | 持久化 | 缺失 |

---

## 九、WebGet / 网络层

| C++ 能力 | 说明 | Go 版状态 |
|---------|------|-----------|
| GET | 基础下载 | 已实现 |
| HEAD / POST / PATCH | 多方法支持 | 仅 GET |
| 代理 | HTTP/SOCKS5 代理抓取 | 已实现（proxy 参数） |
| Cookie | 入参 cookies + 回传 response cookies | 缺失 |
| 自定义请求头 | 完整 string_icase_map | 仅 UA |
| 响应头回传 | 返回完整响应头 | 仅 subscription-userinfo |
| flushCache() | 显式清缓存 | 缺失 |
| 缓存 TTL | 60s/300s/21600s 分级 | 进程内永久 |
| 原始 Socket | HTTP/HTTPS 原始 Socket 抓取 | 缺失 |

---

## 十、其他系统

| C++ 能力 | 说明 | Go 版状态 |
|---------|------|-----------|
| 多线程安全 | safe_get/safe_set 全局 Settings 互斥读写 | sync.Mutex + WaitGroup |
| fetchFileAsync | shared_future 异步预取 | sync.WaitGroup 简化版 |
| uploadGist | 渲染结果上传 GitHub Gist | 缺失 |
| Generator 模式 (-g/--gen) | 离线渲染 profiles/*.ini -> 输出文件 | 缺失 |
| 订阅信息：Header 方式 | 从响应头解析流量信息 | 已实现 |
| 订阅信息：节点备注方式 | 按正则从节点 Remark 提取流量/过期时间 | 缺失 |
| 多线程异步预取缓存 | 订阅/规则/外配置共享 TTL 缓存 | 各 client 独立 |
| tribool 三态 | 未设置/true/false | *bool 对齐 |

---

## 十一、YAML 引擎差异

| 方面 | C++ 版 | Go 版 |
|------|--------|-------|
| 引擎 | yaml-cpp | yaml.v3 |
| 引号风格 | 无强制引号（29845e28 需 hack 修复） | 强制 DoubleQuotedStyle |
| 类型歧义 | 数字开头字符串可能被误判为 int | 从根上免疫 |
| short-id 校验 | 渲染期清洗（奇数补零/非法丢弃） | 不校验，原样透传（双引号防歧义） |

---

## 十二、正则引擎差异

| 方面 | C++ 版 | Go 版 |
|------|--------|-------|
| 引擎 | PCRE2 | RE2 |
| lookahead/lookbehind | 支持 | 不支持，静默失效 |
| 反向引用 | 支持 | 不支持 |
| 常用写法 | 全支持 | 全支持 |

---

## 十三、部署差异

| 方面 | C++ 版 | Go 版 |
|------|--------|-------|
| 构建 | 静态依赖链重，交叉编译复杂 | 单二进制，多阶段 Docker |
| 配置文件 | pref.toml/yml/ini 本地文件 | 无本地配置，URL 参数传入 |
| 规则资产 | base/ 目录可选本地文件 | 全远程拉取 |
| 日志 | 控制台/文件 | SUBCONV_ENV 控制台/文件 |
