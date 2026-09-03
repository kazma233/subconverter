# Go 版与 C++ 版完整差异对照

> 基准：C++ 版 `archive/src/` 全量功能 vs Go 版当前实现（2026-09-03）

## 一、输入侧（协议解析）

### 协议类型

| 协议 | 做什么用的 | Go 版状态 |
|------|-----------|-----------|
| Shadowsocks (SS) | 最老牌的代理协议，机场最常见，加密流量 | 已实现 |
| ShadowsocksR (SSR) | SS 的衍生版，带混淆和协议插件，国内老机场仍有存量 | 缺失 |
| VMess | V2Ray 系主力协议，UUID + 加密，机场常见 | 已实现 |
| VLESS (含 REALITY) | VMess 的精简版，REALITY 可以伪装成访问真实网站，目前最主流 | 已实现 |
| Trojan | 把代理流量伪装成正常 HTTPS 流量，机场常用 | 已实现 |
| Hysteria2 | 基于 QUIC 的高速协议，支持端口跳跃和混淆，鸡场新主流 | 已实现 |
| AnyTLS | 新协议，把代理流量伪装成正常 TLS 双向认证 | 已实现 |
| Snell | Surge 私有协议，类似 Trojan 但 Surge 专用，只有 Surge 用户用 | 缺失 |
| HTTP/HTTPS | 透明 HTTP 代理，不需要加密，适合做中转链路或测试 | 缺失 |
| SOCKS5 | 经典代理协议，支持 UDP，部分机场用它做转发 | 缺失 |
| WireGuard | 轻量 VPN 协议，速度极快，部分机场用它提供整机代理 | 缺失 |
| Hysteria (v1) | Hysteria2 的前代，基于 QUIC 但协议设计不同，机场已基本迁移到 v2 | 缺失（可不做） |
| TUIC | 基于 QUIC 的新协议，支持多路复用和拥塞控制，有一定用户量 | 缺失 |

### 订阅/链接格式

| 格式 | 做什么用的 | Go 版状态 |
|------|-----------|-----------|
| base64 列表 | 机场最常用的订阅格式，整包 base64 编码的多行节点链接 | 已实现 |
| 明文逐行链接 | 不编码的逐行节点链接，部分机场用 | 已实现 |
| Clash YAML | 直接给 Clash 配置文件当订阅，带 proxies/proxy 两种键名 | 已实现 |
| Quantumult 格式 | Quantumult 客户端专有订阅格式（quan://），用的人少 | 缺失 |
| 标准 vmess:// | V2RayN 风格的 vmess 链接，base64 编码的 JSON | 已实现 |
| Shadowrocket 格式 | 小火箭 App 专有订阅格式，iOS 用户用 | 缺失 |
| Kitsunebi 格式 | Kitsunebi App 专有格式，用的人很少 | 缺失 |
| SSD 订阅 | 一种 JSON 订阅格式，一条链接展开多个节点，支持流量信息 | 缺失 |
| 本地配置文件 | 从本地 gui-config.json / .ini / .conf 导入节点，适合从客户端导出 | 缺失 |

### Proxy 结构体缺失字段

这些字段解析不了就不会输出到目标配置，导致节点功能不完整：

- **WireGuard 全套**：SelfIP/SelfIPv6（本机地址）、PrivateKey/PublicKey（密钥对）、PreSharedKey（预共享密钥）、DnsServers/Mtu/AllowedIPs 等，缺了无法用 WireGuard 节点
- **Hysteria v1**：Ports（端口跳跃）、UpSpeed/DownSpeed（限速）、AuthStr/QUICSecure/QUICSecret（认证和加密），v1 已过时可不做
- **TUIC 全套**：DisableSNI/ReduceRTT/RequestTimeout/UdpRelayMode/CongestionController/MaxOpenStreams 等，缺了 TUIC 节点连不上
- **Snell 全套**：SnellVersion/OBFS，Surge 专用
- **HTTP/SOCKS5**：Username/Password/TLS，基本的代理认证字段
- **mihomo 新字段**：IpVersion（IP 版本选择 v4/v6/dual）、ECH（加密客户端 Hello，防流量分析）、SMUX（多路复用，提升连接效率）、mTLS（双向证书认证）、VlessEncryption/VLESS XTLS 系列（流量伪装优化）、WebSocket max-early-data（提前发送数据减少延迟）、HTTP Method+多路径、TrojanSS 子加密
- **VLESS XTLS**：PacketEncoding/PacketAddr/GlobalPadding/AuthenticatedLength/XUDP，这些是 VLESS 的流量伪装增强，缺了可能被检测到

### 三态布尔

C++ 用 tribool（未设置/true/false）区分"没传参数"和"显式关掉"，Go 版 UDP/TCPFastOpen/SkipCertVerify 已改为 *bool 对齐。优先级：节点自带 > /sub 全局参数 > 不写（客户端默认）。

---

## 二、输出侧（目标格式）

| 输出格式 | 做什么用的 | Go 版状态 |
|---------|-----------|-----------|
| Clash (mihomo YAML) | Clash/mihomo 客户端配置文件，用户最多 | 已实现 |
| ClashR | Clash 的 SSR 变种，支持 SSR 协议的 protocol/obfs 字段，已基本没人用 | 不区分 |
| Loon (conf) | Loon App 配置文件，iOS 用户用 | 已实现 |
| sing-box (JSON) | sing-box 客户端配置，移动端和旁路由主流，Hysteria2/TUIC 支持最好 | 已实现 |
| Surge (conf) | Surge App 配置文件，iOS 高端用户用，规则语法和 Loon 类似 | 缺失 |
| Mellow (INI) | Mellow 客户端配置，用的人很少 | 缺失 |
| Quantumult X (conf) | Quantumult X App 配置，iOS 老用户，规则写法特殊 | 缺失 |
| Quantumult (老版) | Quantumult 老版本配置，基本没人用 | 缺失 |
| SS 订阅 (JSON) | 输出为 SS 聚合订阅 JSON，给 SS 客户端直接导入 | 缺失 |
| SSD 订阅 (JSON) | 输出为 SSD 格式订阅，带流量信息 | 缺失 |
| 单节点 URI | 把节点转回单条链接（如 ss://...），适合分享或导入其他工具 | 缺失 |

---

## 三、HTTP 路由

| 端点 | 做什么用的 | Go 版状态 |
|---------|-----------|-----------|
| GET /version | 返回版本号，方便检查服务是否在线 | 已实现 |
| GET /sub | 核心功能：订阅转换 | 已实现 |
| HEAD /sub | 只检查能不能转换成功，不返回内容，适合做探活 | 缺失 |
| GET / | 内嵌的订阅链接生成网页，选格式填地址生成链接 | 已实现 |
| GET /refreshrules | 手动触发刷新规则集缓存，规则更新后不用重启服务 | 缺失 |
| GET /readconf | 重新读取本地 pref 配置文件，改配置后不用重启 | 缺失 |
| POST /updateconf | 通过接口直接修改 pref 配置文件内容，远程管理 | 缺失 |
| GET /flushcache | 清空所有订阅/规则的内存缓存，强制下次重新拉取 | 缺失 |
| GET /sub2clashr | 简化版的 ClashR 转换，固定目标不用写 target 参数 | 缺失 |
| GET /surge2clash | 把 Surge 配置文件反过来转成 Clash，跨客户端迁移 | 缺失 |
| GET /getruleset | 单独下载某个规则集，给客户端直接引用 | 缺失 |
| GET /getprofile | 按本地 profiles 目录下的 ini 文件名生成配置，批量管理 | 缺失 |
| GET /render | 用 Jinja2 模板渲染自定义配置，高端用户自定义输出 | 缺失 |
| GET /get?url= | 通用 HTTP 抓取代理，让 subconverter 当下载工具用 | 缺失 |
| GET /getlocal?path= | 读本地任意文件，调试用 | 缺失 |

### /sub 参数

| 参数 | 做什么用的 | Go 版状态 |
|------|-----------|-----------|
| target / url / config / ua / filename | 基础参数：选格式、填地址、选规则、伪装 UA、设下载文件名 | 有 |
| include / exclude | 按节点名正则筛选保留或剔掉节点 | 有 |
| emoji / add_emoji / remove_emoji | 给节点名加国旗 emoji 或去 emoji，让列表更好认 | 有 |
| udp / tfo / scv | 全局开关 UDP 转发/TCP Fast Open/跳过证书校验，三态 | 有 |
| list | 只输出节点列表不输出完整配置，自己手动合并用 | 有 |
| new_name | Clash 字段名新旧写法切换，老内核兼容 | 有 |
| sort / fdn | 按名字排序 / 过滤已废弃加密方式 | 有 |
| proxy / folder / rename | 拉取时走代理 / 节点名加前缀 / 自定义改名 | 有 |
| expand | 控制策略组是否展开所有节点到组里（vs 只引用组名） | 缺失 |
| insert | 在输出配置里插入自定义段（如额外加一个策略组） | 缺失 |
| tls13 | 全局强制只用 TLS 1.3，不用 1.2，提升安全性 | 缺失 |

---

## 四、配置系统

C++ 版有一套完整的本地配置文件系统（pref.toml/yml/ini），可以把默认 UA、缓存时间、限速、规则路径、全局开关等全部写在配置文件里，不用每次 URL 传参。Go 版没有本地配置，所有参数只能通过 URL 传入。

| 能力 | 做什么用的 | Go 版状态 |
|---------|-----------|-----------|
| pref 本地配置文件 | 把默认设置写在文件里，不用每次 URL 传参，改了不用重新部署 | 完全缺失 |
| 全局 include/exclude/rename/emoji | 配置文件里写默认的筛选和重命名规则，所有请求自动生效 | 仅 URL 参数传入 |
| base/ 目录本地基础配置 | 存 Clash/Loon/sing-box 的基础模板文件，方便自定义默认配置 | 代码内硬编码模板 |
| 多级缓存 TTL | 订阅缓存 60 秒、配置缓存 300 秒、规则集缓存 6 小时自动刷新，保证规则不过期 | 进程内永久缓存，不自动刷新 |
| serveCacheOnFetchFail | 拉取失败时返回上次缓存的旧内容，而不是直接报错，提升可用性 | 缺失（拉取失败直接报错） |
| 限速 | 限制单次下载大小和规则集数量，防止恶意请求或意外拉取超大文件耗尽内存 | 缺失 |
| API_MODE + accessToken | 开启后只允许带正确 token 的请求访问，防止被人白嫖 | 缺失 |
| managedConfigPrefix | 给输出的托管配置加统一前缀名，方便客户端管理 | 缺失 |
| writeManagedConfig | 把转换结果写入本地文件，配合 getprofile 使用 | 缺失 |
| updateInterval | 在输出配置里写入自动更新间隔，客户端按这个频率自动更新订阅 | 缺失 |
| clashProxiesStyle | 控制 Clash 输出的节点字段风格（紧凑 vs 完整） | 缺失 |
| singBoxAddClashModes | sing-box 输出时附加 Clash 的策略模式（如 Global/Direct） | 缺失 |
| clashUseNewField / filterDeprecated | 全局默认使用新字段名 / 过滤废弃加密，不用每次 URL 传 | 仅 URL 参数级 |

---

## 五、脚本引擎

C++ 版内置了 JS 脚本引擎，用户可以用 JavaScript 脚本自定义节点排序、过滤、重命名逻辑。Go 版没有脚本引擎，排序和重命名只能用内置规则。

| 能力 | 做什么用的 | Go 版状态 |
|---------|-----------|-----------|
| QuickJS | 跑 JavaScript 脚本，用户用 JS 写自定义排序/过滤/重命名逻辑（如"按延迟排序""过滤非 HK 节点""把名字里的套餐类型提到前面"） | 完全缺失 |
| ChaiScript | 跑 C++ 风格脚本，用于自定义重命名和 emoji 匹配规则（比 JS 更轻量） | 完全缺失 |
| Duktape | 备用 JS 引擎，QuickJS 不可用时回退 | 完全缺失 |
| sort_script | 全局排序脚本，从配置文件读，每次请求自动执行 | 缺失 |
| filter_script | 全局过滤脚本，从配置文件读 | 缺失 |
| template_webGet | Jinja2 模板里的自定义函数，在模板中拉取远程内容 | 缺失 |
| parse_hostname | Jinja2 模板里的自定义函数，从 URL 解析主机名 | 缺失 |

---

## 六、Cron 定时任务

C++ 版可以配置定时任务，按 cron 表达式定期自动执行转换并输出到文件，适合无人值守场景。Go 版没有定时任务。

| 能力 | 做什么用的 | Go 版状态 |
|---------|-----------|-----------|
| CronTaskConfig | 定义定时任务：每隔多久执行、跑哪个脚本、超时多久 | 完全缺失 |
| refresh_schedule() | 启动时注册所有定时任务 | 缺失 |
| cron_tick() | 到时间了就触发，执行脚本把转换结果写到指定文件，不用人手动请求 | 缺失 |

---

## 七、规则集系统

规则集决定了流量怎么分流（哪些走代理、哪些直连、哪些拦截）。C++ 版支持本地文件和远程 URL，还支持不同客户端格式互转。Go 版只支持远程 URL。

| 能力 | 做什么用的 | Go 版状态 |
|---------|-----------|-----------|
| 远程 http(s) URL 规则集 | 从 GitHub 等下载规则列表（如 ACL4SSR），最主流方式 | 已实现 |
| 本地 .list 文件 | 规则文件存在本地 base/ 目录，不用每次远程拉取，适合自定义规则 | 拒绝非 http(s) 路径 |
| 规则类型互转 | 同一条规则在不同客户端写法不同（如 Surge 的 `DOMAIN-SUFFIX` 和 QuanX 的 `DOMAIN`），自动转换格式 | 缺失 |
| RULE-SET provider | Clash 的高级写法，规则集引用而不展开，配置文件更干净、更新规则不用改配置 | 仅展开为 rules 序列 |
| 规则集并发预取 | 多个规则集同时下载而不是一个一个等，速度快 | 已实现 |
| 共享缓存层 | 订阅、外配置、规则集用同一个缓存，同一 URL 只拉一次 | 各自独立缓存 |
| 缓存过期 | 规则集 6 小时后自动重新拉取，保证规则是最新的 | 进程内永久，不自动刷新 |

---

## 八、策略组类型

策略组是分流的核心：把节点分组，按不同策略选择使用哪个节点。

| 类型 | 做什么用的 | Go 版状态 |
|------|-----------|-----------|
| Select | 手动选哪个节点用，最常用 | 已实现 |
| URLTest | 自动测速选最快的节点，省心 | 已实现 |
| Fallback | 按顺序用，当前节点挂了自动切下一个，保证可用性 | 已实现 |
| LoadBalance | 多个节点轮流用，分摊流量压力 | 已实现（sing-box 退避为 selector） |
| Relay | 链式中继：A 节点连 B 节点再连目标，多跳加密提升匿名性 | 缺失 |
| SSID | 根据连的 Wi-Fi 名字自动切换策略（在家直连、在外走代理） | 缺失 |
| Smart | 智能选择，综合延迟和稳定性选节点 | 缺失 |
| URLTest.Lazy | 不主动测速，只在用到的时候才测，省流量 | 缺失 |
| URLTest.EvaluateBeforeUse | 用之前先测一遍，保证选的节点是好的 | 缺失 |
| URLTest.DisableUdp | 该组禁用 UDP，某些节点 UDP 质量差时用 | 缺失 |
| LoadBalance.Persistent | 同一目标固定走同一节点，不频繁切换，保持连接稳定 | 缺失 |

---

## 九、WebGet / 网络层

subconverter 自己去拉取订阅和规则时用的 HTTP 客户端能力。

| 能力 | 做什么用的 | Go 版状态 |
|---------|-----------|-----------|
| GET | 基础下载，拉取订阅和规则 | 已实现 |
| HEAD / POST / PATCH | 某些订阅需要 POST 带参数才能获取，或用 HEAD 检查是否有效 | 仅 GET |
| 代理 | subconverter 自己挂代理去拉订阅（比如本地有梯子，让它走梯子拉国外订阅） | 已实现 |
| Cookie | 带 Cookie 拉取，某些订阅需要登录态才能获取内容 | 缺失 |
| 自定义请求头 | 完整控制请求头，伪装成浏览器或其他客户端绕过限制 | 仅 UA |
| 响应头回传 | 把上游响应头透传给客户端（如 rate limit 信息） | 仅 subscription-userinfo |
| flushCache() | 手动清缓存，不用重启服务 | 缺失 |
| 缓存 TTL | 订阅 60 秒、配置 300 秒、规则集 6 小时自动过期重新拉 | 进程内永久 |
| 原始 Socket | 遇到奇怪的 CDN 或非标准 HTTP 服务器时用原始 Socket 拉取 | 缺失 |

---

## 十、其他系统

| 能力 | 做什么用的 | Go 版状态 |
|---------|-----------|-----------|
| 多线程安全 | 多个请求同时来时，配置读写不会互相干扰，C++ 用 safe_get/safe_set 互斥 | sync.Mutex + WaitGroup |
| 异步预取 | 提前下载好规则集和订阅，请求来时直接用缓存，不等下载 | sync.WaitGroup 简化版 |
| uploadGist | 把转换结果上传到 GitHub Gist，生成一个链接直接导入客户端，不用自己存文件 | 缺失 |
| Generator 模式 | 不启动 HTTP 服务，命令行直接把配置文件渲染成输出文件，适合 CI/CD 或批处理 | 缺失 |
| 订阅信息：Header 方式 | 从订阅响应头解析流量使用量和到期时间，显示给用户 | 已实现 |
| 订阅信息：节点备注方式 | 有些机场不在响应头里给流量信息，而是写在节点名里（如"剩余 100GB"），用正则提取 | 缺失 |
| 共享 TTL 缓存 | 订阅、规则、外配置用同一个缓存层，同 URL 只拉一次 | 各 client 独立 |
| tribool 三态 | 区分"没传参数"和"显式关掉"，保证优先级链路正确 | *bool 对齐 |

---

## 十一、YAML 引擎差异

| 方面 | C++ 版 | Go 版 |
|------|--------|-------|
| 引擎 | yaml-cpp | yaml.v3 |
| 引号风格 | 不强制引号，纯数字开头的字符串（如节点名 `29845e28`）可能被误判为 int，需要 hack 修复 | 强制双引号，从根上避免类型歧义 |
| short-id 校验 | 渲染期清洗（奇数长度补零、非法字符丢弃），保证 REALITY short-id 格式正确 | 不校验，原样透传（双引号防止 YAML 误判类型） |

---

## 十二、正则引擎差异

| 方面 | C++ 版 | Go 版 |
|------|--------|-------|
| 引擎 | PCRE2 | RE2 |
| lookahead/lookbehind | 支持 `(?=...)`、`(?!...)`、`(?<=...)`、`(?<!...)`（前后瞻断言，比如"匹配日本但前面不能是东"） | 不支持，用了会静默失效 |
| 反向引用 | 支持 `\1`（引用前面捕获的内容，用于匹配成对内容） | 不支持 |
| 常用写法 | 全支持 | 子串、前缀后缀、字符类、量词、分组捕获全支持 |

---

## 十三、部署差异

| 方面 | C++ 版 | Go 版 |
|------|--------|-------|
| 构建 | 静态依赖链重，交叉编译复杂，不同平台要编不同二进制 | 单二进制，多阶段 Docker 构建，一个镜像通吃 |
| 配置文件 | pref.toml/yml/ini 本地文件，改了重启生效 | 无本地配置，所有参数通过 URL 传入 |
| 规则资产 | base/ 目录可选存本地规则文件 | 全远程拉取，镜像不含规则 |
| 日志 | 控制台或文件 | SUBCONV_ENV 环境变量切换控制台/文件 |
