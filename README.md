# subconv

把机场订阅链接转换成 Clash、Loon、sing-box 客户端能用的配置文件。
**Go 实现**（原 C++ 版代码归档于 `archive/`，仅作参考不再构建）。

支持 vless/REALITY、anytls、ss、trojan、hysteria2、vmess 协议，
规则和策略组从 ACL4SSR 等仓库实时拉取，镜像本身不含规则文件。

## 快速开始（本地部署三行命令）

```bash
docker build -t subconv .
docker run -d --name subconv -p 25600:25600 subconv
curl "http://localhost:25600/sub?target=clash&url=<订阅地址URL编码>"
```

浏览器打开 `http://localhost:25600/` 就是订阅链接生成页
（内嵌于二进制，不用额外装东西）：选格式、粘贴订阅地址、挑一个 ACL4SSR 预设，
自动拼好 `/sub` 链接，复制就能用。

不带 Docker 直接运行（需 Go 1.25+，工作目录为仓库根）：

```bash
go build -o subconv . && ./subconv          # 默认监听 :25600
```

规则和策略组都是**运行时实时拉取的**（进程内缓存，重启后重新拉）：
镜像里不含任何规则文件，拉不到就报错，不偷偷兜底。

## `/sub` 参数表

| 参数 | 必填 | 默认值 | 说明 |
| -- | -- | -- | -- |
| `target` | 是 | — | 输出哪种格式：`clash` / `loon` / `singbox`，填别的返回 400 |
| `url` | 是 | — | 订阅地址或节点链接，多个用 `\|` 隔开；节点链接和 http(s) 订阅地址可以混着填，多段会按顺序合并。任何一段拉取或解析失败，整体报 400 |
| `config` | 否 | ACL4SSR_Online_Full | 规则和策略组的配置文件，**只支持完整 http(s) 链接**。不传时默认用 [ACL4SSR\_Online\_Full.ini](https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/config/ACL4SSR_Online_Full.ini) |
| `include` | 否 | — | 只保留名字匹配这个正则的节点 |
| `exclude` | 否 | — | 剔掉名字匹配这个正则的节点；和 `include` 可以一起用 |
| `ua` | 否 | `clash.meta` | 拉订阅时用的 User-Agent |
| `filename` | 否 | — | 下载时的文件名（Content-Disposition） |
| `emoji` | 否 | 不加 | `true` = 先把节点名里已有的 emoji 去掉，再按地区/用途关键词自动加国旗（🇭🇰🇯🇵🇺🇸…）和 Netflix/AI 标签 |
| `udp` | 否 | 按节点自身 | 全局开关 UDP 转发：`true` 全开、`false` 全关、不填按节点自己的设置 |
| `tfo` | 否 | 按节点自身 | 全局开关 TCP Fast Open：`true` 全开、`false` 全关、不填按节点自己的设置 |
| `scv` | 否 | 按节点自身 | 全局开关跳过证书校验（别名 `skip-cert-verify`）：`true` 跳过、`false` 不跳、不填按节点自己的设置。自签证书或抓包时用 |
| `list` | 否 | `false` | `true` = 只输出节点列表，不要基础配置、策略组和规则。适合自己手动合并配置的场景 |
| `sort` | 否 | `false` | `true` 按节点名字母排序 |
| `depr` | 否 | `false` | `true`（别名 `fdn`）过滤掉已废弃的加密方式（比如 SS 的 `chacha20`，新版 Clash.Meta（mihomo）不认） |
| `proxy` | 否 | 直连 | 拉取订阅时走的代理，填 `http://127.0.0.1:7890` 或 `socks5://127.0.0.1:1080` 这种 |
| `folder` | 否 | — | 给所有节点名加前缀，比如 `folder=机场A` → 节点名变成 `机场A - 原名` |
| `rename` | 否 | — | 自定义改名：`旧名@新名`，多组用 `@@` 隔开，比如 `香港@HK@@日本@JP` |

如果订阅响应带了流量信息（`subscription-userinfo` 头），会原样透传给客户端，方便看用了多少流量。

Clash 的 TLS SNI 字段由协议决定：vless/vmess 固定输出 mihomo 所需的 `servername`，trojan/hysteria2/anytls 保持 `sni`；不再提供 `new_name` 切换。

示例：

```
/sub?target=loon&url=https%3A%2F%2Fexample.com%2Fsub&exclude=%E6%97%A5%E6%9C%AC

# 换一个规则配置（config 必须是完整 URL）
/sub?target=clash&url=<订阅URL>&config=https%3A%2F%2Fraw.githubusercontent.com%2FACL4SSR%2FACL4SSR%2Frefs%2Fheads%2Fmaster%2FClash%2Fconfig%2FACL4SSR_Online_Mini.ini
```

## 日志

- **开发模式（默认）**：不设 `SUBCONV_ENV` 或设成非 `production`，日志直接打到控制台。
- **生产模式**：设 `SUBCONV_ENV=production`，日志写到 `LOG_FILE` 指定的文件里（目录不存在会自动建）；
  不设 `LOG_FILE` 默认 `/var/log/subconv/subconv.log`，和 Docker 的日志卷对应，不用额外配置。
- 记录内容：所有访问请求（方法/路径/状态码/耗时/来源 IP，包括 404）、
  `/sub` 入口信息（格式/订阅段数/规则配置）、订阅和规则拉取情况、
  节点过滤结果、渲染完成情况（节点数/输出大小/耗时）、失败原因。
  订阅地址里的 token 不会记进日志，只记域名。

## 输入侧支持的协议

| 协议        | 链接形态                                                    | 备注                       |
| --------- | ------------------------------------------------------- | ------------------------ |
| vless     | `vless://uuid@host:port?...`（含 REALITY：pbk/sid/fp/flow） | short-id 不做校验直接传，能不能用由客户端判断 |
| vmess     | `vmess://` base64 JSON                                  | 新旧字段变体兼容                 |
| ss        | `ss://`                                                 | 明文与 base64 用户信息均可        |
| trojan    | `trojan://`                                             | <br />                   |
| hysteria2 | `hysteria2://` / `hy2://`                               | 支持 salamander 混淆和端口跳跃       |
| anytls    | `anytls://`                                             | <br />                   |

订阅内容支持：base64 列表、明文逐行链接、Clash YAML（含 `Proxy`/`proxies` 两种键名）。

## RE2 正则限制（重要）

Go 的正则引擎是 **RE2**，和 C++ 版用的 PCRE2 有点不一样：

- **不支持** `(?=...)`、`(?!...)`、`(?<=...)`、`(?<!...)` 这些前后瞻语法，也不支持反向引用 `\1`

- **能用**：普通子串、前缀/后缀匹配、字符类、量词、分组捕获这些常用写法都没问题

所以 `include`/`exclude` 和外配置里的正则，请用简单子串/前缀风格写；
用了 lookahead 的正则会静默失效（不报错但这个条件被忽略）。

## 与 C++ 版的差异摘要

| 方面                | C++ 版                                | Go 版                                                        |
| ----------------- | ------------------------------------ | ----------------------------------------------------------- |
| 输出格式        | 18 种（Surge/QuantumultX 等）     | clash / loon / singbox                        |
| 脚本/模板引擎     | QuickJS、libcron、inja 模板        | 不支持                                        |
| YAML 引擎     | yaml-cpp，引号问题需 hack 修复       | yaml.v3，强制双引号，不会有类型歧义问题               |
| short-id 校验 | 渲染期清洗（奇数补零/非法丢弃）           | 不校验，原样透传（双引号防歧义）                         |
| 正则引擎        | PCRE2                        | RE2（见上文限制）                              |
| Loon vless/anytls | 没实现（节点被丢弃）                 | 按 Loon 3.x 语法补齐了（含 REALITY）               |
| 订阅拉取        | libcurl（全局 UA、缓存 TTL、代理规则）   | net/http（默认 UA clash.meta、10s 超时、单次重试、gzip 解压、流量信息头回传） |
| 部署          | 静态依赖链重，交叉编译复杂               | 单二进制，多阶段 Docker 构建                       |
| 本地生成/档案     | `-g`、profile、gist 上传等       | 不支持                                        |

## 开发

```bash
go mod tidy && go build ./... && go vet ./... && go test ./...
```

- `internal/parser` 输入解析、`internal/render` 三种格式渲染与规则装载
- `internal/rule` ACL4SSR 配置解析、`internal/fetch` 订阅拉取、`internal/server` HTTP 服务

- `testdata/subscription.txt`：23 节点 REALITY 脱敏样本（含 3 个 `29845e28`、1 个 `40452118` 回归用例）

- `testdata/acl_mini.ini` + `testdata/lan.list`：ACL 外配置与规则集测试样本（全远程语义）

