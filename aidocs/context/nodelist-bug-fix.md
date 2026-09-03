# NodeList 模式对 clash/loon 不生效的 bug 修复

## 问题

`list=true` 参数（NodeList 模式）只对 singbox 生效（singbox.go L509 判断了 `cfg.NodeList`），
clash 和 loon 没有判断 `cfg.NodeList`，用户传 `&list=true` 时仍输出完整配置（base template +
proxies + groups + rules），而不是只输出节点段。

## 原因

上次实现 10 个 /sub 参数时，Config 结构体里加了 `NodeList` 字段，singbox 渲染器正确判断了它，
但 clash 和 loon 的渲染函数没有加对应分支。

## 修复

- `RenderClash`：节点渲染后，若 `cfg.NodeList` 为 true，只写 `proxies:` 段返回，跳过 base
  template / proxy-groups / rules

- `RenderLoon`：节点渲染前，若 `cfg.NodeList` 为 true，只写 `[Proxy]` 段返回，跳过 general
  template / \[Remote Proxy] / \[Proxy Group] / \[Rule] / \[Remote Rule]

## 验证

`TestNodeListMode` 覆盖三种目标格式，验证：

- clash：含 `proxies:`，不含 `proxy-groups:` / `rules:`

- loon：含 `[Proxy]`，不含 `[Proxy Group]` / `[Rule]`

- singbox：纯数组输出，不含 `route`

