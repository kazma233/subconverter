package render

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"subconv/internal/model"
	"subconv/internal/rule"
)

// ---------- sing-box 顶层 JSON 结构 ----------

type singBoxConfig struct {
	Log       singBoxLog        `json:"log,omitempty"`
	DNS       singBoxDNS        `json:"dns,omitempty"`
	Inbounds  []any             `json:"inbounds,omitempty"`
	Outbounds []json.RawMessage `json:"outbounds"`
	Route     singBoxRoute      `json:"route,omitempty"`
}

type singBoxLog struct {
	Level string `json:"level,omitempty"`
}
type singBoxDNSServer struct {
	Tag     string `json:"tag"`
	Address string `json:"address"`
	Detour  string `json:"detour,omitempty"`
}
type singBoxDNS struct {
	Servers []singBoxDNSServer `json:"servers,omitempty"`
}
type singBoxMixedInbound struct {
	Type    string `json:"type"`
	Tag     string `json:"tag"`
	Listen  string `json:"listen,omitempty"`
	ListenP uint16 `json:"listen_port,omitempty"`
}
type singBoxRoute struct {
	Rules []singBoxRule `json:"rules,omitempty"`
	Final string        `json:"final,omitempty"`
}
type singBoxRule struct {
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
	SourceIPCIDR  []string `json:"source_ip_cidr,omitempty"`
	GeoIP         []string `json:"geoip,omitempty"`
	SourcePort    []uint16 `json:"source_port,omitempty"`
	DestPort      []uint16 `json:"destination_port,omitempty"`
	ProcessName   []string `json:"process_name,omitempty"`
	Outbound      string   `json:"outbound"`
}

// ---------- helpers ----------

// triString 仅当指针非 nil 且为 true 返回 "true" 串，供 JSON 布尔字段判断。
func triTrue(b *bool) bool  { return b != nil && *b }
func triFalse(b *bool) bool { return b != nil && !*b }

// sbServerName 决策 tls.server_name：优先 SNI，次选 Host，空返回空串（不写）。
func sbServerName(p *model.Proxy) string {
	if p.SNI != "" {
		return p.SNI
	}
	return ""
}

// sbSplitPortRanges 校验并标准化 Hysteria2 端口范围。sing-box 的 server_ports
// 使用字符串范围而非端口数字数组，保留范围才不会丢失中间端口。
func sbSplitPortRanges(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		sep := ""
		if strings.Contains(part, ":") {
			sep = ":"
		} else if strings.Contains(part, "-") {
			sep = "-"
		}

		bounds := []string{part}
		if sep != "" {
			bounds = strings.Split(part, sep)
			if len(bounds) != 2 || strings.Contains(bounds[1], ":") || strings.Contains(bounds[1], "-") {
				continue
			}
		}
		start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
		if err != nil || start < 1 || start > 65535 {
			continue
		}
		if len(bounds) == 1 {
			out = append(out, strconv.Itoa(start))
			continue
		}
		end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
		if err != nil || end < start || end > 65535 {
			continue
		}
		out = append(out, strconv.Itoa(start)+":"+strconv.Itoa(end))
	}
	return out
}

// appendTLS 在出站对象中写入 "tls" 字段；scv / sni / alpn / ca 等按非空条件写入。
// realityOut 非 nil 时再追加 reality + utls 结构。
func appendTLS(out map[string]any, p *model.Proxy, scv *bool, realityOut map[string]any) {
	tls := map[string]any{"enabled": true}
	if scv != nil {
		tls["insecure"] = *scv
	}
	if sn := sbServerName(p); sn != "" {
		tls["server_name"] = sn
	}
	if len(p.ALPN) > 0 {
		// sing-box Hysteria2/TUIC/VLESS 习惯写单值 alpn；多个时取第一个
		first := p.ALPN[0]
		if len(p.ALPN) == 1 {
			tls["alpn"] = []string{first}
		} else {
			cp := make([]string, len(p.ALPN))
			copy(cp, p.ALPN)
			tls["alpn"] = cp
		}
	}
	if p.CACertStr != "" {
		tls["certificate"] = p.CACertStr
	} else if p.CACertPath != "" {
		tls["certificate_path"] = p.CACertPath
	}
	if realityOut != nil {
		tls["reality"] = realityOut
		// utls 跟随 reality 启用；指纹优先 ClientFingerprint，次选 Fingerprint
		fp := p.ClientFingerprint
		if fp == "" {
			fp = p.Fingerprint
		}
		if fp == "" {
			fp = "chrome"
		}
		tls["utls"] = map[string]any{
			"enabled":     true,
			"fingerprint": fp,
		}
	}
	out["tls"] = tls
}

// ---------- 每个协议输出单个出站 map ----------

func sbOutboundSS(p *model.Proxy) map[string]any {
	out := map[string]any{
		"type":        "shadowsocks",
		"tag":         p.Name,
		"server":      p.Server,
		"server_port": p.Port,
		"method":      p.Cipher,
		"password":    p.Password,
	}
	return out
}

func sbOutboundVMess(p *model.Proxy) map[string]any {
	out := map[string]any{
		"type":        "vmess",
		"tag":         p.Name,
		"server":      p.Server,
		"server_port": p.Port,
		"uuid":        p.UUID,
		"security":    firstNonEmptySB(p.Security, "auto"),
	}
	if p.AlterID != 0 {
		out["alter_id"] = p.AlterID
	}
	if p.TLSSecure {
		appendTLS(out, p, p.SkipCertVerify, nil)
	}
	sbAppendTransport(out, p)
	return out
}

func sbOutboundTrojan(p *model.Proxy) map[string]any {
	out := map[string]any{
		"type":        "trojan",
		"tag":         p.Name,
		"server":      p.Server,
		"server_port": p.Port,
		"password":    p.Password,
	}
	appendTLS(out, p, p.SkipCertVerify, nil)
	sbAppendTransport(out, p)
	return out
}

func sbOutboundVLESS(p *model.Proxy) map[string]any {
	out := map[string]any{
		"type":            "vless",
		"tag":             p.Name,
		"server":          p.Server,
		"server_port":     p.Port,
		"uuid":            p.UUID,
		"packet_encoding": "xudp",
	}
	flow := ""
	if p.Flow != "" {
		flow = p.Flow
	}
	if flow != "" {
		out["flow"] = flow
	}
	var reality map[string]any
	if p.PublicKey != "" {
		reality = map[string]any{"enabled": true, "public_key": p.PublicKey}
		if sid := strings.TrimSpace(p.ShortID); sid != "" {
			reality["short_id"] = sid
		}
	}
	if p.TLSSecure || reality != nil {
		appendTLS(out, p, p.SkipCertVerify, reality)
	}
	sbAppendTransport(out, p)
	return out
}

func sbOutboundAnyTLS(p *model.Proxy) map[string]any {
	out := map[string]any{
		"type":        "anytls",
		"tag":         p.Name,
		"server":      p.Server,
		"server_port": p.Port,
		"password":    p.Password,
	}
	appendTLS(out, p, p.SkipCertVerify, nil)
	return out
}

func sbOutboundHysteria2(p *model.Proxy) map[string]any {
	out := map[string]any{
		"type":   "hysteria2",
		"tag":    p.Name,
		"server": p.Server,
	}
	// server_ports 存在时不能同时输出 server_port；两者在 sing-box 中互斥。
	if ports := sbSplitPortRanges(p.Hysteria2Ports); len(ports) > 0 {
		out["server_ports"] = ports
	} else if mport := sbSplitPortRanges(p.Hysteria2Mport); len(mport) > 0 {
		out["server_ports"] = mport
	} else {
		out["server_port"] = p.Port
	}
	if p.Hysteria2UpMbps > 0 {
		out["up_mbps"] = p.Hysteria2UpMbps
	}
	if p.Hysteria2DownMbps > 0 {
		out["down_mbps"] = p.Hysteria2DownMbps
	}
	if p.Hysteria2Obfs != "" {
		obfs := map[string]any{"type": p.Hysteria2Obfs}
		if p.Hysteria2ObfsPassword != "" {
			obfs["password"] = p.Hysteria2ObfsPassword
		}
		out["obfs"] = obfs
	}
	if p.Password != "" {
		out["password"] = p.Password
	}
	if p.Hysteria2HopInterval > 0 {
		out["hop_interval"] = strconv.Itoa(p.Hysteria2HopInterval) + "s"
	}
	if p.Hysteria2CWND > 0 {
		out["cwnd"] = p.Hysteria2CWND
	}
	appendTLS(out, p, p.SkipCertVerify, nil)
	return out
}

// sbAppendTransport 按 Network 写入 transport 字段（ws/grpc/h2/http 四种）。
func sbAppendTransport(out map[string]any, p *model.Proxy) {
	switch p.Network {
	case "ws":
		tr := map[string]any{"type": "ws"}
		if p.WSPath != "" {
			tr["path"] = p.WSPath
		}
		if len(p.WSHeaders) > 0 {
			hdrs := map[string]any{}
			for k, v := range p.WSHeaders {
				hdrs[k] = v
			}
			tr["headers"] = hdrs
		}
		out["transport"] = tr
	case "grpc":
		tr := map[string]any{"type": "grpc"}
		if p.GRPCServiceName != "" {
			tr["service_name"] = p.GRPCServiceName
		}
		mode := p.GRPCMode
		if mode == "" {
			mode = "gun"
		}
		// sing-box grpc mode 只有 gun/multi，其它值忽略
		if mode == "gun" || mode == "multi" {
			tr["mode"] = mode
		}
		out["transport"] = tr
	case "h2":
		tr := map[string]any{"type": "http"}
		var host string
		if len(p.WSHeaders) > 0 {
			if h, ok := p.WSHeaders["Host"]; ok {
				host = h
			}
		}
		if host != "" {
			tr["host"] = []string{host}
		}
		if p.WSPath != "" {
			tr["path"] = p.WSPath
		}
		out["transport"] = tr
	case "http":
		tr := map[string]any{"type": "http"}
		var host string
		if len(p.WSHeaders) > 0 {
			if h, ok := p.WSHeaders["Host"]; ok {
				host = h
			}
		}
		if host != "" {
			tr["host"] = []string{host}
		}
		if p.WSPath != "" {
			tr["path"] = p.WSPath
		}
		out["transport"] = tr
	}
}

// firstNonEmptySB 返回第一个非空串，避免依赖 parser 包的同名工具。
func firstNonEmptySB(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------- 策略组：sing-box selector / urltest 出站 ----------

// sbGroupOutbound 由 ACL 单条组定义生成出站结构（map → JSON 序列化）。
// 生成失败返回 nil，跳过。
func sbGroupOutbound(g rule.GroupConfig, members []string) map[string]any {
	switch g.Type {
	case rule.GroupSelect:
		return map[string]any{
			"type":      "selector",
			"tag":       g.Name,
			"outbounds": members,
		}
	case rule.GroupURLTest, rule.GroupFallback, rule.GroupLoadBalance:
		out := map[string]any{
			"type":      "urltest",
			"tag":       g.Name,
			"outbounds": members,
		}
		if g.URL != "" {
			out["url"] = g.URL
		} else {
			out["url"] = "http://www.gstatic.com/generate_204"
		}
		interval := g.Interval
		if interval <= 0 {
			interval = 300 // 秒，对齐 C++ 默认 5min
		}
		out["interval"] = strconv.Itoa(interval) + "s"
		if g.Tolerance > 0 && g.Type == rule.GroupFallback {
			// sing-box urltest tolerance 单位毫秒：容忍窗口，兼容 fallback 语义
			out["tolerance"] = g.Tolerance
		}
		if (g.Type == rule.GroupURLTest || g.Type == rule.GroupLoadBalance) && g.Tolerance > 0 {
			out["tolerance"] = g.Tolerance
		}
		return out
	}
	return nil
}

// ---------- 规则：ACL4SSR 文本规则 → sing-box route.rules ----------

// sbBuildRule 将单条 Clash 规则文本（"DOMAIN,a.com,组名,no-resolve"）
// 转换为 singBoxRule。组名空/DIRECT/REJECT 分别映射 outbound 名字。
func sbBuildRule(line string) (singBoxRule, bool) {
	// 剥离末尾 ,no-resolve 附加片段（sing-box 不需要）
	raw := line
	for {
		trimmed := strings.TrimSuffix(raw, ",no-resolve")
		if trimmed == raw {
			break
		}
		raw = trimmed
	}
	parts := strings.Split(raw, ",")
	if len(parts) < 2 {
		return singBoxRule{}, false
	}
	rtype := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	outbound := "direct"
	if len(parts) >= 3 && parts[2] != "" {
		outbound = strings.TrimSpace(parts[2])
	}
	switch outbound {
	case "DIRECT":
		outbound = "direct"
	case "REJECT":
		outbound = "block"
	}
	r := singBoxRule{Outbound: outbound}
	switch rtype {
	case "DOMAIN":
		r.Domain = []string{value}
	case "DOMAIN-SUFFIX":
		r.DomainSuffix = []string{value}
	case "DOMAIN-KEYWORD":
		r.DomainKeyword = []string{value}
	case "IP-CIDR", "IP-CIDR6":
		r.IPCIDR = []string{value}
	case "SRC-IP-CIDR":
		r.SourceIPCIDR = []string{value}
	case "GEOIP":
		if strings.EqualFold(value, "cn") || value == "!cn" {
			// sing-box geoip 接受小写 code；!cn 反转在野外较少见，原样传入
			r.GeoIP = []string{strings.ToLower(value)}
		} else {
			r.GeoIP = []string{strings.ToLower(value)}
		}
	case "SRC-PORT":
		r.SourcePort = sbParsePortList(value)
	case "DST-PORT":
		r.DestPort = sbParsePortList(value)
	case "PROCESS-NAME":
		r.ProcessName = []string{value}
	default:
		// 不认识的规则类型，丢弃（保持克制：不扩展支持范围）
		return singBoxRule{}, false
	}
	return r, true
}

// sbParsePortList 解析 "22,53,8000-9000" 样式的端口列表为 uint16 切片；
// 范围写法展开成起、止两端（不展开连续区间内的所有端口，避免内存爆炸）。
func sbParsePortList(s string) []uint16 {
	var out []uint16
	for _, tok := range strings.Split(s, "/") {
		for _, part := range strings.Split(tok, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.Contains(part, "-") {
				ps := strings.SplitN(part, "-", 2)
				a, e1 := strconv.Atoi(strings.TrimSpace(ps[0]))
				b, e2 := strconv.Atoi(strings.TrimSpace(ps[1]))
				if e1 == nil && e2 == nil && a > 0 && a <= 65535 && b > 0 && b <= 65535 {
					out = append(out, uint16(a), uint16(b))
				}
				continue
			}
			n, err := strconv.Atoi(part)
			if err == nil && n > 0 && n <= 65535 {
				out = append(out, uint16(n))
			}
		}
	}
	return out
}

// ---------- 主入口 ----------

// RenderSingBox 渲染 sing-box JSON 配置：
//
//	NodeListMode 为 true：只输出 []outbounds（用户自行合并到基础配置）
//	否则：最小化基础 log/dns/mixed inbounds + outbounds + route.rules + final
func RenderSingBox(nodes []model.Proxy, cfg *Config) (string, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	sanitizeNodeNames(nodes)

	nodeOutbounds, err := sbRenderNodeOutbounds(nodes)
	if err != nil {
		return "", err
	}

	// nodelist：仅输出 outbounds JSON 数组
	if cfg.NodeList {
		blob, err := json.MarshalIndent(nodeOutbounds, "", "  ")
		if err != nil {
			return "", fmt.Errorf("singbox nodelist 序列化失败: %w", err)
		}
		return string(blob) + "\n", nil
	}

	// 完整配置：生成组出站、规则、final
	var groupOutbounds []json.RawMessage
	nodeTags := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		nodeTags[node.Name] = true
	}
	var groupNames map[string]bool
	groupMembers := make(map[string][]string)
	if cfg.ACL != nil && len(cfg.ACL.Groups) > 0 {
		groupNames = make(map[string]bool, len(cfg.ACL.Groups))
		for _, g := range cfg.ACL.Groups {
			groupNames[g.Name] = true
		}
		for _, g := range cfg.ACL.Groups {
			members, e := expandGroupItems(g, nodes, groupNames)
			if e != nil {
				return "", fmt.Errorf("策略组 %q 展开失败: %w", g.Name, e)
			}
			groupMembers[g.Name] = members
			out := sbGroupOutbound(g, members)
			if out == nil {
				continue
			}
			data, e := json.Marshal(out)
			if e != nil {
				return "", fmt.Errorf("策略组 %q 序列化失败: %w", g.Name, e)
			}
			groupOutbounds = append(groupOutbounds, data)
		}
	}

	// 默认 selector（引用第一个策略组作为首选项）：把它当 fallback proxy 用
	defaultPolicy := "direct"
	if cfg.ACL != nil {
		defaultPolicy = pickDefaultPolicy(cfg.ACL.Rulesets, cfg.ACL.Groups)
	}
	// 构造 proxy selector：若有自定义组，第一项是第一个组名；否则所有节点摊开
	var proxySelectorItems []string
	if cfg.ACL != nil && len(cfg.ACL.Groups) > 0 {
		proxySelectorItems = append(proxySelectorItems, cfg.ACL.Groups[0].Name)
		for i := 1; i < len(cfg.ACL.Groups); i++ {
			proxySelectorItems = append(proxySelectorItems, cfg.ACL.Groups[i].Name)
		}
	} else {
		for i := range nodes {
			proxySelectorItems = append(proxySelectorItems, nodes[i].Name)
		}
	}
	proxySelectorItems = append(proxySelectorItems, "direct")
	proxySelector := map[string]any{
		"type":      "selector",
		"tag":       "proxy",
		"outbounds": proxySelectorItems,
	}
	proxySelBytes, err := json.Marshal(proxySelector)
	if err != nil {
		return "", err
	}

	directOut, _ := json.Marshal(map[string]any{"type": "direct", "tag": "direct"})
	blockOut, _ := json.Marshal(map[string]any{"type": "block", "tag": "block"})
	dnsOut, _ := json.Marshal(map[string]any{"type": "dns", "tag": "dns-out"})

	// 组装 outbounds：节点 → 组 → proxy → direct → block → dns-out
	var allOut []json.RawMessage
	allOut = append(allOut, nodeOutbounds...)
	allOut = append(allOut, groupOutbounds...)
	allOut = append(allOut, proxySelBytes, directOut, blockOut, dnsOut)

	// route.rules：展开规则集（与 Clash 相同的文本规则，再转 sing-box 结构）
	var sbRules []singBoxRule
	ruleLines, err := renderRules(cfg.ACL)
	if err != nil {
		return "", err
	}
	for _, line := range ruleLines {
		if r, ok := sbBuildRule(line); ok {
			// 修正 outbound：如果命中的组名存在于自定义组，直接使用；否则映射到 proxy/direct/block
			switch r.Outbound {
			case "direct", "block":
				// keep as is
			default:
				if (groupNames != nil && groupNames[r.Outbound]) || nodeTags[r.Outbound] {
					// 保持原样
				} else {
					// ACL 可引用不存在的策略组或手写节点；只能指向已生成的 outbound。
					r.Outbound = "proxy"
				}
			}
			sbRules = append(sbRules, r)
		}
	}

	// final：与 defaultPolicy 对应
	final := defaultPolicy
	switch final {
	case "DIRECT":
		final = "direct"
	case "REJECT":
		final = "block"
	default:
		// 自定义组名：sing-box final 必须是一个已存在 outbound tag，优先组名
		if (groupNames == nil || !groupNames[final]) && !nodeTags[final] {
			final = "proxy"
		}
	}

	root := singBoxConfig{
		Log:       singBoxLog{Level: "info"},
		DNS:       singBoxDNS{Servers: []singBoxDNSServer{{Tag: "local", Address: "223.5.5.5", Detour: "direct"}}},
		Inbounds:  []any{singBoxMixedInbound{Type: "mixed", Tag: "mixed-in", Listen: "127.0.0.1", ListenP: 7890}},
		Outbounds: allOut,
		Route: singBoxRoute{
			Rules: sbRules,
			Final: final,
		},
	}
	blob, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", fmt.Errorf("singbox 序列化失败: %w", err)
	}
	return string(blob) + "\n", nil
}

// sbRenderNodeOutbounds 把所有节点渲染为出站消息数组。
func sbRenderNodeOutbounds(nodes []model.Proxy) ([]json.RawMessage, error) {
	var out []json.RawMessage
	for i := range nodes {
		p := &nodes[i]
		var m map[string]any
		switch p.Type {
		case model.TypeSS:
			m = sbOutboundSS(p)
		case model.TypeVMess:
			m = sbOutboundVMess(p)
		case model.TypeTrojan:
			m = sbOutboundTrojan(p)
		case model.TypeVLESS:
			m = sbOutboundVLESS(p)
		case model.TypeAnyTLS:
			m = sbOutboundAnyTLS(p)
		case model.TypeHysteria2:
			m = sbOutboundHysteria2(p)
		default:
			return nil, fmt.Errorf("singbox 暂不支持协议 %q（节点 %q）", p.Type, p.Name)
		}
		data, err := json.Marshal(m)
		if err != nil {
			return nil, fmt.Errorf("节点 %q 序列化失败: %w", p.Name, err)
		}
		out = append(out, data)
	}
	return out, nil
}
