package render

import (
	"encoding/json"
	"strings"
	"testing"

	"subconv/internal/model"
)

// 辅助：构建最简单的节点切片
func buildSingTestNodes() []model.Proxy {
	scv := true
	tfo := true
	udp := true
	return []model.Proxy{
		{
			Type:                  model.TypeHysteria2,
			Name:                  "hy2-01 香港",
			Server:                "hk.example.com",
			Port:                  443,
			Password:              "hy-pass",
			SNI:                   "hk.example.com",
			Hysteria2Ports:        "20000-40000",
			Hysteria2Obfs:         "salamander",
			Hysteria2ObfsPassword: "obfs123",
			Hysteria2UpMbps:       100,
			Hysteria2DownMbps:     500,
			Hysteria2HopInterval:  60,
			CACertPath:            "/etc/ca.pem",
			ALPN:                  []string{"h3"},
			SkipCertVerify:        &scv,
			TCPFastOpen:           &tfo,
			UDP:                   &udp,
		},
		{
			Type:      model.TypeVLESS,
			Name:      "vless-01 日本 Tokyo",
			Server:    "jp.example.com",
			Port:      443,
			UUID:      "vless-uuid",
			Flow:      "xtls-rprx-vision",
			SNI:       "jp.example.com",
			PublicKey: "reality-pbk",
			ShortID:   "abcd1234",
			TLSSecure: true,
		},
		{
			Type:       model.TypeSS,
			Name:       "ss-01 美西",
			Server:     "us.example.com",
			Port:       8388,
			Cipher:     "aes-128-gcm",
			Password:   "ss-pass",
			SkipCertVerify: nil,
		},
	}
}

// TestRenderSingBox_Basic 检查 sing-box 顶层结构 & Hysteria2 完整字段输出
func TestRenderSingBox_Basic(t *testing.T) {
	nodes := buildSingTestNodes()
	cfg := &Config{NodeList: false} // 空 ACL → 最小顶层
	out, err := RenderSingBox(nodes, cfg)
	if err != nil {
		t.Fatalf("RenderSingBox 失败: %v", err)
	}
	if !strings.Contains(out, `"type": "hysteria2"`) {
		t.Fatal("sing-box 缺少 hysteria2 出站")
	}
	var root singBoxConfig
	if err := json.Unmarshal([]byte(out), &root); err != nil {
		t.Fatalf("sing-box JSON 反序列化失败: %v", err)
	}
	if len(root.Outbounds) == 0 {
		t.Fatal("sing-box outbounds 为空")
	}
	// 检查 dns/log/inbounds 是否存在
	if len(root.DNS.Servers) == 0 {
		t.Error("sing-box dns.servers 为空")
	}
	if root.Log.Level != "info" {
		t.Errorf("log.level = %q, want info", root.Log.Level)
	}
	if len(root.Inbounds) != 1 {
		t.Errorf("inbounds 数 = %d, want 1", len(root.Inbounds))
	}
	// 找出 hysteria2 outbound
	var hy2 map[string]any
	for _, raw := range root.Outbounds {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err == nil && m["type"] == "hysteria2" {
			hy2 = m
			break
		}
	}
	if hy2 == nil {
		t.Fatal("未找到 hysteria2 outbound")
	}
	if hy2["password"] != "hy-pass" {
		t.Errorf("hysteria2 password = %v", hy2["password"])
	}
	if v := hy2["up_mbps"]; v.(float64) != 100 {
		t.Errorf("hysteria2 up_mbps = %v", v)
	}
	if v := hy2["down_mbps"]; v.(float64) != 500 {
		t.Errorf("hysteria2 down_mbps = %v", v)
	}
	// server_ports 范围写法 → 解析为两端
	ports, ok := hy2["server_ports"].([]any)
	if !ok || len(ports) < 2 {
		t.Errorf("hysteria2 server_ports = %v", hy2["server_ports"])
	}
	// obfs salamander + password
	obfs, ok := hy2["obfs"].(map[string]any)
	if !ok || obfs["type"] != "salamander" || obfs["password"] != "obfs123" {
		t.Errorf("hysteria2 obfs 字段非法: %+v", obfs)
	}
	// hop_interval 带 s 后缀
	if hy2["hop_interval"] != "60s" {
		t.Errorf("hysteria2 hop_interval = %v, want 60s", hy2["hop_interval"])
	}
	tls, ok := hy2["tls"].(map[string]any)
	if !ok {
		t.Fatal("hysteria2 缺少 tls 字段")
	}
	if tls["insecure"] != true {
		t.Errorf("hysteria2 tls.insecure = %v, want true", tls["insecure"])
	}
	if tls["server_name"] != "hk.example.com" {
		t.Errorf("hysteria2 tls.server_name = %v", tls["server_name"])
	}
	if tls["certificate_path"] != "/etc/ca.pem" {
		t.Errorf("hysteria2 tls.certificate_path = %v, want /etc/ca.pem", tls["certificate_path"])
	}
	alpn, ok := tls["alpn"].([]any)
	if !ok || len(alpn) == 0 || alpn[0].(string) != "h3" {
		t.Errorf("hysteria2 tls.alpn = %+v", tls["alpn"])
	}
	// REALITY 结构：vless tag=proxy outbound 里有 reality + utls
	var vless map[string]any
	for _, raw := range root.Outbounds {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err == nil && m["type"] == "vless" {
			vless = m
			break
		}
	}
	if vless == nil {
		t.Fatal("未找到 vless outbound")
	}
	if vless["flow"] != "xtls-rprx-vision" {
		t.Errorf("vless flow = %v", vless["flow"])
	}
	vtls, ok := vless["tls"].(map[string]any)
	if !ok {
		t.Fatal("vless 缺少 tls")
	}
	re, ok := vtls["reality"].(map[string]any)
	if !ok || re["public_key"] != "reality-pbk" || re["short_id"] != "abcd1234" {
		t.Errorf("vless tls.reality = %+v", re)
	}
	utls, ok := vtls["utls"].(map[string]any)
	if !ok || utls["enabled"] != true {
		t.Errorf("vless tls.utls = %+v", utls)
	}
	// final 路由
	if root.Route.Final != "proxy" {
		t.Errorf("route.final = %q, want proxy", root.Route.Final)
	}
}

// TestRenderSingBox_NodeList 仅输出 outbounds 数组，无顶层包裹
func TestRenderSingBox_NodeList(t *testing.T) {
	nodes := buildSingTestNodes()
	out, err := RenderSingBox(nodes, &Config{NodeList: true})
	if err != nil {
		t.Fatalf("nodelist 模式失败: %v", err)
	}
	out = strings.TrimSpace(out)
	if !(strings.HasPrefix(out, "[") && strings.HasSuffix(out, "]")) {
		t.Fatalf("nodelist 模式应返回纯数组，实际: %s", out[:60])
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		t.Fatalf("nodelist JSON 解析失败: %v", err)
	}
	if len(arr) != 3 {
		t.Errorf("nodelist 节点数 = %d, want 3", len(arr))
	}
	// outbounds 数组不应包含 proxy selector / direct 等
	for _, m := range arr {
		if m["tag"] == "direct" || m["tag"] == "proxy" {
			t.Errorf("nodelist 不应带 %s 出站", m["tag"])
		}
	}
}

// TestApplySubOverrides_All 端到端检查 10 参数对节点处理链的影响
func TestApplySubOverrides_All(t *testing.T) {
	nodes := []model.Proxy{
		{Type: model.TypeSS, Name: "🇺🇸 US-01 美西GIA", Server: "a", Port: 1, Cipher: "aes-128-gcm"},
		{Type: model.TypeSS, Name: "HK-01", Server: "b", Port: 2, Cipher: "chacha20"}, // 会被 depr 过滤
		{Type: model.TypeTrojan, Name: "B-Japan", Server: "c", Port: 443, Password: "x"}, // sort 后应为 "日本"标签
	}
	scv := true
	udp := true
	tfo := true
	cfg := &Config{
		FolderPrefix:     "机场A",
		RenameRule:       []RenameRule{{Pattern: "US-01", Replacement: "US01"}},
		AddEmoji:         model.BoolPtr(true),
		RemoveEmoji:      model.BoolPtr(true),
		Sort:             true,
		FilterDeprecated: true,
		UDP:              &udp,
		TCPFastOpen:      &tfo,
		SkipCertVerify:   &scv,
	}
	out := ApplySubOverrides(nodes, cfg)
	// depr 过滤掉 chacha20 的 SS
	if len(out) != 2 {
		t.Fatalf("过滤后节点数 = %d, want 2", len(out))
	}
	// 字典序升序：B-Japan → "日本" → "🇯🇵 B-Japan" 前缀应在前面？先加 folder 再排序，顺序需对
	// folder: "机场A - xxx"；sort 按名字典序
	names := []string{out[0].Name, out[1].Name}
	// names[0] 应该 "机场A - 🇯🇵 B-Japan" 开头；names[1] "机场A - 🇺🇸 US01 美西GIA"
	if !strings.Contains(names[0], "机场A - ") || !strings.Contains(names[1], "机场A - ") {
		t.Errorf("folder 前缀缺失: %+v", names)
	}
	// rename: "US-01" 应该被替换为 "US01"
	if !strings.Contains(names[1], "US01") {
		t.Errorf("rename 未生效: %s", names[1])
	}
	// remove emoji + add emoji：原来 "🇺🇸" 被剥掉后，"美西" 仍会命中 🇺🇸 规则 → 仍会出现国旗 emoji（因为关键词在原名字里）
	if !strings.Contains(names[1], "🇺🇸") {
		t.Errorf("emoji 未生效(应含美西): %s", names[1])
	}
	// 三态覆盖：UDP/TFO/SCV 三个都应为 true
	for i := range out {
		if out[i].UDP == nil || !*out[i].UDP {
			t.Errorf("node[%d] UDP 覆盖失败", i)
		}
		if out[i].TCPFastOpen == nil || !*out[i].TCPFastOpen {
			t.Errorf("node[%d] TFO 覆盖失败", i)
		}
		if out[i].SkipCertVerify == nil || !*out[i].SkipCertVerify {
			t.Errorf("node[%d] SCV 覆盖失败", i)
		}
	}
}

// TestConvert_Targets 确认 Convert 分发 singbox/clash/loon 三种目标均不报错
func TestConvert_Targets(t *testing.T) {
	nodes := buildSingTestNodes()
	for _, tgt := range []string{"clash", "loon", "singbox", "sing-box", "sb"} {
		cfg := &Config{NodeList: true}
		out, err := Convert(tgt, nodes, cfg)
		if err != nil {
			t.Errorf("target=%s Convert 错误: %v", tgt, err)
			continue
		}
		if out == "" {
			t.Errorf("target=%s 输出为空", tgt)
		}
	}
	if _, err := Convert("nosuch", nodes, nil); err == nil {
		t.Error("未知 target 应报错")
	}
}

// TestNodeListMode clash/loon/singbox 三种目标在 list=true 时只输出节点段
func TestNodeListMode(t *testing.T) {
	nodes := []model.Proxy{
		{Type: model.TypeSS, Name: "test-ss", Server: "a.example.com", Port: 8388, Cipher: "aes-128-gcm", Password: "p"},
	}
	cfg := &Config{NodeList: true}

	// clash: 只应有 proxies 段，不含 proxy-groups / rules
	clashOut, err := Convert("clash", nodes, cfg)
	if err != nil {
		t.Fatalf("clash nodelist 失败: %v", err)
	}
	if !strings.Contains(clashOut, "proxies:") {
		t.Error("clash nodelist 缺少 proxies:")
	}
	if strings.Contains(clashOut, "proxy-groups:") {
		t.Error("clash nodelist 不应含 proxy-groups")
	}
	if strings.Contains(clashOut, "rules:") {
		t.Error("clash nodelist 不应含 rules")
	}

	// loon: 只应有 [Proxy] 段，不含 [Proxy Group] / [Rule]
	loonOut, err := Convert("loon", nodes, cfg)
	if err != nil {
		t.Fatalf("loon nodelist 失败: %v", err)
	}
	if !strings.Contains(loonOut, "[Proxy]") {
		t.Error("loon nodelist 缺少 [Proxy]")
	}
	if strings.Contains(loonOut, "[Proxy Group]") {
		t.Error("loon nodelist 不应含 [Proxy Group]")
	}
	if strings.Contains(loonOut, "[Rule]") {
		t.Error("loon nodelist 不应含 [Rule]")
	}

	// singbox: 只输出 outbounds 数组
	sbOut, err := Convert("singbox", nodes, cfg)
	if err != nil {
		t.Fatalf("singbox nodelist 失败: %v", err)
	}
	sbOut = strings.TrimSpace(sbOut)
	if !strings.HasPrefix(sbOut, "[") {
		t.Error("singbox nodelist 应以 [ 开头")
	}
	if strings.Contains(sbOut, "\"route\"") {
		t.Error("singbox nodelist 不应含 route")
	}
}
