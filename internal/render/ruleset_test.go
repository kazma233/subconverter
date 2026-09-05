package render

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"subconv/internal/rule"
)

// startListServer httptest serve 一份本地 .list 样本（模拟远程规则集仓库）。
func startListServer(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../testdata/lan.list")
	if err != nil {
		t.Fatalf("读取测试规则集失败: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// renderRuleList 渲染规则列表（供本包测试复用）。
func renderRuleList(t *testing.T, rulesets []rule.RulesetConfig, groups []rule.GroupConfig) []string {
	t.Helper()
	rules, err := renderRules(&rule.ACLConfig{Rulesets: rulesets, Groups: groups})
	if err != nil {
		t.Fatalf("渲染规则失败: %v", err)
	}
	return rules
}

// TestRulesRemoteList 远程 .list 装载：注释跳过、no-resolve 附加参数保留、策略组兜底。
func TestRulesRemoteList(t *testing.T) {
	listURL := startListServer(t)
	rules := renderRuleList(t,
		[]rule.RulesetConfig{{Group: "🎯 全球直连", Path: listURL}},
		nil,
	)
	if len(rules) == 0 {
		t.Fatal("远程规则集渲染结果为空")
	}
	// 抽查典型规则
	joined := "\n" + strings.Join(rules, "\n") + "\n"
	if !strings.Contains(joined, "\nDOMAIN,router.asus.com,🎯 全球直连\n") {
		t.Errorf("DOMAIN 规则展开错误:\n%s", joined)
	}
	if !strings.Contains(joined, "\nIP-CIDR,10.0.0.0/8,🎯 全球直连,no-resolve\n") {
		t.Errorf("IP-CIDR no-resolve 应作为第 4 段保留:\n%s", joined)
	}
	if !strings.Contains(joined, "\nIP-CIDR6,::1/128,🎯 全球直连,no-resolve\n") {
		t.Errorf("IP-CIDR6 规则展开错误:\n%s", joined)
	}
	// 尾部 MATCH 兜底
	if !strings.HasPrefix(rules[len(rules)-1], "MATCH,") {
		t.Errorf("尾部应补 MATCH 兜底, got %q", rules[len(rules)-1])
	}
	// 注释行不应出现
	for _, r := range rules {
		if strings.HasPrefix(r, "#") || strings.HasPrefix(r, ";") {
			t.Errorf("注释行泄漏进规则: %q", r)
		}
	}
}

// TestRulesInlineRules 内联规则：GEOIP,CN 与 FINAL→MATCH。
func TestRulesInlineRules(t *testing.T) {
	rules := renderRuleList(t, []rule.RulesetConfig{
		{Group: "🎯 全球直连", Inline: "GEOIP,CN"},
		{Group: "🐟 漏网之鱼", Inline: "FINAL"},
	}, nil)
	if len(rules) != 2 {
		t.Fatalf("规则数 = %d, want 2", len(rules))
	}
	if rules[0] != "GEOIP,CN,🎯 全球直连" {
		t.Errorf("GEOIP 内联规则 = %q", rules[0])
	}
	if rules[1] != "MATCH,🐟 漏网之鱼" {
		t.Errorf("FINAL 应改写为 MATCH: %q", rules[1])
	}
}

// TestRulesMissingFileFails 文件不存在：规则缺失必须让渲染失败。
func TestRulesMissingFileFails(t *testing.T) {
	_, err := renderRules(&rule.ACLConfig{Rulesets: []rule.RulesetConfig{
		{Group: "组", Path: "http://127.0.0.1:1/rules/不存在/NoSuchFile.list"},
		{Group: "兜底", Inline: "FINAL"},
	}})
	if err == nil || !strings.Contains(err.Error(), "规则集") {
		t.Fatalf("缺失规则集应返回错误, got %v", err)
	}
}

// TestRulesMATCHFallback 无 FINAL 时以首个策略组为默认策略并追加 MATCH。
func TestRulesMATCHFallback(t *testing.T) {
	rules := renderRuleList(t,
		[]rule.RulesetConfig{{Group: "组", Inline: "GEOIP,CN"}},
		[]rule.GroupConfig{{Name: "首选组", Type: rule.GroupSelect, Items: []string{".*"}}},
	)
	if len(rules) != 2 {
		t.Fatalf("规则数 = %d, want 2", len(rules))
	}
	if rules[0] != "GEOIP,CN,组" {
		t.Errorf("首条规则 = %q", rules[0])
	}
	if rules[1] != "MATCH,首选组" {
		t.Errorf("MATCH 兜底策略应为首个策略组, got %q", rules[1])
	}
}

// TestRulesUnknownTypeSkipped 未知规则类型的行跳过（对齐 C++ ClashRuleTypes 过滤）。
func TestRulesUnknownTypeSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("DOMAIN-SUFFIX,ok.com\nNOT-A-TYPE,bad.com\nUSER-AGENT,also-bad\n"))
	}))
	t.Cleanup(srv.Close)
	rules, err := renderRules(&rule.ACLConfig{Rulesets: []rule.RulesetConfig{
		{Group: "组", Path: srv.URL},
		{Group: "兜底", Inline: "FINAL"},
	}})
	if err != nil {
		t.Fatalf("渲染规则失败: %v", err)
	}
	if len(rules) != 2 { // DOMAIN-SUFFIX + MATCH
		t.Fatalf("规则数 = %d, want 2（未知类型行应跳过）: %v", len(rules), rules)
	}
	if rules[0] != "DOMAIN-SUFFIX,ok.com,组" {
		t.Errorf("首条规则 = %q", rules[0])
	}
}

// TestFetchRemoteAndCache httptest 服务端验证远程规则集下载与内存缓存（同 URL 只拉一次）。
func TestFetchRemoteAndCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("DOMAIN-SUFFIX,remote.com\n"))
	}))
	defer srv.Close()

	rules, err := renderRules(&rule.ACLConfig{Rulesets: []rule.RulesetConfig{
		{Group: "远程组", Path: srv.URL},
		{Group: "远程组", Path: srv.URL}, // 同 URL 第二次引用应命中缓存
		{Group: "兜底", Inline: "FINAL"},
	}})
	if err != nil {
		t.Fatalf("渲染规则失败: %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("同一 URL 应只请求一次（缓存）, 实际 %d 次", hits.Load())
	}
	count := 0
	for _, r := range rules {
		if r == "DOMAIN-SUFFIX,remote.com,远程组" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("两个引用同一远程规则集的条目应各展开一次, got %d: %v", count, rules)
	}
}

// TestFetchRemoteError 远程规则集返回 404 时必须报错。
func TestFetchRemoteError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	_, err := renderRules(&rule.ACLConfig{Rulesets: []rule.RulesetConfig{
		{Group: "组", Path: srv.URL + "/missing.list"},
		{Group: "兜底", Inline: "FINAL"},
	}})
	if err == nil || !strings.Contains(err.Error(), "状态码 404") {
		t.Errorf("远程规则集失败应返回包含状态码的错误, got %v", err)
	}
}
