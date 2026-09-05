package render

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"subconv/internal/fetch"
	"subconv/internal/rule"
)

func renderTestClient() *fetch.Client {
	dialer := &net.Dialer{}
	return fetch.NewClient(fetch.ClientOptions{
		LookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
	})
}

func renderRulesForTest(acl *rule.ACLConfig) ([]string, error) {
	return renderRulesWithFetcher(context.Background(), acl, renderTestClient().FetchText)
}

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
	rules, err := renderRulesForTest(&rule.ACLConfig{Rulesets: rulesets, Groups: groups})
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
	rules, err := renderRulesForTest(&rule.ACLConfig{Rulesets: []rule.RulesetConfig{
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

	rules, err := renderRulesForTest(&rule.ACLConfig{Rulesets: []rule.RulesetConfig{
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

	_, err := renderRulesForTest(&rule.ACLConfig{Rulesets: []rule.RulesetConfig{
		{Group: "组", Path: srv.URL + "/missing.list"},
		{Group: "兜底", Inline: "FINAL"},
	}})
	if err == nil || !strings.Contains(err.Error(), "状态码 404") {
		t.Errorf("远程规则集失败应返回包含状态码的错误, got %v", err)
	}
}

func TestRemoteCacheEvictsLeastRecentlyUsedEntry(t *testing.T) {
	resetRemoteCache(t)

	now := time.Now()
	for i := 0; i < maxRemoteCacheEntries; i++ {
		putCachedRemote(fmt.Sprintf("https://cache.example/%d", i), "x", now.Add(time.Duration(i)*time.Second))
	}
	putCachedRemote("https://cache.example/new", "x", now.Add(time.Hour))

	if len(remoteCache) != maxRemoteCacheEntries {
		t.Fatalf("缓存条目数 = %d, want %d", len(remoteCache), maxRemoteCacheEntries)
	}
	if _, ok := getCachedRemote("https://cache.example/0", now.Add(time.Hour)); ok {
		t.Error("最久未使用的缓存条目应被淘汰")
	}
	if content, ok := getCachedRemote("https://cache.example/new", now.Add(time.Hour)); !ok || content != "x" {
		t.Errorf("新缓存条目应保留, content=%q ok=%t", content, ok)
	}
}

func TestRemoteCacheRemovesExpiredEntriesBeforeInsert(t *testing.T) {
	resetRemoteCache(t)
	now := time.Now()
	expiredURL := "https://cache.example/expired"
	remoteCacheMu.Lock()
	remoteCache[expiredURL] = remoteCacheEntry{content: "old", cachedAt: now.Add(-remoteCacheTTL), lastUsed: now}
	remoteCacheBytes = remoteCacheSize(expiredURL, "old")
	remoteCacheMu.Unlock()

	putCachedRemote("https://cache.example/fresh", "new", now)
	if _, ok := getCachedRemote(expiredURL, now); ok {
		t.Error("过期条目不应在新写入后继续占用缓存")
	}
	if got, want := remoteCacheBytes, remoteCacheSize("https://cache.example/fresh", "new"); got != want {
		t.Errorf("缓存字节数 = %d, want %d", got, want)
	}
}

func TestFetchRemoteCoalescesConcurrentRequests(t *testing.T) {
	resetRemoteCache(t)
	const url = "https://cache.example/shared"
	started := make(chan struct{})
	release := make(chan struct{})
	ready := make(chan struct{}, 2)
	goFetch := make(chan struct{})
	var calls atomic.Int32
	fetchText := func(context.Context, string) (string, error) {
		calls.Add(1)
		close(started)
		<-release
		return "DOMAIN-SUFFIX,shared.example\n", nil
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-goFetch
			_, err := fetchRemote(context.Background(), url, fetchText)
			errs <- err
		}()
	}
	<-ready
	<-ready
	close(goFetch)
	<-started
	time.Sleep(20 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("同 URL 并发请求数 = %d, want 1", got)
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("并发下载失败: %v", err)
		}
	}
}

func TestPrefetchRemoteRulesetsLimitsWorkers(t *testing.T) {
	resetRemoteCache(t)
	rulesets := make([]rule.RulesetConfig, fetch.MaxConcurrentDownloads+1)
	for i := range rulesets {
		rulesets[i] = rule.RulesetConfig{Path: fmt.Sprintf("https://cache.example/%d", i)}
	}
	started := make(chan struct{}, fetch.MaxConcurrentDownloads+1)
	release := make(chan struct{})
	fetchText := func(context.Context, string) (string, error) {
		started <- struct{}{}
		<-release
		return "DOMAIN-SUFFIX,example.com\n", nil
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- prefetchRemoteRulesets(context.Background(), rulesets, fetchText)
	}()
	for range fetch.MaxConcurrentDownloads {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("预取任务未在预期时间内启动")
		}
	}
	select {
	case <-started:
		t.Fatal("预取任务超过并发上限")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("预取失败: %v", err)
	}
}

func resetRemoteCache(t *testing.T) {
	t.Helper()
	remoteCacheMu.Lock()
	previousCache, previousBytes := remoteCache, remoteCacheBytes
	remoteCache = make(map[string]remoteCacheEntry)
	remoteCacheBytes = 0
	remoteCacheMu.Unlock()
	t.Cleanup(func() {
		remoteCacheMu.Lock()
		remoteCache, remoteCacheBytes = previousCache, previousBytes
		remoteCacheMu.Unlock()
	})
}
