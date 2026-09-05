package server

import (
	"bytes"
	"context"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"subconv/internal/fetch"
	"subconv/internal/parser"
)

func newTestHandler() http.Handler {
	dialer := &net.Dialer{}
	client := fetch.NewClient(fetch.ClientOptions{
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
	return newHandler(client.FetchSubscription, client.FetchText)
}

// setupACL 注入外配置与规则集动态拉取环境，避免成功链路依赖公网。
func setupACL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/acl_mini.ini":
			data, err := os.ReadFile("../../testdata/acl_mini.ini")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			content := strings.ReplaceAll(string(data), "https://example.com/rules/", "http://"+r.Host+"/rules/")
			_, _ = w.Write([]byte(content))
		case strings.HasPrefix(r.URL.Path, "/rules/"):
			data, err := os.ReadFile("../../testdata/lan.list")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(data)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/acl_mini.ini"
}

// nodeLink1/2 测试用节点链接（vless REALITY + trojan）。
const (
	nodeLink1 = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=PbKey123&sid=29845e28&type=tcp&flow=xtls-rprx-vision#%E9%A6%99%E6%B8%AF01"
	nodeLink2 = "trojan://pw123@5.6.7.8:443?sni=a.example.com#%E6%97%A5%E6%9C%AC01"
)

// TestVersionEndpoint /version 返回版本行。
func TestVersionEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	want := "subconv " + Version + " backend\n"
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestSubClashFullChain /sub clash 全链路：
// 节点链接解析 → 离线 ACL 配置（避免测试依赖网络）→ 策略组/规则渲染。
func TestSubClashFullChain(t *testing.T) {
	acl := setupACL(t)
	q := "target=clash&url=" + url.QueryEscape(nodeLink1+"|"+nodeLink2) +
		"&config=" + url.QueryEscape(acl)
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/yaml; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}

	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
		Groups  []map[string]any `yaml:"proxy-groups"`
		Rules   []string         `yaml:"rules"`
	}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("响应不是合法 YAML: %v\n%s", err, rec.Body.String())
	}
	if len(doc.Proxies) != 2 {
		t.Fatalf("proxies 数 = %d, want 2", len(doc.Proxies))
	}
	if len(doc.Groups) != 5 {
		t.Fatalf("proxy-groups 数 = %d, want 5（acl_mini.ini）", len(doc.Groups))
	}
	if len(doc.Rules) < 47 {
		t.Fatalf("rules 数 = %d, want ≥ 47（9 份规则集 + GEOIP + MATCH）", len(doc.Rules))
	}
	if last := doc.Rules[len(doc.Rules)-1]; last != "MATCH,🐟 漏网之鱼" {
		t.Errorf("MATCH 兜底 = %q", last)
	}
	// short-id 双引号强制字符串（29845e28 不被解析为浮点数）
	ro := doc.Proxies[0]["reality-opts"].(map[string]any)
	if ro["short-id"] != "29845e28" {
		t.Errorf("short-id = %v (%T), want string 29845e28", ro["short-id"], ro["short-id"])
	}
}

// TestSubFilename filename 参数 → Content-Disposition 附件头。
func TestSubFilename(t *testing.T) {
	acl := setupACL(t)
	q := "target=clash&url=" + url.QueryEscape(nodeLink1) +
		"&config=" + url.QueryEscape(acl) + "&filename=my-config.yaml"
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != "attachment; filename=my-config.yaml" {
		t.Errorf("Content-Disposition = %q", cd)
	}
}

// TestSubIncludeExclude include/exclude 过滤。
func TestSubIncludeExclude(t *testing.T) {
	acl := setupACL(t)
	q := "target=clash&url=" + url.QueryEscape(nodeLink1+"|"+nodeLink2) +
		"&config=" + url.QueryEscape(acl) + "&include=" + url.QueryEscape("香港")
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	nodes, err := parser.ParseSubscription(nodeLink1 + "\n" + nodeLink2)
	if err != nil {
		t.Fatal(err)
	}
	// include=香港 应只保留 香港01（排除 日本01）
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("响应不是合法 YAML: %v", err)
	}
	if len(doc.Proxies) != 1 || doc.Proxies[0]["name"] != nodes[0].Name {
		t.Errorf("include 过滤结果错误: %+v", doc.Proxies)
	}

	// exclude 全部过滤后 → 400
	q = "target=clash&url=" + url.QueryEscape(nodeLink1) +
		"&config=" + url.QueryEscape(acl) + "&exclude=" + url.QueryEscape("香港|日本")
	req = httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec = httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("全部节点被过滤应 400, got %d", rec.Code)
	}
}

// TestSubHTTPSubscriptionUnavailable http(s) 订阅地址拉取失败（500）→ 400，
// 对齐 C++ 严格行为：任一订阅段失败即整体报错。
func TestSubHTTPSubscriptionUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/sub?target=clash&url="+url.QueryEscape(srv.URL), nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "500") {
		t.Errorf("错误信息应包含状态码 500, got %q", body)
	}
}

// TestSubRulesetUnavailable 三种输出共用规则集渲染链路；任一规则集失败必须返回错误，
// 不能生成少规则的配置后继续返回 200。
func TestSubRulesetUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/acl.ini":
			_, _ = w.Write([]byte("[custom]\n" +
				"custom_proxy_group=代理`select`.*\n" +
				"ruleset=代理,http://" + r.Host + "/missing.list\n" +
				"ruleset=代理,[]FINAL\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	for _, target := range []string{"clash", "loon", "singbox"} {
		q := "target=" + target + "&url=" + url.QueryEscape(nodeLink1) +
			"&config=" + url.QueryEscape(srv.URL+"/acl.ini")
		req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
		rec := httptest.NewRecorder()
		newTestHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("target=%s: status = %d, want 500, body: %s", target, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "规则集预取失败") {
			t.Errorf("target=%s: 错误应说明规则集预取失败，body: %s", target, rec.Body.String())
		}
	}
}

// TestSubLoonTarget target=loon 全链路：输出 Loon conf 结构与节点行。
func TestSubLoonTarget(t *testing.T) {
	acl := setupACL(t)
	q := "target=loon&url=" + url.QueryEscape(nodeLink1+"|"+nodeLink2) +
		"&config=" + url.QueryEscape(acl)
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	body := rec.Body.String()
	for _, section := range []string{"[General]", "[Proxy]", "[Proxy Group]", "[Rule]", "[Remote Rule]"} {
		if !strings.Contains(body, section) {
			t.Errorf("Loon 输出缺少段头 %s:\n%s", section, body)
		}
	}
	// vless REALITY 节点行（short-id 原值）与 trojan 节点行（Loon 3.x 键名）
	if !strings.Contains(body, `香港01 = vless,1.2.3.4,443,"11111111-2222-3333-4444-555555555555",over-tls=true,sni=www.microsoft.com,flow=xtls-rprx-vision,transport=tcp,public-key=PbKey123,short-id=29845e28`) {
		t.Errorf("vless REALITY 节点行错误:\n%s", body)
	}
	if !strings.Contains(body, `日本01 = trojan,5.6.7.8,443,"pw123",sni=a.example.com`) {
		t.Errorf("trojan 节点行错误:\n%s", body)
	}
	// Loon 规则用 FINAL 而非 MATCH
	if !strings.Contains(body, "\nFINAL,🐟 漏网之鱼\n") {
		t.Errorf("应包含 FINAL 兜底规则:\n%s", body)
	}
	if strings.Contains(body, "MATCH,") {
		t.Errorf("Loon 规则不应出现 MATCH:\n%s", body)
	}
}

// TestSubMultiURLMerge 多个订阅 URL 合并：两个 httptest 订阅各返回一个节点，
// 合并后 2 个节点；subscription-userinfo 以响应头回传。
func TestSubMultiURLMerge(t *testing.T) {
	acl := setupACL(t)
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=123; download=456; total=789")
		_, _ = w.Write([]byte(nodeLink1 + "\n"))
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nodeLink2 + "\n"))
	}))
	defer srv2.Close()

	q := "target=clash&url=" + url.QueryEscape(srv1.URL+"|"+srv2.URL) + "&config=" + url.QueryEscape(acl)
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if su := rec.Header().Get("Subscription-UserInfo"); su != "upload=123; download=456; total=789" {
		t.Errorf("Subscription-UserInfo = %q", su)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("响应不是合法 YAML: %v", err)
	}
	if len(doc.Proxies) != 2 {
		t.Fatalf("合并后节点数 = %d, want 2", len(doc.Proxies))
	}
}

// TestSubMultiURLFailure 多 URL 任一失败 → 400。
func TestSubMultiURLFailure(t *testing.T) {
	acl := setupACL(t)
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nodeLink1 + "\n"))
	}))
	defer srvOK.Close()
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srvBad.Close()

	q := "target=clash&url=" + url.QueryEscape(srvOK.URL+"|"+srvBad.URL) + "&config=" + url.QueryEscape(acl)
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("任一订阅失败应 400, got %d, body: %s", rec.Code, rec.Body.String())
	}
}

// TestSubURLMixed 节点链接 + 订阅 URL 混合（| 分隔）。
func TestSubURLMixed(t *testing.T) {
	acl := setupACL(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nodeLink2 + "\n"))
	}))
	defer srv.Close()

	q := "target=clash&url=" + url.QueryEscape(nodeLink1+"|"+srv.URL) + "&config=" + url.QueryEscape(acl)
	req := httptest.NewRequest(http.MethodGet, "/sub?"+q, nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("响应不是合法 YAML: %v", err)
	}
	if len(doc.Proxies) != 2 {
		t.Fatalf("混合输入节点数 = %d, want 2", len(doc.Proxies))
	}
}

// TestSubBadTarget 非法 target 返回 400 且错误信息明确。
func TestSubBadTarget(t *testing.T) {
	for _, target := range []string{"surge", "quantumult", "ss", ""} {
		req := httptest.NewRequest(http.MethodGet, "/sub?target="+target+"&url=x", nil)
		rec := httptest.NewRecorder()
		newTestHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("target=%q: status = %d, want 400", target, rec.Code)
			continue
		}
		if body := rec.Body.String(); !strings.Contains(body, "unsupported target") {
			t.Errorf("target=%q: body = %q, 应含 unsupported target", target, body)
		}
	}
}

// TestSubMissingParams 缺 url / url 全空段 / config 非法（裸名字、不存在）。
func TestSubMissingParams(t *testing.T) {
	setupACL(t)
	cases := []struct {
		name, query string
	}{
		{"缺url", "target=clash"},
		{"空url段", "target=clash&url=%20%7C%20"},
		{"config裸名字拒绝", "target=clash&url=" + url.QueryEscape(nodeLink1) + "&config=NoSuch.ini"},
		{"config不存在", "target=clash&url=" + url.QueryEscape(nodeLink1) + "&config=http%3A%2F%2F127.0.0.1%3A1%2Fno.ini"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/sub?"+c.query, nil)
		rec := httptest.NewRecorder()
		newTestHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400, body: %s", c.name, rec.Code, rec.Body.String())
		}
	}
}

// TestSubMethodNotAllowed 非 GET 请求返回 405。
func TestSubMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/sub?target=clash", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestSubRejectsUnsafeRemoteAddresses(t *testing.T) {
	cases := []struct {
		name, query, want string
	}{
		{
			name:  "订阅 metadata",
			query: "target=clash&url=" + url.QueryEscape("http://169.254.169.254/latest/meta-data/?token=subscription-secret"),
			want:  "云 metadata 地址",
		},
		{
			name: "外配置 metadata",
			query: "target=clash&url=" + url.QueryEscape(nodeLink1) + "&config=" +
				url.QueryEscape("http://169.254.169.254/latest/meta-data/?token=config-secret"),
			want: "云 metadata 地址",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/sub?"+tc.query, nil)
			rec := httptest.NewRecorder()
			NewHandler().ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Errorf("错误应说明拒绝原因 %q, body: %s", tc.want, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "secret") {
				t.Errorf("错误不应回显 query: %s", rec.Body.String())
			}
		})
	}
}

func TestSubRejectsUnsafeRuleset(t *testing.T) {
	configURL := "https://config.example/acl.ini"
	h := newHandler(
		func(context.Context, string, string, string) (string, map[string]string, error) {
			return nodeLink1, nil, nil
		},
		func(ctx context.Context, rawURL string) (string, error) {
			if rawURL == configURL {
				return "[custom]\ncustom_proxy_group=代理`select`.*\nruleset=代理,http://10.0.0.1/rules.list\nruleset=代理,[]FINAL\n", nil
			}
			return fetch.FetchText(ctx, rawURL)
		},
	)
	req := httptest.NewRequest(http.MethodGet, "/sub?target=clash&url="+url.QueryEscape("https://subscription.example/sub")+"&config="+url.QueryEscape(configURL), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "私网地址") {
		t.Errorf("规则集私网地址应明确拒绝，body: %s", rec.Body.String())
	}
}

func TestSubConcurrencyLimit(t *testing.T) {
	for range maxConcurrentConversions {
		conversionSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for range maxConcurrentConversions {
			<-conversionSlots
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/sub?target=clash&url=x", nil)
	rec := httptest.NewRecorder()
	NewHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want 1", got)
	}
}

func TestSubUsesConversionDeadline(t *testing.T) {
	var deadline time.Time
	h := newHandler(
		func(ctx context.Context, _ string, _, _ string) (string, map[string]string, error) {
			deadline, _ = ctx.Deadline()
			return nodeLink1, nil, nil
		},
		func(context.Context, string) (string, error) {
			return "[custom]\ncustom_proxy_group=代理`select`.*\nruleset=代理,[]FINAL\n", nil
		},
	)
	req := httptest.NewRequest(http.MethodGet, "/sub?target=clash&url=https%3A%2F%2Fsubscription.example%2Fsub", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	remaining := time.Until(deadline)
	if deadline.IsZero() || remaining > conversionTimeout || remaining < conversionTimeout-time.Second {
		t.Errorf("转换上下文剩余时限 = %s, want 接近 %s", remaining, conversionTimeout)
	}
}

func TestExternalConfigUsesRemoteCache(t *testing.T) {
	configURL := "https://config.example/cache-test.ini"
	var calls int
	fetchText := func(context.Context, string) (string, error) {
		calls++
		return "[custom]\n", nil
	}
	for range 2 {
		if _, err := loadExternalConfig(context.Background(), configURL, fetchText); err != nil {
			t.Fatalf("外配置拉取失败: %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("同一外配置应命中缓存，calls = %d", calls)
	}
}

func TestSubConversionTimeout(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	rec := httptest.NewRecorder()
	if err := writeConversionTimeout(rec, ctx); err == nil {
		t.Fatal("超时上下文应返回错误")
	}
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "转换超时（60s）") {
		t.Errorf("超时错误不明确: %s", rec.Body.String())
	}
}

// TestAccessLog 全量访问日志：任意请求（含 404/405）都输出一行
// 方法/路径/状态码/来源 IP，且不落 query（订阅地址含 token）。
func TestAccessLog(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	h := newTestHandler()

	// 200 正常请求（httptest.NewRequest 默认 RemoteAddr 192.0.2.1:1234）
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	// 404 未匹配路径
	req = httptest.NewRequest(http.MethodGet, "/not-exist", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	out := buf.String()
	for _, want := range []string{"[http]", "GET /version 200", "GET /not-exist 404", "来源=192.0.2.1:1234"} {
		if !strings.Contains(out, want) {
			t.Errorf("访问日志应包含 %q:\n%s", want, out)
		}
	}

	// query 不得落日志（订阅、配置、过滤、重命名和代理参数均可携带凭据）
	requestURL := "/sub?target=clash&url=" + url.QueryEscape("https://token-secret@example.com/sub?subscription-secret") +
		"&config=" + url.QueryEscape("https://config.example/acl.ini?config-secret") +
		"&include=include-secret&exclude=exclude-secret&rename=rename-secret%40x&proxy=" +
		url.QueryEscape("http://proxy-secret.example:8080")
	req = httptest.NewRequest(http.MethodGet, requestURL, nil)
	buf.Reset()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	got := buf.String()
	for _, secret := range []string{"token-secret", "subscription-secret", "config-secret", "include-secret", "exclude-secret", "rename-secret", "proxy-secret"} {
		if strings.Contains(got, secret) {
			t.Errorf("访问日志泄露 query 凭据 %q:\n%s", secret, got)
		}
	}
	if !strings.Contains(got, "GET /sub 400") {
		t.Errorf("访问日志应记录 /sub 400:\n%s", got)
	}
}

// TestIndexPage / 返回内嵌订阅链接生成页；未知路径 404；POST 405。
func TestIndexPage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	body := rec.Body.String()
	// 页面必须覆盖后端 /sub 的全部参数，防止页面与接口脱节
	// （config 由预设下拉 + 自定义输入两个控件承担）
	for _, marker := range []string{"target", "url", "configPreset", "configCustom", "include", "exclude", "ua", "filename"} {
		if !strings.Contains(body, `id="`+marker+`"`) {
			t.Errorf("页面缺少参数输入 id=%q", marker)
		}
	}
	if !strings.Contains(body, "/sub") {
		t.Error("页面应生成 /sub 链接")
	}
	if strings.Contains(body, "new_name") {
		t.Error("页面不应保留已删除的 new_name 参数")
	}
	// 默认预设须直接携带完整 URL（页面只读展示 + 生成链接都依赖它）
	defaultACL := "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/config/ACL4SSR_Online_Full.ini"
	if !strings.Contains(body, `value="`+defaultACL+`"`) {
		t.Errorf("默认外配置选项应携带完整 URL %s", defaultACL)
	}

	req = httptest.NewRequest(http.MethodGet, "/not-exist", nil)
	rec = httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("未知路径 status = %d, want 404", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	rec = httptest.NewRecorder()
	newTestHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST / status = %d, want 405", rec.Code)
	}
}
