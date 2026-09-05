// Package fetch 实现受限的远程文本下载。
package fetch

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	defaultUA              = "clash.meta"
	DownloadTimeout        = 30 * time.Second
	MaxConcurrentDownloads = 16
	maxRetries             = 1
	maxBodySize            = 32 << 20
)

var downloadSlots = make(chan struct{}, MaxConcurrentDownloads)

// LookupIPAddrFunc 和 DialContextFunc 仅用于构造可控下载客户端；生产代码使用系统 DNS
// 与默认拨号器，测试通过注入它们模拟受限网络环境。
type LookupIPAddrFunc func(context.Context, string) ([]net.IPAddr, error)
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// ClientOptions 定义下载客户端的可替换网络依赖。
type ClientOptions struct {
	Timeout      time.Duration
	LookupIPAddr LookupIPAddrFunc
	DialContext  DialContextFunc
}

// Client 统一承载订阅、外配置和规则集的下载安全策略。
type Client struct {
	timeout  time.Duration
	lookupIP LookupIPAddrFunc
	dial     DialContextFunc
	client   *http.Client
}

// AddressError 表示 URL 指向了不允许访问的地址；文本可直接返回给调用方，且不含 URL query。
type AddressError struct {
	Reason string
}

func (e *AddressError) Error() string {
	return "请求地址被拒绝：" + e.Reason
}

// IsAddressRejected 用于 HTTP 层把规则集中的不安全地址也映射为客户端参数错误。
func IsAddressRejected(err error) bool {
	var target *AddressError
	return errors.As(err, &target)
}

// NewClient 创建下载客户端。默认配置使用 30 秒单次超时、系统 DNS 和系统拨号器。
func NewClient(options ClientOptions) *Client {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DownloadTimeout
	}
	lookupIP := options.LookupIPAddr
	if lookupIP == nil {
		lookupIP = net.DefaultResolver.LookupIPAddr
	}
	dial := options.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	c := &Client{timeout: timeout, lookupIP: lookupIP, dial: dial}
	c.client = c.newHTTPClient(nil)
	return c
}

var defaultClient = NewClient(ClientOptions{})

// FetchSubscription 使用默认受限客户端拉取订阅。
func FetchSubscription(rawURL, ua, proxy string) (content string, userinfo map[string]string, err error) {
	return defaultClient.FetchSubscription(context.Background(), rawURL, ua, proxy)
}

// FetchSubscriptionContext 使用默认受限客户端拉取订阅，并受调用方请求上下文约束。
func FetchSubscriptionContext(ctx context.Context, rawURL, ua, proxy string) (content string, userinfo map[string]string, err error) {
	return defaultClient.FetchSubscription(ctx, rawURL, ua, proxy)
}

// FetchSubscription 拉取订阅，网络错误或非 200 状态码自动重试一次。
func (c *Client) FetchSubscription(ctx context.Context, rawURL, ua, proxy string) (content string, userinfo map[string]string, err error) {
	if ua == "" {
		ua = defaultUA
	}
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		start := time.Now()
		content, header, err := c.fetchOnce(ctx, rawURL, ua, proxy)
		if err == nil {
			log.Printf("[fetch] 订阅拉取成功 host=%s %d字节 耗时=%s", URLLabel(rawURL), len(content), time.Since(start))
			return content, parseSubscriptionUserinfo(header.Get("subscription-userinfo")), nil
		}
		if attempt < maxRetries && ctx.Err() == nil && !IsAddressRejected(err) {
			log.Printf("[fetch] 订阅拉取失败（将重试）: %v", err)
		}
		lastErr = err
	}
	return "", nil, lastErr
}

// FetchText 使用默认受限客户端下载外配置或规则集文本，不做订阅重试。
func FetchText(ctx context.Context, rawURL string) (string, error) {
	return defaultClient.FetchText(ctx, rawURL)
}

// FetchText 下载外配置或规则集文本。
func (c *Client) FetchText(ctx context.Context, rawURL string) (string, error) {
	content, _, err := c.fetchOnce(ctx, rawURL, defaultUA, "")
	return content, err
}

func (c *Client) fetchOnce(parent context.Context, rawURL, ua, proxy string) (string, http.Header, error) {
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()

	if err := c.validateURL(ctx, rawURL); err != nil {
		return "", nil, err
	}
	client, err := c.clientForProxy(ctx, proxy)
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", nil, &AddressError{Reason: "URL 格式非法"}
	}
	req.Header.Set("User-Agent", ua)
	// 由本包统一解压，避免不同下载入口对 gzip 的限制不一致。
	req.Header.Set("Accept-Encoding", "gzip")

	if err := acquireDownload(ctx); err != nil {
		return "", nil, err
	}
	defer releaseDownload()

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, normalizeFetchError(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("下载返回状态码 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return "", nil, normalizeFetchError(ctx, err)
	}
	content, err := gunzipIfNeeded(body, resp.Header.Get("Content-Encoding"))
	if err != nil {
		return "", nil, fmt.Errorf("下载响应解压失败")
	}
	return content, resp.Header, nil
}

func (c *Client) clientForProxy(ctx context.Context, rawProxy string) (*http.Client, error) {
	if rawProxy == "" {
		return c.client, nil
	}
	proxyURL, err := url.Parse(rawProxy)
	if err != nil || proxyURL.Hostname() == "" {
		return nil, &AddressError{Reason: "代理地址格式非法"}
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https", "socks5":
	default:
		return nil, &AddressError{Reason: "代理协议不受支持"}
	}
	if err := c.validateHost(ctx, proxyURL.Hostname()); err != nil {
		return nil, err
	}
	return c.newHTTPClient(proxyURL), nil
}

func (c *Client) newHTTPClient(proxyURL *url.URL) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = c.dialContext
	// 隐式环境代理会使目标连接转交给未校验的中间节点，只有显式 proxy 参数可启用代理。
	transport.Proxy = nil
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{
		Timeout:   c.timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return c.validateURL(req.Context(), req.URL.String())
		},
	}
}

func (c *Client) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &AddressError{Reason: "目标地址格式非法"}
	}
	ips, err := c.lookupAllowedIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := c.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		return nil, fmt.Errorf("无法连接到目标地址")
	}
	return nil, lastErr
}

func (c *Client) validateURL(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return &AddressError{Reason: "URL 格式非法"}
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return &AddressError{Reason: "仅支持 http(s) URL"}
	}
	return c.validateHost(ctx, u.Hostname())
}

func (c *Client) validateHost(ctx context.Context, host string) error {
	_, err := c.lookupAllowedIPs(ctx, host)
	return err
}

func (c *Client) lookupAllowedIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := c.lookupIP(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, &AddressError{Reason: "域名无法解析"}
	}
	ips := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			return nil, &AddressError{Reason: "域名解析结果非法"}
		}
		ip = ip.Unmap()
		if reason := rejectedAddressReason(ip); reason != "" {
			return nil, &AddressError{Reason: "域名解析到了" + reason}
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func rejectedAddressReason(ip netip.Addr) string {
	if isCloudMetadataIP(ip) {
		return "云 metadata 地址"
	}
	if ip.IsLoopback() {
		return "回环地址"
	}
	if ip.IsPrivate() || isCarrierGradeNAT(ip) || isBenchmarkIP(ip) {
		return "私网地址"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "链路本地地址"
	}
	if !ip.IsGlobalUnicast() {
		return "非公网地址"
	}
	return ""
}

func isCloudMetadataIP(ip netip.Addr) bool {
	return ip == netip.MustParseAddr("169.254.169.254") ||
		ip == netip.MustParseAddr("100.100.100.200") ||
		ip == netip.MustParseAddr("fd00:ec2::254")
}

func isCarrierGradeNAT(ip netip.Addr) bool {
	return ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

func isBenchmarkIP(ip netip.Addr) bool {
	return ip.Is4() && netip.MustParsePrefix("198.18.0.0/15").Contains(ip)
}

func acquireDownload(ctx context.Context) error {
	select {
	case downloadSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return normalizeFetchError(ctx, ctx.Err())
	}
}

func releaseDownload() {
	<-downloadSlots
}

func normalizeFetchError(ctx context.Context, err error) error {
	var addressErr *AddressError
	if errors.As(err, &addressErr) {
		return addressErr
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("下载超时（%s）", DownloadTimeout)
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return fmt.Errorf("下载已取消")
	}
	return fmt.Errorf("下载失败")
}

// URLLabel 只返回 URL 的 host，供日志与错误上下文使用，避免 URL query 中的凭据泄露。
func URLLabel(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "?"
}

// HostOf 保留旧调用方名称；新代码统一使用 URLLabel 表达日志含义。
func HostOf(rawURL string) string {
	return URLLabel(rawURL)
}

// RedactURL 把错误文本中的 URL 替换为 host，兼容旧调用方的日志脱敏。
func RedactURL(text, rawURL string) string {
	return strings.ReplaceAll(text, rawURL, URLLabel(rawURL))
}

func gunzipIfNeeded(body []byte, contentEncoding string) (string, error) {
	if !strings.EqualFold(strings.TrimSpace(contentEncoding), "gzip") {
		return string(body), nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer zr.Close()
	decoded, err := io.ReadAll(zr)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func parseSubscriptionUserinfo(header string) map[string]string {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}
	userinfo := make(map[string]string)
	for _, kv := range strings.Split(header, ";") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		userinfo[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if len(userinfo) == 0 {
		return nil
	}
	return userinfo
}
