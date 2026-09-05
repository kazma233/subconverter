package render

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"subconv/internal/fetch"
	"subconv/internal/rule"
)

const (
	remoteCacheTTL        = 6 * time.Hour
	maxRemoteCacheEntries = 256
	maxRemoteCacheBytes   = 128 << 20
	remoteCacheEntryBytes = 256
)

type remoteCacheEntry struct {
	content  string
	cachedAt time.Time
	lastUsed time.Time
}

type remoteFetchCall struct {
	done    chan struct{}
	content string
	err     error
}

// 规则集 URL 由请求提供，缓存必须有边界，避免公开服务的内存随 URL 数量持续增长。
var (
	remoteCacheMu       sync.Mutex
	remoteCache         = make(map[string]remoteCacheEntry)
	remoteCacheBytes    int
	remoteFetchMu       sync.Mutex
	remoteFetchInFlight = make(map[string]*remoteFetchCall)
)

// FetchRemote 下载远程规则集，带内存缓存与默认下载保护。
func FetchRemote(ctx context.Context, url string) (string, error) {
	return FetchRemoteWith(ctx, url, fetch.FetchText)
}

// FetchRemoteWith 使用调用方指定的下载器拉取远程资产，仍共享进程内缓存。
func FetchRemoteWith(ctx context.Context, url string, fetchText func(context.Context, string) (string, error)) (string, error) {
	return fetchRemote(ctx, url, fetchText)
}

func fetchRemote(ctx context.Context, url string, fetchText func(context.Context, string) (string, error)) (string, error) {
	if content, ok := getCachedRemote(url, time.Now()); ok {
		return content, nil
	}

	key := strings.Clone(url)
	remoteFetchMu.Lock()
	if content, ok := getCachedRemote(key, time.Now()); ok {
		remoteFetchMu.Unlock()
		return content, nil
	}
	if call, ok := remoteFetchInFlight[key]; ok {
		remoteFetchMu.Unlock()
		select {
		case <-call.done:
			return call.content, call.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	call := &remoteFetchCall{done: make(chan struct{})}
	remoteFetchInFlight[key] = call
	remoteFetchMu.Unlock()

	content, err := fetchText(ctx, key)
	if err != nil {
		finishRemoteFetch(key, call, "", err)
		return "", err
	}
	putCachedRemote(key, content, time.Now())
	finishRemoteFetch(key, call, content, nil)
	log.Printf("[fetch] 远程资产拉取 host=%s %d字节", fetch.URLLabel(key), len(content))
	return content, nil
}

func finishRemoteFetch(url string, call *remoteFetchCall, content string, err error) {
	remoteFetchMu.Lock()
	call.content, call.err = content, err
	delete(remoteFetchInFlight, url)
	close(call.done)
	remoteFetchMu.Unlock()
}

func getCachedRemote(url string, now time.Time) (string, bool) {
	remoteCacheMu.Lock()
	defer remoteCacheMu.Unlock()

	deleteExpiredRemoteCacheEntries(now)
	entry, ok := remoteCache[url]
	if !ok {
		return "", false
	}
	entry.lastUsed = now
	remoteCache[url] = entry
	return entry.content, true
}

func putCachedRemote(url, content string, now time.Time) {
	remoteCacheMu.Lock()
	defer remoteCacheMu.Unlock()

	deleteExpiredRemoteCacheEntries(now)
	if old, ok := remoteCache[url]; ok {
		deleteRemoteCacheEntry(url, old)
	}
	entrySize := remoteCacheSize(url, content)
	if entrySize > maxRemoteCacheBytes {
		return
	}
	for len(remoteCache) >= maxRemoteCacheEntries || remoteCacheBytes+entrySize > maxRemoteCacheBytes {
		if !evictOldestRemoteCacheEntry() {
			return
		}
	}
	key := strings.Clone(url)
	remoteCache[key] = remoteCacheEntry{content: strings.Clone(content), cachedAt: now, lastUsed: now}
	remoteCacheBytes += entrySize
}

func deleteRemoteCacheEntry(url string, entry remoteCacheEntry) {
	delete(remoteCache, url)
	remoteCacheBytes -= remoteCacheSize(url, entry.content)
}

func deleteExpiredRemoteCacheEntries(now time.Time) {
	for url, entry := range remoteCache {
		if !now.Before(entry.cachedAt.Add(remoteCacheTTL)) {
			deleteRemoteCacheEntry(url, entry)
		}
	}
}

func remoteCacheSize(url, content string) int {
	return len(url) + len(content) + remoteCacheEntryBytes
}

func evictOldestRemoteCacheEntry() bool {
	var oldestURL string
	var oldest remoteCacheEntry
	for url, entry := range remoteCache {
		if oldestURL == "" || entry.lastUsed.Before(oldest.lastUsed) {
			oldestURL, oldest = url, entry
		}
	}
	if oldestURL == "" {
		return false
	}
	deleteRemoteCacheEntry(oldestURL, oldest)
	return true
}

// clashRuleTypes Clash 支持的规则类型前缀（对齐 C++ ClashRuleTypes）。
var clashRuleTypes = []string{
	"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD",
	"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR",
	"GEOIP", "MATCH", "FINAL",
	"SRC-PORT", "DST-PORT", "PROCESS-NAME",
}

// renderRules 由 ACL 规则集定义生成 rules 列表：
//   - 内联规则（[]GEOIP,CN / []FINAL）直接展开
//   - 远程 http(s) 规则集先并发预取（内存缓存、受调用方下载时限约束），任一失败即返回错误
//   - 非 http(s) 规则集路径直接返回错误
//   - 每条规则展开为 "类型,值,策略[,附加参数]"；无策略的行用所属规则集的组名兜底
//   - 尾部必带 MATCH 兜底（已有 MATCH 时不重复追加）
func renderRules(acl *rule.ACLConfig) ([]string, error) {
	return renderRulesWithFetcher(context.Background(), acl, fetch.FetchText)
}

func renderRulesWithConfig(cfg *Config) ([]string, error) {
	ctx := context.Background()
	if cfg != nil && cfg.RequestContext != nil {
		ctx = cfg.RequestContext
	}
	fetchText := fetch.FetchText
	if cfg != nil && cfg.FetchText != nil {
		fetchText = cfg.FetchText
	}
	var acl *rule.ACLConfig
	if cfg != nil {
		acl = cfg.ACL
	}
	return renderRulesWithFetcher(ctx, acl, fetchText)
}

func renderRulesWithFetcher(ctx context.Context, acl *rule.ACLConfig, fetchText func(context.Context, string) (string, error)) ([]string, error) {
	rulesets := []rule.RulesetConfig{}
	var groups []rule.GroupConfig
	if acl != nil {
		rulesets = acl.Rulesets
		groups = acl.Groups
	}
	defaultPolicy := pickDefaultPolicy(rulesets, groups)

	// 并发预取远程规则集，避免逐条串行等待超时；规则缺失会改变流量路径，必须让请求失败。
	if err := prefetchRemoteRulesets(ctx, rulesets, fetchText); err != nil {
		return nil, fmt.Errorf("规则集预取失败: %w", err)
	}

	var rules []string
	for _, rs := range rulesets {
		group := rs.Group
		if group == "" {
			// 未指定策略组的规则集（ruleset=path 形态）用默认策略兜底
			group = defaultPolicy
		}
		if rs.Inline != "" {
			rules = append(rules, transformRule(rs.Inline, group))
			continue
		}

		content, err := loadRulesetContent(ctx, rs.Path, fetchText)
		if err != nil {
			return nil, fmt.Errorf("规则集 host=%s 装载失败: %w", fetch.URLLabel(rs.Path), err)
		}
		rules = append(rules, parseRulesetLines(content, group)...)
	}

	// 尾部 MATCH 兜底
	hasMatch := false
	for _, r := range rules {
		if r == "MATCH,"+defaultPolicy || strings.HasPrefix(r, "MATCH,") {
			hasMatch = true
			break
		}
	}
	if !hasMatch {
		rules = append(rules, "MATCH,"+defaultPolicy)
	}
	return rules, nil
}

// pickDefaultPolicy 选择兜底策略：优先 []FINAL 规则集的组名，
// 否则第一个策略组，否则 DIRECT。
func pickDefaultPolicy(rulesets []rule.RulesetConfig, groups []rule.GroupConfig) string {
	for _, rs := range rulesets {
		if rs.Inline == "FINAL" && rs.Group != "" {
			return rs.Group
		}
	}
	for _, g := range groups {
		if g.Name != "" {
			return g.Name
		}
	}
	return "DIRECT"
}

// prefetchRemoteRulesets 并发预取所有远程规则集到内存缓存，任一下载失败即返回错误。
// 按 URL 去重：同一 URL 只发起一次下载，被多个规则集引用时共享缓存。
func prefetchRemoteRulesets(ctx context.Context, rulesets []rule.RulesetConfig, fetchText func(context.Context, string) (string, error)) error {
	urls := make(map[string]struct{})
	for _, rs := range rulesets {
		if !strings.HasPrefix(rs.Path, "http://") && !strings.HasPrefix(rs.Path, "https://") {
			continue
		}
		urls[rs.Path] = struct{}{}
	}
	if len(urls) == 0 {
		return nil
	}

	workerCount := min(len(urls), fetch.MaxConcurrentDownloads)
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan string)
	errs := make(chan error, 1)
	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-workCtx.Done():
					return
				case url, ok := <-jobs:
					if !ok {
						return
					}
					if _, err := fetchRemote(workCtx, url, fetchText); err != nil {
						select {
						case errs <- err:
						default:
						}
						cancel()
						return
					}
				}
			}
		}()
	}

dispatch:
	for url := range urls {
		select {
		case <-workCtx.Done():
			break dispatch
		case jobs <- url:
		}
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
		return ctx.Err()
	}
}

// loadRulesetContent 装载规则集内容：仅支持 http(s) 远程 URL 下载（带缓存）。
// 规则资产完全动态，不解析本地文件路径。
func loadRulesetContent(ctx context.Context, path string, fetchText func(context.Context, string) (string, error)) (string, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return fetchRemote(ctx, path, fetchText)
	}
	return "", fmt.Errorf("规则集路径非法：仅支持 http(s) URL")
}

// parseRulesetLines 解析 .list 规则集文本的每一行：
// 跳过空行与 ; # // 注释；截断行内 // 注释；类型前缀不认识的行跳过（对齐 C++）；
// 每行展开为 "类型,值,策略[,附加参数]"。
func parseRulesetLines(content, group string) []string {
	var rules []string
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "//") {
			continue
		}
		// 行内 // 注释截断（对齐 C++）
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}
		if !isKnownRuleType(line) {
			continue
		}
		rules = append(rules, transformRule(line, group))
	}
	return rules
}

// isKnownRuleType 判断行是否以 Clash 支持的规则类型开头。
func isKnownRuleType(line string) bool {
	for _, t := range clashRuleTypes {
		if line == t || strings.HasPrefix(line, t+",") {
			return true
		}
	}
	return false
}

// transformRule 把单条规则展开为 "类型,值,策略[,附加参数]"：
//   - 不足两段（如 MATCH）：补策略 → "MATCH,策略"
//   - 两段：追加策略
//   - 三段及以上：第三段作为附加参数（如 no-resolve）追加在策略之后，
//     其余段丢弃（对齐 C++ transformRuleToCommon）
//   - FINAL 统一改写为 MATCH（Clash 语法）
func transformRule(line, policy string) string {
	if strings.HasPrefix(line, "FINAL") {
		line = "MATCH" + strings.TrimPrefix(line, "FINAL")
	}
	parts := strings.Split(line, ",")
	switch len(parts) {
	case 1:
		return parts[0] + "," + policy
	case 2:
		return parts[0] + "," + parts[1] + "," + policy
	default:
		out := parts[0] + "," + parts[1] + "," + policy + "," + parts[2]
		return out
	}
}
