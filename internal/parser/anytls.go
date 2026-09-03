package parser

import (
	"fmt"
	"strings"

	"subconv/internal/model"
)

// parseAnyTLS 解析 anytls://password@host:port?params#name 链接，
// 参考 C++ 版 explodeStdAnyTLS。
func parseAnyTLS(link string) (*model.Proxy, error) {
	body, query, remark := parseLinkParts(strings.TrimPrefix(link, "anytls://"))

	password, host, port, err := splitUserHostPort(body)
	if err != nil {
		return nil, fmt.Errorf("anytls 链接主机部分非法: %w", err)
	}
	if password == "" {
		return nil, fmt.Errorf("anytls 链接缺少密码")
	}

	q := parseQuery(query)
	node := &model.Proxy{
		Type:              model.TypeAnyTLS,
		Name:              remark,
		Server:            host,
		Port:              port,
		Password:          password,
		SNI:               firstNonEmpty(q["sni"], q["peer"]),
		ClientFingerprint: firstNonEmpty(q["fp"], q["client-fingerprint"]),
		TLSSecure:         true,
		SkipCertVerify:    parseBoolPtrOr(q["insecure"], q["scv"], q["skip-cert-verify"]),
		ALPN:              splitALPN(q["alpn"]),
	}
	if v := parseBoolPtrOr(q["udp"]); v != nil {
		node.UDP = v
	}
	if v := parseBoolPtrOr(q["tfo"], q["fast-open"]); v != nil {
		node.TCPFastOpen = v
	}

	if node.Name == "" {
		node.Name = defaultName(host, port)
	}
	return node, nil
}

func init() {
	register(parseAnyTLS, "anytls")
}
