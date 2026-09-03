package parser

import (
	"fmt"
	"strings"

	"subconv/internal/model"
)

// parseVLESS 解析 vless://uuid@host:port?params#name 链接（含 REALITY 全参数）。
// 参考 C++ 版 explodeStdVLESS。
func parseVLESS(link string) (*model.Proxy, error) {
	body := strings.TrimPrefix(link, "vless://")
	body, query, remark := parseLinkParts(body)

	uuid, host, port, err := splitUserHostPort(body)
	if err != nil {
		return nil, fmt.Errorf("vless 链接主机部分非法: %w", err)
	}
	if uuid == "" {
		return nil, fmt.Errorf("vless 链接缺少 UUID")
	}

	q := parseQuery(query)
	node := &model.Proxy{
		Type:              model.TypeVLESS,
		Name:              remark,
		Server:            host,
		Port:              port,
		UUID:              uuid,
		Flow:              q["flow"],
		PublicKey:         q["pbk"],
		ShortID:           q["sid"],
		ClientFingerprint: q["fp"],
		Fingerprint:       q["hpkp"],
		SNI:               firstNonEmpty(q["sni"], q["peer"]),
	}

	// security=reality 或 tls → 开启 TLS
	switch q["security"] {
	case "reality", "tls":
		node.TLSSecure = true
	}

	// insecure / allowInsecure / scv 三态（空值返回 nil，允许 /sub 参数层覆盖）
	node.SkipCertVerify = parseBoolPtrOr(q["insecure"], q["allowInsecure"], q["scv"], q["skip-cert-verify"])
	if v := parseBoolPtrOr(q["udp"]); v != nil {
		node.UDP = v
	}
	if v := parseBoolPtrOr(q["tfo"], q["fast-open"]); v != nil {
		node.TCPFastOpen = v
	}

	// 传输层。type 缺省 tcp
	network := q["type"]
	if network == "" {
		network = "tcp"
	}
	node.Network = network
	switch network {
	case "tcp", "quic":
		// 无传输层附加字段
	case "ws", "h2", "http":
		if p := q["path"]; p != "" {
			node.WSPath = urlDecode(p)
		}
		if h := q["host"]; h != "" {
			node.WSHeaders = map[string]string{"Host": urlDecode(h)}
		}
	case "grpc":
		node.GRPCServiceName = urlDecode(q["serviceName"])
		if mode := q["mode"]; mode != "" {
			node.GRPCMode = mode
		} else {
			node.GRPCMode = "gun"
		}
	default:
		return nil, fmt.Errorf("vless 链接不支持的传输类型: %q", network)
	}

	node.ALPN = splitALPN(q["alpn"])

	if node.Name == "" {
		node.Name = defaultName(host, port)
	}
	return node, nil
}

func init() {
	register(parseVLESS, "vless")
}
