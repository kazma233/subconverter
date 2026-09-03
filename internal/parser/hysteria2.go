package parser

import (
	"fmt"
	"strconv"
	"strings"

	"subconv/internal/model"
)

// parseHysteria2 解析 hysteria2://password@host:port?params#name 链接
// （hy2:// 为别名），参考 C++ 版 explodeStdHysteria2。
//
// 参数映射（对齐 subconverter 通用 hy2 协议）：
//
//	obfs / obfs-password       —— 混淆 salamander + 密码
//	sni / alpn / insecure      —— TLS 层
//	ca / ca-str                —— CA 证书（路径 / PEM 字符串）
//	mport / ports              —— 端口跳跃范围（逗号/冒号）
//	up / down                  —— 速率（整数 mbps，对应 up_mbps/down_mbps）
//	cwnd                       —— 拥塞窗口
//	hop                        —— 端口跳跃间隔（秒，写进 int 暂存，渲染时补 s）
//	tfo / udp / scv            —— 三态覆盖（tfo/fast-open / udp / scv/skip-cert-verify/insecure）
//
// hysteria2 天然基于 TLS（QUIC），TLSSecure 恒为 true。
func parseHysteria2(link string) (*model.Proxy, error) {
	body := link
	if strings.HasPrefix(link, "hysteria2://") {
		body = strings.TrimPrefix(link, "hysteria2://")
	} else {
		body = strings.TrimPrefix(link, "hy2://")
	}
	body, query, remark := parseLinkParts(body)

	password, host, port, err := splitUserHostPort(body)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 链接主机部分非法: %w", err)
	}
	if password == "" {
		return nil, fmt.Errorf("hysteria2 链接缺少密码")
	}

	q := parseQuery(query)
	node := &model.Proxy{
		Type:                  model.TypeHysteria2,
		Name:                  remark,
		Server:                host,
		Port:                  port,
		Password:              password,
		Hysteria2Mport:        q["mport"],
		Hysteria2Obfs:         q["obfs"],
		Hysteria2ObfsPassword: q["obfs-password"],
		Hysteria2Ports:        firstNonEmpty(q["ports"], q["mport"]),
		SNI:                   q["sni"],
		ClientFingerprint:     firstNonEmpty(q["fp"], q["pin-sha256"]),
		CACertPath:            q["ca"],
		CACertStr:             q["ca-str"],
		ALPN:                  splitALPN(q["alpn"]),
		Hysteria2CWND:         parseIntParam(q["cwnd"]),
		Hysteria2HopInterval:  parseIntParam(q["hop"]),
		Hysteria2UpMbps:       parseIntParam(firstNonEmpty(q["up-mbps"], q["up"], q["upmbps"])),
		Hysteria2DownMbps:     parseIntParam(firstNonEmpty(q["down-mbps"], q["down"], q["downmbps"])),
		TLSSecure:             true,
	}

	// 三态：仅当 query 里有显式值时才写指针，不传 → nil 让 /sub 参数覆盖逻辑兜底
	if v, ok := q["insecure"]; ok {
		b := parseBoolParam(v)
		node.SkipCertVerify = &b
	} else if v, ok := q["scv"]; ok {
		b := parseBoolParam(v)
		node.SkipCertVerify = &b
	} else if v, ok := q["skip-cert-verify"]; ok {
		b := parseBoolParam(v)
		node.SkipCertVerify = &b
	}
	if v, ok := q["tfo"]; ok {
		b := parseBoolParam(v)
		node.TCPFastOpen = &b
	} else if v, ok := q["fast-open"]; ok {
		b := parseBoolParam(v)
		node.TCPFastOpen = &b
	}
	if v, ok := q["udp"]; ok {
		b := parseBoolParam(v)
		node.UDP = &b
	}

	if node.Name == "" {
		node.Name = defaultName(host, port)
	}
	return node, nil
}

// parseIntParam 宽松解析整数参数，空串或非法值返回 0（0 表示未设置，渲染时忽略即可）。
func parseIntParam(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func init() {
	register(parseHysteria2, "hysteria2", "hy2")
}
