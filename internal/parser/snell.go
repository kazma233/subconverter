package parser

import (
	"fmt"
	"strconv"
	"strings"

	"subconv/internal/model"
)

// parseSnell 解析 snell://psk@host:port?params#name 链接。
// C++ 版没有 snell:// URI 解析（Snell 只从 Clash YAML / Surge conf 读入），
// 此处按社区通行约定实现（Shadowrocket / Sub-Store，与 trojan 链接同构）：
//
//	version    —— SnellVersion（非法数字视为未设置）
//	obfs       —— SnellObfs（http / off）
//	obfs-host  —— SnellObfsHost
//	udp/tfo    —— 三态
//
// snell 基于 PSK 自带加密而非 TLS，不读 sni/alpn/insecure。
func parseSnell(link string) (*model.Proxy, error) {
	body, query, remark := parseLinkParts(strings.TrimPrefix(link, "snell://"))

	psk, host, port, err := splitUserHostPort(body)
	if err != nil {
		return nil, fmt.Errorf("snell 链接主机部分非法: %w", err)
	}
	if psk == "" {
		return nil, fmt.Errorf("snell 链接缺少 psk")
	}

	q := parseQuery(query)
	node := &model.Proxy{
		Type:     model.TypeSnell,
		Name:     remark,
		Server:   host,
		Port:     port,
		Password: psk,
	}
	if v, err := strconv.Atoi(q["version"]); err == nil {
		node.SnellVersion = v
	}
	node.SnellObfs = q["obfs"]
	node.SnellObfsHost = q["obfs-host"]
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
	register(parseSnell, "snell")
}
