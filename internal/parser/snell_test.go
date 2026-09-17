package parser

import (
	"testing"

	"subconv/internal/model"
)

func TestSnellBasic(t *testing.T) {
	p, err := ParseLink("snell://psk123@example.com:6160?version=4&obfs=http&obfs-host=bing.com#%E8%8A%82%E7%82%B9")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.Type != model.TypeSnell {
		t.Errorf("Type = %v, want TypeSnell", p.Type)
	}
	if p.Password != "psk123" {
		t.Errorf("Password = %q, want psk123", p.Password)
	}
	if p.Server != "example.com" || p.Port != 6160 {
		t.Errorf("Server/Port = %q/%d, want example.com/6160", p.Server, p.Port)
	}
	if p.SnellVersion != 4 {
		t.Errorf("SnellVersion = %d, want 4", p.SnellVersion)
	}
	if p.SnellObfs != "http" {
		t.Errorf("SnellObfs = %q, want http", p.SnellObfs)
	}
	if p.SnellObfsHost != "bing.com" {
		t.Errorf("SnellObfsHost = %q, want bing.com", p.SnellObfsHost)
	}
	if p.Name != "节点" {
		t.Errorf("Name = %q, want 节点", p.Name)
	}
	// snell 非 TLS，不应设置 TLS 相关字段
	if p.TLSSecure || p.SNI != "" || p.SkipCertVerify != nil {
		t.Errorf("snell 不应携带 TLS 字段: TLSSecure=%v SNI=%q scv=%v", p.TLSSecure, p.SNI, p.SkipCertVerify)
	}
}

func TestSnellDefaults(t *testing.T) {
	p, err := ParseLink("snell://secret@1.2.3.4:443")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.SnellVersion != 0 {
		t.Errorf("SnellVersion = %d, want 0（未指定）", p.SnellVersion)
	}
	if p.SnellObfs != "" || p.SnellObfsHost != "" {
		t.Errorf("混淆字段应为空: %q/%q", p.SnellObfs, p.SnellObfsHost)
	}
	if p.Name != "1.2.3.4:443" {
		t.Errorf("Name = %q, want 1.2.3.4:443", p.Name)
	}
	// 非法 version 视为未设置而不是报错
	p2, err := ParseLink("snell://secret@1.2.3.4:443?version=abc")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p2.SnellVersion != 0 {
		t.Errorf("非法 version 应忽略, got %d", p2.SnellVersion)
	}
}

func TestSnellErrors(t *testing.T) {
	if _, err := ParseLink("snell://example.com:6160?version=4"); err == nil {
		t.Error("缺少 psk 应报错")
	}
	if _, err := ParseLink("snell://psk@example.com"); err == nil {
		t.Error("缺少端口应报错")
	}
}
