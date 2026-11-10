package main

import (
	"strings"
	"testing"
)

func TestNormalizeDNSYAML(t *testing.T) {
	block, parsed, err := normalizeDNSYAML("enable: true\nlisten: \"0.0.0.0:53\"\nnameserver:\n  - 223.5.5.5\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(block, "dns:\n  enable: true\n  listen: \"0.0.0.0:53\"") {
		t.Fatalf("unexpected block: %s", block)
	}
	if parsed["enable"] != true || parsed["listen"] != "0.0.0.0:53" {
		t.Fatalf("unexpected parsed values: %#v", parsed)
	}
}

func TestNormalizeDNSYAMLStripsTopLevelKey(t *testing.T) {
	block, _, err := normalizeDNSYAML("dns:\n  enable: true\n  respect-rules: true\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(block, "  respect-rules: true") {
		t.Fatalf("block not re-indented: %s", block)
	}
}

func TestNormalizeDNSYAMLRejectsUnknownKey(t *testing.T) {
	if _, _, err := normalizeDNSYAML("enable: true\nbogus: 1\n"); err == nil || !strings.Contains(err.Error(), "不支持的键") {
		t.Fatalf("unknown key accepted: %v", err)
	}
}

func TestNormalizeDNSYAMLRejectsInvalidYAML(t *testing.T) {
	if _, _, err := normalizeDNSYAML("enable: [\n"); err == nil {
		t.Fatal("invalid YAML accepted")
	}
}

func TestNormalizeDNSYAMLRejectsHosts(t *testing.T) {
	if _, _, err := normalizeDNSYAML("hosts:\n  a: 1.2.3.4\n"); err == nil {
		t.Fatal("hosts should be rejected")
	}
}
