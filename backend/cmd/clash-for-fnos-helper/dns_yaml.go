package main

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// dnsYAMLKeys is the set of DNS keys accepted by the advanced YAML editor.
// Hosts live in a separate top-level block and are rejected here on purpose.
var dnsYAMLKeys = map[string]bool{
	"enable": true, "listen": true, "ipv6": true, "enhanced-mode": true,
	"fake-ip-range": true, "fake-ip-range6": true, "fake-ip-filter-mode": true, "fake-ip-filter": true,
	"prefer-h3": true, "respect-rules": true, "use-hosts": true, "use-system-hosts": true,
	"default-nameserver": true, "nameserver": true, "fallback": true, "fallback-filter": true,
	"nameserver-policy": true, "proxy-server-nameserver": true, "direct-nameserver": true,
	"direct-nameserver-follow-policy": true, "cache-algorithm": true, "cache-size": true,
	"serve-stale": true, "max-fails": true,
}

// normalizeDNSYAML validates an advanced DNS document and returns the block
// to write plus the parsed mapping. Comments and key order are preserved in
// the returned block.
func normalizeDNSYAML(input string) (string, map[string]any, error) {
	text := strings.TrimSpace(input)
	if text == "" {
		return "", nil, fail(400, "DNS YAML 不能为空")
	}
	lines := strings.Split(text, "\n")
	if first := strings.TrimSpace(lines[0]); strings.HasPrefix(first, "dns:") {
		if remainder := strings.TrimSpace(strings.TrimPrefix(first, "dns:")); remainder != "" && !strings.HasPrefix(remainder, "#") {
			return "", nil, fail(400, "DNS YAML 不支持行内写法，请使用块状写法")
		}
		body := lines[1:]
		min := -1
		for _, line := range body {
			if strings.TrimSpace(line) == "" {
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if min < 0 || indent < min {
				min = indent
			}
		}
		if min < 0 {
			min = 0
		}
		for index, line := range body {
			if len(line) >= min {
				body[index] = line[min:]
			}
		}
		text = strings.TrimRight(strings.Join(body, "\n"), "\n")
	}
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(text), &parsed); err != nil {
		return "", nil, fail(400, fmt.Sprintf("DNS YAML 无效: %v", err))
	}
	if parsed == nil {
		return "", nil, fail(400, "DNS YAML 必须是对象")
	}
	unknown := make([]string, 0)
	for key := range parsed {
		if !dnsYAMLKeys[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return "", nil, fail(400, fmt.Sprintf("DNS YAML 包含不支持的键: %s", strings.Join(unknown, ", ")))
	}
	var block strings.Builder
	block.WriteString("dns:\n")
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			block.WriteString("\n")
			continue
		}
		block.WriteString("  ")
		block.WriteString(line)
		block.WriteString("\n")
	}
	return strings.TrimRight(block.String(), "\n"), parsed, nil
}
