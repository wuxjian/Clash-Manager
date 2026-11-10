package main

import "testing"

func TestDNSYAMLToForm(t *testing.T) {
	input := map[string]any{
		"enhanced-mode": "redir-host", "respect-rules": true,
		"default-nameserver": []any{"223.5.5.5"},
		"nameserver-policy":  map[string]any{"geosite:cn": []any{"223.5.5.5"}},
		"fallback-filter":    map[string]any{"geoip": true, "geoip-code": "CN", "ipcidr": []any{"240.0.0.0/4"}},
	}
	out := dnsYAMLToForm(input)
	if out["enhancedMode"] != "redir-host" || out["respectRules"] != true {
		t.Fatalf("camelCase mapping failed: %#v", out)
	}
	if _, leaked := out["nameserver-policy"]; leaked {
		t.Fatalf("kebab-case key leaked: %#v", out)
	}
	policy, ok := out["nameserverPolicy"].([]any)
	if !ok || len(policy) != 1 {
		t.Fatalf("nameserverPolicy not converted: %#v", out["nameserverPolicy"])
	}
	if out["fallbackGeoip"] != true || out["fallbackGeoipCode"] != "CN" {
		t.Fatalf("fallback-filter not flattened: %#v", out)
	}
}