package configyaml

import (
	"fmt"
	"strings"
)

// QUICPolicy controls how UDP/443 (QUIC) traffic is routed.
//
// Domestic accepts "direct" or "reject"; "direct" keeps QUIC on the local
// path, "reject" forces every client to fall back to TCP. Foreign accepts
// "reject" or "off". REJECT (rather than REJECT-DROP) is used so browsers
// receive an ICMP unreachable and switch to TCP immediately.
type QUICPolicy struct {
	Domestic string `json:"domestic"`
	Foreign  string `json:"foreign"`
}

// NormalizeQUICPolicy fills defaults and validates the allowed values.
func NormalizeQUICPolicy(policy QUICPolicy) (QUICPolicy, error) {
	domestic := strings.ToLower(strings.TrimSpace(policy.Domestic))
	if domestic == "" {
		domestic = "direct"
	}
	foreign := strings.ToLower(strings.TrimSpace(policy.Foreign))
	if foreign == "" {
		foreign = "reject"
	}
	switch domestic {
	case "direct", "reject":
	default:
		return QUICPolicy{}, fmt.Errorf("国内 QUIC 策略必须为 direct 或 reject")
	}
	switch foreign {
	case "reject", "off":
	default:
		return QUICPolicy{}, fmt.Errorf("国外 QUIC 策略必须为 reject 或 off")
	}
	return QUICPolicy{Domestic: domestic, Foreign: foreign}, nil
}

// QUICRules builds the rules that implement the policy. Rules are ordered so
// domestic destinations are decided before the foreign catch-all.
func QUICRules(policy QUICPolicy) []string {
	normalized, err := NormalizeQUICPolicy(policy)
	if err != nil {
		return nil
	}
	if normalized.Domestic == "reject" {
		return []string{"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"}
	}
	rules := []string{
		"AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,cn)),DIRECT",
		"AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN)),DIRECT",
	}
	if normalized.Foreign == "reject" {
		rules = append(rules, "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
	}
	return rules
}

// PrependRules inserts generated rules at the head of the top-level rules
// list while preserving the rest of the document byte for byte. Comments,
// key order and anchors outside the rules block are untouched.
func PrependRules(raw []byte, rules []string) ([]byte, error) {
	if len(rules) == 0 {
		return raw, nil
	}
	lines := strings.Split(string(raw), "\n")
	section := -1
	indent := ""
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(line)-len(strings.TrimLeft(line, " ")) != 0 || !strings.HasPrefix(trimmed, "rules:") {
			continue
		}
		remainder := strings.TrimSpace(strings.TrimPrefix(trimmed, "rules:"))
		if remainder != "" && !strings.HasPrefix(remainder, "#") {
			// Inline sequences are uncommon; rewrite only the value.
			if remainder == "[]" || remainder == "null" {
				continue
			}
			return nil, fmt.Errorf("不支持的 rules 行内写法，请改为块状列表")
		}
		section = index
		break
	}
	entries := make([]string, 0, len(rules))
	if section < 0 {
		for _, rule := range rules {
			entries = append(entries, "  - "+rule)
		}
		base := strings.TrimRight(string(raw), "\n")
		if base != "" {
			base += "\n"
		}
		return []byte(base + "rules:\n" + strings.Join(entries, "\n") + "\n"), nil
	}
	// Reuse the indentation of the first existing entry when present.
	for cursor := section + 1; cursor < len(lines); cursor++ {
		trimmed := strings.TrimSpace(lines[cursor])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		current := len(lines[cursor]) - len(strings.TrimLeft(lines[cursor], " "))
		if current == 0 {
			break
		}
		if strings.HasPrefix(trimmed, "-") {
			indent = strings.Repeat(" ", current)
		}
		break
	}
	if indent == "" {
		indent = "  "
	}
	for _, rule := range rules {
		entries = append(entries, indent+"- "+rule)
	}
	out := make([]string, 0, len(lines)+len(entries))
	out = append(out, lines[:section+1]...)
	out = append(out, entries...)
	out = append(out, lines[section+1:]...)
	return []byte(strings.Join(out, "\n")), nil
}
