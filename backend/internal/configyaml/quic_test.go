package configyaml

import (
	"strings"
	"testing"
)

func TestQUICRules(t *testing.T) {
	cases := []struct {
		name   string
		policy QUICPolicy
		want   []string
	}{
		{"default", QUICPolicy{}, []string{
			"AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,cn)),DIRECT",
			"AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN)),DIRECT",
			"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
		}},
		{"domestic reject", QUICPolicy{Domestic: "reject", Foreign: "off"}, []string{
			"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
		}},
		{"foreign off", QUICPolicy{Domestic: "direct", Foreign: "off"}, []string{
			"AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,cn)),DIRECT",
			"AND,((NETWORK,UDP),(DST-PORT,443),(GEOIP,CN)),DIRECT",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := QUICRules(tc.policy)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("QUICRules() = %#v, want %#v", got, tc.want)
			}
		})
	}
	if got := QUICRules(QUICPolicy{Domestic: "bogus"}); got != nil {
		t.Fatalf("invalid policy should produce no rules, got %#v", got)
	}
}

func TestSystemRulesPrependNTPFirst(t *testing.T) {
	rules := append([]string{NTPDirectRule}, QUICRules(QUICPolicy{})...)
	got, err := PrependRules([]byte("rules:\n  - MATCH,DIRECT\n"), rules)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	ntp := strings.Index(text, NTPDirectRule)
	if ntp < 0 {
		t.Fatalf("NTP rule missing:\n%s", text)
	}
	for _, rule := range QUICRules(QUICPolicy{}) {
		index := strings.Index(text, rule)
		if index < 0 || index < ntp {
			t.Fatalf("QUIC rule not after NTP: %s\n%s", rule, text)
		}
	}
	if strings.Count(text, "DST-PORT,123") != 1 {
		t.Fatalf("duplicate NTP rule:\n%s", text)
	}
}

func TestPrependRulesPreservesDocument(t *testing.T) {
	raw := []byte("port: 7890\nrules:\n    - DOMAIN-SUFFIX,a.com,PROXY\n    - MATCH,DIRECT\n")
	got, err := PrependRules(raw, []string{"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"})
	if err != nil {
		t.Fatal(err)
	}
	want := "port: 7890\nrules:\n    - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT\n    - DOMAIN-SUFFIX,a.com,PROXY\n    - MATCH,DIRECT\n"
	if string(got) != want {
		t.Fatalf("PrependRules() =\n%s\nwant\n%s", got, want)
	}
}

func TestPrependRulesAppendsMissingBlock(t *testing.T) {
	got, err := PrependRules([]byte("port: 7890\n"), []string{"X,Y,Z"})
	if err != nil {
		t.Fatal(err)
	}
	want := "port: 7890\nrules:\n  - X,Y,Z\n"
	if string(got) != want {
		t.Fatalf("PrependRules() = %q, want %q", got, want)
	}
}

func TestPrependRulesRejectsInlineRules(t *testing.T) {
	if _, err := PrependRules([]byte("rules: [A,B]\n"), []string{"X,Y,Z"}); err == nil {
		t.Fatal("inline rules should be rejected")
	}
}
