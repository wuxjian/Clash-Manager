package main

// IPv4 LAN interception is isolated in one owned nft table. It never flushes
// foreign rules, replaces a default route, or persists sysctls across reboots.
import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const bypassTable = "clash_manager_bypass"
const bypassRoute = "18462"
const bypassMark = "0x434d/0xffff"

type bypassState struct {
	Schema          int             `json:"schema"`
	Token           string          `json:"token"`
	Mode            string          `json:"mode"`
	Interface       bypassInterface `json:"interface"`
	Port            int             `json:"port"`
	PreviousForward string          `json:"previousForward"`
	WANInterface    string          `json:"wanInterface,omitempty"`
	DNSHijack       bool            `json:"dnsHijack,omitempty"`
	DNSPort         int             `json:"dnsPort,omitempty"`
	DockerRule      bool            `json:"dockerRule,omitempty"`
	CorePID         int             `json:"corePID"`
	RouteAdded      bool            `json:"routeAdded"`
	RuleAdded       bool            `json:"ruleAdded"`
	TableAdded      bool            `json:"tableAdded"`
	// DockerAvailable and Warnings are runtime-only and never persisted.
	DockerAvailable bool     `json:"-"`
	Warnings        []string `json:"-"`
}
type bypassSystem struct {
	process      func() *processInfo
	interfaces   func() []bypassInterface
	liveConfig   func(context.Context, []byte) (map[string]any, error)
	probe        func(context.Context, string) error
	run          func(context.Context, string, string, ...string) ([]byte, error)
	readForward  func() (string, error)
	writeForward func(string) error
	wan          func(context.Context) string
	ipv6Route    func(context.Context) bool
	dockerChain  func(context.Context) bool
}

func (h *helper) bypassOS() *bypassSystem {
	if h.bypassSystem != nil {
		return h.bypassSystem
	}
	return &bypassSystem{
		run: func(ctx context.Context, input, name string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, name, args...)
			cmd.Stdin = strings.NewReader(input)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return out, fmt.Errorf("%s: %w: %.400s", name, err, out)
			}
			return out, nil
		},
		readForward: func() (string, error) {
			b, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
			return strings.TrimSpace(string(b)), e
		},
		writeForward: func(s string) error { return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(s+"\n"), 0600) },
	}
}
func (h *helper) bypassJournalPath() string {
	return filepath.Join(h.config.etcDir, "bypass-managed.json")
}
func (h *helper) readBypassState() (*bypassState, error) {
	raw, err := os.ReadFile(h.bypassJournalPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s bypassState
	if err = json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.Schema != 1 && s.Schema != 2 || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(s.Token) || (s.Mode != "redir" && s.Mode != "tproxy") || (s.PreviousForward != "0" && s.PreviousForward != "1") {
		return nil, errors.New("接管恢复记录无效，拒绝修改系统")
	}
	if s.WANInterface != "" && !regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(s.WANInterface) {
		return nil, errors.New("接管恢复记录无效，拒绝修改系统")
	}
	if s.DNSPort != 0 && (s.DNSPort < 1 || s.DNSPort > 65535) {
		return nil, errors.New("接管恢复记录无效，拒绝修改系统")
	}
	return &s, nil
}
func (h *helper) saveBypassState(s *bypassState) error {
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	return atomicWrite(h.bypassJournalPath(), raw, 0600)
}
func validBypassInterface(i bypassInterface) bool {
	ip, network, e := net.ParseCIDR(i.CIDR)
	address := net.ParseIP(i.Address)
	if e != nil || network.IP.To4() == nil {
		return false
	}
	last := append(net.IP(nil), network.IP.To4()...)
	for index := range last {
		last[index] |= ^network.Mask[index]
	}
	if !network.IP.IsPrivate() || !last.IsPrivate() {
		return false
	}
	return e == nil && ip.To4() != nil && address != nil && address.To4() != nil && address.IsPrivate() && network.Contains(address) && i.Name != "lo" && !regexp.MustCompile(`^(docker\d+|br-[a-fA-F0-9]{12})$`).MatchString(i.Name) && regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(i.Name)
}
func bypassRules(s *bypassState) string {
	_, network, _ := net.ParseCIDR(s.Interface.CIDR)
	match := fmt.Sprintf("iifname %q ip saddr %s", s.Interface.Name, network.String())
	// The capture chain never sees DNS; a dedicated nat chain redirects port 53
	// to the already configured Mihomo DNS listener.
	skip := fmt.Sprintf("%s meta mark != 0 return\n%s fib daddr type local return\n%s ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n%s meta l4proto { tcp, udp } th dport 53 return\n", match, match, match, match)
	var out strings.Builder
	fmt.Fprintf(&out, "create table ip %s { comment \"clash-manager:%s\"; }\n", bypassTable, s.Token)
	if s.Mode == "redir" {
		fmt.Fprintf(&out, "add chain ip %s capture { type nat hook prerouting priority dstnat; policy accept; }\n", bypassTable)
		out.WriteString(prefixBypassRules(skip))
		fmt.Fprintf(&out, "add rule ip %s capture %s meta l4proto tcp redirect to :%d\n", bypassTable, match, s.Port)
	} else {
		fmt.Fprintf(&out, "add chain ip %s capture { type filter hook prerouting priority mangle; policy accept; }\n", bypassTable)
		out.WriteString(prefixBypassRules(skip))
		fmt.Fprintf(&out, "add rule ip %s capture %s meta l4proto { tcp, udp } tproxy to :%d meta mark set 0x434d accept\n", bypassTable, match, s.Port)
	}
	if s.DNSHijack && s.DNSPort > 0 {
		// -110 runs before the dstnat capture chain and after mangle, so the
		// capture chain's port 53 skip still prevents double redirection.
		fmt.Fprintf(&out, "add chain ip %s dns { type nat hook prerouting priority -110; policy accept; }\n", bypassTable)
		fmt.Fprintf(&out, "add rule ip %s dns %s meta l4proto { tcp, udp } th dport 53 redirect to :%d\n", bypassTable, match, s.DNSPort)
	}
	// Forwarding is expressed in an owned chain. Docker's FORWARD policy DROP is
	// handled separately with an owned DOCKER-USER rule.
	fmt.Fprintf(&out, "add chain ip %s forward { type filter hook forward priority -10; policy accept; }\n", bypassTable)
	fmt.Fprintf(&out, "add rule ip %s forward ct state established,related accept\n", bypassTable)
	fmt.Fprintf(&out, "add rule ip %s forward %s accept\n", bypassTable, match)
	fmt.Fprintf(&out, "add rule ip %s forward oifname %q ip daddr %s accept\n", bypassTable, s.Interface.Name, network.String())
	if s.WANInterface != "" {
		fmt.Fprintf(&out, "add chain ip %s postrouting { type nat hook postrouting priority 100; policy accept; }\n", bypassTable)
		fmt.Fprintf(&out, "add rule ip %s postrouting oifname %q ip saddr %s masquerade\n", bypassTable, s.WANInterface, network.String())
	}
	return out.String()
}
func prefixBypassRules(rules string) string {
	out := ""
	for _, line := range strings.Split(strings.TrimSpace(rules), "\n") {
		out += "add rule ip " + bypassTable + " capture " + line + "\n"
	}
	return out
}
func bypassTableOwner(raw []byte) (bool, string, error) {
	var doc struct {
		Items []struct {
			Table *struct {
				Family  string `json:"family"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if e := json.Unmarshal(raw, &doc); e != nil {
		return false, "", e
	}
	if doc.Items == nil {
		return false, "", errors.New("无法核对 nftables 表归属")
	}
	for _, i := range doc.Items {
		if i.Table != nil && i.Table.Family == "ip" && i.Table.Name == bypassTable {
			return true, i.Table.Comment, nil
		}
	}
	return false, "", nil
}
func (h *helper) bypassPreflight(ctx context.Context, body map[string]any) (*bypassState, error) {
	if runtime.GOOS != "linux" && h.bypassSystem == nil {
		return nil, fail(409, "一键接管仅支持具备 nftables 和 iproute2 的 Linux 主机")
	}
	if fileExists(h.bypassStatePathForMonitor()) {
		return nil, fail(409, "请先恢复旧版旁路由记录")
	}
	s, err := h.readBypassState()
	if err != nil {
		return nil, err
	}
	if s != nil {
		return nil, fail(409, "请先停用已有接管配置")
	}
	mode := stringField(body, "mode")
	if mode != "redir" && mode != "tproxy" {
		return nil, fail(400, "接管模式必须为 Redir 或 TProxy")
	}
	var iface *bypassInterface
	for _, i := range h.bypassInterfaces() {
		if i.Name == stringField(body, "interface") && i.Address == stringField(body, "address") && validBypassInterface(i) {
			copy := i
			iface = &copy
			break
		}
	}
	if iface == nil {
		return nil, fail(400, "请选择实际存在的局域网 IPv4 网卡")
	}
	proc := h.bypassProcess()
	if h.readMode() != "managed" || proc == nil {
		return nil, fail(409, "请先启动 Manager 托管内核")
	}
	raw, err := os.ReadFile(h.config.managedConfig)
	if err != nil {
		return nil, err
	}
	if yamlNestedBoolean(string(raw), "tun", "enable", false) {
		return nil, fail(409, "请先关闭 TUN，避免与独立透明接管规则冲突")
	}
	port := yamlInteger(string(raw), mode+"-port", 0)
	if port == 0 {
		if mode == "redir" {
			port = 7895
		} else {
			port = 7896
		}
	}
	if port < 1 || port > 65535 {
		return nil, fail(400, "透明代理端口无效")
	}
	ops := h.bypassOS()
	wan := ""
	ipv6Route := false
	dockerAvailable := false
	if h.bypassSystem != nil {
		// Injected system (tests) opts into each probe explicitly.
		if h.bypassSystem.wan != nil {
			wan = h.bypassSystem.wan(ctx)
		}
		if h.bypassSystem.ipv6Route != nil {
			ipv6Route = h.bypassSystem.ipv6Route(ctx)
		}
		if h.bypassSystem.dockerChain != nil {
			dockerAvailable = h.bypassSystem.dockerChain(ctx)
		}
	} else {
		wan = detectBypassWAN(ctx, ops)
		ipv6Route = hasIPv6DefaultRoute(ctx, ops)
		dockerAvailable = hasDockerUserChain(ctx, ops)
	}
	dnsHijack := true
	if value, ok := body["dnsHijack"].(bool); ok {
		dnsHijack = value
	}
	dnsPort := 0
	if dnsHijack {
		if !yamlNestedBoolean(string(raw), "dns", "enable", false) {
			return nil, fail(409, "接管 DNS 前请先在 DNS 设置中启用 Mihomo DNS")
		}
		if !dnsLANReachable(string(raw)) {
			return nil, fail(409, "DNS 监听地址仅限回环，请改为 0.0.0.0:53 或局域网地址后再接管 DNS")
		}
		dnsPort = dnsListenPort(string(raw))
	}
	warnings := []string{}
	if wan == "" {
		warnings = append(warnings, "未检测到默认路由，已跳过源地址转换")
	} else if wan == iface.Name {
		warnings = append(warnings, "默认路由与接入网卡相同，源地址转换可能不生效")
	}
	if readRPFilter("all") == "1" || readRPFilter(iface.Name) == "1" {
		warnings = append(warnings, "系统启用了严格 rp_filter，跨网卡转发可能被丢弃")
	}
	if ipv6Route {
		warnings = append(warnings, "检测到 IPv6 默认路由，IPv6 流量不会经过接管")
	}
	tables, err := ops.run(ctx, "", "nft", "-j", "list", "tables")
	if err != nil {
		return nil, err
	}
	exists, _, err := bypassTableOwner(tables)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fail(409, "存在同名 nftables 表，拒绝覆盖")
	}
	forward, err := ops.readForward()
	if err != nil {
		return nil, err
	}
	if forward != "0" && forward != "1" {
		return nil, errors.New("无法读取 IPv4 转发状态")
	}
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		return nil, err
	}
	plan := &bypassState{Schema: 2, Token: hex.EncodeToString(token), Mode: mode, Interface: *iface, Port: port, PreviousForward: forward, CorePID: proc.PID, WANInterface: wan, DNSHijack: dnsHijack, DNSPort: dnsPort, DockerAvailable: dockerAvailable, Warnings: warnings}
	if mode == "tproxy" {
		rules, e := ops.run(ctx, "", "ip", "-4", "rule", "show")
		if e != nil {
			return nil, e
		}
		if strings.Contains(string(rules), bypassRoute) || strings.Contains(string(rules), "0x434d") {
			return nil, fail(409, "策略路由编号或标记已被占用")
		}
		routes, e := ops.run(ctx, "", "ip", "-4", "route", "show", "table", bypassRoute)
		if e != nil && !strings.Contains(string(routes), "FIB table does not exist") {
			return nil, e
		}
		if e == nil && strings.TrimSpace(string(routes)) != "" {
			return nil, fail(409, "策略路由表已被占用")
		}
	}
	if _, err = ops.run(ctx, bypassRules(plan), "nft", "--check", "-f", "-"); err != nil {
		return nil, err
	}
	return plan, nil
}
func (h *helper) prepareBypass(ctx context.Context, body map[string]any) (map[string]any, error) {
	h.mu.Lock()
	h.bypassMu.Lock()
	plan, err := h.bypassPreflight(ctx, body)
	h.bypassMu.Unlock()
	h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	// Persisted through the existing validated user-settings transaction. Bind all
	// proxy listeners to the chosen LAN address rather than exposing every NIC.
	return h.updateNetwork(ctx, map[string]any{plan.Mode: map[string]any{"enabled": true, "port": float64(plan.Port)}, "allowLan": true, "bindAddress": plan.Interface.Address})
}
func (h *helper) configureBypass(ctx context.Context, body map[string]any) (map[string]any, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bypassMu.Lock()
	defer h.bypassMu.Unlock()
	s, err := h.bypassPreflight(ctx, body)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(s.Interface.Address, strconv.Itoa(s.Port)), time.Second)
	if err != nil {
		return nil, fail(409, "透明代理端口尚未运行")
	}
	conn.Close()
	result, err := h.installBypassPlan(ctx, s)
	if err != nil {
		return nil, err
	}
	preferences := &bypassPreferences{Schema: 2, Mode: s.Mode, Interface: s.Interface, Enabled: true, KeepEnabled: boolField(body, "keepEnabled"), DNSHijack: s.DNSHijack}
	if err = h.saveBypassPreferences(preferences); err != nil {
		recovery, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return nil, errors.Join(err, h.cleanupBypassLocked(recovery, 0))
	}
	h.bypassRestoreError = ""
	return result, nil
}

func (h *helper) installBypassPlan(ctx context.Context, s *bypassState) (map[string]any, error) {
	var err error
	ops := h.bypassOS()
	// Journal intent before every mutation so a crashed apply is recoverable.
	if err = h.saveBypassState(s); err != nil {
		return nil, err
	}
	rollback := func(cause error) (map[string]any, error) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return nil, errors.Join(cause, h.cleanupBypassLocked(cleanupCtx, 0))
	}
	if s.Mode == "tproxy" {
		s.RouteAdded = true
		if err = h.saveBypassState(s); err != nil {
			return rollback(err)
		}
		if _, err = ops.run(ctx, "", "ip", "-4", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", bypassRoute); err != nil {
			s.RouteAdded = false
			_ = h.saveBypassState(s)
			return rollback(err)
		}
		s.RuleAdded = true
		if err = h.saveBypassState(s); err != nil {
			return rollback(err)
		}
		if _, err = ops.run(ctx, "", "ip", "-4", "rule", "add", "priority", bypassRoute, "fwmark", bypassMark, "lookup", bypassRoute); err != nil {
			s.RuleAdded = false
			_ = h.saveBypassState(s)
			return rollback(err)
		}
	}
	if s.PreviousForward != "1" {
		if err = ops.writeForward("1"); err != nil {
			return rollback(err)
		}
	}
	s.TableAdded = true
	if err = h.saveBypassState(s); err != nil {
		return rollback(err)
	}
	if _, err = ops.run(ctx, bypassRules(s), "nft", "-f", "-"); err != nil {
		return rollback(err)
	}
	if s.DockerAvailable {
		s.DockerRule = true
		if err = h.saveBypassState(s); err != nil {
			return rollback(err)
		}
		if err = ensureDockerForward(ctx, ops, s); err != nil {
			s.DockerRule = false
			_ = h.saveBypassState(s)
			return rollback(err)
		}
	}
	return map[string]any{"ok": true, "mode": s.Mode, "interface": s.Interface, "port": s.Port, "wan": s.WANInterface, "dnsHijack": s.DNSHijack, "dnsPort": s.DNSPort, "nat": s.WANInterface != "", "dockerRule": s.DockerRule, "warnings": s.Warnings}, nil
}
func (h *helper) cleanupBypassLocked(ctx context.Context, pid int) error {
	s, err := h.readBypassState()
	if err != nil || s == nil {
		return err
	}
	if pid != 0 && pid != s.CorePID {
		return nil
	}
	ops := h.bypassOS()
	if err = removeDockerForward(ctx, ops, s); err != nil {
		return err
	}
	if s.DockerRule {
		s.DockerRule = false
		if err = h.saveBypassState(s); err != nil {
			return err
		}
	}
	raw, err := ops.run(ctx, "", "nft", "-j", "list", "tables")
	if err != nil {
		return err
	}
	exists, owner, err := h.bypassOwner(ctx, raw)
	if err != nil {
		return err
	}
	if exists {
		if owner != "clash-manager:"+s.Token {
			return errors.New("接管表归属已变化，拒绝删除")
		}
		if _, err = ops.run(ctx, "", "nft", "delete", "table", "ip", bypassTable); err != nil {
			return err
		}
	}
	if s.RuleAdded {
		output, readErr := ops.run(ctx, "", "ip", "-4", "rule", "show")
		if readErr != nil {
			return readErr
		}
		for _, line := range strings.Split(string(output), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), bypassRoute+":") {
				continue
			}
			if !strings.Contains(line, "fwmark "+bypassMark) || !strings.Contains(line, "lookup "+bypassRoute) {
				return errors.New("策略路由归属已变化，拒绝删除")
			}
			if _, err = ops.run(ctx, "", "ip", "-4", "rule", "del", "priority", bypassRoute, "fwmark", bypassMark, "lookup", bypassRoute); err != nil {
				return err
			}
		}
		s.RuleAdded = false
		if err = h.saveBypassState(s); err != nil {
			return err
		}
	}
	if s.RouteAdded {
		output, readErr := ops.run(ctx, "", "ip", "-4", "route", "show", "table", bypassRoute)
		if readErr != nil && !strings.Contains(string(output), "FIB table does not exist") {
			return readErr
		}
		route := strings.TrimSpace(string(output))
		if readErr == nil && route != "" {
			if strings.Contains(route, "\n") || (!strings.HasPrefix(route, "local default ") && !strings.HasPrefix(route, "local 0.0.0.0/0 ")) || !strings.Contains(route, "dev lo") {
				return errors.New("路由表归属已变化，拒绝删除")
			}
			if _, err = ops.run(ctx, "", "ip", "-4", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", bypassRoute); err != nil {
				return err
			}
		}
		s.RouteAdded = false
		if err = h.saveBypassState(s); err != nil {
			return err
		}
	}
	current, err := ops.readForward()
	if err != nil {
		return err
	}
	if current == "1" && s.PreviousForward == "0" {
		if err = ops.writeForward("0"); err != nil {
			return err
		}
	}
	return os.Remove(h.bypassJournalPath())
}
func (h *helper) cleanupBypass(ctx context.Context, pid int) error {
	h.bypassMu.Lock()
	defer h.bypassMu.Unlock()
	return h.cleanupBypassLocked(ctx, pid)
}
func (h *helper) bypassManagedStatus(ctx context.Context, rules ...[]byte) map[string]any {
	h.bypassMu.Lock()
	defer h.bypassMu.Unlock()
	s, e := h.readBypassState()
	if e != nil {
		return h.attachBypassPreferences(map[string]any{"active": false, "error": e.Error()})
	}
	if s == nil {
		return h.attachBypassPreferences(map[string]any{"active": false})
	}
	status := map[string]any{"active": true, "mode": s.Mode, "interface": s.Interface, "port": s.Port, "wan": s.WANInterface, "dnsHijack": s.DNSHijack, "dnsPort": s.DNSPort, "dockerRule": s.DockerRule, "rulesPresent": nil}
	if len(rules) > 0 {
		exists, owner, err := h.bypassOwner(ctx, rules[0])
		switch {
		case err != nil:
			status["error"] = "暂时无法核验接管规则归属，请刷新或查看规则明细"
		case !exists:
			status["rulesPresent"] = false
			status["error"] = "接管规则已不存在，请停用恢复后重新配置"
		case owner != "clash-manager:"+s.Token:
			status["rulesPresent"] = false
			status["error"] = "接管规则归属与恢复记录不一致，为避免误删已保留规则"
		default:
			status["rulesPresent"] = true
		}
	}
	return h.attachBypassPreferences(status)
}
