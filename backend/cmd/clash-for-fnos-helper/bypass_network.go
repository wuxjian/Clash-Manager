package main

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
)

// detectBypassWAN reads the IPv4 default route and returns its device.
func detectBypassWAN(ctx context.Context, ops *bypassSystem) string {
	out, err := ops.run(ctx, "", "ip", "-4", "route", "show", "default")
	if err != nil {
		return ""
	}
	return defaultRouteDevice(string(out))
}

func defaultRouteDevice(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for index, field := range fields {
			if field == "dev" && index+1 < len(fields) {
				return fields[index+1]
			}
		}
	}
	return ""
}

// dnsListenPort returns the port of dns.listen, defaulting to 53.
func dnsListenPort(raw string) int {
	listen := strings.TrimSpace(yamlNestedString(raw, "dns", "listen", ""))
	if listen == "" {
		return 53
	}
	if _, port, err := net.SplitHostPort(listen); err == nil {
		if value, parseErr := strconv.Atoi(port); parseErr == nil && value > 0 {
			return value
		}
	}
	if value, err := strconv.Atoi(listen); err == nil && value > 0 {
		return value
	}
	return 53
}

func readRPFilter(name string) string {
	if name == "" {
		name = "all"
	}
	body, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + name + "/rp_filter")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func hasIPv6DefaultRoute(ctx context.Context, ops *bypassSystem) bool {
	out, err := ops.run(ctx, "", "ip", "-6", "route", "show", "default")
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// hasDockerUserChain reports whether iptables exposes Docker's supported
// insertion point for forwarded traffic.
func hasDockerUserChain(ctx context.Context, ops *bypassSystem) bool {
	if _, err := ops.run(ctx, "", "iptables", "-t", "filter", "-S", "DOCKER-USER"); err != nil {
		return false
	}
	return true
}

func dockerForwardArgs(action string, s *bypassState) []string {
	_, network, _ := net.ParseCIDR(s.Interface.CIDR)
	return []string{
		"-t", "filter", action, "DOCKER-USER",
		"-i", s.Interface.Name, "-s", network.String(),
		"-m", "comment", "--comment", "clash-manager-bypass",
		"-j", "ACCEPT",
	}
}

func ensureDockerForward(ctx context.Context, ops *bypassSystem, s *bypassState) error {
	if !s.DockerAvailable {
		return nil
	}
	_, err := ops.run(ctx, "", "iptables", dockerForwardArgs("-I", s)...)
	return err
}

func removeDockerForward(ctx context.Context, ops *bypassSystem, s *bypassState) error {
	if !s.DockerRule {
		return nil
	}
	_, err := ops.run(ctx, "", "iptables", dockerForwardArgs("-D", s)...)
	if err == nil {
		return nil
	}
	// The rule may already be gone; only report an error when our rule still
	// appears in the chain.
	out, listErr := ops.run(ctx, "", "iptables", "-t", "filter", "-S", "DOCKER-USER")
	if listErr != nil || !strings.Contains(string(out), "clash-manager-bypass") {
		return nil
	}
	return err
}
