package main

import (
	"context"
	"net"
	"strings"
)

// bypassLANProbe reports the information needed to point client devices at
// the NAS without changing any network state.
func (h *helper) bypassLANProbe(ctx context.Context, _ map[string]any) (map[string]any, error) {
	ops := h.bypassOS()
	out, _ := ops.run(ctx, "", "ip", "-4", "route", "show", "default")
	return map[string]any{
		"ok":        true,
		"gateway":   defaultRouteGateway(string(out)),
		"localDHCP": dhcpPortInUse(),
	}, nil
}

func defaultRouteGateway(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for index, field := range fields {
			if field == "via" && index+1 < len(fields) {
				return fields[index+1]
			}
		}
	}
	return ""
}

// dhcpPortInUse reports whether something already serves DHCP on this host.
func dhcpPortInUse() bool {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:67")
	if err != nil {
		return true
	}
	conn.Close()
	return false
}
