// Package netif lists network interfaces and recognises VPN tunnels.
package netif

import (
	"regexp"
	"strings"
)

// IANA ifType values used by Windows.
const (
	ifTypePPP    = 23
	ifTypeTunnel = 131
)

type Iface struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Type        uint32 `json:"-"`
}

func (i Iface) Key() string { return i.Name }

var tunnelWords = []string{
	"wireguard", "wintun", "tap-windows", "tap-win32", "openvpn", "amnezia",
	"outline", "sing-box", "sing-tun", "hiddify", "v2ray", "xray", "clash",
	"nekoray", "tailscale", "zerotier", "protonvpn", "nordlynx", "mullvad",
	"expressvpn", "surfshark", "windscribe", "forticlient", "anyconnect",
	"globalprotect", "softether", "pptp", "l2tp", "ikev2", "tunnel",
}

// Unix-style tunnel names: tun0, utun3, wg0, ppp0, tap1.
var unixTunnel = regexp.MustCompile(`^(tun|utun|wg|ppp|tap|ipsec)\d+$`)

func IsTunnel(i Iface) bool {
	s := strings.ToLower(i.Name + " " + i.Description)
	// Windows' built-in IPv6 transition adapters report ifType 131 too.
	for _, w := range []string{"loopback", "teredo", "isatap", "6to4", "ip-https"} {
		if strings.Contains(s, w) {
			return false
		}
	}
	if i.Type == ifTypeTunnel || i.Type == ifTypePPP {
		return true
	}
	if unixTunnel.MatchString(strings.ToLower(i.Name)) {
		return true
	}
	for _, w := range tunnelWords {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// Tunnels returns the up interfaces that look like VPN tunnels.
func Tunnels() ([]Iface, error) {
	all, err := List()
	if err != nil {
		return nil, err
	}
	var out []Iface
	for _, i := range all {
		if IsTunnel(i) {
			out = append(out, i)
		}
	}
	return out, nil
}
