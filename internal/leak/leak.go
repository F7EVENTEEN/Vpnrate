// Package leak detects traffic that escapes the tunnel: DNS resolvers in
// another country, UDP (and thus WebRTC) leaving via a different IP, IPv6
// bypassing an IPv4-only VPN, and a system timezone that contradicts the IP.
package leak

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/F7EVENTEEN/Vpnrate/internal/ipinfo"
	"github.com/F7EVENTEEN/Vpnrate/internal/publicip"
	"github.com/F7EVENTEEN/Vpnrate/internal/score"
)

type Status string

const (
	OK      Status = "ok"
	Leak    Status = "leak"
	Unknown Status = "unknown"
)

type Verdict struct {
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
	IP     string `json:"ip,omitempty"` // the IP that was observed (resolver, UDP exit...)
}

// --- DNS ---------------------------------------------------------------

// ResolverIP asks Akamai's whoami service, which answers with the address
// of the recursive resolver that queried it — i.e. who really resolves
// your DNS on the internet.
func ResolverIP(ctx context.Context, r *net.Resolver) (netip.Addr, error) {
	if r == nil {
		r = net.DefaultResolver
	}
	ips, err := r.LookupNetIP(ctx, "ip4", "whoami.akamai.net")
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, errors.New("no answer")
	}
	return ips[0].Unmap(), nil
}

// publicDNS are anycast resolver networks: they answer from the nearest
// PoP, which is often in a neighbouring country and reveals nothing about you.
var publicDNS = map[int]string{
	15169: "Google", 13335: "Cloudflare", 19281: "Quad9", 42: "Quad9 (PCH)",
	36692: "OpenDNS", 212772: "AdGuard", 34939: "NextDNS", 397215: "NextDNS",
}

func JudgeDNS(exit, resolver ipinfo.Info) Verdict {
	if exit.Country == "" || resolver.Country == "" {
		return Verdict{Status: Unknown, IP: resolver.IP}
	}
	if name, ok := publicDNS[resolver.ASN]; ok && exit.Country != resolver.Country &&
		!score.UnsupportedCountries[resolver.Country] {
		return Verdict{Status: OK, IP: resolver.IP,
			Detail: fmt.Sprintf("public DNS (%s) answering from %s", name, resolver.Country)}
	}
	if exit.Country != resolver.Country {
		return Verdict{Status: Leak, IP: resolver.IP,
			Detail: fmt.Sprintf("DNS resolver %s (%s, AS%d) is in %s, exit IP is in %s",
				resolver.IP, resolver.Org, resolver.ASN, resolver.Country, exit.Country)}
	}
	return Verdict{Status: OK, IP: resolver.IP,
		Detail: fmt.Sprintf("DNS resolver %s is in %s", resolver.IP, resolver.Country)}
}

// --- UDP / WebRTC ---------------------------------------------------------

func JudgeUDP(httpIP, stunIP netip.Addr) Verdict {
	if !httpIP.IsValid() || !stunIP.IsValid() {
		return Verdict{Status: Unknown}
	}
	if httpIP != stunIP {
		return Verdict{Status: Leak, IP: stunIP.String(),
			Detail: fmt.Sprintf("UDP leaves via %s, but HTTP via %s", stunIP, httpIP)}
	}
	return Verdict{Status: OK, IP: stunIP.String()}
}

// JudgeWebRTC checks the ICE candidates a browser gathered: any public
// address that is not one of our exit IPs is visible to websites.
func JudgeWebRTC(exits, candidates []netip.Addr) Verdict {
	for _, c := range candidates {
		c = c.Unmap()
		if !publicip.IsPublic(c) {
			continue
		}
		known := false
		for _, e := range exits {
			if e == c {
				known = true
			}
		}
		if !known {
			return Verdict{Status: Leak, IP: c.String(),
				Detail: fmt.Sprintf("browser WebRTC exposes %s", c)}
		}
	}
	return Verdict{Status: OK}
}

// --- IPv6 ------------------------------------------------------------------

func JudgeIPv6(v4, v6 *ipinfo.Info) Verdict {
	if v6 == nil {
		return Verdict{Status: OK, Detail: "no IPv6 connectivity"}
	}
	if v4 == nil || v4.Country == "" || v6.Country == "" {
		return Verdict{Status: Unknown, IP: v6.IP}
	}
	if v4.Country != v6.Country || (v4.ASN != 0 && v6.ASN != 0 && v4.ASN != v6.ASN) {
		return Verdict{Status: Leak, IP: v6.IP,
			Detail: fmt.Sprintf("IPv6 exits via %s (AS%d, %s), IPv4 via AS%d, %s",
				v6.IP, v6.ASN, v6.Country, v4.ASN, v4.Country)}
	}
	return Verdict{Status: OK, IP: v6.IP}
}

// --- Timezone ----------------------------------------------------------------

func JudgeTimezone(ipTZ string, local *time.Location, now time.Time) Verdict {
	if ipTZ == "" || local == nil {
		return Verdict{Status: Unknown}
	}
	loc, err := time.LoadLocation(ipTZ)
	if err != nil {
		return Verdict{Status: Unknown, Detail: err.Error()}
	}
	_, a := now.In(loc).Zone()
	_, b := now.In(local).Zone()
	diff := time.Duration(a-b) * time.Second
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Hour {
		return Verdict{Status: Leak,
			Detail: fmt.Sprintf("system clock is UTC%s, IP location (%s) is UTC%s", offset(b), ipTZ, offset(a))}
	}
	return Verdict{Status: OK, Detail: ipTZ}
}

func offset(sec int) string {
	sign := "+"
	if sec < 0 {
		sign, sec = "-", -sec
	}
	if m := sec % 3600 / 60; m != 0 {
		return fmt.Sprintf("%s%d:%02d", sign, sec/3600, m)
	}
	return fmt.Sprintf("%s%d", sign, sec/3600)
}
