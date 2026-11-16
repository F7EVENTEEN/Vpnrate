// Package score turns raw observations into the two open, explainable ratings:
// Trust (how "clean" the connection looks) and Stability (how reliable it is).
package score

import "strings"

const (
	GradeExcellent  = "excellent"
	GradeGood       = "good"
	GradeSuspicious = "suspicious"
	GradeHighRisk   = "high_risk"
)

// UnsupportedCountries is an approximate list of countries where major AI
// services (Claude, ChatGPT, Gemini) are not officially available.
var UnsupportedCountries = map[string]bool{
	"RU": true, "BY": true, "CN": true, "HK": true, "MO": true,
	"IR": true, "KP": true, "SY": true, "CU": true,
}

type Penalty struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
	Points int    `json:"points"`
}

type TrustInput struct {
	Country    string
	Datacenter bool
	VPN        bool
	Proxy      bool
	Tor        bool
	Abuser     bool
	DNSLeak    bool
	UDPLeak    bool
	WebRTCLeak bool
	IPv6Leak   bool
	TZMismatch bool
}

type Trust struct {
	Score     int       `json:"score"`
	Grade     string    `json:"grade"`
	Penalties []Penalty `json:"penalties"`
}

func ComputeTrust(in TrustInput) Trust {
	var ps []Penalty
	add := func(cond bool, code, reason string, pts int) {
		if cond {
			ps = append(ps, Penalty{code, reason, pts})
		}
	}
	add(in.Tor, "tor", "IP is a Tor exit node", 50)
	add(UnsupportedCountries[strings.ToUpper(in.Country)], "unsupported_country",
		"exit country is not supported by major AI services", 40)
	add(in.Abuser, "abuser", "IP has abuse / blacklist records", 25)
	add(in.Datacenter, "datacenter", "IP belongs to a datacenter or hosting provider", 20)
	add(in.VPN, "vpn", "IP is a known VPN exit", 10)
	add(in.Proxy, "proxy", "IP is a known proxy", 10)
	add(in.DNSLeak, "dns_leak", "DNS resolver is in a different country than the exit IP", 15)
	// A UDP leak and a browser WebRTC leak expose the same thing, so count it once.
	add(in.UDPLeak || in.WebRTCLeak, "webrtc_leak", "UDP/WebRTC reveals an IP other than the exit IP", 15)
	add(in.IPv6Leak, "ipv6_leak", "IPv6 traffic bypasses the tunnel", 15)
	add(in.TZMismatch, "timezone", "system timezone does not match the IP location", 10)

	s := 100
	for _, p := range ps {
		s -= p.Points
	}
	s = max(s, 0)
	return Trust{Score: s, Grade: Grade(s), Penalties: ps}
}

func Grade(s int) string {
	switch {
	case s >= 85:
		return GradeExcellent
	case s >= 70:
		return GradeGood
	case s >= 50:
		return GradeSuspicious
	}
	return GradeHighRisk
}

type StabilityInput struct {
	UptimePct    float64
	Outages      int
	TunnelDrops  int
	P95LatencyMs float64
}

type Stability struct {
	Score     int       `json:"score"`
	Penalties []Penalty `json:"penalties"`
}

func ComputeStability(in StabilityInput) Stability {
	var ps []Penalty
	if down := 100 - in.UptimePct; down > 0 {
		if pts := int(down*2 + 0.5); pts > 0 {
			ps = append(ps, Penalty{"downtime", "time without internet", pts})
		}
	}
	if in.Outages > 0 {
		ps = append(ps, Penalty{"outages", "connection drops", min(in.Outages*3, 30)})
	}
	if in.TunnelDrops > 0 {
		ps = append(ps, Penalty{"tunnel_drops", "VPN tunnel went down", min(in.TunnelDrops, 20)})
	}
	switch {
	case in.P95LatencyMs > 800:
		ps = append(ps, Penalty{"latency", "p95 latency above 800 ms", 10})
	case in.P95LatencyMs > 300:
		ps = append(ps, Penalty{"latency", "p95 latency above 300 ms", 5})
	}
	s := 100
	for _, p := range ps {
		s -= p.Points
	}
	return Stability{Score: max(s, 0), Penalties: ps}
}
