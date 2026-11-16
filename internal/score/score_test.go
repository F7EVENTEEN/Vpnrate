package score

import "testing"

func TestTrust(t *testing.T) {
	cases := []struct {
		name string
		in   TrustInput
		want int
	}{
		{"clean residential", TrustInput{Country: "DE"}, 100},
		{"datacenter vpn", TrustInput{Country: "NL", Datacenter: true, VPN: true}, 70},
		{"tor in unsupported country", TrustInput{Country: "RU", Tor: true}, 10},
		{"unsupported country lowercase", TrustInput{Country: "ru"}, 60},
		{"leaks", TrustInput{Country: "US", DNSLeak: true, UDPLeak: true, IPv6Leak: true}, 55},
		{"timezone mismatch", TrustInput{Country: "US", TZMismatch: true}, 90},
		{"webrtc leak counts once with udp leak", TrustInput{Country: "US", UDPLeak: true, WebRTCLeak: true}, 85},
		{"webrtc leak alone", TrustInput{Country: "US", WebRTCLeak: true}, 85},
		{"floor at zero", TrustInput{
			Country: "CN", Tor: true, Abuser: true, Datacenter: true, VPN: true, Proxy: true,
			DNSLeak: true, UDPLeak: true, IPv6Leak: true, TZMismatch: true,
		}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ComputeTrust(c.in)
			if got.Score != c.want {
				t.Fatalf("score = %d, want %d (penalties %+v)", got.Score, c.want, got.Penalties)
			}
			if got.Grade != Grade(c.want) {
				t.Fatalf("grade = %q, want %q", got.Grade, Grade(c.want))
			}
		})
	}
}

func TestTrustPenaltiesExplained(t *testing.T) {
	got := ComputeTrust(TrustInput{Country: "NL", Datacenter: true, VPN: true})
	if len(got.Penalties) != 2 {
		t.Fatalf("want 2 penalties, got %+v", got.Penalties)
	}
	for _, p := range got.Penalties {
		if p.Code == "" || p.Reason == "" || p.Points <= 0 {
			t.Fatalf("penalty not explained: %+v", p)
		}
	}
}

func TestGradeBoundaries(t *testing.T) {
	cases := map[int]string{
		100: GradeExcellent, 85: GradeExcellent, 84: GradeGood, 70: GradeGood,
		69: GradeSuspicious, 50: GradeSuspicious, 49: GradeHighRisk, 0: GradeHighRisk,
	}
	for s, want := range cases {
		if got := Grade(s); got != want {
			t.Errorf("Grade(%d) = %q, want %q", s, got, want)
		}
	}
}

func TestStability(t *testing.T) {
	cases := []struct {
		name string
		in   StabilityInput
		want int
	}{
		{"perfect day", StabilityInput{UptimePct: 100, P95LatencyMs: 40}, 100},
		{"1% downtime and 2 outages", StabilityInput{UptimePct: 99, Outages: 2, P95LatencyMs: 40}, 92},
		{"tunnel drops", StabilityInput{UptimePct: 100, TunnelDrops: 4}, 96},
		{"slow p95", StabilityInput{UptimePct: 100, P95LatencyMs: 350}, 95},
		{"very slow p95", StabilityInput{UptimePct: 100, P95LatencyMs: 900}, 90},
		{"outage penalty capped", StabilityInput{UptimePct: 100, Outages: 100}, 70},
		{"tunnel penalty capped", StabilityInput{UptimePct: 100, TunnelDrops: 100}, 80},
		{"floor at zero", StabilityInput{UptimePct: 10, Outages: 50, TunnelDrops: 50, P95LatencyMs: 2000}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ComputeStability(c.in)
			if got.Score != c.want {
				t.Fatalf("score = %d, want %d (penalties %+v)", got.Score, c.want, got.Penalties)
			}
		})
	}
}
