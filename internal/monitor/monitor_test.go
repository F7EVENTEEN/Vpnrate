package monitor

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/F7EVENTEEN/Vpn_rate_agent/internal/ipinfo"
	"github.com/F7EVENTEEN/Vpn_rate_agent/internal/leak"
	"github.com/F7EVENTEEN/Vpn_rate_agent/internal/netif"
	"github.com/F7EVENTEEN/Vpn_rate_agent/internal/store"
)

type fake struct {
	now      time.Time
	probeOK  bool
	v4       string
	stun     string
	resolver string
	tunnels  []netif.Iface
	infos    map[string]ipinfo.Info
}

func newFake() *fake {
	return &fake{
		now:      time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC),
		probeOK:  true,
		v4:       "203.0.113.9",
		stun:     "203.0.113.9",
		resolver: "172.68.1.1",
		tunnels:  []netif.Iface{{Name: "wg0", Description: "WireGuard Tunnel"}},
		infos: map[string]ipinfo.Info{
			"203.0.113.9":  {IP: "203.0.113.9", Country: "NL", ASN: 14061, Datacenter: true, VPN: true, Timezone: "Europe/Amsterdam"},
			"198.51.100.4": {IP: "198.51.100.4", Country: "DE", ASN: 3320, Timezone: "Europe/Berlin"},
			"172.68.1.1":   {IP: "172.68.1.1", Country: "NL", ASN: 13335},
			"95.167.1.1":   {IP: "95.167.1.1", Country: "RU", ASN: 12389},
		},
	}
}

func (f *fake) deps() Deps {
	amsterdam, _ := time.LoadLocation("Europe/Amsterdam")
	return Deps{
		Probe: func(context.Context) (bool, time.Duration) { return f.probeOK, 20 * time.Millisecond },
		PublicV4: func(context.Context) (netip.Addr, error) {
			if f.v4 == "" {
				return netip.Addr{}, errors.New("offline")
			}
			return netip.MustParseAddr(f.v4), nil
		},
		PublicV6: func(context.Context) (netip.Addr, error) { return netip.Addr{}, errors.New("no ipv6") },
		Lookup: func(_ context.Context, ip string) (ipinfo.Info, error) {
			in, ok := f.infos[ip]
			if !ok {
				return ipinfo.Info{}, errors.New("unknown")
			}
			return in, nil
		},
		STUN: func(context.Context) (netip.Addr, error) {
			return netip.MustParseAddr(f.stun), nil
		},
		DNSResolver: func(context.Context) (netip.Addr, error) {
			return netip.MustParseAddr(f.resolver), nil
		},
		Tunnels: func() ([]netif.Iface, error) { return f.tunnels, nil },
		Now:     func() time.Time { return f.now },
		LocalTZ: amsterdam,
	}
}

func newMonitor(t *testing.T, f *fake) (*Monitor, *[]store.Event) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := New(f.deps(), st)
	var got []store.Event
	m.Subscribe(func(e store.Event) { got = append(got, e) })
	return m, &got
}

func kinds(evs []store.Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

func has(evs []store.Event, kind string) bool {
	for _, e := range evs {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func TestOutageEvents(t *testing.T) {
	f := newFake()
	m, evs := newMonitor(t, f)
	ctx := context.Background()
	m.Tick(ctx)
	f.probeOK = false
	for i := 0; i < 3; i++ {
		f.now = f.now.Add(5 * time.Second)
		m.Tick(ctx)
	}
	if m.Status().Online {
		t.Fatal("should be offline")
	}
	f.probeOK = true
	f.now = f.now.Add(5 * time.Second)
	m.Tick(ctx)
	if !m.Status().Online {
		t.Fatal("should be back online")
	}
	if !has(*evs, store.KindOffline) || !has(*evs, store.KindOnline) {
		t.Fatalf("want offline+online events, got %v", kinds(*evs))
	}
	if m.Status().Outages24h != 1 {
		t.Fatalf("outages24h = %d", m.Status().Outages24h)
	}
}

func TestCheckIPComputesTrust(t *testing.T) {
	f := newFake()
	m, evs := newMonitor(t, f)
	m.Tick(context.Background())
	m.CheckIP(context.Background())
	st := m.Status()
	if st.PublicV4 != "203.0.113.9" || st.Exit == nil || st.Exit.Country != "NL" {
		t.Fatalf("exit not filled: %+v", st)
	}
	if st.Leaks.DNS.Status != leak.OK || st.Leaks.UDP.Status != leak.OK || st.Leaks.Timezone.Status != leak.OK {
		t.Fatalf("no leaks expected: %+v", st.Leaks)
	}
	if st.Trust.Score != 70 {
		t.Fatalf("trust = %d, want 70 (%+v)", st.Trust.Score, st.Trust.Penalties)
	}
	if !st.VPNActive {
		t.Fatal("tunnel present, vpn should be active")
	}
	if has(*evs, store.KindIPChanged) {
		t.Fatal("first IP is not a change")
	}

	f.v4, f.stun = "198.51.100.4", "198.51.100.4"
	m.CheckIP(context.Background())
	if !has(*evs, store.KindIPChanged) {
		t.Fatalf("want ip_changed, got %v", kinds(*evs))
	}
}

func TestLeaksDetected(t *testing.T) {
	f := newFake()
	f.stun = "95.167.1.1"
	f.resolver = "95.167.1.1"
	m, evs := newMonitor(t, f)
	m.Tick(context.Background())
	m.CheckIP(context.Background())
	st := m.Status()
	if st.Leaks.UDP.Status != leak.Leak || st.Leaks.DNS.Status != leak.Leak {
		t.Fatalf("want udp+dns leaks: %+v", st.Leaks)
	}
	if st.Trust.Score != 40 {
		t.Fatalf("trust = %d, want 40", st.Trust.Score)
	}
	if !has(*evs, store.KindLeak) {
		t.Fatalf("want leak event, got %v", kinds(*evs))
	}
	// Same leak on the next check must not spam a second event.
	n := len(*evs)
	m.CheckIP(context.Background())
	if len(*evs) != n {
		t.Fatalf("repeated leak must not re-notify: %v", kinds(*evs))
	}
}

func TestTunnelDown(t *testing.T) {
	f := newFake()
	m, evs := newMonitor(t, f)
	m.Tick(context.Background())
	f.tunnels = nil
	f.now = f.now.Add(5 * time.Second)
	m.Tick(context.Background())
	if !has(*evs, store.KindVPNDown) {
		t.Fatalf("want vpn_down, got %v", kinds(*evs))
	}
	if m.Status().VPNActive {
		t.Fatal("vpn should be inactive")
	}
	f.tunnels = []netif.Iface{{Name: "wg0", Description: "WireGuard Tunnel"}}
	f.now = f.now.Add(5 * time.Second)
	m.Tick(context.Background())
	if !has(*evs, store.KindVPNUp) {
		t.Fatalf("want vpn_up, got %v", kinds(*evs))
	}
}

func TestBrowserWebRTC(t *testing.T) {
	f := newFake()
	m, _ := newMonitor(t, f)
	m.Tick(context.Background())
	m.CheckIP(context.Background())
	m.SetBrowserWebRTC([]string{"192.168.1.10", "95.167.1.1"})
	st := m.Status()
	if st.Leaks.WebRTC.Status != leak.Leak {
		t.Fatalf("want webrtc leak: %+v", st.Leaks.WebRTC)
	}
	if st.Trust.Score != 55 {
		t.Fatalf("trust = %d, want 55", st.Trust.Score)
	}
}

// Seen live: the dashboard posted its candidates right after a restart,
// before the first IP check, and our own exit IP was flagged as a leak.
func TestBrowserWebRTCBeforeFirstIPCheck(t *testing.T) {
	f := newFake()
	m, evs := newMonitor(t, f)
	m.SetBrowserWebRTC([]string{"203.0.113.9"})
	if st := m.Status(); st.Leaks.WebRTC.Status != leak.Unknown {
		t.Fatalf("without a known exit IP the verdict must wait: %+v", st.Leaks.WebRTC)
	}
	m.CheckIP(context.Background())
	if st := m.Status(); st.Leaks.WebRTC.Status != leak.OK {
		t.Fatalf("exit IP as candidate is fine: %+v", st.Leaks.WebRTC)
	}
	if has(*evs, store.KindLeak) || has(*evs, store.KindLeakFixed) {
		t.Fatalf("no leak events expected, got %v", kinds(*evs))
	}
}

func TestMinuteSamplesAggregate(t *testing.T) {
	f := newFake()
	m, _ := newMonitor(t, f)
	for i := 0; i < 12; i++ {
		f.probeOK = i != 3
		m.Tick(context.Background())
		f.now = f.now.Add(5 * time.Second)
	}
	m.Tick(context.Background()) // crosses into the next minute and flushes
	samples := m.Samples(1)
	if len(samples) != 1 || samples[0].Probes != 12 || samples[0].OK != 11 {
		t.Fatalf("want one flushed minute with 11/12 ok, got %+v", samples)
	}
}
