package monitor

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/F7EVENTEEN/Vpnrate/internal/ipinfo"
	"github.com/F7EVENTEEN/Vpnrate/internal/leak"
	"github.com/F7EVENTEEN/Vpnrate/internal/netif"
	"github.com/F7EVENTEEN/Vpnrate/internal/store"
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

func TestProxyMode(t *testing.T) {
	f := newFake()
	f.tunnels = nil
	f.resolver = "95.167.1.1" // system DNS goes to the ISP, as it does in proxy mode
	m, evs := newMonitor(t, f)
	proxy := "127.0.0.1:10809"
	m.d.Proxy = func() string { return proxy }
	m.Tick(context.Background())
	m.CheckIP(context.Background())
	st := m.Status()
	if !st.VPNActive || st.Proxy != proxy {
		t.Fatalf("proxy should count as an active VPN route: %+v", st)
	}
	if st.Leaks.DNS.Status != leak.Unknown {
		t.Fatalf("in proxy mode the browser's DNS is resolved by the proxy, so no DNS verdict: %+v", st.Leaks.DNS)
	}
	if st.Trust.Score != 70 {
		t.Fatalf("trust = %d, want 70 (no dns penalty in proxy mode)", st.Trust.Score)
	}
	proxy = ""
	f.now = f.now.Add(5 * time.Second)
	m.Tick(context.Background())
	if !has(*evs, store.KindVPNDown) || m.Status().VPNActive {
		t.Fatalf("disabling the proxy must be a vpn_down: %v", kinds(*evs))
	}
}

func TestProfiles(t *testing.T) {
	f := newFake()
	m, _ := newMonitor(t, f)
	ctx := context.Background()
	tick := func(ok bool) {
		f.probeOK = ok
		m.Tick(ctx)
		f.now = f.now.Add(5 * time.Second)
	}
	// 2 minutes on the NL datacenter VPN, with one outage.
	m.Tick(ctx)
	m.CheckIP(ctx)
	for i := 0; i < 24; i++ {
		tick(i < 6 || i > 9)
	}
	// Switch to the DE residential exit for 1 minute.
	f.v4, f.stun = "198.51.100.4", "198.51.100.4"
	m.CheckIP(ctx)
	for i := 0; i < 13; i++ {
		tick(true)
	}
	ps := m.Profiles(7)
	if len(ps) != 2 {
		t.Fatalf("want 2 profiles, got %+v", ps)
	}
	byKey := map[string]ProfileStats{}
	for _, p := range ps {
		byKey[p.Key] = p
	}
	nl, de := byKey["AS14061-NL"], byKey["AS3320-DE"]
	if nl.Outages != 1 || nl.Trust != 70 || nl.Minutes < 2 || nl.Uptime >= 100 {
		t.Fatalf("NL profile wrong: %+v", nl)
	}
	if de.Outages != 0 || de.Trust != 100 || !de.Current || de.Uptime != 100 {
		t.Fatalf("DE profile wrong: %+v", de)
	}
	if nl.Current {
		t.Fatal("only one profile is current")
	}
	if ps[0].Key != "AS3320-DE" {
		t.Fatalf("current profile should be listed first: %+v", ps)
	}
}

func TestProfilesSurviveRestart(t *testing.T) {
	f := newFake()
	dir := t.TempDir()
	st, _ := store.Open(dir)
	m := New(f.deps(), st)
	m.Tick(context.Background())
	m.CheckIP(context.Background())
	for i := 0; i < 13; i++ {
		f.now = f.now.Add(5 * time.Second)
		m.Tick(context.Background())
	}
	st2, _ := store.Open(dir)
	m2 := New(f.deps(), st2)
	ps := m2.Profiles(7)
	if len(ps) != 1 || ps[0].Trust != 70 || ps[0].Label == "" {
		t.Fatalf("profile metadata must be persisted: %+v", ps)
	}
}

// Seen live: sing-box runs a TUN adapter and sets the system proxy at once.
// The tunnel carries system DNS, so the DNS check stays meaningful.
func TestTunnelPlusProxyKeepsDNSCheck(t *testing.T) {
	f := newFake()
	f.resolver = "95.167.1.1"
	m, _ := newMonitor(t, f)
	m.d.Proxy = func() string { return "127.0.0.1:10808" }
	m.Tick(context.Background())
	m.CheckIP(context.Background())
	if st := m.Status(); st.Leaks.DNS.Status != leak.Leak {
		t.Fatalf("with a tunnel up, a foreign ISP resolver is a real leak: %+v", st.Leaks.DNS)
	}
}

// At logon the agent may start before Wi-Fi or the VPN is up. That wait is
// not an outage: counting starts with the first successful probe.
func TestBootGrace(t *testing.T) {
	f := newFake()
	f.probeOK = false
	m, evs := newMonitor(t, f)
	for i := 0; i < 6; i++ {
		m.Tick(context.Background())
		f.now = f.now.Add(5 * time.Second)
	}
	st := m.Status()
	if st.Online || !st.Starting {
		t.Fatalf("before the network is up the agent is starting, not online: %+v", st)
	}
	if has(*evs, store.KindOffline) || st.Uptime24h != 100 || st.Outages24h != 0 {
		t.Fatalf("boot wait must not count as an outage: %v uptime=%v", kinds(*evs), st.Uptime24h)
	}
	f.probeOK = true
	m.Tick(context.Background())
	if !has(*evs, store.KindNetworkReady) || m.Status().Starting || !m.Status().Online {
		t.Fatalf("want network_ready and online, got %v %+v", kinds(*evs), m.Status())
	}
	f.probeOK = false
	for i := 0; i < 3; i++ {
		f.now = f.now.Add(5 * time.Second)
		m.Tick(context.Background())
	}
	if !has(*evs, store.KindOffline) {
		t.Fatalf("after the network was up, drops count again: %v", kinds(*evs))
	}
}
