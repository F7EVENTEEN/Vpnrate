// Package monitor orchestrates the probes: it keeps the live state, turns
// changes into events, persists history and recomputes the ratings.
package monitor

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/F7EVENTEEN/Vpnrate/internal/ipinfo"
	"github.com/F7EVENTEEN/Vpnrate/internal/leak"
	"github.com/F7EVENTEEN/Vpnrate/internal/netif"
	"github.com/F7EVENTEEN/Vpnrate/internal/probe"
	"github.com/F7EVENTEEN/Vpnrate/internal/score"
	"github.com/F7EVENTEEN/Vpnrate/internal/store"
)

const (
	ProbeInterval  = 5 * time.Second
	IPInterval     = 90 * time.Second
	FullCheckEvery = 10 * time.Minute
	History        = 24 * time.Hour
	Retention      = 30 * 24 * time.Hour
)

// Deps are the outside-world operations, injectable for tests.
type Deps struct {
	Probe       func(context.Context) (bool, time.Duration)
	PublicV4    func(context.Context) (netip.Addr, error)
	PublicV6    func(context.Context) (netip.Addr, error)
	Lookup      func(context.Context, string) (ipinfo.Info, error)
	STUN        func(context.Context) (netip.Addr, error)
	DNSResolver func(context.Context) (netip.Addr, error)
	Tunnels     func() ([]netif.Iface, error)
	Proxy       func() string // system proxy address, "" when none
	Now         func() time.Time
	LocalTZ     *time.Location
}

type Leaks struct {
	DNS      leak.Verdict `json:"dns"`
	UDP      leak.Verdict `json:"udp"`
	WebRTC   leak.Verdict `json:"webrtc"`
	IPv6     leak.Verdict `json:"ipv6"`
	Timezone leak.Verdict `json:"timezone"`
}

type Status struct {
	Online         bool            `json:"online"`
	Starting       bool            `json:"starting"` // waiting for the network after launch
	DownSince      *time.Time      `json:"down_since,omitempty"`
	LatencyMs      float64         `json:"latency_ms"`
	PublicV4       string          `json:"public_v4"`
	PublicV6       string          `json:"public_v6,omitempty"`
	Exit           *ipinfo.Info    `json:"exit"`
	ExitV6         *ipinfo.Info    `json:"exit_v6,omitempty"`
	Resolver       *ipinfo.Info    `json:"resolver,omitempty"`
	VPNActive      bool            `json:"vpn_active"`
	Tunnels        []netif.Iface   `json:"tunnels"`
	Proxy          string          `json:"proxy,omitempty"`
	Profile        string          `json:"profile,omitempty"`
	Leaks          Leaks           `json:"leaks"`
	Trust          score.Trust     `json:"trust"`
	Stability      score.Stability `json:"stability"`
	Uptime24h      float64         `json:"uptime_24h"`
	Outages24h     int             `json:"outages_24h"`
	TunnelDrops24h int             `json:"tunnel_drops_24h"`
	P95Ms          float64         `json:"p95_ms"`
	LastIPCheck    time.Time       `json:"last_ip_check"`
	Started        time.Time       `json:"started"`
	Checked        bool            `json:"checked"` // at least one IP check finished
}

type Monitor struct {
	d     Deps
	store *store.Store

	mu        sync.Mutex
	det       *probe.Detector
	minute    time.Time
	bucket    []probe.Sample
	minutes   []store.MinuteSample
	recent    []store.Event // last 24h, for counters
	st        Status
	tunnelsOK bool // tunnels observed at least once
	warm      bool // network seen at least once since launch
	lastFull  time.Time
	leaking   map[string]bool
	webrtcIPs []netip.Addr
	profiles  map[string]*Profile
	subs      []func(store.Event)
	recheck   chan struct{}
}

func New(d Deps, st *store.Store) *Monitor {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.LocalTZ == nil {
		d.LocalTZ = time.Local
	}
	m := &Monitor{
		d: d, store: st, det: probe.NewDetector(2),
		leaking: map[string]bool{}, recheck: make(chan struct{}, 1),
		profiles: map[string]*Profile{},
	}
	m.st.Starting = true
	m.st.Started = d.Now()
	m.st.Trust = score.ComputeTrust(score.TrustInput{})
	m.loadHistory()
	return m
}

func (m *Monitor) loadHistory() {
	since := m.d.Now().Add(-History)
	if s, err := m.store.Samples(since); err == nil {
		m.minutes = s
	}
	if e, err := m.store.Events(since); err == nil {
		m.recent = e
	}
	m.store.LoadJSON(profilesFile, &m.profiles)
	if m.profiles == nil {
		m.profiles = map[string]*Profile{}
	}
}

// Subscribe registers a callback for every new event (used for notifications).
func (m *Monitor) Subscribe(fn func(store.Event)) {
	m.mu.Lock()
	m.subs = append(m.subs, fn)
	m.mu.Unlock()
}

// emit persists events and notifies subscribers. Call without the lock held.
func (m *Monitor) emit(evs []store.Event) {
	if len(evs) == 0 {
		return
	}
	m.mu.Lock()
	m.recent = append(m.recent, evs...)
	subs := slices.Clone(m.subs)
	m.mu.Unlock()
	for _, e := range evs {
		m.store.AppendEvent(e)
		for _, fn := range subs {
			fn(e)
		}
	}
}

func (m *Monitor) Run(ctx context.Context) {
	m.emit([]store.Event{{Time: m.d.Now(), Kind: store.KindStarted, Message: "agent started"}})
	m.store.Prune(m.d.Now(), Retention)
	m.Tick(ctx)
	m.CheckIP(ctx)

	probeT := time.NewTicker(ProbeInterval)
	ipT := time.NewTicker(IPInterval)
	pruneT := time.NewTicker(24 * time.Hour)
	defer probeT.Stop()
	defer ipT.Stop()
	defer pruneT.Stop()
	for {
		select {
		case <-ctx.Done():
			m.flush()
			return
		case <-probeT.C:
			m.Tick(ctx)
		case <-ipT.C:
			m.CheckIP(ctx)
		case <-m.recheck:
			m.forceFull()
			m.CheckIP(ctx)
		case <-pruneT.C:
			m.store.Prune(m.d.Now(), Retention)
		}
	}
}

// Recheck asks the run loop for an immediate full check.
func (m *Monitor) Recheck() {
	select {
	case m.recheck <- struct{}{}:
	default:
	}
}

func (m *Monitor) forceFull() {
	m.mu.Lock()
	m.lastFull = time.Time{}
	m.mu.Unlock()
}

// Tick runs one connectivity probe and one tunnel scan.
func (m *Monitor) Tick(ctx context.Context) {
	ok, lat := m.d.Probe(ctx)
	tunnels, terr := m.d.Tunnels()
	proxy := ""
	if m.d.Proxy != nil {
		proxy = m.d.Proxy()
	}
	now := m.d.Now()

	var evs []store.Event
	m.mu.Lock()
	if !m.warm && !ok {
		// Launched at logon before Wi-Fi or the VPN came up: waiting for the
		// network is not an outage, so nothing is recorded yet.
		m.st.Online, m.st.Starting = false, true
	} else {
		if !m.warm {
			m.warm, m.st.Starting = true, false
			if wait := now.Sub(m.st.Started); wait >= 10*time.Second {
				evs = append(evs, store.Event{Time: now, Kind: store.KindNetworkReady,
					Message: fmt.Sprintf("network available %s after start", wait.Round(time.Second))})
			}
		}
		evs = append(evs, m.observeLocked(now, ok, lat)...)
	}

	if terr == nil {
		// A route is either a tunnel adapter or a system proxy (proxy-mode clients).
		active := len(tunnels) > 0 || proxy != ""
		if m.tunnelsOK && active != m.st.VPNActive {
			if active {
				evs = append(evs, store.Event{Time: now, Kind: store.KindVPNUp,
					Message: "VPN up: " + route(tunnels, proxy)})
			} else {
				evs = append(evs, store.Event{Time: now, Kind: store.KindVPNDown,
					Message: "VPN down: " + route(m.st.Tunnels, m.st.Proxy),
					Data:    map[string]any{"profile": m.st.Profile}})
			}
		} else if m.tunnelsOK && proxy != m.st.Proxy && proxy != "" && m.st.Proxy != "" {
			m.forceFull()
		}
		m.tunnelsOK = true
		m.st.VPNActive = active
		m.st.Tunnels = tunnels
		m.st.Proxy = proxy
	}
	m.mu.Unlock()

	m.emit(evs)
	// Any change in connectivity or tunnels may mean a new exit IP.
	for _, e := range evs {
		if e.Kind != store.KindOffline {
			m.forceFull()
			m.Recheck()
			break
		}
	}
}

// observeLocked feeds one probe result to the outage detector and the
// per-minute aggregate.
func (m *Monitor) observeLocked(now time.Time, ok bool, lat time.Duration) []store.Event {
	var evs []store.Event
	if tr := m.det.Observe(now, ok); tr != nil {
		if tr.Online {
			d := tr.Outage.Duration().Round(time.Second)
			evs = append(evs, store.Event{Time: now, Kind: store.KindOnline,
				Message: fmt.Sprintf("connection restored after %s", d),
				Data:    map[string]any{"duration_s": d.Seconds(), "start": tr.Outage.Start}})
		} else {
			evs = append(evs, store.Event{Time: tr.At, Kind: store.KindOffline, Message: "connection lost",
				Data: map[string]any{"profile": m.st.Profile}})
		}
	}
	m.st.Online = m.det.Online()
	if ds := m.det.DownSince(); !ds.IsZero() {
		m.st.DownSince = &ds
	} else {
		m.st.DownSince = nil
	}
	if ok {
		m.st.LatencyMs = ms(lat)
	}

	minute := now.Truncate(time.Minute)
	if !m.minute.IsZero() && !minute.Equal(m.minute) {
		m.flushLocked()
	}
	m.minute = minute
	m.bucket = append(m.bucket, probe.Sample{T: now, OK: ok, Latency: lat})
	return evs
}

func route(ifs []netif.Iface, proxy string) string {
	switch {
	case len(ifs) > 0 && proxy != "":
		return names(ifs) + " + proxy " + proxy
	case proxy != "":
		return "system proxy " + proxy
	}
	return names(ifs)
}

func names(ifs []netif.Iface) string {
	var s string
	for i, x := range ifs {
		if i > 0 {
			s += ", "
		}
		s += x.Name
	}
	return s
}

func (m *Monitor) flush() {
	m.mu.Lock()
	m.flushLocked()
	m.mu.Unlock()
}

func (m *Monitor) flushLocked() {
	if len(m.bucket) == 0 {
		return
	}
	s := store.MinuteSample{T: m.minute, Probes: len(m.bucket), P95Ms: ms(probe.P95(m.bucket)), Profile: m.st.Profile}
	var sum time.Duration
	for _, b := range m.bucket {
		if b.OK {
			s.OK++
			sum += b.Latency
		}
	}
	if s.OK > 0 {
		s.AvgMs = ms(sum / time.Duration(s.OK))
	}
	m.bucket = m.bucket[:0]
	m.minutes = append(m.minutes, s)
	cut := m.d.Now().Add(-History)
	for len(m.minutes) > 0 && m.minutes[0].T.Before(cut) {
		m.minutes = m.minutes[1:]
	}
	m.store.AppendSample(s)
}

// CheckIP refreshes the public IP; on change (or every FullCheckEvery) it
// also re-runs the reputation lookup and every leak test.
func (m *Monitor) CheckIP(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	now := m.d.Now()
	v4, err := m.d.PublicV4(ctx)
	if err != nil {
		return // offline or all sources down; keep the last known state
	}
	m.mu.Lock()
	prev := m.st.PublicV4
	full := v4.String() != prev || now.Sub(m.lastFull) >= FullCheckEvery || !m.st.Checked
	m.st.PublicV4 = v4.String()
	m.st.LastIPCheck = now
	m.mu.Unlock()

	var evs []store.Event
	if prev != "" && prev != v4.String() {
		evs = append(evs, store.Event{Time: now, Kind: store.KindIPChanged,
			Message: fmt.Sprintf("exit IP changed: %s → %s", prev, v4),
			Data:    map[string]any{"from": prev, "to": v4.String()}})
	}
	if !full {
		m.emit(evs)
		return
	}

	var exit *ipinfo.Info
	if in, err := m.d.Lookup(ctx, v4.String()); err == nil {
		exit = &in
	}
	var exit6 *ipinfo.Info
	v6, err6 := m.d.PublicV6(ctx)
	if err6 == nil {
		in, err := m.d.Lookup(ctx, v6.String())
		if err != nil {
			in = ipinfo.Info{IP: v6.String()}
		}
		exit6 = &in
	}
	stunIP, _ := m.d.STUN(ctx)
	var resolver *ipinfo.Info
	if rip, err := m.d.DNSResolver(ctx); err == nil {
		if in, err := m.d.Lookup(ctx, rip.String()); err == nil {
			resolver = &in
		} else {
			resolver = &ipinfo.Info{IP: rip.String()}
		}
	}

	m.mu.Lock()
	m.lastFull = now
	m.st.Checked = true
	m.st.Exit, m.st.ExitV6, m.st.Resolver = exit, exit6, resolver
	m.st.PublicV6 = ""
	if exit6 != nil {
		m.st.PublicV6 = exit6.IP
	}
	l := &m.st.Leaks
	l.UDP = leak.JudgeUDP(v4, stunIP)
	l.IPv6 = leak.JudgeIPv6(exit, exit6)
	if exit != nil && resolver != nil && m.st.Proxy != "" && len(m.st.Tunnels) == 0 {
		// Proxied apps (the browser) resolve names at the proxy; only
		// proxy-unaware apps use the system resolver checked here.
		l.DNS = leak.Verdict{Status: leak.Unknown, IP: resolver.IP,
			Detail: fmt.Sprintf("proxy mode: the browser resolves DNS through the proxy; apps that ignore the proxy use %s (%s)", resolver.IP, resolver.Country)}
		l.Timezone = leak.JudgeTimezone(exit.Timezone, m.d.LocalTZ, now)
	} else if exit != nil && resolver != nil {
		l.DNS = leak.JudgeDNS(*exit, *resolver)
		l.Timezone = leak.JudgeTimezone(exit.Timezone, m.d.LocalTZ, now)
	} else {
		l.DNS = leak.Verdict{Status: leak.Unknown}
		l.Timezone = leak.Verdict{Status: leak.Unknown}
		if exit != nil {
			l.Timezone = leak.JudgeTimezone(exit.Timezone, m.d.LocalTZ, now)
		}
	}
	m.judgeWebRTCLocked()
	evs = append(evs, m.leakEventsLocked(now)...)
	m.recomputeTrustLocked()
	m.updateProfileLocked(now)
	m.mu.Unlock()
	m.emit(evs)
}

func (m *Monitor) exitsLocked() []netip.Addr {
	var out []netip.Addr
	for _, s := range []string{m.st.PublicV4, m.st.PublicV6} {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func (m *Monitor) judgeWebRTCLocked() {
	if m.webrtcIPs == nil {
		m.st.Leaks.WebRTC = leak.Verdict{Status: leak.Unknown, Detail: "open the dashboard in your browser to test"}
		return
	}
	exits := m.exitsLocked()
	if len(exits) == 0 {
		m.st.Leaks.WebRTC = leak.Verdict{Status: leak.Unknown, Detail: "waiting for the exit IP"}
		return
	}
	m.st.Leaks.WebRTC = leak.JudgeWebRTC(exits, m.webrtcIPs)
}

// leakEventsLocked emits an event only when a leak appears or disappears,
// so a persistent leak does not spam notifications.
func (m *Monitor) leakEventsLocked(now time.Time) []store.Event {
	var evs []store.Event
	l := m.st.Leaks
	for _, x := range []struct {
		name string
		v    leak.Verdict
	}{{"DNS", l.DNS}, {"UDP", l.UDP}, {"WebRTC", l.WebRTC}, {"IPv6", l.IPv6}, {"Timezone", l.Timezone}} {
		switch {
		case x.v.Status == leak.Leak && !m.leaking[x.name]:
			m.leaking[x.name] = true
			evs = append(evs, store.Event{Time: now, Kind: store.KindLeak,
				Message: x.name + " leak: " + x.v.Detail, Data: map[string]any{"type": x.name}})
		case x.v.Status == leak.OK && m.leaking[x.name]:
			m.leaking[x.name] = false
			evs = append(evs, store.Event{Time: now, Kind: store.KindLeakFixed,
				Message: x.name + " leak resolved", Data: map[string]any{"type": x.name}})
		}
	}
	return evs
}

func (m *Monitor) recomputeTrustLocked() {
	in := score.TrustInput{}
	if e := m.st.Exit; e != nil {
		in = score.TrustInput{Country: e.Country, Datacenter: e.Datacenter, VPN: e.VPN,
			Proxy: e.Proxy, Tor: e.Tor, Abuser: e.Abuser}
	}
	l := m.st.Leaks
	in.DNSLeak = l.DNS.Status == leak.Leak
	in.UDPLeak = l.UDP.Status == leak.Leak
	in.WebRTCLeak = l.WebRTC.Status == leak.Leak
	in.IPv6Leak = l.IPv6.Status == leak.Leak
	in.TZMismatch = l.Timezone.Status == leak.Leak
	m.st.Trust = score.ComputeTrust(in)
}

// SetBrowserWebRTC receives the ICE candidate IPs gathered by the dashboard.
func (m *Monitor) SetBrowserWebRTC(ips []string) {
	addrs := []netip.Addr{}
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil {
			addrs = append(addrs, a)
		}
	}
	m.mu.Lock()
	m.webrtcIPs = addrs
	m.judgeWebRTCLocked()
	evs := m.leakEventsLocked(m.d.Now())
	m.recomputeTrustLocked()
	m.updateProfileLocked(m.d.Now())
	m.mu.Unlock()
	m.emit(evs)
}

// Status returns a snapshot with fresh 24h stability numbers.
func (m *Monitor) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	cut := m.d.Now().Add(-History)
	probes, ok := 0, 0
	var p95s []float64
	for _, s := range m.minutes {
		if s.T.Before(cut) {
			continue
		}
		probes += s.Probes
		ok += s.OK
		if s.OK > 0 {
			p95s = append(p95s, s.P95Ms)
		}
	}
	for _, b := range m.bucket {
		probes++
		if b.OK {
			ok++
		}
	}
	if cur := ms(probe.P95(m.bucket)); cur > 0 {
		p95s = append(p95s, cur)
	}
	st := m.st
	st.Uptime24h = 100
	if probes > 0 {
		st.Uptime24h = float64(ok) * 100 / float64(probes)
	}
	// p95 across minutes, approximated from per-minute p95 values.
	if len(p95s) > 0 {
		slices.Sort(p95s)
		st.P95Ms = p95s[min(len(p95s)-1, int(float64(len(p95s))*0.95))]
	}
	st.Outages24h, st.TunnelDrops24h = 0, 0
	for _, e := range m.recent {
		if e.Time.Before(cut) {
			continue
		}
		switch e.Kind {
		case store.KindOffline:
			st.Outages24h++
		case store.KindVPNDown:
			st.TunnelDrops24h++
		}
	}
	st.Stability = score.ComputeStability(score.StabilityInput{
		UptimePct: st.Uptime24h, Outages: st.Outages24h, TunnelDrops: st.TunnelDrops24h, P95LatencyMs: st.P95Ms,
	})
	st.Tunnels = slices.Clone(st.Tunnels)
	return st
}

func (m *Monitor) Events(since time.Time) []store.Event {
	e, _ := m.store.Events(since)
	return e
}

// Samples returns per-minute samples for the last hours (max 24 from memory,
// older from disk).
func (m *Monitor) Samples(hours int) []store.MinuteSample {
	since := m.d.Now().Add(-time.Duration(hours) * time.Hour)
	if hours > 24 {
		s, _ := m.store.Samples(since)
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.MinuteSample
	for _, s := range m.minutes {
		if !s.T.Before(since) {
			out = append(out, s)
		}
	}
	return out
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
