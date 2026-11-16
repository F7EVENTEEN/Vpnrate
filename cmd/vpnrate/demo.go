package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/F7EVENTEEN/Vpnrate/internal/ipinfo"
	"github.com/F7EVENTEEN/Vpnrate/internal/monitor"
	"github.com/F7EVENTEEN/Vpnrate/internal/netif"
	"github.com/F7EVENTEEN/Vpnrate/internal/store"
	"github.com/F7EVENTEEN/Vpnrate/internal/web"
)

// Demo mode serves the dashboard with made-up data (documentation IP ranges,
// a synthetic 24h history) and makes no network requests at all. It exists
// for screenshots and for trying the UI without installing anything.
// A live outage is staged 20–38 s after start.

const (
	demoExit     = "203.0.113.42"
	demoResolver = "198.51.100.53"
)

var demoInfos = map[string]ipinfo.Info{
	demoExit: {IP: demoExit, Country: "NL", CountryName: "Netherlands", City: "Amsterdam",
		Timezone: "Europe/Amsterdam", ASN: 64500, Org: "ExampleNet Hosting B.V.",
		Datacenter: true, VPN: true, Source: "demo"},
	demoResolver: {IP: demoResolver, Country: "NL", CountryName: "Netherlands", ASN: 13335,
		Org: "Cloudflare, Inc.", Datacenter: true, Source: "demo"},
}

// demoProvider ignores the browser's real WebRTC candidates so the demo never
// shows a real address.
type demoProvider struct{ *monitor.Monitor }

func (d demoProvider) SetBrowserWebRTC([]string) {
	d.Monitor.SetBrowserWebRTC([]string{"192.168.1.20", demoExit})
}

func runDemo(port int) {
	dir, err := os.MkdirTemp("", "vpnrate-demo-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	st, err := store.Open(dir)
	if err != nil {
		log.Fatal(err)
	}
	seedDemoHistory(st, time.Now())

	start := time.Now()
	amsterdam, _ := time.LoadLocation("Europe/Amsterdam")
	mon := monitor.New(monitor.Deps{
		Probe: func(context.Context) (bool, time.Duration) {
			if s := time.Since(start); s > 20*time.Second && s < 38*time.Second {
				return false, 0
			}
			return true, time.Duration(28+rand.IntN(14)) * time.Millisecond
		},
		PublicV4: func(context.Context) (netip.Addr, error) { return netip.MustParseAddr(demoExit), nil },
		PublicV6: func(context.Context) (netip.Addr, error) { return netip.Addr{}, errors.New("no ipv6") },
		Lookup: func(_ context.Context, ip string) (ipinfo.Info, error) {
			if in, ok := demoInfos[ip]; ok {
				return in, nil
			}
			return ipinfo.Info{}, errors.New("unknown")
		},
		STUN:        func(context.Context) (netip.Addr, error) { return netip.MustParseAddr(demoExit), nil },
		DNSResolver: func(context.Context) (netip.Addr, error) { return netip.MustParseAddr(demoResolver), nil },
		Tunnels: func() ([]netif.Iface, error) {
			return []netif.Iface{{Name: "wg-amsterdam", Description: "WireGuard Tunnel"}}, nil
		},
		LocalTZ: amsterdam,
	}, st)

	ln, err := web.ListenLoopback(port)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go http.Serve(ln, web.Handler(demoProvider{mon}))
	go mon.Run(ctx)
	log.Printf("demo dashboard at http://127.0.0.1:%d/ (fake data, no network access)", port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}

// seedDemoHistory writes 24h of per-minute samples with a few outages, a VPN
// reconnect and a short DNS leak, so the uptime strip and event feed look lived-in.
func seedDemoHistory(st *store.Store, now time.Time) {
	end := now.Truncate(time.Minute)
	begin := end.Add(-24 * time.Hour)
	at := func(h float64) time.Time {
		return end.Add(-time.Duration(h * float64(time.Hour))).Truncate(time.Minute)
	}

	outages := []struct {
		start time.Time
		mins  int
	}{{at(20.3), 3}, {at(9.1), 1}, {at(2.4), 1}}
	vpnDown := at(14.2)
	down := func(t time.Time) bool {
		for _, o := range outages {
			if !t.Before(o.start) && t.Before(o.start.Add(time.Duration(o.mins)*time.Minute)) {
				return true
			}
		}
		return false
	}

	const nl, de, home = "AS64500-NL", "AS64501-DE", "AS64496-RU"
	profileAt := func(t time.Time) string {
		if t.Before(vpnDown) {
			return de
		}
		return nl
	}

	// Half an hour without VPN three days ago, to show the "direct" row.
	for t := end.Add(-72 * time.Hour); t.Before(end.Add(-71*time.Hour - 30*time.Minute)); t = t.Add(time.Minute) {
		st.AppendSample(store.MinuteSample{T: t, Probes: 12, OK: 12, AvgMs: 18 + rand.Float64()*4, P95Ms: 25, Profile: home})
	}

	for t := begin; t.Before(end); t = t.Add(time.Minute) {
		hour := float64(t.Hour()) + float64(t.Minute())/60
		// Evening congestion bump plus noise.
		base := 32 + 14*math.Max(0, math.Sin((hour-14)/24*2*math.Pi)) + rand.Float64()*6
		if t.Before(vpnDown) {
			base += 25 // the older VPN was slower
		}
		s := store.MinuteSample{T: t, Probes: 12, OK: 12, AvgMs: base, P95Ms: base * 1.6, Profile: profileAt(t)}
		if down(t) {
			s.OK, s.AvgMs, s.P95Ms = 0, 0, 0
		}
		if t.Equal(vpnDown) {
			s.OK = 9
		}
		st.AppendSample(s)
	}

	ev := func(t time.Time, kind, msg string, data map[string]any) {
		st.AppendEvent(store.Event{Time: t, Kind: kind, Message: msg, Data: data})
	}
	for _, o := range outages {
		d := time.Duration(o.mins) * time.Minute
		ev(o.start, store.KindOffline, "connection lost", map[string]any{"profile": profileAt(o.start)})
		ev(o.start.Add(d), store.KindOnline, fmt.Sprintf("connection restored after %s", d), map[string]any{"duration_s": d.Seconds()})
	}
	ev(vpnDown, store.KindVPNDown, "VPN down: singbox_tun", map[string]any{"profile": de})
	ev(vpnDown.Add(40*time.Second), store.KindVPNUp, "VPN up: wg-amsterdam", nil)
	ev(vpnDown.Add(50*time.Second), store.KindIPChanged, "exit IP changed: 203.0.113.17 → "+demoExit, nil)
	ev(vpnDown.Add(55*time.Second), store.KindLeak, "DNS leak: DNS resolver 192.0.2.53 (HomeISP, AS64511) is in DE, exit IP is in NL", map[string]any{"type": "DNS"})
	ev(vpnDown.Add(3*time.Minute), store.KindLeakFixed, "DNS leak resolved", map[string]any{"type": "DNS"})

	st.SaveJSON("profiles.json", map[string]*monitor.Profile{
		nl: {Key: nl, Label: "ExampleNet Hosting B.V.", Country: "NL", ASN: 64500, Via: "wg-amsterdam",
			Datacenter: true, Trust: 70, Grade: "good", FirstSeen: vpnDown, LastSeen: now},
		de: {Key: de, Label: "OtherCloud GmbH", Country: "DE", ASN: 64501, Via: "singbox_tun",
			Datacenter: true, Trust: 55, Grade: "suspicious", FirstSeen: begin, LastSeen: vpnDown},
		home: {Key: home, Label: "HomeISP", Country: "RU", ASN: 64496, Via: "direct",
			Trust: 60, Grade: "suspicious", FirstSeen: end.Add(-72 * time.Hour), LastSeen: end.Add(-71*time.Hour - 30*time.Minute)},
	})
}
