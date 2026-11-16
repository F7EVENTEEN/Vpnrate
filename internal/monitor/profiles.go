package monitor

import (
	"fmt"
	"sort"
	"time"

	"github.com/F7EVENTEEN/Vpnrate/internal/ipinfo"
	"github.com/F7EVENTEEN/Vpnrate/internal/store"
)

// A profile is one exit network (ASN + country). Switching VPNs, servers or
// going direct lands you on a different profile, so history can be compared
// per connection without asking the user to label anything.

const profilesFile = "profiles.json"

type Profile struct {
	Key        string    `json:"key"`
	Label      string    `json:"label"`
	Country    string    `json:"country"`
	ASN        int       `json:"asn"`
	Via        string    `json:"via"`
	Datacenter bool      `json:"datacenter"`
	Trust      int       `json:"trust"`
	Grade      string    `json:"grade"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

type ProfileStats struct {
	Profile
	Minutes     int     `json:"minutes"`
	Uptime      float64 `json:"uptime"`
	Outages     int     `json:"outages"`
	TunnelDrops int     `json:"tunnel_drops"`
	AvgMs       float64 `json:"avg_ms"`
	Current     bool    `json:"current"`
}

func profileKey(in *ipinfo.Info) string {
	if in == nil || in.Country == "" {
		return ""
	}
	return fmt.Sprintf("AS%d-%s", in.ASN, in.Country)
}

// updateProfileLocked records the current exit as a profile and keeps its
// latest trust score. On a switch, the partial minute is flushed first so
// it is credited to the profile it was spent on.
func (m *Monitor) updateProfileLocked(now time.Time) {
	key := profileKey(m.st.Exit)
	if key == "" {
		return
	}
	if key != m.st.Profile && m.st.Profile != "" {
		m.flushLocked()
	}
	m.st.Profile = key
	p := m.profiles[key]
	if p == nil {
		p = &Profile{Key: key, FirstSeen: now}
		m.profiles[key] = p
	}
	e := m.st.Exit
	p.Label = e.Org
	if p.Label == "" {
		p.Label = fmt.Sprintf("AS%d", e.ASN)
	}
	p.Country, p.ASN, p.Datacenter = e.Country, e.ASN, e.Datacenter
	p.Via = "direct"
	if m.st.VPNActive {
		p.Via = route(m.st.Tunnels, m.st.Proxy)
	}
	p.Trust, p.Grade = m.st.Trust.Score, m.st.Trust.Grade
	p.LastSeen = now
	m.store.SaveJSON(profilesFile, m.profiles)
}

// Profiles aggregates the last days of history per exit network, current
// profile first, then most recently used.
func (m *Monitor) Profiles(days int) []ProfileStats {
	since := m.d.Now().Add(-time.Duration(days) * 24 * time.Hour)
	samples, _ := m.store.Samples(since)
	events, _ := m.store.Events(since)

	m.mu.Lock()
	current := m.st.Profile
	meta := map[string]Profile{}
	for k, p := range m.profiles {
		meta[k] = *p
	}
	m.mu.Unlock()

	type acc struct {
		ProfileStats
		probes, ok int
		latSum     float64
	}
	all := map[string]*acc{}
	get := func(k string) *acc {
		a := all[k]
		if a == nil {
			p, ok := meta[k]
			if !ok {
				p = Profile{Key: k, Label: k}
			}
			a = &acc{ProfileStats: ProfileStats{Profile: p}}
			all[k] = a
		}
		return a
	}
	for _, s := range samples {
		if s.Profile == "" {
			continue
		}
		a := get(s.Profile)
		a.Minutes++
		a.probes += s.Probes
		a.ok += s.OK
		a.latSum += s.AvgMs * float64(s.OK)
	}
	for _, e := range events {
		k, _ := e.Data["profile"].(string)
		if k == "" {
			continue
		}
		switch e.Kind {
		case store.KindOffline:
			get(k).Outages++
		case store.KindVPNDown:
			get(k).TunnelDrops++
		}
	}
	for k, p := range meta {
		if !p.LastSeen.Before(since) {
			get(k)
		}
	}

	out := make([]ProfileStats, 0, len(all))
	for k, a := range all {
		a.Uptime = 100
		if a.probes > 0 {
			a.Uptime = float64(a.ok) * 100 / float64(a.probes)
		}
		if a.ok > 0 {
			a.AvgMs = a.latSum / float64(a.ok)
		}
		a.Current = k == current
		out = append(out, a.ProfileStats)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Current != out[j].Current {
			return out[i].Current
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}
