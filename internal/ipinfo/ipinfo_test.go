package ipinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

const ipapiIsFixture = `{
  "ip": "185.220.101.1",
  "is_bogon": false,
  "is_mobile": false,
  "is_datacenter": true,
  "is_tor": true,
  "is_proxy": false,
  "is_vpn": true,
  "is_abuser": true,
  "company": {"name": "Some Hosting", "type": "hosting"},
  "asn": {"asn": 60729, "org": "Stiftung Erneuerbare Freiheit", "country": "de", "type": "hosting"},
  "location": {"country": "Germany", "country_code": "DE", "city": "Berlin", "timezone": "Europe/Berlin"}
}`

const ipApiComFixture = `{
  "status": "success",
  "country": "Netherlands",
  "countryCode": "NL",
  "city": "Amsterdam",
  "timezone": "Europe/Amsterdam",
  "isp": "DigitalOcean, LLC",
  "org": "DigitalOcean",
  "as": "AS14061 DigitalOcean, LLC",
  "mobile": false,
  "proxy": true,
  "hosting": true,
  "query": "203.0.113.9"
}`

func TestParseIPAPIis(t *testing.T) {
	in, err := ParseIPAPIis([]byte(ipapiIsFixture))
	if err != nil {
		t.Fatal(err)
	}
	if in.IP != "185.220.101.1" || in.Country != "DE" || in.City != "Berlin" || in.Timezone != "Europe/Berlin" {
		t.Fatalf("location wrong: %+v", in)
	}
	if in.ASN != 60729 || in.Org == "" {
		t.Fatalf("asn wrong: %+v", in)
	}
	if !in.Datacenter || !in.Tor || !in.VPN || !in.Abuser || in.Proxy {
		t.Fatalf("flags wrong: %+v", in)
	}
	if in.Source != "ipapi.is" {
		t.Fatalf("source = %q", in.Source)
	}
}

func TestParseIPAPIcom(t *testing.T) {
	in, err := ParseIPAPIcom([]byte(ipApiComFixture))
	if err != nil {
		t.Fatal(err)
	}
	if in.IP != "203.0.113.9" || in.Country != "NL" || in.ASN != 14061 || in.Timezone != "Europe/Amsterdam" {
		t.Fatalf("parsed wrong: %+v", in)
	}
	if !in.Datacenter || !in.Proxy || in.Tor {
		t.Fatalf("flags wrong: %+v", in)
	}
	if _, err := ParseIPAPIcom([]byte(`{"status":"fail","message":"reserved range"}`)); err == nil {
		t.Fatal("fail status must be an error")
	}
}

func TestClientCacheAndFallback(t *testing.T) {
	var primaryHits, secondaryHits int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&primaryHits, 1)
		w.WriteHeader(429)
	}))
	defer primary.Close()
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secondaryHits, 1)
		w.Write([]byte(ipApiComFixture))
	}))
	defer secondary.Close()

	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	c := &Client{
		HTTP:        primary.Client(),
		IPAPIisURL:  primary.URL + "/?q=%s",
		IPAPIcomURL: secondary.URL + "/json/%s",
		TTL:         24 * time.Hour,
		Now:         func() time.Time { return now },
	}
	in, err := c.Lookup(context.Background(), "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if in.Country != "NL" {
		t.Fatalf("fallback result wrong: %+v", in)
	}
	if _, err := c.Lookup(context.Background(), "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if primaryHits != 1 || secondaryHits != 1 {
		t.Fatalf("second lookup must hit cache: primary=%d secondary=%d", primaryHits, secondaryHits)
	}
	now = now.Add(25 * time.Hour)
	c.Lookup(context.Background(), "203.0.113.9")
	if secondaryHits != 2 {
		t.Fatalf("expired entry must be refetched, secondary=%d", secondaryHits)
	}
}

func TestCachePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipcache.json")
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	c := &Client{TTL: time.Hour, Now: func() time.Time { return now }, CachePath: path}
	c.put(Info{IP: "198.51.100.1", Country: "US", Fetched: now})
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	c2 := &Client{TTL: time.Hour, Now: func() time.Time { return now }, CachePath: path}
	if err := c2.Load(); err != nil {
		t.Fatal(err)
	}
	in, ok := c2.get("198.51.100.1")
	if !ok || in.Country != "US" {
		t.Fatalf("cache not restored: %+v %v", in, ok)
	}
}
