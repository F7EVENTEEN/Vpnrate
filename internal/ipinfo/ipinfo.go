// Package ipinfo looks up what the public internet knows about an IP:
// location, ASN and reputation flags. Results are cached, so the free APIs
// are only queried when the exit IP actually changes.
package ipinfo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Info struct {
	IP          string    `json:"ip"`
	Country     string    `json:"country"` // ISO 3166-1 alpha-2, upper case
	CountryName string    `json:"country_name,omitempty"`
	City        string    `json:"city,omitempty"`
	Timezone    string    `json:"timezone,omitempty"`
	ASN         int       `json:"asn,omitempty"`
	Org         string    `json:"org,omitempty"`
	Datacenter  bool      `json:"datacenter"`
	VPN         bool      `json:"vpn"`
	Proxy       bool      `json:"proxy"`
	Tor         bool      `json:"tor"`
	Abuser      bool      `json:"abuser"`
	Mobile      bool      `json:"mobile"`
	Source      string    `json:"source"`
	Fetched     time.Time `json:"fetched"`
}

func ParseIPAPIis(b []byte) (Info, error) {
	var r struct {
		IP           string `json:"ip"`
		IsMobile     bool   `json:"is_mobile"`
		IsDatacenter bool   `json:"is_datacenter"`
		IsTor        bool   `json:"is_tor"`
		IsProxy      bool   `json:"is_proxy"`
		IsVPN        bool   `json:"is_vpn"`
		IsAbuser     bool   `json:"is_abuser"`
		Error        string `json:"error"`
		ASN          struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
		} `json:"asn"`
		Location struct {
			Country     string `json:"country"`
			CountryCode string `json:"country_code"`
			City        string `json:"city"`
			Timezone    string `json:"timezone"`
		} `json:"location"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return Info{}, err
	}
	if r.Error != "" || r.IP == "" {
		return Info{}, fmt.Errorf("ipapi.is: %s", r.Error)
	}
	return Info{
		IP: r.IP, Country: strings.ToUpper(r.Location.CountryCode), CountryName: r.Location.Country,
		City: r.Location.City, Timezone: r.Location.Timezone, ASN: r.ASN.ASN, Org: r.ASN.Org,
		Datacenter: r.IsDatacenter, VPN: r.IsVPN, Proxy: r.IsProxy, Tor: r.IsTor,
		Abuser: r.IsAbuser, Mobile: r.IsMobile, Source: "ipapi.is",
	}, nil
}

func ParseIPAPIcom(b []byte) (Info, error) {
	var r struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		Timezone    string `json:"timezone"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		Mobile      bool   `json:"mobile"`
		Proxy       bool   `json:"proxy"`
		Hosting     bool   `json:"hosting"`
		Query       string `json:"query"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return Info{}, err
	}
	if r.Status != "success" {
		return Info{}, fmt.Errorf("ip-api.com: %s", r.Message)
	}
	in := Info{
		IP: r.Query, Country: strings.ToUpper(r.CountryCode), CountryName: r.Country, City: r.City,
		Timezone: r.Timezone, Org: r.ISP, Datacenter: r.Hosting, Proxy: r.Proxy, Mobile: r.Mobile,
		Source: "ip-api.com",
	}
	// "as" looks like "AS14061 DigitalOcean, LLC".
	if f := strings.Fields(r.AS); len(f) > 0 {
		in.ASN, _ = strconv.Atoi(strings.TrimPrefix(f[0], "AS"))
	}
	return in, nil
}

type Client struct {
	HTTP        *http.Client
	IPAPIisURL  string // with %s for the IP
	IPAPIcomURL string // with %s for the IP
	TTL         time.Duration
	Now         func() time.Time
	CachePath   string

	mu    sync.Mutex
	cache map[string]Info
}

func NewClient(cachePath string) *Client {
	c := &Client{
		HTTP:        &http.Client{Timeout: 10 * time.Second},
		IPAPIisURL:  "https://api.ipapi.is/?q=%s",
		IPAPIcomURL: "http://ip-api.com/json/%s?fields=status,message,country,countryCode,city,timezone,isp,org,as,mobile,proxy,hosting,query",
		TTL:         24 * time.Hour,
		Now:         time.Now,
		CachePath:   cachePath,
	}
	c.Load()
	return c
}

func (c *Client) Lookup(ctx context.Context, ip string) (Info, error) {
	if in, ok := c.get(ip); ok {
		return in, nil
	}
	in, err1 := c.fetch(ctx, c.IPAPIisURL, ip, ParseIPAPIis)
	if err1 != nil {
		var err2 error
		in, err2 = c.fetch(ctx, c.IPAPIcomURL, ip, ParseIPAPIcom)
		if err2 != nil {
			return Info{}, errors.Join(err1, err2)
		}
	}
	in.Fetched = c.Now()
	c.put(in)
	c.Save()
	return in, nil
}

func (c *Client) fetch(ctx context.Context, tmpl, ip string, parse func([]byte) (Info, error)) (Info, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf(tmpl, ip), nil)
	if err != nil {
		return Info{}, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Info{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Info{}, fmt.Errorf("%s: status %d", req.URL.Host, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return Info{}, err
	}
	in, err := parse(b)
	if err == nil && in.IP == "" {
		in.IP = ip
	}
	return in, err
}

func (c *Client) get(ip string) (Info, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	in, ok := c.cache[ip]
	if !ok || c.Now().Sub(in.Fetched) > c.TTL {
		return Info{}, false
	}
	return in, true
}

func (c *Client) put(in Info) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = map[string]Info{}
	}
	c.cache[in.IP] = in
}

// Save writes non-expired entries to CachePath.
func (c *Client) Save() error {
	if c.CachePath == "" {
		return nil
	}
	c.mu.Lock()
	keep := map[string]Info{}
	for k, v := range c.cache {
		if c.Now().Sub(v.Fetched) <= c.TTL {
			keep[k] = v
		}
	}
	c.mu.Unlock()
	b, err := json.Marshal(keep)
	if err != nil {
		return err
	}
	return os.WriteFile(c.CachePath, b, 0o644)
}

func (c *Client) Load() error {
	if c.CachePath == "" {
		return nil
	}
	b, err := os.ReadFile(c.CachePath)
	if err != nil {
		return err
	}
	m := map[string]Info{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	c.mu.Lock()
	c.cache = m
	c.mu.Unlock()
	return nil
}
