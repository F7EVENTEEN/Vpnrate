// Package publicip finds the public exit address using several plain-text
// "what is my IP" services, falling back from one to the next.
package publicip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type Family int

const (
	V4 Family = 4
	V6 Family = 6
)

var (
	DefaultV4Sources = []string{"https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ifconfig.co/ip"}
	DefaultV6Sources = []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"}
)

type Fetcher struct {
	Client  *http.Client
	Sources []string
	Want    Family
}

// New returns a fetcher whose connections are pinned to one IP family, so
// the IPv4 and IPv6 exits are measured separately.
func New(f Family) *Fetcher {
	network, src := "tcp4", DefaultV4Sources
	if f == V6 {
		network, src = "tcp6", DefaultV6Sources
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
	}
	return &Fetcher{Client: &http.Client{Transport: tr, Timeout: 8 * time.Second}, Sources: src, Want: f}
}

func (f *Fetcher) Get(ctx context.Context) (netip.Addr, error) {
	var errs []error
	for _, src := range f.Sources {
		ip, err := f.one(ctx, src)
		if err == nil {
			return ip, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", src, err))
	}
	return netip.Addr{}, errors.Join(errs...)
}

func (f *Fetcher) one(ctx context.Context, url string) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("User-Agent", "curl/8.0")
	resp, err := f.Client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return netip.Addr{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(b)))
	if err != nil {
		return netip.Addr{}, errors.New("not an IP address")
	}
	ip = ip.Unmap()
	if (f.Want == V4) != ip.Is4() {
		return netip.Addr{}, errors.New("wrong address family")
	}
	if !IsPublic(ip) {
		return netip.Addr{}, errors.New("not a public address")
	}
	return ip, nil
}

func IsPublic(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsUnspecified() && !ip.IsMulticast() && !cgnat.Contains(ip)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")
