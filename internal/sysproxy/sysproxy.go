// Package sysproxy detects the system proxy that proxy-mode VPN clients
// (v2rayN, Nekoray, Hiddify, Clash without TUN…) set, and dials through it,
// so the agent sees the same exit as the user's browser.
package sysproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Proxy struct {
	Kind string `json:"kind"` // "http" or "socks5"
	Addr string `json:"addr"` // host:port
}

func (p Proxy) URL() *url.URL { return &url.URL{Scheme: p.Kind, Host: p.Addr} }

func (p Proxy) String() string { return p.Kind + "://" + p.Addr }

// Parse understands the Windows ProxyServer formats: "host:port",
// "http=h:p;https=h:p;socks=h:p", and URLs with an http/socks5 scheme.
func Parse(s string) (Proxy, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Proxy{}, false
	}
	if strings.Contains(s, "=") {
		m := map[string]string{}
		for _, part := range strings.Split(s, ";") {
			if k, v, ok := strings.Cut(part, "="); ok {
				m[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
		}
		for _, k := range []string{"https", "http"} {
			if v := m[k]; validAddr(stripScheme(v)) {
				return Proxy{"http", stripScheme(v)}, true
			}
		}
		if v := m["socks"]; validAddr(stripScheme(v)) {
			return Proxy{"socks5", stripScheme(v)}, true
		}
		return Proxy{}, false
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		switch u.Scheme {
		case "http", "https":
			return Proxy{"http", u.Host}, validAddr(u.Host)
		case "socks", "socks5", "socks5h":
			return Proxy{"socks5", u.Host}, validAddr(u.Host)
		}
	}
	if !validAddr(s) {
		return Proxy{}, false
	}
	return Proxy{"http", s}, true
}

func stripScheme(s string) string {
	if _, rest, ok := strings.Cut(s, "://"); ok {
		return rest
	}
	return s
}

func validAddr(s string) bool {
	h, p, err := net.SplitHostPort(s)
	if err != nil || h == "" {
		return false
	}
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n < 65536
}

// Dial opens a TCP connection to target through the proxy.
func Dial(ctx context.Context, p Proxy, target string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", p.Addr)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", p.Addr, err)
	}
	c.SetDeadline(time.Now().Add(timeout))
	switch p.Kind {
	case "socks5":
		err = socks5Connect(c, target)
	default:
		err = httpConnect(c, target)
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

func httpConnect(c net.Conn, target string) error {
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		return fmt.Errorf("proxy CONNECT: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("proxy CONNECT: %s", resp.Status)
	}
	if br.Buffered() > 0 {
		return errors.New("proxy CONNECT: unexpected data")
	}
	return nil
}

func socks5Connect(c net.Conn, target string) error {
	host, portS, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(portS)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil { // ver, 1 method, no auth
		return err
	}
	b := make([]byte, 10)
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return fmt.Errorf("socks5: %w", err)
	}
	if b[0] != 5 || b[1] != 0 {
		return errors.New("socks5: no acceptable auth method")
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(append(req, 1), ip.To4()...)
	} else if ip != nil {
		req = append(append(req, 4), ip.To16()...)
	} else {
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, b[:4]); err != nil {
		return fmt.Errorf("socks5: %w", err)
	}
	if b[1] != 0 {
		return fmt.Errorf("socks5: connect failed (code %d)", b[1])
	}
	skip := 0
	switch b[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		if _, err := io.ReadFull(c, b[:1]); err != nil {
			return err
		}
		skip = int(b[0])
	}
	_, err = io.ReadFull(c, make([]byte, skip+2))
	return err
}
