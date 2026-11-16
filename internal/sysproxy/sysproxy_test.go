package sysproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		kind string
		addr string
		ok   bool
	}{
		{"127.0.0.1:10809", "http", "127.0.0.1:10809", true},          // v2rayN
		{"http://127.0.0.1:2080", "http", "127.0.0.1:2080", true},     // explicit scheme
		{"socks5://127.0.0.1:1080", "socks5", "127.0.0.1:1080", true}, // explicit scheme
		{"http=127.0.0.1:8080;https=127.0.0.1:8443", "http", "127.0.0.1:8443", true},
		{"socks=127.0.0.1:10808", "socks5", "127.0.0.1:10808", true},
		{"ftp=10.0.0.1:21;socks=127.0.0.1:1080", "socks5", "127.0.0.1:1080", true},
		{"", "", "", false},
		{"garbage", "", "", false},
	}
	for _, c := range cases {
		p, ok := Parse(c.in)
		if ok != c.ok || p.Kind != c.kind || p.Addr != c.addr {
			t.Errorf("Parse(%q) = %+v %v, want %s %s %v", c.in, p, ok, c.kind, c.addr, c.ok)
		}
	}
}

func TestURL(t *testing.T) {
	if u := (Proxy{Kind: "socks5", Addr: "127.0.0.1:1080"}).URL(); u.String() != "socks5://127.0.0.1:1080" {
		t.Fatalf("url = %s", u)
	}
}

// target is a TCP server that answers "pong" to anything.
func target(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("pong"))
			c.Close()
		}
	}()
	return ln.Addr().String()
}

func pipe(a, b net.Conn) {
	go io.Copy(a, b)
	io.Copy(b, a)
}

func httpConnectProxy(t *testing.T) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil || req.Method != "CONNECT" {
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer up.Close()
				c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				pipe(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func socks5Proxy(t *testing.T) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 262)
				if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
					return
				}
				io.ReadFull(c, buf[:buf[1]])
				c.Write([]byte{5, 0})
				io.ReadFull(c, buf[:4]) // ver cmd rsv atyp
				var host string
				switch buf[3] {
				case 1:
					io.ReadFull(c, buf[:4])
					host = net.IP(buf[:4]).String()
				case 3:
					io.ReadFull(c, buf[:1])
					n := int(buf[0])
					io.ReadFull(c, buf[:n])
					host = string(buf[:n])
				}
				io.ReadFull(c, buf[:2])
				port := binary.BigEndian.Uint16(buf[:2])
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				pipe(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func readPong(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "pong" {
		t.Fatalf("tunnel broken: %q %v", b, err)
	}
}

func TestDialThroughHTTPProxy(t *testing.T) {
	c, err := Dial(context.Background(), Proxy{Kind: "http", Addr: httpConnectProxy(t)}, target(t), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	readPong(t, c)
}

func TestDialThroughSOCKS5(t *testing.T) {
	c, err := Dial(context.Background(), Proxy{Kind: "socks5", Addr: socks5Proxy(t)}, target(t), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	readPong(t, c)
}

func TestDialFailsWhenUpstreamDown(t *testing.T) {
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	for _, p := range []Proxy{{Kind: "http", Addr: httpConnectProxy(t)}, {Kind: "socks5", Addr: socks5Proxy(t)}} {
		if _, err := Dial(context.Background(), p, deadAddr, 2*time.Second); err == nil {
			t.Errorf("%s: want error when target is unreachable", p.Kind)
		}
	}
	if _, err := Dial(context.Background(), Proxy{Kind: "http", Addr: deadAddr}, "1.1.1.1:443", time.Second); err == nil {
		t.Error("want error when the proxy itself is down")
	}
}
