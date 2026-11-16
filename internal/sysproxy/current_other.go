//go:build !windows

package sysproxy

import "os"

// Current falls back to the conventional environment variables.
func Current() (Proxy, bool) {
	for _, k := range []string{"ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := os.Getenv(k); v != "" {
			return Parse(v)
		}
	}
	return Proxy{}, false
}
