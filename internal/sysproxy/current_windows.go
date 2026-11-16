package sysproxy

import "golang.org/x/sys/windows/registry"

const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// Current reads the per-user system proxy (what v2rayN & co. toggle).
// PAC scripts (AutoConfigURL) are not evaluated.
func Current() (Proxy, bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE)
	if err != nil {
		return Proxy{}, false
	}
	defer k.Close()
	if on, _, err := k.GetIntegerValue("ProxyEnable"); err != nil || on == 0 {
		return Proxy{}, false
	}
	s, _, err := k.GetStringValue("ProxyServer")
	if err != nil {
		return Proxy{}, false
	}
	return Parse(s)
}
