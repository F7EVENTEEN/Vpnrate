package ui

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"
)

const (
	runKey    = `Software\Microsoft\Windows\CurrentVersion\Run`
	valueName = "VPN Rate"
	// Toasts need a registered AppUserModelID; PowerShell's is always present.
	toastAppID     = `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe`
	createNoWindow = 0x08000000
)

const taskName = "VPN Rate"

// AutostartRegistered reports whether a scheduled task or Run entry exists.
func AutostartRegistered() bool {
	if hidden("schtasks.exe", "/Query", "/TN", taskName).Run() == nil {
		return true
	}
	return runValueExists()
}

// EnableAutostart registers a logon task for exe; if Task Scheduler refuses,
// it falls back to the Run key. Only one mechanism is kept, so the agent
// is never launched twice. It returns which one was used.
func EnableAutostart(exe string) (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "vpnrate-task-*.xml")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	// schtasks wants UTF-16 for non-ASCII user names and paths.
	u16 := utf16.Encode([]rune(TaskXML(u.Username, exe)))
	b := make([]byte, 2+2*len(u16))
	b[0], b[1] = 0xFF, 0xFE
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(b[2+2*i:], c)
	}
	f.Write(b)
	f.Close()
	if out, err := hidden("schtasks.exe", "/Create", "/TN", taskName, "/XML", f.Name(), "/F").CombinedOutput(); err == nil {
		setRunValue("")
		return "task", nil
	} else {
		log.Printf("autostart: scheduled task failed (%v: %s), using Run key", err, bytes.TrimSpace(out))
	}
	return "run", setRunValue(`"` + exe + `" -autostart`)
}

func DisableAutostart() error {
	hidden("schtasks.exe", "/Delete", "/TN", taskName, "/F").Run()
	return setRunValue("")
}

func hidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd
}

func runValueExists() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(valueName)
	return err == nil
}

// setRunValue writes the Run entry, or deletes it when v is empty.
func setRunValue(v string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if v == "" {
		if err := k.DeleteValue(valueName); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	return k.SetStringValue(valueName, v)
}

// Notify shows a Windows toast via a hidden PowerShell process.
func Notify(title, message string) error {
	x := func(s string) string {
		s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
		return strings.ReplaceAll(s, "'", "''") // inside a PowerShell single-quoted string
	}
	script := fmt.Sprintf(`[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml('<toast><visual><binding template="ToastGeneric"><text>%s</text><text>%s</text></binding></visual></toast>')
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('%s').Show([Windows.UI.Notifications.ToastNotification]::new($x))`,
		x(title), x(message), toastAppID)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd.Start()
}

func OpenURL(u string) error {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	return cmd.Start()
}
