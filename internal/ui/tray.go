package ui

import (
	"fmt"
	"image/color"
	"log"
	"runtime/debug"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/F7EVENTEEN/Vpnrate/internal/monitor"
	"github.com/F7EVENTEEN/Vpnrate/internal/store"
)

type Tray struct {
	Mon    *monitor.Monitor
	URL    string
	Notify bool
	OnQuit func()
	// Autostart is the current preference; SetAutostart applies and saves it.
	Autostart    bool
	SetAutostart func(on bool) error
	notifyMu     sync.Mutex
	lastToast    map[string]time.Time
}

// Run blocks until the user picks Quit.
func (t *Tray) Run() {
	t.lastToast = map[string]time.Time{}
	systray.Run(t.ready, func() {
		if t.OnQuit != nil {
			t.OnQuit()
		}
	})
}

func (t *Tray) ready() {
	icons := map[color.RGBA][]byte{}
	for _, c := range []color.RGBA{Green, Yellow, Red, Gray} {
		icons[c] = CircleICO(c)
	}
	systray.SetIcon(icons[Gray])
	systray.SetTitle("VPN Rate")
	systray.SetTooltip("VPN Rate — checking…")

	mIP := systray.AddMenuItem("IP: …", "")
	mIP.Disable()
	mTrust := systray.AddMenuItem("Trust: …", "")
	mTrust.Disable()
	mStab := systray.AddMenuItem("Stability: …", "")
	mStab.Disable()
	systray.AddSeparator()
	mOpen := systray.AddMenuItem("Open dashboard", "")
	mRecheck := systray.AddMenuItem("Recheck now", "")
	systray.AddSeparator()
	mAuto := systray.AddMenuItemCheckbox("Start with Windows", "", t.Autostart)
	mNotify := systray.AddMenuItemCheckbox("Notifications", "", t.Notify)
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "")
	systray.SetOnTapped(func() { OpenURL(t.URL) })

	t.Mon.Subscribe(t.onEvent)
	go keepTrayIcon(make(chan struct{}))

	update := func() {
		s := t.Mon.Status()
		c := Green
		switch {
		case s.Starting:
			c = Gray
		case !s.Online:
			c = Red
		case !s.Checked:
			c = Gray
		case s.Trust.Score < 50 || s.Stability.Score < 50:
			c = Red
		case s.Trust.Score < 70 || s.Stability.Score < 70:
			c = Yellow
		}
		systray.SetIcon(icons[c])
		ip := s.PublicV4
		if ip == "" {
			ip = "…"
		}
		where := ""
		if s.Exit != nil {
			where = " · " + s.Exit.Country
		}
		mIP.SetTitle(fmt.Sprintf("IP: %s%s", ip, where))
		mTrust.SetTitle(fmt.Sprintf("Trust: %d/100", s.Trust.Score))
		mStab.SetTitle(fmt.Sprintf("Stability: %d/100 · uptime %.2f%%", s.Stability.Score, s.Uptime24h))
		state := "online"
		if !s.Online {
			state = "OFFLINE"
		}
		systray.SetTooltip(fmt.Sprintf("VPN Rate — %s\nIP %s%s\nTrust %d · Stability %d", state, ip, where, s.Trust.Score, s.Stability.Score))
	}
	go func() {
		defer recoverLog("tray update")
		update()
		tk := time.NewTicker(5 * time.Second)
		for range tk.C {
			update()
		}
	}()

	go func() {
		defer recoverLog("tray menu")
		for {
			select {
			case <-mOpen.ClickedCh:
				OpenURL(t.URL)
			case <-mRecheck.ClickedCh:
				t.Mon.Recheck()
			case <-mAuto.ClickedCh:
				on := !mAuto.Checked()
				if err := t.SetAutostart(on); err != nil {
					log.Printf("autostart: %v", err)
					continue
				}
				if on {
					mAuto.Check()
				} else {
					mAuto.Uncheck()
				}
			case <-mNotify.ClickedCh:
				t.notifyMu.Lock()
				t.Notify = !t.Notify
				on := t.Notify
				t.notifyMu.Unlock()
				if on {
					mNotify.Check()
				} else {
					mNotify.Uncheck()
				}
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

// onEvent turns monitor events into toasts. Short blips are ignored: we only
// announce an outage once it has lasted 30 seconds.
func (t *Tray) onEvent(e store.Event) {
	switch e.Kind {
	case store.KindOffline:
		go func() {
			time.Sleep(30 * time.Second)
			if !t.Mon.Status().Online {
				t.toast("offline", "Connection lost", "No internet for 30+ seconds")
			}
		}()
	case store.KindOnline:
		if d, _ := e.Data["duration_s"].(float64); d >= 30 {
			t.toast("online", "Connection restored", e.Message)
		}
	case store.KindVPNDown:
		t.toast("vpn", "VPN disconnected", e.Message)
	case store.KindIPChanged:
		t.toast("ip", "Exit IP changed", e.Message)
	case store.KindLeak:
		t.toast("leak:"+fmt.Sprint(e.Data["type"]), "Leak detected", e.Message)
	}
}

// toast rate-limits per key so a flapping connection doesn't spam.
func (t *Tray) toast(key, title, msg string) {
	t.notifyMu.Lock()
	defer t.notifyMu.Unlock()
	if !t.Notify || time.Since(t.lastToast[key]) < 2*time.Minute {
		return
	}
	t.lastToast[key] = time.Now()
	if err := Notify(title, msg); err != nil {
		log.Printf("notify: %v", err)
	}
}

func recoverLog(where string) {
	if r := recover(); r != nil {
		log.Printf("%s panicked: %v\n%s", where, r, debug.Stack())
	}
}
