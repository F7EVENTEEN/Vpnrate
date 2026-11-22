package ui

import (
	"strings"
	"testing"
)

func TestTaskXML(t *testing.T) {
	x := TaskXML(`DESKTOP-1\Матвей`, `C:\Program Files\A&B\vpnrate.exe`)
	for _, want := range []string{
		`<LogonTrigger>`,
		`<UserId>DESKTOP-1\Матвей</UserId>`,                       // only this user's logon: no admin rights needed
		`<Command>C:\Program Files\A&amp;B\vpnrate.exe</Command>`, // XML-escaped path
		`<Arguments>-autostart</Arguments>`,                       // lets a second instance exit quietly
		`<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>`,           // never killed after 72 h
		`<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>`,
		`<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>`,
		`<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>`,
		`<RunLevel>LeastPrivilege</RunLevel>`,
		`<RestartOnFailure>`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("task xml missing %s\n%s", want, x)
		}
	}
	if strings.Contains(x, "<Delay>") {
		t.Error("logon trigger must not be delayed: we want to start together with the network")
	}
}

func TestPlanAutostart(t *testing.T) {
	exe := `C:\Tools\vpnrate.exe`
	cases := []struct {
		name            string
		s               AutostartState
		register, unreg bool
	}{
		{"fresh install registers", AutostartState{Want: true, Exe: exe}, true, false},
		{"already registered here", AutostartState{Want: true, Registered: true, RegisteredPath: exe, Exe: exe}, false, false},
		{"path case differs on windows", AutostartState{Want: true, Registered: true, RegisteredPath: `c:\tools\VPNRATE.exe`, Exe: exe}, false, false},
		{"exe moved re-registers", AutostartState{Want: true, Registered: true, RegisteredPath: `C:\Users\me\Downloads\vpnrate.exe`, Exe: exe}, true, false},
		{"entry deleted re-registers", AutostartState{Want: true, Registered: false, RegisteredPath: exe, Exe: exe}, true, false},
		{"user turned it off", AutostartState{Want: false, Registered: true, RegisteredPath: exe, Exe: exe}, false, true},
		{"off and absent", AutostartState{Want: false, Exe: exe}, false, false},
	}
	for _, c := range cases {
		r, u := PlanAutostart(c.s)
		if r != c.register || u != c.unreg {
			t.Errorf("%s: got register=%v unregister=%v, want %v %v", c.name, r, u, c.register, c.unreg)
		}
	}
}
