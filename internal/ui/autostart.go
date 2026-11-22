package ui

import (
	"fmt"
	"strings"
)

// Autostart is on by default and self-healing: every launch checks that the
// entry exists and points at the running exe, and fixes it if not. A
// one-time "first run" decision proved fragile (a single run with
// -no-autostart disabled it for good).

type AutostartState struct {
	Want           bool   // user preference (default true)
	Registered     bool   // an autostart entry exists right now
	RegisteredPath string // exe path we registered last time
	Exe            string // the running exe
}

func PlanAutostart(s AutostartState) (register, unregister bool) {
	if !s.Want {
		return false, s.Registered
	}
	return !s.Registered || !strings.EqualFold(s.RegisteredPath, s.Exe), false
}

// TaskXML is a Task Scheduler definition that starts the agent the moment
// this user logs on: no trigger delay (unlike the Run key, which Windows
// holds back), never stopped for running long or on battery, restarted if
// it fails to start. A logon trigger scoped to the current user needs no
// admin rights.
func TaskXML(user, exe string) string {
	esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>VPN Rate: watches your connection stability and VPN leaks.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>%[1]s</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>%[1]s</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>5</Count>
    </RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%[2]s</Command>
      <Arguments>-autostart</Arguments>
    </Exec>
  </Actions>
</Task>
`, esc(user), esc(exe))
}
