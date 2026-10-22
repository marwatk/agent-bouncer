// Package notify shows best-effort desktop notifications.
package notify

import (
	"os"
	"os/exec"
	"runtime"
)

const windowsToast = `
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$x = $t.GetElementsByTagName('text')
$x.Item(0).AppendChild($t.CreateTextNode($env:BOUNCER_NOTIFY_TITLE)) > $null
$x.Item(1).AppendChild($t.CreateTextNode($env:BOUNCER_NOTIFY_BODY)) > $null
$id = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($t))
`

// Send displays a notification. Errors are ignored: notifications are a
// convenience, never the only way to see a pending approval.
func Send(title, body string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("/usr/bin/osascript",
			"-e", "on run argv",
			"-e", `display notification (item 2 of argv) with title (item 1 of argv) sound name "Ping"`,
			"-e", "end run", title, body)
	case "windows":
		cmd = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", windowsToast)
		cmd.Env = append(os.Environ(), "BOUNCER_NOTIFY_TITLE="+title, "BOUNCER_NOTIFY_BODY="+body)
	default:
		path, err := exec.LookPath("notify-send")
		if err != nil {
			return
		}
		cmd = exec.Command(path, "--app-name=agent-bouncer", title, body)
	}
	_ = cmd.Run()
}
