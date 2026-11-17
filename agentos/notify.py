"""
Desktop notifications (best effort): used when an approval is waiting in the
dashboard, or a scheduled job finishes. Tries Linux `notify-send`, then a
Windows toast via PowerShell (works from WSL), and otherwise does nothing.
"""

import shutil
import subprocess


def notify(title: str, message: str) -> bool:
    try:
        if shutil.which("notify-send"):
            subprocess.run(["notify-send", "-a", "Agentic OS", title, message[:200]], timeout=5, check=False)
            return True
        ps = shutil.which("powershell.exe")
        if ps:
            safe = lambda s: s.replace("'", "''")[:200]   # noqa: E731
            script = ("[void][Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,"
                      "ContentType=WindowsRuntime];$t=[Windows.UI.Notifications.ToastNotificationManager]::"
                      "GetTemplateContent(1);$x=$t.GetElementsByTagName('text');"
                      f"$x.Item(0).AppendChild($t.CreateTextNode('{safe(title)}: {safe(message)}'))|Out-Null;"
                      "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Agentic OS')"
                      ".Show([Windows.UI.Notifications.ToastNotification]::new($t))")
            subprocess.run([ps, "-NoProfile", "-Command", script], timeout=10, check=False,
                           capture_output=True)
            return True
    except (OSError, subprocess.TimeoutExpired):
        pass
    return False
