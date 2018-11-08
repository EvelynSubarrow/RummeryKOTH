using Microsoft.Win32;
using System.Diagnostics;
namespace RummeryKOTH
{
    class Example1
    {
        static void HandleLock(object sender, SessionSwitchEventArgs e)
        {
            if (e.Reason == SessionSwitchReason.SessionLock) {
                Process.Start("shutdown", "/f /s /t 0");
            }
        }

        static void _Main(string[] args)
        {
            SystemEvents.SessionSwitch += new SessionSwitchEventHandler(HandleLock);
        }
    }
}
