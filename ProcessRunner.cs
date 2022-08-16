//
// dkxce.ProcessRunner
// https://github.com/dkxce/ProcessRunner
//

using System;
using System.Collections;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;

namespace dkxce
{
    public class ProcessRunner
    {               
        #region Structs
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_ATTRIBUTES
        {
            public uint nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;

        }

        internal enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        internal enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }
        #endregion Structs

        #region WinAPI
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);


        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx", SetLastError = true)]
        private static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            Int32 ImpersonationLevel,
            Int32 dwTokenType,
            ref IntPtr phNewToken);


        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            ref IntPtr TokenHandle);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);


        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);


        [DllImport("kernel32.dll")]
        private static extern int WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQueryUserToken(int sessionId, out IntPtr Token);

        #endregion WinAPI

        #region Consts
        private const short SW_SHOW = 5;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const int GENERIC_ALL_ACCESS = 0x10000000;
        private const int STARTF_USESHOWWINDOW = 0x00000001;
        private const int STARTF_FORCEONFEEDBACK = 0x00000040;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        #endregion Consts

        public enum ElevationType
        {
            Default = 1,
            Full = 2,
            Limited = 3
        }

        #region Private

        /// <summary>
        ///     Launch Process (Process Start) with Specified Token and ProcessStartInfo
        /// </summary>
        /// <param name="appName"></param>
        /// <param name="arguments"></param>
        /// <param name="token"></param>
        /// <param name="envBlock"></param>
        /// <param name="psi"></param>
        /// <returns></returns>
        private static (bool started, uint processId) LaunchProcessWithToken(string appName, string arguments, IntPtr token, IntPtr envBlock, ProcessStartInfo psi = null)
        {                
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            SECURITY_ATTRIBUTES saProcess = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES saThread = new SECURITY_ATTRIBUTES();
            saProcess.nLength = (uint)Marshal.SizeOf(saProcess);
            saThread.nLength = (uint)Marshal.SizeOf(saThread);
                
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(si);
            si.lpDesktop = @"WinSta0\Default";
            si.dwFlags = STARTF_USESHOWWINDOW | STARTF_FORCEONFEEDBACK;
            si.wShowWindow = psi == null ? SW_SHOW : (short)psi.WindowStyle; //SW_SHOW;

            if (CreateProcessAsUser(
                token, appName, arguments,
                ref saProcess, ref saThread, false,
                CREATE_UNICODE_ENVIRONMENT, envBlock, null,
                ref si, out pi))
                return (true, pi.dwProcessId);
            return (false, 0);
        }

        /// <summary>
        ///     Get Copy of Process Token
        /// </summary>
        /// <param name="processId"></param>
        /// <returns></returns>
        private static IntPtr GetCopyOfProcessToken(int processId)
        {
            IntPtr copiedToken = IntPtr.Zero;
            IntPtr token = IntPtr.Zero;            
            Process p = Process.GetProcessById(processId);

            bool retVal = OpenProcessToken(p.Handle, TOKEN_DUPLICATE, ref token);
            if (retVal == true)
            {
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = (uint)Marshal.SizeOf(sa);
                DuplicateTokenEx(token, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,ref sa,
                    (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, (int)TOKEN_TYPE.TokenPrimary, ref copiedToken);
                CloseHandle(token);                    
            };
            return copiedToken;
        }

        private static Dictionary<String, String> GetProcessEnvironmentByToken(IntPtr token)
        {
            IntPtr envBlock = IntPtr.Zero;
            CreateEnvironmentBlock(ref envBlock, token, false);
            Dictionary<String, String> uenv = new Dictionary<string, string>();
            if (envBlock != IntPtr.Zero)
            {                    
                try
                {
                    IntPtr ptr = envBlock;
                    while (true)
                    {
                        string str = Marshal.PtrToStringUni(ptr);
                        if (str.Length == 0) break;                            
                        ptr = new IntPtr(ptr.ToInt64() + (str.Length + 1 /* char \0 */) * sizeof(char));
                        string[] kv = str.Split('=');
                        uenv.Add(kv[0], kv[1]);
                    };
                }
                finally
                {
                    DestroyEnvironmentBlock(envBlock);
                };
            };                
            return uenv;
        }        

        private static byte[] CreateEnvironment(Dictionary<string, string> env)
        {
            MemoryStream ms = new MemoryStream();
            StreamWriter w = new StreamWriter(ms, Encoding.Unicode);
            w.Flush();
            ms.Position = 0;
            Char nullChar = (char)0;
            foreach (string k in env.Keys)
            {
                w.Write("{0}={1}", k, env[k]);
                w.Write(nullChar);
            };
            w.Write(nullChar);
            w.Write(nullChar);
            w.Flush();
            ms.Flush();
            byte[] data = ms.ToArray();
            return data;
        }

        private static ElevationType GetProcessElevationTypeByToken(IntPtr hToken)
        {
            if (hToken != IntPtr.Zero)
            {
                uint ret = 0;
                GetTokenInformation(hToken, 18 /*TokenElevationType*/, IntPtr.Zero, 0, out ret);
                IntPtr tokenInformation = Marshal.AllocHGlobal((int)ret);

                GetTokenInformation(hToken, 18 /*TokenElevationType*/, tokenInformation, ret, out ret);

                var value = Marshal.ReadInt32(tokenInformation, 0);
                Marshal.FreeHGlobal(tokenInformation);
                return (ElevationType)value;
            }
            else
            {
                return ElevationType.Default;
            };
        }

        /// <summary>
        ///     Get Process Token
        /// </summary>
        /// <param name="querySessionToken"></param>
        /// <param name="mode"></param>
        /// <returns></returns>
        private static IntPtr GetTokenForUserInteractiveProcess(bool querySessionToken = false, byte mode = 0 /* 0 - default, 1 - elevated priority, 2 - only elevated */)
        {
            int processId = -1;
            int sessid = -1;
            
            try { sessid = WTSGetActiveConsoleSessionId(); } catch { };
            if ((sessid >= 0) && querySessionToken && WTSQueryUserToken(sessid, out IntPtr tkn)) return tkn;

            try
            {
                if ((mode == 0) || (mode == 1)) // (default, elevated priority)
                {
                    Process[] ps = Process.GetProcessesByName("explorer");
                    foreach (Process p in ps) if (p.SessionId == sessid) processId = p.Id;
                };
            }
            catch { };

            if ((mode == 1) || (mode == 2)) // (elevated priority, only elevated)
            {
                Process[] ps = Process.GetProcessesByName("explorer");
                foreach (Process p in ps)
                {
                    if (p.SessionId != sessid) continue;
                    IntPtr token = IntPtr.Zero;
                    try
                    {
                        token = GetCopyOfProcessToken(processId);
                        if (token != IntPtr.Zero)
                        {
                            ElevationType eType = GetProcessElevationTypeByToken(token);
                            if (eType == ElevationType.Full)
                                return token;
                        };
                    }
                    catch { };
                    if (token != IntPtr.Zero) try { CloseHandle(token); } catch { };
                };
            };

            try { if (processId > 1) return GetCopyOfProcessToken(processId); } catch { };

            return IntPtr.Zero;
        }

        #endregion Private

        /// <summary>
        ///     Launch Process as Current Logon User (UserInteractive), WinSvc Cannot Start Elevated Process (Win7+)
        /// </summary>
        /// <param name="psi"></param>
        /// <param name="querySessionToken"></param>
        /// <returns></returns>
        public static (bool started, Process process) Start(ProcessStartInfo psi, bool querySessionToken = false)
        {
            IntPtr token = GetTokenForUserInteractiveProcess(querySessionToken);
            if (token != IntPtr.Zero)
            {                
                Dictionary <String, String> uenv = new Dictionary<string, string>();
                foreach (DictionaryEntry de in psi.EnvironmentVariables)
                    uenv[de.Key.ToString()] = de.Value.ToString();
                byte[] env = CreateEnvironment(uenv);
                IntPtr eBlock = Marshal.AllocHGlobal(env.Length);
                Marshal.Copy(env, 0, eBlock, env.Length);
                (bool ok, uint pid) = LaunchProcessWithToken(null, $"\"{psi.FileName}\" {psi.Arguments}", token, eBlock, psi);                
                System.Threading.Thread.Sleep(750); // ensure that launching app gets all environment variables
                Marshal.FreeHGlobal(eBlock);
                CloseHandle(token);
                if (ok) return (true, Process.GetProcessById((int)pid));
            };
            return (false, null);
        }

        /// <summary>
        ///     Launch Process as Current Logon User (UserInteractive), WinSvc Cannot Start Elevated Process (Win7+)
        /// </summary>
        /// <param name="cmdLine"></param>
        /// <param name="querySessionToken"></param>
        /// <returns></returns>
        public static (bool started, Process process) Start(string cmdLine, bool querySessionToken = false)
        {
            IntPtr token = GetTokenForUserInteractiveProcess(querySessionToken);
            if (token != IntPtr.Zero)
            {
                byte[] env = CreateEnvironment(GetProcessEnvironmentByToken(token));
                IntPtr eBlock = Marshal.AllocHGlobal(env.Length);
                Marshal.Copy(env, 0, eBlock, env.Length);
                (bool ok, uint pid) = LaunchProcessWithToken(null, cmdLine, token, eBlock, null);
                System.Threading.Thread.Sleep(750); // ensure that launching app gets all environment variables
                Marshal.FreeHGlobal(eBlock);
                CloseHandle(token);
                if (ok) return (true, Process.GetProcessById((int)pid));
            };
            return (false, null);
        }
    }
}
