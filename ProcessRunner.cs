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

namespace MSolSvc
{
    public class ProcessRunner
    {
        #region WinAPI

        #region DLL Calls

        #region kernel32.dll
        [DllImport("kernel32.dll")]
        private static extern uint GetLastError();

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles, CreationFlags dwCreationFlags, IntPtr lpEnvironment,
            string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        #endregion kernel32.dll

        #region advapi32.dll

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AllocateAndInitializeSid(
            ref SidIdentifierAuthority pIdentifierAuthority,
            byte nSubAuthorityCount, int dwSubAuthority0, int dwSubAuthority1, int dwSubAuthority2, int dwSubAuthority3,
            int dwSubAuthority4, int dwSubAuthority5, int dwSubAuthority6, int dwSubAuthority7, out IntPtr pSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupAccountSid(
            string lpSystemName, 
            [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, StringBuilder lpName, 
            ref uint cchName, StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupAccountSid(
            string lpSystemName, 
            IntPtr pSid, StringBuilder lpName,
            ref uint cchName, StringBuilder ReferencedDomainName,
            ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupAccountSid(
            [MarshalAs(UnmanagedType.LPTStr)] string strSystemName,
            IntPtr pSid, IntPtr pName, 
            ref uint cchName, IntPtr pReferencedDomainName, 
            ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool EqualSid(IntPtr pSid1, IntPtr pSid2);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertStringSidToSid(string StringSid, out IntPtr ptrSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetLengthSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation,
            uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetTokenInformation(
            IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation, int TokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(IntPtr handle,
            SE_OBJECT_TYPE objectType, SECURITY_INFORMATION securityInfo,
            out IntPtr sidOwner, out IntPtr sidGroup, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges(
           IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, IntPtr PreviousState, IntPtr ReturnLengthInBytes);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName, string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessWithTokenW(
            IntPtr hToken, LogonFlags dwLogonFlags, 
            string lpApplicationName, string lpCommandLine,
            CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, 
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DuplicateTokenEx(
            IntPtr hExistingToken, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, 
            Int32 ImpersonationLevel, Int32 dwTokenType, ref IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateRestrictedToken(
            IntPtr TokenHandle, int Flags, int DisableSidCount,
            IntPtr SidsToDisable, int DeletePrivilegeCount,
            IntPtr PrivilegesToDelete, int RestrictedSidCount,
            IntPtr SidsToRestrict, ref IntPtr phNewToken);

        #endregion advapi32.dll

        #region userenv.dll

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);        

        #endregion userenv.dll               

        #region wtsapi32.dll

        [DllImport("wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSQueryUserToken(int sessionId, out IntPtr Token);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int WTSGetActiveConsoleSessionId();

        #endregion wtsapi32.dll

        #region ntdll.dll

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSetInformationProcess(IntPtr procHandle, _PROCESS_INFORMATION_CLASS processInformationClass, IntPtr patHandle, int patSize);

        #endregion ntdll.dll

        #endregion DLL Calls

        #region Structs

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public uint nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
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

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public uint HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_MANDATORY_LABEL
        {
            public IntPtr pSid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SidIdentifierAuthority
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
            public byte[] Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct _TOKEN_GROUPS
        {
            public int GroupCount;
            public TOKEN_MANDATORY_LABEL[] Groups;
        }

        #endregion Structs

        #region Enums

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        private enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        private enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE,
            SE_FILE_OBJECT,
            SE_SERVICE,
            SE_PRINTER,
            SE_REGISTRY_KEY,
            SE_LMSHARE,
            SE_KERNEL_OBJECT,
            SE_WINDOW_OBJECT,
            SE_DS_OBJECT,
            SE_DS_OBJECT_ALL,
            SE_PROVIDER_DEFINED_OBJECT,
            SE_WMIGUID_OBJECT,
            SE_REGISTRY_WOW64_32KEY
        }

        private enum SECURITY_INFORMATION
        {
            OWNER_SECURITY_INFORMATION = 1,
            GROUP_SECURITY_INFORMATION = 2,
            DACL_SECURITY_INFORMATION = 4,
            SACL_SECURITY_INFORMATION = 8,
        }

        private enum TOKEN_INFORMATION_CLASS
        {
            /// <summary>
            /// The buffer receives a TOKEN_USER structure that contains the user account of the token.
            /// </summary>
            TokenUser = 1,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token.
            /// </summary>
            TokenGroups,

            /// <summary>
            /// The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
            /// </summary>
            TokenPrivileges,

            /// <summary>
            /// The buffer receives a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects.
            /// </summary>
            TokenOwner,

            /// <summary>
            /// The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects.
            /// </summary>
            TokenPrimaryGroup,

            /// <summary>
            /// The buffer receives a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects.
            /// </summary>
            TokenDefaultDacl,

            /// <summary>
            /// The buffer receives a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
            /// </summary>
            TokenSource,

            /// <summary>
            /// The buffer receives a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token.
            /// </summary>
            TokenType,

            /// <summary>
            /// The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
            /// </summary>
            TokenImpersonationLevel,

            /// <summary>
            /// The buffer receives a TOKEN_STATISTICS structure that contains various token statistics.
            /// </summary>
            TokenStatistics,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token.
            /// </summary>
            TokenRestrictedSids,

            /// <summary>
            /// The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token.
            /// </summary>
            TokenSessionId,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
            /// </summary>
            TokenGroupsAndPrivileges,

            /// <summary>
            /// Reserved.
            /// </summary>
            TokenSessionReference,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
            /// </summary>
            TokenSandBoxInert,

            /// <summary>
            /// Reserved.
            /// </summary>
            TokenAuditPolicy,

            /// <summary>
            /// The buffer receives a TOKEN_ORIGIN value.
            /// </summary>
            TokenOrigin,

            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.
            /// </summary>
            TokenElevationType,

            /// <summary>
            /// The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle to another token that is linked to this token.
            /// </summary>
            TokenLinkedToken,

            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION structure that specifies whether the token is elevated.
            /// </summary>
            TokenElevation,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has ever been filtered.
            /// </summary>
            TokenHasRestrictions,

            /// <summary>
            /// The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies security information contained in the token.
            /// </summary>
            TokenAccessInformation,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is allowed for the token.
            /// </summary>
            TokenVirtualizationAllowed,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is enabled for the token.
            /// </summary>
            TokenVirtualizationEnabled,

            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level.
            /// </summary>
            TokenIntegrityLevel,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has the UIAccess flag set.
            /// </summary>
            TokenUIAccess,

            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the token's mandatory integrity policy.
            /// </summary>
            TokenMandatoryPolicy,

            /// <summary>
            /// The buffer receives the token's logon security identifier (SID).
            /// </summary>
            TokenLogonSid,

            /// <summary>
            /// The maximum value for this enumeration
            /// </summary>
            MaxTokenInfoClass
        }

        private enum _PROCESS_INFORMATION_CLASS
        {
            ProcessBasicInformation,
            ProcessQuotaLimits,
            ProcessIoCounters,
            ProcessVmCounters,
            ProcessTimes,
            ProcessBasePriority,
            ProcessRaisePriority,
            ProcessDebugPort,
            ProcessExceptionPort,
            ProcessAccessToken,
            ProcessLdtInformation,
            ProcessLdtSize,
            ProcessDefaultHardErrorMode,
            ProcessIoPortHandlers,
            ProcessPooledUsageAndLimits,
            ProcessWorkingSetWatch,
            ProcessUserModeIOPL,
            ProcessEnableAlignmentFaultFixup,
            ProcessPriorityClass,
            ProcessWx86Information,
            ProcessHandleCount,
            ProcessAffinityMask,
            ProcessPriorityBoost,
            MaxProcessInfoClass
        }

        [Flags]
        private enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [Flags]
        private enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }

        [Flags]
        private enum LogonFlags
        {
            LOGON_WITH_PROFILE = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY = 0x00000002
        }

        #endregion Enums     

        #region Consts

        private const short SW_SHOW = 5;
        private const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        private const uint STANDARD_RIGHTS_READ = 0x00020000;
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_IMPERSONATE = 0x0004;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_QUERY_SOURCE = 0x0010;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_ADJUST_GROUPS = 0x0040;
        private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private const uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        private const uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);
        private const int GENERIC_ALL_ACCESS = 0x10000000;
        private const int STARTF_USESHOWWINDOW = 0x00000001;
        private const int STARTF_FORCEONFEEDBACK = 0x00000040;
        private const string MAIN_INTERACTIVE_PROCESS = "explorer";
        private const int NtSecurityAuthority = 5;
        private const int SECURITY_BUILTIN_DOMAIN_RID = 0x00000020;
        private const int DOMAIN_ALIAS_RID_ADMINS = 0x00000220;
        private const uint SE_GROUP_ENABLED = 0x00000004;
        private const uint SE_GROUP_USE_FOR_DENY_ONLY = 0x10;
        private const string MANDATORY_ZERO_LEVEL = "S-1-16-0";
        private const string MANDATORY_LOW_LEVEL = "S-1-16-4096";
        private const string MANDATORY_MEDIUM_LEVEL = "S-1-16-8192";
        private const string MANDATORY_HIGH_LEVEL = "S-1-16-12288";
        private const string MANDATORY_SYSTEM_LEVEL = "S-1-16-16384";
        private const string MANDATORY_PROTECTED_LEVEL = "S-1-16-20480";
        private const string MANDATORY_SECURE_LEVEL = "S-1-16-28672";

        #endregion Consts

        #endregion WinAPI 

        #region InProc Enums

        private enum ElevationType
        {
            Default = 1,
            Full = 2,
            Limited = 3
        }

        #endregion InProc Enums        

        #region Private        

        private struct KERNEL_PROCESS_ACCESS_TOKEN
        {
            public IntPtr Token;
            public IntPtr Thread;
        }

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
            si.wShowWindow = psi == null ? SW_SHOW : (short)psi.WindowStyle;

            string dir = null;
            if (!string.IsNullOrEmpty(arguments)) { try { dir = Path.GetDirectoryName(arguments); } catch { }; };
            if (!string.IsNullOrEmpty(appName)) { try { dir = Path.GetDirectoryName(appName); } catch { }; };

            // Good, The Right One
            if (CreateProcessAsUser(
                token, appName, arguments,
                ref saProcess, ref saThread, false,
                CreationFlags.UnicodeEnvironment, envBlock, dir,
                ref si, out pi))
                    return (true, pi.dwProcessId);

            //// MayBe, but Not
            //if (CreateProcess(
            //    appName, arguments,
            //    ref saProcess, ref saThread, false,
            //    CreationFlags.UnicodeEnvironment | CreationFlags.Suspended, envBlock, dir,
            //    ref si, out pi))
            //{
            //    SetProcessToken(pi.hProcess, pi.dwProcessId, token);
            //    ResumeProcess((int)pi.dwProcessId);
            //    return (true, pi.dwProcessId);
            //};

            //// MayBe, but Not
            //if (CreateProcessWithTokenW(
            //    token, LogonFlags.LOGON_WITH_PROFILE, appName, arguments,
            //    CreationFlags.UnicodeEnvironment, envBlock, dir,
            //    ref si, out pi))
            //      return (true, pi.dwProcessId);

            return (false, 0);
        }

        private static bool SetProcessToken(IntPtr pHandle, uint procId, IntPtr token)
        {
            // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FNtSetInformationProcess.html
            
            KERNEL_PROCESS_ACCESS_TOKEN pat = new KERNEL_PROCESS_ACCESS_TOKEN();
            pat.Token = token;
            pat.Thread = IntPtr.Zero;

            int sPat = Marshal.SizeOf(typeof(KERNEL_PROCESS_ACCESS_TOKEN));
            IntPtr pPat = Marshal.AllocHGlobal(sPat);
            Marshal.StructureToPtr<KERNEL_PROCESS_ACCESS_TOKEN>(pat, pPat, false);
            try
            {
                bool ok = (NtSetInformationProcess(pHandle, _PROCESS_INFORMATION_CLASS.ProcessAccessToken, pPat, sPat) == 0);
                uint err = GetLastError();
                ServiceLog.WriteDatedLn($"NtSetInformationProcess: {procId} {pHandle} {ok} {err}");
                return ok;
            }
            catch (Exception ex)
            {
                ServiceLog.WriteDatedLn($"NtSetInformationProcess: {procId} {pHandle} False {ex.Message}");
                return false; 
            }
            finally { Marshal.FreeHGlobal(pPat); };            
        }

        private static void SuspendProcess(int pid)
        {
            Process process = Process.GetProcessById(pid);
            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
                if (pOpenThread == IntPtr.Zero) continue;
                SuspendThread(pOpenThread);
                CloseHandle(pOpenThread);
            };
        }

        private static void ResumeProcess(int pid)
        {
            Process process = Process.GetProcessById(pid);
            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);
                if (pOpenThread == IntPtr.Zero) continue;
                int suspendCount = 0;
                do { suspendCount = ResumeThread(pOpenThread); } while (suspendCount > 0);
                CloseHandle(pOpenThread);
            };
        }

        private static IntPtr GetCopyOfProcessToken(int processId)
        {
            IntPtr copiedToken = IntPtr.Zero;
            IntPtr token = IntPtr.Zero;            
            Process p = Process.GetProcessById(processId);

            bool retVal = OpenProcessToken(p.Handle, TOKEN_DUPLICATE, ref token);
            if (retVal == true)
            {
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.bInheritHandle = false; // ?????????????? //
                sa.nLength = (uint)Marshal.SizeOf(sa);
                DuplicateTokenEx(token, TOKEN_ALL_ACCESS, ref sa, (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, (int)TOKEN_TYPE.TokenPrimary, ref copiedToken);
                //DuplicateTokenEx(token, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,ref sa, (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, (int)TOKEN_TYPE.TokenPrimary, ref copiedToken);
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
                // Get token information struct length                
                uint ret = 0; // https://msdn.microsoft.com/en-us/library/windows/desktop/aa379626(v=vs.85).aspx
                GetTokenInformation(hToken, 18 /*TokenElevationType*/, IntPtr.Zero, 0, out ret);
                IntPtr tokenInformation = Marshal.AllocHGlobal((int)ret);

                // Get token information struct
                // https://msdn.microsoft.com/en-us/library/windows/desktop/bb530718(v=vs.85).aspx
                GetTokenInformation(hToken, 18 /*TokenElevationType*/, tokenInformation, ret, out ret);

                // Get a valid structure
                var value = Marshal.ReadInt32(tokenInformation, 0);
                Marshal.FreeHGlobal(tokenInformation);
                return (ElevationType)value;
            }
            else
            {
                return ElevationType.Default;
            };
        }

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
                    Process[] ps = Process.GetProcessesByName(MAIN_INTERACTIVE_PROCESS);
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

        private static IntPtr CreateTokenWithDisabledAdminsSID()
        {
            return CreateTokenWithDisabledAdminsSID(IntPtr.Zero);
        }

        private static IntPtr CreateTokenWithDisabledAdminsSID(IntPtr token)
        {
            bool emptyToken = token == IntPtr.Zero;

            SidIdentifierAuthority NtAuthority = new SidIdentifierAuthority();
            NtAuthority.Value = new byte[] { 0, 0, 0, 0, 0, NtSecurityAuthority };

            // Get the SID for BUILTIN\Administrators
            IntPtr adminsSID;
            try { AllocateAndInitializeSid(ref NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, out adminsSID); } catch { adminsSID = IntPtr.Zero; };
            if (adminsSID == IntPtr.Zero) return IntPtr.Zero;            

            try
            {
                if(emptyToken) token = GetCopyOfProcessToken(Process.GetCurrentProcess().Id);
                if (token == IntPtr.Zero) 
                    return IntPtr.Zero;
                else
                {
                    uint ret = 0;
                    GetTokenInformation(token, (int)TOKEN_INFORMATION_CLASS.TokenGroups, IntPtr.Zero, 0, out ret);
                    IntPtr groupInformation = Marshal.AllocHGlobal((int)ret);
                    GetTokenInformation(token, (int)TOKEN_INFORMATION_CLASS.TokenGroups, groupInformation, ret, out ret);
                    int tgc = Marshal.PtrToStructure<int>(groupInformation);
                    for (int i = 0; i < tgc; i++)
                    {
                        IntPtr tmlPtr = (IntPtr)(groupInformation + IntPtr.Size + Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL)) * i);
                        TOKEN_MANDATORY_LABEL TML = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(tmlPtr);
                        bool eqs = EqualSid(adminsSID, TML.pSid);
                        IntPtr phNt = IntPtr.Zero;
                        // https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken
                        if (eqs && CreateRestrictedToken(token, /*DISABLE_MAX_PRIVILEGE*/ 1, 1, tmlPtr, 0, IntPtr.Zero, 0, IntPtr.Zero, ref phNt) && (phNt != IntPtr.Zero))
                            return phNt;
                    };
                };
            }
            finally
            {
                if (emptyToken && (token != IntPtr.Zero)) CloseHandle(token);
            };
            return IntPtr.Zero;
        }

        private static (IntPtr pSID, uint pLength, bool groupEnabled, string user, string domain, bool global) GetBuiltInAdminSID()
        {            
            SidIdentifierAuthority NtAuthority = new SidIdentifierAuthority();
            NtAuthority.Value = new byte[] { 0, 0, 0, 0, 0, NtSecurityAuthority };

            // Get the SID for BUILTIN\Administrators
            IntPtr adminsSID;
            try { AllocateAndInitializeSid(ref NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, out adminsSID); } catch { adminsSID = IntPtr.Zero; };
            if (adminsSID == IntPtr.Zero) return (IntPtr.Zero, 0, false, null, null, false);

            IntPtr token = IntPtr.Zero;
            try
            {               
                token = GetCopyOfProcessToken(Process.GetCurrentProcess().Id);
                if (token == IntPtr.Zero)
                {
                    StringBuilder acc = new StringBuilder(256);
                    uint accL = (uint)acc.Capacity;
                    StringBuilder dom = new StringBuilder(256);
                    uint domL = (uint)dom.Capacity;
                    LookupAccountSid(null, adminsSID, acc, ref accL, dom, ref domL, out SID_NAME_USE snu);
                    return (adminsSID, GetLengthSid(adminsSID), false, acc.ToString(), dom.ToString(), false);
                }
                else
                {
                    uint ret = 0;
                    GetTokenInformation(token, (int)TOKEN_INFORMATION_CLASS.TokenGroups, IntPtr.Zero, 0, out ret);
                    IntPtr groupInformation = Marshal.AllocHGlobal((int)ret);
                    GetTokenInformation(token, (int)TOKEN_INFORMATION_CLASS.TokenGroups, groupInformation, ret, out ret);
                    int tgc = Marshal.PtrToStructure<int>(groupInformation);
                    for (int i = 0; i < tgc; i++)
                    {
                        IntPtr tmlPtr = (IntPtr)(groupInformation + IntPtr.Size + Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL)) * i);
                        TOKEN_MANDATORY_LABEL TML = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(tmlPtr);
                        bool eqs = EqualSid(adminsSID, TML.pSid);
                        if (eqs)
                        {
                            bool ge = (TML.Attributes & SE_GROUP_ENABLED) == SE_GROUP_ENABLED;
                            bool di = (TML.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) == SE_GROUP_USE_FOR_DENY_ONLY;

                            StringBuilder acc = new StringBuilder(256);
                            uint accL = (uint)acc.Capacity;
                            StringBuilder dom = new StringBuilder(256);
                            uint domL = (uint)dom.Capacity;
                            LookupAccountSid(null, TML.pSid, acc, ref accL, dom, ref domL, out SID_NAME_USE snu);

                            return (TML.pSid, GetLengthSid(TML.pSid), ge, acc.ToString(), dom.ToString(), true);
                        };
                    };
                };
            }
            catch (Exception err)
            {

            }
            finally
            {
                if(token != IntPtr.Zero) CloseHandle(token);
            };
            return (IntPtr.Zero, 0, false, null, null, false);
        }

        private static void ElevateToken(IntPtr token)
        {
            if (token == IntPtr.Zero) return;
                                   
            // set TokenIntegrityLevel
            {               
                /*
                    * https://wiki.sei.cmu.edu/confluence/display/c/WIN02-C.+Restrict+privileges+when+spawning+child+processes
                    * S-1-16-0     - Untrusted Mandatory Level // 0x000
                    * S-1-16-4096  - Low Mandatory Level // 0x1000  
                    * S-1-16-8192  - Medium Mandatory Level // 0x2000  
                    * S-1-16-12288 - High Mandatory Level // 0x3000  
                    * S-1-16-16384 - System Mandatory Level // 0x4000  
                    * S-1-16-20480 - Protected Process Mandatory Level // 0x5000
                    * S-1-16-28672 - Secure Process Mandatory Level // 0x7000
                */

                ConvertStringSidToSid(MANDATORY_HIGH_LEVEL, out IntPtr ptrSid);
                uint pSidL = GetLengthSid(ptrSid);

                TOKEN_MANDATORY_LABEL tml = new TOKEN_MANDATORY_LABEL();
                tml.Attributes = 0x00000020 /*SE_GROUP_INTEGRITY*/;// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-group_users_info_1
                tml.pSid = ptrSid;

                int tmls = Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL));
                IntPtr ptml = Marshal.AllocHGlobal(tmls);
                Marshal.StructureToPtr(tml, ptml, false);
                bool ok = SetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, ptml, tmls + (int)pSidL);
                uint err = GetLastError();
                Marshal.FreeHGlobal(ptml);

                ServiceLog.WriteDatedLn($"SetTokenInformation: TokenIntegrityLevel {ok} {err}");
            };

            // set TokenUIAccess
            {
                IntPtr iPtr = Marshal.AllocHGlobal(sizeof(int));
                Marshal.WriteInt32(iPtr, 1);
                bool ok = SetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenUIAccess, iPtr, sizeof(int));
                uint err = GetLastError();
                Marshal.FreeHGlobal(iPtr);

                ServiceLog.WriteDatedLn($"SetTokenInformation: TokenUIAccess {ok} {err}");
            };
        }

        private static void InteractiveToken(IntPtr token)
        {
            // Set Token Session To User Interactive

            if (token == IntPtr.Zero) return;            

            IntPtr iPtr = Marshal.AllocHGlobal(sizeof(int));            
            try
            {
                int sessid = WTSGetActiveConsoleSessionId();
                Marshal.WriteInt32(iPtr, sessid);
                bool ok = SetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenSessionId, iPtr, sizeof(int));
                uint err = GetLastError();
                ServiceLog.WriteDatedLn($"SetTokenSessionId: {sessid} {ok} {err}");
            }
            finally
            {
                Marshal.FreeHGlobal(iPtr);
            };            
        }

        private static bool EnterDebugMode()
        {
            try { Process.EnterDebugMode(); } catch { };
            bool x = true;
            x &= SetProcessPrivilege("SeDebugPrivilege", 2);
            x &= SetProcessPrivilege("SeBackupPrivilege", 2);
            x &= SetProcessPrivilege("SeRestorePrivilege", 2);
            x &= SetProcessPrivilege("SeIncreaseQuotaPrivilege", 2);
            x &= SetProcessPrivilege("SeAssignPrimaryTokenPrivilege", 2);
            return x;
        }

        private static bool IsSystemProcess()
        {
            uint returnValue = GetSecurityInfo(Process.GetCurrentProcess().Handle,
                SE_OBJECT_TYPE.SE_KERNEL_OBJECT,
                SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION,
                out IntPtr ownerSid, out IntPtr groupSid, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

            if (returnValue != 0) return false;

            System.Security.Principal.SecurityIdentifier securityIdentifier = new System.Security.Principal.SecurityIdentifier(ownerSid);
            if (securityIdentifier.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid))
                return true;
            return false;
        }

        private static bool IsNetworkProcess()
        {
            uint returnValue = GetSecurityInfo(Process.GetCurrentProcess().Handle,
                SE_OBJECT_TYPE.SE_KERNEL_OBJECT,
                SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION,
                out IntPtr ownerSid, out IntPtr groupSid, out IntPtr dacl, out IntPtr sacl,out IntPtr securityDescriptor);

            if (returnValue != 0) return false;

            System.Security.Principal.SecurityIdentifier securityIdentifier = new System.Security.Principal.SecurityIdentifier(ownerSid);
            if (securityIdentifier.IsWellKnown(System.Security.Principal.WellKnownSidType.NetworkServiceSid))
                return true;
            return false;
        }

        private static bool SetProcessPrivilege(string privilegeName, int attrib)
        {
            IntPtr processHandle = GetCurrentProcess(); // no need to close it later
            IntPtr hToken = IntPtr.Zero;
            LUID luid = new LUID();

            try
            {
                if (!OpenProcessToken(processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref hToken)) return false;
                if (!LookupPrivilegeValue(null, privilegeName, ref luid)) return false;

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = new LUID_AND_ATTRIBUTES[1] { new LUID_AND_ATTRIBUTES() { Luid = luid, Attributes = (uint)attrib } };
                if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;

                return Marshal.GetLastWin32Error() == 0;
            }
            finally
            {
                if (hToken != IntPtr.Zero) CloseHandle(hToken);
            };
        }

        private static bool IsAdmin()
        {
            try
            {
                using (System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    System.Security.Principal.WindowsPrincipal principal = new System.Security.Principal.WindowsPrincipal(identity);
                    return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                };
            }
            catch { };
            return true;
        }

        private static Process GetProcessById(uint pid)
        {
            try { return Process.GetProcessById((int)pid);} catch { };
            return null;
        }

        private static (bool started, Process process) RunProcess(ProcessStartInfo psi)
        {
            int tries = 0;
            while (++tries < 3)
            {
                try
                {
                    Process proc = Process.Start(psi);
                    ServiceLog.WriteDatedLn($"Process.Start: {psi.FileName} True {proc.Id} 0");
                    return (true, proc);
                }
                catch (InvalidOperationException ex)
                {
                    if (ex.Message.IndexOf("UseShellExecute") > 0)
                        psi.UseShellExecute = !psi.UseShellExecute;
                    else
                    {
                        ServiceLog.WriteDatedLn($"Process.Start: {psi.FileName} False 0 {ex.Message}");
                        LastError = ex;
                        break;
                    };
                }
                catch (Exception ex)
                {
                    ServiceLog.WriteDatedLn($"Process.Start: {psi.FileName} False 0 {ex.Message}");
                    LastError = ex;
                    break;
                };
            };
            return (false, null);
        }

        #endregion Private        

        public static Exception LastError = null;

        #region PUBLIC Start

        /// <summary>
        ///     Launch Process
        /// </summary>
        /// <param name="psi"></param>
        /// <param name="querySessionToken"></param>
        /// <returns></returns>
        public static (bool started, Process process) Start(ProcessStartInfo psi, bool userInteractive = true, bool elevate_up = false, bool querySessionToken = false)
        {
            // If you want to run current application elevated
            // remember to add in app.manifest: <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />            

            LastError = null;

            bool IsServiceProcess = (GetConsoleWindow() == IntPtr.Zero) || IsSystemProcess() || IsNetworkProcess();
            if (IsServiceProcess || (elevate_up && IsAdmin()))  // Service Process
            {
                EnterDebugMode();
                IntPtr token;
                if (IsServiceProcess) // Service Process
                    token = userInteractive && (!elevate_up) ? GetTokenForUserInteractiveProcess(querySessionToken) : GetCopyOfProcessToken(Process.GetCurrentProcess().Id);
                else // Console or UI (current process is Elevated)
                    token = GetCopyOfProcessToken(Process.GetCurrentProcess().Id); // Already Interactive
                if (token != IntPtr.Zero)
                {
                    if (elevate_up) ElevateToken(token); // Elevated ?
                    if (IsServiceProcess && userInteractive) InteractiveToken(token); // userInteractive ?
                    Dictionary<String, String> uenv = new Dictionary<string, string>();
                    foreach (DictionaryEntry de in psi.EnvironmentVariables)
                        uenv[de.Key.ToString()] = de.Value.ToString();
                    byte[] env = CreateEnvironment(uenv);
                    IntPtr eBlock = Marshal.AllocHGlobal(env.Length);
                    Marshal.Copy(env, 0, eBlock, env.Length);
                    (bool ok, uint pid) = LaunchProcessWithToken(null, $"\"{psi.FileName}\" {psi.Arguments}", token, eBlock, psi);
                    uint lastErr = GetLastError();
                    ServiceLog.WriteDatedLn($"LaunchProcess: {psi.FileName} {ok} {pid} {lastErr}");
                    System.Threading.Thread.Sleep(750); // ensure that launching app gets all environment variables
                    Marshal.FreeHGlobal(eBlock);
                    CloseHandle(token);
                    if (ok) return (ok, GetProcessById(pid));
                    if (lastErr > 0) LastError = new System.ComponentModel.Win32Exception((int)lastErr);
                };
                if (IsServiceProcess) return (false, null);
            };

            // Console or UI (current process is not Elevated) or other                        
            if (elevate_up) { psi.UseShellExecute = true; psi.Verb = "runas"; };
            return RunProcess(psi);
        }        

        /// <summary>
        ///     Start Process from WinService
        /// </summary>
        /// <param name="psi"></param>
        /// <param name="userInteractive"></param>
        /// <param name="elevate_up"></param>
        /// <returns></returns>
        public static (bool started, Process process) StartFromService(ProcessStartInfo psi, bool userInteractive = true, bool elevate_up = false)
        {
            LastError = null;

            EnterDebugMode();
            IntPtr token = userInteractive && (!elevate_up) ? GetTokenForUserInteractiveProcess(false) : GetCopyOfProcessToken(Process.GetCurrentProcess().Id);
            if (token != IntPtr.Zero)
            {
                if (elevate_up) ElevateToken(token); // Elevated ?
                if (userInteractive) InteractiveToken(token); // userInteractive ?
                Dictionary<String, String> uenv = new Dictionary<string, string>();
                foreach (DictionaryEntry de in psi.EnvironmentVariables)
                    uenv[de.Key.ToString()] = de.Value.ToString();
                byte[] env = CreateEnvironment(uenv);
                IntPtr eBlock = Marshal.AllocHGlobal(env.Length);
                Marshal.Copy(env, 0, eBlock, env.Length);
                (bool ok, uint pid) = LaunchProcessWithToken(null, $"\"{psi.FileName}\" {psi.Arguments}", token, eBlock, psi);
                uint lastErr = GetLastError();
                ServiceLog.WriteDatedLn($"LaunchProcess: {psi.FileName} {ok} {pid} {lastErr}");
                System.Threading.Thread.Sleep(750); // ensure that launching app gets all environment variables
                Marshal.FreeHGlobal(eBlock);
                CloseHandle(token);
                if (ok) return (ok, GetProcessById(pid));
                if (lastErr > 0) LastError = new System.ComponentModel.Win32Exception((int)lastErr);
            };
            return (false, null);
        }

        /// <summary>
        ///     Start Process from User Interactive App 
        /// </summary>
        /// <param name="psi"></param>
        /// <param name="userInteractive"></param>
        /// <param name="elevate_up"></param>
        /// <returns></returns>
        public static (bool started, Process process) StartFromUserInteractive(ProcessStartInfo psi, bool elevate_up = false)
        {
            LastError = null;            

            if (elevate_up) { psi.UseShellExecute = true; psi.Verb = "runas"; };
            return RunProcess(psi);
        }

        /// <summary>
        ///     Start Process
        /// </summary>
        /// <returns></returns>
        public static (bool started, Process process) Start(string cmdLine, bool userInteractive = true, bool elevate_up = false, bool querySessionToken = false)
        {
            // If you want to run current application elevated
            // remember to add in app.manifest: <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
            
            LastError = null;

            bool IsServiceProcess = (GetConsoleWindow() == IntPtr.Zero) || IsSystemProcess() || IsNetworkProcess();
            if (IsServiceProcess || (elevate_up && IsAdmin()))
            {
                EnterDebugMode();
                IntPtr token;
                if (IsServiceProcess) // Service Process
                    token = userInteractive && (!elevate_up) ? GetTokenForUserInteractiveProcess(querySessionToken) : GetCopyOfProcessToken(Process.GetCurrentProcess().Id);
                else // Console or UI (current process is Elevated)
                    token = GetCopyOfProcessToken(Process.GetCurrentProcess().Id); // Already Interactive
                if (token != IntPtr.Zero)
                {
                    if (elevate_up) ElevateToken(token); // Elevated ?
                    if (IsServiceProcess && userInteractive) InteractiveToken(token); // userInteractive ?
                    byte[] env = CreateEnvironment(GetProcessEnvironmentByToken(token));
                    IntPtr eBlock = Marshal.AllocHGlobal(env.Length);
                    Marshal.Copy(env, 0, eBlock, env.Length);
                    (bool ok, uint pid) = LaunchProcessWithToken(null, cmdLine, token, eBlock, null);
                    uint lastErr = GetLastError();
                    ServiceLog.WriteDatedLn($"LaunchProcess: {cmdLine} {ok} {pid} {lastErr}");
                    System.Threading.Thread.Sleep(750); // ensure that launching app gets all environment variables
                    Marshal.FreeHGlobal(eBlock);
                    CloseHandle(token);
                    if (lastErr > 0) LastError = new System.ComponentModel.Win32Exception((int)lastErr);
                    if (ok) return (ok, GetProcessById(pid));
                };
                if(IsServiceProcess) return (false, null);
            };
            
            string cmd = cmdLine;
            string arg = "";
            try
            {
                int iof = cmdLine.LastIndexOf(".");
                if (iof > 0) iof = cmdLine.IndexOf(" ", iof);
                if (iof > 0)
                {
                    cmd = cmdLine.Substring(0, iof).Trim();
                    arg = cmdLine.Substring(++iof).Trim();
                };
            }
            catch { };

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.WorkingDirectory = Path.GetDirectoryName(cmd);
            psi.FileName = cmd;
            psi.Arguments = arg;

            // Console or UI (current process is not Elevated) or other            
            if (elevate_up) { psi.UseShellExecute = true; psi.Verb = "runas"; };
            return RunProcess(psi);
        }

        /// <summary>
        ///     Start Process from WinService
        /// </summary>
        /// <param name="cmdLine"></param>
        /// <param name="userInteractive"></param>
        /// <param name="elevate_up"></param>
        /// <returns></returns>
        public static (bool started, Process process) StartFromService(string cmdLine, bool userInteractive = true, bool elevate_up = false)
        {
            LastError = null;

            EnterDebugMode();
            IntPtr token = userInteractive && (!elevate_up) ? GetTokenForUserInteractiveProcess(false) : GetCopyOfProcessToken(Process.GetCurrentProcess().Id);
            if (token != IntPtr.Zero)
            {
                if (elevate_up) ElevateToken(token); // Elevated ?
                if (userInteractive) InteractiveToken(token); // userInteractive ?
                byte[] env = CreateEnvironment(GetProcessEnvironmentByToken(token));
                IntPtr eBlock = Marshal.AllocHGlobal(env.Length);
                Marshal.Copy(env, 0, eBlock, env.Length);
                (bool ok, uint pid) = LaunchProcessWithToken(null, cmdLine, token, eBlock, null);
                uint lastErr = GetLastError();
                ServiceLog.WriteDatedLn($"LaunchProcess: {cmdLine} {ok} {pid} {lastErr}");
                System.Threading.Thread.Sleep(750); // ensure that launching app gets all environment variables
                Marshal.FreeHGlobal(eBlock);
                CloseHandle(token);
                if (ok) return (ok, GetProcessById(pid));
                if (lastErr > 0) LastError = new System.ComponentModel.Win32Exception((int)lastErr);
            };
            return (false, null);
        }

        /// <summary>
        ///     Start Process from User Interactive App
        /// </summary>
        /// <param name="cmdLine"></param>
        /// <param name="elevate_up"></param>
        /// <returns></returns>
        public static (bool started, Process process) StartFromUserInteractive(string cmdLine, bool elevate_up = false)
        {
            LastError = null;

            string cmd = cmdLine;
            string arg = "";
            try
            {
                int iof = cmdLine.LastIndexOf(".");
                if (iof > 0) iof = cmdLine.IndexOf(" ", iof);
                if (iof > 0)
                {
                    cmd = cmdLine.Substring(0, iof).Trim();
                    arg = cmdLine.Substring(++iof).Trim();
                };
            }
            catch { };

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.WorkingDirectory = Path.GetDirectoryName(cmd);
            psi.FileName = cmd;
            psi.Arguments = arg;

            if (elevate_up) { psi.UseShellExecute = true; psi.Verb = "runas"; };
            return RunProcess(psi);
        }

        /// <summary>
        ///     Start Not Elevated Process
        /// </summary>
        /// <param name="psi"></param>
        /// <param name="userInteractive"></param>
        /// <returns></returns>
        public static (bool started, Process process) StartNotElevated(ProcessStartInfo psi, bool userInteractive = true)
        {
            LastError = null;

            EnterDebugMode();
            IntPtr token = userInteractive ? GetTokenForUserInteractiveProcess(false) : GetCopyOfProcessToken(Process.GetCurrentProcess().Id);
            if (token != IntPtr.Zero)
            {                
                {
                    IntPtr tokenN = CreateTokenWithDisabledAdminsSID(token);
                    if(tokenN != IntPtr.Zero)
                    {
                        CloseHandle(token);
                        token = tokenN;
                    };
                }
                if (userInteractive) InteractiveToken(token); // userInteractive ?
                Dictionary<String, String> uenv = new Dictionary<string, string>();
                foreach (DictionaryEntry de in psi.EnvironmentVariables)
                    uenv[de.Key.ToString()] = de.Value.ToString();
                byte[] env = CreateEnvironment(uenv);
                IntPtr eBlock = Marshal.AllocHGlobal(env.Length);
                Marshal.Copy(env, 0, eBlock, env.Length);
                (bool ok, uint pid) = LaunchProcessWithToken(null, $"\"{psi.FileName}\" {psi.Arguments}", token, eBlock, psi);
                uint lastErr = GetLastError();
                ServiceLog.WriteDatedLn($"LaunchProcess: {psi.FileName} {ok} {pid} {lastErr}");
                System.Threading.Thread.Sleep(750); // ensure that launching app gets all environment variables
                Marshal.FreeHGlobal(eBlock);
                CloseHandle(token);
                if (ok) return (ok, GetProcessById(pid));
                if (lastErr > 0) LastError = new System.ComponentModel.Win32Exception((int)lastErr);
            };
            return (false, null);
        }

        /// <summary>
        ///     Start Not Elevated Process
        /// </summary>
        /// <param name="cmdLine"></param>
        /// <param name="userInteractive"></param>
        /// <returns></returns>
        public static (bool started, Process process) StartNotElevated(string cmdLine, bool userInteractive = true)
        {
            LastError = null;

            EnterDebugMode();
            IntPtr token = userInteractive ? GetTokenForUserInteractiveProcess(false) : GetCopyOfProcessToken(Process.GetCurrentProcess().Id);
            if (token != IntPtr.Zero)
            {
                {
                    IntPtr tokenN = CreateTokenWithDisabledAdminsSID(token);
                    if (tokenN != IntPtr.Zero)
                    {
                        CloseHandle(token);
                        token = tokenN;
                    };
                }
                if (userInteractive) InteractiveToken(token); // userInteractive ?
                byte[] env = CreateEnvironment(GetProcessEnvironmentByToken(token));
                IntPtr eBlock = Marshal.AllocHGlobal(env.Length);
                Marshal.Copy(env, 0, eBlock, env.Length);
                (bool ok, uint pid) = LaunchProcessWithToken(null, cmdLine, token, eBlock, null);
                uint lastErr = GetLastError();
                ServiceLog.WriteDatedLn($"LaunchProcess: {cmdLine} {ok} {pid} {lastErr}");
                System.Threading.Thread.Sleep(750); // ensure that launching app gets all environment variables
                Marshal.FreeHGlobal(eBlock);
                CloseHandle(token);
                if (ok) return (ok, GetProcessById(pid));
                if (lastErr > 0) LastError = new System.ComponentModel.Win32Exception((int)lastErr);
            };            
            return (false, null);
        }

        #endregion PUBLIC Start
    }
}
