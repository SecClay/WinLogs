# Helpers for reading and writing SACLs (audit rules). Dot-sourced by Install-WinLogs.ps1 and the tests.
#
# Two Windows quirks drive this file:
#  * a process must switch ON SeSecurityPrivilege (admins hold it, disabled by default) to touch a SACL;
#  * .NET's RegistryKey.OpenSubKey refuses the ACCESS_SYSTEM_SECURITY right, and Get-Acl -Audit fails on
#    registry keys, so the key is opened with the Win32 API and wrapped with RegistryKey.FromHandle.

if (-not ('WinLogsNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

public static class WinLogsNative {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct TokPriv1Luid { public int Count; public long Luid; public int Attr; }

    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr tok);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string host, string name, ref long luid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr tok, bool disAll, ref TokPriv1Luid n, int len, IntPtr prev, IntPtr relen);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern int RegOpenKeyEx(IntPtr hKey, string sub, int options, int sam, out IntPtr result);

    public static bool EnablePrivilege(string priv) {
        IntPtr tok = IntPtr.Zero;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, ref tok)) return false;
        TokPriv1Luid tp; tp.Count = 1; tp.Luid = 0; tp.Attr = 2;
        if (!LookupPrivilegeValue(null, priv, ref tp.Luid)) return false;
        return AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }

    // HKLM subkey opened with READ_CONTROL | ACCESS_SYSTEM_SECURITY, so its SACL can be read and written.
    public static RegistryKey OpenHklmForAudit(string sub) {
        IntPtr h;
        int rc = RegOpenKeyEx(new IntPtr(unchecked((int)0x80000002)), sub, 0, 0x01020000, out h);
        if (rc != 0) throw new System.ComponentModel.Win32Exception(rc);
        return RegistryKey.FromHandle(new SafeRegistryHandle(h, true));
    }
}
'@
}

function Enable-SecurityPrivilege { [void][WinLogsNative]::EnablePrivilege('SeSecurityPrivilege') }

function Open-AuditKey([string]$Path) {
    Enable-SecurityPrivilege
    [WinLogsNative]::OpenHklmForAudit(($Path -replace '^HKLM:\\', ''))
}

# Number of audit rules on a registry key or file/folder.
function Get-AuditRuleCount([string]$Path) {
    if ($Path -like 'HKLM:*') {
        $key = Open-AuditKey $Path
        try {
            return @($key.GetAccessControl([Security.AccessControl.AccessControlSections]::Audit).
                GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier])).Count
        } finally { $key.Close() }
    }
    Enable-SecurityPrivilege
    return @((Get-Acl -LiteralPath $Path -Audit).Audit).Count
}
