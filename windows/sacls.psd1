# Per-object audit rules (SACLs). The "Audit File System" and "Audit Registry" categories only log
# access to objects that have a SACL; these are the objects worth watching for persistence, defense
# evasion, credential access and tampering. Edit freely; Install-WinLogs.ps1 -Revert removes what it added.
# Each rule audits SUCCESS for Everyone. Paths may use %ENV% variables.
@{
    Registry = @(
        # Autostart / persistence
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                         Rights = 'SetValue, CreateSubKey, Delete, ChangePermissions, TakeOwnership' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';                     Rights = 'SetValue, CreateSubKey, Delete, ChangePermissions, TakeOwnership' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run';       Rights = 'SetValue, CreateSubKey, Delete, ChangePermissions, TakeOwnership' }
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';             Rights = 'SetValue, CreateSubKey, Delete, ChangePermissions, TakeOwnership' }
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce';         Rights = 'SetValue, CreateSubKey, Delete, ChangePermissions, TakeOwnership' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components';                  Rights = 'SetValue, CreateSubKey, Delete' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';                 Rights = 'SetValue, CreateSubKey, Delete, ChangePermissions, TakeOwnership' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows';                  Rights = 'SetValue, Delete' }   # AppInit_DLLs, Load
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services';                                     Rights = 'SetValue, CreateSubKey, Delete' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager';                      Rights = 'SetValue, Delete' }   # BootExecute, PendingFileRenameOperations
        # Defense evasion / debugger hijack
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'; Rights = 'SetValue, CreateSubKey, Delete' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit';        Rights = 'SetValue, CreateSubKey, Delete' }
        # Credential access / authentication
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                                  Rights = 'SetValue, CreateSubKey, Delete, ChangePermissions, TakeOwnership' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders';                    Rights = 'SetValue, CreateSubKey, Delete' }   # WDigest UseLogonCredential
        # Security tooling tampering (may be refused when Tamper Protection is on; that is only a warning)
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender';                          Rights = 'SetValue, CreateSubKey, Delete' }
    )
    Files = @(
        @{ Path = '%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp'; Rights = 'CreateFiles, CreateDirectories, Delete, ChangePermissions, TakeOwnership'; Inherit = 'ContainerInherit, ObjectInherit' }
        @{ Path = '%SystemRoot%\System32\Tasks';                                 Rights = 'CreateFiles, CreateDirectories, Delete, ChangePermissions, TakeOwnership'; Inherit = 'ContainerInherit, ObjectInherit' }
        @{ Path = '%SystemRoot%\System32\drivers';                               Rights = 'CreateFiles, Delete';                                                  Inherit = 'ContainerInherit' }
        @{ Path = '%SystemRoot%\System32\drivers\etc\hosts';                     Rights = 'WriteData, AppendData, Delete, ChangePermissions';                     Inherit = 'None' }
    )
}
