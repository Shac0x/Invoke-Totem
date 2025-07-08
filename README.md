# Invoke-Totem
![Logo](Logo.png)

**Invoke-Totem** is a PowerShell script that allows obtaining and impersonating the access token of another process on the system, executing commands under the context of the associated user. This can be useful in post-exploitation scenarios, penetration testing, restricted network environments, or for developers interested in understanding the Windows security model.

---

## 🛠️ Features

- Open a remote process and obtain its token.
- Safely duplicate the token using native Windows API calls.
- Impersonate the target user context.
- Function to check the current user (`whoami`).
- Function to revert impersonation.

---

## 📦 Requirements

- PowerShell 5.0 or higher.
- Administrator privileges.
- Access to the target process (usually requires elevated privileges).
- The target process must have an accessible token (e.g., a process from another logged-in user).

---

## 🧪 Usage

### 1. Import the script:

```powershell
. .\Invoke-Totem.ps1
```

### 2. Search PIDs of user processes:

#### Get-Process and Get-WmiObject
```powershell
Get-WmiObject Win32_Process | Select-Object Name, ProcessId, @{Name='User';Expression={
    (Invoke-Command -ScriptBlock { 
        $temp = $_.GetOwner()
        "$($temp.Domain)\$($temp.User)"
    } -ArgumentList $_)
}} | Format-Table -AutoSize
```

#### Or using Get-CimInstance
```powershell
Get-CimInstance Win32_Process | ForEach-Object {
    $user = ($_ | Invoke-CimMethod -MethodName GetOwner)
    [PSCustomObject]@{
        Name      = $_.Name
        PID       = $_.ProcessId
        User      = if ($user) { "$($user.Domain)\$($user.User)" } else { "SYSTEM" }
    }
} | Format-Table -AutoSize

```

### 3. Impersonate token:

```powershell
Invoke-Totem -processID <PID>
```

Example:

```powershell
Invoke-Totem -processID 1234
```

This will impersonate the user who owns process `1234`.

---

### Check current user:

```powershell
Invoke-TotemWhoami
```

---

### Revert impersonation:

```powershell
Invoke-TotemReset
```

---

## 🔍 How it works

The script performs the following steps:

1. Opens the target process using `OpenProcess`.
2. Obtains its access token using `OpenProcessToken`.
3. Duplicates the token using `DuplicateTokenEx`.
4. Impersonates the context with `ImpersonateLoggedOnUser`.
5. Restores the original token with `RevertToSelf` when needed.

All calls are made via P/Invoke with `Add-Type`.

---

## 🧱 Script structure

- `Invoke-Totem`: Main function to impersonate a token.
- `Invoke-TotemWhoami`: Displays the currently impersonated user.
- `Invoke-TotemReset`: Reverts to the original user context.

---


## 👽 Credits

Developed by [Shac0x_](https://x.com/shac0x_/)  
Inspired by impersonation techniques in Windows environments documented by the offensive security community.

---

## ⚠️ Disclaimer
Use this tool responsibly. Do not use it for illegal activities. The author is not responsible for any misuse.