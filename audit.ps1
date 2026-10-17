Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "[*] WINDOWS CONFIGURATION & ACL AUDITOR (DIRECT EXECUTION)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($id)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$mySids = New-Object System.Collections.Generic.HashSet[string]
[void]$mySids.Add($id.User.Value)
$groupNames = @()
foreach ($g in $id.Groups) {
    [void]$mySids.Add($g.Value)
    try { $groupNames += $g.Translate([System.Security.Principal.NTAccount]).Value } catch {}
}

Write-Host "[i] User: $($id.Name) | Elevated: $isAdmin | Token SIDs: $($mySids.Count)" -ForegroundColor Gray

$findings = New-Object System.Collections.Generic.List[PSCustomObject]

function Get-CleanExePath($rawPath) {
    if (-not $rawPath) { return "" }
    $p = $rawPath.Trim()
    if ($p -match '^"([^"]+)"') { return $matches[1] }
    if ($p -match '^(.*?\.exe)\b') { return $matches[1].Trim() }
    return ($p -split '\s+')[0]
}

function Test-MyAclWrite($path, [switch]$IsRegistry) {
    if (-not $path) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sid = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { "" }
            if (-not $mySids.Contains($sid)) { continue }
            if ($IsRegistry) {
                if ($ace.RegistryRights -band ([System.Security.AccessControl.RegistryRights]::SetValue -bor
                                               [System.Security.AccessControl.RegistryRights]::WriteKey -bor
                                               [System.Security.AccessControl.RegistryRights]::FullControl -bor
                                               [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
                                               [System.Security.AccessControl.RegistryRights]::TakeOwnership)) {
                    return $true
                }
            } else {
                if ($ace.FileSystemRights -band ([System.Security.AccessControl.FileSystemRights]::Write -bor
                                                 [System.Security.AccessControl.FileSystemRights]::Modify -bor
                                                 [System.Security.AccessControl.FileSystemRights]::FullControl -bor
                                                 [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
                                                 [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                                                 [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                                                 [System.Security.AccessControl.FileSystemRights]::TakeOwnership)) {
                    return $true
                }
            }
        }
    } catch {}
    return $false
}

function Test-ServiceDacl($svcName) {
    $result = @{ CanChangeConfig = $false; CanStartStop = $false }
    try {
        $sddlOut = sc.exe sdshow $svcName 2>$null | Where-Object { $_ -match '^D:' } | Select-Object -First 1
        if (-not $sddlOut) { return $result }
        $rawSd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddlOut.Trim())
        foreach ($ace in $rawSd.DiscretionaryAcl) {
            if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) { continue }
            if (-not $mySids.Contains($ace.SecurityIdentifier.Value)) { continue }
            $mask = $ace.AccessMask
            if ($mask -band (0x0002 -bor 0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000)) {
                $result.CanChangeConfig = $true
            }
            if ($mask -band (0x0010 -bor 0x0020 -bor 0x10000000)) {
                $result.CanStartStop = $true
            }
        }
    } catch {}
    return $result
}

# 1. Token & Groups
$privOut = whoami.exe /priv 2>$null
$hasShutdown = $false
if ($privOut) {
    if ($privOut -match "SeShutdownPrivilege") { $hasShutdown = $true }
    foreach ($pName in @("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeDebugPrivilege", "SeManageVolumePrivilege", "SeLoadDriverPrivilege")) {
        if ($privOut -match $pName) {
            $findings.Add([PSCustomObject]@{ Category = "TOKEN"; Item = $pName; Trigger = "Immediate"; Details = "Privilege present in current token (see Checklist 2.1)" })
        }
    }
}

if (($groupNames -match "Administrators") -and (-not $isAdmin)) {
    $findings.Add([PSCustomObject]@{ Category = "UAC"; Item = "Local Administrators (Medium Integrity)"; Trigger = "Immediate"; Details = "Split token detected (see Checklist 2.5)" })
}
foreach ($sg in @("Backup Operators", "DnsAdmins", "Print Operators", "Server Operators", "Hyper-V Administrators", "LAPS_Readers")) {
    if ($groupNames -match [regex]::Escape($sg)) {
        $findings.Add([PSCustomObject]@{ Category = "GROUP"; Item = $sg; Trigger = "Immediate"; Details = "Special group membership" })
    }
}

# 2. Registry & Saved Credentials
$aieHKCU = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
$aieHKLM = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ($aieHKCU -eq 1 -and $aieHKLM -eq 1) {
    $findings.Add([PSCustomObject]@{ Category = "INSTALLER"; Item = "AlwaysInstallElevated = 1"; Trigger = "Immediate"; Details = "Both HKCU and HKLM policies enabled" })
}

$winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($winlogon -and $winlogon.DefaultPassword) {
    $findings.Add([PSCustomObject]@{ Category = "AUTOLOGON"; Item = "Winlogon DefaultPassword"; Trigger = "Immediate"; Details = "User: $($winlogon.DefaultUserName) | Value: $($winlogon.DefaultPassword)" })
}

$cmdkeyOut = cmdkey.exe /list 2>$null
if ($cmdkeyOut -and ($cmdkeyOut -notmatch "NONE" -and $cmdkeyOut -match "Target:")) {
    $findings.Add([PSCustomObject]@{ Category = "CMDKEY"; Item = "Saved Session in cmdkey"; Trigger = "Immediate"; Details = "Check cmdkey /list output" })
}

# 3. Services
$services = @()
try {
    $services = Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name, DisplayName, State, StartMode, StartName, PathName
} catch {
    try {
        $services = Get-WmiObject Win32_Service -ErrorAction Stop | Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    } catch {
        $services = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.Type -in 16,32,272,288 -and $_.ImagePath } |
            ForEach-Object {
                $st = (Get-Service -Name $_.PSChildName -ErrorAction SilentlyContinue).Status
                [PSCustomObject]@{
                    Name        = $_.PSChildName
                    DisplayName = $_.DisplayName
                    State       = if ($st) { "$st" } else { "Unknown" }
                    StartMode   = switch ($_.Start) { 2 {"Auto"} 3 {"Manual"} 4 {"Disabled"} default {"$($_.Start)"} }
                    StartName   = $_.ObjectName
                    PathName    = $_.ImagePath
                }
            }
    }
}

$customApps = @()

foreach ($svc in $services) {
    $raw = if ($svc.PathName) { $svc.PathName.Trim() } else { "" }
    $exePath = Get-CleanExePath $raw
    $isCustom = ($raw -ne "") -and ($raw -notmatch '^"?\\??\\?C:\\Windows') -and ($raw -notmatch '^%?SystemRoot%?')

    $dacl = Test-ServiceDacl $svc.Name
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
    $regWritable = Test-MyAclWrite $regPath -IsRegistry

    $exeWritable = $false
    $appDirWritable = $false
    $parentDir = ""
    if ($exePath -and (Test-Path -LiteralPath $exePath)) {
        $exeWritable = Test-MyAclWrite $exePath
        $parentDir = Split-Path -Parent $exePath
        if ($parentDir -and $isCustom) {
            $appDirWritable = Test-MyAclWrite $parentDir
        }
    }

    $isQuoted = $raw.StartsWith('"')
    $hasSpaces = $exePath -match '\s'
    $isUnquoted = (-not $isQuoted) -and $hasSpaces

    $trig = if ($dacl.CanStartStop) { "Start/Stop Allowed" }
            elseif ($svc.StartMode -eq "Auto" -and $hasShutdown) { "Auto + SeShutdown Enabled" }
            elseif ($svc.StartMode -eq "Auto") { "Auto (On Reboot)" }
            else { "Manual ($($svc.StartMode))" }

    if ($dacl.CanChangeConfig) {
        $findings.Add([PSCustomObject]@{ Category = "SVC_DACL"; Item = "$($svc.Name) (RunAs: $($svc.StartName))"; Trigger = $trig; Details = "Modifiable Service Config (sc.exe config $($svc.Name) binPath= ...)" })
    }
    if ($regWritable) {
        $findings.Add([PSCustomObject]@{ Category = "SVC_REG"; Item = "$($svc.Name) (RunAs: $($svc.StartName))"; Trigger = $trig; Details = "Writable Registry Key: $regPath" })
    }
    if ($exeWritable) {
        $findings.Add([PSCustomObject]@{ Category = "SVC_FILE"; Item = "$($svc.Name) (RunAs: $($svc.StartName))"; Trigger = $trig; Details = "Writable Binary: $exePath" })
    }

    if ($isUnquoted -and $exePath -match '^[A-Za-z]:\\') {
        $parts = $exePath.Split('\')
        $curr = ""
        for ($i = 0; $i -lt $parts.Count - 1; $i++) {
            $curr = ($curr + $parts[$i] + "\").TrimEnd('\')
            if ($parts[$i + 1] -match '\s') {
                $cand = "$curr\" + (($parts[$i + 1] -split '\s+')[0]) + ".exe"
                if (Test-MyAclWrite ($curr + "\")) {
                    $findings.Add([PSCustomObject]@{ Category = "UNQUOTED"; Item = "$($svc.Name) (RunAs: $($svc.StartName))"; Trigger = $trig; Details = "Writable Unquoted Candidate: $cand" })
                }
            }
        }
    }

    if ($appDirWritable) {
        $findings.Add([PSCustomObject]@{ Category = "SVC_DIR"; Item = "$($svc.Name) (RunAs: $($svc.StartName))"; Trigger = $trig; Details = "Writable Service Directory: $parentDir" })
    }

    if ($isCustom) {
        $customApps += [PSCustomObject]@{
            Service   = $svc.Name
            State     = $svc.State
            StartMode = $svc.StartMode
            RunAs     = $svc.StartName
            PathName  = $svc.PathName
        }
    }
}

# 4. %PATH%, Startup, Autorun, Tasks & History
($env:Path -split ';') | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique | ForEach-Object {
    if (Test-MyAclWrite $_) {
        $findings.Add([PSCustomObject]@{ Category = "PATH_DIR"; Item = $_; Trigger = "DLL / Search Order"; Details = "Writable directory in %PATH%" })
    }
}

$commonStartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
if (Test-MyAclWrite $commonStartup) {
    $findings.Add([PSCustomObject]@{ Category = "STARTUP"; Item = $commonStartup; Trigger = "User Logon"; Details = "Writable All-Users StartUp folder" })
}

try {
    Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft*' -and $_.State -ne 'Disabled' } | ForEach-Object {
        $tName = $_.TaskName
        $runAs = $_.Principal.UserId
        foreach ($act in $_.Actions) {
            $exe = Get-CleanExePath "$($act.Execute) $($act.Arguments)"
            if ($exe -and (Test-Path -LiteralPath $exe)) {
                $dir = Split-Path -Parent $exe
                if ((Test-MyAclWrite $exe) -or ($dir -and (Test-MyAclWrite $dir))) {
                    $findings.Add([PSCustomObject]@{ Category = "TASK"; Item = "$tName (RunAs: $runAs)"; Trigger = "Scheduled"; Details = "Writable Task Target: $($act.Execute) $($act.Arguments)" })
                }
            }
        }
    }
} catch {}

Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Length -gt 0) {
        $findings.Add([PSCustomObject]@{ Category = "HISTORY"; Item = "PSReadLine History"; Trigger = "Immediate"; Details = $_.FullName })
    }
}

Write-Host "`n======================================================================" -ForegroundColor Green
Write-Host "[+] CONFIRMED FINDINGS FOR CURRENT USER: $($findings.Count)" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green

if ($findings.Count -gt 0) {
    $findings | Format-Table Category, Item, Trigger, Details -AutoSize -Wrap
} else {
    Write-Host "[-] No direct writable vectors found. Check 3rd-party services below." -ForegroundColor Yellow
}

Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "[i] Installed 3rd-Party Services (outside C:\Windows): $($customApps.Count)" -ForegroundColor Cyan
if ($customApps.Count -gt 0) {
    $customApps | Format-Table Service, State, StartMode, RunAs, PathName -AutoSize -Wrap
}