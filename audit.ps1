unction Invoke-OSCPPrivEscAudit {
    Write-Host "`n======================================================================" -ForegroundColor Cyan
    Write-Host "[*] OSCP WINDOWS PRIVESC HUNTER v4 (CONFIRMED VECTORS FIRST)" -ForegroundColor Cyan
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

    Write-Host "[i] User: $($id.Name) | Elevated Admin: $isAdmin | Groups: $($mySids.Count)" -ForegroundColor Gray

    $confirmedVectors = New-Object System.Collections.Generic.List[PSCustomObject]
    function Add-Vector($Category, $Title, $Trigger, $NextStep) {
        $confirmedVectors.Add([PSCustomObject]@{
            Category = $Category
            Vector   = $Title
            Trigger  = $Trigger
            NextStep = $NextStep
        })
    }

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

    # 1. CHECK TOKEN PRIVILEGES & SPECIAL GROUPS
    $privOut = whoami.exe /priv 2>$null
    $hasShutdown = $false
    if ($privOut) {
        if ($privOut -match "SeShutdownPrivilege")          { $hasShutdown = $true }
        if ($privOut -match "SeImpersonatePrivilege")       { Add-Vector "TOKEN" "SeImpersonatePrivilege" "Immediate" "Run GodPotato / PrintSpoofer / JuicyPotatoNG" }
        if ($privOut -match "SeAssignPrimaryTokenPrivilege"){ Add-Vector "TOKEN" "SeAssignPrimaryTokenPrivilege" "Immediate" "Run GodPotato / PrintSpoofer" }
        if ($privOut -match "SeBackupPrivilege")            { Add-Vector "TOKEN" "SeBackupPrivilege" "Immediate" "robocopy /B C:\Windows\System32\config C:\Windows\Temp SAM SYSTEM" }
        if ($privOut -match "SeRestorePrivilege")           { Add-Vector "TOKEN" "SeRestorePrivilege" "Immediate" "Overwrite service binary or Utilman.exe with backup semantics" }
        if ($privOut -match "SeTakeOwnershipPrivilege")     { Add-Vector "TOKEN" "SeTakeOwnershipPrivilege" "Immediate" "takeown /f <target> && icacls <target> /grant $($env:USERNAME):(F)" }
        if ($privOut -match "SeDebugPrivilege")             { Add-Vector "TOKEN" "SeDebugPrivilege" "Immediate" "Dump lsass.exe via comsvcs.dll MiniDump" }
        if ($privOut -match "SeManageVolumePrivilege")      { Add-Vector "TOKEN" "SeManageVolumePrivilege" "Immediate" "Use SeManageVolume exploit to enable arbitrary write in C:\" }
        if ($privOut -match "SeLoadDriverPrivilege")        { Add-Vector "TOKEN" "SeLoadDriverPrivilege" "Immediate" "Load vulnerable kernel driver (Capcom.sys / EoPLoadDriver)" }
    }

    if (($groupNames -match "Administrators") -and (-not $isAdmin)) {
        Add-Vector "UAC" "User is in Administrators (Medium Integrity)" "Immediate" "Run UAC Bypass (fodhelper.exe registry key or SystemPropertiesAdvanced.exe DLL)"
    }
    foreach ($specialGroup in @("Backup Operators", "DnsAdmins", "Print Operators", "Server Operators", "Hyper-V Administrators", "LAPS_Readers")) {
        if ($groupNames -match [regex]::Escape($specialGroup)) {
            Add-Vector "GROUP" "Member of privileged group: $specialGroup" "Immediate" "Check group-specific abuse in checklist"
        }
    }

    # 2. CHECK REGISTRY POLICIES (AlwaysInstallElevated, AutoLogon, Creds, SAM)
    $aieHKCU = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $aieHKLM = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    if ($aieHKCU -eq 1 -and $aieHKLM -eq 1) {
        Add-Vector "REGISTRY" "AlwaysInstallElevated = 1 (Both HKCU & HKLM)" "Immediate" "msiexec /quiet /qn /i C:\Windows\Temp\rev.msi"
    }

    $winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    if ($winlogon -and $winlogon.DefaultPassword) {
        Add-Vector "CREDENTIAL" "Winlogon AutoLogon Password Found!" "Immediate" "User: $($winlogon.DefaultUserName) | Pass: $($winlogon.DefaultPassword)"
    }

    $cmdkeyOut = cmdkey.exe /list 2>$null
    if ($cmdkeyOut -and ($cmdkeyOut -notmatch "NONE" -and $cmdkeyOut -match "Target:")) {
        Add-Vector "CREDENTIAL" "Saved Credentials in cmdkey /list" "Immediate" "Use: runas.exe /savecred /user:<TargetUser> C:\Windows\Temp\rev.exe"
    }

    if (Test-Path "C:\Windows\System32\config\SAM") {
        try {
            $samStream = [IO.File]::OpenRead("C:\Windows\System32\config\SAM")
            $samStream.Close()
            Add-Vector "CVE" "SAM file is directly readable!" "Immediate" "Copy SAM & SYSTEM or run HiveNightmare.exe (Shadow Copies)"
        } catch {}
    }

    # 3. CHECK SERVICES (ONLY CONFIRMED WRITABLE VECTORS GO TO TOP)
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

        $trig = if ($dacl.CanStartStop) { "sc.exe stop $($svc.Name) && sc.exe start $($svc.Name)" }
                elseif ($svc.StartMode -eq "Auto" -and $hasShutdown) { "Auto-Start + SeShutdown Enabled (Reboot via WMI Win32Shutdown(6))" }
                elseif ($svc.StartMode -eq "Auto") { "Auto-Start (Reboot needed)" }
                else { "Manual ($($svc.StartMode))" }

        if ($dacl.CanChangeConfig) {
            Add-Vector "SERVICE" "$($svc.Name) (Weak Service DACL | RunAs: $($svc.StartName))" $trig "sc.exe config `"$($svc.Name)`" binPath= `"C:\Windows\Temp\rev.exe`""
        }
        if ($regWritable) {
            Add-Vector "SERVICE" "$($svc.Name) (Writable Registry Key | RunAs: $($svc.StartName))" $trig "Set-ItemProperty `"$regPath`" -Name ImagePath -Value `"C:\Windows\Temp\rev.exe`""
        }
        if ($exeWritable) {
            Add-Vector "SERVICE" "$($svc.Name) (Writable .exe Binary | RunAs: $($svc.StartName))" $trig "copy /Y C:\Windows\Temp\rev.exe `"$exePath`""
        }

        if ($isUnquoted -and $exePath -match '^[A-Za-z]:\\') {
            $parts = $exePath.Split('\')
            $curr = ""
            for ($i = 0; $i -lt $parts.Count - 1; $i++) {
                $curr = ($curr + $parts[$i] + "\").TrimEnd('\')
                if ($parts[$i + 1] -match '\s') {
                    $cand = "$curr\" + (($parts[$i + 1] -split '\s+')[0]) + ".exe"
                    if (Test-MyAclWrite ($curr + "\")) {
                        Add-Vector "UNQUOTED" "$($svc.Name) (Writable Unquoted Path | RunAs: $($svc.StartName))" $trig "Drop payload at: `"$cand`""
                    }
                }
            }
        }

        if ($appDirWritable) {
            Add-Vector "DLL/DIR" "$($svc.Name) (Writable Service Dir | RunAs: $($svc.StartName))" $trig "Writable folder: `"$parentDir`" (check missing DLLs / configs)"
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

    # 4. CHECK %PATH%, STARTUP, AUTORUNS & SCHEDULED TASKS
    ($env:Path -split ';') | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique | ForEach-Object {
        if (Test-MyAclWrite $_) {
            Add-Vector "PATH" "Writable Folder in System %PATH%" "DLL Hijack / AutoElevate" "Folder: `"$_`""
        }
    }

    $commonStartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    if (Test-MyAclWrite $commonStartup) {
        Add-Vector "STARTUP" "Writable All-Users StartUp Folder" "Admin Logon" "Drop payload in: `"$commonStartup`""
    }

    foreach ($rk in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")) {
        if (Test-Path $rk) {
            if (Test-MyAclWrite $rk -IsRegistry) {
                Add-Vector "AUTORUN" "Writable Autorun Registry Key" "Admin Logon" "Key: $rk"
            }
            $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -notmatch '^PS') {
                        $exe = Get-CleanExePath "$($p.Value)"
                        if ($exe -and (Test-Path -LiteralPath $exe) -and (Test-MyAclWrite $exe)) {
                            Add-Vector "AUTORUN" "Writable Autorun Binary ($($p.Name))" "Admin Logon" "Overwrite: `"$exe`""
                        }
                    }
                }
            }
        }
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
                        Add-Vector "TASK" "Writable Scheduled Task: $tName (RunAs: $runAs)" "Scheduled Trigger" "Target: $($act.Execute) $($act.Arguments)"
                    }
                }
            }
        }
    } catch {}

    # 5. CHECK POWERSHELL HISTORY FILES (NON-EMPTY)
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Length -gt 0) {
            Add-Vector "HISTORY" "Non-empty PSReadLine History Found!" "Immediate" "Read file: type `"$($_.FullName)`""
        }
    }

    # OUTPUT: 1. READY PRIVESC VECTORS (THE MAIN VERDICT)
    Write-Host "`n======================================================================" -ForegroundColor Red
    Write-Host "[!!!] CONFIRMED PRIVESC VECTORS (READY TO EXPLOIT): $($confirmedVectors.Count)" -ForegroundColor Red
    Write-Host "======================================================================" -ForegroundColor Red

    if ($confirmedVectors.Count -gt 0) {
        $i = 1
        foreach ($v in $confirmedVectors) {
            Write-Host "`n[$i] [$($v.Category)] $($v.Vector)" -ForegroundColor Green
            Write-Host "    Trigger   : $($v.Trigger)" -ForegroundColor Cyan
            Write-Host "    Next Step : $($v.NextStep)" -ForegroundColor Yellow
            $i++
        }
    } else {
        Write-Host "[-] No direct automated vectors confirmed. Check 3rd-party apps & localhost ports below." -ForegroundColor Yellow
    }

    # OUTPUT: 2. COMPACT CONTEXT (3RD-PARTY SERVICES & LOCALHOST PORTS)
    Write-Host "`n----------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[i] Installed 3rd-Party Services (outside C:\Windows): $($customApps.Count)" -ForegroundColor Cyan
    if ($customApps.Count -gt 0) {
        $customApps | Format-Table Service, State, StartMode, RunAs, PathName -AutoSize -Wrap
    }

    $localPorts = @()
    try {
        $netstat = netstat.exe -ano | Select-String "LISTENING" | Select-String "127\.0\.0\.1:"
        foreach ($line in $netstat) {
            $tokens = ($line.ToString().Trim() -split '\s+')
            if ($tokens.Count -ge 5) {
                $addr = $tokens[1]
                $pidNum = $tokens[4]
                $proc = Get-Process -Id $pidNum -ErrorAction SilentlyContinue
                $pName = if ($proc) { $proc.ProcessName } else { "Unknown" }
                if ($pName -notin @("System", "svchost", "lsass", "wininit", "services")) {
                    $localPorts += [PSCustomObject]@{ Address = $addr; PID = $pidNum; Process = $pName }
                }
            }
        }
    } catch {}

    if ($localPorts.Count -gt 0) {
        Write-Host "[i] Interesting Localhost-Only (127.0.0.1) Ports:" -ForegroundColor Cyan
        $localPorts | Format-Table Address, PID, Process -AutoSize
    }
}

Invoke-OSCPPrivEscAudit