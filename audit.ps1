function Invoke-ServiceAudit {
    Write-Host "`n==================================================================" -ForegroundColor Cyan
    Write-Host "[*] WINDOWS PRIVESC VECTOR HUNTER (SERVICES, PATH, TASKS, AUTORUN)" -ForegroundColor Cyan
    Write-Host "==================================================================" -ForegroundColor Cyan

    # 1. Collect all SIDs of current user + groups
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $mySids = New-Object System.Collections.Generic.HashSet[string]
    [void]$mySids.Add($id.User.Value)
    foreach ($g in $id.Groups) { [void]$mySids.Add($g.Value) }
    Write-Host "[i] User: $($id.Name) | Checking ACLs against all $($mySids.Count) token SIDs...`n" -ForegroundColor Gray

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

    # 2. Load services (CIM -> WMI -> Registry fallback)
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

    $foundCount = 0
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

        # Check Unquoted Service Path (spaces before .exe and no quotes)
        $isQuoted = $raw.StartsWith('"')
        $hasSpaces = $exePath -match '\s'
        $isUnquoted = (-not $isQuoted) -and $hasSpaces
        $unquotedTargets = @()

        if ($isUnquoted -and $exePath -match '^[A-Za-z]:\\') {
            $parts = $exePath.Split('\')
            $curr = ""
            for ($i = 0; $i -lt $parts.Count - 1; $i++) {
                $curr = ($curr + $parts[$i] + "\").TrimEnd('\')
                if ($parts[$i + 1] -match '\s') {
                    $cand = "$curr\" + (($parts[$i + 1] -split '\s+')[0]) + ".exe"
                    if (Test-MyAclWrite ($curr + "\")) {
                        $unquotedTargets += "[WRITABLE!] $cand"
                    } else {
                        $unquotedTargets += "[Read-Only] $cand"
                    }
                }
            }
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

        # Only print this service if it has at least one finding!
        if ($dacl.CanChangeConfig -or $regWritable -or $exeWritable -or $appDirWritable -or $isUnquoted) {
            $foundCount++
            $trig = if ($dacl.CanStartStop) { "sc.exe stop $($svc.Name) && sc.exe start $($svc.Name)" }
                    elseif ($svc.StartMode -eq "Auto") { "Auto-Start (Reboot machine via WMI/SeShutdown)" }
                    else { "Manual ($($svc.StartMode) - need trigger)" }

            Write-Host "[!] SERVICE FINDING: $($svc.Name) ($($svc.DisplayName))" -ForegroundColor Red
            Write-Host "    State / Mode : $($svc.State) | StartMode: $($svc.StartMode) | RunAs: $($svc.StartName)" -ForegroundColor White
            Write-Host "    Binary Path  : $($svc.PathName)" -ForegroundColor Gray
            Write-Host "    How to Start : $trig" -ForegroundColor Cyan

            if ($dacl.CanChangeConfig) {
                Write-Host "    [+] WEAK SERVICE DACL (accesschk): You can change service config!" -ForegroundColor Green
                Write-Host "        Action -> sc.exe config `"$($svc.Name)`" binPath= `"C:\Windows\Temp\rev.exe`"" -ForegroundColor Yellow
            }
            if ($regWritable) {
                Write-Host "    [+] WEAK REGISTRY ACL: You can overwrite ImagePath in Registry!" -ForegroundColor Green
                Write-Host "        Action -> reg add `"HKLM\SYSTEM\CurrentControlSet\Services\$($svc.Name)`" /v ImagePath /t REG_EXPAND_SZ /d `"C:\Windows\Temp\rev.exe`" /f" -ForegroundColor Yellow
            }
            if ($exeWritable) {
                Write-Host "    [+] WEAK BINARY ACL (icacls): You can overwrite the service .exe!" -ForegroundColor Green
                Write-Host "        Action -> copy /Y C:\Windows\Temp\rev.exe `"$exePath`"" -ForegroundColor Yellow
            }
            if ($isUnquoted) {
                Write-Host "    [+] UNQUOTED SERVICE PATH DETECTED:" -ForegroundColor Green
                foreach ($u in $unquotedTargets) {
                    $color = if ($u -match '^\[WRITABLE') { "Yellow" } else { "DarkGray" }
                    Write-Host "        Candidate -> $u" -ForegroundColor $color
                }
            }
            if ($appDirWritable) {
                Write-Host "    [+] WRITABLE SERVICE FOLDER (icacls): $parentDir" -ForegroundColor Green
                Write-Host "        Action -> Possible DLL Hijacking or config replacement in $parentDir" -ForegroundColor Yellow
            }
            Write-Host ""
        }
    }

    if ($foundCount -eq 0) {
        Write-Host "[-] No vulnerable services (Unquoted / Weak DACL / Weak File or Reg ACL) found." -ForegroundColor Yellow
    }

    # 3. Check %PATH% folders for Write access (DLL Hijacking / Binary planting)
    Write-Host "------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[*] CHECKING %PATH% FOLDERS FOR WRITE PERMISSIONS (icacls)..." -ForegroundColor Cyan
    $writablePathDirs = @()
    ($env:Path -split ';') | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique | ForEach-Object {
        if (Test-MyAclWrite $_) {
            $writablePathDirs += $_
            Write-Host "    [+] WRITABLE %PATH% FOLDER: $_" -ForegroundColor Green
        }
    }
    if ($writablePathDirs.Count -eq 0) {
        Write-Host "    [-] No writable folders in %PATH%." -ForegroundColor DarkGray
    }

    # 4. Check Autorun / Startup folders & binaries
    Write-Host "------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[*] CHECKING STARTUP FOLDERS & AUTORUN KEYS (icacls)..." -ForegroundColor Cyan
    $startupFound = $false
    $commonStartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    if (Test-MyAclWrite $commonStartup) {
        $startupFound = $true
        Write-Host "    [+] WRITABLE ALL-USERS STARTUP FOLDER: $commonStartup" -ForegroundColor Green
    }
    foreach ($rk in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")) {
        if (Test-Path $rk) {
            if (Test-MyAclWrite $rk -IsRegistry) {
                $startupFound = $true
                Write-Host "    [+] WRITABLE AUTORUN REGISTRY KEY: $rk" -ForegroundColor Green
            }
            $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -notmatch '^PS') {
                        $exe = Get-CleanExePath "$($p.Value)"
                        if ($exe -and (Test-Path -LiteralPath $exe) -and (Test-MyAclWrite $exe)) {
                            $startupFound = $true
                            Write-Host "    [+] WRITABLE AUTORUN BINARY ($($p.Name)): $exe" -ForegroundColor Green
                        }
                    }
                }
            }
        }
    }
    if (-not $startupFound) {
        Write-Host "    [-] No writable Startup folders or Autorun binaries." -ForegroundColor DarkGray
    }

    # 5. Check Custom Scheduled Tasks for writable scripts/binaries
    Write-Host "------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[*] CHECKING CUSTOM SCHEDULED TASKS FOR WRITABLE BINARIES..." -ForegroundColor Cyan
    $taskFound = $false
    try {
        Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft*' -and $_.State -ne 'Disabled' } | ForEach-Object {
            $tName = $_.TaskName
            $runAs = $_.Principal.UserId
            foreach ($act in $_.Actions) {
                $exe = Get-CleanExePath "$($act.Execute) $($act.Arguments)"
                if ($exe -and (Test-Path -LiteralPath $exe)) {
                    $dir = Split-Path -Parent $exe
                    if ((Test-MyAclWrite $exe) -or ($dir -and (Test-MyAclWrite $dir))) {
                        $taskFound = $true
                        Write-Host "    [+] WRITABLE SCHEDULED TASK: $tName (RunAs: $runAs)" -ForegroundColor Green
                        Write-Host "        Target -> $($act.Execute) $($act.Arguments)" -ForegroundColor Yellow
                    }
                }
            }
        }
    } catch {}
    if (-not $taskFound) {
        Write-Host "    [-] No writable custom Scheduled Tasks found." -ForegroundColor DarkGray
    }

    # 6. Compact summary of installed 3rd-party services (just 1 line per service)
    Write-Host "------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[i] Installed 3rd-Party Services (outside C:\Windows): $($customApps.Count)" -ForegroundColor Cyan
    if ($customApps.Count -gt 0) {
        $customApps | Format-Table Service, State, StartMode, RunAs, PathName -AutoSize -Wrap
    }
}

Invoke-ServiceAudit