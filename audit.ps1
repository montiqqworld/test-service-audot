function Invoke-ServiceAudit {
    param(
        [string]$AccessChkPath = ".\accesschk.exe"
    )

    Write-Host "`n======================================================================" -ForegroundColor Cyan
    Write-Host "[*] WINDOWS SERVICE PRIVESC HUNTER v2 (TOKEN-AWARE & ZERO-DEPENDENCY)" -ForegroundColor Cyan
    Write-Host "======================================================================`n" -ForegroundColor Cyan

    # 1. Собираем ВСЕ SID текущего пользователя и всех его групп (включая доменные и кастомные)
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $mySids = New-Object System.Collections.Generic.HashSet[string]
    [void]$mySids.Add($id.User.Value)
    foreach ($g in $id.Groups) { [void]$mySids.Add($g.Value) }
    Write-Host "[i] Пользователь: $($id.Name) | Групп в токене: $($mySids.Count)" -ForegroundColor Gray

    # 2. Получаем список ВСЕХ служб (CIM -> WMI -> Реестр при закрытом SCManager)
    $services = @()
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    } catch {
        try {
            $services = Get-WmiObject Win32_Service -ErrorAction Stop | Select-Object Name, DisplayName, State, StartMode, StartName, PathName
        } catch {
            Write-Host "[!] WMI/SCManager закрыт. Читаю службы напрямую из ветки Реестра..." -ForegroundColor Yellow
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

    # Вспомогательная: чистый путь к .exe без аргументов
    function Get-CleanExePath($rawPath) {
        if (-not $rawPath) { return "" }
        $p = $rawPath.Trim()
        if ($p -match '^"([^"]+)"') { return $matches[1] }
        if ($p -match '^(.*?\.exe)\b') { return $matches[1].Trim() }
        return ($p -split '\s+')[0]
    }

    # Вспомогательная: проверка ACL файла/папки/реестра по всем SID нашего токена
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

    # Вспомогательная: проверка Service DACL через встроенный sc.exe sdshow (без accesschk!)
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
                # 0x0002=CHANGE_CONFIG, 0x00040000=WRITE_DAC, 0x00080000=WRITE_OWNER, 0x10000000=GENERIC_ALL, 0x40000000=GENERIC_WRITE, 0xF01FF=ALL_ACCESS
                if ($mask -band (0x0002 -bor 0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000)) {
                    $result.CanChangeConfig = $true
                }
                # 0x0010=SERVICE_START, 0x0020=SERVICE_STOP
                if ($mask -band (0x0010 -bor 0x0020 -bor 0x10000000)) {
                    $result.CanStartStop = $true
                }
            }
        } catch {}
        return $result
    }

    $exploitable = @()
    $customTable = @()

    foreach ($svc in $services) {
        $raw = if ($svc.PathName) { $svc.PathName.Trim() } else { "" }
        $exePath = Get-CleanExePath $raw
        $isCustom = ($raw -ne "") -and ($raw -notmatch '^"?\\??\\?C:\\Windows') -and ($raw -notmatch '^%?SystemRoot%?')

        # 1. Права на саму службу (SDDL)
        $dacl = Test-ServiceDacl $svc.Name

        # 2. Права на ветку реестра службы
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
        $regWritable = Test-MyAclWrite $regPath -IsRegistry

        # 3. Права на сам .exe и рабочую папку службы
        $exeWritable = $false
        $appDirWritable = $false
        if ($exePath -and (Test-Path -LiteralPath $exePath)) {
            $exeWritable = Test-MyAclWrite $exePath
            $parentDir = Split-Path -Parent $exePath
            if ($parentDir -and $isCustom) {
                $appDirWritable = Test-MyAclWrite $parentDir
            }
        }

        # 4. Проверка Unquoted Service Path + какие промежуточные папки реально открыты на запись
        $isQuoted = $raw.StartsWith('"')
        $hasSpaces = $exePath -match '\s'
        $isUnquoted = (-not $isQuoted) -and $hasSpaces
        $unquotedWritableDirs = @()

        if ($isUnquoted -and $exePath -match '^[A-Za-z]:\\') {
            $parts = $exePath.Split('\')
            $curr = ""
            for ($i = 0; $i -lt $parts.Count - 1; $i++) {
                $curr = ($curr + $parts[$i] + "\").TrimEnd('\')
                # Интересны только уровни, где в СЛЕДУЮЩЕМ сегменте есть пробел
                if ($parts[$i + 1] -match '\s') {
                    if (Test-MyAclWrite ($curr + "\")) {
                        $candidateName = ($parts[$i + 1] -split '\s+')[0] + ".exe"
                        $unquotedWritableDirs += "$curr\$candidateName"
                    }
                }
            }
        }

        # Собираем найденные векторы, на которые мы РЕАЛЬНО можем повлиять
        $vectors = @()
        if ($dacl.CanChangeConfig)              { $vectors += "SERVICE_CONFIG_WRITE (sc config binPath)" }
        if ($regWritable)                       { $vectors += "REGISTRY_IMAGEPATH_WRITE" }
        if ($exeWritable)                       { $vectors += "BINARY_OVERWRITE ($exePath)" }
        if ($unquotedWritableDirs.Count -gt 0)  { $vectors += "UNQUOTED_PATH_HIJACK -> " + ($unquotedWritableDirs -join ", ") }
        elseif ($isUnquoted -and $isCustom)     { $vectors += "Unquoted (но папки Read-Only - проверь вручную)" }
        if ($appDirWritable)                    { $vectors += "WRITABLE_SERVICE_FOLDER (DLL Hijack: $(Split-Path -Parent $exePath))" }

        $trigger = @()
        if ($dacl.CanStartStop)         { $trigger += "sc start/stop (есть права!)" }
        if ($svc.StartMode -eq "Auto")  { $trigger += "Auto (Reboot / SeShutdown)" }
        if ($trigger.Count -eq 0)       { $trigger += "Manual ($($svc.StartMode))" }

        $obj = [PSCustomObject]@{
            Name      = $svc.Name
            State     = $svc.State
            StartMode = $svc.StartMode
            RunAs     = $svc.StartName
            Trigger   = $trigger -join " | "
            Vectors   = if ($vectors.Count -gt 0) { $vectors -join " + " } else { "None" }
            PathName  = $svc.PathName
        }

        if ($isCustom) { $customTable += $obj }
        if ($vectors.Count -gt 0 -and $vectors[0] -notmatch '^Unquoted \(но папки Read-Only') {
            $exploitable += $obj
        }
    }

    # ВЫВОД 1: Главный блок — службы, на которые мы РЕАЛЬНО можем повлиять!
    Write-Host "[!!!] 1. СЛУЖБЫ, НА КОТОРЫЕ МЫ МОЖЕМ ПОВЛИЯТЬ (ГОТОВЫЕ ВЕКТОРЫ PRIVESC):" -ForegroundColor Red
    if ($exploitable.Count -gt 0) {
        $exploitable | Format-Table Name, State, StartMode, RunAs, Trigger, Vectors -AutoSize -Wrap
    } else {
        Write-Host "    Прямых прав на перезапись служб/папок для текущего токена не обнаружено.`n" -ForegroundColor Yellow
    }

    # ВЫВОД 2: Все сторонние службы (вне C:\Windows) — как работают и от кого запущены
    Write-Host "[+] 2. ВСЕ СТОРОННИЕ СЛУЖБЫ (ВНЕ C:\Windows):" -ForegroundColor Green
    $customTable | Format-Table Name, State, StartMode, RunAs, Trigger, Vectors, PathName -AutoSize -Wrap

    # ВЫВОД 3: Краткая сводка по всем запущенным сейчас службам (Running) вне стандартного svchost
    $runningNonSvcHost = $services | Where-Object { $_.State -eq 'Running' -and $_.PathName -notmatch '^"?C:\\Windows\\System32\\svchost\.exe' }
    Write-Host "[+] 3. АКТИВНЫЕ СЛУЖБЫ СЕЙЧАС (Running, кроме svchost): $($runningNonSvcHost.Count)" -ForegroundColor Cyan
    $runningNonSvcHost | Select-Object Name, DisplayName, StartMode, StartName, PathName | Format-Table -AutoSize -Wrap

    # ВЫВОД 4: Дополнительно прогоняем через accesschk.exe (если он загружен на машину)
    if (-not (Test-Path $AccessChkPath)) {
        if (Test-Path "C:\Windows\Temp\accesschk.exe") { $AccessChkPath = "C:\Windows\Temp\accesschk.exe" }
        elseif (Test-Path "C:\Temp\accesschk.exe")     { $AccessChkPath = "C:\Temp\accesschk.exe" }
    }
    if (Test-Path $AccessChkPath) {
        Write-Host "[+] 4. ПРОВЕРКА ЧЕРЕЗ ACCESSCHK ($AccessChkPath):" -ForegroundColor Green
        foreach ($p in @($env:USERNAME, "Users", "Authenticated Users", "Everyone")) {
            $res = & $AccessChkPath /accepteula -uwcqv "$p" * 2>$null
            if ($res -and $res -notmatch "No matching objects") {
                Write-Host "`n--- Найдены права в accesschk для [$p]: ---" -ForegroundColor Yellow
                $res
            }
        }
    }
}

Invoke-ServiceAudit