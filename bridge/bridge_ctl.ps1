param(
    [ValidateSet("start", "stop", "install", "uninstall", "status")]
    [string]$Action = "start"
)

$ErrorActionPreference = "SilentlyContinue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$BridgeDir = $PSScriptRoot
$ScriptPath = Join-Path $BridgeDir "warp_bridge.py"
$ApiBase = "http://127.0.0.1:10881"
$RunRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RunRegName = "PryWarpBridge"
$LegacyRegName = "WARPBridge"
$LegacyLnk = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\WARP_Bridge_Helper.lnk"

function Find-RealPython {
    param([switch]$Windowless)
    $exeName = if ($Windowless) { "pythonw.exe" } else { "python.exe" }

    $preferred = Join-Path $env:APPDATA "uv\python\cpython-3.12-windows-x86_64-none\$exeName"
    if (Test-Path $preferred) { return $preferred }

    $uvRoot = Join-Path $env:APPDATA "uv\python"
    if (Test-Path $uvRoot) {
        $uvFound = Get-ChildItem $uvRoot -Directory | Sort-Object Name -Descending | ForEach-Object {
            Join-Path $_.FullName $exeName
        } | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($uvFound) { return $uvFound }
    }

    $localPy = Join-Path $env:LOCALAPPDATA "Programs\Python"
    if (Test-Path $localPy) {
        $lpFound = Get-ChildItem $localPy -Directory | Sort-Object Name -Descending | ForEach-Object {
            Join-Path $_.FullName $exeName
        } | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($lpFound) { return $lpFound }
    }

    $whereHits = & where.exe $exeName 2>$null
    foreach ($hit in $whereHits) {
        if ($hit -and ($hit -notmatch "WindowsApps") -and (Test-Path $hit)) {
            return $hit
        }
    }

    if ($Windowless) {
        return Find-RealPython
    }
    return $null
}

function Get-BridgeStatus {
    try {
        return Invoke-RestMethod -Uri "$ApiBase/api/status" -TimeoutSec 2
    } catch {
        return $null
    }
}

function Stop-Bridge {
    Write-Host "[PryWarp Bridge] Остановка фонового моста..." -ForegroundColor Yellow
    try {
        Invoke-RestMethod -Method Post -Uri "$ApiBase/api/stop" -TimeoutSec 2 | Out-Null
    } catch {}

    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Milliseconds 350
        if (-not (Get-BridgeStatus)) { break }
    }

    Get-CimInstance Win32_Process -Filter "Name='mihomo.exe' OR Name='usque.exe'" | Where-Object {
        $_.ExecutablePath -like "$BridgeDir*"
    } | ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" | Where-Object {
        $_.CommandLine -like "*warp_bridge.py*"
    } | ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }

    Write-Host "[PryWarp Bridge] Мост остановлен." -ForegroundColor Green
}

function Start-Bridge {
    $existing = Get-BridgeStatus
    if ($existing -and $existing.state -eq "online") {
        $tr = ($existing.transport).ToUpper()
        Write-Host "[PryWarp Bridge] Уже работает ($($existing.colo) / $tr / $($existing.latency_ms) мс)." -ForegroundColor Green
        return $true
    }

    $pyw = Find-RealPython -Windowless
    if (-not $pyw) {
        Write-Host "[PryWarp Bridge] ОШИБКА: Не найден установленный Python 3 (кроме заглушки Microsoft Store)." -ForegroundColor Red
        Write-Host "Установи Python 3.10+ с https://www.python.org/downloads/ и повтори запуск." -ForegroundColor Yellow
        return $false
    }

    Write-Host "[PryWarp Bridge] Запуск фонового моста..." -ForegroundColor Cyan
    Start-Process -FilePath $pyw -ArgumentList @("-X", "utf8", "`"$ScriptPath`"") -WorkingDirectory $BridgeDir -WindowStyle Hidden

    $online = $false
    $lastSt = $null
    for ($i = 0; $i -lt 55; $i++) {
        Start-Sleep -Milliseconds 350
        $st = Get-BridgeStatus
        if ($st) {
            $lastSt = $st
            if ($st.state -eq "online" -and ($st.warp -eq "on" -or $st.warp -eq "plus")) {
                $online = $true
                break
            }
            if ($st.state -eq "error") {
                Write-Host "[PryWarp Bridge] ОШИБКА: $($st.last_error)" -ForegroundColor Red
                return $false
            }
        }
    }

    if ($online) {
        $tr = if ($lastSt.transport -eq "awg") { "AmneziaWG" } else { ($lastSt.transport).ToUpper() }
        Write-Host "[PryWarp Bridge] Готово! WARP работает ($($lastSt.colo) / $tr / $($lastSt.latency_ms) мс)." -ForegroundColor Green
        Write-Host "[PryWarp Bridge] SOCKS5: 127.0.0.1:$($lastSt.socks_port) | Системный IP, DNS и игры не затронуты." -ForegroundColor Gray
        return $true
    } elseif ($lastSt) {
        Write-Host "[PryWarp Bridge] Мост запущен, туннель WARP ещё подключается — через пару секунд в расширении загорится зелёный статус." -ForegroundColor Yellow
        return $true
    } else {
        Write-Host "[PryWarp Bridge] Мост не ответил на 127.0.0.1:10881. Проверь bridge\bridge.log." -ForegroundColor Red
        return $false
    }
}

switch ($Action) {
    "start" {
        $ok = Start-Bridge
        if (-not $ok) { Read-Host "Нажми Enter чтобы закрыть"; exit 1 }
        Start-Sleep -Seconds 2
    }
    "stop" {
        Stop-Bridge
        Start-Sleep -Seconds 2
    }
    "install" {
        $pyw = Find-RealPython -Windowless
        if (-not $pyw) {
            Write-Host "[PryWarp Bridge] ОШИБКА: Не найден Python 3 для автозапуска." -ForegroundColor Red
            Read-Host "Нажми Enter чтобы закрыть"
            exit 1
        }
        $cmdValue = "`"$pyw`" -X utf8 `"$ScriptPath`""
        Set-ItemProperty -Path $RunRegPath -Name $RunRegName -Value $cmdValue -Force
        if (Get-ItemProperty -Path $RunRegPath -Name $LegacyRegName -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $RunRegPath -Name $LegacyRegName -Force
        }
        if (Test-Path $LegacyLnk) { Remove-Item $LegacyLnk -Force }
        Write-Host "[PryWarp Bridge] Автозапуск с Windows включён (без окон и трея)." -ForegroundColor Green
        $ok = Start-Bridge
        if (-not $ok) { Read-Host "Нажми Enter чтобы закрыть"; exit 1 }
        Start-Sleep -Seconds 3
    }
    "uninstall" {
        Stop-Bridge
        foreach ($rk in @($RunRegName, $LegacyRegName)) {
            if (Get-ItemProperty -Path $RunRegPath -Name $rk -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $RunRegPath -Name $rk -Force
            }
        }
        if (Test-Path $LegacyLnk) { Remove-Item $LegacyLnk -Force }
        Write-Host "[PryWarp Bridge] Автозапуск удалён, фоновый мост остановлен." -ForegroundColor Green
        Start-Sleep -Seconds 2
    }
    "status" {
        $st = Get-BridgeStatus
        if ($st) {
            $st | ConvertTo-Json -Depth 4
        } else {
            Write-Host "offline"
        }
    }
}
