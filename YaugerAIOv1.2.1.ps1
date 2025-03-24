# Reliable Self-Elevation (this makes sure the script is run as admin!)
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    $scriptPath = $MyInvocation.MyCommand.Definition
    Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`"" -Verb RunAs
    exit
}

# Set the execution policy for this session so our script runs smoothly
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

# Setup for logging our actions to a file on your Desktop.
$timestamp = Get-Date -Format "yyyyMMdd"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$logFile = Join-Path $desktopPath "YAIO_$timestamp.log"
$script:log = @()                           # This array will collect our log messages.
$script:foundAndFixedCorruption = $false     # Flag to know if SFC fixed any problems.
$script:StartTime = Get-Date                 # Record when the script started.
$script:runDiskCleanup = $false              # Will be set if the user wants to run Disk Cleanup.
$script:needsRestart = $false                # Flag to check if a restart is needed after updates.

function Log {
    param([string]$message, [string]$color = "Green")
    # Save the message in the log and output it in the specified color.
    $script:log += $message
    Write-Host $message -ForegroundColor $color
}

# --------------------------
# Show-Banner (Fancier Version with Instant Reveal)
# --------------------------
function Show-Banner {
    $asciiArt = @"
  __   __   ___    _    _   _____    _____    _____
  \ \ / /  / _ \  | |  | | /  ___\  |  ___|  |  _  \
   \ V /  | |_| | | |  | | | |____  |  ___|  | |_| |
    | |   | | | | | |__| | | |__| | | |____  | | \ \
    |_|   |_| |_| \______/ |______| |______| |_|  |_|
               _____     ___     _____
              /  _  \   |_ _|   /  _  \
              | |_| |    | |    | | | |
              | | | |    | |    | |_| |
              |_| |_|   |___|   \_____/
"@
    $colors = @("Red", "Yellow", "Green", "Cyan", "Blue", "Magenta")
    $lines = $asciiArt -split "`n"
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]
        if ($line -match '\\_____/') {
            # Original behavior for lines containing the marker.
            $match = [regex]::Match($line, '\\_____/')
            $endIndex = $match.Index + $match.Length
            $prefix = $line.Substring(0, $endIndex)
            $suffix = $line.Substring($endIndex)
            Write-Host -NoNewLine $prefix -ForegroundColor $colors[$i % $colors.Count]
            Write-Host -NoNewLine " Proof of Concept" -ForegroundColor White
            Write-Host $suffix -ForegroundColor $colors[$i % $colors.Count]
        }
        else {
            # Print each line instantly with per-character color cycling.
            $trimmedLine = $line.TrimEnd()
            for ($j = 0; $j -lt $trimmedLine.Length; $j++) {
                $char = $trimmedLine[$j]
                $color = $colors[$j % $colors.Count]
                Write-Host -NoNewLine $char -ForegroundColor $color
            }
            Write-Host ""
        }
    }
    Write-Host ""
}

# --------------------------
# Check-DiskSpace
# --------------------------
function Check-DiskSpace {
    try {
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $totalGB = [math]::Round($disk.Size / 1GB, 2)
        $freePercentage = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
        Log "C: Drive Free Space: $freeGB GB out of $totalGB GB ($freePercentage% free)" "Cyan"
    } catch {
        Log "Failed to retrieve disk space info: $_" "Red"
    }
}

# --------------------------
# Check-CPUUsage
# --------------------------
function Check-CPUUsage {
    try {
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time'
        $usage = [math]::Round($cpu.CounterSamples.CookedValue, 2)
        Log "CPU Usage: $usage%" "Cyan"
    } catch {
        Log "Failed to retrieve CPU usage: $_" "Red"
    }
}

# --------------------------
# Flush-DNSCache
# --------------------------
function Flush-DNSCache {
    try {
        $before = (Get-DnsClientCache).Count
        ipconfig /flushdns | Out-Null
        $after = (Get-DnsClientCache).Count
        $flushed = $before - $after
        Log "✔ DNS cache flushed." "Green"
        Log "Entries removed: $flushed" "Cyan"
    } catch {
        Log "Failed to flush DNS cache: $_" "Red"
    }
}

# --------------------------
# Check-RAMUsage
# --------------------------
function Check-RAMUsage {
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $total = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $free = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $used = [math]::Round($total - $free, 2)
        $percentUsed = [math]::Round(($used / $total) * 100, 2)
        Log "RAM Usage: $used GB of $total GB ($percentUsed%)" "Cyan"
    } catch {
        Log "Failed to retrieve RAM usage: $_" "Red"
    }
}

# --------------------------
# Check-GPUDrivers
# --------------------------
function Check-GPUDrivers {
    try {
        $gpus = Get-CimInstance Win32_VideoController
        foreach ($gpu in $gpus) {
            Log "GPU Detected: $($gpu.Name) - Driver Version: $($gpu.DriverVersion)" "Cyan"
        }
    } catch {
        Log "Failed to retrieve GPU driver info: $_" "Red"
    }
}

# --------------------------
# Check-SystemUptime
# --------------------------
function Check-SystemUptime {
    try {
        $uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
        $days = [math]::Round($uptime.TotalDays, 2)
        Log "System Uptime: $days days" "Cyan"
        if ($days -ge 7) {
            $message = @"
🚨 Your system has been running for over a week without a restart!
This can lead to performance issues, memory leaks, and failed updates.
It is strongly recommended that you restart your computer ASAP.
Make it a habit to restart at least every 2-3 days for optimal performance.
"@
            Log $message "Red"
        } elseif ($days -ge 3) {
            $message = @"
⚠️ Your system has been running for over 3 days.
Regularly restarting your computer helps:
- Apply critical updates
- Clear temporary files and memory leaks
- Improve performance and stability
For best results, restart at least once every few days.
"@
            Log $message "Yellow"
        }
    } catch {
        Log "Failed to retrieve system uptime: $_" "Red"
    }
}

# --------------------------
# Run-WindowsUpdate
# --------------------------
function Run-WindowsUpdate {
    try {
        Log "Checking for Windows updates..." "Cyan"
        if (-not (Get-Module -Name PSWindowsUpdate)) {
            Install-Module PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction SilentlyContinue | Out-Null
            Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
        } else {
            Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
        }
        $updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction SilentlyContinue
        if ($updates) {
            $count = $updates.Count
            Log "✔ Updates found: $count. Installing now..." "Cyan"
            foreach ($update in $updates) {
                Log "- $($update.Title)" "Cyan"
            }
            $installedUpdates = @(Install-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction SilentlyContinue)
            if ($installedUpdates) {
                $installedCount = $installedUpdates.Count
                Log "✔ $installedCount updates installed successfully:" "Cyan"
                foreach ($instUpdate in $installedUpdates) {
                    Log "- $($instUpdate.Title)" "Cyan"
                }
            } else {
                Log "✔ Updates installation completed, but no update details were returned." "Cyan"
            }
            $script:needsRestart = $true
            Log "Please restart your computer later to complete the update process." "Yellow"
        } else {
            Log "✔ Your system is up to date. No updates found." "Cyan"
        }
    } catch {
        Log "Windows Update check failed: $_" "Red"
    }
}

# --------------------------
# Clear-BrowserCaches
# --------------------------
function Clear-BrowserCaches {
    try {
        # Chrome
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
        if ((Test-Path $chromePath)) {
            Remove-Item "$chromePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Log "✔ Chrome cache cleared." "Cyan"
        } else {
            Log "✔ User doesn't have Chrome Browser." "Cyan"
        }

        # Edge
        $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
        if ((Test-Path $edgePath)) {
            Remove-Item "$edgePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Log "✔ Edge cache cleared." "Cyan"
        } else {
            Log "✔ User doesn't have Edge Browser." "Cyan"
        }

        # Brave
        $bravePath = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache"
        if ((Test-Path $bravePath)) {
            Remove-Item "$bravePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Log "✔ Brave cache cleared." "Cyan"
        } else {
            Log "✔ User doesn't have Brave Browser." "Cyan"
        }

        # Opera – Check if Opera Software folder exists
        if ((Test-Path "$env:LOCALAPPDATA\Opera Software") -or (Test-Path "$env:APPDATA\Opera Software")) {
            $foundOpera = $false
            $operaStableLocal = "$env:LOCALAPPDATA\Opera Software\Opera Stable\Cache"
            $operaStableRoaming = "$env:APPDATA\Opera Software\Opera Stable\Cache"
            if ((Test-Path $operaStableLocal) -or (Test-Path $operaStableRoaming)) {
                if (Test-Path $operaStableLocal) { Remove-Item "$operaStableLocal\*" -Recurse -Force -ErrorAction SilentlyContinue }
                if (Test-Path $operaStableRoaming) { Remove-Item "$operaStableRoaming\*" -Recurse -Force -ErrorAction SilentlyContinue }
                $foundOpera = $true
            }
            $operaGXLocal = "$env:LOCALAPPDATA\Opera Software\Opera GX\Cache"
            $operaGXRoaming = "$env:APPDATA\Opera Software\Opera GX\Cache"
            if ((Test-Path $operaGXLocal) -or (Test-Path $operaGXRoaming)) {
                if (Test-Path $operaGXLocal) { Remove-Item "$operaGXLocal\*" -Recurse -Force -ErrorAction SilentlyContinue }
                if (Test-Path $operaGXRoaming) { Remove-Item "$operaGXRoaming\*" -Recurse -Force -ErrorAction SilentlyContinue }
                $foundOpera = $true
            }
            Log "✔ Opera cache cleared." "Cyan"
        }
        else {
            Log "✔ User doesn't have Opera Browser." "Cyan"
        }

        # Firefox – Check if Firefox folder exists
        if (Test-Path "$env:APPDATA\Mozilla\Firefox") {
            $foundFirefox = $false
            $firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
            if (Test-Path $firefoxProfilesPath) {
                $profiles = Get-ChildItem -Path $firefoxProfilesPath -Directory -ErrorAction SilentlyContinue
                foreach ($profile in $profiles) {
                    $cache2Path = (Join-Path $profile.FullName "cache2")
                    $cachePath = (Join-Path $profile.FullName "cache")
                    if ((Test-Path $cache2Path) -or (Test-Path $cachePath)) {
                        if (Test-Path $cache2Path) { Remove-Item "$cache2Path\*" -Recurse -Force -ErrorAction SilentlyContinue }
                        if (Test-Path $cachePath) { Remove-Item "$cachePath\*" -Recurse -Force -ErrorAction SilentlyContinue }
                        $foundFirefox = $true
                    }
                }
            }
            Log "✔ Firefox cache cleared." "Cyan"
        }
        else {
            Log "✔ User doesn't have Firefox Browser." "Cyan"
        }
    } catch {
        Log "Failed to clear browser caches: $_" "Red"
    }
}

# --------------------------
# Run-CleanMgr
# --------------------------
function Run-CleanMgr {
    try {
        cleanmgr /sagerun:1 | Out-Null
        Log "✔ Disk Cleanup executed." "Cyan"
    } catch {
        Log "Disk Cleanup failed: $_" "Red"
    }
}

# --------------------------
# Run-DISMScan
# --------------------------
function Run-DISMScan {
    Log "Running DISM Scan..." "Green"
    $dismStdOut = Join-Path $env:TEMP "DISM_stdout.log"
    $dismStdErr = Join-Path $env:TEMP "DISM_stderr.log"
    if (Test-Path $dismStdOut) { Remove-Item $dismStdOut -Force }
    if (Test-Path $dismStdErr) { Remove-Item $dismStdErr -Force }
    $proc = Start-Process -FilePath "dism.exe" `
             -ArgumentList "/Online", "/Cleanup-Image", "/RestoreHealth" `
             -RedirectStandardOutput $dismStdOut -RedirectStandardError $dismStdErr `
             -PassThru -NoNewWindow
    $loadingStates = @(" .  ", " .. ", " ...")
    $loadingIndex = 0
    while (-not $proc.HasExited) {
        Write-Host -NoNewLine "`rScanning" -ForegroundColor Green
        Write-Host -NoNewLine $loadingStates[$loadingIndex] -ForegroundColor Green
        $loadingIndex = ($loadingIndex + 1) % $loadingStates.Length
        Start-Sleep 1
    }
    # After completion, default to three dots
    Write-Host "`rScanning ..." -ForegroundColor Green
    Write-Host ""
    $finalLines = @()
    if (Test-Path $dismStdOut) { $finalLines += Get-Content -Path $dismStdOut -Encoding Unicode }
    if (Test-Path $dismStdErr) { $finalLines += Get-Content -Path $dismStdErr -Encoding Unicode }
    $script:log += "DISM Detailed Output:"
    foreach ($line in $finalLines) {
        $script:log += $line
    }
    Write-Host "DISM Scan complete." -ForegroundColor Cyan
}

# --------------------------
# Run-SFCScan (Updated with Dot Animation)
# --------------------------
function Run-SFCScan {
    Log "Running SFC Scan..." "Green"
    $sfcStdOut = Join-Path $env:TEMP "SFC_stdout.log"
    $sfcStdErr = Join-Path $env:TEMP "SFC_stderr.log"
    if (Test-Path $sfcStdOut) { Remove-Item $sfcStdOut -Force }
    if (Test-Path $sfcStdErr) { Remove-Item $sfcStdErr -Force }
    $proc = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" `
             -RedirectStandardOutput $sfcStdOut -RedirectStandardError $sfcStdErr `
             -PassThru -NoNewWindow

    $loadingStates = @(" .  ", " .. ", " ...")
    $loadingIndex = 0
    while (-not $proc.HasExited) {
        Write-Host -NoNewLine "`rScanning" -ForegroundColor Green
        Write-Host -NoNewLine $loadingStates[$loadingIndex] -ForegroundColor Green
        $loadingIndex = ($loadingIndex + 1) % $loadingStates.Length
        Start-Sleep 1
    }
    # After completion, default to three dots
    Write-Host "`rScanning ..." -ForegroundColor Green
    Write-Host ""

    $finalLines = @()
    if (Test-Path $sfcStdOut) { $finalLines += Get-Content -Path $sfcStdOut -Encoding Unicode }
    if (Test-Path $sfcStdErr) { $finalLines += Get-Content -Path $sfcStdErr -Encoding Unicode }
    if ($finalLines -match "did not find any integrity violations") {
        Log "SFC Result: No integrity violations found." "Cyan"
    }
    elseif ($finalLines -match "found corrupt files and successfully repaired them") {
        Log "SFC Result: Found corrupt files and **repaired** them." "Cyan"
    }
    elseif ($finalLines -match "found corrupt files but was unable to fix") {
        Log "SFC Result: Found corrupt files but **could not fix all** of them." "Cyan"
    }
    else {
        Log "SFC Result: Completed with errors or warnings – check CBS.log for details." "Cyan"
    }
}

# --------------------------
# Main Execution Block
# --------------------------
Show-Banner

Write-Host "During this session, we will:" -ForegroundColor White
Write-Host "- Check available disk space (C:) and optionally run Disk Cleanup" -ForegroundColor White
Write-Host "- Check current CPU usage" -ForegroundColor White
Write-Host "- Flush the DNS cache" -ForegroundColor White
Write-Host "- Check RAM usage" -ForegroundColor White
Write-Host "- Check GPU driver(s) and version(s)" -ForegroundColor White
Write-Host "- Log how long your system has been running (uptime)" -ForegroundColor White
Write-Host "- Clear browser caches (Chrome, Edge, Brave, Opera, Firefox)" -ForegroundColor White
Write-Host "- Run a DISM scan to check and restore system health" -ForegroundColor White
Write-Host "- Run an SFC scan to detect and repair corrupted system files" -ForegroundColor White
Write-Host "- Check for and install Windows Updates" -ForegroundColor White
Write-Host "" -ForegroundColor White

Write-Host "Please close all of your Web Browsers. We will be clearing their caches." -ForegroundColor Yellow
Write-Host "" -ForegroundColor White

Write-Host "Please press Enter to begin." -ForegroundColor White
[void][System.Console]::ReadLine()

$response = Read-Host "Would you like to run Disk Cleanup? (Y/N)"
if ($response -match '^[Yy]$') {
    $script:runDiskCleanup = $true
    Log "✔ Disk Cleanup will be performed." "Green"
} else {
    Log "⏭ Disk Cleanup skipped." "Yellow"
}
$initialFreeSpace = (Get-PSDrive -Name C).Free

Check-DiskSpace
Check-CPUUsage
Flush-DNSCache
Check-RAMUsage
Check-GPUDrivers
Check-SystemUptime

Log "✔ Clearing browser caches to free up disk space..." "Green"
Clear-BrowserCaches

if ($script:runDiskCleanup) {
    Run-CleanMgr
}

Run-DISMScan
Run-SFCScan

# Run Windows Updates so its output is captured in the log and runtime
Run-WindowsUpdate

$finalFree = (Get-PSDrive -Name C).Free
$spaceFreedBytes = $finalFree - $initialFreeSpace
# Prevent negative free space values from displaying.
if ($spaceFreedBytes -lt 0) { $spaceFreedBytes = 0 }
if ($spaceFreedBytes -ge 1GB) {
    $spaceFreedFormatted = ("{0:N2} GB" -f ($spaceFreedBytes / 1GB))
} else {
    $spaceFreedFormatted = ("{0:N2} MB" -f ($spaceFreedBytes / 1MB))
}
Log "✔ Total space freed during this session: $spaceFreedFormatted" "Cyan"

if ($script:foundAndFixedCorruption) {
    Log "✔ Windows system file corruptions were found and repaired." "Cyan"
}

# Calculate total runtime after Windows Updates are done
$duration = (Get-Date) - $script:StartTime
Log "⏱ Total script runtime: $($duration.ToString())" "Cyan"

# Write the complete log to a file after all actions (including Windows Updates) are done.
$script:log | Out-File -FilePath $logFile -Encoding UTF8

# Now, prompt for restart if needed.
if ($script:needsRestart) {
    $response = Read-Host "Updates installed require a restart. Restart now? (Y/N) - Auto restart in 60 seconds if no input"
    if ($response -match '^[Yy]$') {
         Log "Restarting now as per user request..." "Yellow"
         Restart-Computer -Force
    } elseif ($response -match '^[Nn]$') {
         Log "User declined restart." "Yellow"
    } else {
         Log "No valid input received. System will restart in 60 seconds..." "Yellow"
         Start-Sleep -Seconds 60
         Restart-Computer -Force
    }
}

Log "=============================================" "Cyan"
Log "YaugerAIO tasks completed." "Blue"
Log "Thank you for using YaugerAIO. Check the log file on your desktop for details. For bugs or feedback, email rick.yauger@outlook.com. Thanks for helping improve YaugerAIO!" "Blue"
