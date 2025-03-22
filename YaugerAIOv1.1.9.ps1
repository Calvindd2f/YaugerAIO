# Reliable Self-Elevation (must be first thing in the script!)
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    $scriptPath = $MyInvocation.MyCommand.Definition
    Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`"" -Verb RunAs
    exit
}

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

# Logging Setup
$timestamp = Get-Date -Format "yyyyMMdd"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$logFile = Join-Path $desktopPath "YAIO_$timestamp.log"
$script:log = @()
$script:foundAndFixedCorruption = $false
$script:StartTime = Get-Date
$script:runDiskCleanup = $false

function Log {
    param([string]$message, [string]$color = "Green")
    $script:log += $message
    Write-Host $message -ForegroundColor $color
}

# Improved ASCII Banner with "Proof of Concept" inserted next to the O shape
function Show-Banner {
    $asciiArt = @"
  __   __   ___    _    _   _____    _____    _____
  \ \ / /  / _ \  | |  | | /   _ \  |  ___|  |  _  \
   \ V /  | |_| | | |  | | | |___|  |  ___|  | |_| |
    | |   | | | | | |__| | | |____| | |____  | | \ \
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
        # Check if the line contains the O shape "\_____/"
        if ($line -match '\\_____/') {
            $match = [regex]::Match($line, '\\_____/')
            $endIndex = $match.Index + $match.Length
            $prefix = $line.Substring(0, $endIndex)
            $suffix = $line.Substring($endIndex)
            Write-Host -NoNewLine $prefix -ForegroundColor $colors[$i % $colors.Count]
            Write-Host -NoNewLine " Proof of Concept" -ForegroundColor White
            Write-Host $suffix -ForegroundColor $colors[$i % $colors.Count]
        } else {
            Write-Host $line -ForegroundColor $colors[$i % $colors.Count]
        }
    }
    Write-Host
}

# ----- Function Definitions -----

function Check-DiskSpace {
    try {
        # Use CIM to get total and free space of the C: drive
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $totalGB = [math]::Round($disk.Size / 1GB, 2)
        $freePercentage = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
        Log "C: Drive Free Space: $freeGB GB out of $totalGB GB ($freePercentage% free)" "Cyan"
    } catch {
        Log "Failed to retrieve disk space info: $_" "Red"
    }
}

function Check-CPUUsage {
    try {
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time'
        $usage = [math]::Round($cpu.CounterSamples.CookedValue, 2)
        Log "CPU Usage: $usage%" "Cyan"
    } catch {
        Log "Failed to retrieve CPU usage: $_" "Red"
    }
}

function Flush-DNSCache {
    try {
        $before = (Get-DnsClientCache).Count
        ipconfig /flushdns | Out-Null
        $after = (Get-DnsClientCache).Count
        $flushed = $before - $after
        Log "✔ DNS cache flushed. Entries removed: $flushed" "Green"
    } catch {
        Log "Failed to flush DNS cache: $_" "Red"
    }
}

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
            $script:log += $message -split "`n"
            Write-Host $message -ForegroundColor Red
        } elseif ($days -ge 3) {
            $message = @"
⚠️ Your system has been running for over 3 days.

Regularly restarting your computer helps:
- Apply critical updates
- Clear temporary files and memory leaks
- Improve performance and stability

For best results, restart at least once every few days.
"@
            $script:log += $message -split "`n"
            Write-Host $message -ForegroundColor Yellow
        }
    } catch {
        Log "Failed to retrieve system uptime: $_" "Red"
    }
}

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

            Install-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction SilentlyContinue | Out-Null
            Log "✔ $count updates installed successfully." "Cyan"

            $response = Read-Host "Updates installed. Do you want to restart now? (Y/N) - Auto restart in 60 seconds if no input"
            if ($response -match '^[Yy]$') {
                Log "User opted to restart. Restarting now..." "Cyan"
                Restart-Computer -Force
            } elseif ($response -match '^[Nn]$') {
                Log "User declined restart." "Yellow"
            } else {
                Log "No valid input received. System will restart in 60 seconds..." "Yellow"
                Start-Sleep -Seconds 60
                Restart-Computer -Force
            }
        } else {
            Log "✔ Your system is up to date. No updates found." "Cyan"
        }
    } catch {
        Log "Windows Update check failed: $_" "Red"
    }
}

function Clear-BrowserCaches {
    $cleared = $false
    try {
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
        $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"

        if (Test-Path $chromePath) {
            Remove-Item "$chromePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Log "✔ Chrome cache cleared." "Cyan"
            $cleared = $true
        }

        if (Test-Path $edgePath) {
            Remove-Item "$edgePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Log "✔ Edge cache cleared." "Cyan"
            $cleared = $true
        }

        if (-not $cleared) {
            Log "No browser cache folders found to clear." "Yellow"
        }
    } catch {
        Log "Failed to clear browser caches: $_" "Red"
    }
}

function Run-CleanMgr {
    try {
        cleanmgr /sagerun:1 | Out-Null
        Log "✔ Disk Cleanup (Cleanmgr) executed." "Green"
    } catch {
        Log "Disk cleanup failed: $_" "Red"
    }
}

function Run-DISMScan {
    try {
        Log "Running DISM Scan..."
        DISM /Online /Cleanup-Image /ScanHealth | Out-Null
        DISM /Online /Cleanup-Image /RestoreHealth | Out-Null
        Log "✔ DISM scan completed." "Green"
    } catch {
        Log "DISM scan failed: $_" "Red"
    }
}

function Run-SFCScan {
    Log "Running SFC Scan..."
    try {
        sfc /scannow | Out-Null
        Start-Sleep -Seconds 2
        $cbsLogPath = "$env:windir\Logs\CBS\CBS.log"
        $sfcLogContent = Get-Content -Path $cbsLogPath -Tail 500

        if ($sfcLogContent -match "Windows Resource Protection found corrupt files and successfully repaired") {
            $script:foundAndFixedCorruption = $true
            Log "System File Check scan found and fixed Windows Systems files Corruptions." "Blue"
        } elseif ($sfcLogContent -match "Windows Resource Protection did not find any integrity violations") {
            Log "Great news! No system file corruption found." "Blue"
        } elseif ($sfcLogContent -match "Windows Resource Protection found corrupt files but was unable to fix some of them") {
            Log "SFC found issues it couldn't fix. Instructions for sending the log are included in the output file." "Yellow"
            $instructions = @"
=====================
How to Send SFC Scan Log for Troubleshooting
=====================

1. Open PowerShell as Administrator.
2. Run:
   Select-String -Path "$env:windir\Logs\CBS\CBS.log" -Pattern "Beginning system scan" -Context 0,500 | Select-Object -Last 1 | Out-File -FilePath "$env:USERPROFILE\Desktop\SFC_Scan_Details.txt"
3. Email SFC_Scan_Details.txt to: rick.yauger@outlook.com
"@
            $script:log += $instructions
        } else {
            Log "✔ SFC Scan completed." "Cyan"
        }
    } catch {
        Log "SFC scan failed: $_" "Red"
    }
}

# ----- Main Execution Block -----

Show-Banner

Write-Host "During this session, we will:" -ForegroundColor White
Write-Host "- Check available disk space (C:) and optionally run Disk Cleanup" -ForegroundColor White
Write-Host "- Check current CPU usage" -ForegroundColor White
Write-Host "- Flush the DNS cache" -ForegroundColor White
Write-Host "- Check RAM usage" -ForegroundColor White
Write-Host "- Check GPU driver(s) and version(s)" -ForegroundColor White
Write-Host "- Log how long your system has been running (uptime)" -ForegroundColor White
Write-Host "- Clear browser caches (Chrome, Edge, Firefox, Brave, Opera)" -ForegroundColor White
Write-Host "- Run a DISM scan to check and restore system health" -ForegroundColor White
Write-Host "- Run an SFC scan to detect and repair corrupted system files" -ForegroundColor White
Write-Host "- Check for and install Windows Updates" -ForegroundColor White
Write-Host "" -ForegroundColor White
Write-Host "Please press Enter to begin." -ForegroundColor White
[void][System.Console]::ReadLine()

# Prompt for optional Disk Cleanup
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
Run-WindowsUpdate
Log "✔ Browser caches cleared to free up disk space." "Cyan"
Clear-BrowserCaches

if ($script:runDiskCleanup) {
    Run-CleanMgr
}

Run-DISMScan
Run-SFCScan

$finalFree = (Get-PSDrive -Name C).Free
$cleanSpaceFreed = [math]::Round(($finalFree - $initialFreeSpace) / 1GB, 2)
if ($cleanSpaceFreed -lt 0) { $cleanSpaceFreed = 0 }

Log "✔ Total space freed during this session: $cleanSpaceFreed GB" "Cyan"
if ($script:foundAndFixedCorruption) {
    Log "✔ Windows system file corruptions were found and repaired." "Cyan"
}

$duration = (Get-Date) - $script:StartTime
Log "⏱ Total script runtime: $($duration.ToString())" "Cyan"

# Save log to file
$script:log | Out-File -FilePath $logFile -Encoding UTF8

Log "=============================================" "Cyan"
Log "YaugerAIO tasks completed." "Blue"
Log "Thank you for using YaugerAIO. Check the log file on your desktop for details. For bugs or feedback, email rick.yauger@outlook.com. Thanks for helping improve YaugerAIO!" "Blue"
