# YaugerAIO Main Interface Script
# This script demonstrates the new data management system with repository pattern

# Import the classes
# Import classes if available
try {
    . "$PSScriptRoot\YaugerAIOclasses.ps1"
} catch {
    Write-Warning "Could not load YaugerAIOclasses.ps1: $($_.Exception.Message)"
}

# Import the main module
Import-Module "$PSScriptRoot\YaugerAIO.psm1" -Force

function Start-YaugerAIOWorkflow {
    <#
    .SYNOPSIS
        Starts the YaugerAIO workflow with the new data management system.

    .DESCRIPTION
        This function initializes the YaugerAIO interface and executes the workflow
        with options for fast mode and error handling.

    .PARAMETER FastMode
        When true, uses fast disk cleanup mode. When false, uses full disk cleanup.
        Default is true.

    .PARAMETER ContinueOnError
        When true, continues execution even if individual tasks fail.
        Default is true.

    .PARAMETER GenerateReports
        When true, generates performance and storage reports after workflow completion.
        Default is true.

    .EXAMPLE
        Start-YaugerAIOWorkflow -FastMode $true -ContinueOnError $true

    .EXAMPLE
        Start-YaugerAIOWorkflow -FastMode $false -ContinueOnError $false

    .NOTES
        This function uses the new YaugerInterface class to manage the workflow
        and provides comprehensive logging and error handling.
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [bool]$FastMode = $true,

        [Parameter()]
        [bool]$ContinueOnError = $true,

        [Parameter()]
        [bool]$GenerateReports = $true
    )

    try {
        Write-Host "=== YaugerAIO Data Management System ===" -ForegroundColor Magenta
        Write-Host "Initializing workflow..." -ForegroundColor Yellow

        # Initialize the interface
        $interface = [YaugerInterface]::new($PSScriptRoot)

        # Display configuration
        Write-Host "Configuration:" -ForegroundColor Cyan
        Write-Host "  Fast Mode: $FastMode" -ForegroundColor White
        Write-Host "  Continue on Error: $ContinueOnError" -ForegroundColor White
        Write-Host "  Generate Reports: $GenerateReports" -ForegroundColor White
        Write-Host ""

        # Start the workflow
        $interface.StartWorkflow($FastMode, $ContinueOnError)

        # Get results
        $summary = $interface.GetWorkflowSummary()
        $tasks = $interface.GetTaskResults()
        $failures = $interface.GetFailures()
        $latestMetrics = $interface.GetLatestMetrics()
        $previousMetrics = $interface.GetPreviousMetrics()

        # Display summary
        Write-Host ""
        Write-Host "=== Workflow Summary ===" -ForegroundColor Magenta
        Write-Host "Session ID: $($summary.SessionId)" -ForegroundColor White
        Write-Host "Total Tasks: $($summary.TotalTasks)" -ForegroundColor White
        Write-Host "Successful: $($summary.SuccessfulTasks)" -ForegroundColor Green
        Write-Host "Failed: $($summary.FailedTasks)" -ForegroundColor $(if ($summary.FailedTasks -gt 0) { "Red" } else { "White" })
        Write-Host "Skipped: $($summary.SkippedTasks)" -ForegroundColor White
        Write-Host "Duration: $($summary.SessionDuration.ToString('hh\:mm\:ss'))" -ForegroundColor White

        # Display storage changes if available
        if ($latestMetrics -and $previousMetrics) {
            Write-Host ""
            Write-Host "=== Storage Changes ===" -ForegroundColor Magenta
            Write-Host "Free Space Change: $($latestMetrics.storageFreeGBChange) GB" -ForegroundColor $(if ([double]$latestMetrics.storageFreeGBChange -gt 0) { "Green" } else { "White" })
            Write-Host "Used Space Change: $($latestMetrics.storageUsedGBChange) GB" -ForegroundColor $(if ([double]$latestMetrics.storageUsedGBChange -lt 0) { "Green" } else { "White" })
        }

        # Display failed tasks if any
        if ($failures.Count -gt 0) {
            Write-Host ""
            Write-Host "=== Failures ===" -ForegroundColor Red
            foreach ($failure in $failures) {
                Write-Host "  $($failure.name): $($failure.description)" -ForegroundColor Red
            }
        }

        # Display task details
        Write-Host ""
        Write-Host "=== Task Details ===" -ForegroundColor Magenta
        foreach ($task in $tasks) {
            $status = if ($task.isSuccess) { "OK" } elseif ($task.isFailed) { "FAIL" } else { "-" }
            $color = if ($task.isSuccess) { "Green" } elseif ($task.isFailed) { "Red" } else { "Yellow" }
            Write-Host "  $status $($task.name) ($($task.duration.ToString('mm\:ss')))" -ForegroundColor $color
        }

        Write-Host ""
        Write-Host "Workflow completed successfully!" -ForegroundColor Green

        return @{
            Interface       = $interface
            Summary         = $summary
            Tasks           = $tasks
            Failures        = $failures
            LatestMetrics   = $latestMetrics
            PreviousMetrics = $previousMetrics
        }
    }
    catch {
        Write-Error "Workflow failed: $($_.Exception.Message)"
        throw
    }
}

function Get-YaugerAIOStatus {
    <#
    .SYNOPSIS
        Gets the current status of the YaugerAIO system.

    .DESCRIPTION
        This function provides information about the current state of the system
        including storage metrics and recent activity.
    #>

    [CmdletBinding()]
    param()

    try {
        Write-Host "=== YaugerAIO System Status ===" -ForegroundColor Magenta

        # Get basic system information
        $os = Get-WmiObject -Class Win32_OperatingSystem
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem

        Write-Host "System Information:" -ForegroundColor Cyan
        Write-Host "  OS: $($os.Caption) $($os.OSArchitecture)" -ForegroundColor White
        Write-Host "  Computer: $($computerSystem.Name)" -ForegroundColor White
        Write-Host "  Total Memory: $([math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)) GB" -ForegroundColor White

        # Get storage information
        $drives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }

        Write-Host ""
        Write-Host "Storage Information:" -ForegroundColor Cyan
        foreach ($drive in $drives) {
            $freeGB = [math]::Round($drive.FreeSpace / 1GB, 2)
            $totalGB = [math]::Round($drive.Size / 1GB, 2)
            $usedGB = $totalGB - $freeGB
            $freePercent = [math]::Round(($freeGB / $totalGB) * 100, 1)

            Write-Host "  Drive $($drive.DeviceID):" -ForegroundColor White
            Write-Host "    Total: $totalGB GB" -ForegroundColor White
            Write-Host "    Used: $usedGB GB" -ForegroundColor White
            Write-Host "    Free: $freeGB GB ($freePercent%)" -ForegroundColor $(if ($freePercent -lt 10) { "Red" } elseif ($freePercent -lt 20) { "Yellow" } else { "Green" })
        }

        # Get recent processes
        Write-Host ""
        Write-Host "Recent High-Memory Processes:" -ForegroundColor Cyan
        $processes = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 5
        foreach ($process in $processes) {
            $memoryMB = [math]::Round($process.WorkingSet / 1MB, 1)
            Write-Host "  $($process.ProcessName): $memoryMB MB" -ForegroundColor White
        }

    }
    catch {
        Write-Error "Failed to get system status: $($_.Exception.Message)"
    }
}

function Test-YaugerAIOSystem {
    <#
    .SYNOPSIS
        Tests the YaugerAIO system components.

    .DESCRIPTION
        This function performs basic tests to ensure all components are working correctly.
    #>

    [CmdletBinding()]
    param()

    try {
        Write-Host "=== YaugerAIO System Test ===" -ForegroundColor Magenta

        # Test 1: Check if classes can be instantiated
        Write-Host "Testing class instantiation..." -ForegroundColor Yellow
        $repository = [YaugerRepository]::new()
        Write-Host "OK Repository class instantiated" -ForegroundColor Green

        $interface = [YaugerInterface]::new($PSScriptRoot)
        Write-Host "OK Interface class instantiated" -ForegroundColor Green

        # Test 2: Check if required scripts exist
        Write-Host "Testing script availability..." -ForegroundColor Yellow
        $requiredScripts = @(
            "Public\fastchecks.ps1",
            "Private\DebugInfo.ps1",
            "Private\FileStorageInfo.ps1"
        )

        foreach ($script in $requiredScripts) {
            $scriptPath = Join-Path $PSScriptRoot $script
            if (Test-Path $scriptPath) {
                Write-Host "OK $script found" -ForegroundColor Green
            }
            else {
                Write-Host "FAIL $script not found" -ForegroundColor Red
            }
        }

        # Test 3: Check if functions can be loaded
        Write-Host "Testing function loading..." -ForegroundColor Yellow
        $fastchecksPath = Join-Path $PSScriptRoot "Public\fastchecks.ps1"
        if (Test-Path $fastchecksPath) {
            . $fastchecksPath
            $functions = @("RebuildRegistryIndex", "CheckHibernation", "DisableFastBoot")
            foreach ($function in $functions) {
                if (Get-Command $function -ErrorAction SilentlyContinue) {
                    Write-Host "OK Function $function loaded" -ForegroundColor Green
                }
                else {
                    Write-Host "FAIL Function $function not found" -ForegroundColor Red
                }
            }
        }

        # Test 4: Check disk space
        Write-Host "Testing disk space..." -ForegroundColor Yellow
        $systemDrive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }
        if ($systemDrive) {
            $freeGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
            Write-Host "OK System drive has $freeGB GB free space" -ForegroundColor Green
        }
        else {
            Write-Host "FAIL Cannot access system drive information" -ForegroundColor Red
        }

        Write-Host ""
        Write-Host "System test completed!" -ForegroundColor Green

    }
    catch {
        Write-Error "System test failed: $($_.Exception.Message)"
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Start-YaugerAIOWorkflow',
    'Get-YaugerAIOStatus',
    'Test-YaugerAIOSystem'
)
# Example usage (commented out)
<#
# Start the workflow in fast mode with error continuation
$results = Start-YaugerAIOWorkflow -FastMode $true -ContinueOnError $true

# Get system status
Get-YaugerAIOStatus

# Test the system
Test-YaugerAIOSystem
#>