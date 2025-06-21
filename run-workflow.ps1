# Simple script to run YaugerAIO workflow with error handling
# This script tests the fixes we made

Write-Host "=== YaugerAIO Workflow Test ===" -ForegroundColor Magenta

try {
    # Import the classes
    . "$PSScriptRoot\YaugerAIOclasses.ps1"
    Write-Host "Classes imported successfully" -ForegroundColor Green

    # Create interface
    $interface = [YaugerInterface]::new($PSScriptRoot)
    Write-Host "Interface created successfully" -ForegroundColor Green

    # Start workflow with error handling
    Write-Host "Starting workflow..." -ForegroundColor Yellow
    $interface.StartWorkflow($true, $true)  # Fast mode, continue on error

    # Get results
    $summary = $interface.GetWorkflowSummary()
    $tasks = $interface.GetTaskResults()
    $failures = $interface.GetFailures()

    # Display summary
    Write-Host ""
    Write-Host "=== Workflow Summary ===" -ForegroundColor Magenta
    Write-Host "Session ID: $($summary.SessionId)" -ForegroundColor White
    Write-Host "Total Tasks: $($summary.TotalTasks)" -ForegroundColor White
    Write-Host "Successful: $($summary.SuccessfulTasks)" -ForegroundColor Green
    Write-Host "Failed: $($summary.FailedTasks)" -ForegroundColor $(if ($summary.FailedTasks -gt 0) { "Red" } else { "White" })
    Write-Host "Skipped: $($summary.SkippedTasks)" -ForegroundColor White
    Write-Host "Duration: $($summary.SessionDuration.ToString('hh\:mm\:ss'))" -ForegroundColor White

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
    Write-Host "Workflow completed!" -ForegroundColor Green

} catch {
    Write-Host "Workflow failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
} 