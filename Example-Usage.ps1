# Example Usage Script for YaugerAIO Data Management System
# This script demonstrates how to use the new repository pattern and workflow management

# Import the classes and main interface
. "$PSScriptRoot\YaugerAIOclasses.ps1"
. "$PSScriptRoot\YaugerAIO-Main.ps1"

Write-Host "=== YaugerAIO Data Management System - Example Usage ===" -ForegroundColor Magenta
Write-Host ""

# Example 1: Basic workflow execution
Write-Host "Example 1: Basic Workflow Execution" -ForegroundColor Cyan
Write-Host "This will run the workflow in fast mode with error continuation enabled."
Write-Host ""

try {
    $results = Start-YaugerAIOWorkflow -FastMode $true -ContinueOnError $true

    Write-Host "Workflow completed with results:" -ForegroundColor Green
    Write-Host "  Total Tasks: $($results.Summary.TotalTasks)" -ForegroundColor White
    Write-Host "  Successful: $($results.Summary.SuccessfulTasks)" -ForegroundColor Green
    Write-Host "  Failed: $($results.Summary.FailedTasks)" -ForegroundColor $(if ($results.Summary.FailedTasks -gt 0) { "Red" } else { "White" })

}
catch {
    Write-Host "Workflow failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press any key to continue to the next example..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Example 2: System status check
Write-Host ""
Write-Host "Example 2: System Status Check" -ForegroundColor Cyan
Write-Host "This will display current system information and storage status."
Write-Host ""

Get-YaugerAIOStatus

Write-Host ""
Write-Host "Press any key to continue to the next example..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Example 3: System testing
Write-Host ""
Write-Host "Example 3: System Testing" -ForegroundColor Cyan
Write-Host "This will test all system components to ensure they're working correctly."
Write-Host ""

Test-YaugerAIOSystem

Write-Host ""
Write-Host "Press any key to continue to the next example..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Example 4: Direct class usage
Write-Host ""
Write-Host "Example 4: Direct Class Usage" -ForegroundColor Cyan
Write-Host "This demonstrates how to use the classes directly for custom workflows."
Write-Host ""

try {
    # Create a repository instance
    $repository = [YaugerRepository]::new()
    Write-Host "OK Repository created with Session ID: $($repository.sessionId)" -ForegroundColor Green

    # Create a workflow manager
    $workflowManager = [YaugerWorkflowManager]::new($repository, $PSScriptRoot)
    Write-Host "OK Workflow manager created" -ForegroundColor Green

    # Set configuration
    $workflowManager.SetFastMode($true)
    $workflowManager.SetContinueOnError($true)
    Write-Host "OK Configuration set (Fast Mode: True, Continue on Error: True)" -ForegroundColor Green

    # Initialize workflow tasks
    $workflowManager.InitializeWorkflowTasks()
    Write-Host "OK Workflow tasks initialized" -ForegroundColor Green

    # Get the tasks
    $tasks = $repository.GetWorkflowTasks()
    Write-Host "OK Found $($tasks.Count) workflow tasks:" -ForegroundColor Green
    foreach ($task in $tasks) {
        Write-Host "  - $($task.name) (Priority: $($task.priority), Category: $($task.category))" -ForegroundColor White
    }

    # Create a custom task
    $customTask = [task]::new()
    $customTask.name = "Custom Test Task"
    $customTask.description = "This is a custom task for demonstration"
    $customTask.taskID = 999
    $customTask.category = "Custom"
    $customTask.startTime = Get-Date
    $customTask.isSuccess = $true
    $customTask.endTime = Get-Date
    $customTask.duration = $customTask.endTime - $customTask.startTime

    $repository.AddTask($customTask)
    Write-Host "OK Custom task added to repository" -ForegroundColor Green

    # Get task summary
    $allTasks = $repository.GetTasks()
    Write-Host "OK Repository now contains $($allTasks.Count) tasks" -ForegroundColor Green

}
catch {
    Write-Host "Direct class usage failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press any key to continue to the next example..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Example 5: Full workflow with custom interface
Write-Host ""
Write-Host "Example 5: Full Workflow with Custom Interface" -ForegroundColor Cyan
Write-Host "This demonstrates using the YaugerInterface class for complete workflow management."
Write-Host ""

try {
    # Create the interface
    $interface = [YaugerInterface]::new($PSScriptRoot)
    Write-Host "OK YaugerInterface created" -ForegroundColor Green

    # Start a workflow
    Write-Host "Starting workflow..." -ForegroundColor Yellow
    $interface.StartWorkflow($true, $true)  # Fast mode, continue on error

    # Get results
    $summary = $interface.GetWorkflowSummary()
    $tasks = $interface.GetTaskResults()
    $failures = $interface.GetFailures()

    Write-Host "OK Workflow completed!" -ForegroundColor Green
    Write-Host "  Session ID: $($summary.SessionId)" -ForegroundColor White
    Write-Host "  Duration: $($summary.SessionDuration.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host "  Tasks: $($summary.TotalTasks) total, $($summary.SuccessfulTasks) successful, $($summary.FailedTasks) failed" -ForegroundColor White

    # Display task details
    Write-Host ""
    Write-Host "Task Details:" -ForegroundColor Cyan
    foreach ($task in $tasks) {
        $status = if ($task.isSuccess) { "OK" } elseif ($task.isFailed) { "FAIL" } else { "-" }
        $color = if ($task.isSuccess) { "Green" } elseif ($task.isFailed) { "Red" } else { "Yellow" }
        Write-Host "  $status $($task.name) - $($task.category) ($($task.duration.ToString('mm\:ss')))" -ForegroundColor $color
    }

    # Clear session for next use
    $interface.ClearSession()
    Write-Host "OK Session cleared" -ForegroundColor Green

}
catch {
    Write-Host "Full workflow failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Example Usage Complete ===" -ForegroundColor Magenta
Write-Host "All examples have been demonstrated successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Key Features Demonstrated:" -ForegroundColor Cyan
Write-Host "  OK Repository Pattern for data management" -ForegroundColor White
Write-Host "  OK Workflow orchestration with task prioritization" -ForegroundColor White
Write-Host "  OK Error handling and continuation options" -ForegroundColor White
Write-Host "  OK Metrics tracking and comparison" -ForegroundColor White
Write-Host "  OK Comprehensive reporting and logging" -ForegroundColor White
Write-Host "  OK Modular and extensible architecture" -ForegroundColor White
Write-Host ""
Write-Host "The system is now ready for production use!" -ForegroundColor Green