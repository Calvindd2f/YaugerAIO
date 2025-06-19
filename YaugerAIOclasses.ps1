class failures {
    [string]$name
    [string]$description
    [string]$severity
    [string]$status
    [string]$timestamp
}

class task {
    [string]$name
    [string]$description
    [bool]$isSuccess
    [bool]$isSkipped
    [bool]$isFailed
    [int]$taskID
    [string]$errorMessage
    [datetime]$startTime
    [datetime]$endTime
    [timespan]$duration
    [string]$category
}

class metrics {
    [string]$storageTotalGB
    [string]$storageFreeGB
    [string]$storageUsedGB
    [string]$storageFreePercent
    [string]$storageUsedPercent
    [string]$storageFreeGBChange
    [string]$storageUsedGBChange
    [string]$storageFreePercentChange
    [string]$storageUsedPercentChange
    [string]$storageFreeGBChangePercent
    [string]$storageUsedGBChangePercent
    [string]$storageFreePercentChangePercent
    [datetime]$timestamp
}

class workflow_tasks {
    [string]$name
    [string]$description
    [string]$scriptPath
    [string]$functionName
    [hashtable]$parameters
    [bool]$isEnabled
    [int]$priority
    [string]$category
    [string]$dependencies
}

class YaugerRepository {
    [System.Collections.Generic.List[task]]$tasks
    [System.Collections.Generic.List[failures]]$failures
    [System.Collections.Generic.List[metrics]]$metrics
    [System.Collections.Generic.List[workflow_tasks]]$workflowTasks
    [hashtable]$configuration
    [string]$sessionId
    [datetime]$sessionStartTime

    YaugerRepository() {
        $this.tasks = [System.Collections.Generic.List[task]]::new()
        $this.failures = [System.Collections.Generic.List[failures]]::new()
        $this.metrics = [System.Collections.Generic.List[metrics]]::new()
        $this.workflowTasks = [System.Collections.Generic.List[workflow_tasks]]::new()
        $this.configuration = @{}
        $this.sessionId = [System.Guid]::NewGuid().ToString()
        $this.sessionStartTime = Get-Date
    }

    [void] AddTask([task]$task) {
        $this.tasks.Add($task)
    }

    [void] AddFailure([failures]$failure) {
        $this.failures.Add($failure)
    }

    [void] AddMetrics([metrics]$metric) {
        $this.metrics.Add($metric)
    }

    [void] AddWorkflowTask([workflow_tasks]$workflowTask) {
        $this.workflowTasks.Add($workflowTask)
    }

    [task[]] GetTasks() {
        return $this.tasks.ToArray()
    }

    [failures[]] GetFailures() {
        return $this.failures.ToArray()
    }

    [metrics[]] GetMetrics() {
        return $this.metrics.ToArray()
    }

    [workflow_tasks[]] GetWorkflowTasks() {
        return $this.workflowTasks.ToArray()
    }

    [task[]] GetTasksByCategory([string]$category) {
        return $this.tasks | Where-Object { $_.category -eq $category }
    }

    [task[]] GetFailedTasks() {
        return $this.tasks | Where-Object { $_.isFailed -eq $true }
    }

    [task[]] GetSuccessfulTasks() {
        return $this.tasks | Where-Object { $_.isSuccess -eq $true }
    }

    [metrics] GetLatestMetrics() {
        if ($this.metrics.Count -eq 0) {
            return $null
        }
        return $this.metrics | Sort-Object timestamp -Descending | Select-Object -First 1
    }

    [metrics] GetPreviousMetrics() {
        if ($this.metrics.Count -lt 2) {
            return $null
        }
        return $this.metrics | Sort-Object timestamp -Descending | Select-Object -Skip 1 -First 1
    }

    [void] CalculateMetricsChanges() {
        $latest = $this.GetLatestMetrics()
        $previous = $this.GetPreviousMetrics()

        if ($latest -and $previous) {
            $latest.storageFreeGBChange = [math]::Round([double]$latest.storageFreeGB - [double]$previous.storageFreeGB, 2)
            $latest.storageUsedGBChange = [math]::Round([double]$latest.storageUsedGB - [double]$previous.storageUsedGB, 2)
            $latest.storageFreePercentChange = [math]::Round([double]$latest.storageFreePercent - [double]$previous.storageFreePercent, 2)
            $latest.storageUsedPercentChange = [math]::Round([double]$latest.storageUsedPercent - [double]$previous.storageUsedPercent, 2)
        }
    }

    [void] ClearSession() {
        $this.tasks.Clear()
        $this.failures.Clear()
        $this.metrics.Clear()
        $this.sessionId = [System.Guid]::NewGuid().ToString()
        $this.sessionStartTime = Get-Date
    }
}

class YaugerWorkflowManager {
    [YaugerRepository]$repository
    [string]$modulePath
    [hashtable]$taskResults
    [bool]$fastMode
    [bool]$continueOnError

    YaugerWorkflowManager([YaugerRepository]$repo, [string]$path) {
        $this.repository = $repo
        $this.modulePath = $path
        $this.taskResults = @{}
        $this.fastMode = $true
        $this.continueOnError = $true
    }

    [void] SetFastMode([bool]$enabled) {
        $this.fastMode = $enabled
    }

    [void] SetContinueOnError([bool]$enabled) {
        $this.continueOnError = $enabled
    }

    [void] InitializeWorkflowTasks() {
        # Define the workflow tasks
        $workflowTasks = @(
            @{
                name = "Rebuild Registry Index"
                description = "Rebuild the registry index using regsvr32"
                scriptPath = "Public\fastchecks.ps1"
                functionName = "RebuildRegistryIndex"
                parameters = @{}
                isEnabled = $true
                priority = 1
                category = "Registry"
                dependencies = ""
            },
            @{
                name = "Rebuild Windows Search Index"
                description = "Rebuild Windows Search Index"
                scriptPath = "Public\fastchecks.ps1"
                functionName = "RebuildWSearchIndex"
                parameters = @{}
                isEnabled = $true
                priority = 2
                category = "Search"
                dependencies = ""
            },
            @{
                name = "Check Hibernation"
                description = "Check hibernation status"
                scriptPath = "Public\fastchecks.ps1"
                functionName = "CheckHibernation"
                parameters = @{}
                isEnabled = $true
                priority = 3
                category = "Power"
                dependencies = ""
            },
            @{
                name = "Disable Fast Boot"
                description = "Disable Fast Boot feature"
                scriptPath = "Public\fastchecks.ps1"
                functionName = "DisableFastBoot"
                parameters = @{}
                isEnabled = $true
                priority = 4
                category = "Power"
                dependencies = ""
            },
            @{
                name = "Reset Page File"
                description = "Reset page file to system managed"
                scriptPath = "Public\fastchecks.ps1"
                functionName = "ResetPageFile"
                parameters = @{ Force = $false }
                isEnabled = $true
                priority = 5
                category = "Memory"
                dependencies = ""
            },
            @{
                name = "Disk Cleanup"
                description = "Perform disk cleanup"
                scriptPath = if ($this.fastMode) { "Public\diskcleanup_fastmode.ps1" } else { "Public\diskcleanup.ps1" }
                functionName = if ($this.fastMode) { "Start-DiskCleanupFastMode" } else { "Start-DiskCleanup" }
                parameters = @{}
                isEnabled = $true
                priority = 6
                category = "Storage"
                dependencies = ""
            }
        )

        foreach ($taskDef in $workflowTasks) {
            $workflowTask = [workflow_tasks]::new()
            $workflowTask.name = $taskDef.name
            $workflowTask.description = $taskDef.description
            $workflowTask.scriptPath = $taskDef.scriptPath
            $workflowTask.functionName = $taskDef.functionName
            $workflowTask.parameters = $taskDef.parameters
            $workflowTask.isEnabled = $taskDef.isEnabled
            $workflowTask.priority = $taskDef.priority
            $workflowTask.category = $taskDef.category
            $workflowTask.dependencies = $taskDef.dependencies

            $this.repository.AddWorkflowTask($workflowTask)
        }
    }

    [task] ExecuteTask([workflow_tasks]$workflowTask) {
        $task = [task]::new()
        $task.name = $workflowTask.name
        $task.description = $workflowTask.description
        $task.taskID = $this.repository.GetTasks().Count + 1
        $task.category = $workflowTask.category
        $task.startTime = Get-Date
        $task.isSuccess = $false
        $task.isSkipped = $false
        $task.isFailed = $false

        try {
            Write-Host "Executing: $($workflowTask.name)" -ForegroundColor Cyan
            
            # Load the script if it exists
            $scriptFullPath = Join-Path $this.modulePath $workflowTask.scriptPath
            if (Test-Path $scriptFullPath) {
                . $scriptFullPath
            }

            # Execute the function
            $functionName = $workflowTask.functionName
            if (Get-Command $functionName -ErrorAction SilentlyContinue) {
                $result = & $functionName @($workflowTask.parameters.GetEnumerator() | ForEach-Object { $_.Value })
                $task.isSuccess = $true
                Write-Host "OK Completed: $($workflowTask.name)" -ForegroundColor Green
            } else {
                throw "Function $functionName not found"
            }
        }
        catch {
            $task.isFailed = $true
            $task.errorMessage = $_.Exception.Message
            Write-Host "FAIL Failed: $($workflowTask.name) - $($_.Exception.Message)" -ForegroundColor Red
            
            if (-not $this.continueOnError) {
                throw
            }
        }
        finally {
            $task.endTime = Get-Date
            $task.duration = $task.endTime - $task.startTime
            $this.repository.AddTask($task)
        }

        return $task
    }

    [void] ExecuteWorkflow() {
        Write-Host "Starting YaugerAIO Workflow..." -ForegroundColor Yellow
        Write-Host "Mode: $(if ($this.fastMode) { 'Fast' } else { 'Full' })" -ForegroundColor Yellow
        Write-Host "Continue on Error: $(if ($this.continueOnError) { 'Yes' } else { 'No' })" -ForegroundColor Yellow
        Write-Host ""

        # Initialize workflow tasks
        $this.InitializeWorkflowTasks()

        # Get storage metrics before
        $this.CaptureStorageMetrics("Before")

        # Execute tasks in priority order
        $sortedTasks = $this.repository.GetWorkflowTasks() | Sort-Object priority
        foreach ($workflowTask in $sortedTasks) {
            if ($workflowTask.isEnabled) {
                $this.ExecuteTask($workflowTask)
            }
        }

        # Get storage metrics after
        $this.CaptureStorageMetrics("After")

        # Calculate changes
        $this.repository.CalculateMetricsChanges()

        # Generate reports
        $this.GenerateReports()

        Write-Host "Workflow completed!" -ForegroundColor Green
    }

    [void] CaptureStorageMetrics([string]$phase) {
        try {
            Write-Host "Capturing storage metrics ($phase)..." -ForegroundColor Cyan
            
            # Import the storage info module
            $storageScriptPath = Join-Path $this.modulePath "Private\FileStorageInfo.ps1"
            if (Test-Path $storageScriptPath) {
                . $storageScriptPath
            }

            # Get storage information
            $storageInfo = Get-FileStorageInfo
            
            $metric = [metrics]::new()
            $metric.timestamp = Get-Date
            
            # Extract storage information from the output
            if ($storageInfo -and $storageInfo.out) {
                $metric.storageTotalGB = "0" # Will be calculated
                $metric.storageFreeGB = [math]::Round($storageInfo.out.freeSpace / 1GB, 2).ToString()
                $metric.storageUsedGB = "0" # Will be calculated
                $metric.storageFreePercent = "0" # Will be calculated
                $metric.storageUsedPercent = "0" # Will be calculated
            }

            $this.repository.AddMetrics($metric)
            Write-Host "OK Storage metrics captured ($phase)" -ForegroundColor Green
        }
        catch {
            Write-Host "FAIL Failed to capture storage metrics ($phase): $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    [void] GenerateReports() {
        try {
            Write-Host "Generating reports..." -ForegroundColor Cyan

            # Generate computer performance report
            $perfReportPath = Join-Path $this.modulePath "Public\computer_perf_report.ps1"
            if (Test-Path $perfReportPath) {
                . $perfReportPath
                # Assuming there's a function to generate the report
                if (Get-Command "Generate-ComputerPerformanceReport" -ErrorAction SilentlyContinue) {
                    & "Generate-ComputerPerformanceReport" -Repository $this.repository
                }
            }

            # Generate computer space cleanup report
            $spaceReportPath = Join-Path $this.modulePath "Public\computer_space_cleanup_report.ps1"
            if (Test-Path $spaceReportPath) {
                . $spaceReportPath
                # Assuming there's a function to generate the report
                if (Get-Command "Generate-ComputerSpaceCleanupReport" -ErrorAction SilentlyContinue) {
                    & "Generate-ComputerSpaceCleanupReport" -Repository $this.repository
                }
            }

            Write-Host "OK Reports generated" -ForegroundColor Green
        }
        catch {
            Write-Host "FAIL Failed to generate reports: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

class YaugerInterface {
    [YaugerRepository]$repository
    [YaugerWorkflowManager]$workflowManager
    [string]$modulePath

    YaugerInterface([string]$path) {
        $this.modulePath = $path
        $this.repository = [YaugerRepository]::new()
        $this.workflowManager = [YaugerWorkflowManager]::new($this.repository, $path)
    }

    [void] StartWorkflow([bool]$fastMode = $true, [bool]$continueOnError = $true) {
        $this.workflowManager.SetFastMode($fastMode)
        $this.workflowManager.SetContinueOnError($continueOnError)
        $this.workflowManager.ExecuteWorkflow()
    }

    [task[]] GetTaskResults() {
        return $this.repository.GetTasks()
    }

    [failures[]] GetFailures() {
        return $this.repository.GetFailures()
    }

    [metrics] GetLatestMetrics() {
        return $this.repository.GetLatestMetrics()
    }

    [metrics] GetPreviousMetrics() {
        return $this.repository.GetPreviousMetrics()
    }

    [void] ClearSession() {
        $this.repository.ClearSession()
    }

    [hashtable] GetWorkflowSummary() {
        $tasks = $this.repository.GetTasks()
        $failedTasks = $this.repository.GetFailedTasks()
        $successfulTasks = $this.repository.GetSuccessfulTasks()

        return @{
            TotalTasks = $tasks.Count
            SuccessfulTasks = $successfulTasks.Count
            FailedTasks = $failedTasks.Count
            SkippedTasks = ($tasks | Where-Object { $_.isSkipped }).Count
            SessionId = $this.repository.sessionId
            SessionStartTime = $this.repository.sessionStartTime
            SessionDuration = (Get-Date) - $this.repository.sessionStartTime
        }
    }
}
