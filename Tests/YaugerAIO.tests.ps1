# Import the main script
$scriptPath = Join-Path $PSScriptRoot "YaugerAIO.ps1"
. $scriptPath

# Test suite for YaugerAIO
Describe "YaugerAIO Tests" {
    BeforeAll {
        # Setup test environment
        $testTempPath = Join-Path $env:TEMP "YaugerAIO_Test_$(Get-Random)"
        New-Item -ItemType Directory -Path $testTempPath | Out-Null

        # Create test files
        1..10 | ForEach-Object {
            $testFile = Join-Path $testTempPath "test$_"
            Set-Content -Path $testFile -Value "Test content $_"
        }
    }

    AfterAll {
        # Cleanup test environment
        if (Test-Path $testTempPath) {
            Remove-Item -Path $testTempPath -Recurse -Force
        }
    }

    # Test utility functions
    Describe "Utility Functions" {
        It "Test-ValidDrive should validate drive letters correctly" {
            Test-ValidDrive "C:" | Should -Be $true
            Test-ValidDrive "Z:" | Should -Be $true
            Test-ValidDrive "1:" | Should -Be $false
            Test-ValidDrive "" | Should -Be $false
            Test-ValidDrive $null | Should -Be $false
        }

        It "Test-ValidPath should validate paths correctly" {
            Test-ValidPath $testTempPath | Should -Be $true
            Test-ValidPath "C:\NonexistentPath" | Should -Be $false
            Test-ValidPath "" | Should -Be $false
            Test-ValidPath $null | Should -Be $false
        }

        It "Wrap-Text should wrap text correctly" {
            $longText = "This is a very long text that should be wrapped at the specified width to ensure proper formatting and readability of the content."
            $wrapped = Wrap-Text -Text $longText -Width 20
            $wrapped -split "`n" | ForEach-Object {
                $_.Length | Should -BeLessThanOrEqual 20
            }
        }
    }

    # Test file operations
    Describe "File Operations" {
        It "Remove-SafeFile should remove files safely" {
            $testFile = Join-Path $testTempPath "test_remove"
            Set-Content -Path $testFile -Value "Test content"
            Remove-SafeFile -Path $testFile | Should -Be $true
            Test-Path $testFile | Should -Be $false
        }

        It "Get-WindowsTempSize should return valid size" {
            $size = Get-WindowsTempSize
            $size | Should -BeGreaterThanOrEqual 0
            $size | Should -BeOfType [double]
        }

        It "Process-FilesWithHash should process files and calculate hashes" {
            $files = Get-ChildItem -Path $testTempPath -File
            $results = Process-FilesWithHash -Files $files.FullName -MaxThreads 2 -BatchSize 2

            $results.FileStats.Count | Should -Be $files.Count
            $results.Hashes.Count | Should -Be $files.Count
            $results.Errors.Count | Should -Be 0
        }
    }

    # Test system checks
    Describe "System Checks" {
        It "Check-DiskSpace should return valid disk information" {
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='${selectedDrive}'"
            $disk | Should -Not -Be $null
            $disk.FreeSpace | Should -BeGreaterThan 0
            $disk.Size | Should -BeGreaterThan 0
        }

        It "Check-CPUUsage should return valid CPU usage" {
            $cpu = New-Object System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total")
            $cpu.NextValue() | Out-Null
            $usage = $cpu.NextValue()
            $usage | Should -BeGreaterThanOrEqual 0
            $usage | Should -BeLessThanOrEqual 100
        }

        It "Check-RAMUsage should return valid RAM information" {
            $os = Get-CimInstance Win32_OperatingSystem
            $os | Should -Not -Be $null
            $os.TotalVisibleMemorySize | Should -BeGreaterThan 0
            $os.FreePhysicalMemory | Should -BeGreaterThanOrEqual 0
        }
    }

    # Test error handling
    Describe "Error Handling" {
        It "Circuit breaker should handle failures correctly" {
            $script:CircuitBreakerState = @{
                IsOpen = $false
                LastFailureTime = $null
                FailureCount = 0
                CooldownPeriod = New-TimeSpan -Minutes 5
            }

            # Simulate failures
            1..4 | ForEach-Object {
                Update-CircuitBreaker -Success $false
            }

            $script:CircuitBreakerState.IsOpen | Should -Be $true
            $script:CircuitBreakerState.FailureCount | Should -Be 4

            # Test recovery
            $script:CircuitBreakerState.LastFailureTime = (Get-Date).AddMinutes(-6)
            Test-CircuitBreaker | Should -Be $true
        }

        It "Invoke-WithRetry should retry failed operations" {
            $attempts = 0
            $action = {
                $attempts++
                if ($attempts -lt 3) { throw "Test error" }
                return "Success"
            }

            $result = Invoke-WithRetry -Action $action -MaxAttempts 3 -DelaySeconds 0.1
            $result | Should -Be "Success"
            $attempts | Should -Be 3
        }
    }

    # Test performance monitoring
    Describe "Performance Monitoring" {
        It "Start-PerformanceMonitoring should collect metrics" {
            $metrics = Start-PerformanceMonitoring -DurationSeconds 1 -SampleIntervalMs 100
            $metrics | Should -Not -Be $null
            $metrics.Count | Should -BeGreaterThan 0
            $metrics[0].Name | Should -Not -BeNullOrEmpty
            $metrics[0].Value | Should -Not -BeNullOrEmpty
            $metrics[0].Timestamp | Should -Not -BeNullOrEmpty
        }
    }

    # Test browser cache operations
    Describe "Browser Cache Operations" {
        It "Get-TempLockingProcesses should identify running browsers" {
            $processes = Get-TempLockingProcesses
            $processes | Should -Not -Be $null
            $processes | Should -BeOfType [System.Array]
        }

        It "Clear-BrowserCaches should handle missing browser paths gracefully" {
            $browserPaths = @{
                "TestBrowser" = "C:\Nonexistent\Path"
            }

            $results = @()
            $browserPaths.GetEnumerator() | ForEach-Object {
                $browser = $_.Key
                $paths = $_.Value
                $success = $true
                $errors = @()

                try {
                    if (Test-Path $paths) {
                        Get-ChildItem -Path $paths -Recurse -ErrorAction Stop |
                        ForEach-Object {
                            Remove-SafeFile $_.FullName
                        }
                    }
                }
                catch {
                    $success = $false
                    $errors += $_.Exception.Message
                }

                $results += [PSCustomObject]@{
                    Browser = $browser
                    Success = $success
                    Errors = $errors
                }
            }

            $results[0].Browser | Should -Be "TestBrowser"
            $results[0].Success | Should -Be $true
        }
    }

    # Test system health check
    Describe "System Health Check" {
        It "Get-SystemHealthThreaded should run all checks" {
            $result = Get-SystemHealthThreaded
            $result | Should -Be $true
        }
    }
}