# Short, Efficient Functions relevant to the repo.
Function RebuildRegistryIndex {
    # Rebuild the index of the registry.
    regsvr32 /s /i:u shdocvw.dll
}

# Rebuild Windows Search Index
Function RebuildWSearchIndex {
    $CurrentLoc = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search' -Name DataDirectory
    Set-Service WSearch -StartupType disabled
    Stop-Service wsearch
    Remove-Item $CurrentLoc.DataDirectory -Force -Confirm:$false -Recurse
    Set-Service WSearch -StartupType Automatic
    Start-Service WSearch
}

Function CheckHibernation {
    # Check if hibernation is enabled.
    $hibernation = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled
    if ($hibernation.HibernateEnabled -eq 1) {
        Write-Host "Hibernation is enabled."
    }
    else {
        Write-Host "Hibernation is disabled."
    }
}

Function DisableFastBoot {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /F
    Write-Host "Fastboot Disabled"
}

# Function that resets the page file to default and forces it to be system managed. (This uses .NET or COM objects to do this.)
function ResetPageFile {
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    try {
        # Get the current page file settings
        $pageFile = Get-WmiObject -Class Win32_PageFileSetting -ErrorAction Stop

        if (-not $pageFile) {
            throw "No page file settings found"
        }

        $pageFilePath = $pageFile.Name
        Write-Host "Current page file: $pageFilePath"
        Write-Host "Current initial size: $($pageFile.InitialSize) MB"
        Write-Host "Current maximum size: $($pageFile.MaximumSize) MB"

        # To reset to system-managed, we need to:
        # 1. Set InitialSize to 0 (system-managed)
        # 2. Set MaximumSize to 0 (system-managed)
        # 3. Apply the changes

        $pageFile.InitialSize = 0
        $pageFile.MaximumSize = 0

        # Apply the changes
        $result = $pageFile.Put()

        if ($result.ReturnValue -eq 0) {
            Write-Host "Successfully reset page file to system-managed settings" -ForegroundColor Green

            # Verify the changes
            $updatedPageFile = Get-WmiObject -Class Win32_PageFileSetting
            Write-Host "Updated initial size: $($updatedPageFile.InitialSize) MB"
            Write-Host "Updated maximum size: $($updatedPageFile.MaximumSize) MB"

            if ($Force) {
                Write-Host "Rebooting system to apply page file changes..." -ForegroundColor Yellow
                Restart-Computer -Force
            }
            else {
                Write-Host "A system restart may be required for changes to take effect" -ForegroundColor Yellow
            }
        }
        else {
            throw "Failed to update page file settings. Return code: $($result.ReturnValue)"
        }
    }
    catch {
        Write-Error "Failed to reset page file: $_"
        return $false
    }

    return $true
}

# ----------------------------------------------------------------------------
# Name        : Start-DefragglerDefrag
# Description : Defrag selected drive using standalone version of Defraggler which does not require installation to function
# Architect   : Converted from Scripting Simon's batch script
#
# Version History
# ---------------
# v1.0 - Converted from batch script v2.1 (22nd Jan 2019) - Update to version 2.22.33.995
# ----------------------------------------------------------------------------

Function StartDefrag {
    <#
    .SYNOPSIS
        Defrag selected drive using standalone version of Defraggler.

    .DESCRIPTION
        This function defragments a specified drive using the standalone version of Defraggler
        which does not require installation to function. It automatically detects the system
        architecture and uses the appropriate executable (df.exe for x86, df64.exe for x64).

    .PARAMETER Drive
        The drive letter to defragment (e.g., "C:", "D:").

    .PARAMETER DefragglerPath
        The path to the Defraggler executable directory. Defaults to current directory.

    .EXAMPLE
        Start-DefragglerDefrag -Drive "C:"

    .EXAMPLE
        Start-DefragglerDefrag -Drive "D:" -DefragglerPath "C:\Tools\Defraggler"

    .NOTES
        Requires the standalone Defraggler executables (df.exe and df64.exe) to be present
        in the specified directory.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^[A-Za-z]:$")]
        [string]$Drive,

        [string]$DefragglerPath = $PSScriptRoot
    )

    try {
        # Clear the console for better output visibility
        Clear-Host

        # Force working directory to current directory (equivalent to PUSHD %~dp0)
        Push-Location $DefragglerPath

        # Determine OS architecture
        if ([Environment]::Is64BitOperatingSystem) {
            $OSArch = "x64"
            $dfname = "df64.exe"
        }
        else {
            $OSArch = "x86"
            $dfname = "df.exe"
        }

        Write-Host "Operating System Architecture: $OSArch" -ForegroundColor Cyan
        Write-Host "Using Defraggler executable: $dfname" -ForegroundColor Cyan

        # Check for valid drive letter
        if (-not (Test-Path $Drive)) {
            throw "Drive '$Drive' is not accessible or does not exist"
        }

        # Check if the Defraggler executable exists
        $defragglerExe = Join-Path $DefragglerPath $dfname
        if (-not (Test-Path $defragglerExe)) {
            throw "Defraggler executable '$dfname' not found in '$DefragglerPath'"
        }

        # Build and execute the command
        $command = "& '$defragglerExe' '$Drive'"
        Write-Host "Running: $command" -ForegroundColor Green

        # Execute the defragmentation
        $result = Invoke-Expression $command

        if ($LASTEXITCODE -eq 0) {
            Write-Host "Defragmentation completed successfully for drive $Drive" -ForegroundColor Green
        }
        else {
            Write-Warning "Defragmentation completed with exit code: $LASTEXITCODE"
        }

        return $result
    }
    catch {
        Write-Error "Failed to defragment drive $Drive`: $_"
        return $false
    }
    finally {
        # Restore the original location
        Pop-Location
    }
}

# -------------------------------
# Name: OneDrive Stuff for Space Issues
# Description:

function Reset-OneDriveConfiguration {
    <#
    .SYNOPSIS
    Resets and configures OneDrive settings to ensure proper Files on Demand functionality and auto-start.

    .DESCRIPTION
    This function checks OneDrive configuration, verifies if it's properly set up, and fixes any issues.
    It ensures OneDrive runs on boot, enables Files on Demand, and resets OneDrive to correct data sync.

    .EXAMPLE
    Reset-OneDriveConfiguration

    .NOTES
    Requires administrative privileges to modify HKLM registry keys.
    #>

    [CmdletBinding()]
    param()

    Write-Host "Starting OneDrive configuration reset..." -ForegroundColor Green

    # Define registry paths
    $HKLMregistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
    $DiskSizeregistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\DiskSpaceCheckThresholdMB'
    $HKCUOneDrivePath = 'HKCU:\Software\Microsoft\OneDrive'
    $HKCUPoliciesPath = 'HKCU:\Software\Policies\Microsoft\OneDrive'
    $TenantGUID = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

    # Function to check if OneDrive is properly configured
    function Test-OneDriveConfiguration {
        $issues = @()

        # Check if HKLM policies exist
        if (!(Test-Path $HKLMregistryPath)) {
            $issues += "HKLM OneDrive policies path missing"
        }

        # Check if SilentAccountConfig is set
        $silentConfig = Get-ItemProperty -Path $HKLMregistryPath -Name 'SilentAccountConfig' -ErrorAction SilentlyContinue
        if ($silentConfig.SilentAccountConfig -ne 1) {
            $issues += "SilentAccountConfig not properly set"
        }

        # Check if Files on Demand is enabled
        $filesOnDemand = Get-ItemProperty -Path $HKLMregistryPath -Name 'FilesOnDemandEnabled' -ErrorAction SilentlyContinue
        if ($filesOnDemand.FilesOnDemandEnabled -ne 1) {
            $issues += "Files on Demand not enabled"
        }

        # Check if OneDrive auto-start is enabled
        $autoStart = Get-ItemProperty -Path $HKCUPoliciesPath -Name 'EnableAutoStart' -ErrorAction SilentlyContinue
        if ($autoStart.EnableAutoStart -ne 1) {
            $issues += "OneDrive auto-start not enabled"
        }

        return $issues
    }

    # Check current configuration
    Write-Host "Checking current OneDrive configuration..." -ForegroundColor Yellow
    $configurationIssues = Test-OneDriveConfiguration

    if ($configurationIssues.Count -eq 0) {
        Write-Host "OneDrive appears to be properly configured. Proceeding with reset anyway..." -ForegroundColor Yellow
    }
    else {
        Write-Host "Found configuration issues:" -ForegroundColor Red
        foreach ($issue in $configurationIssues) {
            Write-Host "  - $issue" -ForegroundColor Red
        }
    }

    try {
        # Create registry paths if they don't exist
        Write-Host "Setting up registry paths..." -ForegroundColor Yellow
        if (!(Test-Path $HKLMregistryPath)) {
            New-Item -Path $HKLMregistryPath -Force | Out-Null
        }
        if (!(Test-Path $DiskSizeregistryPath)) {
            New-Item -Path $DiskSizeregistryPath -Force | Out-Null
        }
        if (!(Test-Path $HKCUPoliciesPath)) {
            New-Item -Path $HKCUPoliciesPath -Force | Out-Null
        }

        # Configure HKLM policies
        Write-Host "Configuring HKLM OneDrive policies..." -ForegroundColor Yellow
        New-ItemProperty -Path $HKLMregistryPath -Name 'SilentAccountConfig' -Value '1' -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $DiskSizeregistryPath -Name $TenantGUID -Value '102400' -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $HKLMregistryPath -Name 'FilesOnDemandEnabled' -Value '1' -PropertyType DWORD -Force | Out-Null

        # Configure HKCU policies
        Write-Host "Configuring HKCU OneDrive policies..." -ForegroundColor Yellow
        New-ItemProperty -Path $HKCUPoliciesPath -Name 'EnableAutoStart' -Value '1' -PropertyType DWORD -Force | Out-Null

        # Clear problematic registry entries
        Write-Host "Clearing problematic OneDrive registry entries..." -ForegroundColor Yellow
        $regEntriesToDelete = @(
            'SilentBusinessConfigCompleted',
            'ClientEverSignedIn',
            'PersonalUnlinkedTimeStamp',
            'OneAuthUnrecoverableTimestamp'
        )

        foreach ($entry in $regEntriesToDelete) {
            try {
                reg delete "HKCU\Software\Microsoft\OneDrive" /v $entry /f 2>$null
            }
            catch {
                Write-Verbose "Could not delete registry entry: $entry"
            }
        }

        # Kill OneDrive process
        Write-Host "Stopping OneDrive process..." -ForegroundColor Yellow
        $oneDriveProcesses = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
        if ($oneDriveProcesses) {
            $oneDriveProcesses | Stop-Process -Force
            Start-Sleep -Seconds 2
        }

        # Restart Explorer
        Write-Host "Restarting Explorer..." -ForegroundColor Yellow
        $explorerProcesses = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
        if ($explorerProcesses) {
            $explorerProcesses | Stop-Process -Force
            Start-Sleep -Seconds 2
            Start-Process "explorer.exe"
        }

        # Reset OneDrive
        Write-Host "Resetting OneDrive..." -ForegroundColor Yellow
        $oneDrivePath = "C:\Program Files\Microsoft\OneDrive\OneDrive.exe"
        if (Test-Path $oneDrivePath) {
            Start-Process -FilePath $oneDrivePath -ArgumentList "/reset" -Wait
        }
        else {
            Write-Warning "OneDrive executable not found at expected location: $oneDrivePath"
        }

        # Verify configuration after reset
        Write-Host "Verifying configuration after reset..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        $finalIssues = Test-OneDriveConfiguration

        if ($finalIssues.Count -eq 0) {
            Write-Host "OneDrive configuration reset completed successfully!" -ForegroundColor Green
            Write-Host "OneDrive should now be properly configured with Files on Demand enabled and auto-start enabled." -ForegroundColor Green
        }
        else {
            Write-Host "Configuration reset completed, but some issues remain:" -ForegroundColor Yellow
            foreach ($issue in $finalIssues) {
                Write-Host "  - $issue" -ForegroundColor Yellow
            }
        }

    }
    catch {
        Write-Error "Error during OneDrive configuration reset: $($_.Exception.Message)"
        throw
    }
}




# -----------------
# Name  : Remove-Profiles
# Description : Remove profiles for system. Default is not selected.
# 
# VH
# ---------

function Remove-UserProfiles {
    <#
    .SYNOPSIS
        Removes user profiles from the system using multiple methods.

    .DESCRIPTION
        This function attempts to remove user profiles using two different approaches:
        1. Manual removal with registry hive unloading and permission changes
        2. Using DelProf2 utility for more robust profile removal

    .PARAMETER ExcludedUsers
        Array of user names to exclude from removal. Default includes common system accounts.

    .PARAMETER UseDelProf2
        Switch to use DelProf2 utility for profile removal. Default is $false.

    .EXAMPLE
        Remove-UserProfiles -ExcludedUsers @('admin', 'svcaccount') -UseDelProf2

    .NOTES
        Requires administrative privileges to remove profiles.
    #>

    param(
        [string[]]$ExcludedUsers = @('svcaccount', 'admin', 'public'),
        [switch]$UseDelProf2
    )

    # Configure Excluded Local Users in an array.
    # Use regex to do -not and -notmatch to filter the profiles.
    # This is placeholder for additional filtering depending on requirements.

    if ($UseDelProf2) {
        # Attempt 2: Nuclear option with DelProf2 binary. It doesn't care about reg hives or any of that shit.
        Write-Host "Using DelProf2 method for profile removal..."

        # download delprof
        Set-ExecutionPolicy Bypass -Scope Process -Force
        $tempDir = $env:TEMP
        Set-Location $tempDir

        $url = 'https://helgeklein.com/downloads/DelProf2/current/Delprof2%201.6.0.zip'
        Invoke-WebRequest -Uri $url -OutFile "$tempDir\Delprof2.zip"
        Expand-Archive -Path "$tempDir\Delprof2.zip" -DestinationPath "$tempDir\Delprof2" -Force

        Set-Location "$tempDir\Delprof2\delprof2"

        # Get all profiles and filter based on exclusions
        $profiles = Get-ChildItem 'C:\Users' -Directory | Where-Object {
            $ExcludedUsers -notcontains $_.Name -and $_.Name -notmatch "^[a-zA-Z0-9].*"
        }

        # delete the profiles
        foreach ($profile in $profiles) {
            try {
                $path = $profile.FullName
                # run delprof2.exe $path
                & .\delprof2.exe $path
                Write-Host "Deleted profile: $($profile.Name)"
            }
            catch {
                Write-Warning "Failed to delete profile $($profile.Name): $_"
            }
        }
    }
    else {
        # Attempt 1: This is the most basic approach and is error prone due to people fucking with ACLs especially NT AUTHORITY\SYSTEM permission.
        Write-Host "Using manual method for profile removal..."

        $profiles = Get-ChildItem 'C:\Users' -Directory | Where-Object {
            $ExcludedUsers -notcontains $_.Name -and $_.Name -notmatch "^[a-zA-Z0-9].*"
        }

        foreach ($profile in $profiles) {
            try {
                $path = $profile.FullName
                $regKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

                # Find and unload registry hive
                $sidKey = Get-ChildItem $regKey | Where-Object {
                    (Get-ItemProperty $_.PSPath).ProfileImagePath -eq $path
                }

                if ($sidKey) {
                    $sid = $sidKey.PSChildName
                    reg unload "HKU\$sid" 2>$null | Out-Null
                }

                # Take ownership and set permissions
                takeown /f "$path" /r /d y 2>$null | Out-Null
                icacls "$path" /grant SYSTEM:F /t /c 2>$null | Out-Null

                # Remove the profile directory
                Remove-Item "$path" -Recurse -Force -ErrorAction Stop
                Write-Host "Deleted profile: $($profile.Name)"
            }
            catch {
                Write-Warning "Failed to delete profile $($profile.Name): $_"
            }
        }
    }
}