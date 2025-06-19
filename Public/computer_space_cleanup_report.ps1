#region PARAMETER BLOCK
param(
    [ValidateSet('report','cleanup','file','dism')]
    [string]$Mode = 'report',
    [string]$FilePath,
    [string]$CommandArgs
)
#endregion

#region OUTPUT VARIABLES
$variableProps = @{
    freeSpace = $null
    Folders = $null
    systemDiskInfo = $null
    fileDetails = $null
    space = $null
    timeTaken = $null
}
$outputProps = @{
    out = [psobject]::new($variableProps)
    success = $false
}
$activityOutput = [psobject]::new($outputProps)
#endregion

#region FUNCTIONS

function GetCleanupReport {
    $searchPath = @()
    $searchPath += [PSCustomObject]@{
        text = 'Diagnostic Data Viewer database files'
        path = 'C:\ProgramData\Microsoft\Diagnosis\EventTranscript\'
        fileList = "*"
        reportOnly = 'No'
    }
    $searchPath += [PSCustomObject]@{
        text = 'User Downloads folder'
        path = 'C:\Users\username\Downloads'
        fileList = "*"
        reportOnly = 'No'
    }
    $searchPath += [PSCustomObject]@{
        text = 'Windows WinSxS'
        path = 'C:\Windows\WinSxS'
        fileList = "*"
        reportOnly = 'Yes'
    }
    $searchPath += [PSCustomObject]@{
        text = 'IIS Log Files'
        path = 'C:\inetpub\logs\LogFiles\*'
        fileList = "*"
        reportOnly = 'No'
    }
    $searchPath += [PSCustomObject]@{
        text = 'Windows Log Files'
        reportOnly = 'Yes'
        path = 'C:\Windows\Logs\*'
        fileList = "*"
    }
    $searchPath += [PSCustomObject]@{
        text = 'Windows System32 Log Files'
        reportOnly = 'Yes'
        path = 'C:\Windows\System32\LogFiles\*'
        fileList = "*"
    }
    $searchPath += [PSCustomObject]@{
        text = 'Recycle Bin'
        path = 'C:\$Recycle.bin\*'
        fileList = "*"
        reportOnly = 'No'
    }
    $searchPath += [PSCustomObject]@{
        text = 'System error memory dump'
        path = 'C:\windows'
        fileList = "*.dmp"
        reportOnly = 'No'
    }
    $searchPath += [PSCustomObject]@{
        text = 'System error memory minidump'
        path = 'C:\windows\Minidump'
        fileList = "*.dmp"
        reportOnly = 'No'
    }
    $searchPath += [PSCustomObject]@{
        text = 'Windows Error Reporting Files'
        path = 'C:\ProgramData\Microsoft\Windows\WER'
        fileList = "*"
        reportOnly = 'No'
    }
    $searchPath += [PSCustomObject]@{
        text = 'Windows Temp Files'
        path = 'C:\windows\Temp'
        fileList = "*"
        reportOnly = 'No'
    }
    $searchPath += [PSCustomObject]@{
        text = 'User Temp Files'
        path = 'C:\Users\username\AppData\Local\Temp'
        fileList = "*"
        reportOnly = 'No'
    }
    $searchPath += [PSCustomObject]@{
        text = 'User AppData'
        path = 'C:\Users\username\AppData\'
        fileList = "*"
        reportOnly = 'No'
    }

    $Output = @()
    foreach ($sPath in $searchPath ) {
        if ((Test-Path $sPath.path.Replace("*","")) -or ($sPath.path -like "C:\\Users\\username*")) {
            $Folders = @()
            if ($sPath.path.IndexOf("*") -gt 1) {
                $Folders += Get-ChildItem $sPath.path.replace("*","") -force| Where-Object {$_.PSisContainer} | ForEach-Object {$_.FullName}
            } elseif ($sPath.path -like "C:\\Users\\username*") {
                $Folders += Get-ChildItem C:\Users\ -force| Where-Object {$_.PSisContainer} | ForEach-Object {$sPath.path.Replace("C:\\Users\\username",$_.FullName)}
            } else {
                $Folders += $sPath.path
            }
            foreach ($folder in $folders) {
                if (Test-Path $folder) {
                    Write-Host "Getting size of folder $Folder."
                    $SizeGB = $null
                    try {
                        if ($sPath.fileList -eq "*") {
                            $files = Get-ChildItem -Recurse -Force -Path $Folder -Filter $sPath.fileList -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where {$false -eq $_.PSisContainer}
                        } else {
                            $files = Get-ChildItem -Force -Path $Folder -Filter $sPath.fileList -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where {$false -eq $_.PSisContainer}
                        }
                        if ($files){
                            $sizeGB = [math]::round(($files| Measure-Object -Property length -sum).sum / 1gb, 3)
                        } else {
                            $sizeGB = 0
                        }
                    } catch [System.UnauthorizedAccessException] {
                        write-host "WARNING: Can't access $folder"
                    }
                    if ([string]::IsNullOrWhiteSpace($sizeGB)) {
                        $sizeGB = "Access Error"
                    }
                    $text = $sPath.text
                    if (($folders.count -gt 1) -or ($spath.text -eq "IIS Log Files")) {
                        if ($folder -like "C:\users*") {
                            $text = $text.replace("User", "User $($folder.split("\")[2])")
                        } else {
                            $text = $sPath.text + "\" + ($Folder | Split-Path -Leaf)}
                        }
                    if ($folder -like "*S-1-*") {
                        try {
                            $id = New-Object System.Security.Principal.SecurityIdentifier($Folder | Split-Path -Leaf)
                            $text = $text.replace(($Folder | Split-Path -Leaf), $id.Translate([System.Security.Principal.NTAccount]))
                        } catch {}
                    }
                    $Output += [PSCustomObject]@{
                        text = $text
                        path = $Folder
                        fileList = $sPath.fileList
                        reportOnly = $sPath.reportOnly
                        sizeGB = $sizeGB
                    }
                    $files = $null
                } else {
                    Write-host "Could not find folder $Folder"
                }
            }
        } else {
            Write-host "WARNING: Could not find folder $($sPath.path)"
        }
    }
    $SystemDiskInfo = ([System.IO.DriveInfo]::GetDrives() `
        | Where-Object {$_.Name -eq "C:\"}) | Select-Object -Property `
        @{N='text';E={if([string]::IsNullOrEmpty(($_.VolumeLavel))){$_.Name}else{$_.VolumeLabel}}},`
        @{N='value';E={$_.Name}},`
        @{N='FreeSpace (Gb)'; E={($_.TotalFreeSpace/1GB).ToString('F2')}},`
        @{N='Total (Gb)'; E={($_.TotalSize/1GB).ToString('F2')}},`
        @{N='FreePercent'; E={[Math]::Round(($_.TotalFreeSpace / $_.TotalSize) * 100, 2)}}
    $activityOutput.out.folders = $output
    $activityOutput.out.freeSpace = ([System.IO.DriveInfo]::GetDrives() | Where-Object {$_.Name -eq "C:\"}).TotalFreeSpace
    $activityOutput.out.systemDiskInfo = $SystemDiskInfo;
    $activityOutput.success = $true;
    return $activityOutput;
}

function CleanupFolders {
    $returnFolders = @()
    foreach ($folder in ($folders | convertfrom-json)) {
        if ($Folder.reportOnly -eq "No") {
            Write-host "Deleting items in $($Folder.path)"
            $joinPath = Join-Path $($Folder.path) '*'
            Remove-Item -Recurse -Force -Path $joinPath -Filter $folder.fileList  -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            $sizeGB_post =  [math]::round((Get-ChildItem -Recurse -Force -Path $folder.path -Filter $folder.fileList -ErrorAction SilentlyContinue | Measure-Object -Property length -sum).sum / 1gb, 3)
            $returnFolders += [PSCustomObject]@{
                text = $folder.text
                Path = $folder.path
                sizeGB_prior = $folder.sizeGB
                sizeGB_post = $sizeGB_post
                sizeGB_diff = $folder.sizeGB - $sizeGB_post
            }
        } else {
            Write-Host "Folder is report only, not deleting. $($Folder.path)"
        }
    }
    $activityOutput.out.Folders = @($returnFolders)
    $activityOutput.success = $true;
    return $activityOutput;
}

function GetFileDetails {
    if (Test-Path $FilePath) {
        $File = get-item $FilePath
        $FileDetails = [PSCustomObject]@{
            LinkType            = $File.LinkType
            Length              = $File.Length
            CreationTimeUtc     = $File.CreationTimeUtc
            LastAccessTimeUtc   = $File.LastAccessTimeUtc
            LastWriteTimeUtc    = $File.LastWriteTimeUtc
            VersionInfo         = $File.VersionInfo
        }
        $activityOutput.out.fileDetails = @($FileDetails)
        $activityOutput.success = $true;
    } else {
        Write-Host "WARNING: File $FilePath not found."
        $activityOutput.success = $false;
    }
    return $activityOutput;
}

function RunDISM {
    $Drive = "C:\"
    $Args = $CommandArgs
    Write-host "Args: $Args"
    $DISMPath = 'C:\Windows\System32\DISM.exe'
    $Space_prior = ([System.IO.DriveInfo]::GetDrives() | Where-Object {$_.Name -eq $drive}).TotalFreeSpace
    $StartTime = get-date
    $processSettings = New-Object System.Diagnostics.ProcessStartInfo
    $processSettings.FileName = $DISMPath
    $processSettings.RedirectStandardError = $true
    $processSettings.RedirectStandardOutput = $true
    $processSettings.UseShellExecute = $false
    $processSettings.Arguments = $Args
    $DISMprocess = New-Object System.Diagnostics.Process
    $DISMprocess.StartInfo = $processSettings
    $DISMprocess.Start() | Out-Null
    $stdout = $DISMprocess.StandardOutput.ReadToEnd()
    $stderr = $DISMprocess.StandardError.ReadToEnd()
    $DISMprocess.WaitForExit()
    Write-Host "Standard Output:"
    write-host "$stdout"
    if (![string]::IsNullOrWhiteSpace($stderr)) {
        Write-Host "WARNING Error:"
        Write-Host "$stderr "
    }
    if ($DISMprocess.ExitCode -ne 0) {
        $activityOutput.success = $false;
    } else {
        $activityOutput.success = $true;
    }
    $Space_post = ([System.IO.DriveInfo]::GetDrives() | Where-Object {$_.Name -eq $drive}).TotalFreeSpace
    $Space = [PSCustomObject]@{
        prior = $Space_prior
        post = $Space_post
        change = [math]::round(($Space_prior - $Space_post) / 1GB,2)
    }
    $TimeTaken = New-TimeSpan -Start $StartTime -End (Get-Date)
    $activityOutput.out.space = $space
    $activityOutput.out.timeTaken = [string]::Format("{0} minutes {1} seconds",$TimeTaken.Minutes,$TimeTaken.Seconds)
    return $activityOutput;
}

function ExecuteActivity {
    try {
        switch ($Mode) {
            'report'  { return GetCleanupReport }
            'cleanup' { return CleanupFolders }
            'file'    { return GetFileDetails }
            'dism'    { return RunDISM }
            default   { throw "Unknown mode: $Mode" }
        }
    } catch {
        Write-Host "Error in ExecuteActivity: $($_.Exception.Message)"
        $activityOutput.success = $false
        return $activityOutput
    }
}
#endregion

#region MAIN EXECUTION
if ($MyInvocation.InvocationName -eq $MyInvocation.MyCommand.Name) {
    Write-Host "Computer Space Cleanup Report"
    Write-Host "============================="
    $result = ExecuteActivity
    if ($result.success) {
        Write-Host "`nOperation completed successfully!"
        Write-Host "Data available in: `$result.out"
    } else {
        Write-Host "`nOperation completed with errors."
    }
    return $result
}
#endregion