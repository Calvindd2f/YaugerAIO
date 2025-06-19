#region INPUT VARIABLES
$folders
$filePath
$commandArgs
#endregion

#region OUTPUT VARIABLES
$variableProps = @{
    $freeSpace      = $null;
    $Folders        = $null;
    $systemDiskInfo = $null;
    $Folders        = $null;
    $fileDetails    = $null;
    $space          = $null;
    $timeTaken      = $null;
}
$outputProps = @{
    out     = [psobject]::new($variableProps)
    success = $false
}
$activityOutput = [psobject]::new($outputProps)
#endregion

#region FUNCTIONS
function Get-FileStorageInfo {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Folders,

        [Parameter()]
        [string]$FilePath,

        [Parameter()]
        [string]$CommandArgs
    )

    $variableProps = @{
        freeSpace      = $null
        Folders        = $null
        systemDiskInfo = $null
        fileDetails    = $null
        space          = $null
        timeTaken      = $null
    }

    $outputProps = @{
        out     = [psobject]::new($variableProps)
        success = $false
    }

    $activityOutput = [psobject]::new($outputProps)

    function Get-StorageAnalysis {
        $searchPath = @()
        $searchPath += [PSCustomObject]@{
            text       = 'Diagnostic Data Viewer database files'
            path       = 'C:\ProgramData\Microsoft\Diagnosis\EventTranscript\'
            fileList   = "*"
            reportOnly = 'No'
        }
        $searchPath += [PSCustomObject]@{
            text       = 'User Downloads folder'
            path       = 'C:\Users\username\Downloads'
            fileList   = "*"
            reportOnly = 'No'
        }
        $searchPath += [PSCustomObject]@{
            text       = 'Windows WinSxS'
            path       = 'C:\Windows\WinSxS'
            fileList   = "*"
            reportOnly = 'Yes'
        }
        $searchPath += [PSCustomObject]@{
            text       = 'IIS Log Files'
            path       = 'C:\inetpub\logs\LogFiles\*'
            fileList   = "*"
            reportOnly = 'No'
        }
        $searchPath += [PSCustomObject]@{
            text       = 'Windows Log Files'
            reportOnly = 'Yes'
            path       = 'C:\Windows\Logs\*'
            fileList   = "*"
        }
        $searchPath += [PSCustomObject]@{
            text       = 'Windows System32 Log Files'
            reportOnly = 'Yes'
            path       = 'C:\Windows\System32\LogFiles\*'
            fileList   = "*"
        }
        $searchPath += [PSCustomObject]@{
            text       = 'Recycle Bin'
            path       = 'C:\$Recycle.bin\*'
            fileList   = "*"
            reportOnly = 'No'
        }
        $searchPath += [PSCustomObject]@{
            text       = 'System error memory dump'
            path       = 'C:\windows'
            fileList   = "*.dmp"
            reportOnly = 'No'
        }
        $searchPath += [PSCustomObject]@{
            text       = 'System error memory minidump'
            path       = 'C:\windows\Minidump'
            fileList   = "*.dmp"
            reportOnly = 'No'
        }
        $searchPath += [PSCustomObject]@{
            text       = 'Windows Error Reporting Files'
            path       = 'C:\ProgramData\Microsoft\Windows\WER'
            fileList   = "*"
            reportOnly = 'No'
        }
        $searchPath += [PSCustomObject]@{
            text       = 'Windows Temp Files'
            path       = 'C:\windows\Temp'
            fileList   = "*"
            reportOnly = 'No'
        }
        $searchPath += [PSCustomObject]@{
            text       = 'User Temp Files'
            path       = 'C:\Users\username\AppData\Local\Temp'
            fileList   = "*"
            reportOnly = 'No'
        }
        $searchPath += [PSCustomObject]@{
            text       = 'User AppData'
            path       = 'C:\Users\username\AppData\'
            fileList   = "*"
            reportOnly = 'No'
        }

        $Output = @()

        foreach ($sPath in $searchPath) {
            if ((Test-Path $sPath.path.Replace("*", "")) -or ($sPath.path -like "C:\Users\username*")) {
                $Folders = @()

                if ($sPath.path.IndexOf("*") -gt 1) {
                    $Folders += Get-ChildItem $sPath.path.Replace("*", "") -Force | Where-Object { $_.PSIsContainer } | ForEach-Object { $_.FullName }
                }
                elseif ($sPath.path -like "C:\Users\username*") {
                    $Folders += Get-ChildItem C:\Users\ -Force | Where-Object { $_.PSIsContainer } | ForEach-Object { $sPath.path.Replace("C:\Users\username", $_.FullName) }
                }
                else {
                    $Folders += $sPath.path
                }

                foreach ($folder in $folders) {
                    if (Test-Path $folder) {
                        Write-Verbose "Getting size of folder $Folder."

                        $SizeGB = $null
                        try {
                            if ($sPath.fileList -eq "*") {
                                $files = Get-ChildItem -Recurse -Force -Path $Folder -Filter $sPath.fileList -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object { $false -eq $_.PSIsContainer }
                            }
                            else {
                                $files = Get-ChildItem -Force -Path $Folder -Filter $sPath.fileList -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object { $false -eq $_.PSIsContainer }
                            }

                            if ($files) {
                                $sizeGB = [math]::Round(($files | Measure-Object -Property length -Sum).Sum / 1GB, 3)
                            }
                            else {
                                $sizeGB = 0
                            }
                        }
                        catch [System.UnauthorizedAccessException] {
                            Write-Warning "Can't access $folder"
                        }

                        if ([string]::IsNullOrWhiteSpace($sizeGB)) {
                            $sizeGB = "Access Error"
                        }

                        $text = $sPath.text
                        if (($folders.Count -gt 1) -or ($sPath.text -eq "IIS Log Files")) {
                            if ($folder -like "C:\users*") {
                                $text = $text.Replace("User", "User $($folder.Split("\")[2])")
                            }
                            else {
                                $text = $sPath.text + "\" + ($Folder | Split-Path -Leaf)
                            }
                        }

                        if ($folder -like "*S-1-*") {
                            try {
                                $id = New-Object System.Security.Principal.SecurityIdentifier($Folder | Split-Path -Leaf)
                                $text = $text.Replace(($Folder | Split-Path -Leaf), $id.Translate([System.Security.Principal.NTAccount]))
                            }
                            catch {
                                Write-Verbose "SID not found for $folder"
                            }
                        }

                        $Output += [PSCustomObject]@{
                            text       = $text
                            path       = $Folder
                            fileList   = $sPath.fileList
                            reportOnly = $sPath.reportOnly
                            sizeGB     = $sizeGB
                        }

                        $files = $null
                    }
                    else {
                        Write-Warning "Could not find folder $Folder"
                    }
                }
            }
            else {
                Write-Warning "Could not find folder $($sPath.path)"
            }
        }

        $SystemDiskInfo = ([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.Name -eq "C:\" }) | Select-Object -Property @{
            N = 'text'
            E = { if ([string]::IsNullOrEmpty(($_.VolumeLabel))) { $_.Name } else { $_.VolumeLabel } }
        }, @{
            N = 'value'
            E = { $_.Name }
        }, @{
            N = 'FreeSpace (Gb)'
            E = { ($_.TotalFreeSpace / 1GB).ToString('F2') }
        }, @{
            N = 'Total (Gb)'
            E = { ($_.TotalSize / 1GB).ToString('F2') }
        }, @{
            N = 'FreePercent'
            E = { [Math]::Round(($_.TotalFreeSpace / $_.TotalSize) * 100, 2) }
        }

        $activityOutput.out.folders = $Output
        $activityOutput.out.freeSpace = ([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.Name -eq "C:\" }).TotalFreeSpace
        $activityOutput.out.systemDiskInfo = $SystemDiskInfo
        $activityOutput.success = $true

        return $activityOutput
    }

    function Remove-StorageItems {
        param([string]$FoldersJson)

        $returnFolders = @()
        foreach ($folder in ($FoldersJson | ConvertFrom-Json)) {
            if ($Folder.reportOnly -eq "No") {
                Write-Verbose "Deleting items in $($Folder.path)"
                $joinPath = Join-Path $($Folder.path) '*'
                Remove-Item -Recurse -Force -Path $joinPath -Filter $folder.fileList -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                $sizeGB_post = [math]::Round((Get-ChildItem -Recurse -Force -Path $folder.path -Filter $folder.fileList -ErrorAction SilentlyContinue | Measure-Object -Property length -Sum).Sum / 1GB, 3)

                $returnFolders += [PSCustomObject]@{
                    text         = $folder.text
                    Path         = $folder.path
                    sizeGB_prior = $folder.sizeGB
                    sizeGB_post  = $sizeGB_post
                    sizeGB_diff  = $folder.sizeGB - $sizeGB_post
                }
            }
            else {
                Write-Verbose "Folder is report only, not deleting. $($Folder.path)"
            }
        }

        $activityOutput.out.Folders = @($returnFolders)
        $activityOutput.success = $true

        return $activityOutput
    }

    function Get-FileDetails {
        param([string]$FilePath)

        if (Test-Path $FilePath) {
            $File = Get-Item $FilePath
            $FileDetails = [PSCustomObject]@{
                LinkType          = $File.LinkType
                Length            = $File.Length
                CreationTimeUtc   = $File.CreationTimeUtc
                LastAccessTimeUtc = $File.LastAccessTimeUtc
                LastWriteTimeUtc  = $File.LastWriteTimeUtc
                VersionInfo       = $File.VersionInfo
            }
            $activityOutput.out.fileDetails = @($FileDetails)
            $activityOutput.success = $true
        }
        else {
            Write-Warning "File $FilePath not found."
            $activityOutput.success = $false
        }

        return $activityOutput
    }

    function Invoke-DismCleanup {
        param([string]$CommandArgs)

        $Drive = "C:\"
        $DISMPath = 'C:\Windows\System32\DISM.exe'

        $Space_prior = ([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.Name -eq $drive }).TotalFreeSpace
        $StartTime = Get-Date

        $processSettings = New-Object System.Diagnostics.ProcessStartInfo
        $processSettings.FileName = $DISMPath
        $processSettings.RedirectStandardError = $true
        $processSettings.RedirectStandardOutput = $true
        $processSettings.UseShellExecute = $false
        $processSettings.Arguments = $CommandArgs

        $DISMprocess = New-Object System.Diagnostics.Process
        $DISMprocess.StartInfo = $processSettings
        $DISMprocess.Start() | Out-Null

        $stdout = $DISMprocess.StandardOutput.ReadToEnd()
        $stderr = $DISMprocess.StandardError.ReadToEnd()

        $DISMprocess.WaitForExit()

        Write-Verbose "Standard Output: $stdout"

        if (![string]::IsNullOrWhiteSpace($stderr)) {
            Write-Warning "DISM Error: $stderr"
        }

        if ($DISMprocess.ExitCode -ne 0) {
            $activityOutput.success = $false
        }
        else {
            $activityOutput.success = $true
        }

        $Space_post = ([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.Name -eq $drive }).TotalFreeSpace
        $Space = [PSCustomObject]@{
            prior  = $Space_prior
            post   = $Space_post
            change = [math]::Round(($Space_prior - $Space_post) / 1GB, 2)
        }

        $TimeTaken = New-TimeSpan -Start $StartTime -End (Get-Date)

        $activityOutput.out.space = $Space
        $activityOutput.out.timeTaken = [string]::Format("{0} minutes {1} seconds", $TimeTaken.Minutes, $TimeTaken.Seconds)

        return $activityOutput
    }

    # Execute based on parameters provided
    if ($Folders) {
        Remove-StorageItems -FoldersJson $Folders
    }
    elseif ($FilePath) {
        Get-FileDetails -FilePath $FilePath
    }
    elseif ($CommandArgs) {
        Invoke-DismCleanup -CommandArgs $CommandArgs
    }
    else {
        # Default behavior - get storage analysis
        Get-StorageAnalysis
    }

    return $activityOutput
}
#endregion

$Functionz = @(
    $Function:1,
    $Function:2,
    $Function:3,
    $Function:4
)
foreach ($fuck in $Functionz) {
    &  $fuck
}