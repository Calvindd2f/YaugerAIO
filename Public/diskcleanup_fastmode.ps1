<# disk cleanup (powershell after all) ::
   user variables:  usrPrefetch/bool :: usrMiniDump/bool :: usrUpdateCache/bool :: usrPackagesFolder/bool :: usrRecycleBin/bool (!) :: usrBrowserCaches/bool (!) :: usrWERLogs/bool (!)
   warning strings: "Operation Aborted"

   [REDACTED] this includes on reddit, on discord, or as part of other RMM tools. PCSM is the one exception to this rule.

   the moment you edit this script it becomes your own risk and support will not provide assistance with it.#>

#======================================== FUNCTIONS & FUNCTIONS ========================================

Param (
    [bool]$usrPreFetch,
    [bool]$usrMinidump,
    [bool]$usrUpdateCache,
    [bool]$usrPackagesFolder,
    [bool]$usrBrowserCaches,
    [bool]$usrRecycleBin,
    [bool]$usrWERLogs,
    [bool]$usrCrashdumps
)

function getDriveSpace ($drive) {
    #give out the basics
    write-host ": Statistics for Drive $drive"
    $varDriveFree = $([math]::Round(((get-psdrive $($env:SystemDrive).replace(':', '')).Free) / 1GB, 2))
    write-host "- Free Space: $([math]::Round(((get-psdrive $($env:SystemDrive).replace(':','')).Free)/1GB,2)) GB"
    $varDriveUsed = $([math]::Round(((get-psdrive $($env:SystemDrive).replace(':', '')).Used) / 1GB, 2))
    write-host "- Used Space: $([math]::Round(((get-psdrive $($env:SystemDrive).replace(':','')).Used)/1GB,2)) GB"
    #calculate a percentage
    $varDrivePerc = [math]::Round($varDriveFree / ($varDriveFree + $varDriveUsed) * 100, 2)
    write-host "- % Free:     $varDrivePerc%"

    if ($script:varPriorResult) {
        write-host "- (Was:       $($script:varPriorResult)%)"
        $script:varNowResult = $varDrivePerc
    }
    else {
        $script:varPriorResult = $varDrivePerc
    }
}

#windows relative identifier lookup table ::
function checkRID ($SID) {
    switch -regex ($SID) {
        '-18$' {
            write-host ": Account Type:      LocalSystem"
        } '-19$' {
            write-host ": Account Type:      NT Authority"
        } '-20$' {
            write-host ": Account Type:      NetworkService"
        } '-500$' {
            write-host ": Account Type:      Default Administrator"
        } '-501$' {
            write-host ": Account Type:      Guest"
            return $true
        } '-502$' {
            write-host ": Account Type:      Key Distribution Centre"
        } '-503$' {
            write-host ": Account Type:      Default"
        } '-504$' {
            write-host ": Account Type:      Windows Defender AppGuard [Windows Sandbox]"
        } default {
            if ($SID -match $varLocalSID) {
                write-host ": Account Type:      User [Local]"
            }
            else {
                write-host ": Account Type:      User [Domain]"
            }

            if ($(get-itemproperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID" -Name "ProfileLoadTimeHigh" -ea 0).ProfileLoadTimeHigh -eq 0) {
                return $true
            }
        }
    }
}

#since this is an upgrade, set new variables to FALSE to cater for accounts where they aren't set at all
if (!$env:usrRecycleBin -or !$env:usrBrowserCaches) {
    $env:usrRecycleBin = $false
    $env:usrBrowserCaches = $false
    write-host "! NOTICE: When this Component was updated, new variables were introduced."
    write-host "  You can now configure whether to empty the Recycle Bin with usrRecycleBin,"
    write-host "  and whether to clear Browser caches with the usrBrowserCaches variable."
    write-host "  To see these new options, delete the old `'Disk Cleanup`' Component and"
    write-host "  then re-download it fresh from the ComStore."
    write-host "  For safety's sake, these options have been set to FALSE for this Job run."
    write-host "======================================="
    write-host `r
}

#thom yorke violently thrusts a thumbs-down at the screen
function teeString ($string) {
    write-host $string
    $arrLog += "$string"
}

$varEpoch = [int][double]::Parse((Get-Date -UFormat %s))

$varUBR = $((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name UBR -ea 0).UBR)
if (!$varUBR) {
    $varUBR = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Windows\system32\kernel32.dll")).ProductVersion.split('\.')[3]
}

#============================================== CODE PRODE =============================================

write-host "Disk Cleanup Tool ($(get-date))"
write-host "======================================="
write-host "Windows Version: $((get-WMiObject win32_operatingSystem).caption) [$((get-WMiObject win32_operatingSystem).version).$varUBR]"
write-host "Device Name:     $env:COMPUTERNAME"
write-host "Home Drive:      $env:SystemDrive"
write-host "Running From:    $($PWD.Path)"
write-host "---------------------------------------"
write-host ": Clear Prefetch:       $env:usrPrefetch"
write-host ": Clear Minidumps:      $env:usrMinidump"
write-host ": Clear Update Cache:   $env:usrUpdateCache"
write-host ": Clear DRMM Packages:  $env:usrPackagesFolder"
write-host ": Clear Browser Caches: $env:usrBrowserCaches (Cookies are always preserved)"
write-host ": Clear Win Error Logs: $env:usrWERLogs"
write-host ": Empty Recycle Bin:    $env:usrRecycleBin"
write-host "---------------------------------------"
getDriveSpace $env:SystemDrive
write-host "======================================="

#boilerplate -------------------------------------------------------------------------------------------

#produce an endpoint log
$arrLog = @()
$arrLog += "================================================"
$arrLog += "Disk Cleanup Log: $(get-date)"
$arrLog += "The following files have been deleted:"
$arrLog += "------------------------------------------------"

#make sure script only runs 1xday ----------------------------------------------------------------------

if (Get-ItemProperty "HKLM:\Software\CentraStage" -Name SGLCleanup -ea 0) {
    if ($((Get-ItemProperty "HKLM:\Software\CentraStage" -Name SGLCleanup).SGLCleanup) -eq "$($(Get-Date).ToString("MM")).$($(Get-Date).ToString("dd"))") {
        write-host "! NOTICE: Cleanup has already been run once today."
        write-host "  In order to prevent script collision, only one cleanup operation is permitted to run per day."
        write-host "  Operation aborted; If a previous Endpoint log was present on the system, it has been preserved."

        if ($script:MyInvocation.MyCommand.Path -match 'Temp') {
            #response component
            write-host '<-Start Diagnostic->'
            write-host "ERROR: Cleanup has already run once today on this device, so Disk Cleanup operation was cancelled."
            write-host "       This is to prevent script clashes."
        }

        exit
    }

    #write today's date to the registry
    Set-ItemProperty "HKLM:\Software\CentraStage" -Name SGLCleanup -Value "$($(Get-Date).ToString("MM")).$($(Get-Date).ToString("dd"))" -Force | out-null
}
else {
    Set-ItemProperty "HKLM:\Software\CentraStage" -Name SGLCleanup -Value "$($(Get-Date).ToString("MM")).$($(Get-Date).ToString("dd"))" -Force | out-null
}

#get information on users to cleanup -------------------------------------------------------------------

#get the local device's domain SID by looking at the administrator account
$varLocalSID = (get-wmiobject win32_useraccount -filter "LocalAccount=True" | ? { $_.SID -match '-500$' }).SID -replace ".{3}$"

#construct an array of all valid users with profile data
$arrUsers = @()
gci -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | % { Get-ItemProperty $_.PSPath } | % {
    write-host ": Account Name:      $(($_.ProfileImagePath).split('\\')[-1])"
    if (checkRID $($_.PSChildName)) {
        write-host ": Valid for Cleanup: YES"
        $arrUsers += $_.ProfileImagePath
    }
    else {
        write-host ": Valid for Cleanup: NO"
    }
    write-host "------"
}

#clear out user-specific data =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

write-host "- The following user directories' temporary data will be cleared:"
$arrUsers | % { write-host ": $_" }
write-host "======================================="

$arrUsers | % {
    if (!$_) {
        break #this should never happen, but break if no user is logged to prevent accidentally deleting anything
    }

    teeString ": User: $_"

    teeString "- Clearing local temporary data"
    gci "$_\AppData\Local\Temp" -Recurse -Force -ea 0 | % {
        $arrLog += ". $($_.FullName)"
        remove-item $($_.FullName) -Force -Recurse -ea 0
    }

    if ($env:usrWERLogs -eq 'true') {
        teeString "- Clearing Windows Error Reporting logs [User]"
        gci "$_\AppData\Local\Microsoft\Windows\WER" -Recurse -Force | % {
            $arrLog += ". $($_.FullName)"
            remove-item $($_.FullName) -Force -Recurse -ea 0
        }
    }
    else {
        write-host ": Not clearing Windows Error Reporting logs [User]"
    }

    if ($env:usrBrowserCaches -eq 'true') {

        write-host "======"
        write-host ": NoTE for browser cache clearout"
        write-host "- On Chromium-based browsers (Chrome, Edge, Vivaldi, Brave), this has been"
        write-host "  known to cause issues where the browser, if open, still believes the"
        write-host "  caching data to be present and attempts to retrieve it, leading to broken"
        write-host "  stylesheets and images while browsing. These can be relieved with CTRL+F5."
        write-host "  There is no known remediation for this. The browsing data will be cleared,"
        write-host "  but be aware of this side-effect and use this option sparingly."
        write-host "======"

        #ie
        teeString "- Clearing IE Cache"
        gci "$_\AppData\Local\Microsoft\Windows\INetCache\IE" -ea 0 -Recurse -Force | % {
            $arrLog += ". $($_.FullName)"
            remove-item $($_.FullName) -Force -Recurse -ea 0
        }

        #chrome-edge
        teeString "- Clearing Edge [Chrome] Cache"
        gci "$_\AppData\Local\Microsoft\Edge\User Data\Default\Cache" -ea 0 -Recurse -Force | % {
            $arrLog += ". $($_.FullName)"
            remove-item $($_.FullName) -Force -Recurse -ea 0
        }

        #chrome-chrome
        teeString "- Clearing Google Chrome Cache"
        ("$_\AppData\Local\Google\Chrome\User Data\Default\Cache", "$_\AppData\Local\Google\Chrome\User Data\Default\Cache2", "$_\AppData\Local\Google\Chrome\User Data\Default\Media Cache") | % {
            gci $_ -ea 0 -Recurse -Force | % {
                $arrLog += ". $($_.FullName)"
                remove-item $($_.FullName) -Force -Recurse -ea 0
            }
        }

        #vivaldi
        teeString "- Clearing Vivaldi Cache"
        gci "$_\AppData\Local\Vivaldi\User Data\Default\Cache" -ea 0 -Recurse -Force | % {
            $arrLog += ". $($_.FullName)"
            remove-item $($_.FullName) -Force -Recurse -ea 0
        }

        #firefox
        teeString "- Clearing Firefox Cache"
        gci "$_\AppData\Local\Mozilla\Firefox\Profiles\" -ea 0 -Force | ? { $_.PSIsContainer } | % {
            gci "$($_.FullName)\cache2\entries" -ea 0 -Recurse | % {
                $arrLog += ". $($_.FullName)"
                remove-item $($_.FullName) -Force -Recurse -ea 0
            }
        }

        #reddit browser
        teeString "- Clearing Brave Cache"
        gci "$_\AppData\Local\BraveSoftware\User Data\Default\Cache" -ea 0 -Recurse -Force | % {
            $arrLog += ". $($_.FullName)"
            remove-item $($_.FullName) -Force -Recurse -ea 0
        }

    }
    else {
        write-host ": Not clearing Browser caches"
    }

    write-host "------"
}

write-host "- Finished clearing per-user data."
write-host "======================================="

#clear out global data -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

#recycle bin
if ($env:usrRecycleBin -eq 'true') {
    Get-WmiObject win32_logicaldisk | % {
        teeString "- Clearing Recycle Bin on $($_.DeviceID)"
        remove-item "$($_.DeviceID)\RECYCLER" -Force -Recurse -ea 0
        remove-item "$($_.DeviceID)\RECYCLED" -Force -Recurse -ea 0
        remove-item "$($_.DeviceID)\`$RECYCLE.BIN" -Force -Recurse -ea 0
    }
}
else {
    write-host ": Not emptying Recycle Bin/s"
}

#sys:\windows\temp (without clearing the script itself)
teeString "- Clearing Temp directory"
gci "$env:TEMP" -ea 0 -Recurse -Force | % {
    if ($($_.FullName) -eq $($script:MyInvocation.MyCommand.Path)) {
        #do nothing, that's this script!
    }
    else {
        $arrLog += ". $($_.FullName)"
        remove-item $($_.FullName) -Force -Recurse -ea 0
    }
}

#prefetch
if ($env:usrPrefetch -eq 'true') {
    teeString "- Clearing PreFetch directory"
    gci "$env:SystemRoot\PreFetch" -ea 0 -Recurse -Force | % {
        $arrLog += ". $($_.FullName)"
        remove-item $($_.FullName) -Force -Recurse -ea 0
    }
}
else {
    write-host ": Not clearing PreFetch"
}

#windows update cache
if ($env:usrUpdateCache -eq 'true') {
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA 0 | ? { $_.Property }) {
        write-host "! NOTICE: Unable to clear Windows Update cache; a reboot is pending."
    }
    else {
        teeString "- Clearing Windows Update cache"
        Stop-Service bits -Force
        Stop-Service wuauserv -Force
        start-sleep -Seconds 5
        gci "$env:SystemRoot\SoftwareDistribution\Download" -ea 0 -Recurse -Force | % {
            $arrLog += ". $($_.FullName)"
            remove-item $($_.FullName) -Force -Recurse -ea 0
        }
    }
}
else {
    write-host ": Not clearing Windows Update cache"
}

#dmp
if ($env:usrMinidump -eq 'true') {
    teeString "- Clearing Minidumps"
    gci "$env:SystemRoot\Minidump\*.dmp" -ea 0 -Recurse -Force | % {
        $arrLog += ". $($_.FullName)"
        remove-item $($_.FullName) -Force -Recurse -ea 0
    }
}
else {
    write-host ": Not clearing Minidumps"
}

#packages folder
if ($env:usrPackagesFolder -eq 'true') {
    teeString "- Clearing Packages Folder"
    gci "$env:PROGRAMDATA\CentraStage\Packages" -Force -ea 0 | ? { $_.PSIsContainer } | % {
        if ($_.FullName -ne $PWD.Path) {
            #make 100% certain we know what we're doing
            if ($($_.FullName) -match '-') {
                $arrLog += ". [DIR] $($_.FullName)"
                remove-item $_.FullName -Force -Recurse -ea 0
            }
            else {
                write-host "! ERROR: Package clearout subroutine detected a foreign directory."
                write-host "  The path was: $($_.FullName)"
                write-host "  Please report this error. This directory has not been removed."
            }
        }
    }
}
else {
    teeString ": Not clearing Packages Folder"
}

#wer
if ($env:usrWERLogs -eq 'true') {
    teeString "- Clearing Windows Error Reporting logs [Global]"
    gci "$env:PROGRAMDATA\Microsoft\Windows\WER\ReportQueue" -Recurse -Force | % {
        $arrLog += ". $($_.FullName)"
        remove-item $($_.FullName) -Force -Recurse -ea 0
    }
}
else {
    write-host ": Not clearing Windows Error Reporting logs [Global]"
}

#recalculate/display disk space
write-host "======================================="
write-host "- Disk cleanup completed!"
$arrLog += "= END OF DELETION LOG"
getDriveSpace $env:SystemDrive

#deletion log
$arrLog | % { $host.ui.WriteErrorLine($_) }
write-host "- A deletion log has been written to StdErr."
write-host "  It has also been saved locally at $env:ProgramData\CentraStage\Temp\RMMDC-$varEpoch.txt."
$arrLog | out-file "$env:ProgramData\CentraStage\Temp\RMMDC-$varEpoch.txt"

#post a diagnostic
write-host `r
write-host '<-Start Diagnostic->'
write-host "A disk cleanup operation was performed at $(get-date)."
write-host "Drive $env:SystemDrive WAS: $script:varPriorResult% Free"
write-host "Drive $env:SystemDrive  IS: $script:varNowResult% Free"
write-host '<-End Diagnostic->'

#closeout
write-host "======================================="
write-host "- Exiting..."