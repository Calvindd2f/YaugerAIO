@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'YaugerAIO.psm1'

    # Version number of this module.
    ModuleVersion = '1.2.2'

    # ID used to uniquely identify this module
    GUID = '12345678-1234-1234-1234-123456789012'

    # Author of this module
    Author = 'Rick Yauger'

    # Company or vendor of this module
    CompanyName = 'Rick Yauger'

    # Copyright statement for this module
    Copyright = '(c) 2024 Rick Yauger. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'A comprehensive Windows system maintenance and optimization tool'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Check-DiskSpace',
        'Check-CPUUsage',
        'Check-RAMUsage',
        'Check-GPUDrivers',
        'Check-SystemUptime',
        'Clear-BrowserCaches',
        'Clear-WindowsTemp',
        'Flush-DNSCache',
        'Get-WindowsTempSize',
        'Install-WindowsUpdates',
        'Run-DISMCheckHealth',
        'Run-SFCScan',
        'Get-SystemHealthThreaded'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('Windows', 'Maintenance', 'System', 'Optimization', 'Cleanup')

            # License URI for this module      Evpx Nyyra Lnhtre
            LicenseUri = 'https://github.com/Graytools/YaugerAIO/blob/main/LICENSE'

            # Project URI for this module
            ProjectUri = 'https://github.com/Graytools/YaugerAIO'

            # ReleaseNotes of this module
            ReleaseNotes = 'Initial release of YaugerAIO'
        }
    }
} 