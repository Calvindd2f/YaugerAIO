# YaugerAIO

A comprehensive Windows system maintenance and optimization tool that provides various utilities for system cleanup, performance monitoring, and maintenance.

## Features

- Disk space management and cleanup
- System performance monitoring
- Browser cache clearing
- Windows Update management
- System file integrity checks (DISM and SFC)
- GPU driver monitoring
- RAM usage optimization
- DNS cache management
- Threaded operations for better performance
- Enhanced error handling with circuit breaker pattern

## Installation

```powershell
Install-Module -Name YaugerAIO -Force -Scope CurrentUser
```

## Usage

```powershell
# Import the module
Import-Module YaugerAIO

# Run the main maintenance script
.\YaugerAIO.ps1

# Or use individual functions
Check-DiskSpace
Check-CPUUsage
Check-RAMUsage
Clear-BrowserCaches
```

## Functions

- `Check-DiskSpace`: Reports available disk space
- `Check-CPUUsage`: Monitors CPU utilization
- `Check-RAMUsage`: Reports RAM usage and availability
- `Check-GPUDrivers`: Checks GPU driver versions and updates
- `Check-SystemUptime`: Reports system uptime and recommends restarts
- `Clear-BrowserCaches`: Clears cache for various browsers
- `Clear-WindowsTemp`: Removes temporary files
- `Flush-DNSCache`: Clears DNS cache
- `Get-WindowsTempSize`: Reports size of temporary files
- `Install-WindowsUpdates`: Checks and installs Windows updates
- `Run-DISMCheckHealth`: Runs DISM health check
- `Run-SFCScan`: Runs System File Checker
- `Get-SystemHealthThreaded`: Runs comprehensive system health check

## Requirements

- Windows 10 or later
- PowerShell 5.1 or later
- Administrative privileges

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Rick Yauger
- Email: rick.yauger@outlook.com
- GitHub: [Graytools](https://github.com/yourGraytools)

## Acknowledgments

- Thanks to all contributors who have helped improve this module
- Special thanks to the PowerShell community for their support and feedback