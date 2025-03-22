YaugerAIO Script - Version 1.1.9
A simple tool to perform system maintenance on Windows with ease!

What's This For?
This script takes care of common maintenance tasks like checking your system's health, clearing caches, and installing updates. It also provides detailed logs so you can see what’s happening behind the scenes.

Heads-up: You’ll need to launch PowerShell as an administrator before running this script.

What Does It Do?
Key Features:
Easy Logging: Keeps track of everything it does and saves a log file to your desktop.

System Health Checks: Looks at your drive space, RAM, CPU usage, GPU drivers, and how long your system has been running.

Maintenance Tasks:

Clears browser caches (Chrome & Edge).

Flushes the DNS cache.

Runs Disk Cleanup (optional).

System Repairs:

Runs DISM and SFC scans to detect and fix system issues.

Windows Updates: Installs updates using the PSWindowsUpdate module.

Quick Start Guide:
Save the script to your desktop (filename: YaugerAIOv1.1.9.ps1).

Open PowerShell as an administrator.

Run the script and follow the on-screen prompts.

Once it’s done, check the log file (saved to your desktop) for details.

Important Notes:
Run as Admin: The script won’t work unless PowerShell is launched with administrator privileges.

Total Space Freed: After running, it calculates the amount of space freed up during the session.
