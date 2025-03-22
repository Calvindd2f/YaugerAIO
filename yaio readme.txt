====================================================================
                         YaugerAIO Script
====================================================================
Version: 1.1.9
Platform: Windows
PowerShell Required: Yes (Run as Administrator)
====================================================================

OVERVIEW:
---------
YaugerAIO is an all-in-one PowerShell script designed to help you
maintain and optimize your Windows system. It automates key tasks 
like checking system health, cleaning up files, and installing 
updates — all with detailed logging so you can review what happened
after it runs.

IMPORTANT:
----------
⚠️ You MUST run PowerShell as Administrator before launching the script.

FEATURES:
---------
System Monitoring:
  - Disk Space Check: Shows free/used space on your main drive.
  - CPU Usage: Reports current CPU load.
  - RAM Usage: Displays memory consumption.
  - System Uptime: Shows how long the system has been running.
  - GPU Info: Lists GPU(s) and driver versions.

Cleanup & Optimization:
  - Flushes DNS Cache.
  - Clears Browser Cache (Chrome and Edge).
  - Disk Cleanup (optional): Uses Windows Disk Cleanup tool.

System Maintenance:
  - DISM Scan: Checks and repairs Windows system image.
  - SFC Scan: Detects and fixes corrupted system files.

Windows Updates:
  - Installs and configures the PSWindowsUpdate module (if needed).
  - Checks for and installs available Windows updates.
  - Prompts for restart if necessary.

Logging:
  - Creates a detailed log file saved to your Desktop.
  - Tracks every operation, from cleanup to update installation.

USAGE INSTRUCTIONS:
-------------------
1. Place the script file (YaugerAIOv1.1.9.ps1) on your Desktop.
2. Right-click PowerShell and select "Run as Administrator".
3. Run the script and follow the on-screen prompts.
4. Once complete, check your Desktop for a log file with full details.

REQUIREMENTS:
-------------
- Windows 10 or newer
- PowerShell 5.1 or later (pre-installed on most systems)
- Admin rights
- Internet connection (for update module installation if required)

OUTPUT:
-------
The script creates a log file on your Desktop summarizing:
  - System stats (disk, RAM, uptime, etc.)
  - Cleanup results (space cleared, cache removed)
  - Update installation details
  - DISM and SFC scan outcomes
  - Total runtime of the script

SUPPORT & FEEDBACK:
-------------------
This script is provided as a proof of concept and general-use tool.
For suggestions or issues, reach out or submit feedback through your 
preferred support channel.

====================================================================
