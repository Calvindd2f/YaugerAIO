===========================
YaugerAIO Script README
Version: 1.1.9
===========================

Overview:
---------
This PowerShell script performs a series of system maintenance tasks on a Windows computer.
Note: Self-elevation is currently not functioning. Please launch PowerShell as an administrator
before running the script. The script gathers system information, performs health scans, and logs
the results. It also displays an ASCII banner with a "Proof of Concept" message inserted next to
a specific part of the art.

Features:
---------
1. Self-Elevation:
   - (Not functioning) You must manually run PowerShell as an administrator.

2. Execution Policy Setting:
   - The script sets the execution policy to RemoteSigned for the current process.

3. Logging Setup:
   - Creates an in-memory log and saves a log file on the desktop with a timestamped name.
   - All messages are output to the console and stored in the log.

4. ASCII Banner Display:
   - Displays multi-line ASCII art.
   - Searches for the substring "\_____/" and appends "Proof of Concept" (in white) immediately after.

5. Function Definitions:
   The script defines several functions to perform various tasks:
   
   a. Check-DiskSpace:
      - Retrieves free space, total capacity, and percentage free of the C: drive using CIM.
      - Logs the information in the format:
        "C: Drive Free Space: [free GB] GB out of [total GB] GB ([percentage]% free)".

   b. Check-CPUUsage:
      - Retrieves the current CPU usage using performance counters.
      - Logs the CPU usage percentage.

   c. Flush-DNSCache:
      - Flushes the DNS cache using the ipconfig command.
      - Logs the number of DNS entries removed.

   d. Check-RAMUsage:
      - Retrieves total visible memory and free physical memory using CIM.
      - Calculates and logs the used memory and the percentage used.

   e. Check-GPUDrivers:
      - Retrieves information about video controllers using CIM.
      - Logs the name and driver version of each GPU found.

   f. Check-SystemUptime:
      - Calculates system uptime by comparing the current time with the last boot time.
      - Logs the uptime in days.
      - Provides a warning if uptime exceeds 3 days and a more severe warning if it exceeds 7 days.

   g. Run-WindowsUpdate:
      - Checks for available Windows updates using the PSWindowsUpdate module.
      - Installs and imports the module automatically if not already present.
      - Installs available updates and prompts the user to restart if desired.
      - Logs details of the update process.

   h. Clear-BrowserCaches:
      - Checks for browser cache folders for Chrome and Edge in the local application data folder.
      - Deletes cache files if found and logs the results.

   i. Run-CleanMgr:
      - Executes the Disk Cleanup tool (cleanmgr) using a predefined configuration.
      - Logs whether Disk Cleanup was executed successfully.

   j. Run-DISMScan:
      - Runs a DISM scan to check and restore system health.
      - Logs the success or failure of the DISM operations.

   k. Run-SFCScan:
      - Runs the System File Checker (SFC) scan to detect and repair system file corruption.
      - Analyzes the CBS log for results.
      - Logs one of several outcomes:
         * Corrupt files found and fixed.
         * No integrity violations found.
         * Issues found that SFC could not fix (includes instructions for further troubleshooting).
      - If none of the expected patterns are detected, logs "SFC Scan completed."

6. Main Execution Block:
   - Displays the ASCII banner and a list of tasks the script will perform.
   - Prompts the user to press Enter to begin.
   - Prompts for a Y/N input to optionally run Disk Cleanup.
   - Executes each function in sequence:
       * Checks disk space, CPU usage, flushes DNS cache, checks RAM usage, GPU drivers, and system uptime.
       * Runs Windows Update, clears browser caches, and (if chosen) runs Disk Cleanup.
       * Runs DISM and SFC scans.
   - Calculates and logs the total space freed during the session.
   - Logs the total runtime of the script.

7. Final Logging and Completion:
   - Saves the complete log to a file on the desktop.
   - Outputs final completion messages to the console.

Requirements:
-------------
- Windows operating system.
- PowerShell must be launched as an administrator.
- The script automatically handles the installation of the PSWindowsUpdate module if needed.

Usage:
------
1. Place the script (YaugerAIOv1.1.9.ps1) on the desktop.
2. Launch PowerShell as an administrator and run the script.
3. Follow the on-screen prompts.
4. Check the generated log file on the desktop for details on the operations performed.

===========================
