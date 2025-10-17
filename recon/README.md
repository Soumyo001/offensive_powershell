# Windows System & Personal Information Collection Script

## Overview

This is a comprehensive **PowerShell script** that collects a broad array of system, user, network, device, and clipboard information from a Windows PC. It is designed for system auditing, support diagnostics, forensic investigation, or compliance validation in enterprise and personal environments.

- **System hardware**: CPU, RAM, disks, GPU, motherboard, BIOS, batteries.
- **Network**: all adapters, MAC/IP addresses, DHCP info.
- **User**: all local profiles, group memberships, last logon times, admin list.
- **Software**: all installed applications, running processes, startup entries, recent system errors/warnings, Windows Updates.
- **Security**: all detected antivirus, firewall status.
- **Device forensics**: connected and historic USB devices with serials, vendor details, drive letters, filesystem, and registry/arrival event logs.
- **Wireless**: all saved Wi-Fi SSIDs and stored passwords.
- **Clipboard contents** (for current session).
- **Location and ISP** info (using public IP).
- **Outputs**: all raw data files are securely sent to a webhook (e.g., Discord), and then deleted for privacy.

## Features

- **Professional Data Extraction**: Hardware, network, user, software, event logging.
- **USB Forensics**: Device IDs, serials, volume/FS info, VID/PID, historic registry presence, and recent insertion/removal events.
- **Security Inventory**: Multi-vendor antivirus detection, OS firewall state, Windows licensing.
- **Clipboard Support**: Optionally pulls current clipboard contents into a separate file.
- **Geo-IP Location**: External IP geolocation and automatic HTML map file showing device location.
- **Automated Collection**: All findings are formatted and uploaded via webhook; source files are cleaned up afterward.

## Usage

1. **Run PowerShell as Administrator** (required for full access).
2. **Save script** as `info-collector.ps1` and execute:
    ```
    .\info-collector.ps1
    ```
3. **Files created** (in your Documents folder):
    - `personal_info.txt`: IP info, location, MACs, Wi-Fi, etc.
    - `clipboard.txt`: clipboard content (if any).
    - `pc_info.txt`: full hardware/software/device/user report.
    - `DeviceLocation.html`: Google Maps location.

4. **Webhook**: Set your Discord/webhook URL in the `$webhookuri` variable for automatic secure upload.

5. **Cleanup**: All output files are deleted after upload.

## Example Output

- Sample hardware block:
    ```
    ==== CPU Information ====
    Name: Intel(R) Core(TM) i7-9700K
    Manufacturer: GenuineIntel
    NumberOfCores: 8
    ...
    ```
- Device history:
    ```
    ==== Detailed USB Device History ====
    Device: USBSTOR&Disk...
    Manufacturer: Kingston
    SerialNumber: 123456
    InstallDate: 2021-01-15
    ...
    ```

- And extensive blocks for users, groups, drives, security, processors, clipboard, public IP location, etc.

## Requirements

- Windows 10/11 (or recent server OS).
- PowerShell 5.1+.
- Administrator rights for system/registry access.
- Internet access for public IP, geolocation, and webhooks (optional).

## Disclaimer

- Use **only on systems you own or have explicit authorization to audit**.
- The script collects sensitive device/user information. Distribute and handle files responsibly.
- The authors are **not responsible for misuse or unauthorized deployment**.
