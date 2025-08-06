# threat-hunting-scenario


# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "lan-vt"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-06T01:15:27.1828804Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1159" height="252" alt="image" src="https://github.com/user-attachments/assets/ef2a073f-faf3-4ef3-928f-569e79257ce1" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "lan-vt"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1161" height="77" alt="image" src="https://github.com/user-attachments/assets/84d5bdbc-2f67-4bf9-b0ac-6c08ac91d39c" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "lan-vt"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1152" height="360" alt="image" src="https://github.com/user-attachments/assets/1d4ac15d-b053-4ffa-972c-0ddc36424b44" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "lan-vt"
| where InitiatingProcessAccountName !~ "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9051, 9150, 80, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1118" height="347" alt="image" src="https://github.com/user-attachments/assets/2fb65e36-ef5f-45a7-8186-08239b36cd1e" />

---

Chronological Timeline
Phase 1: Download and Installation (3:15 PM - 3:17 PM)

3:15:27 PM - File Download Completed

    Tor Browser installer renamed to final location

    File: tor-browser-windows-x86_64-portable-14.5.5.exe

    Location: C:\Users\labuser\Downloads\

    SHA256: 6d38a13c6a5865b373ef1e1ffcd31b3f359abe896571d27fa666ce71c486a40d

3:16:47 PM - Installation Process Started

    Tor Browser installer executed with silent installation flag

    Command: tor-browser-windows-x86_64-portable-14.5.5 /S

    Process created by: labuser

3:17:08 PM - 3:17:09 PM - Core Files Extracted

    License files created: tor.txt, Torbutton.txt, Tor-Launcher.txt

    Main Tor executable extracted: tor.exe

    Installation directory: C:\Users\labuser\Desktop\Tor Browser\

3:17:27 PM - Installation Completed

    Desktop shortcut created: Tor Browser.lnk

Phase 2: Initial Launch and Process Creation (3:17 PM - 3:18 PM)

3:17:18 PM - 3:17:19 PM - Tor Browser Launch

    Primary Firefox process started

    Executable: C:\Users\labuser\Desktop\Tor Browser\Browser\firefox.exe

    SHA256: 6872f0df504c7a4a308caa86a73c62a51bb6e573107681ab60edbd72126df766

3:17:26 PM - GPU Process Creation

    Firefox GPU acceleration process spawned

3:17:27 PM - 3:17:35 PM - Browser Infrastructure Setup

    Multiple Firefox content processes created for tab handling

    Utility processes for RDD (Remote Data Decoder) functionality

    Child processes numbered 1-6 established

3:17:29 PM - Tor Network Process Started

    Core Tor executable launched: tor.exe

    Configuration files loaded from torrc and torrc-defaults

    Control port established on 127.0.0.1:9151

    SOCKS proxy configured on 127.0.0.1:9150

    Network initially disabled (DisableNetwork 1)

Phase 3: Tor Network Establishment (3:17 PM - 3:18 PM)

3:17:43 PM - 3:17:50 PM - Tor Circuit Building

    Connection to Tor entry nodes:

        95.143.193.125:443 (Initial relay)

        87.118.116.90:443 (Circuit relay)

        194.126.174.190:443 (Circuit relay)

        37.120.171.230:9001 (Circuit relay)

3:17:50 PM - Hidden Service Connections

    Accessed onion domains:

        https://www.wujjupiz5ut5n.com

        https://www.vynfq5kmdoueyba.com

        https://www.xzejyxz7fr.com

        https://www.445dd5l5cr.com

3:17:58 PM - Local Proxy Connection

    Firefox connected to local SOCKS proxy (127.0.0.1:9150)

    Tor network fully operational

Phase 4: Active Browsing Session (3:18 PM - 3:55 PM)

3:18:07 PM - 3:55:47 PM - Extended Browser Usage

    Multiple Firefox content processes spawned for new tabs/windows

    Child processes numbered 7-22 created over time

    Continuous browsing activity indicated by new process creation

    Build ID consistency: 20250722101758 (indicating Tor Browser version integrity)


## Summary

The user labuser on device lan-vt downloaded, installed, and immediately launched Tor Browser version 14.5.5 on August 5, 2025, starting at 3:15 PM. The installation used a silent deployment method to the desktop directory.
Within minutes of launch, the user successfully established Tor network circuits and accessed multiple .onion hidden service domains, indicating immediate dark web engagement. The browsing session lasted approximately 40 minutes with continuous activity across multiple tabs.
During this activity, the user also created a file named tor-shopping-list.txt, suggesting documentation of items or services of interest while browsing the dark web.
The technical indicators show legitimate Tor Browser behavior with proper signatures and expected process execution. However, the rapid progression from installation to hidden service access, combined with the creation of the shopping list file, suggests planned usage for specific procurement activities.
---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
