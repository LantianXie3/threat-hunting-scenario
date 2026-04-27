# Threat Hunt Report: Catching Unauthorized Tor Browser Use

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor onion logo with a crosshair overlay"/>

---

## 📸 Project Preview

<!-- Drop your preview screenshot here -->
![Project Preview](path/to/your-preview-image.png)

*Quick visual of the hunt in action — final query output, dashboard view, or whatever screenshot best represents the project.*

---

## Overview

This is a walkthrough of a threat hunt I ran in a lab environment where I traced how a single user installed and ran the Tor Browser on a corporate Windows 10 endpoint, then used it to reach hidden services on the dark web. The whole investigation was driven from telemetry sitting inside Microsoft Defender for Endpoint, with Kusto Query Language doing the heavy lifting. The goal was to take a vague tip from "management" and turn it into a clean, defensible timeline of what actually happened on the box.

You can find the lab setup that produced this telemetry here:
- [Scenario Creation](https://github.com/LantianXie3/threat-hunting-scenario/blob/main/threat-hunting-scenario-tor-event-creation.md)

---

## Tools & Environment

- **Endpoints:** Windows 10 VMs hosted in Microsoft Azure
- **EDR:** Microsoft Defender for Endpoint
- **Query Language:** Kusto Query Language (KQL)
- **Adversary Tool:** Tor Browser, version 14.5.5

---

## The Scenario

Recent firewall logs had been throwing off some odd patterns: encrypted traffic that didn't match anything on the corporate baseline, and outbound connections landing on IPs that show up in public lists of Tor entry relays. On top of that, a couple of anonymous tips came in claiming employees were swapping notes on how to get around the web filter during the workday.

The ask was straightforward: confirm or rule out Tor activity on the fleet, document anything that surfaces, and loop in management if it's real.

---

## How I Approached It

Before touching the data, I sketched out where the breadcrumbs would most likely live:

- `DeviceFileEvents` — anything getting written, copied, or extracted with "tor" in the filename
- `DeviceProcessEvents` — the installer firing, the browser launching, child processes spawning
- `DeviceNetworkEvents` — outbound connections riding on Tor's well-known ports (9001, 9030, 9050, 9051, 9150)

Three tables, three angles. If Tor was on this box, at least one of them was going to light up.

---

## Steps Taken

### 1. Looking for File Activity in `DeviceFileEvents`

The first sweep was for anything with "tor" in the filename. The results basically gave me the whole story up front: user `labuser` had pulled down the Tor Browser installer, run it, and let the unpacker spill dozens of Tor-related files onto the desktop. There was also a little extra — a file named `tor-shopping-list.txt` created at `2025-08-05T20:27:19.7259964Z`, which is the kind of thing that makes a hunter raise an eyebrow.

The whole sequence kicked off at `2025-08-05T20:15:27.0000000Z`.

```kql
DeviceFileEvents
| where DeviceName == "lan-vt"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-06T01:15:27.1828804Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1159" height="252" alt="DeviceFileEvents query showing tor-related files written to the labuser desktop, including the installer and tor-shopping-list.txt" src="https://github.com/user-attachments/assets/ef2a073f-faf3-4ef3-928f-569e79257ce1" />

*Snapshot of the file events that exposed the Tor installation and the suspicious shopping list file.*

---

### 2. Catching the Installer in `DeviceProcessEvents`

Knowing the installer had hit disk, the next move was confirming it actually ran. I pivoted into the process table and filtered on the installer filename. At `2025-08-05T20:16:47.0000000Z`, `labuser` executed `tor-browser-windows-x86_64-portable-14.5.5.exe` straight out of their Downloads folder, using a command line that pushed it through a silent install — meaning no setup dialog, no prompts, nothing a coworker walking by would visually notice.

```kql
DeviceProcessEvents
| where DeviceName == "lan-vt"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1161" height="77" alt="DeviceProcessEvents row showing the silent install command line for the Tor Browser installer" src="https://github.com/user-attachments/assets/84d5bdbc-2f67-4bf9-b0ac-6c08ac91d39c" />

*The installer firing with a silent flag — quiet on the screen, loud in the logs.*

---

### 3. Did They Actually Open the Browser?

Installation alone isn't the whole story. Plenty of installers run and never get touched again. To rule that out, I went hunting for `firefox.exe` and `tor.exe` activity on the same device. At `2025-08-05T20:17:19.0000000Z` the browser opened, and a chain of `firefox.exe` and `tor.exe` child processes started spawning right after — the textbook process tree you'd expect once Tor is up and running.

```kql
DeviceProcessEvents
| where DeviceName == "lan-vt"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1152" height="360" alt="Multiple firefox.exe and tor.exe processes spawning on lan-vt under the labuser account" src="https://github.com/user-attachments/assets/1d4ac15d-b053-4ffa-972c-0ddc36424b44" />

*The process tree confirming the browser was actually launched, not just installed.*

---

### 4. Watching the Network Light Up

Last piece: did the box actually phone home to the Tor network? I queried `DeviceNetworkEvents` for any connection out of `tor.exe` or `firefox.exe` heading to one of Tor's known ports. At `2025-08-05T20:17:50.0000000Z`, `tor.exe` (running out of `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`) opened a connection to `37.120.171.230` on port `9001` — a classic Tor relay handshake. A bunch of follow-up connections rode out on port `443` after that.

```kql
DeviceNetworkEvents
| where DeviceName == "lan-vt"
| where InitiatingProcessAccountName !~ "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9051, 9150, 80, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

<img width="1118" height="347" alt="DeviceNetworkEvents showing tor.exe reaching out to a relay on port 9001 followed by additional 443 traffic" src="https://github.com/user-attachments/assets/2fb65e36-ef5f-45a7-8186-08239b36cd1e" />

*Outbound connection to a Tor entry node — the moment the circuit went live.*

---

## Reconstructed Timeline

Pulling the four query results together gave me a clean, phase-by-phase view of the whole incident, from initial download to active browsing.

### Phase 1 — Download & Install (3:15 PM – 3:17 PM)

- **3:15:27 PM** — Tor Browser installer landed in `C:\Users\labuser\Downloads\`
  - File: `tor-browser-windows-x86_64-portable-14.5.5.exe`
  - SHA256: `6d38a13c6a5865b373ef1e1ffcd31b3f359abe896571d27fa666ce71c486a40d`
- **3:16:47 PM** — Installer executed with the silent flag (`/S`)
- **3:17:08 – 3:17:09 PM** — License files (`tor.txt`, `Torbutton.txt`, `Tor-Launcher.txt`) and `tor.exe` extracted into `C:\Users\labuser\Desktop\Tor Browser\`
- **3:17:27 PM** — `Tor Browser.lnk` shortcut placed on the desktop

### Phase 2 — First Launch (3:17 PM – 3:18 PM)

- **3:17:18 – 3:17:19 PM** — `firefox.exe` (Tor build) launched
  - SHA256: `6872f0df504c7a4a308caa86a73c62a51bb6e573107681ab60edbd72126df766`
- **3:17:26 PM** — GPU helper process spawned
- **3:17:27 – 3:17:35 PM** — Six content and utility child processes created for tab handling
- **3:17:29 PM** — `tor.exe` started; control port up on `127.0.0.1:9151`, SOCKS proxy on `127.0.0.1:9150`; network initially gated by `DisableNetwork 1`

### Phase 3 — Tor Circuit Up (3:17 PM – 3:18 PM)

- **3:17:43 – 3:17:50 PM** — Outbound to entry and relay nodes:
  - `95.143.193.125:443`
  - `87.118.116.90:443`
  - `194.126.174.190:443`
  - `37.120.171.230:9001`
- **3:17:50 PM** — Hidden service hits across `wujjupiz5ut5n.com`, `vynfq5kmdoueyba.com`, `xzejyxz7fr.com`, and `445dd5l5cr.com`
- **3:17:58 PM** — Firefox connected to the local SOCKS proxy on `127.0.0.1:9150` — circuit fully operational

### Phase 4 — Active Session (3:18 PM – 3:55 PM)

Roughly 40 minutes of continuous browsing, with new content processes (children #7 through #22) being created as new tabs and windows opened. Build ID stayed consistent at `20250722101758` across the session, ruling out tampering with the browser binary.

---

## Findings

`labuser` on `lan-vt` downloaded, silent-installed, and immediately launched Tor Browser 14.5.5 on August 5, 2025, starting at 3:15 PM. Within roughly two minutes of the browser opening, a Tor circuit was up and the user was reaching `.onion` hidden services. The session ran for about 40 minutes of active browsing.

The execution itself was technically clean — proper signatures, expected child processes, no obvious tampering. What stood out was the *behavior pattern*: silent install, immediate dark web access, and a `tor-shopping-list.txt` file created mid-session. Nothing about that sequence looks like idle curiosity.

---

## Response

- Tor activity on `lan-vt` was confirmed.
- The endpoint was isolated through Defender for Endpoint.
- The user's direct manager was notified and given the full timeline and supporting evidence.

---

## What I Learned

This was the first time I built a hunt around a real EDR dataset instead of a static lab dump, and a few things really stuck with me:

- **Cross-table pivoting is everything.** Any single one of those three tables only gives you a slice of the story. File events told me the binary existed. Process events told me it ran. Network events told me it actually did something. Stitching the three together is what turns "this looks suspicious" into "here is a defensible timeline with timestamps and SHA256 hashes."
- **Silent installs are louder than they think.** The `/S` flag is meant to hide the install from the user, but inside EDR telemetry it actually stands out, since legitimate user-driven installs usually trigger UAC and aren't running headless. That ended up being one of the more useful behavioral tells in the whole hunt.
- **Knowing the tool helps you hunt the tool.** Understanding that Tor uses 9001/9030/9050/9051/9150 internally, and that `tor.exe` typically lives under `Browser\TorBrowser\Tor\` inside the install directory, let me write tighter queries than I would have if I'd just been grepping for "tor" everywhere.
- **Writing the report is half the job.** Getting the KQL right is satisfying, but turning the raw rows into a phase-by-phase narrative is what actually makes the work useful to anyone who isn't me.

---

## What I'd Improve Next

A few directions I want to come back to:

- **Turn this into a detection rule.** Instead of running these queries by hand, codify the pattern (silent install of a portable browser → outbound on Tor ports within minutes) as a custom detection in Defender so the same scenario triggers automatically next time.
- **Layer in baseline filtering.** Some users in a real org legitimately run developer or privacy tooling that looks suspicious at first glance. An allowlist of approved processes and paths would cut noise dramatically when applied to a full fleet.
- **Bring DNS telemetry into the hunt.** I leaned on `DeviceNetworkEvents` for this round, but DNS queries to Tor directory authorities, or `.onion` resolution attempts that fail in normal DNS, could be another strong early indicator.
- **Map everything to MITRE ATT&CK.** Tagging the activity to specific techniques — `T1090.003` (Multi-hop Proxy: Tor) being the obvious one — would make the report more useful to a SOC analyst consuming it cold.
- **Run the same hunt on macOS and Linux.** The TTPs shift a bit across platforms, and I'd like to see how this looks when the endpoint isn't Windows — different paths, different processes, different EDR signals.

---
