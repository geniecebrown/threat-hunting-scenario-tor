# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/geniecebrown/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-07-24T01:13:24.2711453Z`. These events began at `2025-07-24T00:47:32.4005341Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "geniece-mde-tes"
| where InitiatingProcessAccountName == "gdbrook"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-24T00:47:32.4005341Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1170" height="517" alt="DeviceFileEvents" src="https://github.com/user-attachments/assets/69c9379c-ef65-4947-b54d-228f5104cf90" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.5.exe". Based on the logs returned, at `2025-07-24T00:54:51.1317821Z`, a user named gdbrook on the “geniece-mde-tes” device ran the file `tor-browser-windows-x86_64-portable-14.5.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "geniece-mde-tes"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1019" height="162" alt="DeviceProcessEvents" src="https://github.com/user-attachments/assets/d9a8b8e7-946f-416f-a3e9-5cfc6a8a4cb7" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "gdbrook" actually opened the TOR browser. There was evidence that they did open it at `2025-07-24T00:55:32.3244638Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "geniece-mde-tes"
| where FileName has_any ("firefox.exe", "tor.exe", "torbrowser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1227" height="606" alt="DeviceProcessEvents Tor" src="https://github.com/user-attachments/assets/b118a788-189f-4a8c-b625-39d152c81cb5" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-07-24T00:55:45.2874879Z`, a user named gdbrook on the "geniece-mde-tes" device successfully established a connection to the remote IP address `188.99.193.108` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\gdbrook\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "geniece-mde-tes"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1263" height="549" alt="DeviceNetworkEvents" src="https://github.com/user-attachments/assets/2c4b5eeb-3efc-4c17-82f9-daa50721494c" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-07-24T00:47:32.4005341Z`
- **Event:** The user "gdbrook" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\gdbrook\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-07-24T00:54:51.1317821Z`
- **Event:** The user "gdbrook" executed the file `tor-browser-windows-x86_64-portable-14.5.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.5.exe /S`
- **File Path:** `C:\Users\gdbrook\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-07-24T00:55:32.3244638Z`
- **Event:** User "gdbrook" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\users\gdbrook\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-07-24T00:55:45.2874879Z`
- **Event:** A network connection to IP `188.99.193.108` on port `9001` by user "gdbrook" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\users\gdbrook\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-07-24T01:16:57.6515089Z` - Connected to `5.45.98.188` on port `443`.
  - `2025-07-24T00:56:05.4919873Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "gdbrook" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-07-24T01:13:24.2711453Z`
- **Event:** The user "gdbrook" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\gdbrook\Desktop\tor-shopping-list.txt`

---

## Summary

The user "gdbrook" on the "geniece-mde-tes" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `geniece-mde-tes` by the user `gdbrook`. The device was isolated, and the user's direct manager was notified.

---
