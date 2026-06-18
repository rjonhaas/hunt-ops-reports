# RoguePlanet — Windows Defender LPE via Remediation Race Condition

**TLP: WHITE** | **Severity: Critical** | **Date: 2026-06-18**

---

## Summary

- Windows Defender LPE exploiting a race condition in the malware remediation flow; no administrator privileges required.
- Standard user escalates to NT AUTHORITY\SYSTEM shell on Windows 10 and Windows 11, including the Canary channel, with patches current through June 2026.
- Payload plants itself at C:\Windows\System32\wermgr.exe via an NTFS junction swap executed during Defender's cleanup write -- Defender itself is the write primitive.
- SYSTEM execution is achieved by triggering the built-in WER QueueReporting scheduled task via the ITaskService COM interface.
- Highest-confidence detection: named pipe `\\.\pipe\RoguePlanet` -- hardcoded in the binary, no legitimate software uses this name, zero false positives.

---

## Threat Overview

| Field | Value |
|---|---|
| **Name** | RoguePlanet |
| **Author / Source** | MSNightmare -- [github.com/MSNightmare/RoguePlanet](https://github.com/MSNightmare/RoguePlanet) |
| **Type** | Local Privilege Escalation (LPE) |
| **Affected Platforms** | Windows 10, Windows 11 (including Canary channel) -- June 2026 patches |
| **Not Affected** | Windows Server -- standard users cannot mount ISO images without administrator rights; author notes all Server versions are architecturally vulnerable if that restriction is bypassed |
| **Severity** | Critical |
| **Requires Admin** | No -- standard user only |
| **CVE** | [CVE-2026-50656](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50656) |
| **CVSS** | 7.8 (Important) — MSRC |
| **EPSS** | 0.343% (25.97th percentile) — as of 2026-06-18; expect upward revision as PoC propagates |
| **Patch Status** | Unpatched — patch in development (Microsoft confirmed 2026-06-16) |
| **First Seen** | 2026-06-18 |
| **TLP** | WHITE |

---

## Attack Chain

### Stage 1 -- Setup and ISO Mount

The exploit begins by writing an embedded ~896 KB ISO image (rawData[917504] in the source) to a uniquely named working directory under %TEMP%:

```
%TEMP%\RP_<UUID>\          # root working directory
%TEMP%\RP_<UUID>\wdtest_temp\
%TEMP%\RP_<UUID>\System32\ # named to match GetWERDir() -> %WINDIR%\System32
```

The ISO contains a single file: `wermgr.exe`, which is a copy of the exploit binary itself.

The ISO is mounted read-only and without a drive letter using the VirtDisk API:

```
OpenVirtualDisk(VIRTUAL_STORAGE_TYPE_DEVICE_ISO, path, ...)
AttachVirtualDisk(..., ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, ...)
```

Mounting without a drive letter keeps the volume off Explorer and away from trivial AV scans. The volume is accessible at `\\?\Volume{<GUID>}\`.

A pool of background "Poseidon" threads is started. These threads spam random-data writes to files in %TEMP%\RP_* continuously throughout the exploit to create I/O pressure, increasing the size of the race window by making the filesystem subsystem busier.

**Artifacts at this stage:**
- `%TEMP%\RP_<UUID>` directory tree
- Mounted ISO volume (no drive letter)
- Multiple high-frequency file write threads in the exploit process

---

### Stage 2 -- Triggering Defender

The exploit copies `wermgr.exe` from the mounted ISO into the specially named temp directory:

```
%TEMP%\RP_<UUID>\System32\wermgr.exe
```

It then creates an NTFS Alternate Data Stream on this file:

```
%TEMP%\RP_<UUID>\System32\wermgr.exe:WDFOO
```

The ADS name `WDFOO` is hardcoded and exploit-specific. It serves as the anchor point for the oplock in Stage 3.

The exploit then loads `MpClient.dll` directly (outside of normal Defender process channels) and calls:

```
MpScanStart()    -- triggers an on-demand scan of the temp directory
MpCleanStart()   -- begins the remediation / cleanup process
```

Defender detects `wermgr.exe` in the temp directory (it is an exact copy of the exploit binary, which is presumably flagged or crafted to be flagged), adds it to the remediation queue, and begins the cleanup sequence.

A `ReadDirectoryChangesW` watcher is placed on `%WINDIR%` to monitor for `Temp\TMP*` activity, confirming that Defender has started its remediation write sequence.

**Artifacts at this stage:**
- `%TEMP%\RP_<UUID>\System32\wermgr.exe` with `:WDFOO` ADS
- `MpClient.dll` loaded into exploit process
- Defender scan/clean activity in event logs

---

### Stage 3 -- Oplock Race

This is the core of the exploit. The timing sequence is:

1. The exploit requests an opportunistic lock (oplock) via `FSCTL_REQUEST_OPLOCK` on the VSS shadow copy path of the ADS stream:

   ```
   \Device\HarddiskVolumeShadowCopyN\...\wermgr.exe:WDFOO
   ```

   Using the shadow copy device path rather than the live path is a well-known technique to obtain an oplock on a file that would otherwise be rejected because Defender has it open.

2. When Defender opens that file handle as part of remediation, the oplock fires. This pauses Defender mid-cleanup -- it is blocked in a kernel wait waiting for the oplock to be broken.

3. During the oplock pause window, the exploit executes the junction swap atomically:
   a. Deletes the reparse point on `%TEMP%\RP_<UUID>\System32` (the junction).
   b. Writes the full exploit PE to a new temp file via `NtCreateFile` with `FILE_SUPERSEDE` disposition.
   c. Redirects the junction: `%TEMP%\RP_<UUID>\System32` now points to `C:\Windows`.
   d. Releases the oplock.

4. `ReadDirectoryChangesW` on `%WINDIR%` confirms Defender resumes and begins writing to `Temp\TMP*`.

The key insight: Defender's remediation writer has already resolved its destination as `%TEMP%\RP_<UUID>\System32\wermgr.exe`. The junction swap happens while Defender is paused, so when it resumes and follows that path, it now resolves to `C:\Windows\System32\wermgr.exe`.

**Artifacts at this stage:**
- FSCTL_REQUEST_OPLOCK handle on shadow copy device
- Junction `%TEMP%\RP_<UUID>\System32` -> `C:\Windows`
- Defender write activity in Sysmon EID 11 events

---

### Stage 4 -- Payload Plant

Defender resumes from the oplock and completes its remediation write. The "clean" replacement file it writes -- sourced from the locked temp file containing the exploit binary -- is written to:

```
C:\Windows\System32\wermgr.exe
```

Defender has faithfully copied the exploit payload into System32, replacing the legitimate Windows Error Reporting manager. The write succeeds because it originates from `MsMpEng.exe`, which runs as SYSTEM with `SeRestorePrivilege` and `SeTakeOwnershipPrivilege`.

The original `wermgr.exe` hash will no longer match known-good baselines. The replaced binary is the exploit payload.

**Artifacts at this stage:**
- `C:\Windows\System32\wermgr.exe` hash no longer matches Microsoft baseline
- Defender remediation completion log entries
- Sysmon EID 11: TargetFilename = C:\Windows\System32\wermgr.exe, Image = MsMpEng.exe

---

### Stage 5 -- SYSTEM Shell

The exploit triggers the `\Microsoft\Windows\Windows Error Reporting\QueueReporting` scheduled task using the Task Scheduler COM interface:

```cpp
CoCreateInstance(CLSID_TaskScheduler, ...)  // ITaskService
ITaskService->Connect(...)
ITaskService->GetFolder(L"\\Microsoft\\Windows\\Windows Error Reporting")
ITaskFolder->GetTask(L"QueueReporting")
IRegisteredTask->Run(...)
```

The QueueReporting task runs `wermgr.exe` as `NT AUTHORITY\SYSTEM`. Since `wermgr.exe` is now the exploit payload:

1. The SYSTEM instance detects it is running elevated (via `IsRunningAsLocalSystem()` check).
2. It creates the named pipe `\\.\pipe\RoguePlanet` and waits.
3. The original user-context instance connects to the pipe.
4. The SYSTEM instance calls `LaunchConsoleInSessionId()` to spawn `conhost.exe` as SYSTEM in the user's interactive logon session (Session 1).
5. The user receives a SYSTEM command prompt in their desktop session.

**Artifacts at this stage:**
- Named pipe `\\.\pipe\RoguePlanet` visible in `\\.\pipe\` enumeration
- `QueueReporting` task manually triggered (parent = `taskeng.exe` or `svchost.exe -k netsvcs`)
- `conhost.exe` child of `wermgr.exe` in process tree
- `wermgr.exe` with SYSTEM token in interactive session

---

## Unified Kill Chain Mapping

See [mappings/ukc.md](mappings/ukc.md) for the full 18-phase UKC table.

This exploit operates primarily in the **IN** and **THROUGH** macro-stages:

- **Weaponization** (IN-2): ~896 KB ISO with embedded payload compiled into the binary at build time.
- **Exploitation** (IN-5): FSCTL_REQUEST_OPLOCK on VSS shadow copy ADS stream pauses Defender mid-remediation; junction swap redirects write to C:\Windows\System32.
- **Defense Evasion** (IN-7): Payload masquerades as wermgr.exe; ADS anchor; Defender itself used as write primitive; ISO delivery avoids standard filesystem write paths.
- **Privilege Escalation** (THROUGH-11): Core outcome -- standard user to SYSTEM via Defender-as-write-primitive.
- **Execution** (THROUGH-12): WER QueueReporting task triggered via ITaskService COM for SYSTEM execution.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation | Race condition in Windows Defender remediation flow used to escalate from standard user to SYSTEM |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation / Defense Evasion | Junction swap abuses Defender's trusted write path (MsMpEng.exe SYSTEM token) to plant payload in System32 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Execution | WER QueueReporting task triggered via ITaskService COM interface for SYSTEM execution |
| T1036 | Masquerading | Defense Evasion | Exploit payload replaces and is named identically to the legitimate wermgr.exe in C:\Windows\System32 |
| T1564.004 | Hide Artifacts: NTFS File Attributes | Defense Evasion | :WDFOO alternate data stream created on wermgr.exe as the oplock anchor point for the race condition |
| T1553 | Subvert Trust Controls | Defense Evasion | ISO image mounted via VirtDisk API delivers payload outside standard filesystem write paths; Defender used as write primitive bypasses normal trust controls |
| T1559.001 | Inter-Process Communication: Component Object Model | Execution | Named pipe \\.\pipe\RoguePlanet used for intra-host callback from SYSTEM wermgr.exe instance to user-context instance; ITaskService COM used to trigger task |

Full ATT&CK Navigator layer: [mappings/mitre-layer.json](mappings/mitre-layer.json)

---

## IOCs

| Type | Value | Confidence | Context |
|---|---|---|---|
| named_pipe | `\\.\pipe\RoguePlanet` | High | Hardcoded named pipe used for user-to-SYSTEM callback. No legitimate software uses this name. |
| ads_stream | `:WDFOO` | High | Alternate data stream created on wermgr.exe as the oplock anchor. Exploit-specific name with no legitimate use. |
| directory_pattern | `%TEMP%\RP_<UUID>` | High | Working directory created in %TEMP% with RP_ prefix followed by a UUID. |
| file_path | `C:\Windows\System32\wermgr.exe` | Medium | Modified by exploit -- verify hash against Microsoft baseline. MsMpEng.exe is the writer in Sysmon logs. |
| dll_load | `MpClient.dll` (outside Defender processes) | High | Exploit loads MpClient.dll directly to invoke MpScanStart/MpCleanStart; any non-Defender process loading this DLL is anomalous. |
| scheduled_task | `\Microsoft\Windows\Windows Error Reporting\QueueReporting` | Medium | Task triggered manually by exploit for SYSTEM execution; correlate with other indicators for fidelity. |

> **Machine-readable**: See [iocs.csv](iocs.csv) for the full CSV and [stix/bundle.json](stix/bundle.json) for the STIX 2.1 bundle.

---

## Detection Guidance

### Sysmon

**Named pipe (EID 17 -- Pipe Created)**

The named pipe `\RoguePlanet` is hardcoded. This is the highest-fidelity detection and should be alerting at critical severity.

```powershell
# PowerShell: query Sysmon operational log for pipe creation
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath `
  "*[System[EventID=17] and EventData[Data[@Name='PipeName']='\RoguePlanet']]"
```

**MpClient.dll loaded outside Defender (EID 7 -- Image Load)**

```powershell
$filter = @('MsMpEng.exe','MpCmdRun.exe','SecurityHealthSystray.exe','MpCopyAccelerator.exe','NisSrv.exe')
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath `
  "*[System[EventID=7] and EventData[Data[@Name='ImageLoaded'][contains(text(),'MpClient.dll')]]]" |
  Where-Object { $filter -notcontains ($_.Properties[4].Value | Split-Path -Leaf) }
```

**wermgr.exe spawning unexpected child (EID 1 -- Process Create)**

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath `
  "*[System[EventID=1] and EventData[Data[@Name='ParentImage'][contains(text(),'wermgr.exe')]]]" |
  Where-Object { $_.Properties[5].Value -match 'cmd\.exe|powershell\.exe|pwsh\.exe|conhost\.exe' }
```

**System32\wermgr.exe written (EID 11 -- File Create)**

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath `
  "*[System[EventID=11] and EventData[Data[@Name='TargetFilename']='C:\Windows\System32\wermgr.exe']]"
```

---

### Elastic / KQL

Full queries also in [queries/elastic.kql](queries/elastic.kql).

```kql
// 1. Named pipe RoguePlanet (Sysmon EID 17)
event.code: "17" and winlog.event_data.PipeName: "\\RoguePlanet"
```

```kql
// 2. MpClient.dll loaded outside Defender processes (Sysmon EID 7)
event.code: "7"
  and winlog.event_data.ImageLoaded: *\\MpClient.dll
  and not winlog.event_data.Image: (
    *\\MsMpEng.exe
    or *\\MpCmdRun.exe
    or *\\SecurityHealthSystray.exe
    or *\\MpCopyAccelerator.exe
    or *\\NisSrv.exe
  )
```

```kql
// 3. wermgr.exe spawning shell or console (Sysmon EID 1)
event.code: "1"
  and winlog.event_data.ParentImage: *\\wermgr.exe
  and winlog.event_data.Image: (*\\cmd.exe or *\\powershell.exe or *\\pwsh.exe or *\\conhost.exe)
```

```kql
// 4. System32\wermgr.exe written by unexpected process (Sysmon EID 11)
event.code: "11"
  and winlog.event_data.TargetFilename: "C:\\Windows\\System32\\wermgr.exe"
  and not winlog.event_data.Image: (
    *\\TiWorker.exe
    or *\\TrustedInstaller.exe
    or *\\wuauclt.exe
    or *\\MsMpEng.exe
    or *\\svchost.exe
  )
```

```kql
// 5. WER QueueReporting task anomalous trigger (Sysmon EID 1)
event.code: "1"
  and winlog.event_data.Image: *\\wermgr.exe
  and not winlog.event_data.ParentImage: *\\svchost.exe
  and not winlog.event_data.CommandLine: *"/queuereporting*"
```

---

### Splunk

Full queries also in [queries/splunk.spl](queries/splunk.spl).

```spl
| search index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=17 PipeName="\\RoguePlanet"
| table _time, Computer, ProcessId, Image, PipeName
| sort -_time
```

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
  ImageLoaded="*\\MpClient.dll"
  NOT Image IN ("*\\MsMpEng.exe","*\\MpCmdRun.exe","*\\SecurityHealthSystray.exe","*\\MpCopyAccelerator.exe","*\\NisSrv.exe")
| table _time, Computer, ProcessId, Image, ImageLoaded
| sort -_time
```

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ParentImage="*\\wermgr.exe"
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\conhost.exe")
| table _time, Computer, ProcessId, Image, ParentImage, CommandLine
| sort -_time
```

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
  TargetFilename="C:\\Windows\\System32\\wermgr.exe"
  NOT Image IN ("*\\TiWorker.exe","*\\TrustedInstaller.exe","*\\wuauclt.exe","*\\MsMpEng.exe","*\\svchost.exe")
| table _time, Computer, Image, TargetFilename
| sort -_time
```

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*\\wermgr.exe"
  NOT ParentImage="*\\svchost.exe"
  NOT CommandLine="*/queuereporting*"
| table _time, Computer, ProcessId, Image, ParentImage, CommandLine, User
| sort -_time
```

---

### Microsoft Defender for Endpoint (MDE)

Full queries also in [queries/mde.kql](queries/mde.kql).

```kql
// 1. Named pipe RoguePlanet
DeviceEvents
| where ActionType == "NamedPipeEvent"
| where AdditionalFields contains "RoguePlanet"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp desc
```

```kql
// 2. MpClient.dll loaded outside Defender
DeviceImageLoadEvents
| where FileName == "MpClient.dll"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","MpCmdRun.exe","SecurityHealthSystray.exe",
                                         "MpCopyAccelerator.exe","NisSrv.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, FolderPath
| order by Timestamp desc
```

```kql
// 3. wermgr.exe spawning shell or console
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wermgr.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","conhost.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

```kql
// 4. System32\wermgr.exe written by unexpected process
DeviceFileEvents
| where FolderPath =~ @"C:\Windows\System32"
| where FileName =~ "wermgr.exe"
| where InitiatingProcessFileName !in~ ("TiWorker.exe","TrustedInstaller.exe","wuauclt.exe",
                                          "MsMpEng.exe","svchost.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName,
          FolderPath, FileName, ActionType
| order by Timestamp desc
```

```kql
// 5. WER QueueReporting task triggered by non-standard parent
DeviceProcessEvents
| where FileName =~ "wermgr.exe"
| where InitiatingProcessFileName !~ "svchost.exe"
| where ProcessCommandLine !contains "/queuereporting"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Velociraptor

**Named pipe hunt using Windows.System.Pipes**

```vql
-- Hunt for RoguePlanet named pipe across all enrolled clients
SELECT * FROM Artifact.Windows.System.Pipes()
WHERE Name =~ "RoguePlanet"
```

**Ad-hoc collection:**

```bash
# From the Velociraptor server, collect pipe information from a specific client
velociraptor -v artifacts collect Windows.System.Pipes \
  --args PipeNameRegex="RoguePlanet" \
  --client C.XXXXXXXXXXXX
```

**VQL notebook -- wermgr.exe hash check:**

```vql
-- Check whether wermgr.exe in System32 matches expected hash
LET expected_hash = "INSERT_KNOWN_GOOD_SHA256_HERE"
SELECT FullPath, Hash.SHA256, Hash.SHA256 = expected_hash AS HashMatch
FROM stat(filename="C:/Windows/System32/wermgr.exe")
LET wermgr_hash = SELECT hash(path="C:/Windows/System32/wermgr.exe", hashselect="SHA256")
SELECT * FROM wermgr_hash
WHERE Sha256 != expected_hash
```

---

### PowerShell

```powershell
# Check for RoguePlanet named pipe (live triage)
Get-ChildItem \\.\pipe\ | Where-Object Name -eq 'RoguePlanet'
```

```powershell
# Check wermgr.exe hash against Microsoft catalog
$f = 'C:\Windows\System32\wermgr.exe'
$hash = (Get-FileHash $f -Algorithm SHA256).Hash
Write-Host "SHA256: $hash"
# Compare against known-good; flag if unexpected
```

```powershell
# List any processes with MpClient.dll loaded (not from Defender)
$defenders = @('MsMpEng','MpCmdRun','SecurityHealthSystray','MpCopyAccelerator','NisSrv')
Get-Process | Where-Object { $defenders -notcontains $_.ProcessName } | ForEach-Object {
    $proc = $_
    try {
        $modules = $proc.Modules | Where-Object { $_.ModuleName -eq 'MpClient.dll' }
        if ($modules) { [PSCustomObject]@{ PID=$proc.Id; Name=$proc.ProcessName; Path=$proc.Path } }
    } catch {}
}
```

```powershell
# Check for RP_ prefixed directories in TEMP (all users)
Get-ChildItem "$env:SystemDrive\Users\*\AppData\Local\Temp" -Directory -Filter 'RP_*' -ErrorAction SilentlyContinue |
  Select-Object FullName, CreationTime, LastWriteTime
```

```powershell
# Check QueueReporting task last run time and result
$task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Error Reporting\' -TaskName 'QueueReporting'
$info = Get-ScheduledTaskInfo -TaskPath '\Microsoft\Windows\Windows Error Reporting\' -TaskName 'QueueReporting'
[PSCustomObject]@{
    TaskName     = $task.TaskName
    LastRunTime  = $info.LastRunTime
    LastResult   = $info.LastTaskResult
    NextRunTime  = $info.NextRunTime
}
```

---

## References

- [MSNightmare/RoguePlanet (GitHub)](https://github.com/MSNightmare/RoguePlanet) -- original PoC source
