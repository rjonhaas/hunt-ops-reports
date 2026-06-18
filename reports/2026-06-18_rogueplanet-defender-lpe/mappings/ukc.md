# Unified Kill Chain Mapping — RoguePlanet Windows Defender LPE

**Threat:** RoguePlanet | **Date:** 2026-06-18 | **Author:** MSNightmare (github.com/MSNightmare/RoguePlanet)

RoguePlanet is a single-host local privilege escalation exploit with no network component. It operates entirely in the **IN** (Initial Foothold) and **THROUGH** (Network Propagation) macro-stages, though "propagation" here means intra-host privilege escalation rather than network movement. The **OUT** (Action on Objectives) macro-stage is partially populated because the exploit delivers a SYSTEM shell whose follow-on impact depends on the attacker's post-exploitation actions.

Key phases: Weaponization (IN-2), Exploitation (IN-5), Defense Evasion (IN-7), Privilege Escalation (THROUGH-11), and Execution (THROUGH-12).

---

## Macro-stage: IN (Initial Foothold)

| Phase # | Phase Name | Applies | Technique / Behavior | Notes |
|---|---|---|---|---|
| IN-1 | Reconnaissance | No | N/A | No reconnaissance phase; exploit targets the local host directly. No external discovery of targets required. |
| IN-2 | Weaponization | Yes | ISO creation with embedded payload | ~896 KB ISO containing exploit binary as `wermgr.exe` built at compile time; `rawData[]` array embedded directly in source. The ISO also contains the Poseidon I/O-pressure thread logic. No external weaponization infrastructure required. |
| IN-3 | Delivery | Yes | Local execution by standard user | Requires a standard (non-admin) user to execute the exploit binary on the target system. No remote delivery component; the binary must already be present on disk (e.g., delivered via phishing, web download, or USB in a prior step). |
| IN-4 | Social Engineering | No | N/A | No social engineering within the exploit itself. Social engineering may precede delivery (out of scope for this mapping). |
| IN-5 | Exploitation | Yes | Race condition in Defender remediation flow | `FSCTL_REQUEST_OPLOCK` on VSS shadow copy device path of `:WDFOO` ADS stream pauses `MsMpEng.exe` mid-cleanup. Junction swap (`%TEMP%\RP_<UUID>\System32` → `C:\Windows`) redirects Defender's trusted write to `C:\Windows\System32\wermgr.exe`. Poseidon threads provide I/O pressure to widen race window. |
| IN-6 | Persistence | No | N/A | No persistence mechanism is established by the exploit itself. The payload planted in `C:\Windows\System32\wermgr.exe` survives reboot but is removed by patching or manual remediation. Attacker may establish persistence post-exploitation (out of scope). |
| IN-7 | Defense Evasion | Yes | Masquerade + ADS + junction manipulation + Defender-as-write-primitive | Four layered evasion techniques: (1) payload disguised as the legitimate `wermgr.exe`; (2) `:WDFOO` ADS used as oplock anchor (unusual stream name, minimal tooling detects it); (3) ISO mounted without drive letter hides it from trivial enumeration; (4) Defender itself (`MsMpEng.exe`) performs the write to System32, giving it the imprimatur of a trusted system process. |
| IN-8 | Command & Control | Partial | Local named pipe only | `\\.\pipe\RoguePlanet` is used for intra-host callback from the SYSTEM `wermgr.exe` instance to the user-context instance. No network C2 channel. Not C2 in the traditional sense, but matches the UKC definition of a control channel enabling the attacker to interact with the compromised context. |

---

## Macro-stage: THROUGH (Network Propagation)

| Phase # | Phase Name | Applies | Technique / Behavior | Notes |
|---|---|---|---|---|
| THROUGH-9 | Pivoting | No | N/A | Single-host exploit. No lateral movement to other hosts as part of the exploit chain. |
| THROUGH-10 | Discovery | Partial | Windows Defender install path + VSS device enumeration | Reads `HKLM\SOFTWARE\Microsoft\Windows Defender` to locate `MpClient.dll` and Defender installation path. Enumerates `\Device\` object directory for `HarddiskVolumeShadowCopy*` devices to identify a VSS shadow copy device path suitable for the oplock. `ReadDirectoryChangesW` on `%WINDIR%` monitors for Defender remediation activity (`Temp\TMP*`). |
| THROUGH-11 | Privilege Escalation | Yes | Standard user -> NT AUTHORITY\SYSTEM | Core exploit outcome. Standard user (no admin, no special privileges) escalates to SYSTEM via the Defender write-primitive race condition. `MsMpEng.exe` (SYSTEM, `SeRestorePrivilege`) is the actual write handle. |
| THROUGH-12 | Execution | Yes | WER QueueReporting scheduled task via COM | `ITaskService` COM interface used to trigger `\Microsoft\Windows\Windows Error Reporting\QueueReporting` task. Task executes `C:\Windows\System32\wermgr.exe` (now the payload) as `NT AUTHORITY\SYSTEM`. SYSTEM instance creates named pipe, calls `LaunchConsoleInSessionId()` to spawn `conhost.exe` in user's interactive session (Session 1). |
| THROUGH-13 | Credential Access | No | N/A | No credential harvesting within the exploit chain. Attacker receives a SYSTEM shell; credential access (e.g., LSASS dump) would be a post-exploitation action. |
| THROUGH-14 | Lateral Movement | No | N/A | No lateral movement within the exploit chain. SYSTEM access on the local host is the terminal objective of this tool. |

---

## Macro-stage: OUT (Action on Objectives)

| Phase # | Phase Name | Applies | Technique / Behavior | Notes |
|---|---|---|---|---|
| OUT-15 | Collection | No | N/A | No data collection within the exploit chain itself. |
| OUT-16 | Exfiltration | No | N/A | No exfiltration within the exploit chain itself. |
| OUT-17 | Impact | Partial | Depends on post-exploitation | Exploit delivers an interactive SYSTEM shell in the user's desktop session. Impact depends on attacker follow-on actions: ransomware deployment, credential theft, persistence installation, etc. The exploit itself does not destructively modify the system beyond replacing `wermgr.exe` in System32. |
| OUT-18 | Objectives | Partial | Privilege escalation as stepping-stone | Exploit's stated objective is SYSTEM access, typically used as a stepping-stone to further compromise (persistence, credential access, lateral movement). The objective is fully achieved when `conhost.exe` spawns under the SYSTEM token in the user's interactive session. |

---

## Coverage Summary

- **Dominant macro-stage:** IN and THROUGH (the exploit is entirely local; OUT depends on post-exploitation)
- **Key phases:** IN-2 (Weaponization), IN-5 (Exploitation), IN-7 (Defense Evasion), THROUGH-11 (Privilege Escalation), THROUGH-12 (Execution)
- **Gaps (not observed):** IN-1 (Reconnaissance), IN-4 (Social Engineering), IN-6 (Persistence), THROUGH-9 (Pivoting), THROUGH-13 (Credential Access), THROUGH-14 (Lateral Movement), OUT-15 (Collection), OUT-16 (Exfiltration) -- none of these phases are part of the exploit chain itself
