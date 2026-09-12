# Project Summary

A running summary of what has been set up in this repo and where things stand.

_Last updated: 2026-09-12_

---

## What this project is

A hands-on **Windows & Active Directory security lab** built to develop SOC analyst
competency. The environment is two VirtualBox VMs on an isolated network; the work is a
series of project modules that each follow a **Build → Break/Observe → Detect** loop,
documented on GitHub as a portfolio.

**Lab environment**
- **DC01** — Windows Server 2022, Domain Controller + DNS, `10.0.0.10`, domain `corp.local`
- **WS01** — Windows 11 Enterprise, domain member, `10.0.0.20`, DNS → DC01
- **Network** — private VirtualBox internal network `lab-net` (no internet, by design)
- **Host** — VirtualBox 7.x on a Windows host

**Build status (2026-08-09):** ✅ **Environment live.** Both VMs built and addressed,
`corp.local` forest created on DC01, WS01 joined and verified. Snapshots on both:
`00-clean-install` (pre-domain) and `01-domain-ready` (the baseline every module
starts from).

---

## Files created

| File | Purpose |
|------|---------|
| `README.md` | Repo landing page — topology diagram, module index with status, repo layout, GitHub push-safety warnings |
| `SOC-Analyst-Roadmap.md` | The full 12-module plan across Windows Administration (Part I) and Active Directory (Part II), plus a mini-SIEM cross-cutting module and an 8-week pacing table |
| `labs/00-lab-build.md` | **Module 00** — VM creation, Windows installs, `lab-net` setup, DC promotion and domain join, with troubleshooting |
| `labs/01-users-and-groups.md` | **Module 01, fully expanded** — the reference implementation every other lab follows |
| `labs/03-windows-registry.md` | **Module 03, complete** — registry persistence, native 4657 vs Sysmon 13; written 2026-09-10, run 2026-09-10 → 2026-09-12, corrected from the run, two findings |
| `labs/04-event-viewer-logging-model.md` | **Module 04, expanded** — the tooling module; written 2026-08-24, not yet run |
| `templates/module-lab-template.md` | Reusable skeleton to keep every module structured identically |
| `.gitignore` | Excludes VM disk images, ISOs, exported logs, and secrets from GitHub |
| `assets/` | Folder for screenshots / evidence referenced by the labs |
| `summary.md` | This file |

---

## The roadmap at a glance

### Part 0 — Environment
| # | Module | Core Event IDs | Status |
|---|--------|----------------|--------|
| 00 | Lab Build | (environment) | ✅ Complete |

### Part I — Windows Administration
| # | Module | Core Event IDs | Status |
|---|--------|----------------|--------|
| 01 | Users & Groups | 4720, 4728, 4624, 4625, 4740, 4771 | ✅ Complete |
| 02 | NTFS Permissions & File Auditing | 4663, 4656, 4670, 4907 | ✅ Complete |
| 03 | The Windows Registry & Persistence | 4657, Sysmon 12/13/14 | ✅ Complete |
| 04 | Event Viewer & the Logging Model | 1102, 104, 4719, 4688 | ✅ Complete |
| 05 | PowerShell for Defenders | 4104, 4103, 4688 | ✅ Complete |
| 06 | Windows Firewall | 5156, 5157, 4946 | ⬜ Planned |
| 07 | Remote Desktop (RDP) | 4624·T10, 1149, 21/25 | ⬜ Planned |

### Part II — Active Directory
| # | Module | Core Event IDs | Status |
|---|--------|----------------|--------|
| 08 | Domains, Forests & DCs | (concepts) | ⬜ Planned |
| 09 | OUs & Delegation | 5136, 4662, 5141 | ⬜ Planned |
| 10 | Group Policy (GPO) | 5136, 4739, 5145 | ⬜ Planned |
| 11 | DNS | 256/257 | ⬜ Planned |
| 12 | Kerberos & LDAP (capstone) | 4768, 4769, 4771, 4662 | ⬜ Planned |

### Cross-cutting
| Module | Focus |
|--------|-------|
| Mini-SIEM | Windows Event Forwarding → optional Elastic/Splunk/Wazuh |

---

## Module 01 — what's in it

The completed reference lab covers, end to end:
- Creating local (WS01) and domain (DC01) users and groups from PowerShell
- SID vs. name (and why the RID — `500`, `512` — matters)
- The high-value built-in groups attackers target
- A simulated "create backdoor admin → escalate to Domain Admins" sequence, with cleanup
- A simulated logon brute force (failed → successful)
- Working `Get-WinEvent` hunt queries for account creation, privileged-group changes,
  and the brute-force-that-worked pattern
- An evidence checklist and MITRE ATT&CK mapping (T1136.002, T1098, T1078.002, T1110.001)

---

## Standard module structure

Every lab (via the template) is laid out identically:
1. Objective & SOC relevance
2. Pre-flight (snapshot, expected VM state)
3. Build (the admin task, exact commands)
4. Break / Observe (generate telemetry)
5. Detect (`Get-WinEvent` queries + Event ID reference)
6. Evidence (what to screenshot for the portfolio)
7. MITRE ATT&CK mapping

---

## Current status

- ✅ Repo scaffolding, README, roadmap, template, and `.gitignore` in place
- ✅ **Module 00 complete** — DC01 and WS01 built on `lab-net`, `corp.local` forest created,
  WS01 joined, both snapshotted at `00-clean-install` and `01-domain-ready`
- ✅ **Module 01 complete** — rewritten as a step-by-step run sheet, executed end to end
  on the lab, and corrected from what the run exposed. Two findings written up.
- ✅ **Module 04 complete** — run across three sittings, built around one skill: telling
  "nothing happened" apart from "I can't see it." Two findings from real telemetry:
  Finding 1 (evidence loss by volume, `oldestRecordNumber` 1→8378) and Finding 2 (log
  clearing, 1102 in Security + 104 in System). The run also corrected Module 01
  (filter-first, DN vs name, and the eight-hour Pacific/WAT timezone gap — findings
  restated in UTC, Finding 2 closed)
- ✅ **Module 05 complete** (2026-09-03). Steps 0–3 run as a ladder — the pipeline built one
  verb at a time (`Get-Process | Where-Object | Sort-Object | Select-Object`), `Get-Member`
  for discovering properties, `-FilterHashtable` assembled from scratch, fields pulled by
  name (`NewProcessName`, `CommandLine`, `SubjectUserName` confirmed on 4688). **Step 4
  (triage.ps1) abandoned** (Notepad/shell working-directory mismatch). **Steps 5–6 run:**
  benign `powershell.exe -EncodedCommand` (plain + `-WindowStyle Hidden`, three runs) →
  **4688** carried the encoded command line and **4104** the decoded payload for the *same*
  execution at **07:53:27 UTC** — a matched pair. 4104 alone logged both the obfuscated
  invocation and the decoded script. Logging enabled by **registry**, not `gpedit.msc`
- ✅ **Module 02 (NTFS Permissions & File Auditing) complete** (run 2026-09-05 → 2026-09-08,
  WS01). `C:\Finance` locked to a `Finance` group and both halves of the access evidence
  captured: **4663 Audit Success** for `WS01\fin_user` against `C:\Finance` at **14:53:46
  UTC on 2026-09-05** (`AccessMask 0x1`, via `notepad.exe`), and **4656 Audit Failure** for
  `WS01\helpdesk` against `C:\Finance\selftext.txt` at **22:40:21 UTC** the same day. The
  denial is a **4656, not a 4663** — 4663 only fires on access that *succeeded*.

  **Finding 2 is the module's real result, and it outgrew the plan:** object-access
  auditing is gated at **four independent layers**, and three of them silently swallowed an
  expected event on this host.

  | # | Gate | Symptom when closed |
  |---|---|---|
  | 1 | `File System` subcategory | no 4663 |
  | 2 | `Handle Manipulation` subcategory | no **4656** — denials vanish entirely |
  | 3 | `Authorization Policy Change` subcategory | no **4670** |
  | 4 | The SACL's **audited rights** (`WRITE_DAC`) | still no **4670**, with all three subcategories reading "Success and Failure" |

  Gates 2 and 3 are off by default on a stock Windows 11 install. Gate 4 is the subtle one
  and the best evidence in the repo: the **4907 at 15:52:46 UTC on 2026-09-07** shows the
  audited-rights mask gaining exactly one token — `WD` (`WRITE_DAC`) —
  `CCDCLCSWRPWPLOCRRC` → `CCDCLCSWRPWPLOCRRCWD`, nothing else changed. Twelve seconds
  later the first **4670** appears (`CORP\Administrator` via `icacls.exe`, 15:52:58 and
  15:53:02 UTC), its descriptors showing `(A;;FR;;;BG)` — the `Guests` read ACE — present
  before and gone after. Identical commands, only the SACL differed.

  Two further results worth carrying: the Step 3 lock-down **could never have logged**,
  because auditing ran after it and auditing is not retroactive; and the first SACL apply
  on 2026-09-05 wrote **no 4907**, which — since a committed SACL change always writes one,
  and the log had not rotated (7 MB of 20 MB) — is positive evidence it *never committed*
  rather than committing and being reverted. Absence used as evidence, the mirror of
  Module 04's Finding 1.

  Three snags fixed along the way and folded into the run sheet: a **second** broad
  inherited ACE (`Authenticated Users:(OI)(CI)(M)`) kept `helpdesk` writable after `Users`
  was removed (`icacls /remove:g`); the SACL didn't persist on first apply; and Step 5's
  `runas ... notepad` was replaced with `runas /user:<u> powershell` plus explicit
  `Out-File`/`Get-Content`, because Notepad silently redirects a blocked save and leaves no
  evidence the folder was touched. Lab file rewritten throughout — Step 3 callout, Step 4.1
  four-gate table, Step 4.2 `Change permissions`, Steps 6.3/6.4, event-ID table, evidence
  checklist, gotchas — plus **two findings** in observation → inference → recommendation
  form. **Eight screenshots** in `assets/` (`02-*`).
- ✅ **Module 03 (The Windows Registry & Persistence) complete** — written 2026-09-10, run
  2026-09-10 → 2026-09-12 on WS01 across two sittings.

  **The module's thesis proved itself inside a single eight-minute window.** Three identical
  `notepad.exe` persistence writes, one host, both instruments configured and running:

  | UTC (2026-09-12) | Value | Key | Tool |
  |---|---|---|---|
  | 21:00:22.880 | `LabPersist` | `HKLM\…\Run` | `reg.exe` |
  | 21:06:25.500 | `LabPersistUser` | `HKU\S-1-5-21-…-500\…\Run` | `powershell.exe`, **no elevation** |
  | 21:08:15.088 | `LabPersistOnce` | `HKLM\…\RunOnce` | `reg.exe` |

  **Native 4657 returned one of the three. Sysmon Event 13 returned all three.**

  **Finding 2** is the result, and the negative half carries its own control: the 4657 query
  that failed to return two of the writes *did* return the third — same command, same window,
  same log, same host — so the four standard causes of empty `Get-WinEvent` output (wrong
  machine, narrow window, rotation, channel off) are excluded by the query's own positive
  result. That makes it a **coverage** failure, not a configuration failure. Native auditing
  worked perfectly for the one key it was pointed at; `HKCU\…\Run` and `HKLM\…\RunOnce` had
  no SACL, so those writes were never auditable events at all. The two misses include the only
  write needing **no privileges** and the only one that **self-deletes**. The generalisation:
  native registry auditing can only report on keys someone anticipated in advance, so it is
  structurally unable to surface a persistence location nobody thought to watch.

  **Finding 1 came out stronger than the plan called for.** Sysmon **Event 1** recorded
  `reg.exe` at **21:08:15.025 UTC — 63 milliseconds before** the Event 13 it caused — carrying
  the full `CommandLine`, `ParentImage` (`powershell.exe`), `User` (`CORP\Administrator`),
  `IntegrityLevel` (`High`), `LogonId` and a SHA256. "A registry value changed" became "this
  account, from an elevated PowerShell, ran this exact command and this is what it changed,"
  joinable on `ProcessGuid`. The execution half was deliberately **not** claimed: a candidate
  `Notepad.exe` exists at 21:04:16 UTC, a minute after a reboot and consistent in timing with a
  `Run`-key firing, but its `ParentImage` was empty, so nothing ties it to the logon. Recorded
  as suggestive timing, not as a link in the chain.

  **Four corrections the run forced into the lab file** — each one had been asserted wrongly or
  incompletely beforehand:

  - **Sysmon logs the per-user hive as `HKU\<SID>\…`, never `HKCU\`.** The exact mirror of
    4657's `\REGISTRY\MACHINE\…`. Neither log prints the shorthand you type, so a hunt string
    built from either returns nothing with no error to explain why.
  - **A deleted *value* is an Event 12 with `EventType = DeleteValue`, not an Event 13.** A
    13-only rule watches the attacker arrive and never leave.
  - **Sysmon's bare-install defaults log no registry events whatever** — measured at 30 records
    across IDs 1/4/5/16 only. The config *adds* registry visibility; it does not trim a flood.
    "Sysmon is installed" and "Sysmon would have caught that" are different claims.
  - **`Details` preserves case exactly as typed** (`notepad.exe` and `Notepad.exe` both appeared
    in one session), so value-data hunts must be case-insensitive.

  **Two things observed and recorded honestly as unexplained, neither promoted to a finding:**
  `sihost.exe` writes a matching `…\RunNotification\StartupTNoti<name>` entry for every `Run`
  value and deletes it when the value goes — none for `RunOnce` — on a **variable** delay (10 s
  and 2m36s in the same session) with a DWORD payload of unknown meaning; and `ParentImage`
  comes back **empty** for Store-packaged applications, which means parent-process correlation
  cannot be assumed available and needs a fallback.

  The **2026-09-10 anomaly stays parked** — the first two `reg add` writes produced no 4657, no
  cause established, and its discriminating test still needs a clean pre-write snapshot that
  does not exist.

  **Sysmon v15.15 is left installed and configured on WS01** (schema 4.90, four-rule
  `RegistryEvent onmatch="include"` config at `C:\Tools\sysmon-registry.xml`). Modules 06 and
  07 inherit it.

  **A wider three-hour 4657 query sharpened Finding 2 further.** It returned exactly five
  value names — `LabPersist` twice, plus `LabPersistRegNow`, `LabPersistPS` and
  `LabPersistBoot` — **every one of them a write to the single SACL'd key**, spanning both
  creation and deletion. Across the same window the two unwatched keys saw five operations
  (`LabPersistUser` deleted, re-planted and deleted; `LabPersistOnce` planted and deleted) and
  produced **no 4657 at all**. So the absence is selective *by key* inside one successful
  query, and the instrument demonstrably covers a value's full lifecycle — it simply never saw
  the other two keys.

  **Evidence: six PNGs in `assets/` (`03-*`)** — the Sysmon config readback, the all-three
  Event 13 output, the five-event 4657 result, the `DeleteValue` paths, the Event 1
  command-line dump, and the blank `ParentImage` shot. Note that two carry this host's
  **unredacted machine SID**; a deliberate call for a throwaway isolated VM, not a pattern to
  repeat.
- ⬜ Modules 06–12 planned but not yet expanded
- ✅ Git repository pushed to `github.com/Simplyaeon/windows-ad-soc-lab` — `main` is
  current through Module 05, evidence included
- ✅ Module 01 evidence in `assets/` (six PNGs, spaceless `01-*` scheme); Finding 2 closed
- ✅ Module 04 evidence complete: eight PNGs in `assets/`, all three custom views built and
  exported to `assets/xml/` (the reusable deliverable)
- ✅ Eval-licence issue resolved — both VMs rearmed. `mod04-start` snapshot **taken**
  (2026-09-04); `mod02-start` is the pre-run baseline for Module 02.

### Open blockers on WS01 (found during the Module 05 run; status as of 2026-09-03)

Three things on this host misbehaved. None block the detection content, but they cost most
of a sitting and are worth fixing or routing around:

- **`gpupdate` is "not recognized as a cmdlet."** So is the GUI path via `gpedit.msc` for
  applying policy. Worked around by setting both Module 05 features directly in the
  registry (`EnableScriptBlockLogging`, `ProcessCreationIncludeCmdLine_Enabled`), which
  applies immediately and is now what the lab documents. Suggests a broken System32/PATH
  or policy-engine state.
- **4688's `CommandLine` field ✅ RESOLVED (2026-09-03).** It was blank in the 2026-09-02
  session but populated on encoded runs the next day (`powershell.exe -EncodedCommand VwBy…`
  at 07:52–07:53 UTC). The field populates only for processes *created after*
  `ProcessCreationIncludeCmdLine_Enabled` takes effect — the earlier blanks were pre-setting
  processes, not a fault (`auditpol` reported Success throughout). Both detection angles now
  work.
- **`triage.ps1` never produced output when run as a file**, although every query inside
  it returns correct results when pasted into the terminal (2,462 events; extraction and
  `Group-Object` both verified by hand). Most likely Notepad and the shell pointing at
  different working directories — `notepad $PWD\triage.ps1` avoids it. Abandoned rather
  than debugged further, since the queries themselves were already proven.

**Verified along the way:** both `$_.InnerText` and `Select-Object -ExpandProperty '#text'`
correctly return event field values on this host, so the `'#text'` accessor taught in
Modules 01/04/05 is sound and needs no change.

---

## Next steps

1. **Optionally reconstruct the first sitting's three screenshots** (`auditpol`, the SACL
   Auditing tab with Set Value ticked, a 4657 detail pane showing `OldValue`/`NewValue`), which
   were never captured. Module 03 is otherwise complete.
2. **Module 06 (Windows Firewall)** or **07 (RDP)** next — both benefit from Sysmon already
   being installed and configured on WS01, which was the main reason Module 03 came first.
3. **Optionally settle the anomaly** with the fresh-SACL test described above. It needs a clean
   baseline snapshot, which does not currently exist.
4. **Consider rebuilding WS01** if the `gpupdate`/`gpedit` blockers keep costing time. The cost
   has risen again: Module 02's audit config, Module 03's `Registry` subcategory + Run-key SACL,
   and now the **completed** Sysmon install and config would all need redoing.
5. **Module 12 (Kerberos capstone)** remains the standout portfolio artifact.
6. Keep the **Progress log** in `README.md` and the status tables here updated as modules complete.
