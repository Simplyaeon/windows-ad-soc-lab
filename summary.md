# Project Summary

A running summary of what has been set up in this repo and where things stand.

_Last updated: 2026-09-08_

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
| 03 | Windows Registry | Sysmon 13, 4657 | ⬜ Planned |
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
- ⬜ Modules 03, 06–12 planned but not yet expanded
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

1. **Commit and push Module 02.** Lab file, two findings, eight `02-*` screenshots, plus
   the README and `summary.md` status updates. Screenshots show `WS01`, `corp.local` and
   the lab account names — consistent with what the `01-*` and `04-*` shots already
   publish, so nothing new is exposed. `main` will then be current through Module 05 *and*
   Module 02.
2. **Module 03 (Windows Registry)** is the natural next build — it adds a new detection
   surface and blocks nothing. It needs **Sysmon** moved into the VMs; the Sysinternals
   Suite is already on the lab host, so it only has to travel via shared folder or an
   attached ISO. Registry auditing has the same SACL-plus-subcategory shape Module 02 just
   taught, so the four-gate lesson transfers directly to 4657.
3. **Consider rebuilding WS01** from a fresh Windows 11 Enterprise eval ISO if the
   `gpupdate`/`gpedit` blockers keep costing time. A rebuild resets the eval clock too.
   Module 05's Steps 0–3 would need re-running, but they're quick now that they're
   known-good. Note that Module 02's audit configuration (three subcategories plus the
   `C:\Finance` SACL) would also have to be redone.
4. **Module 12 (Kerberos capstone)** remains the standout portfolio artifact.
5. Keep the **Progress log** in `README.md` and the status tables here updated as modules
   are completed.
