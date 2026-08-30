# Project Summary

A running summary of what has been set up in this repo and where things stand.

_Last updated: 2026-08-30_

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
| 02 | NTFS Permissions & File Auditing | 4663, 4670, 4907 | ⬜ Planned |
| 03 | Windows Registry | Sysmon 13, 4657 | ⬜ Planned |
| 04 | Event Viewer & the Logging Model | 1102, 104, 4719, 4688 | ✅ Complete |
| 05 | PowerShell for Defenders | 4104, 4103, 4688 | ⬜ Planned |
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
- ⬜ Modules 02, 03, 05–12 planned but not yet expanded
- ✅ Git repository initialized; remote is `github.com/Simplyaeon/windows-ad-soc-lab`
  (nothing pushed yet beyond the initial commit)
- ✅ Module 01 evidence in `assets/` (six PNGs, spaceless `01-*` scheme); Finding 2 closed
- ⬜ Module 04 screenshots not yet in `assets/`; custom Views 1 and 3 not built
- ⚠️ Both VMs' evaluation licences expired and shut down hourly. WS01's rearm is not yet
  clearing (still in Notification mode); DC01 not yet rearmed. `mod04-start` should not be
  snapshotted until the licence state is healthy, or the snapshot freezes the expiry

---

## Next steps

1. **Sort the eval licences.** `slmgr /rearm` + full reboot on both VMs (WS01 needs the
   reboot to actually take effect), confirm with `slmgr /xpr`, *then* snapshot `mod04-start`.
2. **Finish Module 04 housekeeping** — six Module 04 screenshots into `assets/`, build
   custom Views 1 and 3, export the custom-view XMLs (the portfolio deliverable).
3. **Expand Module 05 (PowerShell for Defenders)** next. Half of it is already in hand from
   the Module 04 run — `-FilterHashtable`/`-FilterXPath`, field-by-name extraction, reading
   `.evtx` — so it consolidates rather than introduces.
4. **Then 02 and 03**, which add new detection surfaces but block nothing. Module 03
   needs Sysmon; the Sysinternals Suite is already on the lab host, so it only has to
   be moved into the VMs via shared folder or attached ISO.
5. **Module 12 (Kerberos capstone)** remains the standout portfolio artifact.
6. Keep the **Progress log** in `README.md` and the status tables here updated as modules
   are completed.
