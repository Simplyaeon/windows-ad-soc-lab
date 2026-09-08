# Windows & Active Directory Security Lab

A hands-on lab environment and project journal built to develop **SOC analyst**
competency in Windows administration and Active Directory — and, more importantly,
in the **detection** of attacker activity against them.

Every module follows the same loop: **Build** an administrative capability →
**Break/Observe** by generating realistic activity → **Detect** it in the logs.
The detection step is the point; the rest exists to produce something worth finding.

---

## Lab topology

```
        ┌─────────────────────────┐         lab-net          ┌─────────────────────────┐
        │  DC01                    │      (internal net)      │  WS01                    │
        │  Windows Server 2022     │◄────────────────────────►│  Windows 11 Enterprise   │
        │  Domain Controller · DNS │                          │  Domain member           │
        │  10.0.0.10 · corp.local  │                          │  10.0.0.20 · DNS → DC01  │
        └─────────────────────────┘                          └─────────────────────────┘
```

- **Hypervisor:** VirtualBox 7.x on a Windows host
- **Isolation:** private `internal network` named `lab-net` — no internet, by design
- **Domain:** `corp.local` (NetBIOS `CORP`)

Build instructions for the environment itself are in
[Module 00 — Lab Build](./labs/00-lab-build.md); the roadmap that this repo works
through is [`SOC-Analyst-Roadmap.md`](./SOC-Analyst-Roadmap.md).

---

## Module index

### Part 0 — Environment
| # | Module | Core Event IDs | Status |
|---|--------|----------------|--------|
| 00 | [Lab Build](./labs/00-lab-build.md) | (environment) | ✅ Complete |

### Part I — Windows Administration
| # | Module | Core Event IDs | Status |
|---|--------|----------------|--------|
| 01 | [Users & Groups](./labs/01-users-and-groups.md) | 4720, 4728, 4624, 4625, 4740, 4771 | ✅ Complete |
| 02 | [NTFS Permissions & File Auditing](./labs/02-ntfs-permissions.md) | 4663, 4656, 4670, 4907 | ✅ Complete |
| 03 | Windows Registry | Sysmon 13, 4657 | ⚪ Planned |
| 04 | [Event Viewer & the Logging Model](./labs/04-event-viewer-logging-model.md) | 1102, 104, 4719, 4688 | ✅ Complete |
| 05 | [PowerShell for Defenders](./labs/05-powershell-for-defenders.md) | 4104, 4103, 4688 | ✅ Complete |
| 06 | Windows Firewall | 5156, 5157, 4946 | ⚪ Planned |
| 07 | Remote Desktop (RDP) | 4624·T10, 1149, 21/25 | ⚪ Planned |

### Part II — Active Directory
| # | Module | Core Event IDs | Status |
|---|--------|----------------|--------|
| 08 | Domains, Forests & DCs | (concepts) | ⚪ Planned |
| 09 | OUs & Delegation | 5136, 4662, 5141 | ⚪ Planned |
| 10 | Group Policy (GPO) | 5136, 4739, 5145 | ⚪ Planned |
| 11 | DNS | 256/257 | ⚪ Planned |
| 12 | Kerberos & LDAP (capstone) | 4768, 4769, 4771, 4662 | ⚪ Planned |

### Cross-cutting
| Module | Focus |
|--------|-------|
| Mini-SIEM | Windows Event Forwarding → optional Elastic/Splunk/Wazuh |

---

## Repo layout

```
.
├── README.md                     # you are here
├── SOC-Analyst-Roadmap.md        # the full 12-module plan
├── labs/                         # one file per module — the write-ups
│   ├── 00-lab-build.md           # VM + domain build — start here
│   ├── 01-users-and-groups.md
│   ├── 02-ntfs-permissions.md
│   ├── 04-event-viewer-logging-model.md
│   └── 05-powershell-for-defenders.md
├── templates/
│   └── module-lab-template.md    # copy this to start a new module
├── assets/                       # screenshots / evidence referenced by the labs
│   └── xml/                      # exported Event Viewer custom views (Import Custom View)
```

---

## How to read a module

Each lab file is self-contained and structured identically:

1. **Objective & SOC relevance** — why this matters on the job
2. **Pre-flight** — snapshot to take, VM state expected
3. **Build** — the admin task, with exact commands
4. **Break / Observe** — generate the telemetry
5. **Detect** — find it, with `Get-WinEvent` queries and an Event ID reference
6. **Evidence** — what to screenshot for the portfolio
7. **MITRE ATT&CK mapping** — the technique IDs this covers

---

## If you publish this to GitHub

This is a **defensive learning lab**, but treat the repo as public:

- **Never commit real credentials.** Lab passwords like `Lab-Passw0rd!` are fine as
  documentation of a throwaway environment; never reuse them anywhere real.
- The `.gitignore` excludes VM disk images, ISOs, and exported logs — don't force-add
  them (they're huge and may contain host data).
- Screenshots may leak host machine names, IPs, or usernames. Crop or redact.
- Techniques appear **only** to produce and explain their detections, inside an
  isolated network — keep that framing so the repo reads clearly as defensive work.

---

## Progress log

| Date | Module | Notes |
|------|--------|-------|
| 2026-08-02 | 00 — Lab Build (Part 1) | DC01 + WS01 built on `lab-net`, static IPs assigned, connectivity verified by ping. `00-clean-install` snapshots taken on both. |
| 2026-08-09 | 00 — Lab Build (Part 2) | DC01 promoted to `corp.local` forest (NetBIOS `CORP`, DNS installed). WS01 joined and verified. `01-domain-ready` snapshots taken. **Module 00 complete.** |
| 2026-08-09 | 01 — Users & Groups | 🟡 In progress. Lab rewritten as a step-by-step run sheet; audit-policy setup added (Module 00 never enabled it) and the brute-force step changed from `net use` to login-screen attempts + a lockout policy. |
| 2026-08-15 | 01 — Users & Groups | Steps 0–4 executed. Auditing enabled on DC01 + WS01, `mod01-start` snapshots taken. Local `helpdesk` created on WS01, domain `asmith` created on DC01, Domain Admins baselined (`Administrator` only). |
| 2026-08-22 | 01 — Users & Groups | ✅ **Complete.** Steps 5–9 executed: backdoor admin created and escalated (4720 + 4728, 55s apart), lockout policy applied, five failed logons driving 4771/4740, cleanup verified (Domain Admins back to `Administrator` only). Two findings written up in observation → inference → recommendation form. Lab file corrected from the run: 4728 `Member` is a SID not a name, `Get-WinEvent` windows widened, troubleshooting expanded (wrong machine, `-MaxEvents` starvation, 4771 pre-auth type vs logon type, `ANONYMOUS LOGON` baseline). **Outstanding:** four evidence screenshots not yet copied into `assets/`; Finding 2's 4767/4723/4724 pivot not yet pulled. |
| 2026-08-24 | 04 — Event Viewer & Logging Model | 🟡 Written. Six steps, mostly Event Viewer clicks: the log tree and which VM writes what, an event's General vs XML view, building filters by clicking and saving custom views, measuring real log retention, then destroying evidence two ways. Built around one skill: telling "nothing happened" apart from "I can't see it." |
| 2026-08-31 | 05 — PowerShell for Defenders | 🟡 Written, not yet run. Built as a ladder — the pipeline taught one stage at a time (`Get-Process` → `Where-Object` → `Select-Object` → `Sort-Object`), then `Get-WinEvent -FilterHashtable` and field-by-name extraction assembled from parts, ending in a `triage.ps1` the reader writes themselves. Security half: run a benign base64 `-EncodedCommand` (and `-WindowStyle Hidden`), then watch **4104** Script Block Logging record the *decoded* script while **4688** shows the encoded command line — the two-angle lesson. Enables Script Block Logging and command-line-in-4688 via `gpedit.msc`. |
| 2026-08-30 | 04 — Event Viewer & Logging Model | ✅ **Complete.** Run across three sittings. Findings written from real telemetry: **Finding 1** — evidence loss by volume (the Security log refused to shrink on this host, so ~27,800 `cmd.exe` 4688s pushed `oldestRecordNumber` 1→8378, rolling the 16 Aug 4625 sequence off; live 4625 count 4 vs export 14). **Finding 2** — `Administrator` cleared Security (1102, self-written) at 10:00:51 UTC and Application (104, landing in System). The run also corrected Module 01: filter-first-not-starved (1 vs 11), 4728's member field is a DN, and both VMs were eight hours out on the Windows install-default Pacific timezone — findings restated in UTC, Module 01 Finding 2 closed. |
| 2026-09-03 | 05 — PowerShell for Defenders | ✅ **Complete.** Steps 0–3 run as a ladder (pipeline built one verb at a time, `-FilterHashtable` and field-by-name extraction assembled from parts). Step 4 `triage.ps1` abandoned (Notepad/shell working-directory mismatch). Steps 5–6 run: benign `powershell.exe -EncodedCommand` (plain + `-WindowStyle Hidden`), then **4104** Script Block Logging recovered the *decoded* payload and **4688** the encoded command line for the *same* execution at **07:53:27 UTC** — a matched pair (4104 alone logged both the obfuscated invocation and the decoded script), resolving the prior blank-`CommandLine` blocker (the field populates only for processes created after `ProcessCreationIncludeCmdLine` takes effect). Finding written in observation → inference → recommendation form. Logging enabled by **registry**, not `gpedit.msc` (`gpupdate`/`gpedit` broken on this host). |
| 2026-09-04 | 02 — NTFS Permissions & File Auditing | 🟡 Written, not yet run. WS01-only run sheet built around one idea: **the lock (DACL) and the camera (SACL) are separate switches** — a folder can be locked and log nothing. Lock `C:\Finance` to a Finance group (GUI-first, `icacls`/`Get-Acl` to read), test a denied user, enable File System auditing + a SACL, then read **4663** (Success vs Failure via Keywords), **4670** (permission change) and **4907** (audit-setting change). Extends the Module 04 "nothing happened vs can't see it" lesson to the file level. |
| 2026-09-08 | 02 — NTFS Permissions & File Auditing | ✅ **Complete.** `C:\Finance` locked to a `Finance` group and both halves of the evidence captured: **4663 Audit Success** for `fin_user` (14:53:46 UTC, 2026-09-05) and **4656 Audit Failure** for `helpdesk` (22:40:21 UTC) — the denial is a 4656, not a 4663, because 4663 only fires on access that *succeeded*. The module's real result is **Finding 2**: object-access auditing is gated at **four independent layers**, and three of them silently swallowed an expected event on this host — `Handle Manipulation` off (no 4656), `Authorization Policy Change` off (no 4670), and the SACL not auditing `WRITE_DAC` (still no 4670, with every subcategory reading "Success and Failure"). The 4907 at 15:52:46 UTC proves the last one in its own descriptors: the audited-rights mask gains exactly `WD` and a 4670 appears twelve seconds later. Also established that the Step 3 lock-down could never have logged — auditing is not retroactive — and that the first SACL apply wrote no 4907, so it never committed rather than being reverted. Eight screenshots in `assets/`. |
