# Project Summary

A running summary of what has been set up in this repo and where things stand.

_Last updated: 2026-09-25_

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
| `labs/06-windows-firewall.md` | **Module 06, nearly complete** — written 2026-09-13, four sittings 2026-09-13 → 2026-09-16, rewritten from the run; the first two-VM module since 01. A knock on a closed port is invisible to `pfirewall.log`, to 5157, to 4688 **and to Sysmon Event 3** — visible only as **5152**, which cannot name the sender. All five findings complete |
| `labs/07-remote-desktop.md` | **Module 07, written 2026-09-22, Steps 0–9 complete 2026-09-29** — one RDP session reconstructed from four separate logbooks; the join key is the exercise. **Three of the sheet's own predictions are now dead**: enabling RDP writes 4947 not 4946; a failed RDP logon is **Logon Type 3**, not 10; and turning NLA off changed **nothing** in any of the three logs |
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
| 06 | Windows Firewall | **5152**, 4946/4948, 5157 | 🟡 In progress — four sittings + two closeouts; **2 screenshots left, both need DC01** |
| 07 | Remote Desktop (RDP) | 4624·T10, 1149, 21/24/25, 4778/4779, **4947**, **4625·T3 + 261** | 🟡 In progress — four sittings; findings written, **9 screenshots filed**, Step 10 at **5 of 6** (last row needs DC01) |

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
- 🟡 **Module 06 (Windows Firewall) — nearly complete.** Written 2026-09-13, run across four
  sittings 2026-09-13 → 2026-09-16 on **both VMs** (the first two-VM module since 01). The run
  sheet is rewritten from the run, **all five findings are complete** (observation → inference
  → recommendation), and **ten screenshots are filed in `assets/`**. A closeout sitting on
  **2026-09-25** filled the Step 8 baseline table from command output on both VMs, so the only
  thing outstanding is **three screenshots** (`06-5152-ws01-empty.png`, **`06-5152-listening.png`**
  — missed by every status note until 2026-09-29 — and `06-sysmon3-zero.png`, which is permanently
  unobtainable).

  **The module's thesis was wrong, and disproving it is the result.** It was built on "the
  text file is thin, event 5157 is rich." Three TCP knocks from WS01 to DC01 port 9999 —
  nothing listening, no rule permitting it — produced **nothing in `pfirewall.log` and
  nothing in 5157**, twice, in windows twenty minutes apart. Both instruments were
  demonstrably alive: the text file held an unrelated ICMP `DROP` at 08:41:56 local, and the
  5157 query returned unrelated events under the identical command. The knocks appear only
  as **5152**, whose subcategory is **off by default** and which the run sheet's Step 2 had
  omitted.

  **A controlled experiment then established why**, one variable at a time:

  | Listening on the port? | Explicit block rule? | `Filter Origin` | App named in 5152 | In `pfirewall.log`? |
  |---|---|---|---|---|
  | No | No | `Stealth` | `-` (PID 0) | No |
  | No | **Yes** | `Stealth` | `-` (PID 0) | No |
  | **Yes** | Yes | `Query User Default` | **`powershell.exe`** | **Yes** |

  Row 2's rule was verified by readback rather than trusted — `Enabled: True`,
  `Direction: Inbound`, `Action: Block`, `Profile: Public`, `Protocol: TCP`,
  `LocalPort: 9999` — and changed nothing. Row 3 changed one thing: a
  `System.Net.Sockets.TcpListener` holding the port open. Everything moved at once.

  So **stealth mode intercepts packets to closed ports before any rule is consulted**;
  `pfirewall.log` records a drop only once the packet gets past that point; and 5152 names
  the **local** process only where one exists. Since a port scan is overwhelmingly attempts
  against *closed* ports, **the firewall's own log file is structurally blind to port
  scanning**, and so is 5157.

  **The second half of the module is attribution, and nothing in the lab has it.** Four
  instruments checked, each proved alive first and each empty: DC01's firewall saw the packet
  but cannot see inside WS01; WS01's firewall recorded nothing because its outbound traffic is
  allowed (**1040** unrelated 5152s proving the channel); WS01's process log holds no 4688 for
  the knock (**330** unrelated 4688s in the same twenty minutes) because `Test-NetConnection`
  is a cmdlet running inside an already-open shell, not a program that starts — **process-
  creation logging records a program starting, not what it does afterwards**; and **Sysmon
  Event 3, armed specifically for this, returned zero.**

  **That last one was settled by experiment on 2026-09-16, and it is the module's strongest
  result.** A `NetworkConnect` rule scoped to `DestinationPort is 9999` was applied and
  confirmed in the live-config readback *before* the break. Three knocks at **22:49:36,
  22:49:59 and 22:50:00 UTC** → **zero** Event 3s, against **373 Event 1s** in the same window.
  Nineteen minutes later a `TcpListener` plus a readback-verified inbound **allow** rule made
  DC01 answer; the identical knock returned `True` and produced **exactly one** Event 3 at
  **23:09:13.841 UTC** carrying `Image …\powershell.exe`, **`User CORP\Administrator`**,
  `SourceHostname WS01.corp.local`, `DestinationHostname DC01`, `Initiated true` and a
  `ProcessGuid` that joins back to Event 1. **One variable moved: whether the far end
  answered.**

  So **`NetworkConnect` records connections that complete, not attempts that go unanswered** —
  structurally the same reason 5157 never fires for a closed port. **Finding 2 was rewritten
  from "the attribution is on the other machine, go and get it" to "no instrument in this lab
  can attribute a probe of a closed port."** Sysmon names the sender only once a probe finds
  something **open** — that is, only for the minority of a scan that succeeds, after the
  interesting part is over. The instruments become informative exactly when the attack
  succeeds, which is backwards for catching someone who has not got in yet. What cannot be
  distinguished from this evidence: "completed" versus "received any response" — a port that
  returns RST rather than being stealth-dropped would discriminate them, and that test has
  **not** been run.

  Alongside that, from sitting 1: **4946 and 4948 record no account** — fields limited to
  Profile Changed / Rule ID / Rule Name, `.Message` adding nothing, `Event.System.Security`
  empty on both with the 4946 run as a control — on a host carrying **four** 4946s and
  **seven** 4948s with nobody attacking it, three of them written by Windows unattended
  overnight. So the module's consistent subject is: **Windows records a great deal about what
  happened and remarkably little about who did it.**

  **Three things the run corrected in the run sheet.** DC01 was powered off at the start and
  WS01 logged in normally on **cached credentials**, with the first symptom appearing two
  steps later as the wrong firewall profile (Step 0.2 now boots DC01 first). Ping already
  worked, because **DC promotion enables its own echo-request rule** on the `Any` profile,
  live since Module 00 — so Step 3 became a **block** rule, demonstrating **block beats
  allow** at the network layer and yielding a deletion to catch. And **Finding 5**: the run
  sheet listed four gates, enabled three, and chose a break condition neither remaining
  instrument could see — the module reproduced its own central lesson on its own author,
  recorded deliberately rather than quietly patched.

  **Unexplained, recorded as observations with no cause established:** DC01 sits on the
  `Public` profile while WS01 is on `Domain` — **still true after the 2026-09-16 reboot**,
  confirmed in `06-firewall-profiles.png`; row 3 of the matrix reads `Query User Default`
  rather than naming the block rule; and WS01's process-creation rate, now measured **twice** —
  308 in twenty minutes on 2026-09-15 and **330 in twenty minutes on 2026-09-16** — against
  Module 04's ~0.26 MB/day August measurement. Two independent readings that close suggest a
  real rate rather than boot noise, but **neither window was controlled for a reboot**, so it
  stays an open question. If real, WS01's 20 MB Security log fills in about a day.

  **Two procedural failures the sitting caught, both now in Finding 5.** The block rule
  reported deleted on 2026-09-15 was found **still present and enabled** the next sitting — a
  `Remove-` that ran is not a rule that is gone, and every state change now gets a `Get-`
  afterwards. And a mistyped `Id=49466` returned `NoMatchingEventsFound`, the **identical**
  message a genuine empty result gives, which briefly looked like DC01's 4946 events had been
  destroyed by log rotation; the screenshot preserves both the typo and the correct retype.
  **Suspect the query before the host.**

  **The Step 8 baseline is complete as of 2026-09-25**, every cell read from command output on
  one machine or the other rather than filled from memory. **The 2026-09-25 readbacks closed three open unknowns.** `LogBlocked` **survived the
  2026-09-16 reboot** on both machines, each on its own active profile only (`Domain` for WS01,
  `Public` for DC01) — it had been set on 2026-09-15 and never re-read, so this was genuinely
  unknown. **DC01 is still on `Public`**, a third sighting and the first via
  `Get-NetConnectionProfile` rather than the GUI, which rules out a reading artifact and leaves the
  anomaly standing with no cause. And two new traps entered the gotchas list: **`Get-NetFirewallProfile`
  reads the *configured* store by default**, returning `DefaultInboundAction: NotConfigured` — which
  means "nothing explicitly set here", **not** "no default applies"; `-PolicyStore ActiveStore`
  returned **Block inbound / Allow outbound** on both hosts, reconciling with the
  `BlockInbound,AllowOutbound` already on record. And **`LogFileName` is stored as a literal
  `%systemroot%\...`**, which PowerShell does not expand.

  **Left to finish:** two capturable screenshots — `06-5152-ws01-empty.png` (the 1040-count beside the empty
  `9999` filter). **`06-sysmon3-zero.png` was deliberately not captured** — a decision by the user on
  2026-09-25, to avoid holding up Module 07. Module 07 Step 3.2 then added port 3389 to the Sysmon
  config, so the re-derivation described above is **no longer available** and the screenshot is
  **permanently outstanding**. The underlying result is unaffected: Finding 2 rests on the
  2026-09-16 run, where three unanswered knocks produced 0 Event 3s against 373 Event 1s, and the
  Event 3 count was independently confirmed to still be **1** on 2026-09-25 before any config
  change. The missing item is the illustration, not the evidence.
- 🟡 **Module 07 (Remote Desktop) — sittings 1–4 complete, Steps 0–11 bar one readback and one screenshot (2026-09-29).** Two RDP
  sessions made from DC01 to WS01, reconstructed across all four logbooks and joined, with the
  access story and its MITRE mapping written (T1021.001, T1078).

  **The Security log cannot tell this story on its own, and that is the module's result.** One RDP
  attachment writes **three 4624s** — two **Type 3** NLA credential checks with subject Logon ID
  `0x0`, then the **Type 10** with SYSTEM (`0x3E7`) as subject — so counting Type 10s over-counts
  sessions by one per reconnect. The interactive session was **`0x4F246D`, 09:30:26 → 09:42:20
  UTC**, carried by **479 events** including **154 × 4688**, which is the pivot from "who logged
  on" to "what the session did". **None of those 479 events marks the 3m30s the user was detached**
  (09:37:33 → 09:41:03). **LocalSessionManager says it in two lines** — `24` disconnected, `25`
  reconnected — with `User`, `SessionID` and `Address` on every row.

  **An unplanned controlled experiment produced the strongest finding.**
  `auditpol /get /subcategory:"Other Logon/Logoff Events"` read **`No Auditing`** — a **third**
  switch, distinct from the `Logon` and `Logoff` subcategories verified in sitting 1 — so the
  missing 4778/4779 were the instrument, not Windows. Enabled, readback confirmed, boundary marked,
  identical activity repeated: **four events where there had been none, and nothing before the
  boundary.** Auditing is not retroactive, so the morning disconnect is permanently unrecoverable.
  **4778/4779 are not RDP events** — they track any window-station attach/detach, and the extra
  pair is **Administrator's console session being displaced** when `asmith` connected. That switch
  is now lab state on WS01 and should be **left on**.

  **No single field spans the four logs, and one identity has four spellings**: `asmith` + `CORP`
  (4624), `asmith@corp.local` (1149), `CORP\asmith` (LocalSessionManager), `NT AUTHORITY\NETWORK
  SERVICE` (Sysmon Event 3). The join is made in **hops** — Logon ID inside the Security log,
  SessionID inside the session log, nothing carrying both — so the bridge is user + source address
  + a ~1 s timestamp coincidence. **Two sessions from one user within a minute would be separable
  only by timestamp.** Each log answers exactly one question: Sysmon *where from* (a machine, never
  a person — `svchost.exe` / `NETWORK SERVICE`), 1149 *who*, LocalSessionManager *what happened to
  the session*, Security *what the session did*.

  **Module 06's open question is closed:** Sysmon Event 3 **does** log the inbound half —
  total **11** against a baseline of **1**, `Initiated: false`, `SourceHostname DC01`, port 3389.

  **Also settled:** the **4732** from the Step 3.1 group addition exists (2026-09-25 10:14:46 UTC),
  closing a sitting-1 unknown. **New traps:** wrong *channel* is as silent as wrong machine
  (`Id=24,25` against RemoteConnectionManager returns `NoMatchingEventsFound`); fields for these
  channels live at **`.Event.UserData.EventXML`**; `Select-String` returns match objects, use
  `.Line`; the **newest** matching event is not the right event.

  **Evidence:** `C:\evidence\07-security.evtx` and `07-lsm.evtx` exported on WS01 before anything
  could roll. **Three screenshots are filed in `assets/`**, each opened and verified against its
  contents on 2026-09-29: `07-1149-auth.png`, `07-session-attribution.png` (the cleanest single
  image the module has produced) and `07-session-lifecycle.png` — **two of them renamed from
  `07-1149-auth.png.png` and `Session-Lifecycle.png`.** The note that said none were filed was
  stale: **pasting into a chat does not put a file on disk, but a stale note does not prove one is
  missing — check the directory.** Outstanding: `07-sysmon-config.png`,
  `07-4947-rules-modified.png` (**Finding 5's first observation has no image behind it**), the
  479-event `Group-Object` breakdown, and sitting 3's `07-4625-nla-on.png`, `07-nla-comparison.png`
  and `07-261-listener.png`.

  **Unexplained, recorded as observations:** 4624 queries with a 4-hour window that returned
  nothing although the events sat inside it (rotation, rendering and boundary each excluded, no
  cause established); noted-vs-logged times disagreeing by up to a minute **in both directions**,
  which switching windows cannot explain; **5 × 1149 for two sessions**; and 479 Security events
  from one twelve-minute session, consistent with Module 06's parked rate observation but still not
  measured against a controlled window.

  **Sitting 3 (2026-09-28 → 2026-09-29) completed Steps 8 and 9 — the failed logon and the NLA
  experiment — and killed two more of the sheet's predictions.**

  **A refused RDP logon is Logon Type 3, not 10.** One refusal wrote **exactly one 4625**
  (21:26:35 UTC), against three 4624s for one successful attachment. A rule hunting RDP by
  **Type 10** catches every success and **misses every failure**. Neither SID resolved
  (`S-1-0-0` for subject *and* target): a refused logon yields **the string that was typed, never
  an identity**. And the account arrives with a **fifth spelling** — `asmith@corp.local` with an
  empty domain, where the successful 4624 said `asmith` + `CORP`, so **the same log spells the
  same user differently depending on whether they got in**.

  **The sharpest result: no single event can classify the attempt.** Nothing in the 4625 says
  *RDP* — Type 3, `NtLmSsp`/`NTLM`, Source Port `0` is indistinguishable from a failed SMB or
  WinRM logon. What identifies it is **261 ("Listener RDP-Tcp received a connection")** in
  RemoteConnectionManager, 26 seconds earlier — and **261 carries only the listener name**, no
  user, no address. **The identity-bearing event cannot name the protocol; the protocol-bearing
  event cannot name the identity.** LocalSessionManager stayed **silent** (no session was ever
  built) and no **1149** was written. **Candidate finding, seen twice: 261 with no matching 1149
  is the signature of a refusal.**

  **The silence had its positive control in the same output** — a console-logon cluster 2m40s
  before the attempt, so the channel proved itself alive without reaching back to Step 6. Two of
  sitting 2's six unresolved IDs are now closed on the box: **261** as above, and **59** =
  `RpcGetCurrentSessionCapabilities` (internal RPC chatter, not session activity).

  **The NLA experiment produced a negative result, honestly bounded.** With
  `UserAuthentication = 0` (readback-verified), the 4625 was **field for field identical**, the
  session log **untouched**, no 1149, and a **261** 32 s ahead of the failure — the two matrix
  rows match exactly. Even the *visible* prediction failed: no login screen appeared inside the
  RDP window. **No cause established.** `SecurityLayer = 2` was read and ruled out as a second
  gate. The leading candidate is that **the running listener never reloaded** — the licence
  reboot fell *before* the change, not after, so it was **not** the free control it first looked
  like. **Discriminating test, not run:** set NLA off, reboot, retry.

  **New traps:** **`-Name` on `Get-ItemProperty` restricts what comes back**, so selecting an
  unrequested property prints a **blank column** — "never retrieved" is indistinguishable from
  "empty"; a **misspelled channel name errors loudly** while a real channel with no matches is
  silent, which refines sitting 2's wrong-channel trap (only a channel that *exists* can fool
  you); **a cap returning fewer rows than the cap is a complete population**; and **shape is not a
  field** — a cluster that looked exactly like a session being built for a failed logon was
  killed in one read by `Address: LOCAL`.

  **Cleanup verified:** `UserAuthentication` back to **`1`** on WS01, and **`asmith` is not
  locked** (read on DC01), so no analyst-generated 4767 exists to be mistaken for lab noise.

  **WS01's Windows 11 evaluation licence is expired and shuts the VM down roughly hourly** — it
  did so between Steps 8 and 9. This is now an active constraint on sittings, not a future one.

  **All five findings are now drafted** (2026-09-29) in observation → inference → recommendation
  form, with an open-questions table carrying seven unsettled items out of the module rather than
  letting them read as settled. **Finding 5 is "four of this run sheet's own predictions were
  wrong"** — 4946-vs-4947, the switched-off 4778/4779, the NLA null result, and an expectation
  that could not fail.

  **Resume at Step 10** — lab-state readbacks, then Step 11's remaining screenshots. **Open and carried forward:** H3's reboot test; the **unidentified 4625 at 00:29:46 UTC
  on 2026-09-29**, fields never read; `0xC000006A` vs `0xC0000064` (fail as a nonexistent user —
  no lockout cost); and whether connecting by IP is what forced **NTLM** rather than Kerberos.
- 🟡 **Sitting 4 (2026-09-29) — Steps 10 and 11, WS01 only.** DC01 was off, which is the only
  reason anything remains. **The opening command destroyed the sitting's own plan and that was
  the result:** WS01's Security log was measured at a **one-day horizon** (2065 × 5152, oldest
  2026-09-28 13:41:34 UTC), so the 2026-09-14/16 knock and the 2026-09-25 4947 burst were
  **already gone** — both recorded in their checklists as *"recoverable."* This **closes Module
  06's parked "not measured properly" observation** and confirms its prediction; the mechanism was
  measured the same day at **154 × 4688 per twelve-minute session**. An `.evtx` was exported
  immediately, and `07-4624-type10.png` plus the 479-event breakdown were then **recovered from a
  file the live log had already discarded**. **Nine screenshots filed**, each opened and checked
  against its contents. **Results:** all four 4625s on the box accounted for — two lab refusals and
  **two Type 2 console mistypes**, which **closes the sitting-3 unknown** and leaves `asmith`'s
  attempt count as recorded; **`%%2313` resolved on the box** to *"Unknown user name or bad
  password"*, so the human-readable field **deliberately conflates** what `SubStatus` beside it
  would disambiguate; **`WorkstationName` names the destination on a 4624 and the source on a
  4625**, breaking naive success↔failure joins; the success used **`Negotiate`** where the refusal
  used **`NTLM`**, which weakens the recorded NTLM-because-IP explanation; and **a reconnect gets
  its own Logon ID** (`0x741ee0`, torn down at reattach), which explains both the Type 10
  over-count and sitting 2's `-First 1` trap. **One anomaly, found by reading a screenshot rather
  than running anything:** Sysmon's two `DestinationPort` conditions are **combined with `And`** —
  see H1/H2 in the next-sitting checklist. **Four new traps:** `-FilterXPath` on a *live* channel
  returns `NoMatchingEventsFound` while the events sit there; a wrong registry key gives the same
  blank column as a wrong `-Name`; `Get-LocalGroupMember` throws **1789** when the DC is down;
  `[xml]` on an un-indexed array fails with a message that reads like a parser fault.
- ⬜ Modules 08–12 planned but not yet expanded
- ✅ Git repository pushed to `github.com/Simplyaeon/windows-ad-soc-lab` — **`main` was level
  with `origin/main` at `c5f1c39` on 2026-09-29**, including Module 07's sittings 1–3. The earlier
  "committed locally and not pushed" note was **stale**. Read `git log origin/main..main` rather
  than trusting this line either way
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

### 🚩 The next sitting, in order

**One short run with BOTH VMs up closes Modules 06 and 07.** Rewritten 2026-09-29 after sitting 4,
which completed Module 07's Step 10 bar one row and filed six screenshots. Verified against the two
lab files' own checklists, not against status notes.

**DC01 must be powered on.** Sitting 4 ran WS01-only because it was off, and that is the only
reason anything is left.

**A. The `TcpListener` run (both VMs) — the last outstanding lab work in either module**

Three knocks, one setup, because the matrix rows differ:

| | Setup on DC01 | Gives |
|---|---|---|
| **1** | nothing | WS01 logs nothing about its own outbound knock → **`06-5152-ws01-empty.png`** |
| **2** | `TcpListener` + **allow** rule | the connection completes → **does Sysmon log Event 3 for 9999?** |
| **3** | `TcpListener` + **block** rule | 5152 reads `Query User Default` / `powershell.exe` → **`06-5152-listening.png`** |

**Knock 3 needs a BLOCK rule, not an allow rule.** Matrix row 3 is *something listening **and** a
block rule* — that combination is what moves `Filter Origin` off `Stealth` and puts a process name
in the event. An allow rule produces the wrong frame.

For knock 1, **use the uncapped query**. The run sheet's own `-MaxEvents 20 | Where-Object` form is
the filter-first trap and cannot find a knock more than a few minutes old; a correction is now
written into Step 7.1. Put `hostname` **and the oldest record's timestamp** in the frame, so the
image states the window it covers.

Delete every rule afterwards **with a readback** — Finding 5 has three instances of a `Remove-`
that ran not being a rule that is gone.

**⚠️ What knock 2 settles.** Module 07 Step 3.2 added port 3389 to the same Sysmon `NetworkConnect`
group. The 2026-09-29 live readback shows both `DestinationPort` conditions **combined with `And`**
— unsatisfiable read literally. Port 3389 demonstrably still matches, so they cannot be strictly
ANDed; but **9999 has not been tested since the edit**, and Module 06's only Event 3 for it predates
the edit by nine days.

- **H1** — same-field conditions are OR'd despite the label; nothing has changed.
- **H2** — the last condition wins, and the 9999 rule was **silently disabled** by an edit that
  looked purely additive.

If H2 holds it is a finding in its own right: *a config edit that applies cleanly, returns
`Configuration updated`, and passes a live readback showing both values can still have disabled an
existing rule.* Every check this lab knows how to run passes either way.

**B. Module 07 Step 10 — one row left (WS01)**

```
Get-LocalGroupMember -Group 'Remote Desktop Users'
```

Expect `CORP\asmith`, `PrincipalSource: ActiveDirectory`. It **failed with error 1789** on
2026-09-29 — *the trust relationship … failed* — because **DC01 was powered off** and the group
holds a domain account whose SID needs a DC to resolve. Expected to pass once DC01 is up; if it
does not, that is a real problem rather than a side effect.

Everything else in Step 10 is read and recorded: `fDenyTSConnections` **0**, `UserAuthentication`
**1**, `SecurityLayer` **2**, Sysmon v15.15 / schema 4.90 with both ports and all four registry
rules, and all four audit switches. **The decision is recorded: RDP stays on, with NLA on.**

**C. Everything optional — DROPPED by decision, 2026-09-29. Do not re-propose.**

The following were carried as optional and are now **closed as won't-do**. They are recorded here
so a future session recognises them as decided rather than forgotten:

- ✖ **`07-4947-rules-modified.png`** — its events are permanently gone (the burst was 2026-09-25;
  the log holds a day), and regenerating them means toggling the Remote Desktop rules. **Finding
  5's first observation stands on text with no image**, which is stated in the finding.
- ✖ **NLA off → reboot → retry.** Finding 3's leading candidate — that the listener never reloaded
  — therefore **remains untested**, and the finding says so.
- ✖ **Fail as a nonexistent user.** `0xC000006A` therefore **remains recall, not established**,
  and the finding says so. What *is* established is that `FailureReason` conflates the two cases
  deliberately (`%%2313` = "Unknown user name or bad password").
- ✖ **Module 06's RST probe**, stealth-mode reconfiguration, the `Query User Default` precedence
  question, and the 4688-rate re-measurement — the last of these was **answered anyway** by
  sitting 4's rotation measurement.
- ✖ **Module 03's three reconstructed screenshots** and the fresh-SACL test for its parked anomaly.

**These stay written into the Findings as open questions**, because that is what the evidence
honestly supports — an unrun test is a limitation to declare, not a task to carry. **The
distinction matters: they are no longer work, they are still caveats.**

**D. Desk work**

- **Commit and push.** Done 2026-09-29 (`c34880e`); `main` level with `origin/main`. Review
  screenshots before publishing; the repo is public.
- Decide on the `.evtx` files on WS01: `07-security.evtx`, `07-lsm.evtx`, `0929-security.evtx`, and
  a fourth dated **2026-08-25** that is **unidentified**. None are in the repo.

**The lesson sitting 4 paid for, and it outranks the checklist:** **"recoverable later" is a
deadline nobody wrote down.** Screenshots recorded as *"recoverable — the event is still in the
log"* were, for Module 06's knock and Module 07's 4947 burst, already gone. **Export an `.evtx`
first, then photograph at leisure** — that is what made the Type 10 logon and the 479-event
breakdown recoverable at all.

---

1. 🚩 **NEXT SESSION — one short run with BOTH VMs up closes Module 06 and Module 07.**
   Full checklist above under **"The next sitting, in order"**. After sitting 4 (2026-09-29) the
   only outstanding lab work is the `TcpListener` run, which needs DC01 powered on — that is also
   what blocks Module 07's last Step 10 row and settles the Sysmon `And` question.
2. **Then Module 08.** Nothing optional stands between here and it — every "could also test" item
   across Modules 03, 06 and 07 was **closed as won't-do on 2026-09-29** and is listed under
   section C above. Each survives where it belongs, as a declared limitation inside the finding it
   qualifies. **Do not re-propose them as work.**
3. **Consider rebuilding WS01** if the `gpupdate`/`gpedit` blockers keep costing time. The cost
   has risen again: Module 02's audit config, Module 03's `Registry` subcategory + Run-key SACL,
   and now the **completed** Sysmon install and config would all need redoing.
4. **Module 12 (Kerberos capstone)** remains the standout portfolio artifact.
5. Keep the **Progress log** in `README.md` and the status tables here updated as modules complete.
