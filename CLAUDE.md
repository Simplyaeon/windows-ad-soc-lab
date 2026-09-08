# Windows & AD SOC Lab — working notes

A hands-on lab and project journal for building **SOC analyst** competency in Windows
and Active Directory, with **detection** as the point. Every module follows the same
loop: **Build** an admin capability → **Break/Observe** by generating activity →
**Detect** it in the logs. Published as a portfolio.

## The lab

| Host | Role | Address |
|---|---|---|
| **DC01** | Windows Server 2022 — Domain Controller + DNS | `10.0.0.10` |
| **WS01** | Windows 11 Enterprise — domain member | `10.0.0.20` |

Domain `corp.local` (NetBIOS `CORP`), VirtualBox internal network `lab-net`, no
internet by design. Snapshots: `00-clean-install` (pre-domain), `01-domain-ready`,
`mod01-start`; `mod04-start` taken 2026-09-04. Credentials are documented in
`labs/00-lab-build.md` — throwaway lab passwords, never reused anywhere real.

**Both VMs are on `W. Central Africa Standard Time` (UTC+1)** as of 2026-08-24. They ran
on the Windows install default of Pacific until then, so any timestamp recorded before
that date and *displayed* rather than read from XML is eight hours out.

**Both eval licences are rearmed and healthy.** DC01's Windows Server evaluation had
expired and was shutting the VM down hourly (`1074`, "license period ... has expired");
`slmgr /rearm` + reboot fixed it, and `slmgr /dlv` shows the remaining rearm count. Two
things still follow from it: **the licence state lives in the snapshots**, so restoring
`01-domain-ready` reinstates the *expired* licence (use `mod04-start`, taken 2026-09-04
post-rearm, as the clean baseline), and WS01's Windows 11 evaluation will hit the same
wall later.

**The VMs run on a separate Windows PC.** They cannot be reached from a Claude Code
session on this Mac. All lab commands are for the user to run there; ask for output
rather than trying to inspect anything directly.

## Where things stand

**Read `summary.md` first** — it carries the current status, the per-module findings, and
the next steps, and is the file to update as modules complete. Modules 00, 01, 04 and 05
are complete with findings written and evidence in `assets/`; `main` is pushed through
Module 05. Module 02 is the module in flight (below). The rest are planned — see
`SOC-Analyst-Roadmap.md`.

Only what a session can't get from those files is kept here: the blockers, the measured
baselines, and the traps.

### Open blockers on WS01 (found 2026-09-02; CommandLine resolved 2026-09-03)

- **`gpupdate` is "not recognized as a cmdlet"**, as is `gpedit.msc` for applying policy.
  Worked around by setting both Module 05 features directly in the registry
  (`EnableScriptBlockLogging`, `ProcessCreationIncludeCmdLine_Enabled`), which applies
  immediately and is what the lab now documents.
- **4688's `CommandLine` field — ✅ resolved 2026-09-03.** Blank on 2026-09-02, populated the
  next day on encoded runs (07:52–07:53 UTC). The field populates only for processes *created
  after* `ProcessCreationIncludeCmdLine_Enabled` takes effect; the earlier blanks were
  pre-setting processes, not a fault (`auditpol` reported Success throughout).
- **`triage.ps1` produced no output when run as a file**, though every query inside it
  works pasted into the terminal. Most likely Notepad and the shell in different working
  directories — `notepad $PWD\triage.ps1` avoids it.

Three unexplained policy-related faults on one host is a pattern; **rebuilding WS01** from
a fresh Windows 11 Enterprise eval ISO is on the table if they keep costing time.

Measured on WS01, 2026-08-24 — useful baselines: Security log holds **8764 records /
7.07 MB of 20 MB**, oldest event 28 July, ~845 bytes per event, ~0.26 MB/day, so ~76
days to fill.

**Module 02 (NTFS Permissions & File Auditing) is nearly complete** (2026-09-05, WS01).
Steps 1–5 done and Step 6 proven: `C:\Finance` locked to a `Finance` group, File System auditing
+ SACL on, and both halves of the evidence in the log — `fin_user` allowed as **4663 Success**,
`helpdesk` denied as **4656 Failure**. Three snags fixed along the way:
`Authenticated Users:(OI)(CI)(M)` was a *second* broad inherited ACE that kept `helpdesk`
writable after `Users` was removed (`icacls /remove:g` fixed it; lab Step 3 updated to remove
both); the SACL didn't persist on first apply (re-added — `InheritanceFlags` is
`ContainerInherit, ObjectInherit`, so files *are* covered, and the folder-only hypothesis was
wrong); and **the denied access logged nothing at all until the `Handle Manipulation`
subcategory was enabled**. That last one is the module's real lesson: the SACL's `AuditFlags`
and `auditpol /get /subcategory:"File System"` can *both* read `Success and Failure` and
denials still vanish, because both of those govern **4663 — which only fires on access that
*succeeded***. A refusal is a **4656**, fed by a third switch that is off by default. Check it
*before* generating denied access, not after. Step 5 now uses `runas /user:<u> powershell` with
explicit `Out-File`/`Get-Content` instead of `runas ... notepad`, which silently redirects a
blocked save and leaves no evidence the folder was ever touched. Remaining: 4670/4907
(Step 6.3), screenshots, finding write-up.

After 02: Module 03 (needs Sysmon moved into the VMs).

## How to work on this

**The user comes from Linux and is new to Windows and PowerShell.** Keep guides heavily
simplified. Prefer GUI clicks where GUI and command line both work. Introduce one new
construct at a time.

- **Always say which VM a command runs on.** Wrong-machine queries return empty results
  rather than errors, and that has cost real time.
- **Use UPN form** (`administrator@corp.local`), never `CORP\administrator` — the user's
  keyboard layout produces the wrong character for `\`.
- **Event Viewer first** when the goal is reading a handful of events; its General tab
  labels and resolves every field. The GUI also filters at the log, so it *cannot* be
  starved the way a PowerShell pipeline can. Save `Get-WinEvent` for genuine scale.
- **Build commands up across several runs** — shortest useful form first, run it, add one
  piece, run it again. Do not hand over a finished multi-line pipeline; the user is
  building the ability to write these, and pasting a working block produces output
  without competence.
- **Lead every step with its aim** — one sentence on what it lets you do afterwards,
  before any instructions. Steps given as bare instructions read as busywork.

### Get-WinEvent traps already hit

- **Filter first, limit second.** `-MaxEvents 500 | Where-Object Id -eq 4625` takes the
  newest 500 events and *then* filters, so older matches never reach the filter — and the
  low count reads as an answer rather than a failure. Measured on WS01 2026-08-24: that
  form returned **1**, `-FilterHashtable @{LogName='Security'; Id=4625}` returned **11**,
  same log, same moment. Use `-FilterHashtable` on live logs, `-FilterXPath` on exported
  `.evtx`. Keep `Where-Object` for narrowing already-correct results.
- `StartTime` **filters, it does not search** — anything older than the window is
  invisible. Start wide (`AddDays(-7)`), then narrow.
- `-MaxEvents` caps the **total**, newest first. Mixing rare IDs (4720, 4728) with
  high-volume ones (4624, 4768) lets the noisy ones consume every slot.
- **Default output columns hide the answer.** `Message`'s first line is boilerplate —
  every 4768 reads "A Kerberos authentication ticket (TGT) was requested", so rows look
  identical. Pull the field by name, or use Event Viewer's **Find** (`Ctrl+F`).
- **4728 vs 4732 vs 4756** is group *scope*: global / local / universal. Domain Admins is
  4728, Backup Operators and Remote Desktop Users are 4732, Enterprise Admins is 4756 —
  so watching only 4728 misses real escalation paths. A 4732 can also mean a machine-local
  group on WS01; the `Computer` field distinguishes them.
- **4728's `Member → Account Name` is a distinguished name**, not the logon name
  (`CN=svc_backup,CN=Users,DC=corp,DC=local`). 4732 is the one that often shows `-`.
- **A 4724 beside a 4720** is account creation, not a password reset —
  `New-ADUser -AccountPassword` writes 4720/4722/4724 in the same second. A 4724 *alone*
  against an existing account is the suspicious one.
- **Automatic lockout expiry writes no 4767.** A 4767 existing at all is evidence of
  deliberate administrative action.
- Get fields **by name**, not `Properties[n]`:
  ```powershell
  ([xml]$e.ToXml()).Event.EventData.Data | Format-Table Name, '#text'
  ```
  Most events keep their fields under `.Event.EventData.Data`, but some use `UserData`
  instead — **1102** stores its subject at `.Event.UserData.LogFileCleared`
  (`SubjectUserName`), and 104 similarly. If `EventData.Data` is empty, check `UserData`.
- **Read an exported log with `-Path <file>.evtx`**, and filter it with `-FilterXPath`
  (not `-FilterHashtable`, which is live-log only), e.g.
  `Get-WinEvent -Path C:\evidence\x.evtx -FilterXPath "*[System[(EventID=4625)]]"`. An
  `.evtx` is a **frozen snapshot** taken at export time — it does not track the live log,
  which is exactly why it survives overwrite/clear. `wevtutil epl <log> <file>` exports;
  reads work on any machine, not just the source host.
- 4771 has **no Logon Type** — "Type: 2" there is Pre-Authentication Type
  (`PA-ENC-TIMESTAMP`). Interactive-vs-network evidence comes from 4625 on WS01.
- Empty output is not an error. Check in order: wrong machine → window too narrow or
  starved → **events overwritten** (`wevtutil gli <log>`, and compare `FileSize` to
  `MaximumSizeInBytes` — if the log has never filled, the oldest event is the machine's
  true beginning, not a rotation boundary) → channel disabled → auditing actually off.

## Module and findings conventions

Each lab file is a **step-by-step run sheet**, ordered, each step naming its VM — not a
reference document. Structure: objective → pre-flight → build → break/observe → detect →
evidence → MITRE mapping, then a Findings section and a troubleshooting section.

Findings use **observation → inference → recommendation**, kept strictly separate:

- **Observation** — only what the log literally says. Host, log, event ID, timestamp,
  accounts. Reproducible by someone else. **State timestamps in UTC** — that is what the
  event stores (`TimeCreated SystemTime`); Event Viewer only converts for display. The
  lab VMs were installed on Pacific while the analyst is on WAT (UTC+1), so displayed
  hours ran eight hours out and mid-morning activity looked like 3 AM. Name the offset
  if you also give a local time.
- **Inference** — labelled judgement, with confidence language ("I assess with high
  confidence"), MITRE technique IDs, and an explicit statement of what *cannot* be
  determined from the evidence.
- **Recommendation** — specific and actionable, naming the follow-up queries.

Where evidence supports more than one story, name the competing hypotheses, say which is
favoured and why, and state what would discriminate between them. Never let sequence
imply causation.

## Git

Remote is `github.com/Simplyaeon/windows-ad-soc-lab`. **Treat the repo as public.**
Commit when asked; **do not push without explicit confirmation** — screenshots can leak
host names, IPs, and usernames, and should be checked before anything is published.
Keep the README progress log and `summary.md` current as modules complete.
