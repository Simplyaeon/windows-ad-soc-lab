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
the next steps, and is the file to update as modules complete. Modules 00, 01, 02, 04 and 05
are complete with findings written and evidence in `assets/`; `main` is pushed through
Module 02. **Module 03 is complete** (run 2026-09-10 → 2026-09-12) — see below for what it
established and the two things it left unexplained.
The rest are planned — see `SOC-Analyst-Roadmap.md`.

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

**Module 02 (NTFS Permissions & File Auditing) is complete** (run 2026-09-05 → 2026-09-08,
WS01; committed and pushed). `C:\Finance` locked to a `Finance` group, with both halves of
the access evidence in the log — `fin_user` allowed as **4663 Success**, `helpdesk` denied
as **4656 Failure**.

The module's lasting lesson, and the one that **transfers directly to registry auditing in
Module 03**: object-access auditing is gated at **four independent layers**, and three of
them silently swallow an expected event on a stock Windows 11 install.

| # | Gate | Symptom when closed |
|---|---|---|
| 1 | `File System` subcategory | no 4663 |
| 2 | `Handle Manipulation` subcategory | no **4656** — denials vanish entirely |
| 3 | `Authorization Policy Change` subcategory | no **4670** |
| 4 | The SACL's **audited rights** (`WRITE_DAC`) | still no **4670**, with all three subcategories reading "Success and Failure" |

So **4663 only fires on access that *succeeded*** — a refusal is a **4656**, fed by a
different switch. Check every gate *before* generating the activity, not after. Gate 4 is
the subtle one: the 4907 at 15:52:46 UTC on 2026-09-07 shows the audited-rights mask
gaining exactly `WD` (`CCDCLCSWRPWPLOCRRC` → `CCDCLCSWRPWPLOCRRCWD`) and the first 4670
appearing twelve seconds later, on identical commands.

Two further traps worth carrying: **auditing is not retroactive**, so the Step 3 lock-down
could never have logged; and a committed SACL change *always* writes a 4907, so the missing
4907 on the first apply is positive evidence it never committed (absence used as evidence —
the mirror of Module 04's Finding 1). Also: `runas ... notepad` is useless for denial
evidence — Notepad silently redirects a blocked save; use `runas /user:<u> powershell` with
explicit `Out-File`/`Get-Content`.

**Module 03 (The Windows Registry & Persistence) is COMPLETE** (`labs/03-windows-registry.md`,
written 2026-09-10; run 2026-09-10 → 2026-09-12 across two sittings, WS01-only). Thesis, and it
held: **native registry auditing is opt-in per key (4657), Sysmon is opt-out per rule (Event
13)** — three benign persistence entries planted with only one under a SACL, and the *gap* is
the finding. Module 02's four gates carried over renamed: **`Registry`** is separate from
`File System`, and **`Set Value`** is the gate-4 right that `WRITE_DAC` was for 4670.

**The headline result, proven inside one eight-minute window with both instruments live:**
three identical `notepad.exe` writes — `HKLM\…\Run` 21:00:22.880 UTC via `reg.exe`,
`HKU\S-1-5-21-…-500\…\Run` 21:06:25.500 via `powershell.exe` with **no elevation**,
`HKLM\…\RunOnce` 21:08:15.088 via `reg.exe` — **4657 returned one, Sysmon Event 13 returned
all three.** The negative result carries its own control: the same 4657 query that missed two
*returned* the third, so wrong-host / narrow-window / rotation / channel-off are all excluded
by the query's own positive result. Finding 1 also came out stronger than designed — Sysmon
**Event 1** caught `reg.exe` **63 ms** before its Event 13 with full `CommandLine`,
`ParentImage`, `User` and `IntegrityLevel`.

**Verified on WS01 during the run** — only what the user pasted back:

| Fact | Evidence |
|---|---|
| `Registry` subcategory on | `auditpol` read Success and Failure, twice |
| `Handle Manipulation` works for keys | 4 × 4656, `ObjectType` = `Key` |
| `Registry` subcategory works for keys | 15 × 4663, `ObjectType` = `Key` |
| SACL on `HKLM/…/Run` audits `SetValue` | `-band 2` → `True`; one 4907 written |
| **4657 `ObjectName` is `\REGISTRY\MACHINE\…`**, not `HKLM\` | confirmed directly — **this open question is now CLOSED**. Filtering on `'*HKLM*'` silently returns nothing; Sysmon normalises back to `HKLM\`, so one hunt string cannot serve both logs |
| 4657 fires for create, modify **and** delete, via both `reg.exe` and `Set-ItemProperty` | 4 events, incl. `LabPersistRegNow` |
| `RegistryRights` collapses flags into composite names — **`WriteKey` (6) = `SetValue` (2) + `CreateSubKey` (4)** | `Get-Acl -Audit` showed `Delete, WriteKey, ChangePermissions` with no literal `SetValue`. Test the bit (`-band 2`), never grep the string |
| 4907 count follows **object** count | one 4907, because the `Run` key has no subkeys (cf. Module 02's two, folder + file) |
| `OperationType` comes out of XML as a raw message-table ref (`%%1904`) | resolve via `.Message` or Event Viewer, never from recall |
| **Sysmon's bare-install defaults log NO registry events** | post-install, pre-config: 30 records, IDs **1, 4, 5, 16 only** (process create, Sysmon service state, process terminate, Sysmon config state). **No 13.** So the Module 03 config *adds* registry logging — it does not narrow an existing flood. Corrects the natural assumption |
| Sysmon build on WS01 is **v15.15**, config schema **4.90** | `Sysmon64.exe -s` → `<manifest schemaversion="4.90" binary version=18>`. The run sheet's hard-coded `4.90` happens to be right for this build — but read it off the binary, don't inherit the number |
| `Sysmon64.exe -c` **with** a filename applies, **without** one prints | used both ways; the apply returned `Configuration updated` and the readback showed the `RegistryEvent` rules with all four `TargetObject … contains` lines |
| **Sysmon logs the per-user hive as `HKU\<SID>\…`, never `HKCU\`** | the `HKCU:` write came back as `HKU\S-1-5-21-…-500\…\Run\LabPersistUser`. A hunt on `'*HKCU*'` returns nothing. **Exact mirror of the 4657 `\REGISTRY\MACHINE\` finding** — neither log prints the shorthand you type |
| **A deleted *value* is Event 12 with `EventType = DeleteValue`**, not Event 13 | all four Step 7.1 deletions recovered with full paths. A 13-only rule sees the attacker arrive and never leave. `EventType` is Sysmon's equivalent of 4657's `OperationType` — the ID gets you to the pile, a field says what happened |
| Sysmon **Event 1** pairs with Event 13 at millisecond resolution | `reg.exe` Event 1 at 21:08:15.025 vs its Event 13 at 21:08:15.088 — 63 ms. Carries `CommandLine`, `ParentImage`, `User`, `IntegrityLevel`, `LogonId`, SHA256. Join on `ProcessGuid` |
| `Details` / `NewValue` preserve **case exactly as typed** | `notepad.exe` and `Notepad.exe` both appeared in one session. Value-data hunts must be case-insensitive |
| A registry-only `onmatch="include"` config does **not** disable other event types | 1311 Event 1s present after the config was applied |
| `notepad.exe` in a `Run` value executes as `C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_…\Notepad.exe` | so the string *written* and the string *executed* differ — never correlate them literally |

**Open anomaly — parked, NOT a finding.** The first two writes (`LabPersist`, `LabPersistBoot`,
both `reg add`) produced **no 4657** when checked; every write from the third onward logged
normally. **No cause established.** Three explanations were proposed and all three were killed
by later evidence — see the Evidence discipline section below, which exists because of it. The
discriminating test (not yet run, needs a clean baseline): restore a pre-write snapshot, apply
the SACL fresh, write immediately, and see whether the first write is silent again.

**Two further unexplained observations from 2026-09-12 — recorded, NOT findings.**

1. **`sihost.exe` writes a shadow copy of every `Run` value.** After each `Run` write, Shell
   Infrastructure Host created `…\CurrentVersion\RunNotification\StartupTNoti<valuename>` in
   the **per-user hive**, and deleted it when the `Run` value was deleted. **None for
   `RunOnce`.** Delay is **variable** (10 s for one plant, 2m36s for another, same session) and
   the DWORD payload differed (`0x0` vs `0x1`) with **no established meaning**. Potentially
   useful as corroboration — an attacker who cleans `Run` may not clean this — but no
   controlled test has been run, so it stays an observation.
2. **`ParentImage` comes back empty for Store-packaged apps.** Every Sysmon Event 1 for the
   packaged Notepad (`C:\Program Files\WindowsApps\…\Notepad.exe`) had a blank
   `ParentImage`, while the same pipeline returned `ParentImage` correctly for `reg.exe` in the
   same log — so it is not a spelling or extraction fault. **No cause established; not
   investigated further, deliberately.** Consequence: parent-process correlation cannot be
   assumed available on this host — a detection depending on `ParentImage` needs a fallback
   (`LogonId`, `ParentProcessGuid`, session correlation).

Because of (2), the **write → execution chain was left unproven**. A candidate `Notepad.exe`
exists at 21:04:16 UTC, a minute after a reboot and consistent in timing with a `Run` key
firing, but nothing ties it to the logon. Finding 1 states this as suggestive timing only.

**Lab state on WS01 after the run:**

- **Sysmon is installed, running and configured — leave it that way.** v15.15, schema 4.90,
  service `Sysmon64`, log `Microsoft-Windows-Sysmon/Operational`, config
  `C:\Tools\sysmon-registry.xml`: one `RegistryEvent onmatch="include"` group with four
  `TargetObject condition="contains"` rules — `CurrentVersion\Run` (which covers `Run` **and**
  `RunOnce`, in **both** hives, from one line), `Winlogon\Shell`, `Winlogon\Userinit`,
  `Image File Execution Options`. **Modules 06 and 07 depend on this.**
- **All lab registry values removed and confirmed clean** (2026-09-12). `HKLM:/…/Run`,
  `HKCU:/…/Run` and `HKLM:/…/RunOnce` are back to the Step 2.2 baseline — verified by reading
  all three keys, not assumed from the delete commands.
- **`mod03-presysmon` snapshot exists** (pre-Sysmon-install rollback point). **`mod03-start`
  was never taken** — so there is still no clean pre-*write* baseline, which is exactly what
  the parked anomaly's discriminating test needs.

**Step 5.4's designed lesson is intact and unaffected by the anomaly:** `HKCU:/…/Run` and
`HKLM:/…/RunOnce` have no SACL, so `LabPersistUser` and `LabPersistOnce` were never auditable.
That gap is by construction — it is what Sysmon closes in Steps 6–7.

The other open question is **closed**: the PowerShell registry provider **does** accept `/` as
a path separator (verified 2026-09-10, Step 1.2) — see the working-instructions list below.

Sysmon travelled in by **VirtualBox bidirectional drag-and-drop** from the host's Sysinternals
Suite — never by giving the VM internet. That route is proven; use it again for any other
Sysinternals tool. It installs a service *and* a kernel driver, and logs to
**`Microsoft-Windows-Sysmon/Operational`**, not Security — a `LogName='Security'` query will
never see a Sysmon event, with no error to say why. **Leave it installed after Module 03**;
Modules 06 and 07 use it.

The "it floods the log without a config" warning needs one correction now that it has been
measured: **the bare defaults log no registry events at all** (verified above), so an unconfigured
Sysmon is not a registry flood. The flood risk is real but belongs to what a *config* switches on —
an `onmatch="include"` rule set that is too broad, or an `exclude` rule set, against a hive that
Windows writes to constantly when idle. Per Module 04, that is how older evidence gets destroyed.

**Do not edit Winlogon `Userinit` or `Shell` on WS01.** A bad value boots to a blank screen with no
shell, recoverable only by snapshot restore. `Run` keys fail harmlessly; those two do not.

## How to work on this

**The user comes from Linux and is new to Windows and PowerShell.** Keep guides heavily
simplified. Prefer GUI clicks where GUI and command line both work. Introduce one new
construct at a time.

- **Always say which VM a command runs on.** Wrong-machine queries return empty results
  rather than errors, and that has cost real time.
- **Use UPN form** (`administrator@corp.local`), never `CORP\administrator` — the user's
  keyboard layout produces the wrong character for `\`.
- **Use forward slashes in PowerShell registry paths** — `HKLM:/SOFTWARE/Microsoft/...`
  works identically to `HKLM:\SOFTWARE\...`. **Verified on WS01 2026-09-10** against
  `HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion`; the provider normalises `/` to `\`.
  This is the standing workaround for the backslash-keyboard problem in every registry
  module. It does **not** extend to `reg.exe`, which is a plain Win32 program and needs
  real backslashes, and event logs always print paths back with backslashes regardless.
- **Event Viewer first** when the goal is reading a handful of events; its General tab
  labels and resolves every field. The GUI also filters at the log, so it *cannot* be
  starved the way a PowerShell pipeline can. Save `Get-WinEvent` for genuine scale.
- **Build commands up across several runs** — shortest useful form first, run it, add one
  piece, run it again. Do not hand over a finished multi-line pipeline; the user is
  building the ability to write these, and pasting a working block produces output
  without competence.
- **Lead every step with its aim** — one sentence on what it lets you do afterwards,
  before any instructions. Steps given as bare instructions read as busywork.

### Evidence discipline — never state more than has been verified

**This is a learning lab. Wrong information is worse than no information**, because the user
cannot tell a confident wrong answer from a right one and will carry it forward as knowledge.
Set on 2026-09-12 after a Module 03 diagnostic session where three successive explanations
were asserted and then retracted, and two registry values were tracked as existing when the
commands creating them had never been run.

- **A command you proposed is not a command that ran.** Only treat lab state as real when the
  user has reported the actual output. When a message contains several commands and the reply
  addresses one of them, the others are **unknown**, not done. Ask, or re-verify — never
  assume, and never carry an assumed value into a later count.
- **Prefer one state-changing command per message** when the result matters. Multiple commands
  in one message produce partial replies, and partial replies are where false state enters.
- **Label every claim: verified / assumed / hypothesis.** "Verified" means the user pasted the
  output. Anything else gets said out loud as uncertain. Never let a hypothesis inherit the
  grammar of a fact.
- **Do not invent a mechanism to explain data.** Generating a plausible-sounding cause for a
  surprising result is the main hallucination risk in diagnostic work, and it is seductive
  because it sounds like expertise. If the cause is not established, say **"I don't know what
  causes this"** and name the test that would discriminate.
- **No finding before the control has run.** Name it a hypothesis until a controlled
  observation survives. Avoid "that's the answer" / "the finding writes itself" — that phrasing
  commits the user to a conclusion the evidence has not earned.
- **Re-derive counts from what the user actually reported**, not from a running tally in the
  conversation. State the inventory back for confirmation before building on it.
- **When corrected, drop the theory immediately** and re-state only the verified facts. Do not
  defend a partially-supported explanation.
- **Uncertainty about Windows behaviour is normal and must be said.** Enumerated fields
  (`OperationType` → `%%1904`), event semantics and version-specific behaviour should be
  resolved **on the box** — Event Viewer's General tab, or `.Message` — not recalled from
  memory and presented as fact.

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
- **A cap plus a partial paste invents a missing population — cost time 2026-09-12.** Three
  rows reported back from a `-MaxEvents 5` query were read as "only three of these events
  exist," which made the host look like it had stopped logging process creation and produced a
  confident, entirely fictional anomaly. `Measure-Object` returned **1311**. This is the mirror
  of the filter-first trap above: there a cap hides *old* matches; here a cap plus an incomplete
  reply manufactures an *absent* one. **Confirm a count with `Measure-Object` before treating a
  small number as a result**, and when a count is surprising, suspect the query and the
  transcription before inventing a mechanism.
- **`Where-Object { $_.Message -like '…' }` matches the whole event, not the field you meant.**
  Hunting Sysmon Event 1 for `'*Notepad.exe*'` returned a **`reg.exe`** process, because
  `Message` contains every field and that process's *command line* mentioned `notepad.exe`.
  Extract the field first, then filter on it.
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
