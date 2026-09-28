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
the next steps, and is the file to update as modules complete. Modules 00–05 are complete
with findings written and evidence in `assets/`; `main` is pushed through **Module 06** —
check `git log origin/main..main` rather than trusting this line.
**Module 06 is NEARLY COMPLETE** (written 2026-09-13; four sittings 2026-09-13 → 2026-09-16,
plus a closeout sitting 2026-09-25; lab work done, all five findings written, ten screenshots
filed, **Step 8 baseline table now fully read on both VMs** — only **two screenshots**
outstanding) — see its section below. The rest are planned — see
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

### Module 06 (Windows Firewall) — NEARLY COMPLETE

Written 2026-09-13 (`labs/06-windows-firewall.md`); four sittings 2026-09-13 → 2026-09-16,
**both VMs**. The run sheet is rewritten from the run, **all five findings are complete**
(observation → inference → recommendation), Step 7 is rewritten as 7.0–7.7, the Step 8 baseline
table is **complete — every cell read on one machine or the other**, the last of them on
2026-09-25 — and ten screenshots are filed in `assets/`. Outstanding: **two screenshots only**.

**The module's result, established by controlled experiment and not by argument.** Three TCP
knocks from WS01 to DC01 port 9999 (nothing listening, no rule) produced **nothing** in
`pfirewall.log` and **nothing** in 5157 — while both instruments were demonstrably alive (the
text file held an unrelated ICMP `DROP`; the 5157 query returned unrelated events). They appear
only as **5152**, whose subcategory is **off by default**. One variable changed at a time:

| Listening on the port? | Explicit block rule? | `Filter Origin` | App in 5152 | In `pfirewall.log`? |
|---|---|---|---|---|
| No | No | `Stealth` | `-` (PID 0) | No |
| No | **Yes** (readback-verified) | `Stealth` | `-` (PID 0) | No |
| **Yes** (`TcpListener`) | Yes | `Query User Default` | **`powershell.exe`** | **Yes** |

So **stealth mode intercepts packets to closed ports before rules are consulted**, `pfirewall.log`
only records a drop *after* that point, and 5152 names the **local** process only where one exists.
A port scan is overwhelmingly closed ports, so the firewall's own log file is blind to it.

**Verified during the run — only what the user pasted back:**

| Fact | Evidence |
|---|---|
| **4946 and 4948 carry no account** | fields are Profile Changed / Rule ID / Rule Name; `.Message` adds nothing; `Event.System.Security` **empty on both** — the 4946 run as a control |
| Firewall rule changes are **routine noise** on DC01 | **4** × 4946 and **7** × 4948 with nobody attacking; **3 of the 4946s appeared overnight unattended**, which made the hand-written one the **oldest** — `-MaxEvents 1` returns the wrong event |
| `pfirewall.log` stamps **local** time | header line `#Time Format: Local`; the event log stores UTC, so the text file reads one hour *ahead* here |
| `Protocol: 6` = TCP | IANA number; the event does not spell it out |
| **`Test-NetConnection` creates no process**, so no 4688 | a ±1-minute window around a knock returned **zero** 4688s, against 308 in the surrounding 20 minutes |
| WS01's firewall records **nothing** about its own outbound knock | WS01's 5152 channel proven alive first (**7** unrelated inbound drops, e.g. to `10.0.0.20:53`), then no knock in it — outbound default is allow, so nothing was blocked to log |
| DC01 `Firewall Policy` | `BlockInbound,AllowOutbound`, Public profile |
| Ping was already allowed before the module started | two enabled allow rules on DC01 — `File and Printer Sharing (Echo Request - ICMPv4-In)` on Public, and an **AD Domain Controller** echo rule on **Any**. DC promotion enables its own firewall rules; live since Module 00 |
| **Block beats allow** at the network layer | one scoped block rule overrode both allow rules; ping went `True` → `False` → `True` on delete. Same principle as NTFS |
| `wf.msc` **works on WS01** | unlike `gpedit.msc`/`gpupdate`, which remain broken. Firewall build steps can be GUI clicks |

**Traps this module added, beyond the ones already listed further down:**

- **Sysmon Event 3 does not see a probe of a closed port** — verified 2026-09-16 by controlled
  experiment (0 for three unanswered knocks, 1 for one completed connection, rule unchanged).
  It is an *attribution* instrument for connections that succeed, not a scan detector.
- **A mistyped event ID is indistinguishable from a genuine absence.** `Id=49466` returns
  `NoMatchingEventsFound` — the same message as a real empty result. It briefly looked like log
  rotation had destroyed DC01's 4946s. **Suspect the query before the host**, and retype before
  theorising.
- **`auditpol /get /subcategory: "…"` with a space after the colon** fails with
  `Error 0x00000057 … The parameter is incorrect.` and dumps usage text that reads like a broken
  tool rather than a typo.
- **A terminal screenshot with no hostname in the frame is weak evidence.** Both VMs prompt
  `PS C:\Users\Administrator>`. `06-auditpol-before.png` is a genuine, unrepeatable baseline whose
  host can no longer be established. Put `hostname` at the top of any capture meant as evidence.
- **A knock on a closed port is a *packet*, never a *connection*.** `Filtering Platform
  Connection` (5156/5157) and `Filtering Platform Packet Drop` (5152/5153) are **separate
  subcategories**. Watching only the first gives silence with no error.
- **An expectation that cannot fail is not evidence.** Step 7.1 was written as "run the query on
  WS01 and expect nothing" — but WS01's packet-drop subcategory was still `No Auditing`, so the
  empty result was meaningless. It only became evidence after the switch was enabled and the
  channel proved itself with 7 unrelated events. **Verify the instrument before trusting a
  silence you predicted.**
- **Process-creation logging records a program *starting*, not what it does afterwards.** A shell
  open for an hour writes one 4688 and then does a hundred invisible things. Cmdlet activity
  inside an existing session is not visible to 4688 at all.

**Unexplained, recorded as observations, no cause established:**

1. **DC01 sits on the `Public` firewall profile** while WS01 is on `Domain`, with the domain
   otherwise healthy. Only `LogBlocked` and per-rule profile ticks are affected, so it did not
   block the module — but **read the active profile on each machine separately**, never assume.
2. **Row 3 of the matrix reads `Query User Default`, not the block rule's name**, although that
   rule was present, enabled and matching. Precedence between the query-user filter and an
   explicit rule was **not investigated**.
3. **WS01 wrote 308 × 4688 in 20 minutes** on 2026-09-15, against Module 04's measured ~0.26
   MB/day in August. The window included a boot, so it may not be a real rate change. **Not
   measured properly.** If it is real, WS01's Security log fills in about a day.

**Sitting 4 (2026-09-16) closed the attribution question the other way.** Sysmon was armed
*before* the break with `<NetworkConnect onmatch="include"><DestinationPort condition="is">9999`,
applied and confirmed in the live-config readback. **Three unanswered knocks → 0 Event 3s**
(against 373 Event 1s in the same window). Then a `TcpListener` plus a readback-verified inbound
**allow** rule on DC01 made the far end answer: the identical knock returned `True` and produced
**exactly one** Event 3 — `Image …\powershell.exe`, `User CORP\Administrator`,
`SourceHostname WS01.corp.local`, `DestinationHostname DC01`, `Initiated true`, `ProcessGuid`
joining to Event 1. **One variable moved: whether DC01 answered.**

So **Sysmon `NetworkConnect` records connections that COMPLETE, not attempts that go
unanswered** — the same structural reason 5157 never fires for a closed port. **Finding 2 was
rewritten**: no instrument in this lab can attribute a probe of a closed port. Not
distinguishable from this evidence: "completed" vs "received any response" — an **RST** test
would discriminate and has **not** been run.

**Lab state left behind (2026-09-16):**

- **`mod06-start` snapshots exist on both VMs.**
- **Audit switches left ON deliberately**, both VMs: `Filtering Platform Connection` = Failure,
  `MPSSVC Rule-Level Policy Change` = Success, `Filtering Platform Packet Drop` = Failure.
  All re-read on 2026-09-16 except `Filtering Platform Connection`/DC01 and `MPSSVC`/WS01.
  **`Filtering Platform Connection` Success is deliberately OFF** — it logs every *allowed*
  connection and would destroy the log per Module 04.
- **`LogBlocked` = True**, on **DC01/Public** and **WS01/Domain** — the profiles that are actually
  active, which differ per machine. **Not re-read on 2026-09-16.**
- **All lab firewall rules gone, both deletions confirmed by readback.** `Lab Block Ping from
  ws01`, `lab Block tcp9999 from ws01` and `Lab Allow TCP9999 from WS01` all return
  "no matching objects found"; port 9999 confirmed closed.
- **`lab Block tcp9999 from ws01` was found still present and enabled on 2026-09-16**, having
  been reported deleted on 2026-09-15 with no readback. **A `Remove-` that ran is not a rule that
  is gone.** This is now Finding 5's third instance.
- **Sysmon on WS01 now carries the `NetworkConnect` rule** alongside the registry group — scoped
  to `DestinationPort is 9999` only, so it cannot flood. **Leave it; Module 07 extends this group
  to RDP rather than rebuilding it.** Verified: a `NetworkConnect` element sits legally as a
  direct child of `<EventFiltering>`, as a sibling of the existing `<RuleGroup>`.
- **DC01 is still on the `Public` profile** after an unplanned shutdown and reboot on 2026-09-16
  (`06-firewall-profiles.png`). Still no cause established.
- **DC01 shut down unexpectedly mid-sitting** on 2026-09-16. The 1074/6008 diagnosis was
  **deliberately skipped by the user**; cause unknown. Eval-licence expiry is the known prior
  (2026-09-04), not a verified cause here.

**`06-sysmon3-zero.png` was deliberately not captured** — a decision by the user on
2026-09-25, to avoid holding up Module 07. Module 07 Step 3.2 then added port 3389 to the Sysmon
config, so the re-derivation described above is **no longer available** and the screenshot is
**permanently outstanding**. The underlying result is unaffected: Finding 2 rests on the
2026-09-16 run, where three unanswered knocks produced 0 Event 3s against 373 Event 1s, and the
Event 3 count was independently confirmed to still be **1** on 2026-09-25 before any config
change. The missing item is the illustration, not the evidence.

**What is left to finish Module 06 — one screenshot, `06-5152-ws01-empty.png`.** The six `Get-NetFirewallProfile`
readbacks were taken on **2026-09-25** and the Step 8 table is now fully populated from command
output on both VMs. Remaining: `06-5152-ws01-empty.png` only.

**The 2026-09-25 readbacks closed three open unknowns.** `LogBlocked` **survived the
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

**Ten screenshots are filed in `assets/`**, each verified against its actual contents before
filing rather than trusted by filename: `06-5152-stealth.png`, `06-rule-verified.png`,
`06-sysmon-attribution.png`, `06-auditpol-before.png`, `06-firewall-profiles.png`,
`06-4946-rule-added.png`, `06-4946-allow-rule-added.png`, `06-4948-rule-deleted.png`,
`06-4948-extended.png`, `06-no-attribution.png`. **No `.evtx` export was taken** — a deliberate
decision by the user on 2026-09-15, on the grounds that lab activity is regenerable on demand. If
logs roll, the timestamps cited in the findings must be regenerated and the findings edited to
match.

**Three things reading the screenshots corrected, which is why they must be read and not
trusted by filename:**

1. **`06-auditpol-before.png` exists and is genuine** (2026-09-13 14:08) — it had been written
   off in-session as uncapturable. **Which host it is from is not recoverable from the frame**;
   the prompt is `PS C:\Users\Administrator>` on both machines. A terminal screenshot without a
   hostname is weak evidence — put `hostname` at the top of the capture.
2. **The "DC01's 4946s have vanished" scare was a typo**, preserved in `06-no-attribution.png`:
   `Id=49466` returns `NoMatchingEventsFound`, the **identical** message a genuine empty result
   gives. A log-rotation theory was half-built on it before the retype cleared it. **Suspect the
   query before the host.**
3. **Rule names in the log differ in case from the run sheet's**: `Lab Block Ping from ws01`,
   `lab Block tcp9999 from ws01`, `Lab Allow TCP9999 from WS01`. `-DisplayName` matching is
   case-insensitive so it only bites when comparing by eye — but findings must quote what the log
   printed. Also verified: `ProfileChanged` reads `(null)` for a single-profile rule and `All`
   for `-Profile Any`.

### Module 07 (Remote Desktop) — IN PROGRESS, sittings 1–2 complete

Written 2026-09-22 (`labs/07-remote-desktop.md`). **Sitting 1 ran 2026-09-25 in two parts and is
complete** — Steps 0–3. WS01 only so far.

**Lab state on WS01 after sitting 1 — all readback-verified:**

- **Remote Desktop is ON.** `fDenyTSConnections` = **0** (double negative: zero means enabled).
- **NLA is ON.** `UserAuthentication` = **1**. **This is Step 9.5's restore value** — Step 9 turns
  NLA off deliberately and must put it back to `1`.
- **`asmith` is in WS01's local `Remote Desktop Users`**, `PrincipalSource` = `ActiveDirectory`.
- **Sysmon config now carries port 3389 alongside 9999** in the existing `NetworkConnect` include
  group; `Configuration updated` returned and the live readback showed both ports **and** the
  Module 03 registry rules intact. The registry rules must keep surviving — Modules 03 and 06
  depend on them.
- **WS01 is on `DomainAuthenticated`** (the Domain profile), read via `Get-NetConnectionProfile`.
- Baselines from part 1, to compare against after the break: Security **4624 = 172**, Sysmon
  **Event 3 = 1**, `LocalSessionManager` **725 records**, `RemoteConnectionManager` **0 records**.

**Unconfirmed and carried as unknown, not done:** `sysmon-registry.xml.bak` (issued with the edit,
never confirmed), `assets/07-sysmon-config.png` (asked for, not confirmed — recoverable, the
config re-reads on demand) and the schema version in the readback. **The 4732 is now found** — see
sitting 2 below.

**The result sitting 1 produced, and it killed one of the sheet's own predictions.** The run sheet
said to watch for a **4946** when enabling RDP's firewall rules. There was **none**. There were
**seven 4947s in a two-second burst at 09:39:25–09:39:26 UTC** — one programmatic action, not a
person clicking. The Remote Desktop rules **already existed**, shipped disabled; enabling RDP
flipped `Enabled` and Windows logged **modified**, not **added**.

- **4946 = "a rule that was not there before now is." 4947 = "an existing rule changed."** A
  firewall hunt written only for 4946 **misses a host being opened up to RDP entirely**. Candidate
  for the module's Finding 5.
- **Not established: seven 4947s for three rules.** `-DisplayGroup 'Remote Desktop'` returned
  three (`Shadow (TCP-In)`, `User Mode (TCP-In)`, `User Mode (UDP-In)`, all `Enabled: True`, all
  **`Profile: Any`**). No cause established; not chased.
- **Three 4948s at 09:37:18, 09:48:02, 09:55:10 UTC are NOT this module's** — scattered, one
  before the burst and two after. Module 06 saw unattended firewall rule-change noise on **DC01**;
  this is the **first sighting on WS01**, and rules being deleted roughly every seven minutes with
  nobody touching the machine has **no established cause**. The oldest row sat **on the query's
  window boundary**, so the series may run further back than the query could see.

**Two cmdlet traps added:**

- **`Get-NetFirewallProfile` does not tell you which profile is active.** It lists all three, each
  reading `Enabled: True`. **`Get-NetConnectionProfile`** gives the `NetworkCategory` actually in
  use. This is the second way that cmdlet misleads — Module 06 found it reads the *configured*
  store by default and returns `DefaultInboundAction: NotConfigured`.
- **The shipped Remote Desktop rules are `Profile: Any`**, so the per-profile worry does not bite
  for RDP itself on this host. It remains real for hand-written rules.

**A screenshot arrived that was evidence for a different module.** A 2026-09-15 capture of the
three `Test-NetConnection` knocks to `10.0.0.10:9999` — all `TcpTestSucceeded: False` with
`PingSucceeded: True` at 1 ms — is **Module 06's ground truth** for Finding 2, showing a closed
port on a live host rather than an unreachable host. **It identifies its own host from inside the
frame** via `SourceAddress : 10.0.0.20`, which is stronger than the `PS C:\Users\Administrator>`
prompt that left `06-auditpol-before.png` unattributable. **Not yet filed** — offered and not taken
up.

**Sitting 2 ran 2026-09-28 — Steps 4–7 complete, WS01.** Two RDP sessions made from DC01, found in
all four logs and joined. **Resume at Step 8**; Steps 8–11 are the last sitting on the VMs, and the
Findings section after them is desk work. **Step 9 must end with `UserAuthentication` back to `1`,
readback-verified.** `asmith`'s five-attempt lockout threshold is live through Steps 8 and 9 —
`Unlock-ADAccount -Identity asmith` on DC01 is the recovery.

**The module's result, and the Security log does not survive it well.** One RDP attachment writes
**three 4624s**: two **Type 3** network logons with subject Logon ID `0x0` (NLA checking
credentials before a session exists), then the **Type 10**, subject `0x3E7` (SYSTEM). So counting
Type 10s over-counts sessions by one per reconnect, and counting a user's 4624s over-counts by
three. The interactive session was **`0x4F246D`, 4624 at 09:30:26 → 4647 at 09:42:20 UTC**, carried
by **479 events** including **154 × 4688** — a genuine pivot from "who logged on" to "what the
session did". **Not one of those 479 events marks the 3m30s the user was detached** (09:37:33 →
09:41:03).

**The newest matching event is not the right event.** `-First 1` on the `asmith` 4624s returned
`0x741EE0` — Type 10, source `10.0.0.10`, indistinguishable from the session — which got a **4634
nine seconds later** and had ended before the user was back at the desktop. Read the whole set
before picking one.

**Unplanned controlled experiment, and the sitting's strongest finding.**
`auditpol /get /subcategory:"Other Logon/Logoff Events"` returned **`No Auditing`** — a **third**
switch, distinct from the `Logon` and `Logoff` subcategories verified in sitting 1. So the missing
4778/4779 were the instrument, not Windows. Enabled with `/success:enable`, readback confirmed,
boundary marked at 12:55:18 UTC, identical activity repeated → **four events where there had been
none**, and **nothing before the boundary**. Auditing is not retroactive; the morning disconnect is
permanently unrecoverable. **4778/4779 are not RDP events** — they track *any* window-station
attach/detach, `Session Name` separating `Console` from `RDP-Tcp#N`. The extra pair is
**Administrator's console session being displaced** when `asmith` connected, which is what an RDP
logon onto an occupied machine looks like from both sides.

**`Other Logon/Logoff Events` = Success is now lab state on WS01. Leave it on** — Module 06
precedent, and it is the only instrument that caught the console displacement.

**LocalSessionManager is the log that tells the story**, in two lines where the Security log needed
479 events to miss it: `21` logon, `24` **disconnected**, `25` **reconnected**, `23` logoff. Both
sessions recovered in full with per-event attribution.

**Verified during the run — only what the user pasted back:**

| Fact | Evidence |
|---|---|
| **Fields live at `.Event.UserData.EventXML`** as named elements (`User`, `SessionID`, `Address`) | `EventData.Data` returned **nothing**, as the sheet predicted. A **third** shape, distinct from `EventData.Data`-with-`Name` and from 1102's `UserData.LogFileCleared` |
| **`Address` separates remote from local in one field** | `LOCAL` for Administrator's console sessions, `10.0.0.10` for `asmith`'s RDP. The Security log needs Type 10 *plus* a source address to say as much |
| **This channel logs local logons too** | Administrator console 21/22 at 09:50:21, 11:30:33, 13:40:17. A hunt on ID 21 alone is not an RDP hunt |
| **SessionIDs are reused and unordered** | morning session **3**, afternoon session **2** — same user, same machine, same day, later session with the *lower* number. Identifies a session only within a time window |
| **The `23` carries no `Address`** | a hunt reading only session endings loses the source IP |
| 1149 names **`asmith@corp.local`** and source `10.0.0.10` | RemoteConnectionManager held **0 records** at baseline, so everything in it is this module's |
| **5 × 1149 for two sessions** | credentials accepted more than once per session. **No cause established.** 258/261/263/1136/20523/20524 in that channel were **never resolved on the box** |
| **Sysmon Event 3 logs the inbound half** — closes Module 06's open question | total **11** against a baseline of **1**; `Initiated: false`, `SourceHostname DC01`, `DestinationPort 3389` / `ms-wbt-server` |
| **…but it attributes a machine, never a person** | `Image: svchost.exe`, `User: NT AUTHORITY\NETWORK SERVICE`. `asmith` appears nowhere. Module 06's outbound event named `powershell.exe` and the real user — the receiving end cannot |
| **Sysmon prints `UtcTime` explicitly** | the only instrument here that does; every Windows channel displays local and stores UTC |
| **4732 from the Step 3.1 group addition exists** | one event, 2026-09-25 10:14:46 UTC. Closes a sitting-1 unknown |

**No single field spans the four logs, and one identity has four spellings** — `asmith` + `CORP`
(4624), `asmith@corp.local` (1149), `CORP\asmith` (LocalSessionManager), `NT AUTHORITY\NETWORK
SERVICE` (Sysmon). **No two match as strings**, so one hunt string cannot search all four — the
same shape as Module 03's `\REGISTRY\MACHINE\` vs `HKLM\`. The join is made in **hops**: Logon ID
ties the Security log to itself, SessionID ties the session log to itself, **nothing carries
both**, so the bridge is user + source address + a ~1 s timestamp coincidence. **Two sessions from
one user within a minute would be separable only by timestamp** — a real limit, stated as one.

**Each log answers exactly one question:** Sysmon *where from* (machine), 1149 *who*,
LocalSessionManager *what happened to the session*, Security *what the session did*.

**Traps this sitting added:**

- **The wrong-*channel* trap, which nearly produced a false finding.** `Id=24,25` against
  **RemoteConnectionManager** returns `NoMatchingEventsFound` — identical to a genuine absence, no
  error. It briefly looked like this build does not record RDP disconnects at all. The two channels
  divide the work: **RemoteConnectionManager is the connection, LocalSessionManager is the
  session.** Same family as the wrong-machine trap already on record.
- **`Select-String` emits match objects, not text.** Piping a DateTime and MatchInfo together
  makes PowerShell fall back to list view and bury the answer under `IgnoreCase`/`LineNumber`/
  `Path`. Use `.Line` (or `.Line.Trim()`) to get the matched text.
- **4624 carries two `Account Name` and two `Logon ID` fields.** **Subject** is who requested the
  logon (usually the machine account, `0x3E7` = SYSTEM); **New Logon** is the account logged on.
  Hunting the first one returns the machine account on every event.
- **`4647` ≠ `4634`.** The interactive session ended with **4647** ("user initiated logoff"); the
  transient one got **4634** ("session was terminated"). A hunt for 4634 alone misses the
  deliberate sign-out.

**Unexplained, recorded as observations, no cause established:**

1. **4624 queries with a 4-hour window returned nothing** although the events sat well inside it.
   Rotation, message rendering and window boundary were each tested and excluded. Likeliest
   candidate is that a `-MaxEvents 50` variant was the one that actually ran — **not established**.
2. **Noted times and logged times disagree by up to a minute, in both directions.** Morning
   disconnect: log 09:37:33, noted 09:38:35. Afternoon: log 12:59:49, noted **12:59:04** — the note
   *precedes* the event, which switching windows to type a timestamp cannot explain. Possible clock
   skew between DC01 and WS01. **Not measured.**
3. **479 Security events from one twelve-minute session**, against Module 04's ~0.26 MB/day
   measured in August. Consistent with Module 06's parked 308-per-20-minutes observation. Still
   **not measured properly** — no window controlled for a reboot.

**Evidence: two `.evtx` exports on WS01** — `C:\evidence\07-security.evtx` and
`C:\evidence\07-lsm.evtx`, taken 2026-09-28 before anything could roll. Not in the repo.

**Six screenshots exist on the Windows machine and none are in `assets/`** — pasting into a chat
does not put them on disk. From sitting 1: `07-sysmon-config.png`, `07-4947-rules-modified.png`.
From sitting 2: `07-1149-auth.png`, `07-session-lifecycle.png`, **`07-session-attribution.png`**
(the User/SessionID/Address table — the cleanest single image this module has produced), and the
`Group-Object` breakdown of the 479 events.

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
- **Wrong *channel* is as silent as wrong machine.** `Id=24,25` against
  **TerminalServices-RemoteConnectionManager** returns `NoMatchingEventsFound`; those IDs live in
  **LocalSessionManager**. No error, and the message is identical to a genuine absence. Verified
  2026-09-28 — it nearly produced a finding that Windows does not log RDP disconnects. Add
  "wrong channel" to the empty-output checklist below, next to "wrong machine".
- **`Select-String` returns match objects, not text.** Piping a DateTime and MatchInfo into one
  stream makes PowerShell fall back to list view and bury the value under `IgnoreCase`,
  `LineNumber`, `Path`, `Pattern`. Use `.Line` or `.Line.Trim()`.
- **If `EventData.Data` is empty, check `UserData` — and then go one level deeper.** The
  TerminalServices channels store fields at **`.Event.UserData.EventXML`** as named elements
  (`User`, `SessionID`, `Address`), not as `Data` entries with a `Name` attribute. `.Event.UserData`
  alone prints only the wrapper. A **third** field shape, after `EventData.Data` and 1102's
  `UserData.LogFileCleared`.
- **The newest matching event is not the right event.** `-First 1` on `asmith`'s 4624s returned a
  Type 10 logon from the correct source address that was a **nine-second** transient, not the
  interactive session. Read the whole set, then pick.
- Empty output is not an error. Check in order: wrong machine → **wrong channel** → window too narrow or
  starved → **events overwritten** → channel disabled → auditing actually off.
- **To judge rotation, read `oldestRecordNumber` from `wevtutil gli <log>` — NOT `FileSize`
  against `MaximumSizeInBytes`.** Verified on WS01 2026-09-25:
  `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` reported `FileSize`
  **exactly equal** to `MaximumSizeInBytes` (1,052,672) while holding only 725 records and an
  `oldestRecordNumber` of **1** — i.e. nothing had ever been discarded. **An event log file is
  allocated at its configured size regardless of how full it is**, so the two numbers matching
  means nothing about rotation. `oldestRecordNumber` = 1 is the reliable proof a log has never
  wrapped; anything higher is the count already lost. This corrects the earlier guidance here,
  which read the size comparison as diagnostic and produced a confident wrong call about a log
  rotating when it never had.

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
