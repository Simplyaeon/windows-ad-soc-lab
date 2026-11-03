# Module 08 — Domains, Forests & Domain Controllers

> **Runs on:** DC01 only. WS01 is not needed and should stay powered off
> **Time:** ~2 hours, split across two sittings
> **Roll back to:** `mod04-start` · **Snapshot before starting:** `mod08-start` (DC01)
> **Status:** ✅ **complete 2026-11-03.** Written 2026-10-01; sitting 1 ran 2026-10-12 (Steps 0–5),
> sitting 2 ran 2026-10-23 (Steps 6–9, 11), and the four sitting-1 screenshots were recaptured on
> 2026-11-03, when they were found never to have been taken. Both run logs and three findings are
> below. Everything marked **prediction** in the steps is the expectation as written *before* the
> run; where the run disagreed, a **Run result** note says so.

---

## What you're going to do

Every module so far has looked at one machine's own records — its files, its registry, its
firewall, its sessions. This one looks at the thing that makes the two machines a *domain*
rather than two unrelated computers: the **directory**, and the server that holds it.

`corp.local` has existed since Module 00 and you have been using it the whole time — `asmith`
logging into WS01, `fin_user` being denied a file, Kerberos tickets being issued. **You have
never once looked at the database all of that comes out of.** That is what this module is for.

You will read the shape of the directory, find out which special jobs DC01 is holding, locate
the two files on disk that *are* the domain, and then — the part that matters for a SOC —
discover that **changes to the directory are not logged by default**, switch that on, and watch
a change appear.

### This module is deliberately shaped differently

Modules 01–07 all ran **Build → Break → Detect**: make an admin capability, use it, find it in
the logs. Module 08 is mostly **reference**. There is no attacker action here, and the roadmap
lists its event IDs as "(concepts)". That is honest — this module exists because Modules 09–12
are unreadable without it, and Kerberos (Module 12) especially.

But a reference module with no detection work in it would be a wasted sitting, so the second
half borrows the one thing that genuinely belongs here: **finding out whether this DC records
changes to its own directory**, and switching it on if not.

### One limitation, stated up front

**This lab has one domain and one domain controller, so two of the roadmap's intended
deliverables cannot exist.**

- **There are no trusts.** A trust is a relationship between two *forests* or two *domains*.
  `corp.local` is a single domain in a single forest, so the trust diagram the roadmap asks for
  would be a box with nothing attached to it.
- **There is nothing to replicate.** Replication is how multiple DCs agree on the directory's
  contents. With one DC there is no second copy to disagree.

**Neither is a fault in the lab and neither is being worked around.** Step 4 runs the trust
query anyway and records the empty result as a documented baseline — *this is what no trusts
looks like, and this is the query that would show one.* Knowing what an empty result means is
exactly the skill this journal has spent seven modules building.

### The question this module is really asking

Modules 02 and 03 found the same structure twice. Object-access auditing in Windows is gated at
several independent layers, and closing any one of them makes an expected event vanish **with no
error anywhere**:

| Module | Store | The subcategory gate | The object gate |
|---|---|---|---|
| 02 | NTFS files | `File System` | the SACL's audited rights (`WRITE_DAC`) |
| 03 | The registry | `Registry` | the SACL's audited rights (`Set Value`) |
| 08 | **Active Directory** | **`Directory Service Changes`** | the SACL's audited rights (`CreateChild`, `WriteProperty` — and, untested, `Delete`) |

**The hypothesis is that the pattern holds a third time, in a completely different store.**

If it does, it is no longer a filesystem quirk or a registry quirk — it is **how Windows object
auditing works everywhere**, and that is a genuinely transferable result rather than a lab
curiosity. If it does not hold, that is a more interesting finding still.

> **This is a hypothesis, not a fact.** It has not been tested on this host. Steps 6–9 test it by
> reading the gates first, then changing one, then generating identical activity on both sides of
> the switch.

In this module you will:

1. Read the shape of `corp.local` — forest, domain, and the one DC in it
2. Find out which of the five special jobs (FSMO roles) DC01 holds
3. Locate the two things on disk that physically *are* the domain
4. Run the trust query and record an empty result as a baseline
5. Inventory the logbooks AD keeps about itself, and measure how long DC01's Security log holds
6. Read the four `DS Access` audit gates **before** changing anything
7. Open the one gate that is off, and put a SACL on a scoped test OU
8. Make three benign directory changes
9. Find them — and find out which of the three the log actually kept
10. Write the forest inventory and FSMO role map

**Every step says which VM, and for this module the answer is always DC01.** A query run on WS01
returns empty rather than an error — that has cost this lab real time more than once.

---

### Four ideas you need first

**A domain is an administrative boundary with one shared account database.** Every account in
`corp.local` — `asmith`, `fin_user`, `svc_backup`, and the two computer accounts DC01 and WS01 —
lives in one database, and every machine in the domain trusts it to say who is who. That is why
`asmith` can log into WS01 without WS01 holding a copy of the password.

**A forest is the outermost boundary, and it is the real security boundary.** A forest contains
one or more domains. People often say the domain is the security boundary; it is not — the
*forest* is, because the schema and the Enterprise Admins group are forest-wide. `corp.local` is
a forest containing exactly one domain, which is also called `corp.local`. That is the ordinary
case for a small organisation.

**A domain controller is a server holding a writable copy of that database.** Real domains run at
least two so that one can fail. This lab runs one, which is why Step 4 finds nothing to replicate.

**FSMO roles are the five jobs that cannot be done by committee.** Most of what a DC does, any DC
can do. Five specific tasks cannot — they need exactly one DC to be in charge, or two DCs could
make conflicting decisions. Those five jobs are called **FSMO roles** (Flexible Single Master
Operation), and in a one-DC domain all five are on the same machine by definition.

The two that matter most to a SOC analyst:

- **PDC Emulator** — among other things, it is the domain's **authoritative clock**, and it is
  where account lockouts are processed. Kerberos refuses tickets when clocks are more than five
  minutes apart, so this role failing breaks authentication domain-wide. Module 07 parked an
  unexplained observation about DC01 and WS01 clocks disagreeing by up to a minute; this is the
  machine that would be at fault.
- **RID Master** — hands out the pools of numbers used to build new account SIDs. Without it you
  eventually cannot create accounts.

---

# Run log — Sitting 2 (2026-10-23, Steps 6–9 and 11 complete, DC01)

Only what was pasted back or shown in a screenshot is recorded as verified. Three predictions
held, one failed, and one change happened that the run sheet never planned. The findings are
written further down this file.

## Steps 6–8 — gates read, gates opened, three changes made

| Step | Read | Result |
|---|---|---|
| 6.1 | `auditpol /get /category:"DS Access"` | **prediction held.** `Directory Service Changes` **No Auditing**, `Directory Service Replication` No Auditing, `Detailed Directory Service Replication` No Auditing, `Directory Service Access` **Success**. `hostname` → `DC01` in frame. `08-ds-access-gates.png` (taskbar 10:35 AM local, UTC+1) |
| 6.3 | boundary, `(Get-Date).ToUniversalTime()` | **09:38:38 UTC** 2026-10-23. Everything before this is the control |
| 7.1 | `auditpol /set … "Directory Service Changes" /success:enable`, then `/get` | readback **Success**. **First change made to DC01 in this module** |
| 7.2 | `New-ADOrganizationalUnit LabAudit`, then `Get-ADOrganizationalUnit` | `DistinguishedName : OU=LabAudit,DC=corp,DC=local`. Created with the subcategory **on** and **no SACL yet** — the 9.4 control. **Not individually timed** |
| 7.3 | SACL via `dsa.msc` (Everyone, Success, this object and all descendants, Write all properties + Create all child objects) | reported done by the user; no screenshot (optional, declined). Verified in 7.4 |
| 7.4 | `(Get-Acl 'AD:/OU=LabAudit,…' -Audit).Audit` | **verified.** Entry 1: **`CreateChild, WriteProperty`**, `ObjectType` all-zero (all properties), `InheritanceType All`, `Success`, `Everyone`, **`IsInherited False`** — the 7.3 rule, both rights printed by name. Entries 2 and 3 **were not added by us**: `WriteProperty` on `ObjectType` `f30e3bbe-…` / `f30e3bbf-…`, `InheritedObjectType bf967aa5-…`, **`IsInherited True`**. What those GUIDs name is **not resolved on the box**. `08-sacl-readback.png` |
| 7.4b | `(Get-Acl 'AD:/DC=corp,DC=local' -Audit).Audit`, then `@(…).Count` | **5 entries, complete** — the count closed a frame whose bottom showed no prompt. (1) `WriteProperty, WriteDacl, WriteOwner`, Everyone, `InheritanceType None`; (2) `ExtendedRight`, BUILTIN\Administrators, `None`; (3) `ExtendedRight`, CORP\Domain Users, `None`; (4)/(5) `WriteProperty` on `f30e3bbf-…`/`f30e3bbe-…`, Everyone, `All`, **`IsInherited False`** — the source of `LabAudit`'s inherited entries. **No entry carries `CreateChild`.** `08-domain-sacl.png` |
| 8.0 | `(Get-Date).ToUniversalTime()` + `$start = Get-Date` | **09:58:10 UTC** |
| 8.1 | `Set-ADOrganizationalUnit … -Description 'module 08 test'`, readback with `-Properties Description` | `Description : module 08 test` (as relayed — the log prints `Module 08 test`; see 9.2) |
| 8.2 | `New-ADUser lab_dirtest -Path 'OU=LabAudit,…' -Enabled $false`, readback | `CN=lab_dirtest,OU=LabAudit,DC=corp,DC=local`, `Enabled : False` (as relayed — the log prints `Lab_dirtest`) |
| 8.3 | `Remove-ADUser … -Confirm:$false`, readback | `Cannot find an object with identity …` — the error is the confirmation |
| 8.end | `(Get-Date).ToUniversalTime()` | **10:10 UTC** (no seconds relayed). Step 8 window: 09:58:10 → 10:10 UTC |

**Why 7.4b was run.** It is **not established** whether a creation is audited against the new
object's SACL or its parent's. If the parent's, the control depended on the domain root's SACL,
which had not been read. It turned out not to matter for the 5137: when `LabAudit` was created,
neither it nor the domain audited `CreateChild`, so the control holds under both possibilities.

## Step 9 — what the log kept

| Step | Read | Result |
|---|---|---|
| 9.1 | `… Id=5136 \| Measure-Object` (no window) | **6** — for one deliberate modify |
| 9.2 | `$d = … Id=5136; StartTime=$start`, `@($d).Count` | **4** inside the Step 8 window, so **2 predate 09:58:10 UTC** |
| 9.2 `$d[0]` | `.Message` | **from 8.2.** `CORP\Administrator` `0x39279`; `CN=Lab_dirtest,OU=LabAudit,…`, Class `user`, GUID `{3b26da90-…}`; **`userAccountControl`** = **`514`**, `Value Added`; Correlation ID **`{4e555345-2e07-4428-998c-bf56feb2f96a}`**. `514` = normal + disabled is **recall**, consistent with `-Enabled $false` |
| 9.2 `$d[1]` | `.Message` | **from 8.2.** Same object; **`sAMAccountName`** = `Lab_dirtest`, `Value Added`; **same Correlation ID** |
| 9.2 `$d[2]` | `.Message` | **from 8.2.** Same object; **`objectClass`** = `1.2.840.113556.1.5.9` (raw OID — that it names `user` is **recall**), `Value Added`; **same Correlation ID** |
| 9.2 `$d[3]` | `.Message` | **the 8.1 change — prediction held.** `OU=LabAudit,DC=corp,DC=local`, GUID **`{6525648f-…}`** = the `ObjectGUID` read in 7.4; **`description`** = `Module 08 test`; **`Value Added` only**; Correlation ID **`{83c69c3e-b1cc-4686-bda6-55ddbfcb3701}`** — a separate operation. `08-5136-change.png` |
| 9.3 | `Measure-Object` on 5137, then 5141 (no window) | **5137 : 1. 5141 : 0 — the deletion prediction FAILED.** `lab_dirtest` is confirmed gone, so the delete happened and was not logged as a 5141 |
| 9.4 | `$c = … Id=5137`, `$c[0].Message` | **the control held.** The only 5137 on DC01 is `CN=Lab_dirtest,OU=LabAudit,…`, GUID `{3b26da90-…}`, `0x39279` — **no 5137 exists for `LabAudit`**. **Same Correlation ID `{4e555345-…}` as the three 8.2 5136s.** The 5137 carries **no attribute fields**. `08-sacl-control.png` |

`Get-WinEvent` returns newest first, so 8.1 — the first change made — was `$d[3]`, as predicted
before it was read.

**Two offered tests were declined by the user on 2026-10-23**, both recorded so the findings state
the limitation rather than imply a result:

- **A second change to the now-populated `description`**, which would have shown what a 5136 does
  when a plain string value is *replaced*.
- **Adding `Delete all child objects` to the SACL, then creating and deleting a second user**, which
  would have tested whether the missing 5141 is the SACL's rights mask.

**Fact relevant to the 5141 miss, verified in 7.4:** the `LabAudit` SACL's rights are
`CreateChild, WriteProperty` only — **no `Delete`, `DeleteChild` or `DeleteTree`** — and the
domain's SACL (7.4b) carries none either.

**⏸ Paused after 9.4; resumed the same day.** The PowerShell window was lost in the break, so
`$start` was re-set by hand — `Get-Date '2026-10-23 10:58:10'`, 09:58:10 UTC in DC01's UTC+1 — and
read back as `Friday, October 23, 2026 10:58:10 AM`.

## Step 9 (continued) — the two 5136s nobody planned

| Step | Read | Result |
|---|---|---|
| 9.2b | `$p = … Id=5136; EndTime=$start`, `@($p).Count` | **2** — matches 6 − 4, confirming the hand-set `$start` |
| `$p` times | `$p \| Select-Object TimeCreated` | **both 10:42:37 AM local = 09:42:37 UTC** — four minutes after the boundary, early in Step 7 |
| `$p[0]` | `.Message` | `CORP\Administrator` **`0x39279`** (today's session); **`DC=corp,DC=local`**, Class `domainDNS`, GUID `{df2288c6-…}`; **`nTSecurityDescriptor`**, `Value Added`; Correlation ID **`{8767bcc8-56e8-4850-9e00-9e094b4aa04a}`**. The value's `S:` section matches the five SACL entries read in 7.4b |
| `$p[1]` | `.Message`, relayed | same object, attribute and Correlation ID, **`Value Deleted`**. **One replacement**: old value out, new value in, same second, one ID |
| field names | `([xml]$p[0].ToXml()).Event.EventData.Data \| Format-Table Name` | 15 fields; value in **`AttributeValue`**, operation in **`OperationType`**, object in **`ObjectDN`** — two names that had been recall |
| lengths | each `AttributeValue` into `$a`/`$b`, `.Length` | **new 3540, old 3528** — the descriptor **genuinely changed**; not a save with nothing changed |
| diff | `Compare-Object ($b -split '\(') ($a -split '\(')` | **one piece, `D;;DC;;;WD)`, `=>`** (new only); nothing removed. `(D;;DC;;;WD)` is **12 characters — the length difference exactly** |
| decode | `ConvertFrom-SddlString -Sddl 'D:(D;;DC;;;WD)' -Type ActiveDirectoryRights` | **`Everyone: AccessDenied (DeleteChild)`** — resolved on the box |
| protection | `Get-ADOrganizationalUnit LabAudit -Properties ProtectedFromAccidentalDeletion` | **`True`** |

**What the evidence supports, and what it does not.** At 09:42:37 UTC, in the session running this
module, the domain root's DACL gained `Everyone: AccessDenied (DeleteChild)`, and the domain's own
SACL entry 1 (`WriteProperty, WriteDacl, WriteOwner`, Everyone) is what made the change auditable.
**The leading candidate cause is Step 7.2**: `New-ADOrganizationalUnit` created `LabAudit` with
accidental-deletion protection on, and that protection is recalled as adding exactly this entry to
the **parent**. Timing, content and the `True` flag all fit, and no competing candidate is known —
but 7.2 was not timed and the mechanism is recall, so it is **not established**.

## Step 9.5 — the export

| Step | Read | Result |
|---|---|---|
| 9.5 | `New-Item C:/evidence` (absent on DC01), `Set-Location`, `wevtutil epl Security 08-dc01-security.evtx` | prints nothing. **Coverage: oldest 7/28/2026, newest 2026-10-23 8:51 PM local** — all of DC01's history, including the whole of today |

## Step 11 — cleanup, and the deny entry that stayed

| Step | Read | Result |
|---|---|---|
| 11.1a | `Remove-ADOrganizationalUnit LabAudit -Confirm:$false` | **`Access is denied` — prediction held**, for the domain Administrator |
| 11.1b | `$clear = Get-Date` (about 8 PM UTC; exact value not relayed), `-ProtectedFromAccidentalDeletion $false`, readback | **`False`** (verified). **5136 since `$clear`: none** |
| 11.1c | `(Get-Acl 'AD:/DC=corp,DC=local').Sddl -like '*(D;;DC;;;WD)*'` | **`True`** — clearing `LabAudit`'s protection did **not** remove the entry from the parent |
| 11.1d | `Remove-ADOrganizationalUnit LabAudit`, readback `-Filter "Name -eq 'LabAudit'"` | readback **empty** — removed (the same query returned it in 7.2) |
| 11.1e | 5141 count; the domain-root `-like` check again | **5141 : 0** — the OU's deletion was silent too, with no delete right audited on it or the domain. **Deny entry: `True`** — **it outlives the OU that most likely caused it** |
| 11.2 | `auditpol /get /subcategory:"Directory Service Changes"` | **Success** — left on **by decision**. It also agrees with 7.1 at the end of the day, which is weak evidence against the GPO-overwrite hypothesis in the gotchas (no forced policy refresh was run) |

## Lab state at the end of sitting 2 — from readbacks, not memory

| Item | State | Read |
|---|---|---|
| `Directory Service Changes` | **Success** — left on deliberately | 11.2 |
| `Directory Service Access` | **Success** — unchanged since 6.1 | 6.1 |
| `Directory Service Replication`, `Detailed Directory Service Replication` | No Auditing — unchanged | 6.1 |
| `LabAudit` OU and its SACL | **removed**, confirmed absent | 11.1d |
| `lab_dirtest` | **deleted**, confirmed absent | 8.3 |
| **Domain root DACL** | **carries `(D;;DC;;;WD)` — Everyone denied DeleteChild — added 09:42:37 UTC 2026-10-23, most likely by 7.2's protected OU. Left in place and documented**; no removal requested | 11.1e |
| `C:\evidence\08-dc01-security.evtx` | on DC01; covers 2026-07-28 → 2026-10-23 8:51 PM local. Not in the repo | 9.5 |
| DC01 Security log | never wrapped (sitting 1) | 5.3 |

## Traps this sitting added

- **An undefined variable is silently `$null`.** `$sd[0]` (a typo for `$d[0]`) returned `Cannot
  index into a null array` — the error names the indexing, not the misspelling.
- **`-Confirm:$false` means "don't ask", not "don't do".** It suppresses the prompt and the action
  runs — `rm -f`, not a dry run. The readback settled it.
- **Variables die with the window.** Losing the PowerShell window lost `$start`; re-setting it by
  hand from the written-down UTC time, then checking it against a known count (2 = 6 − 4), made the
  re-set verifiable rather than hoped.
- **A readback can look complete and not be.** The 7.4b frame ended without a prompt; `@(…).Count`
  confirmed five entries before "no `CreateChild`" was concluded.
- **Before comparing two values for equality, prove neither is empty.** Two empty variables compare
  equal. `.Length` first — and here the lengths alone answered the question.
- **Relayed text drifts from logged text.** `module 08 test` and `lab_dirtest` were relayed
  lowercase; the log printed `Module 08 test` and `Lab_dirtest`. Findings quote the log.

---

# Run log — Sitting 1 (2026-10-12, Steps 0–5 complete, DC01)

Entirely read-only; nothing on DC01 was changed. WS01 stayed off. Only what was pasted back or
shown in a screenshot is recorded as verified.

## Every prediction in Steps 0–4 held

| Step | Read | Result |
|---|---|---|
| 0.1 | `mod08-start` snapshot | **taken** (reported by the user) |
| 0.2 | `hostname` | `DC01` |
| 0.3 / 1.2 | `Get-ADDomain -Current LocalComputer` | populated; `DNSRoot` `corp.local`, `NetBIOSName` `CORP`, `DistinguishedName` `DC=corp,DC=local`, `DomainMode` `Windows2016Domain`, `DomainSID` `S-1-5-21-3536249948-3294943055-3998780783`, `ReplicaDirectoryServers` `{DC01.corp.local}`, `ReadOnlyReplicaDirectoryServers` `{}` |
| 1.1 | `Get-ADForest` | `Domains` `{corp.local}`, `ForestMode` `Windows2016Forest`, `GlobalCatalogs` `DC01.corp.local`, `SchemaMaster` and `DomainNamingMaster` `DC01.corp.local` |
| 1.3 | `Get-ADDomainController -Filter *` | **one** DC: `DC01`, `IPv4Address` `10.0.0.10`, `IsGlobalCatalog` `True`, `IsReadOnly` `False`, `Site` `Default-First-Site-Name`, `Windows Server 2022 Standard Evaluation` `10.0 (20348)`, `LdapPort` 389 |
| 2.1 | `netdom query fsmo` | all five roles on DC01 |
| 3.1 | NTDS `Parameters` | `DSA Database file` = `C:\Windows\NTDS\ntds.dit` |
| 3.2 | `Get-SmbShare` | `ADMIN$`, `C$`, `IPC$`, `NETLOGON` (`C:\Windows\SYSVOL\sysvol\corp.local\SCRIPTS`), `SYSVOL` (`C:\Windows\SYSVOL\sysvol`) |
| 3.3 | `Get-ChildItem C:/Windows/NTDS` | `ntds.dit` + `edb.chk`, `edb.log`, `edb00001.log`, `edbres00001.jrs`, `edbres00002.jrs`, `edbtmp.log`, `ntds.jfm`, `temp.edb` |
| 4 | `Get-ADTrust -Filter *` | **no output** |

Step 2.2 was not run separately — it asks for the same five fields `Get-ADForest` and `Get-ADDomain`
had already returned in full, and `netdom` agreed with them.

**Step 4's empty result is a genuine absence, and the evidence for that is specific:** wrong machine
excluded by `hostname`; broken cmdlets or unreachable directory excluded by `Get-ADForest` returning
`Domains: {corp.local}` from the same module, same host, same morning; no cap was used; there was no
ID to mistype. **A populated result from the same tools, close in time, is what makes an empty one
trustworthy.**

**Step 1.2's SID prediction is untested, not confirmed.** Module 03 only recorded the `HKU` SID
abbreviated (`S-1-5-21-…-500`), and whether that `-500` was the **domain** Administrator or WS01's
**local** one was never recorded — the two have different prefixes. The comparison cannot be made
from the notes.

**Step 3.2, the analyst's sentence on why SYSVOL is worth watching** (verbatim): *"To see which
endpoint accessed the file."*

## Step 5 — the measurement

| | Value |
|---|---|
| `Directory Service` `RecordCount` | **1027** |
| `Directory Service` `MaximumSizeInBytes` | **1,052,672** (~1 MB — the same as WS01's LocalSessionManager) |
| Security `oldestRecordNumber` | **1** |
| Oldest Security event | **ID 4688, 2026-07-28** (displayed date) |

**DC01's Security log has never discarded anything and holds its entire history — about 76 days,
2026-07-28 → 2026-10-12. WS01's holds about one day** (measured 2026-09-29). The oldest event is not
a **1102**, so the log was not cleared. **No cause is established for the difference between the
hosts**; the first thing to compare is each log's `maxSize` from `wevtutil gli Security`, which was
not read back today.

**Consequence for sitting 2:** DC01 has no rotation deadline at its current rate, so Step 9's
evidence is not on the overnight clock Module 07's was. Step 7 adds a new audit subcategory at an
unmeasured rate, so **Step 9.5's export-first still stands**.

**`Directory Service`, newest 200 events, by ID** (`Group-Object Id`; counts sum to exactly 200):

| Count | Event IDs |
|---|---|
| 18 | 2405, 2406 |
| 12 | 330 |
| 9 | 1000, 1394, 1539, 2041, 2120, 2121, 2886, 3041, 3051, 3054 |
| 8 | 1869, 3027, 3033 |
| 6 | 102, 105, 326, 700, 701, 1004 |
| 1 | 702, 703 |

**Resolved on the box:** **1000 = "Microsoft Active Directory Domain Services startup complete."** So
AD DS started **nine times** inside those 200 events. **Hypothesis, not established:** the counts
cluster at 6/8/9 (18 = 2 × 9), which is what a fixed batch written once per startup would look like.
Sharing a count with 1000 is suggestive, not proof; the times of the 1000s were not read.

## The domain is older than the README says

| Source | Date |
|---|---|
| `Get-ADObject 'DC=corp,DC=local' -Properties whenCreated` | **2026-08-02 4:24:22 PM** (displayed in DC01's UTC+1; **15:24:22 UTC** assuming PowerShell converted from AD's stored UTC, which is recall, not checked) |
| `edb00001.log`, `edbres00001.jrs`, `edbres00002.jrs`, `edbtmp.log` LastWriteTime | **8/2/2026 4:24 PM** — the same minute |
| Oldest DC01 Security event | **2026-07-28** |
| Oldest WS01 Security event, recorded in CLAUDE.md on 2026-08-24 | **28 July** |
| README progress log | VMs built **2026-08-02**, DC01 promoted **2026-08-09** |

The directory and the filesystem agree: **`corp.local` was created on 2026-08-02**, not 2026-08-09.
Both hosts were logging from 28 July, before the README's build date. **The repository's first
commit is 2026-08-09 13:36**, so both Module 00 progress-log rows were written retrospectively on or
after that date — consistent with them recording the write-up rather than the work, **but that is
not established.** The README has been annotated from this evidence rather than silently re-dated.

## Observations, no cause established

- **Every file in `C:\Windows\NTDS` is a round number of bytes.** `ntds.dit` is exactly **16 MiB**
  (16,777,216); the four 2 August files are exactly **10 MiB** each (10,485,760). That looks like
  pre-allocation — the same shape as event-log files, whose size says nothing about how full they
  are — but **this is not established**, so the file size must not be read as "the domain holds
  16 MB of data".
- **`ntds.dit`, `edb.chk`, `ntds.jfm` and `temp.edb` all read 9:13 AM today**, four minutes before
  the first screenshot. Plausibly the boot; not established.

## Traps this sitting added

- **`(…).Count` printed nothing for a single DC; `@(…).Count` printed `1`.** Verified. The
  explanation offered in-session — one returned object is not a list, and an AD object answers
  `.Count` with its own (absent) property — **predicted the `@( )` result, but is not proven.** The
  practical rule stands either way: **wrap a count in `@( )`, or a population of one prints as
  blank** — no error, and blank reads like zero. Another member of the "silence that looks like an
  answer" family.
- **PowerShell truncates long values with `...` in list view.** `OperationMasterRoles` displayed
  `{SchemaMaster, DomainNamingMaster, PDCEmulator, RIDMaster...}` — `InfrastructureMaster` hidden,
  not absent. **Truncated display is not missing data.**
- **A misspelled channel name errors loudly — confirmed on a second host.** `'Directory Sercices'`
  and `'Directory Sercice'` both returned *"There is not an event log on the localhost computer
  that matches…"*. Only a channel that exists can fool you.
- **Counting objects by eye in list view.** One DC's output is a ~20-line block, and the lines were
  counted as objects (21). Let PowerShell count.

## Still open from sitting 1

- **`maxSize`** of DC01's Security log, to compare against WS01's
- *(optional)* the `TimeCreated` of the `1000` events, which would test the once-per-startup
  hypothesis and date DC01's restarts
- **Screenshots exist on the Windows machine and are not filed** — frames covering Steps 0.2/0.3,
  1.3, 3.2/3.3 and 5.2. They do not map one-to-one onto Step 12's checklist; reviewed and filed
  deliberately, not by filename

---

# Step 0 — Pre-flight (DC01)

**Aim: be certain which machine you are on and that the directory is answering, before any
result from it means anything.**

### 0.1 Snapshot first

With DC01 **shut down**, take a VirtualBox snapshot named **`mod08-start`**.

> **Do not fall back to `01-domain-ready` if you later need a clean baseline.** That snapshot
> predates the licence rearm of 2026-09-04 and restoring it reinstates the *expired* licence.
> **`mod04-start` is the clean baseline for DC01.**

### 0.2 Prove which machine you are on

Boot DC01 and open PowerShell **as Administrator**. Then:

```powershell
hostname
```

Put this at the top of every screenshot you take in this module. `06-auditpol-before.png` is a
genuine, unrepeatable baseline whose host **can no longer be established**, because both VMs
prompt `PS C:\Users\Administrator>` and nothing in the frame says which one it was.

### 0.3 Prove the directory is answering

```powershell
Get-ADDomain -Current LocalComputer
```

**Prediction:** a block of properties describing `corp.local`.

If this errors, stop and read the error rather than continuing — an AD cmdlet that cannot reach a
directory produces a message that sounds much worse than the problem usually is. Module 07 ended
with `Get-LocalGroupMember` reporting *"the trust relationship between this workstation and the
primary domain failed"* purely because **DC01 was powered off**, a message that invites a
diagnosis costing a rebuild. Here you are *on* DC01, so the likely causes are the AD DS service
not yet started after boot, or the machine not having finished booting. Give it a minute and
retry before theorising.

---

# Step 1 — Read the shape of the directory (DC01)

**Aim: be able to say what `corp.local` actually is — one forest, one domain, one DC — from
command output rather than from memory of having built it.**

Three cmdlets, from the outside in. Run each on its own and read the output before moving on.

### 1.1 The forest

```powershell
Get-ADForest
```

Things worth finding in that output, in your own words afterwards:

- **`ForestMode`** — the feature level, which is capped by the *oldest* DC version in the forest
- **`Domains`** — **prediction:** exactly one, `corp.local`
- **`GlobalCatalogs`** — which DCs hold the forest-wide index
- **`SchemaMaster`** and **`DomainNamingMaster`** — the two forest-wide FSMO roles, which Step 2
  comes back to

### 1.2 The domain

```powershell
Get-ADDomain
```

- **`DNSRoot`** / **`NetBIOSName`** — `corp.local` and `CORP`, the two names for one thing
- **`DistinguishedName`** — **prediction:** `DC=corp,DC=local`. This is the format the directory
  itself uses, and you will see it again in event logs. Module 01 already met it: a 4728's
  `Member → Account Name` is a distinguished name (`CN=svc_backup,CN=Users,DC=corp,DC=local`),
  **not** a logon name
- **`DomainSID`** — the prefix every account SID in this domain is built on. Compare it against
  the `S-1-5-21-…` strings Module 03 saw in `HKU\<SID>\…` paths; **prediction:** they match
- **`PDCEmulator`**, **`RIDMaster`**, **`InfrastructureMaster`** — the three domain-wide FSMO roles

### 1.3 The domain controllers

```powershell
Get-ADDomainController -Filter *
```

**`-Filter *` means "all of them".** AD cmdlets use their own filter language rather than piping
into `Where-Object`, because the filtering happens *in the directory* rather than on everything
it sent back — the same reason `-FilterHashtable` beats `Get-WinEvent | Where-Object`.

**Prediction:** one row, DC01. Note `IsGlobalCatalog`, `Site` (**prediction:**
`Default-First-Site-Name`), and `OperatingSystem`.

---

# Step 2 — Who holds the five special jobs (DC01)

**Aim: read the FSMO roles off the machine, and meet a class of tool that is not a cmdlet.**

### 2.1 The quick way

```powershell
netdom query fsmo
```

**Prediction:** all five roles on `DC01.corp.local`.

**`netdom` is not a cmdlet.** It is a legacy command-line program, and that distinction matters
more than it sounds: it prints **text**, not objects. `Get-ADForest | Select-Object SchemaMaster`
works; `netdom query fsmo | Select-Object SchemaMaster` returns nothing useful, because there is
no `SchemaMaster` property on a line of text. This is the same family as `auditpol`, `wevtutil`
and `reg.exe`, all of which this lab has already used.

### 2.2 The same answer as objects

```powershell
Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster
```

```powershell
Get-ADDomain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
```

Two commands, five roles, and the split tells you something: **two roles belong to the forest and
three belong to the domain.** In a multi-domain forest the first two exist once in total and the
last three exist once *per domain*.

### 2.3 Write it down

You will need this for Step 10's deliverable. **Prediction:** a five-row table with `DC01` in
every cell — which is the correct and expected answer for a single-DC domain, not a shortcoming.

---

# Step 3 — Where the directory physically lives (DC01)

**Aim: see that the whole domain is two things on a disk — because that is what an attacker who
wants every password in the organisation is actually after.**

### 3.1 The database

Read the parameters rather than assuming the default path:

```powershell
Get-ItemProperty 'HKLM:/SYSTEM/CurrentControlSet/Services/NTDS/Parameters'
```

> Forward slashes work in PowerShell registry paths — verified on WS01 2026-09-10, and the
> standing workaround in this lab for the backslash keyboard problem. It does **not** extend to
> `reg.exe`.

**Prediction:** `DSA Database file` reads `C:\Windows\NTDS\ntds.dit`.

**`ntds.dit` is the domain.** Every account, every group, every computer, and **every password
hash** in `corp.local` is in that one file. This is why `NTDS.dit` extraction is a named technique
rather than a generic one — an attacker who copies it off a DC has the entire organisation's
credentials and never needs to crack a login again.

### 3.2 The shared folder

```powershell
Get-SmbShare
```

**Prediction:** two shares that did not exist before this machine became a DC — **`SYSVOL`** and
**`NETLOGON`**. SYSVOL holds the files that Group Policy delivers to every machine in the domain,
and every domain member reads it. Module 10 lives there.

Note the implication while you are looking at it: **a folder that every machine in the domain
reads, hosted on the machine holding every password.** Write down in one sentence why that
combination is worth watching.

### 3.3 Confirm it is really there

```powershell
Get-ChildItem 'C:/Windows/NTDS'
```

**Prediction:** `ntds.dit` plus log files. You cannot open it — AD holds it locked while the
service runs, which is itself the reason credential-theft tooling uses volume shadow copies
rather than a plain file copy.

---

# Step 4 — The empty baseline: trusts (DC01)

**Aim: run the query that would show a trust, record that it shows none, and make that a
documented baseline rather than an untested assumption.**

```powershell
Get-ADTrust -Filter *
```

**Prediction: no output at all.** `corp.local` is a single domain in a single forest, so there is
nothing for it to trust and nothing trusting it.

**This is the module's one deliberate encounter with an empty result, and the point is that you
know *why* it is empty.** Seven modules of this journal have been spent on the difference between:

- the query found nothing because there is nothing (**here**)
- the query found nothing because it ran on the wrong machine
- the query found nothing because it ran against the wrong channel
- the query found nothing because a cap hid the matches
- the query found nothing because of a typo in the ID

Add a line to your notes stating which of those this is, and how you know. **Prediction:** the
control is Step 1.1, where `Get-ADForest` returned `Domains: {corp.local}` — a populated result
from the same subsystem, a minute earlier, proving the cmdlets work and the directory answers.

> **Record the limitation honestly in the write-up.** "No trusts exist in this lab, so trust
> enumeration and cross-forest attack paths are out of scope for this journal" is a perfectly
> good sentence. Pretending the module covered them would not be.

---

# Step 5 — AD's own logbooks, and DC01's rotation deadline (DC01)

**Aim: find the channels this module's evidence will land in, and — more urgently — find out how
long DC01 keeps anything at all, because that number has never been measured on this machine.**

### 5.1 The channel you have never used

Modules 03, 06 and 07 all found that the Security log is not the only logbook, and that a query
against the wrong channel returns `NoMatchingEventsFound` — identical to a genuine absence, with
no error. AD has its own.

```powershell
Get-WinEvent -ListLog 'Directory Service'
```

**Prediction:** a low-volume channel. Note `RecordCount` and `MaximumSizeInBytes`.

### 5.2 Find out what it actually contains

Rather than guessing which event IDs live there, ask:

```powershell
Get-WinEvent -LogName 'Directory Service' -MaxEvents 200 | Group-Object Id | Sort-Object Count -Descending
```

`Group-Object Id` buckets events by ID and counts each — one command that says what a channel
records, instead of what you hoped it records. Module 06 used the same move to prove Sysmon was
alive.

> **Resolve anything interesting on the box, not from memory.** Pick one ID and read `.Message`
> on an example. Module 07 left six event IDs in a channel unresolved for two sittings and had to
> come back to them; two turned out to be the answer to a question that was open at the time.

### 5.3 The measurement that matters more than the module

**WS01's Security log holds roughly one day — measured 2026-09-29. DC01's has never been
measured.** Everything this module is about to generate lands in it.

```powershell
wevtutil gli Security
```

Read **`oldestRecordNumber`**. **`oldestRecordNumber` of 1 means the log has never discarded
anything; anything higher is the count already lost.**

> **Do not judge rotation by comparing `FileSize` to `MaximumSizeInBytes`.** Verified on WS01
> 2026-09-25: a log reported those two numbers **exactly equal** while holding 725 records and an
> `oldestRecordNumber` of 1 — nothing had ever been discarded. **An event log file is allocated at
> its configured size regardless of how full it is.** That comparison produced a confident wrong
> call once already in this lab.

Then get the actual date of the oldest event:

```powershell
Get-WinEvent -LogName 'Security' -Oldest -MaxEvents 1 | Select-Object TimeCreated
```

**Write the answer into the run log.** If DC01 also holds about a day, then Step 9's evidence has
a deadline and Step 12's screenshots cannot be left for another sitting.

---

**End of sitting 1.** Everything to this point is read-only — nothing on DC01 has changed, so this
is a safe place to stop. **Sitting 2 starts changing audit configuration.**

---

# Step 6 — Read the four gates before changing anything (DC01)

**Aim: establish the before-state, so that any change in behaviour afterwards has exactly one
cause you introduced.**

Module 06's Finding 5 came out of a step written as *"run the query and expect nothing"* — on a
host where the instrument was switched off, so the empty result could not have come out any other
way. **An expectation that cannot fail is not evidence.** This step exists so that Step 9's result
is not that.

### 6.1 Read the whole category

```powershell
auditpol /get /category:"DS Access"
```

> **No space after the colon.** `auditpol /get /category: "DS Access"` fails with
> `Error 0x00000057 … The parameter is incorrect.` and dumps usage text that reads like a broken
> tool rather than a typo.

**Prediction:** four subcategories — `Directory Service Access`, `Directory Service Changes`,
`Directory Service Replication`, `Detailed Directory Service Replication`.

**Prediction, and it is recall rather than established:** `Directory Service Access` reads
**Success** (it is enabled by default on domain controllers) while `Directory Service Changes`
reads **No Auditing**. **Read what the box says and write that down — do not inherit these
words.** Module 07 found a third audit switch (`Other Logon/Logoff Events`) reading `No Auditing`
when two related ones were on, and that discovery was the sitting's strongest finding.

### 6.2 Note what each one costs

Before switching anything on, understand which of these is dangerous:

- **`Directory Service Changes`** (5136/5137/5139/5141) — *what changed, from what, to what*.
  Requires a SACL on the object as well, so it only fires where you have asked for it. **This is
  the one to enable.**
- **`Directory Service Access`** (4662) — *somebody touched an object*. Fires enormously on a DC
  and is the event Module 12 uses for DCSync detection. **Leave it exactly as you found it.**

> ⚠️ **Do not enable `Directory Service Access` Success broadly on this host.** Module 04 measured
> what a flood does: it destroys older evidence by pushing it out of the log. On a DC whose
> retention you measured in Step 5.3, a per-object-access event would leave a log measured in
> hours. If Step 5.3 came back with a short horizon, this warning is not theoretical.

### 6.3 Mark the boundary

```powershell
(Get-Date).ToUniversalTime()
```

Write it down. **Auditing is not retroactive** — this lab has paid for that lesson twice, in
Module 02's Step 3 lock-down that could never have logged, and in Module 07's morning disconnect
that is permanently unrecoverable. Everything before this line is the control.

---

# Step 7 — Build: a scoped test OU and its SACL (DC01)

**Aim: open the subcategory gate and the object gate separately, so that if nothing is logged you
can tell which one was responsible.**

### 7.1 Open the subcategory gate

```powershell
auditpol /set /subcategory:"Directory Service Changes" /success:enable
```

Read it back rather than trusting the command's own output:

```powershell
auditpol /get /subcategory:"Directory Service Changes"
```

> **A command that ran is not a change that took effect.** Module 06's Finding 5 has three
> instances of a `Remove-NetFirewallRule` that ran, reported success, and left the rule live.

### 7.2 Create somewhere scoped to work in

```powershell
New-ADOrganizationalUnit -Name 'LabAudit' -Path 'DC=corp,DC=local'
```

**An Organizational Unit is a folder inside the directory**, and the thing you can attach policy
and permissions to. Module 09 is about designing them properly; here it is just a container that
keeps this experiment away from everything real.

Read it back:

```powershell
Get-ADOrganizationalUnit -Filter "Name -eq 'LabAudit'"
```

> **This creation happens *before* the SACL exists**, deliberately. It is the control: Step 9
> should find no **5137** for it.

> **Run result (2026-10-23): no 5137 — but not no event.** Creating `LabAudit` also wrote a 5136
> pair on the **domain root**: its DACL gained `Everyone: AccessDenied (DeleteChild)`, most likely
> because new OUs are protected from accidental deletion, and the domain's own SACL audits changes
> to its permissions. **Time this command** (`(Get-Date).ToUniversalTime()` before and after) if
> you rerun the module — the 2026-10-23 run could only place it "early in Step 7". See Finding 1.

### 7.3 Open the object gate — the GUI is better here

**Prefer the GUI for this.** The Auditing tab shows you every field at once, which the
command-line equivalent does not, and it is how Modules 02 and 03 set their SACLs.

On **DC01**, open **Active Directory Users and Computers** (`dsa.msc`). Then:

1. **View → Advanced Features** — tick it. **The Security tab does not appear without this**, and
   its absence looks like a permissions problem rather than a hidden menu option
2. Right-click the **`LabAudit`** OU → **Properties** → **Security** tab → **Advanced**
3. **Auditing** tab → **Add**
4. **Principal:** `Everyone` · **Type:** `Success` · **Applies to:** `This object and all
   descendant objects`
5. Tick **`Write all properties`** and **`Create all child objects`**
6. OK out of all three dialogs

**Those two ticks are the gate-4 equivalent** — `WRITE_DAC` in Module 02, `Set Value` in Module 03.
In Module 02 the audited-rights mask was the difference between an event and silence *with all
three subcategories reading "Success and Failure"*, which is the subtlest failure this lab has
found.

### 7.4 Confirm the SACL exists

```powershell
(Get-Acl -Path 'AD:/OU=LabAudit,DC=corp,DC=local' -Audit).Audit
```

**`AD:` is a PowerShell drive for the directory**, the same idea as `HKLM:` for the registry — a
construct this lab already knows, pointed at a new store.

**Prediction:** at least one audit rule, principal `Everyone`.

> **Test the bits, do not grep the names.** Module 03 found that `RegistryRights` collapses flags
> into composite names — `WriteKey` (6) is `SetValue` (2) + `CreateSubKey` (4), so a SACL that
> genuinely audited `SetValue` showed **no literal `SetValue` string anywhere**. Expect AD rights
> to behave the same way. Read what the property actually contains before concluding the tick did
> not take.

---

# Step 8 — Break: three benign directory changes (DC01)

**Aim: generate three changes of three different kinds, inside the audited scope, so the detect
step can show which kinds the log distinguishes.**

Mark the time first:

```powershell
(Get-Date).ToUniversalTime()
```

Then keep the same moment in a variable, so Step 9 can search from it:

```powershell
$start = Get-Date
```

**The first line is for your notes (UTC, the way findings are written); the second is for the
query.** `StartTime` expects local time, which is what plain `Get-Date` gives. A variable lives only
as long as this PowerShell window — **do Steps 8 and 9 in the same window**. If it gets closed, set
`$start` again by hand from the time you wrote down.

### 8.1 Modify an attribute

```powershell
Set-ADOrganizationalUnit -Identity 'OU=LabAudit,DC=corp,DC=local' -Description 'module 08 test'
```

### 8.2 Create a child object

```powershell
New-ADUser -Name 'lab_dirtest' -Path 'OU=LabAudit,DC=corp,DC=local' -Enabled $false
```

**`-Enabled $false` is deliberate** — this account should never be able to log in. Module 01
established that `New-ADUser` with a password writes 4720/4722/4724 in the same second; this one
has no password and will not.

### 8.3 Delete it

```powershell
Remove-ADUser -Identity 'CN=lab_dirtest,OU=LabAudit,DC=corp,DC=local' -Confirm:$false
```

**Module 03's lesson applied in advance:** a 13-only rule saw the attacker arrive and never leave,
because a deleted *value* was Event 12 rather than 13. The equivalent question here is whether
deletion gets its own ID — **prediction:** 5141, a different ID from the 5136 of 8.1. Step 9 tests
it.

> **Run result (2026-10-23): no 5141 was written** — not for this delete, and not for `LabAudit`'s
> own deletion in Step 11. The SACL set in 7.3 audits `CreateChild, WriteProperty` and **no delete
> right**. That this is the cause is the leading hypothesis and **was not tested**. **If you rerun
> this module, tick `Delete` and `Delete all child objects` as well in 7.3** — and record whether
> a 5141 then appears, which would settle it.

Mark the closing time:

```powershell
(Get-Date).ToUniversalTime()
```

---

# Step 9 — Detect: find the changes (DC01)

**Aim: find out which of the three changes the log kept, and prove the instrument was alive for
the ones it did not keep.**

### 9.1 Count before concluding

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136} | Measure-Object
```

> **Never take a small number from a capped query as a result.** Module 03 read three rows from a
> `-MaxEvents 5` query as "only three exist", which made the host look like it had stopped logging
> process creation and produced a confident, entirely fictional anomaly. `Measure-Object` returned
> **1311**. Get the count first.

### 9.2 Read one properly

**Aim: read the 5136 that Step 8.1 caused, and be sure it is that one.**

Take only the 5136s from Step 8's window:

```powershell
$d = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136; StartTime=$start}
```

```powershell
@($d).Count
```

> **Do not reach for `-MaxEvents 1` here.** "The newest matching event is not the right event" has
> bitten this lab twice — Module 07's `-First 1` returned a nine-second transient logon, and Module
> 06's `-MaxEvents 1` returned an LDAP drop fourteen minutes past the knock. Filter by time first,
> then choose by content.

**How many to expect is not established.** Creating `lab_dirtest` in 8.2 may write 5136s of its
own as the new object's attributes are filled in. Read what comes back rather than assuming one.

Look at the first one:

```powershell
$d[0].Message
```

`.Message` renders every field with its label, which is what Event Viewer's General tab shows and
is easier than XML for a first look. **You want the one whose `LDAP Display Name` is
`description`** and whose object is `OU=LabAudit,DC=corp,DC=local`. If `$d[0]` is not it, try
`$d[1]`, `$d[2]` and so on. When you find it, give it its own name — with the number you found in
place of `0`:

```powershell
$one = $d[0]
```

Then pull the fields by name:

```powershell
([xml]$one.ToXml()).Event.EventData.Data | Format-Table Name, '#text'
```

> **`[xml]` accepts exactly one root element.** `$d.ToXml()` without an index concatenates every
> event's XML and fails with *"this document already has a DocumentElement node"* — which reads
> like a parser fault rather than a missing subscript. That is why the chosen event gets its own
> variable first.

**Prediction:** fields naming the object's distinguished name, the attribute that changed, the old
and new values, and the account that did it.

### 9.3 Check the other two event IDs

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5137} | Measure-Object
```

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5141} | Measure-Object
```

**Prediction:** 5137 for the creation in 8.2, 5141 for the deletion in 8.3.

### 9.4 The control — the change that should NOT be there

**Aim: show, in one output, a creation the log kept and a creation it did not.**

The `LabAudit` OU was created in Step 7.2, **before** the SACL existed. `lab_dirtest` was created in
8.2, **after**. Both are creations, so both would be 5137s — if both were logged.

> **Why not just search the message for `LabAudit`?** Because `lab_dirtest` lives *inside*
> `LabAudit`, so its 5137 contains that word too — `CN=lab_dirtest,OU=LabAudit,DC=corp,DC=local`.
> A whole-message search would return it and make the control look failed when it has not. This is
> the trap Module 03 hit, where hunting `'*Notepad.exe*'` returned a `reg.exe` process. **Extract
> the field first, then filter on it.**

Get every 5137:

```powershell
$c = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5137}
```

Look at the field names in the first one:

```powershell
([xml]$c[0].ToXml()).Event.EventData.Data | Format-Table Name, '#text'
```

**A field named `ObjectDN` holds the object's full distinguished name** — confirmed on DC01
2026-10-23 from a 5136's field list (`OpCorrelationID`, `AppCorrelationID`, `SubjectUserSid`,
`SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`, `DSName`, `DSType`, `ObjectDN`,
`ObjectGUID`, `ObjectClass`, `AttributeLDAPDisplayName`, `AttributeSyntaxOID`, `AttributeValue`,
`OperationType`). That the 5137 uses the same name is expected but read it off the box.

Now print just that field for every 5137. `foreach` runs the part in `{ }` once per event, with
`$e` standing for the current one — the one new construct in this step:

```powershell
foreach ($e in $c) { (([xml]$e.ToXml()).Event.EventData.Data | Where-Object Name -eq 'ObjectDN').'#text' }
```

**Prediction:** `CN=lab_dirtest,OU=LabAudit,DC=corp,DC=local` appears, and
`OU=LabAudit,DC=corp,DC=local` **on its own does not**. That combination is the finding — the same
argument structure as Module 03's Finding 2, where the query that missed two writes *returned* the
third, so wrong-host, narrow-window, rotation and channel-off were all excluded by the query's own
positive result. Here the positive and the absence sit in the same list.

> **If the list is empty — no `lab_dirtest` either — you have not got a result, you have got an
> unproven instrument.**
> Go back to 7.1 and 7.4 and establish which gate is still shut. Do not write a finding until one
> of these queries returns something.

> **Run result (2026-10-23): the prediction held, more simply than written.** DC01 held exactly
> **one** 5137 — `CN=Lab_dirtest,OU=LabAudit,DC=corp,DC=local` — so `$c[0].Message` answered it
> without the `foreach`. The `foreach` stays here because a domain with any other audited creation
> would return more than one. **Then read the 5136s from before Step 8** (`EndTime=$start`): on the
> 2026-10-23 run, the "nothing" for `LabAudit` turned out to be "no 5137, plus a 5136 pair on its
> parent". See the run log and Finding 1.

### 9.5 Freeze the evidence before photographing anything

```powershell
Set-Location 'C:/evidence'
```

```powershell
wevtutil epl Security 08-dc01-security.evtx
```

Moving into the folder first means no path separators are needed at all — the trick Module 06 used
for `Sysmon64.exe`. If `C:\evidence` does not exist on DC01:
`New-Item -ItemType Directory -Path 'C:/evidence'`.

> **This is the lesson sitting 4 of Module 07 paid for, and it outranks the checklist.**
> *"Recoverable later"* is a deadline nobody wrote down. Screenshots recorded as "recoverable — the
> event is still in the log" were, for Module 06's knock and Module 07's 4947 burst, **already
> gone**. Export first, photograph at leisure.

Check what it covers:

```powershell
Get-WinEvent -Path 08-dc01-security.evtx -Oldest -MaxEvents 1 | Select-Object TimeCreated
```

---

# Step 10 — Deliverable: the forest inventory and FSMO role map

**Aim: produce the thing a real job asks for — a written statement of what this directory is, so
that a future change can be recognised as a change.**

This replaces the roadmap's "network + trust diagram", which cannot exist in a single-domain
forest. Write it into this file, from **command output** rather than recollection.

> **Step 10 of Module 07 earned this instruction.** Every note in the repo said WS01's
> `Remote Desktop Users` group contained `asmith`. Reading it back on 2026-09-30 returned **two**
> members — `CORP\asmith` and `WS01\helpdesk`. Writing the state from memory would have missed a
> second account with remote-logon rights.

### 10.1 The inventory table

*Filled 2026-10-12 from sitting 1's command output.*

| | Value | Read from |
|---|---|---|
| Forest name | `corp.local` | `Get-ADForest` |
| Forest mode | `Windows2016Forest` | `Get-ADForest` |
| Domains in forest | `{corp.local}` — one | `Get-ADForest` |
| Domain DNS root / NetBIOS | `corp.local` / `CORP` | `Get-ADDomain` |
| Domain mode | `Windows2016Domain` | `Get-ADDomain` |
| Domain distinguished name | `DC=corp,DC=local` | `Get-ADDomain` |
| Domain SID | `S-1-5-21-3536249948-3294943055-3998780783` | `Get-ADDomain` |
| Domain created | 2026-08-02 (displayed 4:24:22 PM, UTC+1) | `Get-ADObject … -Properties whenCreated` |
| Domain controllers | one — `DC01`, `10.0.0.10`, Windows Server 2022 (20348), writable | `Get-ADDomainController -Filter *` |
| Global catalog | `DC01` | `Get-ADDomainController -Filter *` |
| Site | `Default-First-Site-Name` | `Get-ADDomainController -Filter *` |
| Trusts | **none** | `Get-ADTrust -Filter *` |
| `ntds.dit` path | `C:\Windows\NTDS\ntds.dit` | NTDS registry parameters |
| SYSVOL / NETLOGON shared | yes — `C:\Windows\SYSVOL\sysvol`, `…\sysvol\corp.local\SCRIPTS` | `Get-SmbShare` |
| Security log horizon | **never wrapped** — `oldestRecordNumber` 1, oldest event 2026-07-28 | `wevtutil gli Security` |

### 10.2 The FSMO role map

| Role | Scope | Held by |
|---|---|---|
| Schema Master | Forest | `DC01.corp.local` |
| Domain Naming Master | Forest | `DC01.corp.local` |
| PDC Emulator | Domain | `DC01.corp.local` |
| RID Master | Domain | `DC01.corp.local` |
| Infrastructure Master | Domain | `DC01.corp.local` |

All five read from `Get-ADForest`/`Get-ADDomain` **and** `netdom query fsmo`, which agreed.

### 10.3 Two sentences in your own words

Not a summary of the commands — the thing the inventory means:

> Why does an attacker who reaches `ntds.dit` not need to crack anything afterwards?

> This lab has one DC holding all five FSMO roles. Name one specific thing that breaks if it is
> offline, and say which log you would check first.

**Answers, filed 2026-11-03:**

1. *(The analyst's words.)* The attacker doesn't need to crack anything because the hash can work
   without the attacker needing to know the password.
2. *(Written by Claude at the analyst's request, 2026-11-03 — not the analyst's own wording.)* With
   DC01 offline, WS01 can no longer resolve domain accounts: on 2026-09-30, with DC01 powered off,
   `Get-LocalGroupMember -Group 'Remote Desktop Users'` on WS01 failed with **error 1789** because
   it could not resolve `asmith`'s SID, and the identical command succeeded once DC01 was booted.
   I would check **WS01's System log first**, for Netlogon errors saying it could not reach a domain
   controller. **That this appears as Netlogon event 5719 is recall, not seen in this lab.**

The second answer names a single-DC failure rather than a single-*role* failure. In this lab the two
are the same: DC01 holds every role, so any role-specific symptom (the PDC Emulator's clock, lockout
processing, the RID Master's SID pool) arrives together with everything else.

---

# Step 11 — Lab state and cleanup (DC01)

**Aim: leave the machine in a state a future sitting can rely on, and write down what that state
is rather than remembering it.**

### 11.1 Remove the test objects

```powershell
Remove-ADOrganizationalUnit -Identity 'OU=LabAudit,DC=corp,DC=local' -Confirm:$false
```

**Prediction: this fails.** New OUs are created with accidental-deletion protection on. That is not
a fault — it is Windows doing its job, and the fix is to clear the flag first:

```powershell
Set-ADOrganizationalUnit -Identity 'OU=LabAudit,DC=corp,DC=local' -ProtectedFromAccidentalDeletion $false
```

Then retry the removal, and **read it back**:

```powershell
Get-ADOrganizationalUnit -Filter "Name -eq 'LabAudit'"
```

> **Run result (2026-10-23): held** — `Access is denied`, even for the domain Administrator, until
> the flag was cleared. **Then check the parent:**
> `(Get-Acl -Path 'AD:/DC=corp,DC=local').Sddl -like '*(D;;DC;;;WD)*'`. On this run it read
> **`True`** both after clearing the protection and after deleting the OU — the deny entry that
> creating the OU added to the domain root **stayed behind**, and no 5136 recorded any change to it.

An empty result is the correct answer here, and you now know from Step 4 how to tell this empty
result from a broken query.

### 11.2 Decide on the audit switch, and write the decision down

**Recommendation: leave `Directory Service Changes` enabled**, and say so explicitly in the
write-up as a decision rather than letting it look like an oversight.

The reasoning matches Module 06's, which left three switches on for the same reason: it fires only
where a SACL asks for it, every lab SACL is about to be deleted with the OU, so it costs nothing
in volume — and Modules 09 and 10 both need it. Re-read it so the recorded state is true:

```powershell
auditpol /get /subcategory:"Directory Service Changes"
```

**Leave `Directory Service Access` exactly as Step 6.1 found it.**

### 11.3 Record the state

Write into the run log, from readbacks and not from memory:

- `Directory Service Changes` — the value you just read
- `Directory Service Access` — the value from 6.1, unchanged
- `LabAudit` OU — removed and confirmed absent
- `C:\evidence\08-dc01-security.evtx` — present, and the window it covers
- DC01 Security log horizon — the number from Step 5.3

---

# Step 12 — Evidence for the portfolio

Save into `../assets/`. **Put `hostname` at the top of every frame.**

- [x] `08-forest-domain.png` — `Get-ADForest` and `Get-ADDomain` output together: the shape of
      the directory in one image. **Recaptured 2026-11-03** (never taken in sitting 1); `hostname` →
      `DC01` in frame, every value matches the sitting-1 run log
- [x] `08-fsmo-roles.png` — `netdom query fsmo`, all five roles on one host. **Recaptured
      2026-11-03**; `hostname` → `DC01`, five roles on `DC01.corp.local`
- [x] `08-ntds-sysvol.png` — the NTDS parameters and `Get-SmbShare` side by side: the two things
      on disk that are the domain. **Recaptured 2026-11-03**; `hostname` → `DC01`,
      `C:\Windows\NTDS\ntds.dit` and the same five shares as sitting 1
- [x] `08-no-trusts.png` — `Get-ADTrust -Filter *` returning nothing, **with `Get-ADForest`'s
      populated `Domains` in the same frame as the control.** The empty result is only evidence
      beside the thing that proves the query works. **Recaptured 2026-11-03** (first attempt
      saved as an all-black file); cropped to the PowerShell window. `hostname` → `DC01`,
      `Domains {corp.local}`, then no output from `Get-ADTrust`
- [x] `08-ds-access-gates.png` — `auditpol /get /category:"DS Access"` **before** the change, with
      `hostname` → `DC01` in frame. Filed 2026-10-23
- [x] `08-5136-change.png` — the 8.1 `description` 5136 (`$d[3].Message`). **Shows a new value
      only** — the field was empty before, so there was no old value to show. Filed and cropped
      2026-10-23
- [x] `08-sacl-control.png` — the only 5137 on DC01, for `Lab_dirtest`. Filed and cropped
      2026-10-23. **The count of 1 is not in the frame** — it rests on the 9.3 readback

**Filed beyond the checklist, 2026-10-23:** `08-sacl-readback.png` (the `LabAudit` SACL, both
rights by name, plus the two inherited entries) and `08-domain-sacl.png` (the domain root's five
SACL entries — the evidence that no `CreateChild` was audited when `LabAudit` was created). **Not
captured:** the domain-root 5136 pair and its `Compare-Object` result. They are in
`C:\evidence\08-dc01-security.evtx` on DC01 and can be photographed from the export.

---

# Findings

> Written 2026-10-23 from the two run logs above. **Observation → inference → recommendation**, kept
> strictly separate; timestamps in **UTC**. All events: host **DC01**, log **Security**, subject
> **`CORP\Administrator`**, Logon ID **`0x39279`**, date **2026-10-23** unless stated.

### Finding 1 — The object gate holds in Active Directory, and an unaudited object can still surface through its parent

**Observation.**

- At **09:38:38 UTC** `Directory Service Changes` read **No Auditing**; Step 7.1 set it to
  **Success**, readback-verified. `LabAudit` was then created **with no SACL of its own**, and the
  domain root's five SACL entries (read and counted in 7.4b) included **no `CreateChild`**.
- A SACL was then added to `LabAudit`: `CreateChild, WriteProperty`, Everyone, Success, this object
  and all descendants (readback in 7.4).
- `lab_dirtest`, created inside `LabAudit` after that, produced a **5137**
  (`CN=Lab_dirtest,OU=LabAudit,DC=corp,DC=local`, GUID `{3b26da90-6499-4071-b815-693313fe90c9}`).
  It is **the only 5137 on DC01**. **No 5137 exists for `LabAudit`.**
- At **09:42:37 UTC**, early in Step 7, two **5136**s were written for **`DC=corp,DC=local`**,
  attribute **`nTSecurityDescriptor`**: one `Value Deleted`, one `Value Added`, same second, Correlation ID
  `{8767bcc8-56e8-4850-9e00-9e094b4aa04a}`. The two `AttributeValue`s are 3528 and 3540
  characters long, and differ by exactly one DACL entry, **`(D;;DC;;;WD)`**. `ConvertFrom-SddlString`
  resolves it to **`Everyone: AccessDenied (DeleteChild)`**.
- `LabAudit` read **`ProtectedFromAccidentalDeletion : True`**. The entry was **still present** on
  the domain root after the protection was cleared and after the OU was deleted, and **no 5136**
  recorded either of those steps.

**Inference.**

- **I assess with high confidence that the SACL is a necessary gate for AD creation events**, as
  it was for NTFS (Module 02) and the registry (Module 03). The same query that found no 5137 for
  `LabAudit` returned one for `lab_dirtest`: same host, log and command, separated only by whether
  `CreateChild` was audited. **That is now three stores with the same gate structure.** The
  pattern looks architectural rather than a quirk of one store.
- **What this run did not test is the subcategory gate on its own.** Nothing was created while
  `Directory Service Changes` was off, so "the subcategory switch alone silences AD events" is
  **expected from Modules 02–03, not observed here**.
- **I cannot tell from this evidence whether a creation is audited against the new object's SACL
  or its parent's.** Neither one audited `CreateChild` when `LabAudit` was created, so the control
  holds either way and cannot tell the two apart.
- **"An unaudited object leaves no trace" is false.** `LabAudit` produced no 5137, but creating it
  changed its **parent's** permissions, and the domain's own default SACL (`WriteDacl`, Everyone)
  recorded that change. **I assess with moderate-to-high confidence that Step 7.2 caused the 5136
  pair**, through accidental-deletion protection: timing, content and the `True` flag all fit, and
  no other candidate is known. **It is not established.** 7.2 was not individually timed, and how
  the protection works is recall rather than something read on the box.
- **The change was asymmetric: logged going on, never undone.** Clearing the protection and
  deleting the OU left the deny entry on the domain root. So an ordinary admin action (making a
  protected OU) leaves a lasting change on the most important object in the directory, and the
  domain's audit trail records it as a permission change made by that admin.
- MITRE: **T1136.002** (Create Account: Domain Account) for `lab_dirtest`. The ACL change is
  benign here. Its relevance is that the same 5136 is the event an attacker's change to domain-root
  permissions would write.

**Recommendation.**

- **Pre-flight for any audited-object experiment: read the subcategory, the object's SACL *and*
  its parent's SACL**, and count each readback with `@( ).Count` before treating it as complete.
- **Hunt permission changes on the domain root:** 5136 where `ObjectDN = DC=corp,DC=local` and
  `AttributeLDAPDisplayName = nTSecurityDescriptor`. Pair the events on `OpCorrelationID` and diff
  the two `AttributeValue`s, as in the run log (`-split '\('` + `Compare-Object`, then
  `ConvertFrom-SddlString`). **A `D;;…;;;WD` entry appearing on its own is the signature of an OU
  being protected. Anything else on that object deserves a person's attention.**
- **Record `(D;;DC;;;WD)` on the domain root as known lab state**, so a future module does not
  rediscover it as an anomaly.

### Finding 2 — A 5136 carries values, and a replacement is two events joined by one ID

**Observation.**

- Step 8.1 set `description` on an OU where it had been **empty**. **One** 5136, `Value Added`,
  value `Module 08 test`, Correlation ID `{83c69c3e-b1cc-4686-bda6-55ddbfcb3701}`. **No
  `Value Deleted`.**
- The domain root's `nTSecurityDescriptor` change (Finding 1) was **two** 5136s, `Value Deleted`
  (old, 3528 characters) and `Value Added` (new, 3540), same second, **same Correlation ID**.
- The event's fields, read by name: `OpCorrelationID`, `AppCorrelationID`, `SubjectUserSid`,
  `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`, `DSName`, `DSType`, `ObjectDN`,
  `ObjectGUID`, `ObjectClass`, `AttributeLDAPDisplayName`, `AttributeSyntaxOID`, `AttributeValue`,
  `OperationType`.
- Values print **raw**: `objectClass` as the OID `1.2.840.113556.1.5.9`, `userAccountControl` as
  `514`, permissions as SDDL.

**Inference.**

- **I assess with high confidence that a 5136 records the *after* value, and that replacing an
  existing value also records the *before* value as a separate `Value Deleted` event**, joined to
  the `Value Added` by `OpCorrelationID`. **This was observed on one attribute only,
  `nTSecurityDescriptor`.** The planned test on a plain string attribute (changing `description` a
  second time) **was declined**, so the behaviour for ordinary attributes is expected, not
  observed.
- **A first write has no "before".** A lone `Value Added` means the attribute was empty, or this is
  the first write to it. It does not mean the event lost the old value.
- This is unusually rich for the Security log. Module 03's 4657 was the only earlier event here
  that carried old and new values. **What a 5136 cannot tell you is the meaning of a raw value**:
  `514`, the OID and the SDDL all need decoding. `ConvertFrom-SddlString` decoded the SDDL on the
  box. The meanings of `514` and the OID are recall, unresolved.

**Recommendation.**

- **Join 5136s on `OpCorrelationID`, never on timestamp.** Same-second events from different
  operations are possible, and the ID is exact.
- **Read `OperationType` before reading `AttributeValue`.** A `Value Deleted` value is the state
  that was *removed*, so read alone it says the opposite of what happened.
- Decode permission values with `ConvertFrom-SddlString`, never by eye.

### Finding 3 — One event ID per operation, but the counts mislead and deletes went unrecorded

**Observation.**

- **Create.** `lab_dirtest` wrote **1 × 5137 plus 3 × 5136** (`objectClass`, `sAMAccountName`,
  `userAccountControl`), all four sharing Correlation ID
  `{4e555345-2e07-4428-998c-bf56feb2f96a}`. **The 5137 carries no attribute fields.**
- **Modify.** One `description` change wrote **1 × 5136**.
- **Delete.** `lab_dirtest` was deleted (readback `Cannot find an object`) and **no 5141** was
  written. `LabAudit` was deleted (readback empty) and **no 5141** was written. **5141 total on
  DC01: 0.**
- Of the **six** 5136s on DC01 after the day's work, **one** was a deliberate modification. Three
  came from one creation and two from a side-effect permission change.
- Neither `LabAudit`'s SACL nor the domain's audited **any delete right**.

**Inference.**

- **Creation and modification have their own IDs, as predicted.** But **a 5136 is not a
  "modification" in the everyday sense**: one user creation produced three of them. **A 5136 count
  overstates deliberate changes.** Here it was six events for one intended change. This is the same
  over-counting shape as Module 07, where one RDP connection wrote three 4624s.
- **A 5137 alone tells you *that* an object was created, not *what* it was created with.** The
  values are only in the 5136s that share its Correlation ID.
- **Deletion was not recorded at all, twice.** The leading hypothesis is that the SACL's rights
  decide whether a delete is audited, the same way the audited rights were Module 02's fourth gate.
  **The discriminating test (add `Delete all child objects`, create and delete a second user,
  recount) was offered and declined. I don't know what causes the missing 5141s**, and this run
  cannot rule out that 5141 behaves differently from expectation on this host.
- **The blind spot this exposes:** with a SACL scoped like this run's, **an attacker's object is
  seen arriving and never seen leaving**. That is Module 03's Event 12-vs-13 gap, reproduced in a
  third store, by a different mechanism.

**Recommendation.**

- **Treat a creation as a unit:** 5137 plus every 5136 sharing its `OpCorrelationID`.
- **If deletions matter, audit them explicitly.** Include `Delete` / `Delete all child objects` in
  the SACL, then **prove a 5141 fires** before relying on it, because this run never saw one.
- **Never count 5136s as "changes made".** Group them by `OpCorrelationID` first.

### Open questions — carried, not scheduled

| Question | What would settle it |
|---|---|
| Is the missing 5141 the SACL's rights mask? | Add `Delete all child objects`, create and delete, recount — **declined 2026-10-23** |
| Does a plain-string replacement write `Value Deleted` + `Value Added`? | Change `description` twice — **declined 2026-10-23** |
| Does the subcategory switch alone silence AD events? | Generate a change on a SACL'd object with `Directory Service Changes` off |
| Is a creation audited against the new object's SACL or the parent's? | Audit `CreateChild` on the parent only, create, look for a 5137 |
| Did accidental-deletion protection add `(D;;DC;;;WD)` to the parent? | Time a protected-OU creation; compare with one made with `-ProtectedFromAccidentalDeletion $false` |
| What do `f30e3bbe-…`, `f30e3bbf-…` and `bf967aa5-…` name? | Resolve the GUIDs on the box against the schema |
| What do `514` and `1.2.840.113556.1.5.9` mean? | Resolve on the box — currently recall |

### Open question — how long does DC01 keep anything?

**Measured 2026-10-12 — answered.** DC01's Security log has **never wrapped**: `oldestRecordNumber`
1, oldest event a 4688 on 2026-07-28, not a 1102. It holds its entire ~76-day history, against
WS01's ~1 day. **Why the two hosts differ is not established**; `maxSize` on each is the first
comparison.

### Declared limitation — no trusts, no replication

Single domain, single DC. Trust enumeration and replication monitoring are **out of scope for this
journal**, not deferred work. Step 4 records the empty baseline and the reason.

---

# Reference

**Event IDs introduced in this module**

| Event ID | Log | Meaning |
|---|---|---|
| 5136 | Security | A directory service object was **modified** — **confirmed 2026-10-23** (`.Message`). Also written during a *creation*, once per attribute filled |
| 5137 | Security | A directory service object was **created** — **confirmed 2026-10-23** (`.Message`). Carries no attribute values |
| 5139 | Security | A directory service object was **moved** — recall, not observed |
| 5141 | Security | A directory service object was **deleted** — recall; **never observed**, two deletes produced none |
| 4662 | Security | An operation was performed on an AD object — **not enabled in this module** |

> **Rows marked recall have not been resolved on the box.** 5136 and 5137 were read from `.Message`
> on DC01; 5139 and 5141 never appeared.

**Audit subcategories**

| Subcategory | Category | Gives | This module |
|---|---|---|---|
| `Directory Service Changes` | DS Access | 5136/5137/5139/5141 | **enabled in Step 7.1** |
| `Directory Service Access` | DS Access | 4662 | **left untouched** |
| `Directory Service Replication` | DS Access | replication events | not used — one DC |
| `Detailed Directory Service Replication` | DS Access | verbose replication | not used — one DC |

**MITRE ATT&CK mapping**

| Technique | ID | Where it appears here |
|---|---|---|
| OS Credential Dumping: NTDS | T1003.003 | Step 3.1 — the file an attacker is after |
| Account Manipulation | T1098 | Steps 8–9 — directory changes and whether they are recorded |
| Domain Trust Discovery | T1482 | Step 4 — the query, run against a forest with no trusts |
| Remote System Discovery | T1018 | Step 1.3 — enumerating domain controllers |
| Impair Defenses: Disable Windows Event Logging | T1562.002 | Step 6 — a gate left shut has the same effect as one turned off |

---

## Notes & gotchas

**From the run (sitting 1, 2026-10-12):**

- **Count with `@( )`.** `(Get-ADDomainController -Filter *).Count` printed **nothing** for one DC;
  `@(Get-ADDomainController -Filter *).Count` printed `1`. Blank, no error, reads like zero.
- **`...` at the end of a value is display truncation, not missing data** —
  `OperationMasterRoles` hid `InfrastructureMaster` this way.
- **A misspelled channel name errors loudly** (`'Directory Sercice'`); only a real channel can
  return a misleading silence.

**From the run (sitting 2, 2026-10-23)** — fuller detail in the sitting 2 run log:

- **An undefined variable is silently `$null`**, so a typo'd name errors on the indexing
  (`Cannot index into a null array`), not on the misspelling.
- **`-Confirm:$false` suppresses the prompt; the action still runs.**
- **Variables die with the window.** Write every boundary time down in UTC so it can be re-set
  by hand — and check the re-set against a known count.
- **Two empty values compare equal.** Check `.Length` before trusting `-eq`.
- **Creating an OU can change its parent's permissions.** Read the parent's SACL and DACL as well as
  the object's.
- **The GPO-overwrite hypothesis below survived one day:** 11.2's readback agreed with 7.1 roughly
  ten hours later. No policy refresh was forced, so it is weak evidence, not a test.

**Carried in from earlier modules** as things to watch for here:

- **Every command in this module runs on DC01.** A query on WS01 returns empty rather than an
  error. Wrong machine is the first entry on the empty-output checklist for a reason.
- **`auditpol /get /subcategory:` takes no space after the colon**, or it fails with
  `Error 0x00000057` and prints usage text that reads like a broken tool.
- **AD cmdlets accept `-Server`** and will silently query a different DC or domain. It cannot
  mislead you in a one-DC lab yet; the habit of naming the target belongs with "always say which
  VM".
- **`netdom`, `auditpol`, `wevtutil` and `reg.exe` print text, not objects.** `Select-Object` on
  their output does not work and does not error usefully.
- **`[xml]` takes one root element** — index into the array first.
- **A cap plus a partial paste invents a missing population.** `Measure-Object` before treating any
  small number as a result.
- **`-FilterHashtable` on live logs, `-FilterXPath` on exported `.evtx`.** Getting this backwards
  returns `NoMatchingEventsFound` while the events sit in the channel — verified WS01 2026-09-29,
  the most deceptive member of the empty-output family, because the channel and the ID were both
  right.
- **Wrong syntax shouts; wrong value whispers.** Two mistyped-event-ID incidents are on record in
  this lab. **Retype before theorising.**
- **The Default Domain Controllers GPO may overwrite `auditpol` settings at policy refresh.**
  **Hypothesis, untested on this host** — `gpupdate` is broken on WS01 but has never been tried on
  DC01. If Step 11.2's readback disagrees with Step 7.1's, this is the first thing to check, and
  settling it would be a finding in its own right.
