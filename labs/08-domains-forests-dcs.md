# Module 08 — Domains, Forests & Domain Controllers

> **Runs on:** DC01 only. WS01 is not needed and should stay powered off
> **Time:** ~2 hours, split across two sittings
> **Roll back to:** `mod04-start` · **Snapshot before starting:** `mod08-start` (DC01)
> **Status:** written 2026-10-01. **Not yet run.** Everything marked **prediction** is an
> expectation to be tested, not a fact. Correct this file from the run.

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
| 08 | **Active Directory** | **`Directory Service Changes`** | **the SACL on the AD object** |

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
> should find no event for it.

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

```powershell
$d = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136} -MaxEvents 1
```

```powershell
$d.Message
```

`.Message` renders every field with its label, which is what Event Viewer's General tab shows and
is easier than XML for a first look.

Then pull the fields by name:

```powershell
([xml]$d.ToXml()).Event.EventData.Data | Format-Table Name, '#text'
```

> **`[xml]` accepts exactly one root element.** `$arr.ToXml()` without an index concatenates every
> event's XML and fails with *"this document already has a DocumentElement node"* — which reads
> like a parser fault rather than a missing subscript. Assign one event to its own variable first,
> as above.

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

The `LabAudit` OU was created in Step 7.2, **before** the SACL existed. Look for it:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5137} | Where-Object { $_.Message -like '*LabAudit*' }
```

**Prediction: nothing, while 9.3 returned a count above zero.** That combination is the finding —
the same argument structure as Module 03's Finding 2, where the query that missed two writes
*returned* the third, so wrong-host, narrow-window, rotation and channel-off were all excluded by
the query's own positive result.

> **If 9.3 found nothing either, you have not got a result — you have got an unproven instrument.**
> Go back to 7.1 and 7.4 and establish which gate is still shut. Do not write a finding until one
> of these queries returns something.

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

| | Value | Read from |
|---|---|---|
| Forest name | | `Get-ADForest` |
| Forest mode | | `Get-ADForest` |
| Domains in forest | | `Get-ADForest` |
| Domain DNS root / NetBIOS | | `Get-ADDomain` |
| Domain distinguished name | | `Get-ADDomain` |
| Domain SID | | `Get-ADDomain` |
| Domain controllers | | `Get-ADDomainController -Filter *` |
| Global catalog | | `Get-ADDomainController -Filter *` |
| Site | | `Get-ADDomainController -Filter *` |
| Trusts | | `Get-ADTrust -Filter *` |
| `ntds.dit` path | | NTDS registry parameters |
| SYSVOL / NETLOGON shared | | `Get-SmbShare` |
| Security log horizon | | `wevtutil gli Security` |

### 10.2 The FSMO role map

| Role | Scope | Held by |
|---|---|---|
| Schema Master | Forest | |
| Domain Naming Master | Forest | |
| PDC Emulator | Domain | |
| RID Master | Domain | |
| Infrastructure Master | Domain | |

### 10.3 Two sentences in your own words

Not a summary of the commands — the thing the inventory means:

> Why does an attacker who reaches `ntds.dit` not need to crack anything afterwards?

> This lab has one DC holding all five FSMO roles. Name one specific thing that breaks if it is
> offline, and say which log you would check first.

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

- [ ] `08-forest-domain.png` — `Get-ADForest` and `Get-ADDomain` output together: the shape of
      the directory in one image
- [ ] `08-fsmo-roles.png` — `netdom query fsmo`, all five roles on one host
- [ ] `08-ntds-sysvol.png` — the NTDS parameters and `Get-SmbShare` side by side: the two things
      on disk that are the domain
- [ ] `08-no-trusts.png` — `Get-ADTrust -Filter *` returning nothing, **with `Get-ADForest`'s
      populated `Domains` in the same frame as the control.** The empty result is only evidence
      beside the thing that proves the query works
- [ ] `08-ds-access-gates.png` — `auditpol /get /category:"DS Access"` **before** the change. This
      is the one that cannot be retaken later
- [ ] `08-5136-change.png` — the 5136 field table from 9.2, showing the attribute and its old and
      new values
- [ ] `08-sacl-control.png` — 9.3's non-zero count beside 9.4's empty `LabAudit` result. **The pair
      is the module's central evidence**, in the same way `06-5152-stealth.png` was Module 06's

---

# Findings

> **Nothing here yet — this module has not been run.** Below are the questions the run is designed
> to answer, each with the evidence that would settle it. **No finding gets written until a
> controlled observation survives**, and a hypothesis must never inherit the grammar of a fact.
> Findings use **observation → inference → recommendation**, kept strictly separate, with
> timestamps in **UTC**.

### Candidate Finding 1 — Windows object auditing is gated the same way in a third store

**Settled by:** Step 9.4 returning nothing for `LabAudit` while 9.3 returns a non-zero count.

If the pattern holds across NTFS, the registry and Active Directory, the inference is that this is
**architectural rather than per-store**, and the recommendation is a reusable pre-flight: *before
generating activity against any audited object, read the subcategory and the object's SACL and
confirm both.* If it does **not** hold — if AD logs changes without a SACL, or ignores one — that
is the more interesting result and the comparison table in "What you're going to do" needs
rewriting.

### Candidate Finding 2 — A directory change is logged with before and after values

**Settled by:** the 9.2 field table.

The Security log usually says *what happened*, not *what the value used to be* — Module 03's 4657
was unusual in carrying `OldValue`/`NewValue`. If 5136 does the same for AD attributes, say so
precisely, and name what it still cannot tell you.

### Candidate Finding 3 — Create, modify and delete are three different event IDs

**Settled by:** Steps 9.1 and 9.3.

This is Module 03's Event 12-vs-13 question in a new store: a hunt written for only one ID sees
part of the activity and reports it as all of it. State the specific blind spot a 5136-only hunt
would have.

### Open question — how long does DC01 keep anything?

**Measured in Step 5.3.** WS01 holds roughly one day. DC01's horizon has never been measured, and
every conclusion in Modules 01, 06 and 07 that rests on a DC01 timestamp depends on it.

### Declared limitation — no trusts, no replication

Single domain, single DC. Trust enumeration and replication monitoring are **out of scope for this
journal**, not deferred work. Step 4 records the empty baseline and the reason.

---

# Reference

**Event IDs introduced in this module**

| Event ID | Log | Meaning |
|---|---|---|
| 5136 | Security | A directory service object was **modified** |
| 5137 | Security | A directory service object was **created** |
| 5139 | Security | A directory service object was **moved** |
| 5141 | Security | A directory service object was **deleted** |
| 4662 | Security | An operation was performed on an AD object — **not enabled in this module** |

> **Everything in that table except the channel is recall until the run confirms it.** Resolve
> meanings on the box via `.Message` or Event Viewer's General tab, and correct this table from
> what the host actually printed.

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

**To be filled in from the run.** Carried in from earlier modules as things to watch for here:

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
