# Module 04 — Event Viewer & the Windows Logging Model

> **Runs on:** WS01 and DC01 (both powered on)
> **Time:** ~2 hours, in one sitting or split up
> **Snapshot before starting:** `mod04-start` · **Do _not_ roll back to `01-domain-ready`** (see 0.1)

---

## What you're going to do

Module 01 worked, but the friction wasn't Windows administration — it was log mechanics.
Queries run on the wrong VM. Time windows too narrow. And empty output that looked
identical whether the event never happened, had scrolled out of the log, or was sitting
right there just outside the filter.

**The goal of this module is one skill: telling the difference between "nothing
happened" and "I can't see it."**

There is no new attack here. This module reads the events Module 01 already generated,
then deliberately destroys some of them — twice, in two different ways — so you can see
what each kind of loss looks like from the analyst's side.

Six steps:

1. Where events live, and which machine writes which
2. How to read a single event properly
3. How to build a filter by clicking, and save it
4. How long your logs actually keep anything
5. Make evidence disappear without deleting it
6. Clear a log, and find the event that survives

Most of this is done in **Event Viewer**, with clicks. Where a command is needed, it's
short and there's a line saying what it does.

Each step says **which VM** to run it on.

---

# Step 0 — Pre-flight

### 0.1 Do not restore a snapshot

Every module so far started with a rollback. **This one must not.**

`01-domain-ready` predates the audit policy you turned on in Module 01, and predates
every event Module 01 produced. Restoring it would leave you with auditing off and an
empty log — and this module has nothing of its own to read.

Both VMs should be running, in whatever state Module 01 left them.

### 0.2 Snapshot where you are now

Shut both VMs down and snapshot each as **`mod04-start`**.

This matters more than usual: Steps 5 and 6 destroy the WS01 Security log on purpose,
and this snapshot is the way back.

Start **DC01 first**, wait for the login screen, then start **WS01**.

### 0.3 Count what you have

On **WS01**, log in as `administrator@corp.local`, then right-click
**Start → Terminal (Admin)**.

First, confirm which machine you're on:

```powershell
hostname
```

Should say `WS01`.

Now count the failed logons from Module 01:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | Measure-Object
```

`-FilterHashtable` hands the filter to the log itself — "only give me 4625s from
Security." The filtering happens *before* anything is read. `Measure-Object` counts what
comes back.

**Write the count down.** In Step 5 you'll watch it become zero, and explaining why is
the whole point of the module.

> **Why not `-MaxEvents 500 | Where-Object Id -eq 4625`?** Because it lies quietly.
> `-MaxEvents` takes the newest 500 events **first**, and only then filters them. On a
> machine that has written more than 500 events since the activity you're hunting, the
> events you want never reach the filter — you get a small number back, and it looks
> like an answer rather than a failure.
>
> Measured on WS01, 2026-08-24: the `-MaxEvents` form returned **1**, the
> `-FilterHashtable` form above returned **11**. Same log, same machine, same moment.
> This is the `-MaxEvents` starvation trap from Module 01, and it's the easiest way in
> Windows to convince yourself an attack left no trace.

> If it's already 0, this VM was rolled back at some point. The module still works —
> Steps 5 and 6 make their own material — but you lose the before/after comparison,
> which is the best part of it.

---

# Step 1 — Where events live (WS01)

**Start → Event Viewer.** Expand the tree on the left. It has two halves, and the split
is the most useful thing to understand about Windows logging.

### The three classic logs — `Windows Logs`

| Log | What's in it | Who can write to it |
|---|---|---|
| **Security** | Logons, account management, object access | The kernel only, via audit policy. Ordinary programs **cannot** write here — that's what makes it evidence |
| **System** | Drivers, services, the OS itself | OS components |
| **Application** | Whatever installed programs want to say | Any program |

Reading Security needs administrator rights. That's also why it's the first thing an
attacker with admin wants to touch.

### The modern tree — `Applications and Services Logs`

Expand it, then **Microsoft → Windows**. Several hundred folders. Each one is a
component that ships its own dedicated log, called a **channel**.

The ones you'll use later:

| Channel | What it gives you | Module |
|---|---|---|
| `PowerShell/Operational` | What was actually typed and run | 05 |
| `Sysmon/Operational` | Process, network and registry detail | 03 |
| `TaskScheduler/Operational` | Scheduled tasks — classic persistence | — |
| `TerminalServices-*/Operational` | The RDP session story | 07 |
| `Windows Defender/Operational` | Detections, and exclusions being added | — |

**Most of these channels are off by default.** An empty channel means nothing was
recorded — not that nothing happened. Same trap as a too-narrow time window, one level up.

### See it as a list

Back in **Terminal (Admin)** on WS01:

```powershell
Get-WinEvent -ListLog *
```

`-ListLog` asks about the logs themselves rather than the events inside them. You'll get
a long list and some red errors — a few channels can't be read even as admin. Harmless.

That's too much to read, so narrow it to the ones that actually contain something:

```powershell
Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object RecordCount -gt 0
```

Two additions: `-ErrorAction SilentlyContinue` hides the red errors, and
`Where-Object RecordCount -gt 0` keeps only logs with more than zero records.

📸 **Screenshot this** as `04-log-inventory.png` — it's your whole evidence surface on
one screen.

> **Which machine writes which event.** This is the wrong-machine trap from Module 01,
> stated once properly: **a log records what happened on that machine.** WS01's Security
> log knows only about WS01. Domain account management (4720, 4728, 4740) and Kerberos
> (4768, 4771) are decided by the domain controller, so they're on **DC01** — even when
> the person was sitting at WS01. Run `hostname` before every hunt.

---

# Step 2 — Read one event properly (DC01)

Switch to **DC01**. **Event Viewer → Windows Logs → Security.**

Click **Filter Current Log…** on the right, put `4728` in the **Event IDs** box, click
**OK**. Click the top result — that's `svc_backup` being added to Domain Admins in
Module 01.

The bottom pane has two tabs. Learn both.

### The General tab — the human version

Prose, with SIDs resolved to names wherever Windows can manage it. This is why the rule
in this repo is **Event Viewer first**: it does the translation for you.

Read across it:

| Field | What it tells you |
|---|---|
| **Subject → Account Name** | who did it |
| **Member → Security ID** | who was added — a **SID**, permanent |
| **Member → Account Name** | the same account's **distinguished name** (`CN=…,CN=Users,DC=corp,DC=local`) — a path, so it changes if the object is moved |
| **Group → Group Name** | what they were added to |

### The Details tab — the machine version

Click **Details**, then select **XML View**. You get the raw record:

```xml
<Event>
  <System>
    <EventID>4728</EventID>
    <TimeCreated SystemTime="2026-08-11T02:50:59.123456700Z" />
    <Computer>DC01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="MemberSid">S-1-5-21-...-1105</Data>
    <Data Name="TargetUserName">Domain Admins</Data>
    <Data Name="SubjectUserName">Administrator</Data>
  </EventData>
</Event>
```

Two halves, and the difference matters:

- **`<System>`** — the same fields on *every* event ever written: ID, time, computer.
  This is what you filter on.
- **`<EventData>`** — different for every event ID, with **named** fields. This is where
  the answer to your question lives.

📸 **Screenshot the XML view** as `04-event-xml-view.png`.

### Getting the field names without the GUI

Module 01 used `$_.Properties[4]`, which means "the fifth `<Data>` element, counted by
position." Positions differ per event ID and nothing warns you when you're off by one —
you just get a plausible-looking wrong column.

Ask for the names instead. Two short commands on **DC01**.

Grab one 4728 and put it in a box called `$e`:

```powershell
$e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4728} -MaxEvents 1
```

Now print its named fields:

```powershell
([xml]$e.ToXml()).Event.EventData.Data | Format-Table Name, '#text'
```

`$e.ToXml()` gives the XML you just looked at in the GUI as text; `[xml]` turns that text
into something PowerShell can walk through with dots; the rest walks down to the `Data`
elements and prints each one's `Name` next to its value.

Run that once per event ID you care about and you never guess a position again.

> **Times are stored in UTC.** Compare what Event Viewer shows you with what's actually
> in the record:
> ```powershell
> $e.TimeCreated
> ([xml]$e.ToXml()).Event.System.TimeCreated.SystemTime
> ```
> The second one ends in `Z` — that's UTC. Event Viewer converts to the machine's local
> time for display. Three consequences: a timestamp in a finding is meaningless without
> its timezone; a UTC timestamp pasted into a local-time query searches the wrong window;
> and correlating WS01 with DC01 assumes their clocks agree. Check with `Get-TimeZone`.
>
> **Found on this run, 2026-08-24.** The 4728 stored `2026-08-11T09:50:59Z` but Event
> Viewer displayed `02:50:59 AM` — DC01 was still on the Windows install default of
> Pacific (UTC−7), while the analyst is on WAT (UTC+1). Eight hours out: mid-morning
> activity was reading as 3 AM, and out-of-hours is a real triage signal. Module 01's
> findings were restated in UTC as a result. Fix both VMs with
> `Set-TimeZone -Id "W. Central Africa Standard Time"` — events are stored in UTC, so
> all history simply re-renders correctly.

---

# Step 3 — Build a filter by clicking (WS01)

This is the technique that means you never have to write a filter by hand.

### 3.1 Filter with clicks

On **WS01**: **Event Viewer → Windows Logs → Security → Filter Current Log…**

- **Logged:** Last 7 days
- **Event IDs:** `4625`

**OK.** You should see the Module 01 failures.

### 3.2 Look at what your clicks produced

Reopen **Filter Current Log…** and click the **XML** tab. Windows has written your
clicks out as a query:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) &lt;= 604800000]]]</Select>
  </Query>
</QueryList>
```

Worth decoding once:

- `EventID=4625` — the bit you typed in the box
- `604800000` — 7 days, in **milliseconds**
- `&lt;=` is just `<=`; a bare `<` isn't allowed inside XML

You can copy that text and hand it to PowerShell later with `-FilterXml`, which is how
you turn any GUI filter into a script. You don't need to today.

> **The GUI's User box does not filter on the account in the event.** It filters the
> account the *logging process* ran as — which is `SYSTEM` for nearly every Security
> event. Type `asmith` in that box and you get nothing back, for a 4625 that is
> unambiguously about `asmith`. Filter by event ID and read the account off the General
> tab instead.

### 3.3 Save three views

A **Custom View** is a saved filter, and unlike **Filter Current Log** it can cover more
than one log at a time.

For each one: **right-click `Custom Views` → Create Custom View… → XML tab → tick
`Edit query manually` → paste → OK → name it.**

**View 1 — Failed authentication** (make this on both VMs)

```xml
<QueryList>
  <Query Id="0">
    <Select Path="Security">*[System[(EventID=4625 or EventID=4771 or EventID=4740) and TimeCreated[timediff(@SystemTime) &lt;= 604800000]]]</Select>
  </Query>
</QueryList>
```

On WS01 this shows the 4625s; on DC01 it shows the Kerberos side, 4771 and 4740. Same
view, two halves of one story — Module 01's central lesson, now permanently on screen.

**View 2 — Account and group changes** (DC01)

```xml
<QueryList>
  <Query Id="0">
    <Select Path="Security">*[System[(EventID=4720 or EventID=4722 or EventID=4723 or EventID=4724 or EventID=4725 or EventID=4726 or EventID=4728 or EventID=4729 or EventID=4732 or EventID=4756 or EventID=4767) and TimeCreated[timediff(@SystemTime) &lt;= 2592000000]]]</Select>
  </Query>
</QueryList>
```

Thirty days, because account changes are rare and you want the history.

**This view answers Module 01's open Finding 2.** 4767 (unlocked), 4723 and 4724
(password changed / reset) are all in it. Open it on DC01 and look between the 04:15
lockout and the successful logon that followed — an unlock or a reset in that gap is the
evidence that decides between the two hypotheses.

**View 3 — Log tampering** (both VMs)

```xml
<QueryList>
  <Query Id="0">
    <Select Path="Security">*[System[(EventID=1102 or EventID=1100 or EventID=4719)]]</Select>
    <Select Path="System">*[System[(EventID=104)]]</Select>
  </Query>
</QueryList>
```

Two `<Select>` lines, two different logs, one view — the thing Filter Current Log can't
do. **This view should be empty and boring forever.** Steps 5 and 6 are going to put
entries in it, and that's the point.

Right-click each view → **Export Custom View…** → save the XML. Those files are the
module deliverable.

📸 **Screenshot View 2 on DC01** as `04-custom-view-account-changes.png`.

---

# Step 4 — How long your logs actually keep anything (both VMs)

The question nobody asks until the day it matters.

### 4.1 The GUI answer

**Right-click `Security` → Properties.** You get the log's path, its **current size**,
its **maximum size**, and what happens when it fills.

### 4.2 The command answer

On **WS01**, then again on **DC01**:

```powershell
Get-WinEvent -ListLog Security, System, Application
```

Look at three columns: `RecordCount`, `MaximumSizeInBytes`, and `LogMode`.

Now the number that actually matters — how far back the log reaches:

```powershell
Get-WinEvent -LogName Security -Oldest -MaxEvents 1
```

`-Oldest` reads from the beginning instead of the end, so this is the oldest event still
present. Its timestamp is your **real** retention — not the policy, the reality.

On a busy domain controller with the default 20 MB Security log, that can be **hours**.
That's the blind spot: an intrusion found on Friday, first activity the previous Monday,
and the evidence overwrote itself on Tuesday. Nobody deleted anything.

### 4.3 The three retention modes

| `LogMode` | What happens when the log fills | Verdict |
|---|---|---|
| **Circular** | Oldest events silently overwritten | The default. Silent evidence loss |
| **AutoBackup** | Archived to a new file, log starts fresh | What you want on a DC |
| **Retain** | Stops accepting new events | Almost never — you stop logging entirely |

### 4.4 Fix the DC

On **DC01**, note the current size first, then raise it:

```powershell
wevtutil gl Security
```

`wevtutil` is the log administration tool; `gl` means "get log config". Note the
`maxSize` value so you can put it back.

```powershell
wevtutil sl Security /ms:1073741824
```

`sl` means "set log", `/ms` is max size in bytes — this is 1 GB. Sizes must be multiples
of 64 KB, so stick to round numbers like this one.

📸 **Screenshot the retention output from both VMs** as `04-retention.png`.

---

# Step 5 — Make evidence disappear without deleting it (WS01)

No attacker needed. Just a small log and some noise.

### 5.1 Preserve first

Always before touching a suspect machine. On **WS01**:

```powershell
New-Item -ItemType Directory -Path C:\evidence -Force
```

```powershell
wevtutil epl Security C:\evidence\WS01-Security-before.evtx
```

`epl` means "export log". The `.evtx` is a complete, self-contained copy.

> Paste those two rather than typing them — they contain `\`, which your keyboard
> layout gets wrong.

Check it worked, and note that you can read an exported log on **any** machine:

```powershell
Get-WinEvent -Path C:\evidence\WS01-Security-before.evtx -FilterXPath "*[System[(EventID=4625)]]" | Measure-Object
```

Same count as Step 0.3. (`-FilterXPath` is the filter-first equivalent for a file on
disk — `-FilterHashtable` only works on live logs.) That's the whole trick to offline forensics: collect the
`.evtx`, analyse it elsewhere.

> **Never commit `.evtx` files.** `.gitignore` already excludes exported logs — they
> carry hostnames, usernames, IPs and SIDs.

### 5.2 Note where the log currently is

```powershell
wevtutil gli Security
```

`gli` means "get log info" — the log's *state* rather than its config. Note
**`oldestRecordNumber`** and **`numberOfLogRecords`**.

Record numbers only ever count upward, so a jump in `oldestRecordNumber` is direct proof
that records were overwritten, and the size of the jump tells you how many.

### 5.3 Shrink the log

```powershell
wevtutil gl Security
```

Note the `maxSize` — you restore it in Step 6.4.

```powershell
wevtutil sl Security /ms:1048576
```

1 MB. Small, but not unrealistic — plenty of real machines fill their default just as
fast.

### 5.4 Make noise

Turn on process creation logging first:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

That's event **4688**, one per process started — the most useful ID in Windows and also
the noisiest, which is what makes it a good flood. Module 05 uses it properly.

Now start two thousand processes:

```powershell
1..2000 | ForEach-Object { & cmd.exe /c exit }
```

`1..2000` is the numbers 1 to 2000; `ForEach-Object { }` runs the block once for each;
the block starts `cmd.exe` and immediately exits. Takes about a minute.

### 5.5 Look at what you lost

```powershell
wevtutil gli Security
```

`oldestRecordNumber` is now far higher than in 5.2.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | Measure-Object
```

**Count: 0.** Note this is the filter-first form from Step 0.3 — nothing is being
starved here. The events are genuinely gone.

Sit with that for a second. The query is right. The machine is right. And it returns
nothing — for events you watched being created a few days ago, and which are still
sitting in the file you exported ten minutes ago:

```powershell
Get-WinEvent -Path C:\evidence\WS01-Security-before.evtx -FilterXPath "*[System[(EventID=4625)]]" | Measure-Object
```

📸 **Screenshot the live query returning 0 next to the export returning your Step 0.3 count** as
`04-overwritten-vs-archive.png`. Best single image in the module.

### 5.6 The lesson

An empty result has four causes, and the output looks identical for all of them:

1. **Wrong machine** — `hostname`
2. **Window too narrow** — widen it, or drop the time filter entirely
3. **The events existed and were overwritten** — `wevtutil gli`, and Step 4's oldest-event
   check
4. **Auditing was never on** — `auditpol /get /category:*`

Before this module you could only check the first two. Cause 3 is the one that turns
"nothing happened" into "we cannot say."

> **This is also an attack technique.** Shrinking a log so recent activity rolls off is a
> recognised way to impair logging (T1562.002), and it's far quieter than clearing —
> there's no 1102, no obvious alert. The only traces are a changed log configuration and
> an oddly high `oldestRecordNumber`. Which is why Step 4 is worth running as a routine
> health check, not just during an investigation.

---

# Step 6 — Clear a log (WS01)

Now the loud version.

### 6.1 Clear the Security log

**Event Viewer → Windows Logs → right-click `Security` → Clear Log…**

Choose **Clear** (not *Save and Clear* — you already exported in 5.1).

### 6.2 Find the event that survived

```powershell
Get-WinEvent -LogName Security -MaxEvents 5
```

The log is empty except for one record: **1102, "The audit log was cleared"** — with the
account that did it.

Windows writes 1102 into the Security log as the very first record *after* clearing it.
You cannot clear the Security log without leaving that behind. Clear it again and you
just get a second 1102.

### 6.3 Now a different log

**Right-click `Application` → Clear Log → Clear.** Then:

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=104}
```

**104** landed in **System**, and it names which log was cleared.

The asymmetry is worth memorising:

| Log cleared | Event written | Where it lands |
|---|---|---|
| Security | **1102** | Security itself |
| Anything else | **104** | System |

Open your **View 3 — Log tampering** on WS01. The view that was supposed to stay empty
forever now has both events in it. That's what the alert looks like.

📸 **Screenshot View 3** as `04-1102-log-cleared.png`.

**Read it like an analyst.** There is no legitimate operational reason to clear a
workstation's Security log — this isn't maintenance. Two things follow immediately:
pivot to the logs they *didn't* clear, and treat the 1102 timestamp as the anchor for
your whole timeline.

And the bigger point: everything you found in Module 01 on **DC01** would have survived
this completely. Getting logs off the host is the only real defence — which is what the
mini-SIEM module exists to do.

### 6.4 Put WS01 back

```powershell
wevtutil sl Security /ms:20971520
```

Use whatever `maxSize` you noted in 5.3. Confirm:

```powershell
Get-WinEvent -ListLog Security
```

Leave the `Process Creation` auditing **on** — Module 05 needs 4688.

Optionally, on **DC01**, make the Security log archive instead of overwrite:

```powershell
wevtutil sl Security /ab:true /r:false
```

Never set `/r:true` on its own — that's Retain mode, and the log stops accepting events
once full.

---

# Evidence for the portfolio

Save into `../assets/`:

- [ ] `04-log-inventory.png` — every log that contains records
- [ ] `04-event-xml-view.png` — the Details → XML view of a 4728
- [ ] `04-custom-view-account-changes.png` — View 2 on DC01
- [ ] `04-retention.png` — log sizes and oldest event, both VMs
- [ ] `04-overwritten-vs-archive.png` — live query 0, export 5
- [ ] `04-1102-log-cleared.png` — View 3 with the 1102 and 104

Plus the three exported custom-view XML files. "I built the saved views a SOC runs on"
is a concrete thing to point at in an interview.

---

# Findings

**Write these after the run**, in the same **observation → inference → recommendation**
form as Module 01, with the three kept strictly separate.

Two are set up for you:

### Finding 1 — Security log evidence loss on WS01 (Step 5)

The observation is the interesting part: the record-number gap from `wevtutil gli`, the
configured maximum size, the timestamp of the oldest surviving event, and the events
known to be missing. The inference has to name both hypotheses honestly — **routine
circular overwrite under normal volume** versus **deliberate log-size reduction to force
evidence off the host (T1562.002)** — say which you favour and why, and state what would
tell them apart: a 4719 audit-policy change, or a log configuration change correlated in
time with other suspicious activity.

### Finding 2 — Security log cleared on WS01 (Step 6)

Observation: the 1102 timestamp, the account, and the 104 in System naming the
Application log. Inference: T1070.001, and be explicit about **what can no longer be
determined** — naming the specific gap is what separates a real finding from "logs were
cleared."

Note in both that you performed these actions yourself. Writing a lab finding as though
the activity were unattributed is a good exercise; presenting it as a real detection
isn't.

---

# Reference

### Event IDs from this module

| ID | Log | Meaning |
|---|---|---|
| **1102** | Security | **The Security log was cleared** — written into Security itself |
| **1100** | Security | Event logging service shut down (normal at shutdown, suspicious otherwise) |
| **104** | System | **A log other than Security was cleared** — names which one |
| **4719** | Security | **Audit policy was changed** — auditing being turned off |
| **4688** | Security | Process created (enabled in Step 5.4) |

### `wevtutil` — the log administration tool

| Command | What it does |
|---|---|
| `wevtutil gl <log>` | Get log **config** — max size, retention mode |
| `wevtutil gli <log>` | Get log **state** — size, record count, oldest record number |
| `wevtutil sl <log> /ms:<bytes>` | Set max size (multiples of 64 KB) |
| `wevtutil sl <log> /e:true` | Enable a disabled channel |
| `wevtutil sl <log> /ab:true /r:false` | Archive when full instead of overwriting |
| `wevtutil epl <log> <file.evtx>` | **Export** a log for offline analysis |

### The three ways to filter

| Method | Use it when |
|---|---|
| **Event Viewer filter / custom view** | Reading a handful of events, or you want fields resolved and labelled — **start here** |
| **`-FilterHashtable`** | Scripted checks on a live log, like the counts in this module. **Filters before reading** — can't be starved |
| **`-FilterXPath`** | The same, on an exported `.evtx` file |
| **`-FilterXml`** | Multi-log queries. Build it in the GUI and copy the XML out |

### MITRE ATT&CK

| Technique | ID | Where in this module |
|---|---|---|
| Indicator Removal: Clear Windows Event Logs | T1070.001 | Step 6 |
| Impair Defenses: Disable Windows Event Logging | T1562.002 | Step 5 (shrinking), 4719 |
| Log Enumeration | T1654 | Step 1 — attackers inventory logs too |
| Data from Local System | T1005 | Step 5.1 — collection cuts both ways |

---

# If something goes wrong

**`Get-WinEvent` returns nothing.**
Work through these in order — you can now answer all four:

1. **Wrong machine.** `hostname`. Domain events on DC01, workstation logon failures on
   WS01.
2. **Window too narrow, or the search was starved.** Widen `StartTime`, and make sure
   you're filtering with `-FilterHashtable` rather than filtering after `-MaxEvents`.
3. **The events were overwritten.** `wevtutil gli <log>` — a high `oldestRecordNumber`,
   or an oldest event newer than the period you're asking about, means they're gone and
   no query recovers them.
4. **Auditing genuinely off.** `auditpol /get /category:*`.
5. **The channel is disabled.** `Get-WinEvent -ListLog <name>` and check `IsEnabled`.
   Turn it on with `wevtutil sl <name> /e:true`.

**A count comes back suspiciously low, and Event Viewer shows more.**
You filtered *after* limiting. `-MaxEvents 500 | Where-Object Id -eq 4625` takes the
newest 500 events first, then filters those — so anything older never reaches the
filter. Measured on WS01 during this module's own run: that form returned **1**, while
`Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625}` returned **11**.

Rule: **filter first, limit second.** Use `-FilterHashtable` on live logs and
`-FilterXPath` on exported `.evtx` files. Keep `Where-Object` for narrowing results that
are already correctly filtered.

**`wevtutil sl` says "The parameter is incorrect."**
The size isn't a multiple of 64 KB. Use round values: `1048576` (1 MB), `20971520`
(20 MB), `1073741824` (1 GB).

**"Access is denied" from `wevtutil`, or the Security log won't open.**
The session isn't elevated. Close it and open with right-click **Start → Terminal
(Admin)** — the title bar must say **Administrator:**.

**A custom view saves but shows nothing.**
Usually the wrong VM — View 2 is nearly empty on WS01 by design. Otherwise check the
`timediff` number: it's **milliseconds**, so 7 days is `604800000`, not `604800`.

**The GUI's User box returns nothing for an account you can see in the event.**
Expected — see Step 3.2. That box filters the logging account, not the account the event
is about.

**`Get-WinEvent -ListLog *` prints red errors.**
Some channels can't be queried even as admin. Add `-ErrorAction SilentlyContinue`.

**The flood didn't overwrite anything.**
The log wasn't actually shrunk. Run `wevtutil gl Security` and confirm `maxSize` reads
`1048576`; if not, the `sl` command didn't run elevated.

**You need Module 01's WS01 events back.**
Read them from `C:\evidence\WS01-Security-before.evtx`. If you skipped 5.1, restore the
`mod04-start` snapshot.

---

**Next:** → [Module 05 — PowerShell for Defenders](./05-powershell-for-defenders.md) *(not written yet)*
