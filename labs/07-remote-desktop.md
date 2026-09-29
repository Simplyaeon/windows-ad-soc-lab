# Module 07 — Remote Desktop (RDP)

> **Runs on:** WS01 **and** DC01 — WS01 is the machine being connected *to*, and that is
> where nearly all the evidence lands
> **Time:** ~2 hours, best split across three sittings
> **Roll back to:** `mod06-start` · **Snapshot before starting:** `mod07-start` (both VMs)
> **Status:** written 2026-09-22. **Sitting 1 complete 2026-09-25 (two parts) — see the run log below.**
> Everything marked **prediction** is an expectation to be tested, not a fact. Correct this file
> from the run.

---

## What you're going to do

Remote Desktop lets you sit at one machine and use another one's screen and keyboard as
though you were in front of it. Administrators use it constantly. So do attackers — a
stolen password plus RDP is the cheapest way to move from one machine to the next inside a
company, which is why it is one of the most-watched things in a SOC.

**This module is about reconstructing one remote session from the logs alone.**

You will make a single RDP connection from DC01 to WS01, use it, disconnect, reconnect, and
log off. Then you will go and find that session in the logs — and discover that Windows did
not write the story in one place. It scattered it across **four separate logbooks**, each
holding a different slice.

The work is joining them back together. That means answering a question that sounds trivial
and is not: **what field proves that an entry in one log and an entry in another log are the
same session, and not two things that merely happened at a similar time?** Timestamps are not
enough — on a busy host two sessions seconds apart would be indistinguishable.

Then you will do the same for a logon that **fails**, and run one controlled experiment on
the switch that plausibly decides how much a failure records at all.

### The question this module is really asking

Module 06 ended on a structural result: the firewall instruments went quiet exactly when the
attempt **did not succeed**. A probe of a closed port could not be attributed by anything in
this lab, because every instrument only became informative once the connection completed.

**The hypothesis here is that RDP has the same shape, and that NLA is the mechanism.**

**Network Level Authentication** makes you prove who you are *before* a desktop session is
built. If that is how this host behaves, a wrong password should be rejected before any
session exists — so the two session logbooks should stay silent, and only the Security log
should record the failure.

> **This is a hypothesis, not a fact.** It has not been tested on this host and version-specific
> event behaviour is exactly the thing CLAUDE.md says to resolve on the box rather than from
> memory. It is worth building the module on because it is **falsifiable**: Step 9 runs the same
> failed logon twice, with NLA on and then off, changing one variable. Either outcome is a
> result. If the session logs *do* record NLA-rejected attempts, the hypothesis is dead and that
> is the finding.

In this module you will:

1. Read all four logbooks before changing anything, and prove each one is switched on
2. Turn on Remote Desktop on WS01 and give one account permission to use it
3. Arm Sysmon for RDP *before* the break — Module 06's Finding 5 in one line
4. Make one real session: log on, disconnect, reconnect, log off
5. Find the session in the Security log
6. Find the same session in the two Remote Desktop logs
7. **Join them** — work out what actually ties the four together
8. Fail a logon on purpose and see how much less gets recorded
9. Turn NLA off, fail it identically, and compare — one variable
10. Write the access story: who, from where, when, what happened, when it ended

Follow the steps in order. **Every step says which VM.** The evidence is almost all on WS01
this time, which is the reverse of Module 06 — a query on the wrong machine returns empty
rather than an error.

---

### Three words you need first

**A session** is your working environment on a machine — your desktop, your open windows, the
programs you are running. When you log on, Windows builds one and gives it a number. When you
log off, it tears it down.

**Disconnecting is not logging off.** This is the distinction the whole module leans on. If you
close the Remote Desktop window, your session **stays alive on the far machine** with everything
still running — you have walked away from the desk, not gone home. Logging off ends it. The two
produce different events, and an attacker who disconnects rather than logs off leaves a live
session sitting there with their access in it. That is a real technique, not a curiosity.

**NLA (Network Level Authentication)** decides *when* you have to prove who you are. With NLA on,
you authenticate first and a desktop is built only if that works. With it off, the far machine
builds you a desktop and shows you a login screen inside it. The security difference is that NLA
makes an unauthenticated stranger unable to reach the desktop machinery at all; the **logging**
difference is what Step 9 measures.

---

### Sitting split

| Sitting | Steps | Ends with |
|---|---|---|
| 1 | 0 – 3 | Module 06 closed out, four logbooks verified alive, RDP on, Sysmon armed, nothing triggered yet |
| 2 | 4 – 7 | One complete session made, found in all four logs, and joined |
| 3 | 8 – 11 + Findings | The failed logon, the NLA experiment, the access story, evidence, write-up |

Sitting 2 is the one that produces the deliverable. Do not start it with twenty minutes left.

---

# Run log — Sitting 1 (2026-09-25, complete)

**Every value here was pasted back from the machine.** Anything not listed was not read, and is
**unknown** rather than done.

### Completed and verified

| Step | Reading | Value |
|---|---|---|
| 0.1 | `Test-ComputerSecureChannel` (WS01) | **True** |
| 0.2 | `Get-ADUser asmith` (DC01) | **exists** |
| 0.3 | Lockout threshold / observation window (DC01) | **5** / **10 minutes** — matches Module 01 |
| 0.4 | `mod07-start` snapshots | **taken on both VMs**, clean shutdown, both restarted |
| 1.1 | `auditpol` `Logon` (WS01) | **Success and Failure** |
| 1.1 | `auditpol` `Logoff` (WS01) | **Success and Failure** |
| 1.2 | LocalSessionManager/Operational (WS01) | **`IsEnabled: True`**, `LogMode: Circular`, **725 records**, `FileSize` = `MaximumSizeInBytes` = **1,052,672** |
| 1.2 | … oldest event | **2026-07-28**, `oldestRecordNumber` **1** |
| 1.2 | RemoteConnectionManager/Operational (WS01) | **`IsEnabled: True`**, **`RecordCount: 0`** |
| 1.3 | Security 4624 count (WS01) | **172** |
| 1.3 | Sysmon Event 3 count (WS01) | **1** |

### What these settled

**Both Remote Desktop channels are enabled by default on this build.** That was an open
prediction in this sheet and it is now closed — no gate to open, for either channel.

**`RemoteConnectionManager` holds zero records**, which is the strongest possible baseline: the
channel works and has never recorded anything, so every event appearing in it after Step 4 is
unambiguously this module's. RDP has genuinely never been used on WS01.

**`LocalSessionManager` has never rotated**, and the way that was established corrected a piece of
guidance in CLAUDE.md. `FileSize` read **exactly equal** to `MaximumSizeInBytes`, which was first
called as "the log is full and overwriting" — wrong. `oldestRecordNumber` came back **1**, meaning
nothing has ever been discarded, and the 2026-07-28 oldest event is WS01's true beginning rather
than a rotation boundary (the same date as the Security log's oldest event, recorded in Module
04). **An event log file is allocated at its configured size regardless of how full it is**, so
comparing those two numbers says nothing about rotation. `oldestRecordNumber` is the reliable
test. At 725 records across 59 days the channel runs at roughly **12 events a day** — no rotation
pressure, which also lowers the urgency of the Step 6.6 export.

### Part 2 — Steps 2.1 – 3.2 (same day, resumed)

The sitting had stopped at Step 2.1 with Remote Desktop not yet enabled. It resumed there and ran
to the end of Step 3.

| Step | Reading | Value |
|---|---|---|
| 2.1 | Remote Desktop enabled via `SystemPropertiesRemote.exe`, NLA box left ticked | **applied** |
| 2.2 | `fDenyTSConnections` (WS01) | **0** — RDP enabled |
| 2.2 | `UserAuthentication` (WS01) | **1** — NLA required. **This is Step 9.5's restore value** |
| 2.3 | `Get-NetConnectionProfile` (WS01) | `NetworkCategory` = **`DomainAuthenticated`** |
| 2.3 | `Get-NetFirewallRule -DisplayGroup 'Remote Desktop'` | **3 rules, all `Enabled: True`, all Inbound, all `Profile: Any`** — `Shadow (TCP-In)`, `User Mode (TCP-In)`, `User Mode (UDP-In)` |
| 2.3 | Rule-change events, 30-minute window | **7 × 4947**, **3 × 4948**, **0 × 4946** |
| 3.1 | `Get-LocalGroupMember -Group 'Remote Desktop Users'` | **`asmith`**, `PrincipalSource` = **ActiveDirectory** |
| 3.2 | `Sysmon64.exe -c sysmon-registry.xml` | **`Configuration updated`** |
| 3.2 | Live config readback (`-c`, no filename) | **both ports (9999, 3389) and the registry rules present** — reported, not pasted |

### What part 2 settled

**Enabling Remote Desktop writes 4947, not 4946 — and this sheet predicted 4946.** Step 2.3 said
to watch for a 4946 ("a rule was added"). The window contained **none**. What it contained was
**seven 4947s inside a two-second burst at 09:39:25–09:39:26 UTC** — the signature of one
programmatic action rather than a person clicking. The Remote Desktop rules **already existed** on
WS01, shipped disabled; turning RDP on flipped their `Enabled` flag and Windows logged them as
**modified**.

**That sharpens what 4946 means for detection.** It is not "someone changed the firewall" — it is
specifically **"a rule that was not there before now is"**. A hunt written only for 4946 would
miss a machine being opened up to RDP entirely, because opening it up modifies rules that Windows
already shipped. **This is a candidate for Finding 5**, which is reserved for whichever prediction
the run kills.

**Not established: why seven 4947s for three rules.** `-DisplayGroup 'Remote Desktop'` returned
three rules; the burst holds seven events. More rules in the group than that filter returns, more
than one 4947 per rule, or unrelated rules modified in the same instant are all consistent with
the evidence. **No cause established**, and it was not chased.

**The three 4948s are not this module's.** 09:37:18, 09:48:02 and 09:55:10 UTC — scattered, one
*before* the toggle burst and two *after*, none aligned with it. Module 06 recorded firewall
rule-change events appearing unattended on **DC01**; this is the first sighting of the same
pattern on **WS01**, and something deleting firewall rules roughly every seven minutes with nobody
touching the machine has **no established cause**. Recorded as an observation. Note also that the
oldest row sat **on the query's window boundary**, so the series may extend further back than the
query could see.

**The firewall rules read `Profile: Any`, not `Domain`.** `Any` covers the Domain profile that
WS01 is actually on, so nothing was blocked — but the recorded value is `Any`. Worth being exact:
this module's own pre-flight predicted a per-profile check would matter, and on this host it did
not, because the shipped rules are not profile-scoped at all.

### Where the sitting stopped

**Sitting 1 is complete.** Steps 0 through 3 are done and every state change was confirmed by an
independent readback rather than by the action appearing to succeed.

**Resume at Step 4 — the break.** That is the sitting that produces the deliverable; do not start
it with twenty minutes left.

**Closed after the sitting** (reported 2026-09-25): `C:\Tools\sysmon-registry.xml.bak` **exists**,
the live-config screenshot **was captured on WS01**, and the readback's schema version reads
**4.90** — matching the v15.15 build on record, and confirming `-c` was printing the live config
rather than echoing the file.

### Start the next session with these

Four items, left deliberately rather than forgotten. **None blocks Step 4**, and only the first
two decay with time.

**1. Move two screenshots onto the Mac and into `assets/`.** Both exist on the Windows machine but
**not in the repo** — screenshots pasted into a chat do not land on disk.

| File | What it shows | Why it matters |
|---|---|---|
| `07-sysmon-config.png` | the `.\Sysmon64.exe -c` live readback | proves both ports **and** Module 03's registry rules loaded together |
| `07-4947-rules-modified.png` | the `Remote Desktop` rule table **and** the 4946/4947/4948 query, one frame | **the evidence behind this sitting's whole result** — three `Profile: Any` rules, the seven-4947 burst at 10:39:25–26 local, and the absent 4946. Finding 5 currently rests on text with no image behind it |

**2. Find the 4732** from the Step 3.1 group addition, on **WS01**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732; StartTime=(Get-Date).AddHours(-3)} | Select-Object TimeCreated, Id
```

Widen the window if the sitting is on a later day. "A member was added to a security-enabled
**local** group" — the local-scope cousin of Module 01's 4728; `Computer` is the field that tells a
machine-local group from a domain one. **An empty result is interesting, not broken** — check the
subcategory before concluding anything.

**3. Module 06's last item — `06-5152-ws01-empty.png`.** Still capturable at any time, and Module
06 cannot be called complete without it. `06-sysmon3-zero.png` is **permanently outstanding**:
Step 3.2 has added 3389 to the config, so the zero state can no longer be re-derived.

**4. Optional — file the 2026-09-15 `Test-NetConnection` capture as Module 06 evidence.** Three
knocks to `10.0.0.10:9999`, all `TcpTestSucceeded: False` with `PingSucceeded: True` at 1 ms. It is
**Finding 2's ground truth** — a closed port on a *live* host, not an unreachable host — and it
identifies its own machine from inside the frame via `SourceAddress : 10.0.0.20`, which is stronger
than the `PS C:\Users\Administrator>` prompt that left `06-auditpol-before.png` unattributable.

**Then Step 4.** Give it a clear run — it is the sitting that produces the deliverable.

### Carried over from Module 06

`06-sysmon3-zero.png` was **deliberately dropped** on 2026-09-25 rather than captured before the
Step 3.2 config change. `06-5152-ws01-empty.png` is still capturable at any time and remains
outstanding.


# Run log — Sitting 2 (2026-09-28, Steps 4–7 complete)

### Step 4 — ground truth, as recorded live

All five times are **UTC**, read with `(Get-Date).ToUniversalTime()` on **DC01** except row 2,
which was read inside the session on **WS01**.

| # | What was done | UTC |
|---|---|---|
| 1 | Clock read on DC01 *before* connecting | **09:14:50** |
| 2 | `whoami` inside the session → **`corp\asmith`** | **09:35:03** |
| 3 | **Disconnected** — closed the RDP window, did not sign out | **09:38:35** |
| 4 | **Reconnected** — PowerShell still open with the 09:35:03 output visible | **09:41:07** |
| 5 | **Signed out** via Start → account icon → Sign out | **09:41:46** |

**Row 1 is not the connect time**, only an upper bound on it: a forgotten password and the RDP
certificate dialog put roughly twenty minutes between reading the clock and landing on the
desktop. The authoritative logon timestamp comes from the 4624 and the 1149.

**The session survived the disconnect, verified from the user's side before any log was read.**
The PowerShell window reopened at 09:41:07 still carrying its 09:35:03 output — nothing was
restarted or reopened. So the logs have to explain a session that *detached* at 09:38:35 and
only genuinely *ended* at 09:41:46, a distinction of 3m11s.

**Incidental, and to be labelled as the analyst's own footprints in any later hunt:** `asmith`'s
password was not remembered at the start of the sitting; failed attempts and any reset performed
on DC01 belong to this sitting, not to an intruder. Which route was used — the documented
`Lab-Passw0rd!` or a reset — was **not reported**, so whether a **4724/4738** exists on DC01 at
around 09:20 UTC on 2026-09-28 is **unknown** and must be read off the log rather than assumed.

### Step 5 — the Security log half

**The session you sat in is Logon ID `0x4F246D`, 4624 at 09:30:26 UTC.** Finding it was not
straightforward and the route matters as much as the result.

**One RDP attachment writes three 4624s, not one.** Eight 4624s name `asmith`, in three groups:

| UTC | Subject Logon ID | Type | New Logon ID |
|---|---|---|---|
| 09:30:20 | `0x0` | **3** | `0x4E9917` |
| 09:30:24 | `0x0` | **3** | `0x4E9C62` |
| **09:30:26** | `0x3E7` | **10** | **`0x4F246D`** |
| 09:40:27 | `0x0` | **3** | `0x727717` |
| 09:40:49 | `0x0` | **3** | `0x7376F6` |
| 09:40:54 | `0x3E7` | **10** | `0x741EE0` |

*(Two further 4624s at 09:22:39 and 09:23:55 were returned by the same query but their fields were
not read — **unknown**, not absent.)*

Two **Type 3** network logons with **no requesting subject** (`0x0`) precede each **Type 10**,
which carries SYSTEM (`0x3E7`) as subject. The Type 3 pair is NLA checking credentials over the
network before any session exists. **Counting Type 10s over-counts sessions by one per reconnect;
counting all of a user's 4624s over-counts by three**, and the Type 3s are indistinguishable from
ordinary file-share access if only the type is read.

**The newest Type 10 is a trap.** `0x741EE0` (09:40:54) is Type 10 with `Source Network Address
10.0.0.10`, and looks exactly like the session — but it got a **4634 at 09:41:03**, a **nine-second**
logon that had already ended before the user was back at the desktop (reconnect noted 09:41:07).
`Select-Object -First 1` picks it. **The newest matching event is not the same thing as the right
event.**

**The join key works, and it is a genuine pivot.** `0x4F246D` is carried by **479 events**:

| Count | ID | | Count | ID |
|---|---|---|---|---|
| 154 | **4688** process creation | | 14 | 4797 blank-password query |
| 154 | 5379 Credential Manager read | | 1 | **4624** logon |
| 50 | 4670 permissions changed | | 1 | **4647** logoff |
| 50 | 4658 handle closed | | 1 each | 5058 / 5059 / 5061 |
| 27 | 4656 handle requested | | 25 | 4690 handle duplicated |

**Span 09:30:26 (4624) → 09:42:20 (4647).** The 154 × 4688 is what a Logon ID buys that a timestamp
never could: twelve minutes of process activity attributed to one authenticated session from one
source address.

**The session ended with 4647, not 4634.** The transient logon got a 4634 ("session was
terminated"); the interactive one got **4647 ("user initiated logoff")**. A hunt written for 4634
alone misses the deliberate sign-out.

**And the disconnect is invisible.** 479 events across the span, **not one 4778 or 4779**, and the
user was detached from 09:37:33 to 09:41:03. Reading only this log, the session is twelve
continuous minutes with one person at the desktop throughout.

### The controlled experiment: the disconnect events were switched off

**`auditpol /get /subcategory:"Other Logon/Logoff Events"` returned `No Auditing`** — a third
switch, distinct from the `Logon` and `Logoff` subcategories verified in Sitting 1. So the silence
was the instrument, not Windows. This is Module 06's rule applying exactly: *verify the instrument
before trusting a silence you predicted.*

One variable was then moved. `/success:enable`, **readback confirmed `Success`**, boundary marked
at **12:55:18 UTC**, and the identical activity repeated (connect, `whoami`, disconnect 12:59:04,
reconnect, sign out 13:01:38 UTC).

**Result: four events where there had been none.**

| UTC | ID | Owner |
|---|---|---|
| 12:58:30 | 4779 | — |
| 12:59:46 | 4779 | — |
| 13:01:01 | 4778 | — |
| 13:04:08 | 4778 | **`administrator`, Session Name `Console`** (read directly) |

**Nothing before 12:55:18**, so this morning's disconnect at 09:37:33 is permanently unrecoverable.
**Auditing is not retroactive** — the same lesson as Module 02's Step 3 lock-down.

**4778/4779 are not RDP events.** They track *any* session attaching to or detaching from a window
station, and `Session Name` separates them (`Console` vs `RDP-Tcp#N`). The extra pair is
Administrator's console session being **displaced** when `asmith` connected — confirmed
independently by the LocalSessionManager rows below, and by the user's own observation that WS01's
console prompted them to log off so `asmith` could log in. **"A console session was displaced" is
exactly what an RDP logon onto an occupied machine looks like, and the event names both sides.**

### Step 6 — the Remote Desktop half

**6.1 — RemoteConnectionManager.** The 1149 names **`asmith@corp.local`** and **source network
address `10.0.0.10`**. Six hours of that channel held **5 × 1149**, 30 × 263, 10 × 261, 4 × 20524,
4 × 20523, 4 × 1136, 4 × 258. **Five 1149s for two sessions** — credentials are accepted more than
once per session. The meanings of 258/261/263/1136/20523/20524 were **not resolved on the box** and
are not stated here.

**The wrong-channel trap, and it nearly produced a false finding.** `Id=24,25` run against
**RemoteConnectionManager** returns `NoMatchingEventsFound` — identical to a genuine absence, no
error. It briefly looked like this build does not record RDP disconnects at all. The two channels
divide the work: **RemoteConnectionManager is the connection** (1149 — credentials accepted, from
this address); **LocalSessionManager is the session** (21/22/23/24/25). This lab already had the
wrong-*machine* version of this trap written down; this is the wrong-*channel* version.

**6.2/6.3 — LocalSessionManager, with attribution.** `EventData.Data` returns **nothing** — the
prediction held. The fields live at **`.Event.UserData.EventXML`**, as named elements (`User`,
`SessionID`, `Address`), a **third** shape distinct from both forms met so far. If `EventData.Data`
is empty, check `UserData` before concluding anything.

| UTC | ID | User | Session | Address |
|---|---|---|---|---|
| 09:30:27 | 21 logon | `CORP\asmith` | **3** | `10.0.0.10` |
| 09:37:33 | **24 disconnected** | `CORP\asmith` | 3 | `10.0.0.10` |
| 09:41:03 | **25 reconnected** | `CORP\asmith` | 3 | `10.0.0.10` |
| 09:42:21 | 23 logoff | `CORP\asmith` | 3 | *(empty)* |
| 12:58:31 | 24 | `CORP\Administrator` | 1 | **`LOCAL`** |
| 12:58:34 | 21 | `CORP\asmith` | **2** | `10.0.0.10` |
| 12:59:49 | **24** | `CORP\asmith` | 2 | `10.0.0.10` |
| 13:01:01 | **25** | `CORP\asmith` | 2 | `10.0.0.10` |
| 13:02:13 | 23 | `CORP\asmith` | 2 | *(empty)* |
| 13:04:08 | 25 | `CORP\Administrator` | 1 | `LOCAL` |

**Four results from this table.**

1. **`Address` separates remote from local in one field** — `LOCAL` for console sessions,
   `10.0.0.10` for RDP. The Security log needs Logon Type 10 *plus* a source address to say as much.
2. **This channel logs local logons too**, not only RDP (Administrator's console sessions at
   09:50:21, 11:30:33, 13:40:17). A hunt built on ID 21 alone is not an RDP hunt.
3. **Session IDs are reused and not ordered.** Morning was session **3**, afternoon session **2** —
   same user, same machine, same day, later session with the *lower* number. A session ID
   identifies a session **only within a time window**, and cannot say which of two came first.
4. **The 23 carries no `Address`**, so a hunt reading only session endings loses the source IP.

**6.5 — Sysmon saw the inbound half, and this closes Module 06's open question.** Total Event 3 =
**11** against a baseline of **1**; the ten new ones sit on the RDP activity (~5 TCP connections
per session). One read in full:

| Field | Value |
|---|---|
| `Initiated` | **`false`** — the receiving end (Module 06's outbound read `true`) |
| `Image` | `C:\Windows\System32\svchost.exe` — the victim's own service |
| `User` | **`NT AUTHORITY\NETWORK SERVICE`** — **`asmith` appears nowhere** |
| `SourceIp` / `SourceHostname` | `10.0.0.10` / **`DC01`** |
| `DestinationPort` | `3389` / `ms-wbt-server` |
| `UtcTime` | `2026-09-28 13:00:45.015` — **printed as UTC explicitly** |

So **Event 3 fires on both ends of a completed connection**, and on the receiving end it attributes
to a *machine*, not a person. Sysmon is also the only instrument here that prints UTC rather than
making the analyst convert.

**6.6 — exported** on WS01: `C:\evidence\07-security.evtx` and `C:\evidence\07-lsm.evtx`.

### The join — what actually ties the four logs together

**No single field spans all four, and one identity has four spellings.**

| Log | Identity as printed | Join field it offers |
|---|---|---|
| Security 4624/4647 | `asmith` + `CORP` (separate fields) | **Logon ID** `0x4F246D` |
| RemoteConnectionManager 1149 | **`asmith@corp.local`** | — (address + time only) |
| LocalSessionManager 21/24/25/23 | **`CORP\asmith`** | **SessionID** `3` |
| Sysmon Event 3 | **`NT AUTHORITY\NETWORK SERVICE`** | `ProcessGuid` (of svchost) |

**No two of those identity strings match**, so one hunt string cannot search all four — the same
shape as Module 03's `\REGISTRY\MACHINE\` vs `HKLM\` and Module 06's rule-name case differences.

**The join is made in hops, not on one key.** Logon ID ties the Security log to itself (479
events). SessionID ties the session log to itself. **Nothing carries both**, so Security ↔
LocalSessionManager is bridged by **user + source address + a ~1 s timestamp coincidence**
(4624 09:30:26 / 21 at 09:30:27; 4647 09:42:20 / 23 at 09:42:21). **Two sessions from the same user
within a minute would not be separable by this evidence except by timestamp** — stated plainly
because it is a real limit.

**Each log answers exactly one question**: Sysmon *where from* (machine), 1149 *who*,
LocalSessionManager *what happened to the session*, Security *what the session did*.

### Unexplained, recorded as observations

1. **The 4-hour 4624 queries returned nothing** although the events sat well inside the window.
   Rotation, message rendering and window boundary were each tested and excluded. The likeliest
   candidate is that the `-MaxEvents 50` variant was the one that actually ran (it is visible in
   the screenshot and explains the exact count of 50), but **no cause is established**.
2. **Noted times and logged times disagree by up to a minute, in both directions.** Morning
   disconnect: log 09:37:33, noted 09:38:35 (note 62 s late). Afternoon: log 12:59:49, noted
   12:59:04 (note 45 s *early*). The note can only lag the event, never precede it, so something
   further is in play — possibly clock skew between DC01 and WS01. **Not established.** Sign-out is
   the same shape: noted 13:01:38, 23 at 13:02:13; morning 4647 09:42:20 vs noted 09:41:46.
3. **Five 1149s for two sessions**, and the meanings of RemoteConnectionManager 258/261/263/1136/
   20523/20524 were never resolved on the box.
4. **WS01's Windows 11 evaluation licence has expired** — desktop watermark, seen 2026-09-28. This
   is the wall CLAUDE.md predicted after DC01 hit it on 2026-09-04. Not acted on.

### Lab state changed this sitting

- **`auditpol` `Other Logon/Logoff Events` = Success on WS01**, set 2026-09-28, readback confirmed.
  **Leave it on** (Module 06 precedent) — it is the only instrument that recorded the console
  displacement, and Step 10's cleanup should say so rather than revert it.
- Two `.evtx` exports on WS01 under `C:\evidence\`. Not in the repo; `.gitignore` excludes them.
- Two RDP sessions and one extra sign-out of Administrator's console session.

### Step 7 — the access story (completed 2026-09-28)

**All times UTC.** Sources named per line. This is the deliverable: the reconstruction a colleague
could act on without re-running any of the work.

```
RDP session — WS01 (10.0.0.20) — 2026-09-28 — CORP\asmith from DC01 (10.0.0.10)

  09:22:39  4624  Security            asmith — Logon Type NOT READ (connection attempts)
  09:23:55  4624  Security            asmith — Logon Type NOT READ
  09:30:20  4624  Security            asmith, Type 3   — NLA credential check
  09:30:24  4624  Security            asmith, Type 3
  09:30:25  3     Sysmon              inbound tcp/3389 from DC01, svchost.exe, Initiated=false
  09:30:26  4624  Security            asmith, Type 10, Logon ID 0x4F246D, src 10.0.0.10
  09:30:27  21    LocalSessionManager session 3 logon, CORP\asmith, Address 10.0.0.10
  09:30:28  22    LocalSessionManager shell start
   (across the session: 154 x 4688 process creation, all carrying Logon ID 0x4F246D)
  09:37:33  24    LocalSessionManager session 3 DISCONNECTED   <-- session left running
  09:41:03  25    LocalSessionManager session 3 RECONNECTED
  09:42:20  4647  Security            user-initiated logoff, Logon ID 0x4F246D
  09:42:21  23    LocalSessionManager session 3 logoff

  1149  RemoteConnectionManager  asmith@corp.local authenticated from 10.0.0.10
        (5 x 1149 across the day's two sessions; per-event times not recorded)
```

**Second session, same host, same account, same source, later the same day:** session **2**, logon
12:58:34, disconnected 12:59:49, reconnected 13:01:01, logoff 13:02:13 — and, because the
`Other Logon/Logoff Events` subcategory had been enabled at 12:55:18, the Security log recorded
its own view of the detach and reattach as **4779** and **4778** for the first time.

**In prose.** `CORP\asmith` authenticated to WS01 over Remote Desktop from **DC01, 10.0.0.10**, at
**09:30:26 UTC**, holding session 3 for just under twelve minutes. The session was **disconnected
at 09:37:33 and left running** with nobody attached, **reattached at 09:41:03**, and deliberately
ended by the user at **09:42:21**. A second session from the same account and the same source
followed at 12:58:34 and ended at 13:02:13. Both connections were preceded by NLA credential
checks appearing as Type 3 logons.

**Only the afternoon session displaced anyone.** `CORP\Administrator` held WS01's console
(session 1, `Address: LOCAL`) and was detached at **12:58:31**, three seconds before `asmith`
logged on, reattaching at **13:04:08** after the sign-out. In the morning no displacement occurred:
Administrator had already logged off at **09:17:36**, thirteen minutes before `asmith` connected.
The two sessions therefore differ in a way that matters — one took a machine someone was sitting
at, the other took an idle one — and **only the occupied case leaves the console-displacement
trail**.

**What this evidence cannot support**, stated explicitly:

- **The Logon Type of the 09:22:39 and 09:23:55 events.** They were returned by the account
  filter but their fields were never read, so what kind of logon they were is **unknown**. The
  09:30 group's pattern makes Type 3 likely; likely is not read.
- **What was done inside the session.** 154 process-creation events carry the Logon ID, but Module
  06 established that cmdlet activity inside an already-open shell writes **no 4688 at all**. The
  visible processes are a floor, never a ceiling.
- **Who was at the keyboard.** The logs prove the credential was used from DC01. They cannot
  establish that `asmith` used it.
- **What happened during the 3m30s gap.** The session existed with nobody attached. Nothing in any
  of the four logs records whether anything ran in it.
- **That two sessions from this account could be separated if they overlapped.** SessionID is
  reused and unordered (morning = 3, afternoon = 2), and nothing carries both a SessionID and a
  Logon ID. Two sessions from the same user within a minute would be separable **only by
  timestamp**.
- **That this gap would be visible at all on a default host.** The Security log's own record of the
  disconnect required a subcategory that ships **off**, and the morning disconnect is recorded only
  because the LocalSessionManager channel happens to be enabled by default on this build.

**MITRE.** T1021.001 (Remote Services: Remote Desktop Protocol) for the access itself; T1078
(Valid Accounts) for the use of a legitimate credential, which is what makes this traffic
indistinguishable from administration without the surrounding context.

### Where the sitting stopped

Steps 4, 5, 6 and 7 are **complete**, including an unplanned controlled experiment that produced the
sitting's strongest finding. **Resume at Step 8** — the failed logon. Steps 8–11 are the last sitting that
touches the VMs; the Findings section after it is desk work.

**Screenshots to move into `assets/`** (they exist on the Windows machine, not in the repo):
`07-1149-auth.png`, `07-session-lifecycle.png`, **`07-session-attribution.png`** (the
User/SessionID/Address table — the cleanest single image this module has produced), and the Step 5
`Group-Object` breakdown of the 479 events. Still outstanding from Sitting 1:
`07-sysmon-config.png`, `07-4947-rules-modified.png`, and Module 06's `06-5152-ws01-empty.png`.

---

# Run log — Sitting 3 (2026-09-28 → 2026-09-29, Steps 8–9 complete)

**Every value here was pasted back from the machine.** Anything not listed was not read, and is
**unknown** rather than done. All times UTC; the VMs display UTC+1, so local output read one hour
ahead and **crossed midnight mid-sitting** — Step 8's events print as 9/28, Step 9's as 9/29.

## Step 8 — a logon that fails, with NLA on (WS01)

Boundary read on **DC01**: **21:25:42**. One deliberate wrong-password attempt via `mstsc.exe` to
`10.0.0.20` as `asmith@corp.local`, refused once.

**One refusal wrote exactly one 4625**, at **21:26:35** — against **three 4624s** for one
successful attachment in sitting 2. Successes and failures are not symmetric, so a count of one is
not a count of the other.

| Field | Value |
|---|---|
| Subject | `S-1-0-0`, Account Name `-`, Domain `-`, **Logon ID `0x0`** |
| **Logon Type** | **3** |
| Account For Which Logon Failed | SID **`S-1-0-0`**, Account Name **`asmith@corp.local`**, Domain `-` |
| Failure Reason | Unknown user name or bad password |
| Status / Sub Status | **`0xC000006D`** / **`0xC000006A`** |
| Process Information | Caller PID `0x0`, Caller Process Name `-` |
| Network Information | Workstation Name **`DC01`**, Source Network Address **`10.0.0.10`**, Source Port **`0`** |
| Detailed Authentication | Logon Process **`NtLmSsp`**, Package **`NTLM`**, Key Length `0` |

**The sheet's prediction survived: Logon Type 3, not 10.** A rule that hunts RDP by watching
**Type 10** catches every successful RDP logon on this host and **misses every failed one**.
Successes and failures do not share a logon type, so they do not share a hunt.

**Neither SID resolved.** Subject *and* target both came back `S-1-0-0`. A refused logon yields
**the string that was typed, never a resolved identity** — Windows does not look up a SID for a
logon it rejects.

**A fifth spelling of the same person.** This event says `asmith@corp.local` with Domain `-`; the
successful 4624 said `asmith` + `CORP`. **The same log spells the same user two different ways
depending on whether they got in**, so a hunt joining 4624 to 4625 on Account Name silently returns
nothing. Same shape as Module 03's `\REGISTRY\MACHINE\` vs `HKLM\`, now *inside a single channel*.

**`0xC000006A` is recall, not established.** High confidence it means *account exists, password
wrong* (against `0xC0000064`, no such user), and the `Failure Reason` string deliberately conflates
the two so the person at the keyboard cannot tell which they got. **Not verified on the box.** The
discriminating test costs nothing against the lockout budget: fail as a username that does not
exist and compare the Sub Status. The distinction is the whole difference between **password
guessing against a known account** and **username enumeration**.

**NTLM, not Kerberos** — `NtLmSsp` / `NTLM`. **Hypothesis, not established:** connecting by **IP**
forces NTLM because Kerberos needs an SPN and that requires a *name*. Two cheap tests, neither run:
connect to `ws01.corp.local` and see whether the package changes; or check **DC01** for a `4771`
near 21:26:35 — Kerberos pre-auth failures land at the DC, NTLM ones do not, so an absent 4771 is
consistent with NTLM.

### The session log stayed silent, and the control was in the same output

`LocalSessionManager` held nothing after the boundary. Newest events were **21:23:02–21:23:03**:
three × **59**, then **21**, then **22** — Administrator's console logon after boot.

**That is a positive control 2m40s before the attempt, in the same five rows as the silence.** No
need to reach back to Step 6's session to prove the channel alive. This is Module 06's *verify the
instrument before trusting a silence you predicted* applied correctly rather than reproduced as a
mistake.

**Id 59 resolved on the box** — one of sitting 2's six unresolved IDs:
`RpcGetCurrentSessionCapabilities from C:\WINDOWS\system32\svchost.exe -k netsvcs -s CertPropSvc`
(×3) and `from "LogonUI.exe" /flags:0x2 …` (×2). So this channel carries **two different kinds of
thing**: the session-lifecycle family (21/22/23/24/25) that told sitting 2's whole story, and
**internal RPC chatter** like 59 that only proves the channel is awake. A hunt must not mistake a
pile of 59s for activity.

### The connection channel did record it — 26 seconds earlier

`RemoteConnectionManager` returned **261 at 21:26:09**, twenty-six seconds **before** the 4625. No
new **1149**.

**261 resolved on the box = "Listener RDP-Tcp received a connection"** — a second of sitting 2's
unresolved IDs closed. Its `UserData.EventXML` carries **only the listener name `RDP-Tcp`**: no
user, no source address, no port. (`Event_NS` in that output is the XML namespace wrapper, not a
field.) Checked rather than inferred from the one-line message, because fields can exist without
being rendered into message text.

**The absence of 1149 is a complete answer, not a truncated one.** `-MaxEvents 10` came back
*full*, so older events exist — but the ten returned reach back to **21:22:31**, before the
boundary. The window is fully covered. Contrast the 4625 query, where `-MaxEvents 5` returned
**3**: a cap that comes back **under** the cap is the one case where a small number is a genuine
population count and not the filter-first trap.

### What a refused RDP logon leaves behind

| Channel | Got | Says |
|---|---|---|
| RemoteConnectionManager | **261** @ 21:26:09 | a connection reached the RDP listener |
| Security | **4625** Type 3 @ 21:26:35 | *who* was tried, from where, why it failed |
| LocalSessionManager | **nothing** | no session was ever built |
| 1149 | **absent** | credentials were never accepted |

**The sharp edge, and it is better than the sheet predicted.** Nothing in the 4625 says *RDP* —
Type 3, `NtLmSsp`/`NTLM`, Source Port `0`, from `10.0.0.10` is indistinguishable from a failed SMB
or WinRM logon. The thing that identifies it as RDP is the **261 in a different channel 26 seconds
earlier**. **The identity-bearing event cannot name the protocol, and the protocol-bearing event
cannot name the identity.** The hop-based join from sitting 2 is now needed *just to classify the
event*, not merely to enrich it.

**Candidate finding, observed twice (Steps 8 and 9): `261` present with no matching `1149` is the
signature of a refused RDP connection.** 1149 is the credentials-accepted marker; a connection that
arrives and never earns one is what a refusal looks like in that channel.

## Interruption — WS01's expired licence shut the VM down

**WS01's Windows 11 evaluation licence is expired and shuts the machine down roughly hourly.** It
shut down **after Step 8, before Step 9** — the wall CLAUDE.md predicted after DC01 hit it on
2026-09-04. This is now an active constraint on sittings, not a future one.

Recovered from the logs rather than from memory: RDP service startup chatter at **00:29:00**
(`20524`, `263`, `263` — same family as the 21:22:31 boot cluster), then **00:29:49–00:29:50**,
three × `59`, `21`, `22`. Fields read: **`CORP\Administrator`, SessionID `1`, Address `LOCAL`** —
a console logon, not RDP.

**Reading the `Address` field is what settled it.** The cluster sat three seconds after an
unexplained 4625 and had the identical shape to a session being built, which is exactly what a
refused-logon-builds-a-session result would have looked like. Shape was not enough; the field was.

**An unidentified 4625 at 00:29:46 is carried as unknown.** Its fields were **not read**. The
user's account of the evening makes a console mistype three seconds before getting in plausible,
but that is **a guess, not established** — and if it were instead a third RDP attempt, the lockout
count would be higher than recorded.

## Step 9 — the controlled experiment: NLA off (WS01)

`SystemPropertiesRemote.exe`, NLA unticked, **readback `UserAuthentication = 0`** ✅. Companion
value read from the same key: **`SecurityLayer = 2`**.

`SecurityLayer`'s meaning is **recall, moderate confidence** (`2` = TLS required, `0` = native RDP
encryption, `1` = negotiate) and **unlike the event IDs there is no `.Message` to resolve it
against on this box**. It does not act as a second gate: transport encryption and NLA are different
things, and `SecurityLayer=2` with `UserAuthentication=0` is a coherent combination.

Boundary on **DC01**: **00:36:34** (2026-09-29). Identical failure, same account, same wrong
password, once.

### The sheet's own prediction about the experience failed

The run sheet said the far machine would build a desktop and show a Windows login screen *inside*
the Remote Desktop window. **It did not.** Credentials were collected in DC01's own dialog and
refused there — `Your credentials did not work` — **visually identical to NLA on**.

### And the logs did not move either

| NLA | 4625? | Logon Type | Auth package | Session log (21/22/24) | 1149 | 261 |
|---|---|---|---|---|---|---|
| **On** (Step 8) | 1 @ 21:26:35 | **3** | NtLmSsp / NTLM | **untouched** | none | **261** @ 21:26:09 (−26 s) |
| **Off** (Step 9) | 1 @ 00:37:58 | **3** | NtLmSsp / NTLM | **untouched** | none | **261** @ 00:37:26 (−32 s) |

The 00:37:58 event was **field for field identical** to Step 8's, including Sub Status
`0xC000006A` — which also confirms `asmith` was **not locked** at that moment, since a locked
account carries a different code. The experiment was not contaminated.

**The module's designed lesson did not reproduce on this host.** The sheet expected the bottom row
to show session events the top row lacked, and it does not. Written up as a negative result, with
its limit stated: **identical rows are equally consistent with "NLA does not affect failure
logging" and with "NLA never actually disengaged."**

### The leading explanation, and why it is not established

Three hypotheses were live. **H2** (the server disengaged and the prediction was only wrong about
the *client*) is weakened by the unchanged client experience. **H1** (a companion value holds NLA
in force) found no support — `SecurityLayer` is not that gate.

**H3 — the listener needs a reload before a changed `UserAuthentication` applies — is the leading
candidate.** The sequence, established from the user's account of the evening: **the licence
shutdown and reboot came *before* the NLA change, not after.** WS01 came up at ~00:29 with NLA
**on**, the value changed underneath a running listener at ~00:33, and no reload followed. An
in-session hope that the reboot had served as a free control for H3 was **wrong and retracted** —
it fell on the wrong side of the change.

**No cause established.** **The discriminating test, not run:** set `UserAuthentication = 0`, let
the machine restart — the hourly licence shutdown supplies a free reboot — then retry the identical
failure. Behaviour changes after a reload → H3 confirmed. Behaviour unchanged → NLA genuinely does
not affect this, and *that* is the finding. Deferred deliberately rather than chased at 02:00, on
the grounds that it costs a third failed logon and leaving NLA off overnight to chase it is the
exact shape of Module 06's Finding 5.

### Cleanup, readback-verified

- **9.5 — `UserAuthentication` back to `1`** ✅ read back on **WS01**.
- **9.6 — `asmith` is not locked out** ✅ read on **DC01**. Two deliberate failures on record
  (21:26:35 on 9/28, 00:37:58 on 9/29); no `Unlock-ADAccount` was needed, so **no 4767 of the
  analyst's own making exists** to be mistaken for lab noise later.

## Traps this sitting added

- **`-Name` on `Get-ItemProperty` restricts what comes back.** `Get-ItemProperty -Path … -Name
  UserAuthentication | Select-Object UserAuthentication, SecurityLayer` printed a **blank
  `SecurityLayer` column** — not an error, not an empty value. **A property that was never
  retrieved looks exactly like a property that is empty.** Dropping `-Name` returned both. Same
  family as the other silent-empty traps: shortest useful form *first*, filter second.
- **A misspelled channel *name* errors loudly; a real channel with no matches is silent.**
  `'…RemoteConectionManager…'` returned *"There is not an event log on the localhost computer that
  matches…"*. Compare sitting 2's wrong-channel trap, which returned `NoMatchingEventsFound` with
  no error. **Refines the existing trap: only a channel that exists can fool you.**
- **A cap returning fewer rows than the cap is a complete population.** `-MaxEvents 5` → 3 events
  means three exist. The mirror of the filter-first trap, and the one case where a small number is
  an answer.
- **A full cap can still give a complete answer** if its oldest row predates your boundary. Check
  what the window *covers*, not just whether it filled.
- **Shape is not a field.** A `59,59,59 → 21 → 22` cluster three seconds after a 4625 looked
  exactly like a session being built for a failed logon. `Address: LOCAL` killed it in one read.

## Where the sitting stopped

**Steps 8 and 9 are complete.** Remaining: **Step 10** (lab-state readbacks), **Step 11**
(screenshots) and the **Findings** section — all of Step 10 needs the VMs, Findings does not.

**Open, carried forward:**

1. **H3's discriminating test** — NLA off, reboot, retry. Five minutes at the start of a sitting.
2. **The 4625 at 00:29:46 UTC on 2026-09-29** — fields never read.
3. **`0xC000006A` vs `0xC0000064`** — fail as a nonexistent user and compare. No lockout cost.
4. **NTLM-because-IP** — connect to `ws01.corp.local`, or look for a 4771 on DC01.
5. **WS01's expired licence** now costs a reboot roughly hourly, mid-sitting.

---

# Step 0 — Pre-flight (both VMs)

### 0.0 Close out Module 06 first — and mind the order

**Aim: finish the previous module while its lab state still exists, because this one changes it.**

Module 06 has two clerical items left — the six `Get-NetFirewallProfile` readbacks were taken on
2026-09-25 and its Step 8 table is now fully populated. One of the two **stops being possible**
once you edit Sysmon's config in Step 3:

1. `06-5152-ws01-empty.png`
2. `06-sysmon3-zero.png` — **do this one before touching Sysmon.** Fire three knocks at the
   now-closed port 9999 from WS01 and capture the Event 3 count staying at **1**. The original
   zero state no longer exists, so this is a re-derivation, not a recreation, and the honest
   capture is the count *not moving*.

### 0.1 Boot DC01 first and prove the domain is up

**Aim: prove the domain works before you touch anything, so anything odd later is something
you did.**

**Start DC01 before WS01** and give it a minute or two after the login screen.

On **WS01**, in **PowerShell (Admin)**:

```powershell
Test-ComputerSecureChannel
```

You want **`True`**.

> **A successful login is not proof the domain is up.** Windows signs you in from **cached
> credentials** with no network at all. On 2026-09-13 this cost most of a sitting.

### 0.2 Check the account you are going to use still exists

**Aim: don't discover in Step 4 that your test account was cleaned up two modules ago.**

Module 01 created a domain user `asmith` and did **not** delete it (only `svc_backup` was
removed). Confirm rather than assume. On **DC01**:

```powershell
Get-ADUser asmith
```

If it is missing, recreate it — same command Module 01 used:

```powershell
$pw = ConvertTo-SecureString "Lab-Passw0rd!" -AsPlainText -Force
New-ADUser -Name "asmith" -SamAccountName "asmith" -UserPrincipalName "asmith@corp.local" -Path "CN=Users,DC=corp,DC=local" -AccountPassword $pw -Enabled $true
```

### 0.3 Read the lockout policy — this one will bite you

**Aim: know how many wrong passwords you can afford before the account locks and changes the
evidence underneath you.**

Module 01 set a **real lockout policy** on this domain, and `asmith` is the account it locked
out. On **DC01**:

```powershell
Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow
```

**Expected from Module 01: threshold 5, duration 10 minutes, observation window 10 minutes** —
verify, don't trust this sentence.

This matters because Steps 8 and 9 each fail a logon on purpose. Two deliberate failures is
comfortably under five — but a mistyped password during the *successful* step counts too, and a
locked account fails for a completely different reason, producing different events. **If you
end up retrying, count your attempts**, and wait out the observation window rather than pushing
through.

> **Prediction to check in Step 8:** a locked-out account and a wrong password both produce a
> **4625**, distinguished by the failure-reason / status field inside the event, not by the
> event ID. Read the field; do not infer from the ID.

### 0.4 Snapshot both VMs

**Aim: make Step 9's NLA experiment repeatable, and give the lab the clean baseline Module 03
still lacks.**

Shut both VMs down cleanly and take a snapshot on each named **`mod07-start`**.

> Module 03's anomaly is still parked and still untestable, purely because `mod03-start` was
> never taken. This step is thirty seconds. Do not skip it.

---

# Step 1 — Look at the four logbooks before you change anything (WS01)

**Aim: prove every instrument is switched on and recording *before* you generate anything —
so that a later empty result means "it didn't happen", not "I wasn't listening".**

This is Module 02's four-gate lesson in its fourth outfit, and Module 06's Finding 5 in
advance: *an expectation that cannot fail is not evidence*. Module 06 wrote a step that
predicted silence from an instrument that was switched off, and the meaningless empty result
briefly looked like a result.

### 1.1 The two Security-log switches

On **WS01**:

```powershell
auditpol /get /subcategory:"Logon"
```

Then:

```powershell
auditpol /get /subcategory:"Logoff"
```

You want **Success and Failure** on `Logon`, and at minimum **Success** on `Logoff`. **Module 01
Step 0.3 set both of these on WS01 specifically** (not only on DC01), so they are **expected to
already be on** — confirm rather than assume, and switch them on if not:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

> **No space after the colon.** `auditpol /get /subcategory: "Logon"` fails with
> `Error 0x00000057 ... The parameter is incorrect` and dumps usage text that reads like a
> broken tool rather than a typo. Cost time on 2026-09-13.

### 1.2 The two Remote Desktop logbooks — are they even enabled?

**Aim: find out whether these channels record by default on this build, because a disabled
channel returns an empty result with no error to explain why.**

These two logs are not part of the Security log. They are separate channels, the same way
Sysmon's log was in Module 03 — and a `LogName='Security'` query will never see them.

On **WS01**, start with the shortest useful form:

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
```

Then ask it the questions that matter:

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' | Format-List LogName, IsEnabled, RecordCount, FileSize, MaximumSizeInBytes
```

Now the other one:

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' | Format-List LogName, IsEnabled, RecordCount, FileSize, MaximumSizeInBytes
```

**What to record, for each of the two:**

| Question | Why it matters |
|---|---|
| `IsEnabled` — True or False? | False means it records nothing and says nothing about it |
| `RecordCount` | Your "before" number. Step 6 compares against it |
| `FileSize` vs `MaximumSizeInBytes` | If it has never filled, its oldest event is this machine's true beginning — not a rotation boundary (Module 04) |

> **I do not know whether these two channels are enabled by default on this Windows 11 build.**
> That is precisely why this step exists. If `IsEnabled` is `False`, enable the channel in
> **Event Viewer** — navigate to *Applications and Services Logs → Microsoft → Windows →
> TerminalServices-LocalSessionManager*, right-click **Operational → Enable Log** — and then
> re-run the command above to confirm it took.

### 1.3 Write down the four "before" numbers

**Aim: make the Step 6 comparison a measurement rather than an impression.**

On **WS01**, one line per log. Security first:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} | Measure-Object
```

> **Count before you conclude.** Module 03 lost a sitting to reading a small `-MaxEvents`
> result as "that is all there is", which was fiction — the real count was 1311.

Record all four numbers in a note. You will want them again in Step 6 and in the write-up.

---

# Step 2 — Turn on Remote Desktop (WS01)

**Aim: make WS01 reachable by Remote Desktop — the build half of the module — and confirm each
change actually committed rather than merely being commanded.**

### 2.1 Switch it on in the GUI

On **WS01**, the quickest reliable route to the right dialog:

```powershell
SystemPropertiesRemote.exe
```

That opens the **Remote** tab of System Properties directly. Select **Allow remote connections
to this computer**. Accept the warning it offers about sleep settings.

Leave **"Allow connections only from computers running Remote Desktop with Network Level
Authentication"** **ticked** — NLA stays **on** for now. Step 9 is where it comes off, deliberately
and temporarily.

> Settings → System → Remote Desktop reaches the same switches on Windows 11, and the exact
> wording of the NLA checkbox varies between builds. Use whichever you find; the readback below
> is the authority, not the wording on the screen.

### 2.2 Read it back from the registry

**Aim: confirm from a second, independent place that the toggle committed — the habit Module 06's
Finding 5 exists to enforce.**

```powershell
Get-ItemProperty -Path 'HKLM:/SYSTEM/CurrentControlSet/Control/Terminal Server' -Name fDenyTSConnections | Select-Object fDenyTSConnections
```

**`fDenyTSConnections` = `0` means Remote Desktop is ENABLED.** The name is a double negative —
"deny terminal server connections" — so zero is on. Misreading this field as if 1 meant enabled
is an easy and expensive mistake.

Now read the NLA setting, which lives in a different key:

```powershell
Get-ItemProperty -Path 'HKLM:/SYSTEM/CurrentControlSet/Control/Terminal Server/WinStations/RDP-Tcp' -Name UserAuthentication | Select-Object UserAuthentication
```

**`UserAuthentication` = `1` means NLA is required.** Write down what it says now — Step 9
changes it and Step 9.5 has to put it back.

> Forward slashes are deliberate and verified on WS01 (2026-09-10): the PowerShell registry
> provider normalises `/` to `\`. This is the standing workaround for the backslash-keyboard
> problem. It does **not** extend to `reg.exe`.

### 2.3 Check the firewall actually allows it — on the right profile

**Aim: avoid the specific failure where RDP is "on" but the rule is enabled for a profile this
machine is not using.**

Turning Remote Desktop on normally enables its firewall rules too. Do not take that on trust:

```powershell
Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Select-Object DisplayName, Enabled, Direction, Profile
```

**WS01 was on the `Domain` profile and DC01 on `Public`** as of 2026-09-16 — unexplained and
still true after a reboot. So confirm WS01's active profile for yourself rather than inheriting
that sentence:

```powershell
Get-NetConnectionProfile | Select-Object Name, NetworkCategory
```

> **Corrected 2026-09-25.** This step originally called `Get-NetFirewallProfile | Select Name,
> Enabled`, which is the wrong instrument: it lists **all three** profiles and will show
> `Enabled: True` for every one of them. That tells you a profile exists and is switched on — not
> which one this machine's connection is using. `Get-NetConnectionProfile` answers the question
> actually being asked. On the run, WS01 returned `NetworkCategory: DomainAuthenticated` — the
> firewall's **Domain** profile.

The inbound Remote Desktop rule must be **enabled on whichever profile WS01 is actually using**.
If it is not:

```powershell
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
```

Then **re-run the `Get-` above**. A `Enable-` that ran is not a rule that is enabled — the block
rule reported deleted on 2026-09-15 was found still present and enabled the next sitting.

> **Watch for rule-change events here.** Module 06 left `MPSSVC Rule-Level Policy Change` auditing
> **on**, so this should write events on WS01 — free corroboration that those switches are still
> live. Cast the net across **4946, 4947 and 4948** rather than one ID:
>
> ```powershell
> Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4946,4947,4948; StartTime=(Get-Date).AddMinutes(-30)} | Select-Object TimeCreated, Id
> ```
>
> **This sheet originally predicted a 4946 and was wrong.** The run produced **seven 4947s in a
> two-second burst and no 4946 at all** — because the Remote Desktop rules already existed,
> shipped disabled, so enabling RDP **modified** them rather than adding anything. **4946 means
> specifically "a rule that was not there before now is."** See the sitting-1 run log.

---

# Step 3 — Give one account permission, and arm Sysmon (WS01)

### 3.1 Add asmith to Remote Desktop Users

**Aim: make the session you are about to create belong to an ordinary user rather than an
administrator, so the logs show a realistic account.**

Members of the local **Administrators** group can already use Remote Desktop. An ordinary domain
user cannot until they are added to the local **Remote Desktop Users** group on the target
machine. That group is *local to WS01* — being in it grants nothing anywhere else.

Use the GUI, which avoids typing a backslash entirely. In the **System Properties → Remote**
dialog from Step 2.1, click **Select Users… → Add…**, type:

```
asmith@corp.local
```

and click **Check Names**. It should resolve. Click **OK** twice.

Read it back:

```powershell
Get-LocalGroupMember -Group 'Remote Desktop Users'
```

> **Fallback if the dialog will not take the UPN**, without needing a backslash:
> ```powershell
> $sid = (New-Object System.Security.Principal.NTAccount("asmith@corp.local")).Translate([System.Security.Principal.SecurityIdentifier])
> ```
> ```powershell
> Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $sid.Value
> ```
> Then re-run `Get-LocalGroupMember`.

> **Expect a 4732 on WS01.** "A member was added to a security-enabled **local** group" — the
> local-scope cousin of the 4728 from Module 01. Worth finding later as corroboration; the
> `Computer` field is what distinguishes a machine-local group from a domain one.

### 3.2 Extend Sysmon's network rule to RDP — before the break, not after

**Aim: arm the instrument in advance, so that whatever it records or fails to record is
evidence either way.**

Module 06 established that Sysmon **Event 3 records connections that complete, not attempts that
go unanswered**. An RDP session completes — so this is a genuine test of where that finding's
boundary lies.

There is a second open question in it, and it should be stated as a question rather than assumed:
Module 06 observed Event 3 on the **sending** host, for an **outbound** connection it initiated.
Here WS01 is the **receiving** end. **Whether Sysmon on the receiving host records an inbound
connection is not established by anything in this lab.** Arm it and find out.

WS01's Sysmon config is `C:\Tools\sysmon-registry.xml`. It already contains a `NetworkConnect`
group scoped to port 9999 from Module 06. **Add to that group — do not rebuild the file.** The
registry rules must survive; Modules 03 and 06 both depend on them.

Open it:

```powershell
notepad C:\Tools\sysmon-registry.xml
```

Add a second `DestinationPort` line inside the existing `NetworkConnect` include group, beside
the 9999 one:

```xml
<DestinationPort condition="is">3389</DestinationPort>
```

**3389 is Remote Desktop's port.** Scoping to one port is what stops this flooding the log —
Module 04 measured what volume does to evidence.

Apply it:

```powershell
cd C:\Tools
```

```powershell
.\Sysmon64.exe -c sysmon-registry.xml
```

Expect `Configuration updated`. Now read back the **live** config — not the file, which only
proves what you typed:

```powershell
.\Sysmon64.exe -c
```

`-c` **with** a filename applies; **without** one it prints what is actually loaded. Confirm you
can see both the registry rules and both destination ports.

📸 **Screenshot the live-config readback** → `assets/07-sysmon-config.png`. Put `hostname` at the
top of the capture.

---

# Step 4 — Break: one complete session (DC01 → WS01)

**Aim: generate the exact activity you are going to reconstruct — and write down the ground truth
as it happens, so you can check the logs against reality rather than against memory.**

**Direction matters.** DC01 is the client, WS01 is the host. So in WS01's logs, the connection's
source address should be **DC01's address, `10.0.0.10`**. If you find `10.0.0.20` in a source
field, you have the direction — or the machine — the wrong way round.

> **A practical note on the VM windows.** You are opening a remote desktop *inside* DC01's
> VirtualBox console window, so you will be looking at WS01's desktop inside DC01's desktop
> inside a window on your host PC. It works, but keep track of which desktop you are typing into.

### 4.1 Write down the time first

On **DC01**:

```powershell
(Get-Date).ToUniversalTime()
```

Note it. Findings are stated in **UTC** — that is what the event stores; Event Viewer only
converts for display.

### 4.2 Connect

On **DC01**:

```powershell
mstsc.exe
```

In **Computer**, type:

```
10.0.0.20
```

Click **Connect**. When prompted for credentials, use:

```
asmith@corp.local
```

with the password `Lab-Passw0rd!` (or whatever you set in Step 0.2).

**Type it carefully.** A mistyped password here is a wrong-password attempt against an account
with a five-attempt lockout threshold, and it will contaminate Step 8.

You should land on WS01's desktop as `asmith`.

### 4.3 Do something, so the session has content

Inside the RDP session, open PowerShell and run:

```powershell
whoami
```

Then:

```powershell
(Get-Date).ToUniversalTime()
```

Note both. `whoami` proves which account the session belongs to, from inside it.

### 4.4 Disconnect — do not log off

**Aim: create the distinction the module turns on.**

Click the **X** on the blue connection bar at the top of the RDP window, or just close the
window. Confirm if asked.

**Your session is still running on WS01.** Nothing was closed, nothing was saved, nothing ended.
Note the UTC time on DC01.

### 4.5 Reconnect

Run `mstsc.exe` again, same address, same credentials. You should come back to **the same
session** — if you left PowerShell open, it should still be there with your previous output
visible. That is the proof it never ended.

Note the time.

### 4.6 Now log off properly

Inside the session: **Start → the account icon → Sign out**.

This is the real ending. Note the time.

### 4.7 Write down your ground truth

**Aim: have a reality to check the logs against.**

Five timestamps, in UTC, in a note:

| # | What you did | UTC time |
|---|---|---|
| 1 | Connected and authenticated | |
| 2 | `whoami` inside the session | |
| 3 | Disconnected (closed the window) | |
| 4 | Reconnected | |
| 5 | Signed out | |

---

# Step 5 — Detect: the Security-log half (WS01)

**Aim: find the logon in the log you already know, and read the two fields that make it an RDP
logon rather than any other kind.**

Everything from here runs on **WS01**. The client machine records almost nothing — the same
asymmetry Module 06 found, where the receiving host held the evidence.

### 5.1 Find the logon

Shortest useful form first:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 5
```

That will be full of noise — every service start and local logon is a 4624. Narrow it by the
thing that makes yours different:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50 | Where-Object { $_.Message -like '*asmith*' } | Select-Object TimeCreated, Id
```

> **Filter first, limit second** is the rule, and `-FilterHashtable` cannot filter on account
> name — so this is the legitimate use of `Where-Object`: narrowing an already-correct result.
> But `-MaxEvents 50` here caps *before* the account filter, so if your logon is older than the
> newest 50 events it will not appear. If it comes back empty, raise the number — do not conclude
> it is missing.

### 5.2 Read the fields that matter

```powershell
$e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50 | Where-Object { $_.Message -like '*asmith*' } | Select-Object -First 1
```

```powershell
$e.Message
```

Find these four:

| Field | What you expect | Why it matters |
|---|---|---|
| **Logon Type** | **10** | This is what makes it RDP. 2 = at the keyboard, 3 = over the network, **10 = RemoteInteractive** |
| **Account Name** | `asmith` | Who |
| **Source Network Address** | `10.0.0.10` | Where from — DC01 |
| **Logon ID** | a hex value like `0x3E7A1` | **The candidate join key.** Write it down |

**The Logon ID is the thing to pay attention to.** It is Windows' internal handle for this one
logon session, and any other Security event belonging to the same session should carry the same
value. That makes it the strongest candidate for tying events together — much stronger than a
timestamp.

📸 **Screenshot this**, `hostname` at the top → `assets/07-4624-type10.png`.

### 5.3 Follow the Logon ID across the Security log

**Aim: test whether the join key works *within* one log, before asking it to work across four.**

Take the hex value from 5.2 and search on it:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-3)} | Where-Object { $_.Message -like '*0x3E7A1*' } | Select-Object TimeCreated, Id
```

*(substitute your own Logon ID)*

**Prediction to test:** you should see the logon and its logoff sharing that ID, and possibly
session reconnect/disconnect events too. Candidate IDs to look for, and to confirm rather than
assume:

| ID | Meaning |
|---|---|
| 4624 | The logon (Type 10) |
| 4634 / 4647 | Logoff |
| 4778 | A session was **reconnected** to a window station |
| 4779 | A session was **disconnected** from a window station |

> **Whether 4778/4779 appear here, and whether they carry your Logon ID, is not established.**
> Record what you actually find. If they are present but carry a *different* correlation field,
> that is more interesting than if they match — it means the join is not uniform even inside one
> log.

---

# Step 6 — Detect: the Remote Desktop half (WS01)

**Aim: find the same session in the two logs that exist specifically for Remote Desktop, and see
what they add that the Security log does not have.**

### 6.1 The authentication log

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149} -MaxEvents 5
```

**1149** means Remote Desktop Services accepted the user's credentials.

Read one:

```powershell
$r = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149} -MaxEvents 1
```

```powershell
$r.Message
```

**Prediction to test:** it carries the user, the domain and the source network address. Confirm
what it actually says.

### 6.2 The session log

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'} -MaxEvents 20 | Select-Object TimeCreated, Id
```

This is where the shape of your session should appear. Expected IDs, to be confirmed against
your own ground-truth times from 4.7:

| ID | Meaning | Should match ground truth # |
|---|---|---|
| 21 | Session logon succeeded | 1 |
| 22 | Shell (desktop) start notification | 1 |
| 24 | Session **disconnected** | 3 |
| 25 | Session **reconnected** | 4 |
| 23 | Session logoff succeeded | 5 |

**The 24 followed by 25 is the module's best single piece of evidence.** It is Windows recording,
in its own words, that a session was abandoned and then picked up again — and that between those
two entries the session existed with nobody attached to it.

📸 **Screenshot the sequence** → `assets/07-session-lifecycle.png`.

### 6.3 Pull the fields — and expect the extraction to be different here

**Aim: get at the field values, and meet the second place Windows hides them.**

Start with the pattern from Modules 01 and 04:

```powershell
$s = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21} -MaxEvents 1
```

```powershell
([xml]$s.ToXml()).Event.EventData.Data | Format-Table Name, '#text'
```

> **Prediction: this will return nothing.** Module 04 already found that not every event stores
> its fields under `EventData` — **1102** keeps its subject under `UserData` instead. These
> Remote Desktop events are expected to do the same. If the command above is empty, that is not a
> failure, it is the lesson:
>
> ```powershell
> ([xml]$s.ToXml()).Event.UserData
> ```
>
> Follow whatever structure that reveals. **Record which of the two it actually was** — this is a
> concrete, reusable fact about these channels and belongs in the findings either way.

Whichever it is, you are looking for the **Session ID** and the **user**.

### 6.4 The join

**Aim: answer the module's real question — what proves these four logs describe one session?**

Build the table. One row per event you found, across all four sources:

| Log | Event ID | UTC time | User | Session ID | Logon ID | Source address |
|---|---|---|---|---|---|---|
| Security | 4624 | | | | | |
| Security | 4634/4647 | | | | | |
| RemoteConnectionManager | 1149 | | | | | |
| LocalSessionManager | 21 | | | | | |
| LocalSessionManager | 24 | | | | | |
| LocalSessionManager | 25 | | | | | |
| LocalSessionManager | 23 | | | | | |
| Sysmon | 3 | | | | | |

Leave a cell **visibly empty** where the event does not carry that field. The empty cells are the
finding, not a gap in your work.

**Then answer, in writing:**

1. Is there a **single field** present in all four sources that ties them together? Or does the
   join have to be made in two hops — one field bridging the Security log to the session log, a
   different one bridging that to the connection log?
2. If you had **two** RDP sessions from the same user within a minute of each other, would your
   join still separate them? If the answer is "only by timestamp", say so plainly — that is a
   real limitation of this evidence and an honest finding.
3. Which log gives you the **source IP**, and which gives you the **session lifecycle**? No single
   one is expected to give both.

> **Do not decide the answer before running it.** This is the step where the temptation to write
> "the Logon ID ties it all together" before checking is strongest. Module 06's thesis was wrong
> and disproving it was the result.

### 6.5 Did Sysmon see an inbound connection?

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -MaxEvents 10 | Select-Object TimeCreated, Id
```

**Genuinely open.** Module 06 proved Event 3 fires for a *completed outbound* connection from the
sending host. Whether the *receiving* host logs the inbound half is not established here.

- **If events appear:** read `Initiated` (expected `false` for inbound), `Image`, `User`,
  `SourceHostname`. If it names a *local* process on WS01, note which — on the receiving side the
  process owning the socket is a Windows service, not the attacker's tool.
- **If nothing appears:** prove the channel is alive before calling it blind, exactly as Module 06
  did. `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} | Measure-Object`
  returning a healthy count is the control that excludes wrong-log, wrong-host and rotation.

### 6.6 Export the logs — recommended for this module

**Aim: keep the evidence that the write-up depends on.**

Module 06 deliberately took no `.evtx` export, on the reasonable grounds that a port knock is
regenerable on demand. **An RDP timeline is not cheap to regenerate**, and WS01's process-creation
rate measured ~308 and ~330 per twenty minutes on two separate days against Module 04's ~0.26
MB/day in August. That rate is **not established** — neither window was controlled for a reboot —
but if it is real, the 20 MB Security log fills in about a day and the timestamps your findings
cite will be gone.

On **WS01**:

```powershell
wevtutil epl Security C:\evidence\07-security.evtx
```

```powershell
wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational C:\evidence\07-lsm.evtx
```

An `.evtx` is a **frozen snapshot** taken at export time. That is exactly why it survives the log
rolling over. `.evtx` files are excluded by `.gitignore` — they stay on the VM, not in the repo.

---

# Step 7 — The access story (WS01)

**Aim: produce the deliverable — the thing you could hand a colleague.**

Write the timeline as a SOC analyst would in a ticket. One table, UTC, source named for every
line, and a short paragraph under it.

```
RDP session — WS01 — 2026-09-XX

  HH:MM:SS  1149  RemoteConnectionManager   asmith@corp.local authenticated from 10.0.0.10
  HH:MM:SS  4624  Security                  Logon Type 10, Logon ID 0x…, source 10.0.0.10
  HH:MM:SS  21    LocalSessionManager       Session N logon succeeded
  HH:MM:SS  24    LocalSessionManager       Session N disconnected  ← session left running
  HH:MM:SS  25    LocalSessionManager       Session N reconnected
  HH:MM:SS  23    LocalSessionManager       Session N logoff
  HH:MM:SS  4634  Security                  Logon ID 0x… ended
```

Then, in prose: who connected, from where, when, what the session did while it was disconnected
(**you cannot tell** — say so), and when it genuinely ended.

**State what the evidence cannot support.** The logs record that a session existed and when it
was attached to; they do not record what was done inside it. Process creation (4688) and Sysmon
Event 1 are where that would come from, and only if the actions started new processes — Module 06
established that **cmdlet activity inside an already-open shell writes no 4688 at all**.

---

# Step 8 — Break: a logon that fails (DC01 → WS01)

**Aim: find out how much Windows records about someone who tried and was refused — the question
Module 06 left open in a different form.**

> **Count your attempts. One.** Five within ten minutes locks the account and changes what the
> events say.

### 8.1 Note the time, then fail on purpose

On **DC01**:

```powershell
(Get-Date).ToUniversalTime()
```

Run `mstsc.exe`, connect to `10.0.0.20`, and enter `asmith@corp.local` with a **deliberately
wrong password**. Let it be refused **once**. Cancel out.

### 8.2 Find the failure

On **WS01**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5
```

Read one:

```powershell
$f = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 1
```

```powershell
$f.Message
```

Record, precisely:

| Field | Record what it says |
|---|---|
| **Logon Type** | |
| **Source Network Address** | |
| **Failure Reason / Status** | |
| **Account Name** | |

> **Prediction, to be tested, not assumed:** with NLA on, the failure may be recorded as **Logon
> Type 3 (network)** rather than Type 10, because the rejection happens during authentication
> before any interactive session is built. **If that is what you find, it is a significant
> detection point** — a detection rule watching only `Type 10` would miss every failed RDP logon
> while catching every successful one. Confirm it on the box; do not write it up from this
> paragraph.

### 8.3 Check the session logs — the test of the hypothesis

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'} -MaxEvents 5 | Select-Object TimeCreated, Id
```

Compare the newest timestamp against your 8.1 time.

**Either outcome is a result:**

- **Nothing new** → consistent with the hypothesis. The session logs record sessions, and no
  session was ever built. **But the channel must have been proven alive first** — it was, in Step
  6, when it recorded your real session. That positive control is what makes this silence mean
  something, and it is the Module 06 lesson applied correctly rather than reproduced as a mistake.
- **Something new** → the hypothesis is wrong, and that is the more interesting finding. Record
  exactly which event and what it carries.

Also check 1149:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149} -MaxEvents 3 | Select-Object TimeCreated
```

1149 means authentication **succeeded**, so a new one here would be surprising. Note whether the
log holds any *other* event ID for the failure.

---

# Step 9 — The controlled experiment: NLA off (WS01, then DC01)

**Aim: change exactly one variable and see whether it is NLA that decides how much a failure
records.**

This is the Module 06 method: stop reasoning about why and establish it.

### 9.1 Turn NLA off

On **WS01**:

```powershell
SystemPropertiesRemote.exe
```

**Untick** the Network Level Authentication checkbox. OK.

Read it back:

```powershell
Get-ItemProperty -Path 'HKLM:/SYSTEM/CurrentControlSet/Control/Terminal Server/WinStations/RDP-Tcp' -Name UserAuthentication | Select-Object UserAuthentication
```

**You want `0`.** If it still says `1`, the dialog did not commit — do not proceed on the
assumption that it did.

### 9.2 Fail the identical logon

Note the UTC time on DC01. Connect with `mstsc.exe` to `10.0.0.20`.

**The experience should be visibly different:** with NLA off, the far machine builds you a desktop
and shows you a Windows login screen *inside* the Remote Desktop window, rather than asking for
credentials in a local dialog first.

Enter `asmith@corp.local` with the **same wrong password**, **once**. Then close the window.

> **Attempt count: this is your second deliberate failure.** Three more and the account locks.

### 9.3 Compare — all three logs

Run the same three queries as Step 8, in the same order:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 1
```

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'} -MaxEvents 5 | Select-Object TimeCreated, Id
```

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'} -MaxEvents 5 | Select-Object TimeCreated, Id
```

### 9.4 The matrix

Fill it from what you actually read. Leave a cell blank rather than guessing it.

| NLA | 4625 present? | Logon Type in 4625 | Session log (21/22/24) touched? | 1149? |
|---|---|---|---|---|
| **On** (Step 8) | | | | |
| **Off** (Step 9) | | | | |

**One variable moved: whether authentication happened before the session was built.**

If the bottom row shows session events that the top row does not, then **NLA is not only a
hardening control — it changes what your logs can tell you about an attacker who fails.** That
would be worth stating carefully in both directions: NLA is unambiguously the right setting for
security, and it may *reduce* the forensic detail available about unsuccessful attempts. Both
things can be true, and a finding that says only one of them is incomplete.

📸 **Screenshot both halves** → `assets/07-nla-comparison.png`.

### 9.5 Put NLA back on — and confirm it

**Aim: leave the lab in a secure, known state.**

```powershell
SystemPropertiesRemote.exe
```

**Re-tick** Network Level Authentication. OK. Then:

```powershell
Get-ItemProperty -Path 'HKLM:/SYSTEM/CurrentControlSet/Control/Terminal Server/WinStations/RDP-Tcp' -Name UserAuthentication | Select-Object UserAuthentication
```

**You want `1` again.** This is not optional and not a formality — it is the third instance of
Module 06's Finding 5, and the module's own cleanup is exactly where that failure keeps happening.

### 9.6 Check the account did not lock

```powershell
Get-ADUser asmith -Properties LockedOut, BadLogonCount | Select-Object Name, LockedOut, BadLogonCount
```

*(run on **DC01**)*. If `LockedOut` is `True`, unlock it:

```powershell
Unlock-ADAccount -Identity asmith
```

> A manual unlock writes a **4767**. Module 01 established that **automatic lockout expiry writes
> no 4767 at all**, so a 4767 existing is evidence of deliberate administrative action. Yours
> would be genuine — note it so it is not mistaken for lab noise later.

---

# Step 10 — Lab state and cleanup (WS01)

**Aim: leave the machine in a state you have written down, so the next module starts from fact.**

Decide and record each of these:

| Setting | Leave as | Confirmed by |
|---|---|---|
| Remote Desktop enabled (`fDenyTSConnections`) | **Your call** — see below | registry readback |
| NLA (`UserAuthentication`) | **1 — on** | registry readback (9.5) |
| `asmith` in Remote Desktop Users | Leave, and document | `Get-LocalGroupMember` |
| Sysmon `NetworkConnect` ports | 9999 **and** 3389 | `Sysmon64.exe -c` live readback |
| Sysmon registry rules | **Untouched** | same readback |
| Module 06 audit switches | Unchanged | `auditpol` |

**On leaving RDP enabled:** the argument for is that Part II's Active Directory modules may want
remote access to WS01, and turning it off means rebuilding this step. The argument against is that
it is a real attack surface and the lab's own principle is to leave nothing on that is not needed.
**Recommendation: leave it on, with NLA on, and write it down here** — an undocumented enabled
service is the problem, not an enabled service.

Whatever you choose, **read it back and record the value**, rather than recording the command you
ran.

---

# Step 11 — Evidence for the portfolio

Each screenshot needs `hostname` at the top of the frame. Both VMs prompt
`PS C:\Users\Administrator>`, and `06-auditpol-before.png` is a genuine, unrepeatable baseline
whose host can no longer be established from the image.

**Filed in `assets/`, each opened and checked against its actual contents (2026-09-29):**

- [x] **`07-1149-auth.png`** — five 1149s and `$auth.Message` showing `asmith@corp.local`, an
  **empty Domain field** and `10.0.0.10`. **Carries `hostname` → `WS01` at the top of the frame**,
  so it is self-attributing. *(Arrived on disk as `07-1149-auth.png.png` — renamed.)*
- [x] **`07-session-attribution.png`** — the User / SessionID / Address table for both sessions.
  The strongest single image in the module: `LOCAL` vs `10.0.0.10` in one column, SessionID **3**
  in the morning and **2** in the afternoon, and the `23` rows visibly missing an `Address`. The
  `EventXML / -------- / EventXML` fragment at the top of the frame is the `UserData`-prints-only-
  the-wrapper trap, captured by accident.
- [x] **`07-session-lifecycle.png`** — 21 → 24 → 25 → 23 with timestamps. Strictly weaker than
  the attribution shot (no user, no address, **no hostname in frame**), but it is the clean
  lifecycle sequence. *(Arrived as `Session-Lifecycle.png` — renamed to the convention.)*

**Still outstanding:**

- [ ] `07-sysmon-config.png` — live config readback showing both ports and the registry rules.
  Recoverable on demand: `Sysmon64.exe -c` re-reads the live config.
- [ ] `07-4947-rules-modified.png` — the `Remote Desktop` rule table and the 4946/4947/4948 query
  in one frame. **Finding 5's first observation currently rests on text with no image behind it.**
- [ ] `07-4624-type10.png` — the logon, with Logon Type 10, source address and Logon ID visible
- [ ] `07-4625-nla-on.png` — the failed logon with NLA on, Logon Type **3** and the Sub Status
  visible. **Finding 3's headline.** Recoverable — the event is still in the log.
- [ ] `07-nla-comparison.png` — the two halves of the Step 9 matrix
- [ ] `07-261-listener.png` — the 261 and its `EventXML` showing **only** `RDP-Tcp`. Supports
  Finding 3's "the protocol-bearing event cannot name the identity".
- [ ] The Step 5 `Group-Object` breakdown of the 479 events
- [x] The access story from Step 7, written out — in this file
- [ ] **Module 06's `06-5152-ws01-empty.png`** — confirmed absent from `assets/` on 2026-09-29;
  Module 06 cannot be called complete without it

> **The notes said "six screenshots exist on the Windows machine and none are in `assets/`."
> Three were already there, two under wrong filenames.** Pasting a screenshot into a chat does not
> put it on disk — but neither does a stale note prove it is missing. **Check the directory.**

**Check every screenshot against its actual contents before filing it.** Reading Module 06's ten
corrected three things that had been recorded wrongly from memory, including a scare about
missing events that turned out to be a mistyped event ID.

---

# Findings

**Written from the run.** Observation is only what the log literally says, in **UTC** — the VMs
display UTC+1, so every local time in a screenshot reads one hour ahead of the figure quoted here.
Inference is labelled judgement. Recommendation names the follow-up queries.

Evidence for each finding is the run log above; screenshots are named where they exist.

---

## Finding 1 — One session, four logbooks, and no field that spans them

**Observation.** A single RDP session from DC01 (`10.0.0.10`) to WS01 on 2026-09-28 appears in four
separate logs, and the same user is spelled four different ways:

| Log | Event | What it printed for the user |
|---|---|---|
| Security | 4624, Type 10, 09:30:26, Logon ID `0x4F246D` | `asmith` + domain `CORP` |
| TerminalServices-RemoteConnectionManager | 1149, 09:30:24 | `asmith@corp.local`, **Domain field empty** |
| TerminalServices-LocalSessionManager | 21, 09:30:27, SessionID `3` | `CORP\asmith` |
| Sysmon | Event 3, `DestinationPort` 3389 | `NT AUTHORITY\NETWORK SERVICE` |

**No two of those match as strings.** The Security log's Logon ID (`0x4F246D`) appears nowhere
outside the Security log; LocalSessionManager's SessionID (`3`) appears nowhere outside that
channel. The two identifiers never co-occur in a single event.

The session was reconstructed by joining on **user + source address + timestamp proximity**: the
1149 at 09:30:24, the 4624 at 09:30:26 and the LocalSessionManager `21` at 09:30:27 sit within
three seconds of each other and share `10.0.0.10`.

Each log answers exactly one question: **Sysmon** where the connection came from (a machine),
**1149** who authenticated, **LocalSessionManager** what happened to the session,
**Security** what the session did.

*Evidence: `07-session-attribution.png`, `07-1149-auth.png`.*

**Inference.** I assess with **high confidence** that no single field joins these four logs on this
build, and that any correlation rule must therefore be written as a multi-hop join keyed on user,
source address and a timestamp tolerance. I assess with **high confidence** that a hunt written
with one identity string will silently return partial results — the same structural failure as
Module 03's `\REGISTRY\MACHINE\` vs `HKLM\`, and now demonstrated across four channels instead of
two.

**What cannot be determined from this evidence:** the join is **not reliable for concurrent
sessions**. Two logons by the same user from the same source within the timestamp tolerance would
be separable only by ordering, and nothing in the evidence establishes that the four channels
order simultaneous events consistently. This is a real limit of the method, not a gap in the data
collection.

Relevant technique: **T1021.001** (Remote Services: Remote Desktop Protocol), **T1078** (Valid
Accounts) — a legitimate credential is what makes this traffic indistinguishable from
administration without the surrounding context.

**Recommendation.**

- Normalise the account field at ingest — strip the UPN suffix and the `DOMAIN\` prefix to a bare
  `samAccountName` — **before** any correlation rule runs. Do not rely on the raw strings.
- Key the RDP correlation on `(normalised user, source address, ±5 s)` and treat the result as a
  candidate, not a fact, whenever more than one session from that user is open.
- Retain the Logon ID as the pivot **within** the Security log: `Get-WinEvent -FilterHashtable
  @{LogName='Security'; StartTime=…}` filtered on the session's Logon ID is what turns "who logged
  on" into "what they did".

---

## Finding 2 — A disconnected session is still a live session, and the Security log does not say so

**Observation.** The session `0x4F246D` opened with a 4624 at **09:30:26** and ended with a
**4647** at **09:42:20**. Between those, the user detached from the session at **09:37:33** and
reattached at **09:41:03** — a gap of **3m30s** during which the session existed with nobody
attached to it.

**None of the 479 Security-log events carrying Logon ID `0x4F246D` marks that gap.** The
Security log records the session as continuous.

LocalSessionManager records it in two rows, each carrying user, SessionID and source address:

| UTC | ID | Meaning | User / Session / Address |
|---|---|---|---|
| 09:37:33 | **24** | disconnected | `CORP\asmith` / 3 / `10.0.0.10` |
| 09:41:03 | **25** | reconnected | `CORP\asmith` / 3 / `10.0.0.10` |

The detachment was independently confirmed from the user's side before any log was read: a
PowerShell window reopened at reconnect still carrying output written at 09:35:03, so nothing had
been restarted.

Two further observations from the same channel: **the `23` (logoff) carries no `Address`**, and
**this channel logs local console sessions too** — `CORP\Administrator`, SessionID `1`, `Address:
LOCAL` at 09:50:21, 11:30:33 and 13:40:17.

*Evidence: `07-session-lifecycle.png`, `07-session-attribution.png`.*

**Inference.** I assess with **high confidence** that a detection built only on Security-log logon
and logoff events cannot distinguish a session that ended from a session that is still resident
with no one attached, and that this matters because a disconnected session holds a live token.
That is the precondition for **T1563.002** (Remote Service Session Hijacking: RDP) — an attacker
with SYSTEM on the host can attach to a disconnected session without ever authenticating as its
owner, and the 4624 for that attach names the hijacker's context, not the session's owner.

I assess with **moderate confidence** that ID `21` alone is not a usable RDP indicator on this
build, because the same ID is written for local console logons; `Address` is the field that
separates them, not the ID.

**What cannot be determined from this evidence:** no hijack was performed, so this run does not
establish what the logs look like *during* a hijack — only that the precondition is invisible in
the Security log. The 3m30s gap here was benign.

**Recommendation.**

- Alert on **ID 24 with no matching ID 25 or 23** within a defined window — a session left
  disconnected is the state worth knowing about.
- Use `Address` to classify, never the event ID alone:
  `([xml]$e.ToXml()).Event.UserData.EventXML` → `Address` is `LOCAL` for console, an IP for RDP.
- Enumerate resident sessions on demand (`qwinsta`) when a host is under investigation; the log
  tells you a session was left open, the host tells you whether it still is.

---

## Finding 3 — A refused RDP logon is Logon Type 3, and NLA changed nothing

**Observation — the failure itself.** One deliberate wrong-password attempt as
`asmith@corp.local` from DC01 on 2026-09-28 produced **exactly one 4625**, at **21:26:35**:

| Field | Value |
|---|---|
| **Logon Type** | **3** |
| Account Name | **`asmith@corp.local`**, Account Domain `-` |
| Security ID (subject **and** target) | **`S-1-0-0`** |
| Status / Sub Status | `0xC000006D` / `0xC000006A` |
| Workstation Name / Source | `DC01` / `10.0.0.10`, Source Port `0` |
| Logon Process / Package | `NtLmSsp` / **NTLM** |

One *successful* attachment writes **three** 4624s; one *failure* writes **one** 4625. The
successful interactive logon was **Type 10**; the failure was **Type 3**.

**Observation — the three channels.**

| Channel | Result |
|---|---|
| RemoteConnectionManager | **261** at **21:26:09** — "Listener RDP-Tcp received a connection", 26 s before the 4625 |
| Security | **4625**, Type 3, at 21:26:35 |
| LocalSessionManager | **nothing** — and the channel proved itself alive 2m40s earlier with a console-logon cluster at 21:23:02–21:23:03 |
| 1149 | **absent** |

The **261 carries only the listener name** `RDP-Tcp` — read from
`.Event.UserData.EventXML`, not inferred from its one-line message. No user, no source address, no
port.

**Observation — the NLA experiment.** `UserAuthentication` was set to `0` and read back as `0`;
`SecurityLayer` read `2`. The identical failure was repeated on 2026-09-29 at **00:37:58**:

| NLA | 4625 | Logon Type | Package | Session log | 1149 | 261 |
|---|---|---|---|---|---|---|
| **On** | 1 @ 21:26:35 | **3** | NtLmSsp / NTLM | untouched | none | 21:26:09 (−26 s) |
| **Off** | 1 @ 00:37:58 | **3** | NtLmSsp / NTLM | untouched | none | 00:37:26 (−32 s) |

**The rows are identical, field for field.** The client experience was also unchanged: no login
screen appeared inside the Remote Desktop window; credentials were collected in DC01's own dialog
and refused there.

**Inference.** I assess with **high confidence** that on this build a failed RDP logon is recorded
as **Logon Type 3**, and therefore that **a detection rule scoped to Logon Type 10 catches every
successful RDP logon on this host and misses every failed one.** Successes and failures do not
share a logon type, so they cannot share a hunt. This is the single most actionable result in the
module.

I assess with **high confidence** that **no single event classifies the attempt as RDP**. The 4625
is Type 3 over NTLM with Source Port `0` — indistinguishable from a failed SMB or WinRM logon — and
the 261 that does identify the protocol carries no identity. **The identity-bearing event cannot
name the protocol; the protocol-bearing event cannot name the identity.** The multi-hop join from
Finding 1 is therefore required *to classify the event at all*, not merely to enrich it.

I assess with **moderate confidence** that **261 present with no matching 1149** is a usable
signature for a refused RDP connection, on the reasoning that 1149 is the credentials-accepted
marker. Observed twice. **This is a candidate signature, not an established one** — no run has yet
confirmed that every refusal produces a 261, nor that a 261 cannot occur without an authentication
attempt following it.

**On NLA, the honest statement is a negative result.** The run sheet predicted that disabling NLA
would cause the session to be built before authentication, leaving session-log traces that an
NLA-on failure does not. **It did not.** **No cause is established.** The evidence is equally
consistent with two explanations, and I will not choose between them:

- **NLA does not affect what a failure records on this build.**
- **NLA never actually disengaged** — the value was changed underneath a running listener with no
  reload. This is the **leading candidate**, because the client experience was also unchanged, and
  because the licence-driven reboot that night fell *before* the change rather than after it.

`SecurityLayer = 2` was read and **excluded** as a second gate: transport encryption and NLA are
independent settings.

**What cannot be determined from this evidence:** whether NLA affects failure logging at all;
whether `0xC000006A` specifically means *wrong password against an existing account* as opposed to
*no such user* (the `Failure Reason` string deliberately conflates them, and the code's meaning was
**not resolved on the box**); and whether NTLM was selected because the connection was made by IP
rather than by name.

Relevant technique: **T1110.001** (Brute Force: Password Guessing) — a real campaign would produce
many of these events; **T1021.001** for the access attempt.

**Recommendation.**

- **Rewrite any RDP failure rule to key on 4625 with Logon Type 3 plus a source address**, and
  join to a 261 in `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` within
  ~60 s to confirm the protocol. A Type 10 rule will not fire.
- **Alert on the Sub Status, not the Failure Reason string.** `0xC000006A` and `0xC0000064` are the
  difference between password guessing against a known account and username enumeration, and the
  rendered message hides it.
- **Run the three outstanding discriminating tests**, all cheap:
  - NLA off → **reboot** → repeat the failure. Settles the leading candidate.
  - Fail as a nonexistent user and compare the Sub Status. No lockout cost.
  - Connect to `ws01.corp.local` instead of `10.0.0.20`, or query DC01 for a **4771** around the
    failure time — Kerberos pre-auth failures land at the DC, NTLM ones do not.

---

## Finding 4 — The target holds the evidence; the client holds almost none

**Observation.** Every event cited in Findings 1–3 was read on **WS01**, the machine that was
connected *to*. The 4624s, the 4625s, the 1149s, the session lifecycle and the Sysmon Event 3s all
live there. DC01 — the machine the connections were *made from* — was used only to read the clock
and run `mstsc.exe`, and `Get-ADUser` for the lockout check.

Sysmon on WS01 recorded the inbound half with `Initiated: false`, `SourceHostname DC01`,
`DestinationPort 3389` — but attributed it to `Image: svchost.exe`, `User: NT AUTHORITY\NETWORK
SERVICE`. **`asmith` appears nowhere in the Sysmon event.** In Module 06 the *outbound* Sysmon
Event 3 from WS01 named `powershell.exe` and the real user; the receiving end cannot.

**Inference.** I assess with **high confidence** that RDP investigation on this build must begin on
the destination host, and that a SOC collecting logs only from servers-of-interest and not from
workstations will see lateral movement *into* monitored hosts and be blind to movement *between*
unmonitored ones.

I assess with **high confidence** that Sysmon `NetworkConnect` attributes a **machine on the
receiving end, never a person** — the process that accepts the connection is a service running as
a service account. Combined with Module 06's finding that Sysmon Event 3 does not fire at all for
an unanswered probe, the picture is: **Sysmon attributes completed connections, from the initiating
side, to a person only when the initiating host is instrumented.**

**What cannot be determined from this evidence:** what DC01's own logs held for these connections
was **not read**. The claim that the client records "almost none" rests on the design of the
protocol and on Module 06's outbound findings, **not on a query run against DC01 during this
module.** That is a gap in this run, not a conclusion.

**Recommendation.**

- Collect the Security log **and** both TerminalServices channels from workstations, not only
  servers. `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` is enabled by
  default on this build and holds the session story in two lines.
- Close this finding's own gap: run the Step 5 and Step 6 queries **on DC01** for the same time
  windows and record what the initiating host actually kept.

---

## Finding 5 — Four of this run sheet's own predictions were wrong

Module 06 recorded its author's mistakes rather than quietly patching them, and that became its
most useful finding. This sheet made explicit predictions. Four failed.

**Observation 1 — enabling RDP writes 4947, not 4946.** The sheet said to watch for a **4946**
("a rule was added"). There was none. There were **seven 4947s** ("a rule was modified") in a
two-second burst at **09:39:25–09:39:26** on 2026-09-25. The Remote Desktop rules **already
existed, shipped disabled**; enabling RDP flipped `Enabled` on three rules
(`Shadow (TCP-In)`, `User Mode (TCP-In)`, `User Mode (UDP-In)`, all `Profile: Any`). Why three
rules produced seven events is **not established**.

**Observation 2 — the disconnect events were switched off, not absent.** The expected 4778/4779
were missing. `auditpol /get /subcategory:"Other Logon/Logoff Events"` returned **`No Auditing`** —
a **third** switch, distinct from the `Logon` and `Logoff` subcategories verified in sitting 1.
Enabled, readback confirmed, boundary marked at **12:55:18**, identical activity repeated:
**four events where there had been none, and nothing before the boundary.**

**Observation 3 — NLA changed nothing.** Covered in Finding 3. Both the predicted log difference
and the predicted change in the connection's *appearance* failed to materialise.

**Observation 4 — a 4625 window that could not fail.** Step 8.3 was written as "run the query and
expect nothing" for the session log. That expectation was only meaningful because the channel had
written a console-logon cluster **2m40s before** the attempt, in the same five rows as the
silence. Without that control the empty result would have been worth nothing — the same mistake
Module 06's Step 7.1 made and corrected.

**Inference.** I assess with **high confidence** that the recurring failure mode across three
modules is the same one: **an absence was read as evidence before the instrument was proven alive.**
Module 02 found object auditing gated at four independent layers; Module 06 found a packet-drop
subcategory off by default; this module found a *third* logon subcategory off by default. In every
case the log was silent and the silence looked like a fact about Windows.

I assess with **high confidence** that **4946 and 4947 are not interchangeable**: 4946 means a rule
that did not exist now does; 4947 means an existing rule changed. **A firewall hunt written only
for 4946 misses a host being opened up to RDP entirely**, because the rules ship pre-installed and
merely get enabled.

**What cannot be determined from this evidence:** why seven 4947s were written for three rules; and
whether NLA has any effect on failure logging, for the reasons in Finding 3.

Relevant technique: **T1562.002** (Impair Defenses: Disable Windows Event Logging) — an
adversary does not need to clear a log if the subcategory that would have written to it was never
enabled. Three of this lab's modules found such a subcategory off by default on a stock install.

**Recommendation.**

- **Hunt 4946 and 4947 together.** A rule flipped from disabled to enabled is the realistic path to
  a host being exposed, and it writes only the second.
- **Audit the audit configuration as a standing control.** `auditpol /get /category:*` on every
  host, compared against a baseline, catches the gate that is closed before an investigation
  depends on it. Verify the instrument before trusting a silence, every time.
- **Record predictions in the run sheet before the run, and record which ones died.** Three of the
  four failures above were only visible because the prediction was written down first.

---

## Open questions carried out of this module

Named so they are not mistaken for settled results.

| # | Question | Discriminating test |
|---|---|---|
| 1 | Does NLA affect failure logging at all? | NLA off → **reboot** → repeat the failure |
| 2 | Does `0xC000006A` mean *wrong password* rather than *no such user*? | fail as a nonexistent user, compare Sub Status |
| 3 | Was NTLM selected because the connection was made by **IP**? | connect to `ws01.corp.local`; or look for a **4771** on DC01 |
| 4 | What did **DC01** record about connections it initiated? | run the Step 5/6 queries on DC01 |
| 5 | Why seven 4947s for three rules? | not chased |
| 6 | What is the unidentified **4625 at 00:29:46 on 2026-09-29**? | read its fields; a console mistype is plausible but unestablished |
| 7 | Why **5 × 1149** for two sessions? | not chased |

---

# Reference

### Event IDs

| ID | Log | Meaning |
|---|---|---|
| 4624 | Security | Successful logon — **Type 10 = RemoteInteractive (RDP)** |
| 4625 | Security | Failed logon — read the Logon Type *and* the failure reason |
| 4634 / 4647 | Security | Logoff |
| 4778 / 4779 | Security | Session reconnected / disconnected from a window station |
| 4732 | Security | Member added to a security-enabled **local** group (Remote Desktop Users) |
| 4740 | Security (DC01) | Account locked out |
| 4767 | Security (DC01) | Account **manually** unlocked — never written by automatic expiry |
| 1149 | TerminalServices-RemoteConnectionManager/Operational | User authentication succeeded |
| 21 | TerminalServices-LocalSessionManager/Operational | Session logon succeeded |
| 22 | same | Shell start notification received |
| 23 | same | Session logoff succeeded |
| 24 | same | Session **disconnected** |
| 25 | same | Session **reconnected** |
| 3 | Microsoft-Windows-Sysmon/Operational | Network connection |

### Logon types worth knowing

| Type | Meaning |
|---|---|
| 2 | Interactive — at the keyboard |
| 3 | Network — e.g. reaching a file share, and **possibly** NLA-stage RDP authentication |
| 5 | Service |
| 10 | **RemoteInteractive — RDP** |

### MITRE ATT&CK

| Technique | ID | Where it appears here |
|---|---|---|
| Remote Services: Remote Desktop Protocol | T1021.001 | The whole module |
| Valid Accounts: Domain Accounts | T1078.002 | `asmith` connecting with legitimate credentials |
| Brute Force: Password Guessing | T1110.001 | Steps 8–9, and Module 01's lockout policy |
| Remote Service Session Hijacking: RDP Hijacking | T1563.002 | The 24/25 disconnected-session gap |

---

## Notes & gotchas

- **`fDenyTSConnections = 0` means RDP is ON.** A double negative in a registry value name is an
  easy and expensive misread.
- **The evidence is on the machine being connected *to*.** Querying DC01 for RDP events returns
  empty, with no error to say why.
- **A disconnect leaves the session running.** Closing the window ends nothing.
- **Count your failed logons.** Module 01 set a five-attempt lockout with a ten-minute window on
  this domain, and `asmith` is the account it has locked before.
- **These are separate log channels, not the Security log.** `LogName='Security'` will never see
  a 21, 24 or 1149 — the same trap Sysmon set in Module 03.
- **`EventData` may be empty on these events; check `UserData`.** Module 04 met this first with
  1102.
- **Read the active firewall profile on each machine separately.** DC01 was on `Public` and WS01
  on `Domain` simultaneously as of 2026-09-16, unexplained.
- **A `Set-`/`Enable-`/`Remove-` that ran is not a state that changed.** Read it back. Module 06's
  Finding 5, three instances and counting.
- **`gpedit.msc` and `gpupdate` remain broken on WS01.** Everything here uses System Properties,
  the registry, or `wf.msc` — all of which work.
- **Put `hostname` at the top of every screenshot.**
- **Suspect the query before the host.** A mistyped event ID returns `NoMatchingEventsFound` —
  the identical message a genuine empty result gives.
- **4946 is "rule added", 4947 is "rule modified" — enabling a shipped-but-disabled rule is a
  4947.** Verified on WS01 2026-09-25: turning RDP on produced 7 × 4947 and **zero** 4946. A
  firewall hunt written only for 4946 misses a host being opened up to RDP.
- **`Get-NetFirewallProfile` does not tell you which profile is active.** It lists all three, each
  reading `Enabled: True`. `Get-NetConnectionProfile` gives the `NetworkCategory` actually in use.
  Module 06 already found this cmdlet misleading in a second way — it reads the *configured* store
  by default and returns `DefaultInboundAction: NotConfigured`.
- **The shipped Remote Desktop rules are `Profile: Any`.** So the per-profile worry this sheet
  raises does not bite for RDP itself on this host — but it is still real for rules you write.
