# Module 07 — Remote Desktop (RDP)

> **Runs on:** WS01 **and** DC01 — WS01 is the machine being connected *to*, and that is
> where nearly all the evidence lands
> **Time:** ~2 hours, best split across three sittings
> **Roll back to:** `mod06-start` · **Snapshot before starting:** `mod07-start` (both VMs)
> **Status:** written 2026-09-22. **Sitting 1 part-run 2026-09-25 — see the run log below.**
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

# Run log — Sitting 1 (2026-09-25, part-run)

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

### Where the sitting stopped

**Step 2.1 was issued but not confirmed.** `SystemPropertiesRemote.exe` was handed over with
instructions to enable Remote Desktop and leave NLA ticked; **no confirmation was pasted back**,
so the state of that dialog is **unknown**. Resume by running the Step 2.2 registry readback
first — it reports what is actually set, whichever way the dialog went.

**Not started:** Steps 2.2, 2.3, 3.1, 3.2.

### Carried over from Module 06

`06-sysmon3-zero.png` was **deliberately dropped** on 2026-09-25 rather than captured before the
Step 3.2 config change. `06-5152-ws01-empty.png` is still capturable at any time and remains
outstanding.

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
Get-NetFirewallProfile | Select-Object Name, Enabled
```

The inbound Remote Desktop rule must be **enabled on whichever profile WS01 is actually using**.
If it is not:

```powershell
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
```

Then **re-run the `Get-` above**. A `Enable-` that ran is not a rule that is enabled — the block
rule reported deleted on 2026-09-15 was found still present and enabled the next sitting.

> **Watch for a 4946 here.** Module 06 left `MPSSVC Rule-Level Policy Change` auditing **on**, so
> enabling these rules should write rule-change events on WS01. Free corroboration, and a nice
> confirmation that Module 06's switches are still live.

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

- [ ] `07-sysmon-config.png` — live config readback showing both ports and the registry rules
- [ ] `07-4624-type10.png` — the logon, with Logon Type 10, source address and Logon ID visible
- [ ] `07-session-lifecycle.png` — 21 → 24 → 25 → 23 in one frame
- [ ] `07-1149.png` — the authentication event with user and source address
- [ ] `07-join-table.png` — or the table written into this file; the join is the deliverable
- [ ] `07-4625-nla-on.png` — the failed logon with NLA on, failure reason visible
- [ ] `07-nla-comparison.png` — the two halves of the Step 9 matrix
- [ ] The access story from Step 7, written out

**Check every screenshot against its actual contents before filing it.** Reading Module 06's ten
corrected three things that had been recorded wrongly from memory, including a scare about
missing events that turned out to be a mistyped event ID.

---

# Findings

**Left deliberately unwritten.** Findings are written *from* the run, in
**observation → inference → recommendation** form, with the three kept strictly separate.
Observation is only what the log literally says, in UTC. Inference is labelled judgement with
confidence language and an explicit statement of what cannot be determined. Recommendation names
the follow-up queries.

The questions each finding should answer:

**Finding 1 — What ties four logs into one session?** Name the join key or keys. State plainly
whether a single field spans all four, and whether two simultaneous sessions from one user would
still be separable. An honest "only by timestamp, which is insufficient" is a stronger finding
than a confident wrong one.

**Finding 2 — Disconnected is not logged off.** The 24/25 pair, and what the logs can and cannot
say about a session that exists with nobody attached. Relevant technique: RDP session hijacking.

**Finding 3 — What a failed logon records, and what NLA changes.** The Step 9 matrix. If the
Logon Type differs between success and failure, say what that does to a detection rule written
only for Type 10. Give both sides of the NLA trade-off.

**Finding 4 — Which host holds the evidence.** The client machine records little; the target holds
almost everything. Compare deliberately with Module 06, where the attribution was on neither.

**Finding 5 — Whichever prediction in this run sheet turned out wrong.** Module 06 recorded its
own author's mistake rather than quietly patching it, and that became one of its most useful
findings. This sheet makes several explicit predictions — the NLA hypothesis, Logon Type 3 on
failure, `UserData` rather than `EventData`, Sysmon on the receiving end. **Some of them will be
wrong.** Write up which, and what the evidence actually said.

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
