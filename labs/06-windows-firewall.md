# Module 06 — Windows Firewall

> **Runs on:** WS01 **and** DC01 — the first module since 01 that needs both
> **Time:** ~2 hours, best split across three sittings
> **Roll back to:** `mod04-start` (WS01) · **Snapshot before starting:** `mod06-start` (both VMs)

---

## What you're going to do

Every machine keeps a list of rules about which network connections it will accept and
which it will refuse. Windows has one built in and it is switched on by default. When
something tries to connect and no rule permits it, the connection is refused.

**The refusal is the thing this module is about.** In real work, a refused connection can
be someone scanning your network looking for a way in. So the question to answer is: when
a connection was refused, can you find it afterwards, and can you say who caused it?

You will cause exactly one refusal — WS01 knocking on a door that is closed on DC01 — and
then go and find it.

The lesson that makes this a detection module: **the same refusal is recorded in two
places, and they tell you very different amounts.**

| Where | What it tells you |
|---|---|
| A plain text file on disk (`pfirewall.log`) | A packet to this address and port was dropped, at this time. That's all |
| The Windows event log (event **5157**) | The same refusal, plus which **program** tried, which **account** it was running as, and which direction |

The text file is nearly anonymous. The event log entry is something you could put in a
ticket. Seeing both for one refusal you caused yourself, at a time you wrote down, is the
result this module produces.

In this module you will:

1. Read the firewall state on both machines before changing anything
2. Turn on recording — in the event log *and* the text file
3. Write one firewall rule of your own and then delete it, watching Windows record both —
   and discover that neither record says who did it
4. Knock on a closed door on DC01 from WS01
5. Find that refusal in the text file, then in the event log
6. Discover that it was recorded on **DC01 only** — and that looking on WS01 finds nothing

Follow the steps in order. **Every step says which VM.** This time it genuinely varies,
and a query run on the wrong machine returns empty rather than an error.

---

### Two words you need first

**A port** is a numbered door on a machine. One machine has thousands. A service listens
behind a particular door — file sharing on 445, DNS on 53 — and if nothing is listening
behind a door, a connection to it goes nowhere. In Step 4 you will knock on door 9999 on
DC01, where nothing is listening and no rule allows it.

**A profile** is which set of firewall rules is currently in force. Windows keeps three —
**Domain**, **Private** and **Public** — and uses one at a time depending on the kind of
network it thinks it is on. Both lab machines are domain-joined, so both should be on the
**Domain** profile. This matters because it is very easy to write a rule or switch on
logging for a profile you are not actually using, and then wonder why nothing happened.

---

### Sitting split

| Sitting | Steps | Ends with |
|---|---|---|
| 1 | 0 – 3 | Recording switched on, one rule written, nothing triggered yet |
| 2 | 4 – 7 | The refusal caused and found in both logs |
| 3 | 8 – 9 + Findings | Baseline table, screenshots, write-up |

---

# Step 0 — Pre-flight (both VMs)

### 0.1 Check both machines are healthy

**Aim: start from machines that will not shut down mid-sitting.**

Both evaluation licences were rearmed on 2026-09-04, but DC01 has been barely touched
since Module 01. On **DC01**, right-click **Start → Windows PowerShell (Admin)**:

```powershell
slmgr /dlv
```

A dialog appears. Check the remaining time is not close to zero. Do the same on **WS01**
if you want, though WS01 has been in use recently.

### 0.2 Boot DC01 first, and prove the domain is actually up

**Aim: prove the domain works before you touch the firewall, so that anything odd later is
something you did.**

**Start DC01 before WS01, and let it finish booting** — give it a minute or two after the
login screen appears, because the domain services take longer to come up than the desktop
does.

The domain controller is not a machine that *participates* in the domain — it **is** the
domain. It holds every account, password and group membership, and there is no second
copy. With DC01 off, nothing about `corp.local` can be checked by anyone.

On **WS01**, in **PowerShell (Admin)**:

```powershell
Test-ComputerSecureChannel
```

It returns `True` or `False`: does this machine still have a working trust relationship
with `corp.local`? You want **`True`** before going any further.

> **Do not take a successful login as proof the domain is up.** Windows keeps **cached
> credentials** — it remembers recent domain logons so you can sign in with no network at
> all. On 2026-09-13 this module's first sitting began with DC01 powered off; WS01 logged in
> normally on cache, and the first sign of trouble was the firewall showing the wrong
> profile two steps later.

### 0.2b Check the profile followed

**Aim: catch the one after-effect that does not fix itself when DC01 comes up.**

```powershell
Get-NetConnectionProfile
```

`NetworkCategory` should read **`DomainAuthenticated`**. If it still reads `Public` —
which it will if DC01 was started after WS01 — **reboot WS01**. The category is decided
when the network connection comes up and is not reassessed afterwards, so `True` from
`Test-ComputerSecureChannel` and a `Public` category can be true at the same moment.

This matters more here than in any previous module: `Public` active means every rule and
every logging setting in Steps 2 and 3 has to go on the **Public** profile instead, or it
is inert. Settle it now.

### 0.2c Confirm the two machines can talk

```powershell
Test-NetConnection -ComputerName 10.0.0.10
```

`PingSucceeded` may come back **False** even though the network is fine — Windows blocks
ping by default. What matters is that the command returns and the address resolves. You
will fix the ping in Step 3.

### 0.3 Snapshot both VMs

**Aim: bookmark this state so the whole module can be repeated, and so a firewall rule
that locks you out is recoverable.**

Shut both VMs down cleanly. Take a snapshot on **each**, both named **`mod06-start`**.
Boot both back up and log in as `administrator@corp.local`.

> Module 03 skipped its snapshot, and that is the only reason its unexplained 4657 result
> is still sitting there with no way to test it. Take these two.

---

# Step 1 — Look at the firewall before you change it (both VMs)

**Aim: know what the firewall already looks like, so that every change you make later can
be proved rather than assumed.**

You never change a setting you have not read first — the same discipline as reading a
folder's permissions before locking it in Module 02.

### 1.1 Open the firewall window

On **WS01**: press `Win+R`, type `wf.msc`, press Enter.

This is **Windows Defender Firewall with Advanced Security**. It is a different tool from
the `gpedit.msc` that is broken on this host, and it works.

Look at the middle pane. It shows all three profiles — Domain, Private, Public — and says
which one is active. Note down:

- Which profile says **is active**
- Whether **Windows Defender Firewall is on** for that profile
- What the **inbound** and **outbound** defaults are

You should see inbound default to **block** and outbound to **allow**. That asymmetry is
the whole shape of a host firewall: it is much more worried about what reaches it than
what leaves it.

### 1.2 The same thing as text

**Aim: get the same facts in a form you can paste into the baseline table in Step 8.**

Still on **WS01**, in **PowerShell (Admin)**:

```powershell
Get-NetFirewallProfile
```

That prints a lot. Narrow it to the columns that matter:

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
```

Three profiles, three rows. Compare against what `wf.msc` showed you.

### 1.3 Do both of the above on DC01

**Aim: DC01 is where the refusal will be recorded, so its state matters more than WS01's.**

Repeat 1.1 and 1.2 on **DC01**. Write both machines' answers down — Step 8 turns them into
the module's deliverable.

---

# Step 2 — Turn on the recording (both VMs)

**Aim: get both instruments running *before* anything happens, because none of this is
retroactive.**

This is Module 02's lesson arriving again in network form. Auditing never reaches
backwards. Anything you want recorded has to be switched on before you do it.

There are **four independent switches** here, and as in Modules 02 and 03, one being on
tells you nothing about the others.

| # | Switch | What it controls | Symptom when off |
|---|---|---|---|
| 1 | `Filtering Platform Connection` subcategory | events **5156** (allowed) / **5157** (blocked) | no 5157 — your refusal is invisible in the event log |
| 2 | `Filtering Platform Packet Drop` subcategory | events **5152** / **5153** | no packet-drop events — a *separate* switch from 1 |
| 3 | `MPSSVC Rule-Level Policy Change` subcategory | events **4946–4948** — firewall *rules* changing | no record that someone edited the firewall |
| 4 | The profile's own `-LogBlocked` setting | the text file `pfirewall.log` | no text file, or an empty one — and it is set **per profile** |

Switch 4 is the subtle one, exactly as the SACL's audited rights were in Module 02:
it is set per-profile rather than globally, so turning it on for Domain leaves Private and
Public recording nothing.

### 2.1 Read the current state first

**Aim: find out what is already on, rather than trusting anyone's claim about Windows
defaults — mine included.**

On **WS01**, in **PowerShell (Admin)**:

```powershell
auditpol /get /subcategory:"Filtering Platform Connection"
```

Then the other two, one at a time:

```powershell
auditpol /get /subcategory:"Filtering Platform Packet Drop"
```

```powershell
auditpol /get /subcategory:"MPSSVC Rule-Level Policy Change"
```

Write down what each says — `No Auditing`, `Success`, `Failure`, or `Success and Failure`.
This is the "before" half of the evidence.

> **I do not know what these read by default on your hosts**, and neither should you until
> you have looked. Read them off the box.

### 2.2 Switch on blocked connections only

**Aim: record refusals without drowning the log.**

Here is why this matters. Switch 1 has two halves. **Failure** records connections that
were *blocked* — on a quiet lab, a handful a day. **Success** records every connection
that was *allowed*, which on a domain-joined machine is constant: every conversation with
the domain controller, every background service. Turning Success on produces an enormous
number of events very quickly.

You already proved in Module 04 what that does — the Security log fills, and **the oldest
events are pushed out and destroyed**. That is what ate the 16 August failed logons.

So: **Failure only.** On **WS01**:

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
```

Then read it back — never assume a `/set` worked:

```powershell
auditpol /get /subcategory:"Filtering Platform Connection"
```

It should now read `Failure`. Do the same two commands on **DC01**.

> Leave **Success** off for the whole module. If you ever switch it on, switch it off the
> same sitting and check the log size afterwards (`wevtutil gli Security`, per Module 04).

### 2.3 Switch on rule-change recording

**Aim: so that the rule you write in Step 3 leaves a record — and so would an attacker's.**

Switch 3, on **WS01**:

```powershell
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable
```

Read it back:

```powershell
auditpol /get /subcategory:"MPSSVC Rule-Level Policy Change"
```

Do the same on **DC01**.

> **Order matters here and nowhere else in the module.** This has to be on *before* Step 3
> writes a rule. Write the rule first and there will be no 4946, and it will look like a
> broken host rather than the wrong order.

### 2.4 Switch on the text file

**Aim: get the second instrument running, so Step 5 and Step 6 describe the same refusal.**

Switch 4, on **DC01** — this is the machine that will do the refusing, so this one is the
one that counts. **Use the profile Step 1 said was active on *that* machine**, which is not
necessarily the same on both:

```powershell
Set-NetFirewallProfile -Name Public -LogBlocked True
```

Read it back:

```powershell
Get-NetFirewallProfile -Name Public | Select-Object Name, LogBlocked, LogFileName
```

> **On 2026-09-13 the two machines differed**: WS01 came up `DomainAuthenticated` (Domain
> profile) and DC01 came up **Public**. So WS01 takes `-Name Domain` and DC01 takes
> `-Name Public`. Substitute per machine — this is exactly the mistake the profile warning
> exists for, and here it is live on the first run.

`LogBlocked` should read `True`, and `LogFileName` gives you the path the text file will
appear at — normally
`%systemroot%\system32\LogFiles\Firewall\pfirewall.log`.

Do the same on **WS01** as well. WS01 is unlikely to record this particular refusal, but
having it on both is what makes Step 7's result meaningful rather than an accident.

> **Note the profile name.** You are setting this on `Domain` because that is what Step 1
> said was active. If Step 1 told you something different on either machine, use that name
> instead — and say so in your write-up, because it changes what the evidence means.

---

# Step 3 — Write a rule, delete it, and watch Windows record both (DC01)

**Aim: learn what writing a firewall rule looks like, and meet the two events that fire
when someone changes a firewall — including the one that matters most, which is the
deletion.**

Ping is the safe thing to experiment with: nothing the domain needs depends on it, so a
rule that blocks it can be written and removed with no risk.

### 3.1 Find out whether ping already works

On **WS01**:

```powershell
Test-NetConnection -ComputerName 10.0.0.10
```

Read the `PingSucceeded` line.

> **On the 2026-09-14 run it came back `True` before any rule was written** — which
> contradicted this run sheet's first draft, and matched Module 00's progress log, where
> connectivity was "verified by ping" back on 2026-08-02. Something on DC01 had been
> allowing it all along. Step 3.2 finds out what. Do not skip it just because your answer
> here is `False`; knowing which rules are live is the point.

### 3.2 Find the rules that are actually in force

**Aim: read existing rules before adding one — the same discipline as reading a DACL before
changing it.**

On **DC01**:

```powershell
Get-NetFirewallRule -DisplayName '*Echo Request*' | Select-Object DisplayName, Profile, Action
```

That returns a long list, because Windows ships many rules that are present but switched
off. Add one piece to keep only the live ones:

```powershell
Get-NetFirewallRule -DisplayName '*Echo Request*' | Where-Object Enabled -eq 'True' | Select-Object DisplayName, Profile, Action
```

> **Verified 2026-09-14 on DC01:** two enabled allow rules —
> `File and Printer Sharing (Echo Request - ICMPv4-In)` on **Public**, and an
> **Active Directory Domain Controller** echo-request rule on **Any**. Promoting a server to
> a domain controller enables its own set of firewall rules, and one of them is this. That is
> why ping worked from Module 00 onward with nobody configuring it.

### 3.3 Write a **block** rule in the GUI

**Aim: see that a single block beats any number of allows — the network-layer version of
Module 02's "deny beats allow".**

You are about to block ping while two enabled rules are actively allowing it.

On **DC01**, open `wf.msc` (`Win+R`, `wf.msc`, Enter).

1. Click **Inbound Rules** in the left pane
2. Click **New Rule...** in the right pane
3. Rule Type: **Custom** → Next
4. Program: **All programs** → Next
5. Protocol type: choose **ICMPv4** from the dropdown → Next
6. Scope: under *Which remote IP addresses...*, choose **These IP addresses**, click
   **Add**, enter `10.0.0.20` → OK → Next
7. Action: **Block the connection** → Next
8. Profile: tick **the profile that is active on DC01** — on the 2026-09-14 run that was
   **Public**, not Domain. Tick that one only → Next
9. Name: `LAB Block Ping from WS01` → Finish

Scoping to one address is the point of using **Custom** rather than the quick path: "block
ping from this one machine" is a different rule from "block ping from everywhere", and real
firewall rules are judged on exactly that distinction.

Back on **WS01**:

```powershell
Test-NetConnection -ComputerName 10.0.0.10
```

`PingSucceeded` should now be **False**. Two rules allowing, one blocking, and the block
wins.

### 3.4 Find the record of the addition — 4946

**Aim: see that firewall changes are themselves logged.**

On **DC01**, in **PowerShell (Admin)**. Shortest useful query first:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4946}
```

`4946` means *a rule was added to the firewall exception list*.

Add one piece — the times:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4946} | Select-Object TimeCreated, Id
```

> **Do not assume the newest event is yours.** On 2026-09-14 there were **four** 4946s on
> DC01 and the one written by hand was the **oldest** — three more had been added by Windows
> itself overnight, with nobody touching the firewall. `-MaxEvents 1` returns the *newest*
> and would have grabbed the wrong event. Identify yours by **rule name**, not by position.

`Get-WinEvent` returns events newest-first, so the *oldest* is `-Last 1`:

```powershell
$e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4946} | Select-Object -Last 1
```

Then list its fields by name, the same way you have since Module 01:

```powershell
([xml]$e.ToXml()).Event.EventData.Data | Format-Table Name, '#text'
```

Confirm the rule name is the one you typed before treating the event as yours.
**Screenshot this** — it is evidence item 3.

### 3.5 Delete the rule, and catch the deletion — 4948

**Aim: meet the event that fires when someone removes a protection, which is the one an
attacker generates.**

An attacker who wants to reach a machine does not have to defeat the firewall. They can
delete the rule that stops them. That writes a **4948**.

On **DC01**, in `wf.msc`: **Inbound Rules** → find `LAB Block Ping from WS01` → right-click
→ **Delete** → **Yes**.

Confirm on **WS01** that ping works again:

```powershell
Test-NetConnection -ComputerName 10.0.0.10
```

Then find the deletion on **DC01**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4948}
```

```powershell
$d = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4948} -MaxEvents 1
```

```powershell
([xml]$d.ToXml()).Event.EventData.Data | Format-Table Name, '#text'
```

### 3.6 Ask who did it — and find out you cannot

**Aim: establish, by evidence rather than assertion, that these events do not identify the
account.**

Look for an account field in what 3.5 returned. Then ask Windows directly:

```powershell
$d.Message
```

`.Message` is the human-readable rendering — the same text Event Viewer's General tab shows,
every field resolved and labelled. Then check the event header, which is separate from the
fields and sometimes carries the SID of whoever caused the event:

```powershell
([xml]$d.ToXml()).Event.System.Security
```

Run the same header check against the 4946 as a **control**, so the result is about this
family of events rather than one odd event:

```powershell
([xml]$e.ToXml()).Event.System.Security
```

> **Verified 2026-09-14 on DC01.** 4948's fields are Profile Changed, Rule ID and Rule Name.
> `.Message` adds nothing further. `Event.System.Security` is **empty on both 4946 and 4948**.
> Neither event records the account. See Finding 3.

**End of sitting 1.** Both instruments are on, on both machines; one rule has been written
and deleted; no connection has been refused yet.

---

# Step 4 — Break: knock on a closed door (WS01 → DC01)

**Aim: produce exactly one refusal, at a time you have written down, so that everything
found afterwards can be tied to it.**

Port 9999 on DC01 has nothing listening behind it and no rule allowing it, so DC01's
firewall will refuse the connection.

### 4.1 Write down the time first

On **WS01**:

```powershell
Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
```

Write that down. Note it is **local time (WAT, UTC+1)** — the logs store UTC, so what you
find will read one hour *earlier* than this. That gap has cost this lab real time before.

### 4.2 Knock

On **WS01**:

```powershell
Test-NetConnection -ComputerName 10.0.0.10 -Port 9999
```

It will pause for a few seconds and return `TcpTestSucceeded: False`. That pause is the
connection going unanswered.

Do it **three times**, a few seconds apart. Three attempts are easier to pick out of a log
than one, and a repeated attempt is what a scan actually looks like.

### 4.3 Write down the time again

```powershell
Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
```

You now have a window with a start and an end. Everything in Steps 5–7 gets judged against
it.

---

# Step 5 — Detect in the text file (DC01)

**Aim: read a firewall log that is not an event log, and see how little it tells you.**

### 5.1 Open the file

On **DC01**, in **PowerShell (Admin)**:

```powershell
Get-Content 'C:/Windows/System32/LogFiles/Firewall/pfirewall.log' -Tail 20
```

> **Forward slashes work.** PowerShell accepts `/` in file paths exactly as it does in
> registry paths (Module 03) — it normalises them. That is the standing way around the
> backslash on your keyboard. It does **not** apply to `reg.exe` or to Notepad's Open
> dialog.

`-Tail 20` gives you the last 20 lines, which for a file this new is probably all of it.

The first few lines are a header explaining the columns. Then each entry is one line:
date, time, action (`DROP`), protocol, source address, destination address, source port,
destination port, and a set of mostly-empty fields.

### 5.2 Find your three attempts

```powershell
Get-Content 'C:/Windows/System32/LogFiles/Firewall/pfirewall.log' | Select-String '9999'
```

`Select-String` searches text — it is the closest thing here to `grep`, and it works
because this is a plain text file, not an event log. None of `Get-WinEvent`,
`-FilterHashtable` or XML field extraction applies to it.

**Screenshot this.** Then look at what it gives you and, more importantly, what it does
not: an address, a port, a time, the word `DROP`. It cannot tell you which program on WS01
made the attempt, or which account was logged in. If this were the only record you had,
your ticket would say "something on 10.0.0.20 probed port 9999" and stop there.

---

# Step 6 — Detect in the event log (DC01)

**Aim: get the same refusal with the detail that makes it actionable, and see why the
event log is worth the volume it costs.**

### 6.1 Start wide

On **DC01**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} -MaxEvents 10
```

**5157** means *the Windows Filtering Platform blocked a connection*. The Filtering
Platform is the machinery underneath the firewall that actually makes the allow/block
decision — the firewall rules are the policy, this is the engine that enforces it.

If that returns nothing, stop and read the troubleshooting list at the bottom of this file
before changing anything.

### 6.2 Count before you conclude

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} | Measure-Object
```

Module 03 cost a sitting to this exact trap: a small number returned under `-MaxEvents`
was read as "that is all there is", which was fiction. Get the count before you treat any
number as a result.

### 6.3 Narrow to your three attempts

You want only the ones aimed at port 9999. Take one event and look at its fields by name
first, so you know what the field is called rather than guessing:

```powershell
$e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} -MaxEvents 1
```

```powershell
([xml]$e.ToXml()).Event.EventData.Data | Format-Table Name, '#text'
```

Read the list. You are looking for the destination port field, the source address, the
application, and the account.

### 6.4 The fields that make 5157 worth having

**Aim: state plainly what this event gives you that the text file does not.**

Pull the useful fields out for your three events. Build it up — first get the events:

```powershell
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} -MaxEvents 20
```

Then for one of them, print the four fields that matter by name (substitute the exact
names you read in 6.3):

```powershell
$x = ([xml]$events[0].ToXml()).Event.EventData.Data
$x | Where-Object Name -in 'Application','SourceAddress','DestPort','ProcessId' | Format-Table Name, '#text'
```

**Screenshot this.** Compare it directly against the Step 5 screenshot. That comparison is
the module's main result, and it is what Finding 1 will be written from.

> **Read the field names off your own output, not from this file.** I have not verified the
> exact spelling of 5157's fields on your hosts. If 6.3 shows different names, use those and
> correct this run sheet afterwards — that is how Modules 02 and 03 both ended up accurate.

---

# Step 7 — The same query on the wrong machine (WS01)

**Aim: prove to yourself that an empty result can mean "you are asking the wrong computer",
and learn to rule that out first.**

Run the *identical* query from 6.1, this time on **WS01**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} -MaxEvents 10
```

**What I expect:** nothing, or nothing related to port 9999. WS01 *sent* the connection;
DC01 *refused* it. The refusal is DC01's decision, so DC01 is where the record lives.
WS01's outbound default is allow, so from WS01's point of view nothing was blocked at all.

**This is an expectation, not a verified fact on your lab.** If WS01 does return something,
that is a legitimate and more interesting result — record what it says and write it up.
Either answer is worth having; what is not acceptable is assuming.

Either way, note the shape of the failure: the query is correct, the log is healthy, the
window is right, and it still returns nothing — because the event was never on that
machine. That is the fourth entry on your empty-output checklist, and this module is where
it stops being theoretical.

**End of sitting 2.**

---

# Step 8 — Deliverable: the firewall baseline

**Aim: produce the thing a real job asks for — a written statement of what these machines
allow, so that a future change can be recognised as a change.**

Fill this in from Step 1 and Step 2, one row per machine:

| | WS01 | DC01 |
|---|---|---|
| Active profile | | |
| Firewall enabled | | |
| Default inbound | | |
| Default outbound | | |
| `Filtering Platform Connection` auditing | | |
| `MPSSVC Rule-Level Policy Change` auditing | | |
| `LogBlocked` on active profile | | |
| Text log path | | |
| Lab rules added | | |

Then two or three sentences in your own words: what each machine currently accepts, what
you changed, and how someone would notice if it changed again.

---

# Step 9 — Evidence for the portfolio

In `../assets/`, spaceless `06-*` names:

- [ ] `06-firewall-profiles.png` — `wf.msc` on DC01 showing the three profiles and which is
      active, with inbound block / outbound allow visible
- [ ] `06-auditpol-before.png` — the three `auditpol /get` readings from Step 2.1, before
      any change
- [ ] `06-4946-rule-added.png` — the 4946 for `LAB Block Ping from WS01`, fields pulled by
      name, with the rule name visible
- [ ] `06-4948-rule-deleted.png` — the 4948 for the same rule, showing Profile Changed,
      Rule ID and Rule Name — **and no account field**. Finding 3's evidence
- [ ] `06-no-attribution.png` — `([xml]$d.ToXml()).Event.System.Security` returning empty,
      with the same check against the 4946 as the control. The proof that the absence is
      about this family of events, not one odd event
- [ ] `06-pfirewall-drop.png` — the `Select-String '9999'` result from the text file: the
      `DROP` lines, addresses and ports, and nothing else
- [ ] `06-5157-fields.png` — the same refusal as an event, showing application, source
      address, port and process. **The pair with the above is the module's evidence**
- [ ] `06-5157-ws01-empty.png` — the identical query returning nothing on WS01

Then, in your own words: who probed what, how you know, and what the text file could not
have told you.

---

# Findings

Written after the run, observation → inference → recommendation, kept strictly separate.
Timestamps in **UTC** — the event stores UTC and Event Viewer only converts for display.
These VMs display WAT (UTC+1), so screenshots read one hour ahead.

---

### Finding 1 — Repeated connection attempts to a closed port, refused at the destination (DC01)

**Observation.**
_(To be written from the run: host, log, event ID, exact UTC times, source address,
destination port, the application and account named in 5157, and the matching `DROP` lines
from the text file.)_

**Inference.**
_(Judgement, labelled as such. Confidence language. What cannot be determined from this
evidence — in particular, what the text file alone could not establish.)_

**Recommendation.**
_(Specific follow-up queries.)_

---

### Finding 2 — The refusal was recorded only on the refusing host

**Observation.**
_(To be written from Step 7: the identical query, its result on DC01 and its result on
WS01, and the evidence that the WS01 log was healthy and the window correct — so the
absence is about location, not about the query.)_

**Inference.**
_(Note that this is the same *shape* of argument as Module 03's Finding 2: a negative
result made trustworthy by a positive control run under identical conditions.)_

**Recommendation.**

---

### Finding 3 — Firewall rule changes are logged without attribution (DC01)

**Observation.** On **DC01**, on **2026-09-14**, a firewall rule named
`LAB Block Ping from WS01` was created through `wf.msc` and deleted a few minutes later.
Both actions were recorded in the Security log: a **4946** for the addition and a **4948**
for the deletion, with `MPSSVC Rule-Level Policy Change` auditing enabled for Success
(confirmed by `auditpol` readback; all three firewall subcategories read `No Auditing` on
both hosts before the run).

The 4948's fields are **Profile Changed**, **Rule ID** and **Rule Name**. `.Message` adds
nothing beyond those. `Event.System.Security` — the event-header slot that carries the SID
of the causing account on many event types — is **empty**. The same header check run
against the 4946 as a control is **also empty**.

Background volume on a host nobody attacked: **four** 4946 events and **seven** 4948 events
were present. Three of the four 4946s were written by Windows itself overnight, with no
administrator action; the hand-written rule was the **oldest** of the four.

**Inference.** _(To be written: what can and cannot be concluded. Note the scope — two
events of one family on one host, not a general claim about every Windows build. Note that
the volume figures make "a firewall rule changed" unusable as an alert on its own.)_

**Recommendation.** _(To be written: correlation against process-creation evidence —
**4688** on DC01, which has no Sysmon, versus Sysmon **Event 1** on WS01, which does. The
same move as Module 03's Finding 1, where Event 1 turned "a registry value changed" into
"this account ran this command".)_

---

# Reference

### Event IDs

| ID | Log | Meaning |
|---|---|---|
| **5157** | Security | The Filtering Platform **blocked** a connection. Needs `Filtering Platform Connection` / Failure |
| **5156** | Security | The Filtering Platform **allowed** a connection. Needs the same subcategory / Success — deliberately left **off** in this module because of the volume |
| **5152 / 5153** | Security | A packet was blocked / restricted. A **separate** subcategory from 5156/5157 |
| **4946** | Security | A rule was **added** to the firewall exception list. Fields: Profile Changed, Rule ID, Rule Name. **No account** — verified 2026-09-14 |
| **4947** | Security | A firewall rule was **modified** |
| **4948** | Security | A firewall rule was **deleted** — the one an attacker generates. Same three fields, **no account** — verified 2026-09-14 |

### Reading the firewall

| Want | Command | VM |
|---|---|---|
| Profiles and defaults | `Get-NetFirewallProfile \| Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction` | either |
| Text-log settings | `Get-NetFirewallProfile -Name Domain \| Select-Object LogBlocked, LogFileName` | either |
| The GUI | `Win+R` → `wf.msc` | either |
| The text log | `Get-Content 'C:/Windows/System32/LogFiles/Firewall/pfirewall.log' -Tail 20` | the refusing host |

### MITRE ATT&CK

Candidates — confirm the IDs against attack.mitre.org before putting them in the write-up.

| Technique | ID | Where it appears here |
|---|---|---|
| Network Service Discovery | T1046 | Step 4's closed-port probe |
| Impair Defenses: Disable or Modify System Firewall | T1562.004 | Step 3's rule addition (4946) — benign here, the technique when it isn't |
| Remote Services | T1021 | the inbound rules you read in Step 1 |

---

## Notes & gotchas

- **A rule on the wrong profile does nothing, silently.** A rule ticked for a profile that
  is not active is present, enabled, correct-looking, and inert. Check the active profile in
  `wf.msc` on **each machine separately** before debugging anything else — on 2026-09-13 WS01
  was on **Domain** and DC01 on **Public** at the same moment.
- **A domain controller sitting on the Public profile is odd and is recorded here as an
  observation, not explained.** DC01 read `Public` in `wf.msc` on 2026-09-13 with the domain
  otherwise healthy (WS01's secure channel `True`, logons working). **No cause established.**
  It does not affect this module, because only two things are profile-specific — `LogBlocked`
  and the rule in Step 3 — and both simply go on Public instead. Worth understanding before
  the Active Directory modules.
- **A domain-joined machine sitting on the Public profile usually means it cannot see a
  domain controller.** Confirmed on 2026-09-13: DC01 was powered off, so WS01 fell back to
  `Public` and `Test-ComputerSecureChannel` returned `False`; both cleared the moment DC01
  was booted, and the profile followed after a WS01 reboot. **Boot DC01 first, always** —
  and remember cached credentials will let you log in to WS01 regardless, so a successful
  login proves nothing about the domain.
- **The text file and the event log are separate switches.** `LogBlocked` governs only the
  text file; `auditpol` governs only the events. Turning on one and looking for the other
  is the most likely way to lose an hour here.
- **No 4946 for a rule you definitely created** almost certainly means
  `MPSSVC Rule-Level Policy Change` was switched on *after* you created it. Auditing is
  never retroactive — the same cause as Module 02's missing 4670 and Module 03's SACL
  timing. Create another rule and watch that one instead.
- **4946 and 4948 do not say who.** Verified on DC01, 2026-09-14: Profile Changed, Rule ID
  and Rule Name are the whole story, `.Message` adds nothing, and `Event.System.Security` is
  empty on both. Attribution needs correlation against process creation — **4688**, or
  Sysmon **Event 1** where it is installed (WS01 has it, DC01 does not).
- **Firewall rules change on their own.** DC01 held **four** 4946s and **seven** 4948s with
  nobody attacking it, and three of those 4946s appeared overnight unattended. So the
  detection is never "a rule changed" — it is *which rule*, correlated to *who*. Baseline the
  count before treating any number as a signal.
- **Do not assume the newest event is yours.** On 2026-09-14 the hand-written rule's 4946 was
  the **oldest** of four, because Windows added three more afterwards. `-MaxEvents 1` takes
  the newest and would have returned the wrong event with no error. Identify by **rule name**,
  not by position: `| Select-Object -Last 1` takes the oldest of a newest-first list.
- **Empty output is not an error.** Work the checklist in order: **wrong machine** (this
  module's Step 7 is that failure made deliberate) → window too narrow → events overwritten
  (`wevtutil gli Security`) → channel disabled → auditing actually off.
- **Never switch on 5156 (allowed connections) and walk away.** Every conversation with the
  domain controller becomes an event. Module 04 measured what that does to this lab: the
  Security log fills and the oldest events are destroyed. If you turn it on, turn it off in
  the same sitting.
- **Do not write a blanket outbound block on WS01 toward DC01.** WS01 must reach DC01
  constantly to authenticate; cutting that off leaves a machine that cannot log in,
  recoverable only by restoring `mod06-start`. Allow rules are safe, single-port block
  rules are safe, blanket outbound blocking toward the domain controller is not. Same shape
  as Module 03's warning about the Winlogon keys.
- **Ping being blocked is not a fault.** Windows blocks inbound ICMP by default, so
  `PingSucceeded: False` between two healthy machines is normal. Step 3 is what changes it.
