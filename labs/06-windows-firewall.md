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

**The answer this module actually produces, established by experiment on 2026-09-14:**

> A knock on a **closed** port is discarded by Windows **stealth mode** before any firewall
> rule is consulted. It is **not** written to `pfirewall.log`, and it is **not** an event
> **5157**. The only instrument that records it is event **5152**, and that subcategory is
> **off by default**.

That is the condition a port scan creates — mostly closed ports — so the instrument most
people reach for first is blind to the most common reconnaissance activity there is.

The second half of the answer: **none of these records names the attacker.** 5152 names the
program on the *receiving* side, and only when one is listening; it never names the program
or the account on the *sending* side, because neither exists on the machine doing the
logging. Firewall rule changes (4946 / 4948) name nobody at all.

In this module you will:

1. Read the firewall state on both machines before changing anything
2. Turn on recording — in the event log *and* the text file
3. Write one firewall rule of your own and then delete it, watching Windows record both —
   and discover that neither record says who did it
4. Knock on a closed door on DC01 from WS01
5. Find that neither `pfirewall.log` nor 5157 has it, with both demonstrably working
6. Switch on the packet-drop subcategory, find it as **5152**, and read `Filter Origin`
7. Run the controlled experiment that proves *why* — vary one thing at a time until the
   instruments start reporting

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
network it thinks it is on. This matters because it is very easy to write a rule or switch on
logging for a profile you are not actually using, and then wonder why nothing happened.

> **Do not assume both machines agree.** On 2026-09-14 WS01 was on **Domain** and DC01 on
> **Public** at the same moment, with the domain otherwise healthy. Read the active profile on
> each machine separately in Step 1 and use whatever it says.

---

### Sitting split

| Sitting | Steps | Ends with |
|---|---|---|
| 1 | 0 – 3 | Recording switched on, one rule written and deleted, nothing triggered yet |
| 2 | 4 – 6b | The knock made, found in 5152 and nowhere else, and the experiment run |
| 3 | 7 – 9 + Findings | The source-host check, baseline table, screenshots, write-up |

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

### 2.2b Switch on blocked **packets** as well — do not skip this

**Aim: watch the only instrument that sees a knock on a closed port.**

Switch 1 covers *connections*. Switch 2 covers *packets*, and they are not the same thing.
A packet is one message arriving. A connection is what exists after both machines have
agreed to talk. **A knock on a closed port never becomes a connection**, so it is never a
5156 or a 5157 — it is a 5152, governed by this separate switch.

On **DC01**:

```powershell
auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable
```

```powershell
auditpol /get /subcategory:"Filtering Platform Packet Drop"
```

Do the same on **WS01**.

> **This step did not exist in the first draft of this run sheet, and its absence cost most
> of a sitting on 2026-09-14.** The gate table above listed four switches; Steps 2.2–2.4
> enabled three. The break in Step 4 then produced nothing in either instrument being
> watched — both of which were working, and both of which were structurally incapable of
> seeing it. The module reproduced its own central lesson on its own author. Left in the
> record deliberately; see Finding 4.

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

**Aim: read a firewall log that is not an event log — and find that it holds nothing at all
about what you just did, while proving it is working.**

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

> **Read the header.** The fourth line says **`#Time Format: Local`**. This file stamps
> **local** time while the event log stores **UTC**. Correlating the two needs the offset
> applied in the opposite direction from the one you are used to — on these VMs the text
> file reads one hour *ahead* of the same event in the Security log.

### 5.2 Find your three attempts — and do not find them

```powershell
Get-Content 'C:/Windows/System32/LogFiles/Firewall/pfirewall.log' | Select-String '9999'
```

`Select-String` searches text — it is the closest thing here to `grep`, and it works
because this is a plain text file, not an event log. None of `Get-WinEvent`,
`-FilterHashtable` or XML field extraction applies to it.

> **Expect nothing.** Verified 2026-09-14: with `LogDroppedConnections` reading `Enable`
> on the active profile, and across **two** separate knock windows twenty minutes apart,
> `pfirewall.log` contained **no entry for port 9999**. The file was not broken — it held a
> real `DROP` line for an ICMP packet from `10.0.0.20` at 08:41:56 local. So the file works
> and is selectively blind to what you just generated.
>
> That absence is a finding, not a fault. Do **not** start changing settings. Step 6 shows
> what did record it, and Step 6b establishes why.

---

# Step 6 — Detect in the event log (DC01)

**Aim: find out which of the two event IDs actually recorded your knock, and prove the one
that did not is working before calling it blind.**

### 6.1 Look for the connection event first

On **DC01**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} -MaxEvents 10
```

**5157** means *the Filtering Platform blocked a connection*. The Filtering Platform is the
machinery underneath the firewall that makes the allow/block decision — the rules are the
policy, this is the engine that enforces it.

> **Expect events, none of them yours.** Verified 2026-09-14: this query returned results on
> DC01, and **none were the port 9999 knocks**. That combination is the whole point. The
> channel is alive, the host is right, the window is right — and your activity is not in it.
> A query that returns *something* is its own control: it excludes wrong-machine, wrong-log,
> rotation and channel-off in one stroke. Same argument structure as Module 03's Finding 2.

### 6.2 Count before you conclude

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} | Measure-Object
```

Module 03 cost a sitting to this exact trap: a small number returned under `-MaxEvents` was
read as "that is all there is", which was fiction. Get the count before treating any number
as a result.

### 6.3 Now look for the packet event

**Aim: find the instrument that actually saw it.**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152} -MaxEvents 10
```

**5152** means *the Filtering Platform blocked a packet*. Your knocks are here — provided
Step 2.2b was done. If Step 2.2b was skipped, this returns nothing and **that is the lesson**:
go back and switch it on, then knock again, and watch the same activity appear in a log that
was empty five minutes ago.

### 6.4 Read what 5152 carries

```powershell
$p = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152} -MaxEvents 1
```

```powershell
$p.Message
```

`.Message` renders every field with its label — easier here than the XML extraction, and it
is what Event Viewer's General tab shows.

**Verified output, DC01, 2026-09-14:**

```
Application Information:
        Process ID:            0
        Application Name:      -
Network Information:
        Direction:             Inbound
        Source Address:        10.0.0.20      Source Port: 49745
        Destination Address:   10.0.0.10      Destination Port: 9999
        Protocol:              6
Filter Information:
        Filter Origin:         Stealth
        Layer Name:            Transport
```

Three things to take from it.

**`Process ID: 0`, `Application Name: -`.** This field names the **local** process that owned
the socket. Nothing on DC01 was listening on 9999, so no local process was ever involved. The
program that sent this is on WS01, and DC01 cannot see inside WS01. **A blocked inbound packet
tells you what was targeted and from which address — never by what program or which user.**

**`Protocol: 6`** is TCP, by IANA number. The event does not spell it out.

**`Filter Origin: Stealth`** is the key to Step 6b. The drop was made by Windows **stealth
mode** — the built-in behaviour of silently discarding uninvited packets — and not by any
firewall rule.

**Screenshot this.** It is the module's central piece of evidence.

---

# Step 6b — The controlled experiment (DC01 + WS01)

**Aim: stop reasoning about why the instruments were blind and establish it, by changing one
thing at a time.**

This is the part of the module worth the most. Everything so far is an observation; this turns
it into a result. Two variables, changed separately.

### 6b.1 Variable one — add an explicit rule

**Question: were the drops missing from `pfirewall.log` because no *rule* made them?**

On **DC01**, in `wf.msc`: **Inbound Rules → New Rule → Custom → All programs → Protocol
type: TCP → Local port: Specific Ports `9999` → Scope: remote IP `10.0.0.20` → Block the
connection → Public only → Name `LAB Block TCP9999 from WS01`**.

Verify the rule rather than trusting the wizard:

```powershell
Get-NetFirewallRule -DisplayName 'LAB Block TCP9999 from WS01' | Select-Object DisplayName, Enabled, Direction, Action, Profile
```

```powershell
Get-NetFirewallRule -DisplayName 'LAB Block TCP9999 from WS01' | Get-NetFirewallPortFilter
```

Knock three more times from **WS01**, then re-check both instruments on DC01.

> **Verified result, 2026-09-14: nothing changed.** The rule read back `Enabled: True`,
> `Direction: Inbound`, `Action: Block`, `Profile: Public`, `Protocol: TCP`,
> `LocalPort: 9999` — correct in every respect. The fresh 5152 still said
> `Filter Origin: Stealth`, and `pfirewall.log` was still empty for 9999. A correct, enabled,
> matching block rule made **no difference**, which excludes "the rule did not match."

### 6b.2 Variable two — make something listen

**Question: is the deciding factor that nothing is listening on the port?**

On **DC01**:

```powershell
$listener = [System.Net.Sockets.TcpListener]9999; $listener.Start()
```

This is a new construct — reaching into .NET directly rather than using a cmdlet. It opens
port 9999 and holds it open under `powershell.exe`. Nothing answers meaningfully; the port
simply exists.

Knock once more from **WS01**, then on **DC01**:

```powershell
$p3 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152} -MaxEvents 1
```

```powershell
$p3.Message
```

```powershell
Get-Content 'C:/Windows/System32/LogFiles/Firewall/pfirewall.log' | Select-String '9999'
```

Then release the port:

```powershell
$listener.Stop()
```

> **Verified result, 2026-09-14: both instruments changed at once.** `Filter Origin` became
> **`Query User Default`** — no longer stealth — `Application Name` became **`powershell.exe`**,
> and `pfirewall.log` **populated** for port 9999 for the first time in the module.

### 6b.3 The matrix

| Something listening? | Explicit block rule? | `Filter Origin` | App named in 5152 | In `pfirewall.log`? |
|---|---|---|---|---|
| No | No | `Stealth` | `-` (PID 0) | **No** |
| No | **Yes** | `Stealth` | `-` (PID 0) | **No** |
| **Yes** | Yes | `Query User Default` | **`powershell.exe`** | **Yes** |

One variable changed per row. The conclusions follow directly:

1. **Stealth mode intercepts packets to closed ports before rules are consulted.** A correct
   matching rule changed nothing; opening the port changed everything.
2. **`pfirewall.log` records a drop only once the packet gets past stealth.** `LogBlocked` was
   `Enable` throughout, so this was never a logging-configuration problem.
3. **5152 names the program on the receiving side, and only when one exists.** It never names
   the sender.

**Not established:** why the third row reads `Query User Default` rather than naming the block
rule. The rule was present, enabled and matching, and something else still made the decision.
**No cause established** — the precedence between the query-user filter and an explicit rule
was not investigated. Recorded as an open question, not explained.

### 6b.4 Clean up

On **DC01**, in `wf.msc` → **Inbound Rules**, delete **`LAB Block TCP9999 from WS01`**. Confirm
the listener is stopped.

**Leave `Filtering Platform Packet Drop` switched on.** It is Failure-only, the lab is isolated,
and it is the one instrument shown here to catch this activity. A deliberate decision, not an
oversight — say so in the write-up.

---

**End of sitting 2.**

---

# Step 7 — Go and get the attribution from the source host (WS01)

**Aim: recover the one thing DC01 could never tell you — what made the attempt — and in doing
so meet the empty-result-because-wrong-machine case deliberately.**

Step 6 established that DC01's evidence names no sender. That information is not lost; it is
simply on the other machine. This step goes and gets it.

### 7.1 The same query, the wrong machine

Run the *identical* query from 6.3, this time on **WS01**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152} -MaxEvents 10
```

**Expect nothing related to port 9999.** WS01 *sent* the connection; DC01 *dropped* it.
WS01's outbound default is allow, so from WS01's point of view nothing was blocked at all.

Note the shape of that failure: the query is correct, the log is healthy, the window is
right, auditing is on — and it still returns nothing, because the event was never on this
machine. That is the fourth entry on the empty-output checklist, and here it stops being
theoretical.

> **State the result you actually get.** If WS01 *does* return something, that is a
> legitimate and more interesting finding — record it rather than forcing it to match this
> expectation.

### 7.2 Find what made the attempt

**Aim: name the program and account that DC01 could not.**

On **WS01**, the knock was `Test-NetConnection` running inside PowerShell. That is a process,
and process creation is something you have logged since Module 05:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-3)} | Measure-Object
```

Narrow to the window you wrote down in Step 4, then pull `NewProcessName`, `CommandLine` and
`SubjectUserName` by name — exactly the extraction built in Module 05.

**WS01 also has Sysmon** (installed in Module 03, still configured). Sysmon **Event 1** carries
the full command line, `User`, `IntegrityLevel` and `ParentImage` in one record — the same
move that turned Module 03's Finding 1 from "a value changed" into "this account ran this
command".

> **DC01 has no Sysmon.** Only WS01 does. So the attribution story is asymmetric across this
> lab, which is worth stating in the write-up: the host that saw the attack cannot name the
> actor, and the host that can name the actor did not see the attack.

### 7.3 Write the join

The deliverable of this step is one sentence that no single log could produce:

> At *(UTC time)*, `powershell.exe` running as *(account)* on WS01 attempted a TCP connection
> to `10.0.0.10:9999`; DC01's Filtering Platform dropped the packet under stealth mode,
> recording it as 5152 with no sending process identified.

Two hosts, two logs, one event. That join is the actual skill this module teaches.

**End of sitting 3's first half.**

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
- [ ] `06-pfirewall-empty.png` — `Select-String '9999'` returning **nothing** from the text
      file, with the file's two unrelated `DROP` lines visible below it proving the file works
- [ ] `06-5152-stealth.png` — the 5152 for a knock, showing `Application Name: -`,
      `Process ID: 0` and **`Filter Origin: Stealth`**. **The module's central evidence**
- [ ] `06-rule-verified.png` — the block rule read back (`Enabled/Direction/Action/Profile`)
      alongside `Get-NetFirewallPortFilter` (`TCP`, `LocalPort 9999`) — the proof that row 2
      of the matrix had a correct rule
- [ ] `06-5152-listening.png` — the 5152 after the listener was started, showing
      `Filter Origin: Query User Default` and `Application Name: powershell.exe`, plus the
      now-populated text file. **The pair with `06-5152-stealth.png` is Finding 4**
- [ ] `06-5157-ws01-empty.png` — the identical query returning nothing on WS01

Then, in your own words: who probed what, how you know, and what the text file could not
have told you.

---

# Findings

Written after the run, observation → inference → recommendation, kept strictly separate.
Timestamps in **UTC** — the event stores UTC and Event Viewer only converts for display.
These VMs display WAT (UTC+1), so screenshots read one hour ahead.

---

### Finding 1 — A knock on a closed port is invisible to two of the three firewall instruments (DC01)

**Observation.** On **DC01**, on **2026-09-14**, three TCP connection attempts were made from
WS01 (`10.0.0.20`) to port **9999**, a port with no listening service and no rule permitting
it, inside the window **09:02:45 – 09:03:48 UTC**. Each attempt timed out slowly rather than
being refused immediately. The attempts were repeated a second time after configuration
changes, with the same outcome.

Three instruments were live on DC01 at the time:

| Instrument | Configuration verified | Result |
|---|---|---|
| `pfirewall.log` | `LogDroppedConnections: Enable` on the active (Public) profile; `Firewall Policy: BlockInbound,AllowOutbound` | **No entry for port 9999**, across two windows twenty minutes apart |
| **5157** (connection blocked) | `Filtering Platform Connection` = `Failure` (`auditpol` readback) | **Returned events, none of them the knocks** |
| **5152** (packet blocked) | initially `No Auditing`; enabled mid-run | **Recorded all knocks** once enabled |

Both negative instruments were demonstrably functional: `pfirewall.log` held a real `DROP`
line for an ICMP packet from `10.0.0.20` at **08:41:56 local**, and the 5157 query returned
events under the identical command that failed to return the knocks.

The 5152 recorded `Process ID: 0`, `Application Name: -`, `Direction: Inbound`,
`Source Address: 10.0.0.20`, `Destination Port: 9999`, `Protocol: 6`, and
**`Filter Origin: Stealth`**.

**Inference.** _(To be written. Points to cover: the two negatives are coverage failures, not
configuration failures, and the positive 5157 result is the control that establishes this —
the same argument structure as Module 03's Finding 2. A port scan consists overwhelmingly of
attempts against closed ports, so this is the condition under which reconnaissance occurs.
State what cannot be determined: the sending program and account are not recoverable from
DC01's evidence at all.)_

**Recommendation.** _(To be written. `Filtering Platform Packet Drop` must be enabled for
scan detection; `pfirewall.log` alone is insufficient; attribution requires the source host.)_

---

### Finding 4 — Stealth mode, not rule configuration, is what makes the drop invisible (DC01)

**Observation.** A controlled experiment on **2026-09-14** varied two factors independently
against the same port, same source and same knock.

| Something listening? | Explicit block rule? | `Filter Origin` | App named in 5152 | In `pfirewall.log`? |
|---|---|---|---|---|
| No | No | `Stealth` | `-` (PID 0) | No |
| No | **Yes** | `Stealth` | `-` (PID 0) | No |
| **Yes** | Yes | `Query User Default` | **`powershell.exe`** | **Yes** |

Row 2's rule was verified by readback, not assumed: `Enabled: True`, `Direction: Inbound`,
`Action: Block`, `Profile: Public`, `Protocol: TCP`, `LocalPort: 9999`. Row 3's listener was
a `System.Net.Sockets.TcpListener` on port 9999 held open by `powershell.exe`.

**Inference.** _(To be written. Supported: stealth mode intercepts packets to closed ports
before rules are consulted; `pfirewall.log` records a drop only after that point; 5152 names
the local process only where one exists. Not supported and to be stated as such: why row 3
reads `Query User Default` rather than naming the block rule — the precedence between the
query-user filter and an explicit rule was **not** investigated and **no cause is
established**.)_

**Recommendation.**

---

### Finding 5 — The author's own run sheet reproduced the module's central failure

**Observation.** The gate table in Step 2 listed **four** independent switches. Steps 2.2–2.4
as originally written enabled **three**, omitting `Filtering Platform Packet Drop`. The break
in Step 4 was designed against a **closed** port — precisely the condition that routes the
packet to stealth mode and away from both instruments the run sheet told the reader to watch.
The omission was found only after both instruments returned nothing and were separately proved
functional. Step 2.2b was added afterwards.

**Inference.** _(To be written. This is the fourth consecutive module in which a silent gate
produced empty output with no error — Module 02's `Handle Manipulation` and `WRITE_DAC`,
Module 03's per-key SACL, and now this. Worth stating plainly that knowing the failure mode in
advance was not sufficient to avoid it.)_

**Recommendation.** _(To be written. Enumerate every gate and verify each by readback before
the Break step, rather than enabling the ones the planned detection needs.)_

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
| **5152** | Security | A **packet** was blocked. Needs `Filtering Platform Packet Drop` / Failure — **off by default**, and the **only** instrument that sees a knock on a closed port. Carries the *local* application only, so it is blank for a port with no listener |
| **5153** | Security | A packet was **restricted** by a more-restrictive filter. Same subcategory as 5152 |
| **5157** | Security | The Filtering Platform blocked a **connection**. Needs `Filtering Platform Connection` / Failure. **Never fires for a closed port** — no connection is ever formed. Verified 2026-09-14 |
| **5156** | Security | The Filtering Platform **allowed** a connection. Same subcategory / Success — deliberately left **off** in this module because of the volume |
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
- **A knock on a closed port is a *packet*, never a *connection*.** It is a **5152**, not a
  5157, and 5152's subcategory is off by default. Watching only 5157 gives silence with no
  error. Verified 2026-09-14 — cost most of a sitting, including to the person who wrote this
  file.
- **`pfirewall.log` does not record stealth-mode drops**, no matter what `LogBlocked` says or
  what rules exist. Verified by experiment: an explicit, enabled, matching block rule changed
  nothing; making a program listen on the port changed both the filter origin and the text
  file at once. So the firewall's own log file is blind to port scanning against closed ports.
- **`pfirewall.log` stamps LOCAL time; the event log stores UTC.** The header says so —
  `#Time Format: Local`. Correlating the two needs the offset applied in the opposite
  direction from the usual one.
- **`Application Name` in 5152 is the *local* process, not the sender.** It reads `-` with
  `Process ID: 0` whenever nothing was listening, which is exactly the interesting case.
  DC01 can never name what on WS01 made the attempt; that evidence only exists on WS01.
- **`Protocol: 6` means TCP** (IANA number). 1 is ICMP, 17 is UDP. The event does not spell
  them out.
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
