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

The second half of the answer, established on 2026-09-15 and **the opposite of what this run
sheet originally predicted**:

> **Nothing names the attacker — not even the attacking machine.** 5152 names the program on
> the *receiving* side, and only when one is listening. Going to the *source* host does not
> rescue it: `Test-NetConnection` creates no process, so there is no **4688**; and Sysmon
> **Event 3** records connections that **complete**, so three unanswered knocks produced
> nothing while one successful connection produced a full record. Firewall rule changes
> (4946 / 4948) name nobody at all.

So the instruments get informative exactly when the probe **succeeds** — which is the wrong way
round for catching someone who has not got in yet. See Finding 2.

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
8. Go to the sending machine to recover the attacker's identity — arming Sysmon for it first —
   and establish by a second controlled experiment that it is not recoverable there either

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

# Step 7 — Go looking for the attribution on the source host (WS01)

**Aim: recover the one thing DC01 could never tell you — what made the attempt — and find
out that on a closed port, no instrument in this lab can.**

Step 6 established that DC01's evidence names no sender. The obvious assumption is that the
information is not lost, merely on the other machine, and this step goes to get it.

> **That assumption is wrong, and the run proved it on 2026-09-15.** Three instruments on
> WS01 — packet-drop auditing, process-creation auditing and Sysmon — were each verified
> alive and each recorded **nothing** about the knock. The step is kept in this order
> because working through all three is what makes the conclusion trustworthy; see Finding 2.

### 7.0 Arm Sysmon *before* you knock (WS01)

**Aim: give WS01 an instrument that records outbound network activity with the process and
the account attached — and get it running before the activity, because nothing here is
retroactive.**

Sysmon's **Event 3** is "a network connection was made", recorded from the *sender's* side
with `Image`, `User`, `ProcessGuid` and the destination attached. That is exactly the field
set DC01 cannot supply.

The catch is volume. WS01 talks to DC01 constantly — DNS, Kerberos, LDAP, every few seconds
— so a broad network rule buries the log, which is the failure Module 04 measured. Scope it
as tightly as a rule can be scoped: **destination port 9999 and nothing else.**

Read the config before changing it:

```powershell
Get-Content 'C:/Tools/sysmon-registry.xml'
```

Then ask Sysmon what it is *actually running*, which is not necessarily what is in that file:

```powershell
Sysmon64.exe -c
```

> **Same switch, two behaviours.** With no filename, `-c` **prints** the live config. With a
> filename, it **applies** one. Verified in Module 03 and used both ways here.

Open the file — `notepad 'C:/Tools/sysmon-registry.xml'` — and add this immediately above the
closing `</EventFiltering>` line, leaving the `RegistryEvent` group untouched:

```xml
  <NetworkConnect onmatch="include">
    <DestinationPort condition="is">9999</DestinationPort>
  </NetworkConnect>
```

Three lines, three ideas. **`NetworkConnect`** is the rule group for Event 3, as
`RegistryEvent` is for Events 12 and 13 — one group per event type. **`onmatch="include"`**
means *log only what matches below*; an empty include group logs nothing at all.
**`condition="is"`** is an exact match — `contains`, which the registry rules use, would be
wrong here because it would also catch ports 19999 and 99990.

> **Verified 2026-09-15:** a `NetworkConnect` element placed directly under `<EventFiltering>`,
> as a sibling of the existing `<RuleGroup>`, is accepted and works. It does not have to live
> inside a rule group.

Apply it. Move to the folder first, so no path separators are needed at all:

```powershell
Set-Location 'C:/Tools'
```

```powershell
Sysmon64.exe -c sysmon-registry.xml
```

You want `Configuration updated`. Then read back what is now running:

```powershell
Sysmon64.exe -c
```

The `NetworkConnect` rule must appear alongside the four registry rules. **The knock is
worthless without this readback** — "the file says so" and "Sysmon is evaluating it" are two
different claims.

### 7.1 The same query, the wrong machine

**Aim: meet the empty-result-because-wrong-machine case deliberately — and learn to prove an
instrument is alive *before* believing a silence from it.**

Run the *identical* query from 6.3, this time on **WS01**. But prove the channel first:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152} | Measure-Object
```

> **Verified 2026-09-15: 1040 events.** WS01 drops inbound packets constantly with nobody
> attacking it — the network-layer twin of "firewall rules change on their own". A single
> 5152 is background, not a signal.

Only now is a silence worth anything:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152} -MaxEvents 20 | Where-Object { $_.Message -like '*9999*' }
```

> **That `-like` searches the whole event text, not the destination-port field** — Module 03's
> trap, where hunting `*Notepad.exe*` returned `reg.exe`. It is deliberately a wide net here:
> if a loose search finds nothing, a precise one certainly will not.

**Verified 2026-09-15: nothing for 9999**, against 1040 events proving the instrument records.
WS01 *sent* the connection and its outbound default is allow, so nothing was blocked and
nothing was logged. The refusal happened a metre away, on another machine.

That is the fourth entry on the empty-output checklist, and here it stops being theoretical.

> **The first attempt at this step, on 2026-09-15, was worthless.** It was written as "run the
> query and expect nothing" — but WS01's packet-drop subcategory was still `No Auditing`, so
> the empty result could not have come out any other way. **An expectation that cannot fail is
> not evidence.** The step only became real once the switch was on and the channel had proved
> itself. See Finding 5.

### 7.2 Try process creation — and find it structurally blind

**Aim: eliminate the instrument you would normally reach for, so that whatever comes next is
clearly not something 4688 could have given you.**

On **WS01**, the knock was `Test-NetConnection`. Process creation has been logged since
Module 05, so start by proving it is recording:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddMinutes(-20)} | Measure-Object
```

> **Verified 2026-09-15: 330 events in 20 minutes.** An earlier window on 2026-09-15 measured
> **308** in 20 minutes. Two independent measurements that close suggest a real rate rather
> than boot noise, but **neither window was controlled for a reboot**, so this is recorded as
> an open question, not a measurement. If the rate is real, WS01's 20 MB Security log fills in
> roughly a day — against Module 04's measured ~0.26 MB/day in August.

Now look for the knock:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddMinutes(-20)} | Where-Object { $_.Message -like '*Test-NetConnection*' }
```

**Verified 2026-09-15: nothing.** `Test-NetConnection` is a cmdlet running *inside* a
PowerShell session that was already open. No process is created, so there is no 4688.

> **The general lesson, and it is bigger than this module: process-creation logging records a
> program starting, not what it does for the next hour.** A shell opened once and used all
> afternoon writes exactly one 4688 and then does a hundred invisible things. Cmdlet activity
> inside an existing session is not visible to 4688 at all — that is what Module 05's script
> block logging (4104) is for.

### 7.3 Try Sysmon Event 3 — and find it blind too

**Aim: test the instrument armed in 7.0, which was built for exactly this.**

On **WS01**, count first — never `-MaxEvents`, which is how Module 03 invented a missing
population:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} | Measure-Object
```

> **Verified 2026-09-15: zero.** Three knocks, a rule scoped to exactly this port, applied and
> read back before the knocks — and no Event 3.

Before theorising, rule out the dullest explanation — that Sysmon has simply stopped:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=(Get-Date).AddMinutes(-30)} | Group-Object Id | Select-Object Count, Name
```

`Group-Object Id` buckets events by ID and counts each — one command that says what Sysmon
has been recording, rather than what you hoped it recorded.

> **Verified 2026-09-15: 373 Event 1s in 30 minutes, no Event 3.** Service alive, channel
> alive, registry rules intact. So the question is genuinely about the network rule.

Two explanations survive, and they are **not** distinguishable from this evidence:

1. `NetworkConnect` records connections that **complete**, and an unanswered SYN never becomes
   one — structurally the same reason 5157 does not fire for a closed port.
2. The rule is not being **evaluated** — "appears in the readback" is not "is being applied".

**Do not pick one.** Step 7.4 changes one variable and lets the result decide.

### 7.4 The discriminating test — make the far end answer

**Aim: change exactly one thing, so the outcome names the cause instead of the analyst naming
it.**

This is Step 6b's variable-two move again, and it mirrors it: back then, making something
listen flipped both *firewall* instruments. Now find out whether it flips Sysmon.

A listener alone is not enough — DC01's inbound default is block, so the connection would
still never complete. It needs an allow rule as well.

On **DC01**, open the port:

```powershell
$listener = [System.Net.Sockets.TcpListener]9999; $listener.Start()
```

**Leave that window open.** The listener lives inside the session and dies with it.

Then let the traffic through:

```powershell
New-NetFirewallRule -DisplayName 'LAB Allow TCP9999 from WS01' -Direction Inbound -Protocol TCP -LocalPort 9999 -RemoteAddress 10.0.0.20 -Action Allow -Profile Any
```

`-Profile Any` sidesteps the profile trap entirely. Read the rule back rather than trusting
the cmdlet's own output:

```powershell
Get-NetFirewallRule -DisplayName 'LAB Allow TCP9999 from WS01' | Select-Object DisplayName, Enabled, Direction, Action, Profile
```

Knock once from **WS01**:

```powershell
Test-NetConnection -ComputerName 10.0.0.10 -Port 9999
```

**This one must return `TcpTestSucceeded: True`.** If it does not, the test has not run and
there is no point looking at Sysmon. Then, on **WS01**, the identical count from 7.3:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} | Measure-Object
```

> **Verified 2026-09-15: one.** Same rule, same port, same source, same destination — the only
> variable that moved was whether DC01 answered. **0 across three unanswered attempts, 1 for
> one completed attempt.** Explanation 1 holds; the rule was fine all along.

### 7.5 Read what Event 3 does carry

**Aim: establish what attribution looks like when it *is* available, so the gap is measured
against something concrete rather than asserted.**

On **WS01**:

```powershell
$n = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -MaxEvents 1
```

```powershell
([xml]$n.ToXml()).Event.EventData.Data | Format-Table Name, '#text'
```

**Verified output, WS01, 2026-09-15:**

| Field | Value |
|---|---|
| `UtcTime` | `2026-09-15 23:09:13.841` |
| `Image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `User` | **`CORP\Administrator`** |
| `ProcessId` / `ProcessGuid` | `8960` / `{106e60df-cae4-6aa9-ec00-000000004000}` |
| `Protocol` / `Initiated` | `tcp` / `true` (outbound from this host) |
| `SourceIp` / `SourceHostname` / `SourcePort` | `10.0.0.20` / `WS01.corp.local` / `49758` |
| `DestinationIp` / `DestinationHostname` / `DestinationPort` | `10.0.0.10` / `DC01` / `9999` |
| `RuleName` | `-` |

Two things beyond the obvious. **Sysmon resolves hostnames** — DC01's 5152 gave bare IPs,
this names both machines. And **`ProcessGuid` is the join key back to Event 1**, which carries
the command line that started that shell. That is the same move as Module 03's Finding 1.

**Screenshot this** — it is `06-sysmon-attribution.png`.

### 7.6 Write the join — and write what it cannot cover

The deliverable is two sentences, and the second one is the module's actual result:

> At **23:09:13.841 UTC on 2026-09-15**, `powershell.exe` running as `CORP\Administrator` on
> `WS01.corp.local` opened a TCP connection to `DC01` on port 9999, recorded as Sysmon Event 3
> on WS01 and as a permitted connection on DC01.
>
> The three attempts nineteen minutes earlier — **22:49:36, 22:49:59 and 22:50:00 UTC**, to the
> same port on the same host from the same shell — appear **only** as three 5152 packet drops
> on DC01, with `Process ID: 0` and `Application Name: -`. **No instrument on either machine
> names the sender of those three.**

Two hosts, four logs, one answer and one hole. Naming the hole precisely is the skill.

### 7.7 Clean up — and confirm it

On **DC01**:

```powershell
Remove-NetFirewallRule -DisplayName 'LAB Allow TCP9999 from WS01'
```

```powershell
Get-NetFirewallRule -DisplayName 'LAB Allow TCP9999 from WS01'
```

A red "no matching objects found" error is the correct answer. Then, **in the window holding
the listener**:

```powershell
$listener.Stop()
```

```powershell
Get-NetTCPConnection -LocalPort 9999
```

> **Do not skip the two readbacks.** On 2026-09-15 a block rule was deleted "and confirmed"
> without either, and was found still live at the start of the next sitting — which meant the
> baseline for the next run was wrong until it was checked. A `Remove-` command that ran is
> not a rule that is gone.

**Leave the Sysmon `NetworkConnect` rule in place.** It is scoped to port 9999 only, so it
cannot flood anything, and Module 07 extends the same group to RDP rather than rebuilding it.

**End of sitting 3's first half.**

---

# Step 8 — Deliverable: the firewall baseline

**Aim: produce the thing a real job asks for — a written statement of what these machines
allow, so that a future change can be recognised as a change.**

Fill this in from Step 1 and Step 2, one row per machine. **Cells marked `(unread)` are not
guesses to be filled from memory** — run the command and paste the answer, or leave the gap
visible.

**State as at 2026-09-25.** Every cell below is either a readback pasted during the run or a
value visible in a filed screenshot; the provenance column says which. Cells marked **†** were
read on **2026-09-25**, in the sitting that closed this module out; the rest date from
2026-09-16 or earlier and say so where it matters.

| | WS01 | DC01 | Source |
|---|---|---|---|
| Active profile | **Domain** (`DomainAuthenticated`) **†** | **Public** **†** | `Get-NetConnectionProfile`, both hosts |
| Firewall enabled | **On, all three profiles** **†** | **On, all three profiles** **†** | `Get-NetFirewallProfile`, both hosts |
| Default inbound | **Block** **†** | **Block** **†** | `Get-NetFirewallProfile -PolicyStore ActiveStore` |
| Default outbound | **Allow** **†** | **Allow** **†** | `Get-NetFirewallProfile -PolicyStore ActiveStore` |
| `Filtering Platform Connection` | **Failure** | **Failure** (sitting 2; **still not re-read**) | `auditpol` readback |
| `Filtering Platform Packet Drop` | **Failure** | **Failure** | `auditpol` readback, both hosts |
| `MPSSVC Rule-Level Policy Change` | **Success** (2026-09-15; not re-read since) | **Success** **†** | `auditpol` readback |
| `LogBlocked` on active profile | **True** — on `Domain` only **†** | **True** — on `Public` only **†** | `Get-NetFirewallProfile -PolicyStore ActiveStore` |
| Text log path | `%systemroot%\system32\LogFiles\Firewall\pfirewall.log` **†** | `%systemroot%\system32\LogFiles\Firewall\pfirewall.log` **†** | `Select-Object -ExpandProperty LogFileName` |
| Lab rules remaining | **none** | **none** — both lab rules deleted and confirmed by readback | `Get-NetFirewallRule` erroring |
| Sysmon | v15.15, registry rules **+ `NetworkConnect` port 9999** | **not installed** | `Sysmon64.exe -c` readback |

**Three things the 2026-09-25 readbacks established that were previously unknown:**

1. **`LogBlocked` survived the 2026-09-16 reboot** on both machines. It was set on 2026-09-15
   and never re-read, so this was an open unknown rather than a formality. Each host has it on
   **only** its own active profile — `Domain` for WS01, `Public` for DC01 — which is why the
   two machines' `True` sits in a different row of their own profile lists.
2. **DC01 is still on `Public`** — a third sighting, this time via `Get-NetConnectionProfile`
   rather than the GUI or a screenshot. A different instrument returning the same answer rules
   out a reading artifact. **Still no cause established.**
3. **Both machines store the text-log path with an unexpanded `%systemroot%`.** It is a literal
   template, not a resolved path — see the gotcha below.

**Pre-run baseline, for comparison** (2026-09-13 13:08, `06-auditpol-before.png`): all three
subcategories `No Auditing`, `LogAllowedConnections` and `LogDroppedConnections` both
`Disable`, `Firewall Policy: BlockInbound,AllowOutbound`, `FileName
%systemroot%\system32\LogFiles\Firewall\pfirewall.log`, `MaxFileSize 4096`,
`InboundUserNotification Enable`, `RemoteManagement Disable`. Everything in the table above
that is not a default is a change this module made.

> **Which host that screenshot is from is not recorded in the frame** — the prompt reads
> `PS C:\Users\Administrator>` on both machines. The taskbar is centred, which is Windows 11
> and therefore WS01, but that is an inference from a UI detail and it is **not** treated as
> established here. Confirm it before citing those values as either machine's baseline. The
> lesson generalises: **a terminal screenshot that does not contain the hostname is weak
> evidence**, and `hostname` costs one line at the top of the capture.

Then two or three sentences in your own words: what each machine currently accepts, what
you changed, and how someone would notice if it changed again.

> **The asymmetry is the part worth writing down.** DC01 — the machine that gets attacked in
> every scenario this lab will run — has no Sysmon and sits on the **Public** profile for
> reasons never established. WS01, which nobody is attacking, carries the better instrument.
> See Finding 3's recommendation.

---

# Step 9 — Evidence for the portfolio

In `../assets/`, spaceless `06-*` names:

- [x] `06-firewall-profiles.png` — **captured 2026-09-16, 01:03 local.** `wf.msc` on DC01:
      all three profiles with **Windows Defender Firewall is on**, inbound blocked, outbound
      allowed, and **`Public Profile is Active`** — the profile anomaly still present after the
      unplanned shutdown and reboot
- [x] `06-auditpol-before.png` — **captured 2026-09-13, 14:08 local**, during sitting 1. All
      three subcategories reading **`No Auditing`** before any change, above a firewall profile
      block showing `LogAllowedConnections: Disable`, `LogDroppedConnections: Disable`,
      `FileName %systemroot%\system32\LogFiles\Firewall\pfirewall.log`, `MaxFileSize 4096`,
      `Firewall Policy BlockInbound,AllowOutbound`. The genuine "before" state, and
      unrepeatable once the switches were thrown
- [x] `06-4946-rule-added.png` — **captured 2026-09-14, 08:55 local.** The 4946 for
      `Lab Block Ping from ws01` — `ProfileChanged (null)`, `RuleId {13BD1F31-…}` — reached via
      `| Select-Object -Last 1`. The same frame shows **all four 4946s**: three at
      `9/14 08:28:15` and the hand-written one at `9/13 14:39:31`, which is the evidence that
      the analyst's own event was the **oldest**
- [x] `06-4946-allow-rule-added.png` — **captured 2026-09-16, 00:28 local.** The 4946 for
      `Lab Allow TCP9999 from WS01` created during the Step 7.4 experiment —
      `ProfileChanged: All` (from `-Profile Any`), contrasting with the `(null)` above
- [x] `06-4948-rule-deleted.png` — **captured 2026-09-15, 23:01 local.** The 4948 at
      `22:57:30 local` for the deletion of `lab Block tcp9999 from ws01`, showing Profile
      Changed, Rule ID and Rule Name — **and no account field**
- [x] `06-4948-extended.png` — **captured 2026-09-15, 23:04 local.** The stronger single
      exhibit: the same 4948's **fields and header in one frame** — `EventRecordID 37499`,
      `Channel Security`, `Computer DC01.corp.local`, and **`Security :`** blank
- [x] `06-no-attribution.png` — **captured 2026-09-15, 23:10 local.**
      `([xml]$d.ToXml()).Event.System` for the 4948 and for a 4946 as control, both with every
      header field populated and `Security` **empty**. The proof that the absence is about this
      family of events, not one odd event. The frame also preserves a mistyped `Id=49466`
      returning `NoMatchingEventsFound` — see the gotcha on that below
- [x] `06-5152-stealth.png` — **captured**. One frame carries both halves: the 5152 for a knock
      (`Process ID: 0`, `Application Name: -`, `Source Address 10.0.0.20`,
      `Destination Port 9999`, `Protocol: 6`, **`Filter Origin: Stealth`**,
      `Filter Run-Time ID 68581`, `Layer Name Transport`) **and**, directly below it,
      `Select-String '9999'` returning **nothing** from `pfirewall.log` while a full
      `Get-Content` of the same file shows its header and two unrelated `DROP` lines
      (`08:41:56 DROP ICMP 10.0.0.20 → 10.0.0.10` and `08:43:53 DROP UDP 127.0.0.1`).
      **The module's central evidence** — the blind instrument and the proof it was working,
      in one screenshot. Supersedes the separate `06-pfirewall-empty.png`
- [x] `06-rule-verified.png` — **captured**. The block rule read back —
      `Enabled: True`, `Direction: Inbound`, `Action: Block`, `Profile: Public` — alongside
      `Get-NetFirewallPortFilter` (`Protocol: TCP`, `LocalPort: 9999`, `RemotePort: Any`), the
      proof that row 2 of the matrix had a correct rule. The same frame timestamps the knock:
      `$ps.TimeCreated` = **10:23:21 local / 09:23:21 UTC, 2026-09-14**
- [ ] `06-5152-listening.png` — the 5152 after the listener was started, showing
      `Filter Origin: Query User Default` and `Application Name: powershell.exe`, plus the
      now-populated text file. **The pair with `06-5152-stealth.png` is Finding 4**
- [x] `06-sysmon-attribution.png` — **captured 2026-09-16.** Sysmon **Event 3** fields pulled
      by name for the connection that **completed**: `UtcTime 2026-09-15 23:09:13.841`,
      `Image …\powershell.exe`, **`User CORP\Administrator`**, `SourceHostname WS01.corp.local`,
      `DestinationHostname DC01`, `DestinationPort 9999`, `Initiated true`, `ProcessGuid`.
      **Finding 2's positive half** — what attribution looks like when it is available at all
- [ ] `06-sysmon3-zero.png` — the same Event 3 count returning **0** for the three unanswered
      knocks, beside the `Group-Object Id` output showing **373 Event 1s** in the same window.
      **Finding 2's negative half, and it needs its control in the same frame** — the count
      alone proves nothing without the evidence that Sysmon was recording
- [ ] `06-5152-ws01-empty.png` — on WS01, the count of **1040** 5152 events beside the
      `9999` filter returning nothing. The instrument demonstrably alive and demonstrably
      silent about the knock, in one frame. (Replaces the planned `06-5157-ws01-empty.png`;
      5152 is the channel that matters and the one that was actually enabled there)

Then, in your own words: who probed what, how you know, and — the harder half — **what none of
the four instruments could have told you**, which is the module's actual result.

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

**Inference.** I assess with **high confidence** that both negative results are **coverage
failures, not configuration failures** — the instruments were working and are structurally
incapable of seeing this activity.

The evidence for that distinction is the positive control inside each negative. The 5157 query
that failed to return the knocks **returned other events** under the identical command, which
excludes wrong host, wrong log, wrong window, log rotation and channel-off in one stroke. The
`pfirewall.log` that held no 9999 entry **did** hold a real `DROP` line for an ICMP packet from
the same source address, which excludes "the file is not being written". This is the same
argument structure as Module 03's Finding 2, where the query that missed two registry writes
returned the third.

The mechanism for each differs and both matter:

- **5157 is connection-oriented.** A knock on a closed port never becomes a connection, so
  there is never a 5157 to write. `Filtering Platform Connection` and
  `Filtering Platform Packet Drop` are separate subcategories governing separate event
  families, and watching only the first produces silence with no error.
- **`pfirewall.log` never sees the packet at all**, because stealth mode discards it before
  the rule engine — established by the controlled experiment in Finding 4, not inferred here.

The operational consequence: **a port scan consists overwhelmingly of attempts against closed
ports**, which is precisely the condition that routes the traffic away from both instruments an
analyst reaches for first. A host firewall's own log file is therefore blind to the most common
form of network reconnaissance there is (**T1046**).

**What cannot be determined from DC01's evidence:** the sending program and the sending account,
at all. `Process ID: 0` / `Application Name: -` is not a gap in the record — it is the correct
value, because the field names the *local* process owning the socket and no local socket exists.
Finding 2 establishes that this information is not recoverable from the sending host either.

**Recommendation.**

1. **Enable `Filtering Platform Packet Drop` (Failure) on any host where probing should be
   detected.** It is off by default on both hosts in this lab; the module's central evidence
   would not exist without it. Leave `Filtering Platform Connection` **Success** off — it logs
   every permitted connection and destroys log retention, per Module 04.
2. **Do not treat `pfirewall.log` as the scan instrument.** Its correct use is auditing
   rule-based decisions. Where the text file and the event log disagree, the event log is the
   more complete record — and note the two stamp time differently (`#Time Format: Local`
   versus UTC in the event).
3. **Query on the shape, not the event:** source address grouped against distinct destination
   ports per short window. A single 5152 is background noise on both hosts here.
4. **Write the attribution gap into the report explicitly.** "Source `10.0.0.20`, process and
   account not determinable from available telemetry" is the accurate sentence, and it is more
   useful to a reader than silence about it.

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

**Inference.** Three claims are supported by the matrix, and I assess each with **high
confidence** because each rests on a single changed variable rather than on argument:

1. **Stealth mode intercepts packets to closed ports before firewall rules are consulted.**
   Row 2 is the load-bearing row: a rule that was present, enabled, correctly scoped and
   verified by readback changed **nothing** — same `Filter Origin: Stealth`, same empty text
   file. That excludes "the rule did not match", which is the explanation an analyst would
   otherwise reach for and spend an afternoon on.
2. **`pfirewall.log` records a drop only once a packet gets past stealth.** `LogBlocked` read
   `Enable` throughout all three rows, so the text file's behaviour was never a logging
   configuration problem. Row 3 flipped it by changing the port's state, not by changing any
   logging setting.
3. **5152 names the program on the receiving side, and only where one exists.** The field went
   from `-` / PID 0 to `powershell.exe` at the moment a process owned the socket. It has never
   named, and cannot name, the sender.

Taken together with Finding 2, the two halves of the module meet: the receiving host's
visibility improves exactly when the probe **succeeds**, and so does the sending host's. Both
instruments are informative about connections that work and quiet about reconnaissance that
does not — which is the wrong way round for detecting an attacker who has not got in yet.

**Not established, and stated as such:** why row 3 reads **`Query User Default`** rather than
naming the block rule. The rule was present, enabled and matching, and something else made the
decision. The precedence between the query-user filter and an explicit block rule was **not
investigated** and **no cause is established**. Nothing in this finding depends on it — rows 1
and 2 carry the conclusion on their own — but it should not be glossed as though it were
understood.

Also not tested: whether stealth-mode behaviour is configurable on this build, and what the
matrix would look like with it off. That is the obvious next experiment and it was not run.

**Recommendation.**

1. **Do not debug a "missing" firewall log entry by editing rules.** This matrix is the
   counter-example: a correct rule changed nothing. Establish first whether the packet reached
   the rule engine at all — `Filter Origin` in the 5152 is the field that says so.
   `Stealth` means no rule was consulted.
2. **Read `Filter Origin` on every packet-drop event you triage.** It distinguishes "the
   firewall decided" from "Windows discarded it before deciding", and those are different
   stories about the same dropped packet.
3. **Treat an open port as the condition under which your telemetry becomes good.** Detection
   coverage for closed-port probing has to be built deliberately (5152, aggregated) because
   nothing provides it by default.
4. **Follow-up tests to run:** (a) whether stealth mode can be disabled and the matrix
   re-derived with it off; (b) what `Filter Origin` reports for a port that is open *and*
   covered by an explicit block rule with no query-user filter involved, which is the missing
   control for row 3.

---

### Finding 5 — The author's own run sheet reproduced the module's central failure

**Observation.** The gate table in Step 2 listed **four** independent switches. Steps 2.2–2.4
as originally written enabled **three**, omitting `Filtering Platform Packet Drop`. The break
in Step 4 was designed against a **closed** port — precisely the condition that routes the
packet to stealth mode and away from both instruments the run sheet told the reader to watch.
The omission was found only after both instruments returned nothing and were separately proved
functional. Step 2.2b was added afterwards.

**The same shape recurred twice more in later sittings, in different forms.**

- **An unfalsifiable step.** Step 7.1 was written as "run this query on WS01 and expect
  nothing." On the first attempt WS01's `Filtering Platform Packet Drop` subcategory was still
  `No Auditing`, so the empty result could not have come out any other way and proved nothing.
  It became evidence only after the switch was enabled and the channel demonstrated **1040**
  unrelated events.
- **An unverified state change.** On 2026-09-15 the rule `LAB Block TCP9999 from WS01` was
  reported deleted with no readback. At the start of the next sitting it was **still present
  and enabled**, which meant the "clean baseline" every subsequent knock assumed was wrong
  until it was checked.

**Inference.** I assess with **high confidence** that the recurring defect is procedural rather
than conceptual. This is the **fourth consecutive module** in which a silent gate produced empty
output with no error — Module 02's `Handle Manipulation` and `WRITE_DAC` audited-rights bit,
Module 03's per-key SACL, and now `Filtering Platform Packet Drop` — and in every case the run
sheet *documented the failure mode in advance*. The gate table in Step 2 of this very file lists
four switches; the build steps beneath it enabled three.

The plain statement is worth making: **knowing the failure mode was not sufficient to avoid
it.** The error lived in the gap between the design and the procedure — between a table that
enumerates gates and a sequence of steps that happens to cover some of them. An analyst does
not fail here from ignorance of the mechanism; they fail because the checklist and the
understanding were never made the same artifact.

The two later recurrences sharpen it into a general rule, and both are about **evidence**
rather than configuration: a predicted negative is worthless unless the instrument has
independently demonstrated it can produce a positive, and a state change is not a state until
it has been read back.

**What cannot be concluded:** nothing here is a claim about Windows. It is a claim about how
this lab's procedures failed, on a sample of four modules run by one person.

**Recommendation.**

1. **Make the gate table the pre-flight checklist, mechanically.** Every gate named in the
   design gets a numbered readback step immediately before the Break step, with the expected
   string written next to it. Not prose — a list that is ticked.
2. **Every step that predicts a negative result must be preceded by a positive control on the
   same instrument, on the same host, in the same window.** If the control cannot be produced,
   the step does not run. "Expect nothing" is not a test.
3. **Never record a state change from the command that made it.** `Remove-NetFirewallRule`
   returning silently is not evidence the rule is gone; `Get-NetFirewallRule` erroring is.
   The same applies to `auditpol /set`, `Sysmon64.exe -c`, and every SACL change since
   Module 02.
4. **Carry this forward as a standing pre-flight for Modules 07–12**, since the failure has now
   recurred in four consecutive modules and is not going to stop on its own.

---

### Finding 2 — A probe of a closed port cannot be attributed by any instrument in this lab (WS01 + DC01)

> This finding was designed to say "the attribution is on the other machine, go and get it."
> The run on 2026-09-15 established the opposite. The original expectation is left visible in
> Step 7 because the route to the result is the point.

**Observation.** On **2026-09-15**, three TCP connection attempts were made from WS01
(`10.0.0.20`) to DC01 (`10.0.0.10`) port **9999** — no listening service, no rule permitting
it — at **22:49:36**, **22:49:59** and **22:50:00 UTC**. All three returned
`TcpTestSucceeded: False`. All four instruments below were verified alive *before* the
absence was interpreted.

| Instrument | Host | Proof it was recording | Result for the three attempts |
|---|---|---|---|
| **5152** packet drop | WS01 | `Failure` by `auditpol` readback; **1040** events present | **nothing for 9999** |
| **4688** process creation | WS01 | **330** events in the surrounding 20 minutes | **nothing** — no process is created |
| **Sysmon Event 3** | WS01 | rule applied and read back; **373** Event 1s in the surrounding 30 minutes | **zero** |
| **5152** packet drop | DC01 | `Failure` by `auditpol` readback | **all three recorded** — `Filter Origin: Stealth`, `Application Name: -`, `Process ID: 0` |

The Sysmon rule was `<NetworkConnect onmatch="include"><DestinationPort condition="is">9999`,
applied with `Sysmon64.exe -c` (`Configuration updated`) and confirmed present in the live
config readback before the attempts.

At **23:09:13.841 UTC**, nineteen minutes later, a `System.Net.Sockets.TcpListener` was
started on DC01:9999 and an inbound allow rule (`LAB Allow TCP9999 from WS01`, verified by
readback) was added. A fourth attempt — **same source host, same shell, same destination,
same port, same unchanged Sysmon rule** — returned `TcpTestSucceeded: True` and produced
**exactly one** Sysmon Event 3, carrying `Image: powershell.exe`, `User: CORP\Administrator`,
`SourceHostname: WS01.corp.local`, `DestinationHostname: DC01`, `DestinationPort: 9999`,
`Initiated: true`, `ProcessGuid: {106e60df-cae4-6aa9-ec00-000000004000}`.

**The single variable that differed between 0 and 1 was whether DC01 answered.**

**Inference.** I assess with **high confidence** that Sysmon's `NetworkConnect` records
network connections that **complete**, and not connection attempts that go unanswered. The
count pair is a controlled result rather than an observation: three attempts → 0, one
completed connection → 1, with the rule, port, source, destination and process held constant
and verified between them. This is structurally the same reason 5157 does not fire for a
closed port — no connection is ever formed, so there is nothing for a connection-oriented
instrument to record.

The consequence is the finding. For a probe of a **closed** port:

- the **receiving** host records the packet (5152) but **cannot** name the sender —
  `Process ID: 0` and `Application Name: -` are not data loss, they are correct: no local
  process owns a socket that does not exist;
- the **sending** host records **nothing at all** — not in the firewall, not in
  process creation, not in Sysmon.

So attribution for this activity is **unavailable from any instrument configured in this
lab**. Sysmon names the sender only once a probe finds something **open** — that is, only for
the minority of a scan that succeeds, after the interesting part is over. Since Network
Service Discovery (**T1046**) consists overwhelmingly of attempts against closed ports, the
detection available here can say *that* a host was probed and *from which address*, and can
never say *by what program* or *as which account*.

**A competing explanation I cannot exclude from this evidence.** "Records completed
connections" and "records connections that received any response" are not distinguished by
this experiment — DC01 was silent in the negative case and completed a handshake in the
positive one, with no intermediate condition tested. A port that actively **refuses** (sends
an RST) rather than silently dropping would discriminate them, and that test was **not run**.
For detection purposes the two are equivalent; for describing the mechanism they are not, and
the stronger claim should not be made until the RST case is tested.

Also not determined: whether other Sysmon versions or configurations behave differently. This
is v15.15 / schema 4.90 on one host.

**Recommendation.**

1. **Do not use Sysmon Event 3 as a scan-detection instrument.** It is an *attribution*
   instrument for connections that succeed. Configure it for that purpose — outbound to
   sensitive ports and to external addresses — and expect it to be silent during
   reconnaissance.
2. **Scan detection has to come from the receiving side**, which means
   `Filtering Platform Packet Drop` enabled (Failure) on hosts you expect to detect probing
   against. It is **off by default**, so this is a deployment task, not a query.
3. **Alert on the pattern, never the event.** WS01 alone holds 1040 5152s with nobody
   attacking it. The signal is *one source address against many distinct destination ports
   inside a short window* — group by `SourceAddress`, count distinct `DestPort`, per five
   minutes. Baseline that count per host before choosing a threshold.
4. **Accept the attribution gap explicitly, or close it with a different class of tool.**
   Naming the process behind an unanswered outbound SYN needs an agent that hooks connection
   *attempts* rather than completions, or network-level capture. Neither exists in this lab,
   and the honest statement in a report is "source host `10.0.0.20`, process unknown".
5. **Follow-up test to run:** a probe against a port that returns RST rather than being
   stealth-dropped, to discriminate the two mechanisms named above.

---

### Finding 3 — Firewall rule changes are logged without attribution (DC01)

**Observation.** All timestamps UTC; the screenshots display WAT (UTC+1).

Before the run, all three firewall subcategories read **`No Auditing`** on both hosts
(`auditpol` readback, **2026-09-13 13:08**), with `LogAllowedConnections` and
`LogDroppedConnections` both `Disable` and `Firewall Policy: BlockInbound,AllowOutbound`.

On **DC01** a rule named **`Lab Block Ping from ws01`** was created through `wf.msc` at
**2026-09-13 13:39:31**, recorded as a **4946** with fields `ProfileChanged: (null)`,
`RuleId {13BD1F31-AA25-4461-85E5-3A6241022751}`, `RuleName`. It was deleted later in the same
sitting, recorded as a **4948**.

Three further 4946 events were written at **2026-09-14 07:28:15**, all within the same second,
with no administrator action — so of the four 4946s present, the hand-written one was the
**oldest**, and `-MaxEvents 1` returns one of the three unattended events instead.

Across the whole module the fields of 4946 and 4948 are **Profile Changed**, **Rule ID** and
**Rule Name**, and nothing else. `.Message` adds nothing beyond them.
`Event.System.Security` — the event-header slot that carries the SID of the causing account on
many event types — is **empty**, with every other header field populated
(`EventRecordID`, `Channel: Security`, `Computer: DC01.corp.local`).

Four events of the family were checked this way across two sittings:

| Event | Rule | Time | `Security` header |
|---|---|---|---|
| 4946 | `Lab Block Ping from ws01` | 2026-09-13 13:39:31 | — |
| 4948 | `lab Block tcp9999 from ws01` | 2026-09-15 21:57:30 | **empty** |
| 4946 | (control, `EventRecordID 37073`) | 2026-09-15 | **empty** |
| 4946 | `Lab Allow TCP9999 from WS01`, `ProfileChanged: All` | 2026-09-15 23:28 | — |

Background volume on a host nobody attacked: **four** 4946 and **seven** 4948 events.

**Inference.** I assess with **high confidence** that, on this host and build, 4946 and 4948
do not carry the account responsible for the change — in their fields or in the event header.
The field extraction was run on **four** events of the family across three sittings, three of
them created by hand at known times, and none carried an account. The header check was run on
**two** — a 4948 and a 4946 as control — and both came back empty while every other header
field on those same events was populated.

**Scope, stated deliberately:** this is two event IDs, on one host, on one Windows Server 2022
build. It is not a general claim about every Windows version, and it would be wrong to write it
into a report as one.

The volume figures carry a second, more operationally important conclusion. DC01 held **four**
4946s and **seven** 4948s with nobody attacking it, and **three of the four** 4946s were written
by Windows itself overnight with no administrator action. So **"a firewall rule changed" is
unusable as an alert on its own** — it would fire on routine platform behaviour and be tuned out
within a week. The hand-written rule was also the **oldest** of the four, so `-MaxEvents 1`
returns the wrong event with no error.

The combination — no attribution, and a noisy baseline — means this event family cannot answer
either question an analyst has about a firewall change: *who* and *is this unusual*. It can only
answer *what*, and only if you already know which rule name to look for.

**Recommendation.**

1. **Correlate against process creation on the same host and window.** On WS01 that is Sysmon
   **Event 1**, which carries the command line, `User` and `IntegrityLevel` in one record — the
   move that turned Module 03's Finding 1 from "a value changed" into "this account ran this
   command". On DC01 it is **4688** only, and 4688 will not see a change made through `wf.msc`
   in an already-open window (Finding 2's 7.2 result), so the correlation there is weaker.
2. **Install Sysmon on DC01.** The lab's attribution capability is currently asymmetric — the
   host that gets attacked cannot name actors, the host that can name them is not the target.
   That asymmetry is backwards and it is worth fixing before the Active Directory modules.
3. **Alert on named rules, not on rule changes.** Maintain a small list of security-relevant
   rules whose *deletion* matters (**T1562.004**) and alert on `Rule Name` matching that list
   in a 4948. Ignore the general stream.
4. **Baseline the unattended rate per host first.** Four and seven in this lab; measure it
   before choosing any threshold elsewhere.
5. **Identify events by `Rule Name`, never by position.** `| Select-Object -Last 1` takes the
   oldest of a newest-first list, and neither is a substitute for checking the name.

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
| **3** | `Microsoft-Windows-Sysmon/Operational` | Sysmon **network connection**. Carries `Image`, `User`, `ProcessGuid`, `Initiated`, and both endpoints **with hostnames resolved**. **Records connections that complete — verified 2026-09-15 to produce nothing at all for three unanswered attempts and exactly one for a completed one, same rule.** An attribution instrument, not a scan-detection instrument |
| **1** | `Microsoft-Windows-Sysmon/Operational` | Sysmon process creation. Join to Event 3 on **`ProcessGuid`** to recover the command line behind a connection |

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

- **`Get-NetFirewallProfile` reads the *configured* store by default, not the effective one.**
  Without `-PolicyStore ActiveStore` it returned `DefaultInboundAction: NotConfigured` on both
  machines (2026-09-25) — which does **not** mean "no default applies". It means nothing has
  explicitly set that value in the store being read; Windows' built-in behaviour is still in
  force. Re-read through `ActiveStore` and the same machines returned **Block inbound, Allow
  outbound**, reconciling with the `Firewall Policy: BlockInbound,AllowOutbound` already on
  record from 2026-09-13. Taken at face value, `NotConfigured` would have entered the baseline
  as a wrong fact — the same family as the empty-`Get-WinEvent` traps: **a reading that looks
  like an answer and is not one.**
- **`LogFileName` is stored as a literal `%systemroot%\system32\LogFiles\Firewall\pfirewall.log`**
  on both machines. PowerShell does **not** expand `%VAR%` syntax — `Get-Content` on that
  literal string fails. Use `$env:systemroot`, or the expanded path. Module 06's own reads
  never hit this because the file was opened by its expanded path.
- **Read the table's columns before running its commands.** On 2026-09-25 the first three
  readbacks were run on DC01 when it was **WS01's** cells that were marked `(unread)` — the
  column order is WS01 first. No harm done (DC01's cells gained a command readback in place of
  a screenshot) but it cost a round of commands. **The wrong-machine trap does not only apply
  to queries; it applies to deciding which machine to query.**

- **A mistyped event ID looks exactly like a genuine absence.** `Id=49466` instead of `4946`
  returns `No events were found that match the specified selection criteria` /
  `NoMatchingEventsFound` — the identical message a real empty result gives. On 2026-09-15 that
  typo briefly looked like DC01's 4946 events had been destroyed by log rotation, and a
  rotation theory was half-built on it before the retype cleared it. **Suspect the query before
  the host.** The screenshot preserves both the typo and the correct run.
- **`auditpol /get /subcategory: "…"` with a space after the colon fails** with
  `Error 0x00000057 … The parameter is incorrect.` and dumps the usage text, which reads like a
  broken tool rather than a typo. No space: `auditpol /get /subcategory:"Filtering Platform
  Connection"`.
- **Rule names come back exactly as typed, case and all.** The evidence holds
  `Lab Block Ping from ws01`, `lab Block tcp9999 from ws01` and `Lab Allow TCP9999 from WS01` —
  three different capitalisations of the same naming scheme. `-DisplayName` matching is
  case-insensitive, so this bites only when you compare strings by eye. Findings must quote the
  name as the log prints it, not as the run sheet planned it.
- **`ProfileChanged` reads `(null)` for a rule scoped to one profile and `All` for
  `-Profile Any`.** Verified across two 4946s. It is not an account field and never becomes one.
- **Sysmon Event 3 does not see a probe of a closed port.** Verified 2026-09-15 with a rule
  scoped to exactly that port, applied and read back beforehand: **0** events for three
  unanswered knocks, **1** for a single connection that completed, with nothing else changed.
  Sysmon names the sender only once the probe finds something open. Do not plan a scan
  detection around it.
- **A predicted negative needs a positive control on the same instrument, or it is not
  evidence.** Every silence in this module was made trustworthy by a number next to it — 1040
  unrelated 5152s on WS01, 330 unrelated 4688s, 373 unrelated Sysmon Event 1s. A step written
  as "run this and expect nothing" proves nothing at all when the instrument is off, which is
  exactly what happened on the first attempt at Step 7.1.
- **`Test-NetConnection` creates no process, so it writes no 4688.** It is a cmdlet inside a
  shell that is already running. More generally: **process-creation logging records a program
  starting, not what it does afterwards** — a shell open for an hour writes one 4688 and then
  does a hundred invisible things. Script block logging (4104, Module 05) is what covers that
  gap, not 4688.
- **A `Remove-` that ran is not a rule that is gone.** `LAB Block TCP9999 from WS01` was
  reported deleted on 2026-09-15 with no readback and was still present and enabled at the
  start of the next sitting. Every state change gets a `Get-` afterwards — firewall rules,
  `auditpol /set`, Sysmon config, SACLs.
- **A `TcpListener` dies with the PowerShell session that created it.** It is not a service.
  Closing the window, or the VM shutting down, releases the port with no trace.
- **A `NetworkConnect` element can sit directly under `<EventFiltering>`**, as a sibling of an
  existing `<RuleGroup>` — verified 2026-09-15. It does not have to be inside a rule group.
  Scope it with `condition="is"` on a port, not `contains`, which would also match 19999.
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
