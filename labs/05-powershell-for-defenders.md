# Module 05 — PowerShell for Defenders

> **Runs on:** WS01 (with two queries on DC01)
> **Time:** ~2–3 hours, best split across two sittings
> **Snapshot before starting:** `mod05-start`

---

## What you're going to do

Every module so far handed you PowerShell to paste. This one teaches you to **write it
yourself**, then turns that skill on the thing attackers actually use to operate:
PowerShell itself.

The goal is one capability: **read a query and know what each piece does, and build a new
one from scratch.** Not memorise cmdlets — understand the pipeline well enough that the
next query is something you assemble, not something you look up.

The way we get there is a ladder. You'll start with a single word, run it, add one piece,
run it again — so every addition's effect is visible on screen. By the end you'll have
built the exact triage query Module 01 handed you, one word at a time, and written a small
triage script of your own.

Then the security half: attackers run PowerShell **encoded and obfuscated** to hide what
it does. You'll run a (benign) encoded command yourself and watch **Script Block Logging**
record the *decoded* script anyway — the single most important PowerShell defence there is.

Structure:

1. The pipeline, one piece at a time (`Get-Process` → a real query)
2. `Get-WinEvent -FilterHashtable`, the analyst's query language, built up
3. Variables, and getting fields by name
4. Write a triage script of your own
5. **Break:** run an encoded / obfuscated command
6. **Detect:** watch 4104 record the decoded script, and 4688 the command line

Each step says **which VM**. Almost everything is WS01.

---

# Step 0 — Pre-flight

### 0.1 Start from the healthy baseline

Both VMs should be rearmed and running. Restore **`mod04-start`** if you want a clean
start — it has the audit policy on and the licences healthy. Do **not** restore
`01-domain-ready`; it predates both.

Log into **WS01** as `administrator@corp.local`.

### 0.2 Turn on the logging this module detects

Two features have to be on, and both are **off by default** — which is itself the lesson:
PowerShell's most valuable logging is not enabled out of the box.

**Aim: make PowerShell record what it runs.** Open the Local Group Policy Editor — press
**Start**, type `gpedit.msc`, Enter.

**Feature 1 — Script Block Logging (event 4104).** Navigate:

**Computer Configuration → Administrative Templates → Windows Components → Windows
PowerShell → Turn on PowerShell Script Block Logging**

Double-click it → **Enabled** → **OK**.

**Feature 2 — command line in process events (enriches 4688).** Navigate:

**Computer Configuration → Administrative Templates → System → Audit Process Creation →
Include command line in process creation events**

Double-click it → **Enabled** → **OK**.

Close gpedit, then apply the policy now rather than waiting:

```powershell
gpupdate /force
```

> **Why both?** 4104 records the *PowerShell* that ran, decoded. 4688 records *any*
> process starting, and with Feature 2 on, its **full command line** — so you catch
> `powershell.exe -EncodedCommand …` even when it's launched from outside PowerShell.
> They're two angles on the same activity, and Step 6 reads both.

### 0.3 Confirm process auditing is still on

Module 04 enabled this; confirm it survived:

```powershell
auditpol /get /subcategory:"Process Creation"
```

Should read **Success**. If not: `auditpol /set /subcategory:"Process Creation" /success:enable`.

### 0.4 Snapshot

Shut WS01 down, snapshot it as **`mod05-start`**, start it again. This is your rollback if
you want to repeat the module.

---

# Step 1 — The pipeline, one piece at a time (WS01)

**Aim: understand the one idea the whole language is built on** — that `|` passes the
output of one command into the next, and you build a query by adding one stage at a time.

Open **Terminal (Admin)**. Run just this:

```powershell
Get-Process
```

A long table of every running process. Too much — so let's shape it. **Add one piece**,
run it, see what changed. Each command below is the previous one with one more stage.

### 1.1 Keep only what you want to see — `Where-Object`

```powershell
Get-Process | Where-Object { $_.CPU -gt 10 }
```

Read the `|` as "then." *Get the processes, **then** keep the ones where…* Inside the
braces, `$_` means "the current process" — the one being tested right now. `.CPU` is one
of its properties; `-gt 10` is "greater than 10." So: processes that have used more than
10 seconds of CPU.

`-gt` is the tell that PowerShell doesn't use `>` for comparison. The operators:

| Operator | Means |
|---|---|
| `-eq` / `-ne` | equals / not equals |
| `-gt` / `-lt` | greater than / less than |
| `-like` | wildcard match (`*`) |

### 1.2 Pick which columns — `Select-Object`

```powershell
Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object Name, Id, CPU
```

Another "then." *…**then** show only these three columns.* The table is now readable:
name, process ID, CPU.

### 1.3 Order it — `Sort-Object`

```powershell
Get-Process | Where-Object { $_.CPU -gt 10 } | Sort-Object CPU -Descending | Select-Object Name, Id, CPU
```

*…**then** sort by CPU, biggest first, **then** show the columns.* The busiest process is
now at the top.

**Stop and look at what you built.** Four stages, left to right, each one word of a
sentence:

> get the processes → keep the busy ones → sort by CPU → show name, id, CPU

That's the whole language. Every query in this repo, including the ones Module 01 handed
you, is this shape. You just wrote one.

### 1.4 The cmdlets worth knowing

Same pipeline, different first word. Try each bare, then shape it yourself:

```powershell
Get-Service   | Where-Object { $_.Status -eq 'Running' }
```

```powershell
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
```

```powershell
Get-LocalUser | Where-Object { $_.Enabled -eq $true }
```

| Cmdlet | Answers |
|---|---|
| `Get-Process` | what's running |
| `Get-Service` | what services exist and their state |
| `Get-NetTCPConnection` | what's listening or connected on the network |
| `Get-LocalUser` | local accounts |
| `Get-CimInstance` | almost anything else about the system (deep, for later) |

Don't memorise their properties. Ask:

```powershell
Get-Service | Get-Member
```

`Get-Member` lists every property and method the thing has — it's how you find out what
you can put after `$_.` without guessing.

---

# Step 2 — `Get-WinEvent`, built up (WS01)

**Aim: build the log-query language you've been pasting, one piece at a time, so you can
write the next one yourself.**

`Get-WinEvent` is just another first word in the same pipeline. Start bare:

```powershell
Get-WinEvent -LogName Security -MaxEvents 5
```

*Get 5 events from the Security log.* `-MaxEvents 5` keeps it small while you experiment.

### 2.1 The filter belongs *inside*, not after

You could pipe to `Where-Object`, but Module 04 taught the trap: filtering *after*
`-MaxEvents` starves the query. So the filter goes **into the log request itself**, with
`-FilterHashtable`:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688 } -MaxEvents 5
```

`@{ … }` is a **hashtable** — a set of `Key=Value` pairs. Here two: which log, which
event ID. The log does the filtering before anything is read, so it can't be starved.
This is the single most important query form in the whole job.

### 2.2 Add a time bound

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-1) } -MaxEvents 5
```

One more `Key=Value` in the hashtable: `StartTime`. `(Get-Date)` is now; `.AddHours(-1)`
is an hour ago. So: 4688s from the last hour. Widen with `.AddDays(-7)` when hunting
something older — remember `StartTime` *filters*, it doesn't search, so too-narrow returns
nothing.

### 2.3 Shape the output like any other pipeline

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-1) } |
  Select-Object TimeCreated, Id -First 10
```

The `|` at the end of a line lets a command continue on the next — nothing more. This is
now exactly Step 1's pipeline: get events → show columns. The events are just a different
kind of object flowing down the same pipe.

---

# Step 3 — Variables and fields by name (WS01)

**Aim: stop the two things that made earlier queries frustrating — re-fetching the same
event, and guessing `Properties[4]`.**

### 3.1 A variable holds a result

```powershell
$e = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688 } -MaxEvents 1
```

Nothing printed — the event went into the box `$e` instead of the screen. `$` marks a
variable; `=` means "put into." Now ask `$e` questions without querying again:

```powershell
$e.TimeCreated
```

```powershell
$e.Id
```

### 3.2 Get every field by its real name

The columns you actually want — who ran what — live in the event's `EventData`, and
Module 04 showed guessing their position (`Properties[4]`) drifts silently. Ask for names
instead:

```powershell
([xml]$e.ToXml()).Event.EventData.Data | Format-Table Name, '#text'
```

Run it. For a 4688 you'll see `NewProcessName`, `CommandLine`, `SubjectUserName`, and
more — each label beside its value. Do this once per event ID and you never guess a
position again. (If `EventData` is empty, the fields are under `UserData` — some events,
like 1102, put them there.)

### 3.3 Select a named field into a clean column

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688 } -MaxEvents 20 |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
      Time    = $_.TimeCreated
      Process = ($d | Where-Object Name -eq 'NewProcessName').'#text'
      Command = ($d | Where-Object Name -eq 'CommandLine').'#text'
    }
  } | Format-Table -AutoSize
```

This is the biggest block in the module, so take it stage by stage — it's Step 1's
pipeline with one new middle stage:

- `Get-WinEvent …` — get the events (filter-first, as always)
- `ForEach-Object { … }` — **for each event**, do the block. `$_` is the current event
- `$d = …ToXml()…` — pull that event's named fields into `$d`
- `[pscustomobject]@{ … }` — build a tidy row with three columns you name
- `($d | Where-Object Name -eq 'CommandLine').'#text'` — from the fields, take the one
  called `CommandLine`, give me its value

You've now built, from parts you understand, the exact shape of every hunt query in this
repo. That was the goal of Steps 1–3.

---

# Step 4 — Write a triage script of your own (WS01)

**Aim: turn a query into a reusable tool — the thing that makes you faster than someone
clicking through Event Viewer.**

A script is just commands saved in a `.ps1` file. Build one that answers "what happened on
this box recently?" — recent logons, failures, and new processes, in one run.

Open Notepad from the terminal:

```powershell
notepad triage.ps1
```

Paste this, save, close:

```powershell
# triage.ps1 — quick "what happened here lately" summary
$since = (Get-Date).AddHours(-2)

"`n=== Failed logons (4625) ==="
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$since } -ErrorAction SilentlyContinue |
  Measure-Object | Select-Object @{n='FailedLogons';e={$_.Count}}

"`n=== New processes (4688) ==="
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=$since } -ErrorAction SilentlyContinue |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    ($d | Where-Object Name -eq 'NewProcessName').'#text'
  } | Group-Object | Sort-Object Count -Descending | Select-Object Count, Name -First 10
```

Run it:

```powershell
.\triage.ps1
```

The `.\` means "in this folder." Two new pieces earn their place here:

- `$since` is set **once** at the top and reused twice — change the window in one place.
- `Group-Object` collapses duplicates and counts them, so instead of 2,000 process lines
  you get "cmd.exe: 2000" at the top. That's how you spot a flood — like the one you
  generated in Module 04.

> **If a section errors**, `-ErrorAction SilentlyContinue` keeps the script running to the
> next section instead of stopping. "No events found" is not a failure — it's a valid
> answer, and the script should survive it.

You now have a tool you wrote. That is the deliverable, and it is a genuinely useful thing
to show.

---

# Step 5 — Break: run an encoded / obfuscated command (WS01)

**Aim: do what an attacker does — hide a command's contents — so Step 6 can show you it
doesn't work against good logging.**

Attackers rarely type readable PowerShell. They pass it **base64-encoded** so a glance at
the command line shows gibberish, and defenders (and some tools) can't read it. Everything
below is benign — it prints text — but the *technique* is exactly the real one.

### 5.1 Build an encoded command

First the readable version, so you know what it does:

```powershell
$plain = 'Write-Output "hello from an encoded command"'
```

Now encode it the way `-EncodedCommand` expects — base64 of UTF-16LE bytes:

```powershell
$bytes   = [System.Text.Encoding]::Unicode.GetBytes($plain)
$encoded = [Convert]::ToBase64String($bytes)
$encoded
```

That last line prints the base64 blob — a wall of characters that reveals nothing about
what it does. Copy it.

### 5.2 Run it as an attacker would

```powershell
powershell.exe -EncodedCommand <paste the blob here>
```

It prints `hello from an encoded command`. To anyone watching the command line, though, all
they saw was `powershell.exe -EncodedCommand SQBlAG…` — the intent was hidden.

### 5.3 One more, nested — the obfuscation attackers actually layer

```powershell
powershell.exe -EncodedCommand <blob> -WindowStyle Hidden
```

`-WindowStyle Hidden` runs with no visible window — combined with encoding, this is a
staple of real intrusions. Note the time; you'll find both runs in the logs next.

---

# Step 6 — Detect: the decoded script, and the command line (WS01)

**Aim: prove that encoding hides the command from a human but not from the logs** — the
whole reason Script Block Logging exists.

### 6.1 The decoded script — 4104

Script Block Logging lives in its own channel, not Security. Get the recent script blocks:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddHours(-1) } -MaxEvents 20 |
  Format-List TimeCreated, Message
```

Look at the `Message`. **Your `Write-Output "hello from an encoded command"` is sitting
there in plain text** — decoded, even though you ran it as base64. That's the point:
PowerShell logs the script block *after* it decodes it, so obfuscation doesn't hide the
contents from this log. Encoding defeats a person reading the command line; it does not
defeat 4104.

📸 **Screenshot a 4104 showing your decoded command.** Best evidence in the module.

> **4104 has a Level.** Warning-level 4104 events are ones PowerShell itself flagged as
> suspicious (certain APIs, known-bad patterns). In a real hunt you'd start there:
> `@{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; Level=3 }`.

### 6.2 The command line — 4688

The other angle: the process starting, with its full command line (Feature 2 from Step 0):

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-1) } |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
      Time    = $_.TimeCreated
      Command = ($d | Where-Object Name -eq 'CommandLine').'#text'
    }
  } | Where-Object { $_.Command -like '*EncodedCommand*' } | Format-Table -AutoSize
```

Here the `Command` column shows `powershell.exe -EncodedCommand SQBlAG…` — the encoded
form, *not* decoded. So the two logs are complementary and you need both:

| Log | What it shows | What it hides |
|---|---|---|
| **4688** (Security) | the command line **as launched** — proof `-EncodedCommand` was used | the decoded contents |
| **4104** (PowerShell/Operational) | the **decoded** script — what it actually did | — |

Note the final `Where-Object` filters on the `Command` **column you built**, not on the
raw event — that's a legitimate use of `Where-Object`, narrowing results that are already
correctly filtered.

### 6.3 The analyst read

`powershell.exe -EncodedCommand` with `-WindowStyle Hidden` is rarely a normal user. The
encoding hides intent; the hidden window hides presence. On a real host you'd take the
decoded 4104 content, work out what it does, and pivot to what the process touched next.
The chain here is benign, but the detection is exactly the real one.

---

# Step 7 — Evidence for the portfolio

Save into `../assets/` (spaceless `05-*` names):

- [ ] `05-pipeline-ladder.png` — the Step 1 query built up (the busy-process pipeline)
- [ ] `05-filterhashtable.png` — a `-FilterHashtable` query returning events
- [ ] `05-triage-script.png` — your `triage.ps1` output
- [ ] `05-4104-decoded.png` — the 4104 showing your decoded encoded command
- [ ] `05-4688-commandline.png` — the 4688 showing `-EncodedCommand` on the command line

Then a few sentences in your own words: what encoding hides, what 4104 recovers, and why
you need both logs.

---

# Findings

**Write after the run**, observation → inference → recommendation, the three kept
separate. One is set up for you:

### Finding — Encoded PowerShell executed on WS01

Observation: the 4688 command line proving `-EncodedCommand` (and `-WindowStyle Hidden`)
was used, with timestamps in **UTC**, and the corresponding 4104 with the decoded script.
Inference: **T1059.001** (PowerShell), **T1027** (obfuscated), **T1140** (decode) — and be
explicit about what the logs *do* settle (that encoding was used, and what the decoded
content was) versus what they don't (whether it was interactive or scripted, and where the
launching process came from). Note honestly that you ran this yourself.

A second finding worth writing if you disabled and re-enabled logging: turning off Script
Block Logging is **T1562.001**, and the gap it leaves is the tell.

---

# Reference

### Core cmdlets

| Cmdlet | Use |
|---|---|
| `Get-Process` / `Get-Service` | running processes, services |
| `Get-NetTCPConnection` | listening / connected ports |
| `Get-LocalUser` | local accounts |
| `Get-CimInstance` | deep system info (hardware, OS, installed software) |
| `Get-WinEvent` | the log query engine |
| `Get-Member` | list an object's properties — how to stop guessing |

### The pipeline verbs

| Verb | Does |
|---|---|
| `Where-Object` | keep rows matching a condition |
| `Select-Object` | pick columns (and `-First N`) |
| `Sort-Object` | order rows |
| `Group-Object` | collapse duplicates and count |
| `Measure-Object` | count / sum |
| `ForEach-Object` | run a block per item |

### Event IDs

| ID | Log | Meaning |
|---|---|---|
| **4104** | PowerShell/Operational | **Script block** — the decoded script that ran. Level 3 = flagged suspicious |
| **4103** | PowerShell/Operational | Module/pipeline logging — cmdlets and parameters |
| **400 / 600** | Windows PowerShell (classic) | engine / provider start |
| **4688** | Security | Process created — with command line if enabled |
| **4624 / 4625** | Security | logon success / failure (triage script) |

### MITRE ATT&CK

| Technique | ID | Where |
|---|---|---|
| Command & Scripting Interpreter: PowerShell | T1059.001 | Step 5 |
| Obfuscated Files or Information | T1027 | Step 5.1 |
| Deobfuscate/Decode Files or Information | T1140 | Step 6.1 |
| Impair Defenses: Disable/Modify Tools | T1562.001 | if logging disabled |

---

# If something goes wrong

**No 4104 events at all.**
Script Block Logging didn't take. Re-check Step 0.2 in `gpedit.msc`, run `gpupdate /force`,
then re-run an encoded command *after* — logging only captures what runs once it's on.
Confirm the channel exists and is enabled:
`Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' | Select-Object IsEnabled, RecordCount`.

**4688 shows no `CommandLine` field.**
Feature 2 (Step 0.2) isn't on, or the process predates it. Enable "Include command line in
process creation events", `gpupdate /force`, and generate a *new* process.

**`-EncodedCommand` errors with "invalid base64".**
The blob got line-wrapped on paste, or you encoded UTF-8 instead of UTF-16LE. Rebuild it
with `[System.Text.Encoding]::Unicode` (Step 5.1) — `Unicode` here means UTF-16LE, which
is what `-EncodedCommand` requires.

**`.\triage.ps1` refuses to run — "running scripts is disabled".**
Execution policy. For this session only:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`. Scoped to the process, it
reverts when you close the window — don't set it machine-wide.

**A query returns nothing.**
The Module 04 checklist: wrong machine → window too narrow or starved (use
`-FilterHashtable`, not `-MaxEvents` then `Where-Object`) → overwritten → channel disabled
→ auditing off.

**`Get-Member` on a `Get-WinEvent` result doesn't show the event fields.**
Those live in `EventData`, not as top-level properties. Use the `([xml]$e.ToXml())` method
from Step 3.2 to see them.

---

**Next:** → [Module 02 — NTFS Permissions & File Auditing](./02-ntfs-permissions.md) *(not written yet)*
