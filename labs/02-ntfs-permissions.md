# Module 02 — NTFS Permissions & File Auditing

> **Runs on:** WS01 (everything; no DC01 needed)
> **Time:** ~2 hours, best split across two sittings
> **Roll back to:** `mod04-start` · **Snapshot before starting:** `mod02-start`

---

## What you're going to do

Files are where the valuable things live — finance records, credentials, someone's
private folder. Attackers go looking for them, and the question a SOC analyst has to
answer is simple to ask and hard to prove: **who touched this file, and were they
allowed to?**

Answering it needs two separate things, and this module builds both:

1. **Permissions** — the lock on the door. Which accounts can read, write, or change a
   folder, and how Windows decides. You'll lock a "Finance" folder down to one group and
   watch an unauthorized account bounce off it.
2. **Auditing** — the camera above the door. Permissions *stop* access; they don't
   *record* it. A separate switch makes Windows write an event every time someone reaches
   for the folder — allowed or denied. You'll turn it on and generate both.

The catch that makes this a detection module: **the lock and the camera are independent.**
A folder can be perfectly locked and record nothing, or wide open and fully watched. Most
"why is there no log?" moments come from confusing the two — the same lesson Module 04
taught with cleared logs, now at the file level.

In this module you will:

1. Read a folder's permissions (its DACL) and learn what an ACE actually says
2. Lock `C:\Finance` down to a "Finance" group, and test it as a denied user
3. Turn on object-access auditing and put a **SACL** on the folder — the camera
4. Access the folder as an authorized *and* an unauthorized user
5. Find both in the logs — the allowed access (**4663**) and the denied one (**4656**)
   — plus the audit-setting change (**4907**) and a deliberately generated permission
   change (**4670**), and write up what you found

Follow the steps in order. Every step says **which VM** — this time it's always WS01.

**Accounts used in this module** (all local to WS01, so there's no `\` or `@corp.local`
to type — just the bare name at the login screen)

| Account | Password | Role in this module |
|---|---|---|
| `administrator` | `Lab-Passw0rd!` | does the admin work (owns, locks, audits) |
| `fin_user` | `Lab-Passw0rd!` | **authorized** — member of the Finance group |
| `helpdesk` | `Lab-Passw0rd!` | **unauthorized** — the account that should bounce (reused from Module 01) |

> **Two vocabularies, kept apart.** A **DACL** is the permission list — the lock, who's
> allowed. A **SACL** is the audit list — the camera, who gets recorded. Same folder,
> two separate lists on it. Every confusing moment in this module comes from mixing them
> up, so it's worth pinning down now: **D**iscretionary = who *can*, **S**ystem =
> who's *watched*.

---

# Step 0 — Pre-flight

### 0.1 Start from the healthy baseline

**Aim: begin from a known-good WS01 so the Break step is repeatable and licence-healthy.**

WS01 powered off → **Snapshots** → restore **`mod04-start`** (the rearmed, audit-policy-on
baseline). Start WS01 and log in as `administrator` / `Lab-Passw0rd!`.

> Don't restore `01-domain-ready` — that reverts to the expired evaluation licence and to
> pre-audit-policy state.

### 0.2 Make the unauthorized account, if it isn't there

**Aim: guarantee you have one authorized and one unauthorized local user to test with.**

`helpdesk` was created in Module 01 but may not have survived snapshots. Check, and make
the authorized user either way. Right-click **Start → Windows PowerShell (Admin)** on
**WS01**:

```powershell
Get-LocalUser | Select-Object Name, Enabled
```

If `helpdesk` is missing, create it:

```powershell
New-LocalUser -Name 'helpdesk' -Password (Read-Host -AsSecureString 'Password') -FullName 'Help Desk'
```

(It'll prompt for the password — type `Lab-Passw0rd!`.)

### 0.3 Snapshot

**Aim: bookmark this exact state so you can redo the whole Break step later.**

Shut WS01 down cleanly and take a snapshot named **`mod02-start`**. Boot back up.

---

# Step 1 — Read a folder's permissions before you change any (WS01)

**Aim: learn to read a DACL, so that when you lock the folder down in Step 3 you can prove
the change rather than assume it.**

You never change a permission you haven't read first. Create the folder and look at what
it inherited by default.

### 1.1 Create the folder

In **PowerShell (Admin)** on **WS01**:

```powershell
New-Item -Path 'C:\Finance' -ItemType Directory
```

### 1.2 Read the permissions two ways

The quick, readable view first:

```powershell
icacls C:\Finance
```

You'll see lines like `BUILTIN\Users:(OI)(CI)(RX)` and
`NT AUTHORITY\SYSTEM:(OI)(CI)(F)`. Each line is one **ACE** (Access Control Entry) — one
rule. Read an ACE as three parts:

- **who** — the principal (`BUILTIN\Users`, `Administrators`, `SYSTEM`)
- **what** — the rights: `F` full, `M` modify, `RX` read & execute, `R` read, `W` write
- **how it spreads** — inheritance flags: `(OI)` object-inherit (files below get it),
  `(CI)` container-inherit (subfolders get it), `(I)` this ACE was *itself* inherited
  from the parent

The key thing you're looking at: **`BUILTIN\Users:(OI)(CI)(RX)`** means *every user on
this machine can already read this folder.* That's the default, and it's what you're about
to remove.

> **Why is `Users` on there at all?** `C:\Finance` inherited it from `C:\`. Almost every
> permission problem starts as an *inherited* one — the folder didn't grant it, its parent
> did, and it flowed down. The `(I)` flag is how you spot an inherited ACE.

### 1.3 The same list in the GUI

**Aim: connect the text to the screen you'll actually click in.** Open **File Explorer →
`C:\` → right-click `Finance` → Properties → Security tab.** The "Group or user names" box
is the same DACL `icacls` just printed. Click **Users** and you'll see the same *Read &
execute* ticked below. Leave it open — Step 3 works here.

---

# Step 2 — Make the Finance group and its authorized user (WS01)

**Aim: create the "allowed" side of the story — a group that will be the only thing able
to read the folder, and a user inside it to test with.**

Permissions are cleaner when granted to a **group**, not a person — you add and remove
people from the group without ever touching the folder again. Make the group, the user,
and put the user in the group. In **PowerShell (Admin)** on **WS01**:

```powershell
New-LocalGroup -Name 'Finance' -Description 'Access to C:\Finance'
```

```powershell
New-LocalUser -Name 'fin_user' -Password (Read-Host -AsSecureString 'Password') -FullName 'Finance User'
```

(Password `Lab-Passw0rd!` at the prompt.)

```powershell
Add-LocalGroupMember -Group 'Finance' -Member 'fin_user'
```

Confirm the membership:

```powershell
Get-LocalGroupMember -Group 'Finance'
```

You want `WS01\fin_user` in the list. Now you have the allowed group; `helpdesk` is
deliberately *not* in it — that's your unauthorized user.

---

# Step 3 — Lock the folder down (WS01)

**Aim: turn `C:\Finance` from "everyone can read" into "only the Finance group can",
and read the DACL again to prove the lock took.** This is the Build step.

> **This change will not be logged, and that is the point.** You might expect a **4670**
> ("permissions on an object were changed") here. There won't be one: auditing isn't
> switched on until Step 4, and **auditing is never retroactive** — nothing was watching
> when you turned the lock. Step 6.3 generates a real 4670 deliberately, once the camera
> is running (Step 6.4). Measured on WS01, 2026-09-07: this lock-down produced **zero**
> 4670 events.
> Remember the shape of it — "I made the change but there's no event" is far more often
> *ordering* or a *missing subcategory* than a broken log.

Do this in the **Security tab** you left open in Step 1.3 (GUI first — it's clearer than
the command line for this, and it's how a real admin does it).

### 3.1 Stop inheritance

The broad `Users` access is *inherited* from `C:\`, so you can't just delete it while
inheritance is on — it'll flow straight back. Break the flow first:

1. In the **Security tab**, click **Advanced**.
2. Click **Disable inheritance**.
3. Choose **"Convert inherited permissions into explicit permissions on this object."**
   (This keeps the current entries but freezes them, so removing one actually sticks.)
4. **Apply**.

### 3.2 Remove the broad access, add the group

Still in **Advanced** (or back on the **Security tab → Edit**):

1. Select the **Users** entry → **Remove**. (This is the ACE that let everyone read.)
2. **Also remove `Authenticated Users`** if it's there. `C:\` passes down *two* broad
   rules, not one — `Users:(RX)` **and** `Authenticated Users:(M)`. Removing only Users
   leaves the folder open to anyone who has logged on, because they're an authenticated
   user. Remove both. (Found the hard way on the 2026-09-05 run — see Findings.)
3. **Add → Select a principal →** type `Finance` → **Check Names → OK**.
4. Tick **Modify** (which includes Read & write) → **OK**.
5. Leave `Administrators` and `SYSTEM` alone — you always keep an admin path in.
6. **Apply → OK** out of every window.

### 3.3 Prove the lock took

Back in **PowerShell** on **WS01**:

```powershell
icacls C:\Finance
```

`BUILTIN\Users` **and** `NT AUTHORITY\Authenticated Users` should both be **gone**, and
`WS01\Finance:(OI)(CI)(M)` present. No `(I)` on your new entries — they're explicit now,
not inherited. The lock is real and you can *show* it changed, which is the whole point of
reading before and after.

> **If a denied user can still write, an inherited broad ACE survived.** The command-line
> way to sweep it, if the GUI missed one: `icacls C:\Finance /remove:g "Authenticated Users"`
> (`/remove:g` drops a granted/Allow entry). Re-read with `icacls C:\Finance` to confirm.

> **The rule you just relied on:** with `Users` removed, `helpdesk` has no allow entry at
> all, so it's denied by absence — Windows denies anything not explicitly allowed. You
> didn't need a **Deny** ACE. Keep that in mind: an explicit **Deny** always wins over any
> Allow ("deny beats allow"), but you rarely need one — removing the allow is cleaner.

---

# Step 4 — Turn on the camera (WS01)

**Aim: make Windows *record* access to this folder. Permissions from Step 3 stop the wrong
people; they log nothing. This step is the separate switch that produces 4663.**

Two things must both be true, or you get silence — this is the module's core trap:

- **The policy switch** — object-access auditing turned on for the machine (like flipping
  the breaker for the camera circuit).
- **The SACL** — an audit rule *on this specific folder* saying what to record (like
  pointing the camera at this door). A folder with no SACL is never logged no matter how
  the policy is set.

### 4.1 Flip the policy switch

In **PowerShell (Admin)** on **WS01**:

```powershell
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

Confirm it took:

```powershell
auditpol /get /subcategory:"File System"
```

You want **Success and Failure** both listed. `Success` logs allowed access; `Failure`
logs *denied* access — and the denied one is what catches an attacker probing a folder
they can't open, so you want both.

Now the second switch — the one that makes *denied* access loggable at all:

```powershell
auditpol /get /subcategory:"Handle Manipulation"
```

It will almost certainly say **No Auditing**. Turn it on:

```powershell
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
```

**Do not skip this.** `File System` auditing records access that *happened* — it writes a
4663 when a right is actually used. A refusal never gets that far: Windows decides it when
the handle is *requested*, and that decision is a **4656**, which needs `Handle
Manipulation`. With this switch off, an allowed access logs perfectly and a denied one
leaves nothing at all — while the SACL and `File System` auditing both still read "Success
and Failure", so every check you'd think to run says the camera is fine. Measured on WS01,
2026-09-05: helpdesk's denied read produced no event whatsoever until this was enabled,
then produced a 4656 on the first retry.

Now the **third** switch — the one that logs changes to the permissions themselves:

```powershell
auditpol /get /subcategory:"Authorization Policy Change"
```

If it says **No Auditing**, turn it on:

```powershell
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
```

**This is the switch that feeds 4670.** Neither `File System` nor `Handle Manipulation`
produces it — a DACL change is a *policy* change, not an access, so it comes from a third
subcategory entirely. Get this on now and any later permission change on `C:\Finance`
leaves a record.

> **The pattern to take out of this module — four gates, not one.** An event reaches the
> log only if *every* gate below is open, and each one is checked by a different command:
>
> | # | Gate | Checked with | Governs |
> |---|---|---|---|
> | 1 | `File System` subcategory | `auditpol /get` | **4663** — a right was *used* (success only) |
> | 2 | `Handle Manipulation` subcategory | `auditpol /get` | **4656** — a handle was *requested*; carries allow/deny |
> | 3 | `Authorization Policy Change` subcategory | `auditpol /get` | **4670** — the *permissions* were changed |
> | 4 | The SACL's **audited rights** | `Get-Acl -Audit`, or the Auditing tab | *which* actions any of the above records |
>
> Gates 2 and 3 are **off by default**. Gate 4 is the subtle one: it is set per-object and
> per-right, so `WRITE_DAC` ("Change permissions") being unticked silently suppresses 4670
> even with all three subcategories enabled. And none of it is retroactive — every gate
> must be open *before* the activity happens.
>
> Checking one gate and finding "Success and Failure" is not evidence about any other.
> That assumption cost a run on 2026-09-05 and two more findings on 2026-09-07.

### 4.2 Point the camera at the folder — the SACL (writes 4907)

Back in **File Explorer → `C:\Finance` → Properties → Security → Advanced → Auditing tab**:

1. **Add → Select a principal →** type `Everyone` → **OK**. (Audit *everyone* — you want
   to catch the unauthorized user, who isn't in any group you'd name.)
2. **Type: All** (records both successful and failed attempts).
3. Tick **Read & execute**, **Write**, and **Delete** (enough to prove access without
   drowning in noise).
4. Click **Show advanced permissions** and also tick **Change permissions**.
5. **OK** out of every window.

The moment you apply that SACL, Windows writes a **4907** ("auditing settings on an object
were changed") — your first evidence, and proof the camera was *installed* and when.

> **Why step 4 matters — the gate below the subcategory.** The rights you tick here are
> not a noise filter, they are the *definition* of what gets recorded. Changing a folder's
> permissions uses a right called `WRITE_DAC`, which the GUI calls **Change permissions**
> — and it is not part of Read & execute, Write, or Delete. Leave it unticked and a DACL
> change on this folder produces **no 4670 at all**, even with `Authorization Policy
> Change` enabled and `auditpol` reporting Success and Failure. Measured on WS01,
> 2026-09-07: two `icacls` permission changes logged nothing; after ticking **Change
> permissions** the identical two commands produced two 4670s naming `C:\Finance` and
> `Administrator`. Same commands, same subcategories — only the SACL's audited rights
> differed.

---

# Step 5 — Break: touch the folder as both users (WS01)

**Aim: generate the two events that matter — an allowed access and a denied one — so
Step 6 can tell them apart in the log.** Note the **time before each**; you'll filter by
it. Everything here is benign.

### 5.1 As the authorized user

Note the time first — you'll filter by it. In **PowerShell** on **WS01** as
`administrator`:

```powershell
Get-Date
```

Then open a shell running *as* fin_user:

```powershell
runas /user:fin_user powershell
```

Enter `Lab-Passw0rd!`. A **new PowerShell window** opens, running as fin_user. Confirm
that in the new window before doing anything else:

```powershell
whoami
```

Then one write and one read, in that same window:

```powershell
"fin_user was here" | Out-File C:\Finance\authorized.txt
```

```powershell
Get-Content C:\Finance\authorized.txt
```

Both should succeed — fin_user is in the Finance group — leaving **Success** 4663s. Close
that window.

> **Why a shell and not `runas /user:fin_user "notepad C:\Finance\authorized.txt"`?**
> Notepad quietly offers to save somewhere else when a folder refuses it, so the file
> never lands in `C:\Finance` and afterwards you can't tell whether the access was even
> attempted. A shell does exactly what you typed and reports its own failure out loud.

### 5.2 As the unauthorized user

Back in the administrator window:

```powershell
runas /user:helpdesk powershell
```

Enter `helpdesk`'s password, `whoami` to confirm, then reach for the same file:

```powershell
Get-Content C:\Finance\authorized.txt
```

It should fail with **Access is denied** — helpdesk isn't in the Finance group. The
*attempt* is the evidence, and it lands as a **4656 Failure**, not a 4663. Close the
window.

> If `runas` complains the account can't log on, `helpdesk` may lack "log on locally"
> rights or be disabled — enable it with `Enable-LocalUser -Name helpdesk` and retry. The
> event you want is the access attempt, so any method that makes helpdesk reach into
> `C:\Finance` works.

---

# Step 6 — Detect: who touched the folder, and were they allowed? (WS01)

**Aim: read the three events back and answer the analyst's question — separating the
authorized access from the blocked one, which is the entire job.**

### 6.1 The access attempts — 4663

Start wide, newest first, in **PowerShell** on **WS01**:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4663; StartTime=(Get-Date).AddHours(-1) } -MaxEvents 40 |
  Format-Table TimeCreated, Id -AutoSize
```

That confirms 4663s exist. But the default view hides the answer — every 4663 says the
same boilerplate. Pull the fields **by name**, the way Modules 01/04/05 taught, and keep
only the ones about *your* folder:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4663; StartTime=(Get-Date).AddHours(-1) } -MaxEvents 40 |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
      Time    = $_.TimeCreated
      Who     = ($d | Where-Object Name -eq 'SubjectUserName').'#text'
      Object  = ($d | Where-Object Name -eq 'ObjectName').'#text'
      Access  = ($d | Where-Object Name -eq 'AccessMask').'#text'
    }
  } | Where-Object { $_.Object -like '*Finance*' } | Format-Table -AutoSize
```

Read the `Who` column: you should see **fin_user** rows and **helpdesk** rows against
`C:\Finance\…`. That's the answer — both accounts *reached for* the folder, and now you
have the names and times.

> **`AccessMask` is what they asked to do**, as a hex code: `0x1` read data, `0x2` write
> data, `0x4` append, `0x10000` delete, `0x20000` read control. Multiple 4663s per file
> open are normal — one per right requested. Don't read the *count* as "how many times" —
> read it as "how many kinds of access."

### 6.2 Allowed vs denied — the piece that matters

Every 4663 you just listed is `fin_user`. The denial is not there, and no filter will make
it appear: **4663 fires when a right is *used***, and helpdesk never got that far. The
refusal is a **4656** — the handle request Windows turned down. Start small enough to read
raw:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4656; StartTime=(Get-Date).AddMinutes(-15) }
```

Then pull the fields by name and keep only your folder:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4656; StartTime=(Get-Date).AddMinutes(-15) } |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
      Time   = $_.TimeCreated
      Who    = ($d | Where-Object Name -eq 'SubjectUserName').'#text'
      Object = ($d | Where-Object Name -eq 'ObjectName').'#text'
      Result = $_.KeywordsDisplayNames -join ','
    }
  } | Where-Object { $_.Object -like '*Finance*' } | Format-Table -AutoSize
```

`helpdesk` should appear with **Audit Failure** against `C:\Finance\authorized.txt`.
*That* is the finding: an unauthorized account reached for a sensitive folder, and you can
name it, time it, and prove it was denied.

> **The pair worth memorising.** **4656** = a handle was *requested*, and it carries the
> allow/deny decision. **4663** = a right was *used*, so it only ever exists where access
> succeeded. Watch **4656 Failure** for probing, **4663 Success** for what was actually
> read or written. They come from two different audit subcategories (Step 4.1) — which is
> exactly why one can be silent while the other works perfectly.

### 6.3 The camera install — 4907

This proves the folder was put under watch, and when. A **4907** you didn't expect means
someone changed a camera.

**Go wide on the window.** These config changes happened whenever you ran Steps 3–4, which
may be days ago by the time you read them back. `StartTime` *filters* — it does not search
— so a two-hour window returns nothing and reads exactly like "the events aren't there":

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4907; StartTime=(Get-Date).AddDays(-7) } |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
      Time   = $_.TimeCreated
      Object = ($d | Where-Object Name -eq 'ObjectName').'#text'
    }
  } | Format-Table -AutoSize
```

Expect **several 4907s that are not yours** — Windows audits its own objects. Read the
`Object` column and keep only `C:\Finance`.

> **One apply, several events.** A SACL applies to the folder *and* to each object that
> inherits it, so a single apply writes one 4907 per object, all in the same second.
> Measured on WS01, 2026-09-07: 5 × 4907 in the window, of which **2 were `C:\Finance`**,
> both at **14:47:18 UTC** — the folder plus the one file that existed by then. Same
> second means *one* apply, not two.

### 6.4 Generate a real 4670 — permissions changed

Your Step 3 lock-down wrote no 4670 (auditing wasn't on yet, and `Authorization Policy
Change` was off). Now that both are fixed, make one small reversible change so the event
exists to be read.

**On WS01**, add a harmless ACE and then remove it:

```powershell
icacls C:\Finance /grant "Guests:(R)"
```

```powershell
icacls C:\Finance /remove:g "Guests"
```

Note the time, then read it back — same shape as 6.3, one ID changed:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4670; StartTime=(Get-Date).AddMinutes(-15) } |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
      Time   = $_.TimeCreated
      Who    = ($d | Where-Object Name -eq 'SubjectUserName').'#text'
      Object = ($d | Where-Object Name -eq 'ObjectName').'#text'
    }
  } | Format-Table -AutoSize
```

Two 4670s against `C:\Finance`, `Who` = `Administrator` — one per `icacls` call. That's
the detection you'd alert on: **the lock on a protected folder changed, and here is who
changed it.**

> **If this returns nothing, or returns a row with a blank `Object` and `WS01` as `Who`:**
> the blank-object row is an unrelated system event, not yours. Your change didn't log
> because the SACL is missing the **Change permissions** right — go back to Step 4.2 and
> tick it, then run the two `icacls` commands again. That is exactly what happened on
> 2026-09-07, and it is gate 4 from the table in Step 4.1.

> **Why this is worth doing rather than skipping.** An attacker who widens a folder's
> permissions to reach it leaves exactly this event. It is the difference between
> detecting *access* and detecting the *preparation* for access — and you can only see it
> if `Authorization Policy Change` was already on, which is the whole argument for turning
> the switches on before you need them.

---

# Step 7 — Evidence for the portfolio

Captured 2026-09-07, in `../assets/` (spaceless `02-*` names):

- [x] `02-dacl-before.png` — `icacls C:\Finance-demo` on a freshly created folder, showing
      the inherited default this module removes: **both** `BUILTIN\Users:(I)(OI)(CI)(RX)`
      *and* `NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(M)`. This is a fresh folder
      standing in for the original state, not a saved "before" — `C:\Finance` was already
      locked by the time evidence was collected. Say so when presenting it
- [x] `02-dacl-after.png` — `icacls C:\Finance` showing only
      `BUILTIN\Administrators:(OI)(CI)(F)`, `NT AUTHORITY\SYSTEM:(OI)(CI)(F)` and
      `WS01\Finance:(OI)(CI)(M)`. Both broad ACEs gone, **no `(I)` on any entry** (they are
      explicit now, not inherited), and no leftover `Guests` from Step 6.4. Pairs with the
      above to prove the lock-down
- [x] `02-4656-denied.png` — the **4656 Audit Failure**, `WS01\helpdesk` against
      `C:\Finance\selftext.txt`, 22:40:21 UTC. The best evidence in the module — an
      unauthorized access, named and timed. Note the ID: the denial is a 4656, *not* a 4663
- [x] `02-4663-allowed.png` — the 4663 **Audit Success**, `WS01\fin_user` against
      `C:\Finance`, `AccessMask 0x1`, 14:53:46 UTC — the contrast
- [x] `02-4907-sacl.png` — the 4907 at 15:52:46 UTC whose descriptors show the audited
      rights gaining `WD` (`WRITE_DAC`). This is the evidence for Finding 2's gate 4
- [x] `02-4670-permissions-changed.png` — the 4670 at 15:53:02 UTC, `CORP\Administrator`
      via `icacls.exe`, with `(A;;FR;;;BG)` present in the original descriptor and absent
      from the new one — the `Guests` ACE being removed, visible in the event itself
- [x] `02-auditpol-three-switches.png` — `auditpol /get` for **all three** subcategories
      in one shot, all reading Success and Failure. The evidence behind the module's
      central claim: one switch reading healthy told you nothing about the other two
- [x] `02-sacl-auditing-tab.png` — the Auditing entry for `Everyone` / Type: All /
      *This folder, subfolders and files*, with **Change permissions ticked** — the right
      whose absence suppressed 4670

Then a few sentences in your own words: who touched the folder, who was blocked, and how
you told allowed from denied.

---

# Findings

Written after the run, observation → inference → recommendation, kept strictly separate.
Timestamps are **UTC** — the event stores UTC and Event Viewer only converts for display.
These VMs display local WAT (UTC+1), so every screenshot reads one hour ahead of the times
below.

All times below were read from the event detail panes captured in `assets/` and converted
from the displayed WAT to UTC.

---

### Finding 1 — Unauthorized account attempted access to a protected folder (WS01)

**Observation.**

On **2026-09-05**, `C:\Finance` on WS01 was restricted to the local `Finance` group;
`BUILTIN\Users` and `NT AUTHORITY\Authenticated Users` were removed and inheritance was
disabled. `icacls C:\Finance` shows `WS01\Finance:(OI)(CI)(M)` with no `(I)` flag on the
explicit entries.

The Security log records both halves of the subsequent access test:

| Time (UTC) | Event | Result | Account | Object | Access | Process |
|---|---|---|---|---|---|---|
| 2026-09-05 **14:53:46** | **4663** | Audit Success | `WS01\fin_user` | `C:\Finance` | `0x1` ReadData / ListDirectory | `notepad.exe` |
| 2026-09-05 **22:40:21** | **4656** | Audit Failure | `WS01\helpdesk` | `C:\Finance\selftext.txt` | ReadAttributes | `powershell.exe` |

Both events name `Computer: WS01.corp.local`. `fin_user` is a member of `Finance`;
`helpdesk` is not, and holds no allow entry on the folder — it is denied by absence of
permission, not by an explicit Deny ACE.

The audit configuration itself is timestamped in the same log. Two **4907** events at
**14:47:18 UTC on 2026-09-05** record the SACL being applied to `C:\Finance` — one for the
folder and one for the file it then contained, 6 minutes 28 seconds before the `fin_user`
access above.

On **2026-09-07** a deliberate permission change was generated to produce the missing
4670 (see Finding 2). The sequence is recorded in three events, all subject
`CORP\Administrator` against `C:\Finance`:

| Time (UTC) | Event | Process | What changed |
|---|---|---|---|
| 15:52:46 | **4907** | `explorer.exe` | SACL rights gained `WD` (`WRITE_DAC`) — see Finding 2 |
| 15:52:58 | **4670** | `icacls.exe` | `Guests` granted read |
| 15:53:02 | **4670** | `icacls.exe` | `Guests` removed |

The second 4670's security descriptors show the change explicitly — the original carries
`(A;;FR;;;BG)` (Allow, `FILE_GENERIC_READ`, `BUILTIN\Guests`) and the new one does not.

**Inference.**

I assess with **high confidence** that an account with no authorization to `C:\Finance`
attempted to read a file inside it and was refused by NTFS permissions, and that the
control worked as designed. The 4656 Failure is the refusal itself — Windows declining the
handle request — and the paired 4663 Success for `fin_user` establishes that the folder was
reachable and auditable at the same time, so the denial reflects the permission model
rather than a broken path or an offline share. This maps to **T1083 — File and Directory
Discovery** if such attempts recur across multiple protected locations, and the 4670 events
map to **T1222.001 — File and Directory Permissions Modification (Windows)**, which is the
event an attacker would generate while widening access to reach a folder they cannot
currently open.

**What this evidence does not settle.** It does not establish intent. A single denied read
is not an incident: it is equally consistent with a curious user, a mistyped path, a
backup or indexing process running under the wrong account, and deliberate reconnaissance.
Nor does it establish who was at the keyboard — 4656 names the account, not the person, and
nothing here rules out use of valid credentials by someone other than their owner
(**T1078.003 — Valid Accounts: Local Accounts**). The discriminator is *pattern*, not this
event: a sequence of 4656 Failures from one account across several protected folders in a
short window is reconnaissance; one denial against one file is noise until something else
corroborates it.

**Recommendation.**

1. **Alert on 4656 Audit Failure where `ObjectName` matches the protected path**, rather
   than on 4663 — the refusal is the signal, and 4663 by design never carries it.
   Threshold on *distinct objects per account per hour* so a single mistyped path doesn't
   page anyone while a folder sweep does.
2. **Baseline `Finance` group membership and alert on change.** An attacker who cannot
   read the folder can instead be added to the group that can. That is a **4732** on this
   host (local group), which ties directly to Module 01's group-change detection.
3. **Treat any unexpected 4670 or 4907 against `C:\Finance` as tampering** with the lock or
   the camera respectively, and alarm on them independently of who generated them.
4. **Follow-up queries** if this pattern recurs: all 4656 Failures for the account across
   all paths in the preceding 24 hours; 4624/4625 for the same account to establish how and
   from where it authenticated; and 4732 against `Finance` in the same window.

---

### Finding 2 — Object-access auditing produced silent gaps at three independent layers (WS01)

This is the more consequential finding, and it was discovered by the module failing rather
than succeeding.

**Observation.**

Between 2026-09-05 and 2026-09-07, three separate audit-configuration gaps on WS01 each
caused an expected Security event to be absent from the log, with no error and no warning
in any interface:

| # | Expected event | Cause of absence | Confirmed |
|---|---|---|---|
| 1 | **4656** for a denied access | `Handle Manipulation` subcategory set to **No Auditing** | 2026-09-05 |
| 2 | **4670** for a permission change | `Authorization Policy Change` subcategory set to **No Auditing** | 2026-09-07 |
| 3 | **4670** for a permission change | SACL did not audit `WRITE_DAC` ("Change permissions") | 2026-09-07 |

In each case the checks an analyst would naturally run reported a healthy configuration:

- For gap 1, `auditpol /get /subcategory:"File System"` returned **Success and Failure**,
  and the folder's SACL `AuditFlags` read **Success, Failure**. Both are true statements
  about 4663, which fires only on access that *succeeded*; neither governs the refusal.
- For gap 3, all three subcategories returned **Success and Failure**. Two `icacls`
  permission changes against `C:\Finance` produced **no 4670**. After ticking **Change
  permissions** in the SACL and issuing the identical two commands, two 4670 events
  appeared naming `C:\Finance` and `CORP\Administrator`. Only the SACL's audited rights
  differed between the two attempts.

  The 4907 that recorded that SACL edit contains the proof in its own descriptors:

  ```
  Original:  S:AI(AU;OICISAFA;CCDCLCSWRPWPLOCRRC;;;WD)
  New:       S:ARAI(AU;OICISAFA;CCDCLCSWRPWPLOCRRCWD;;;WD)
  ```

  The audited-rights mask gains exactly one token — **`WD`**, `WRITE_DAC` — and nothing
  else changes. (The trailing `WD` after the semicolons is the trustee, `Everyone`; the
  one that matters is the one appended to the rights string.) Twelve seconds later the
  first 4670 appears. That single token is the entire difference between a permission
  change being recorded and vanishing.

A fourth, structural gap was also observed: the Step 3 lock-down on 2026-09-05 preceded any
audit configuration and produced **no 4670**, because auditing is not retroactive.

Separately, the first SACL application on 2026-09-05 did not persist and wrote **no 4907**.
Because a SACL change that commits to disk writes a 4907 unconditionally, and because the
Security log held approximately 7 MB of a 20 MB maximum at the time (measured 2026-08-24,
~0.26 MB/day) so no rotation had occurred, the absence is evidence in itself.

**Inference.**

I assess with **high confidence** that object-access auditing on Windows is gated at four
independent layers, and that an event reaches the log only when all four are open:

1. The subcategory governing that specific event (`File System` → 4663,
   `Handle Manipulation` → 4656, `Authorization Policy Change` → 4670);
2. The presence of a SACL on the object;
3. The **specific rights** enumerated in that SACL — a per-right gate below the
   subcategory, which suppressed 4670 even with every subcategory correctly enabled;
4. All of the above being in place **before** the activity occurs.

Layers 1 and 3 are the dangerous ones, because both fail silently and both defeat the
obvious verification. Two of the three subcategories involved are off by default on a stock
Windows 11 installation, and no interface surfaces the dependency between an event ID and
the subcategory that feeds it.

I assess with **high confidence** that the first SACL application never committed, rather
than committing and being reverted — a committed change writes a 4907, none exists, and log
rotation is excluded by the volume measurement above. The competing hypothesis (it
committed, logged, and the event was evicted) is not supported by the log's fill state.

For an adversary this is **T1562.002 — Impair Defenses: Disable Windows Event Logging**:
disabling one subcategory, or narrowing an object's SACL, removes a specific detection
while leaving every adjacent check reporting healthy. No log is cleared, so **1102** does
not fire; the telemetry simply stops, and the configuration continues to read as correct.

**What this evidence does not settle.** It does not establish how long these gaps had been
open — `auditpol` reports current state and carries no history, so there is no way from
this evidence to date the configuration or to know what activity went unrecorded while the
subcategories were off. It does not establish whether the same gaps exist on DC01 or on
other hosts; this was measured on a single workstation. And it cannot distinguish a default
installation state from deliberate weakening: on this host the settings were almost
certainly Windows defaults, but the log looks identical either way, which is the point.

**Recommendation.**

1. **Verify auditing per event ID, not per category.** Before relying on any object-access
   detection, confirm the specific subcategory that feeds the specific event —
   `auditpol /get /subcategory:"<name>"` for each of `File System`, `Handle Manipulation`
   and `Authorization Policy Change`. A healthy reading on one says nothing about the
   others.
2. **Audit the SACL's rights, not just its presence.** `Get-Acl -Audit` on protected paths,
   checking that `WRITE_DAC` is included wherever 4670 is expected. A SACL that exists and
   reads "Success, Failure" can still be blind to the change you most want to catch.
3. **Generate a known-good test event after any audit-policy change** and confirm it
   reaches the log. This is the only reliable verification: every static check passed while
   three separate events were being silently dropped.
4. **Monitor for the gaps being reintroduced.** **4719** (system audit policy changed) is
   the event for a subcategory being turned off, and **4907** for a SACL being narrowed.
   Both are the adversary's version of what happened here accidentally, and both should
   alarm.
5. **Enable auditing before the activity, not after.** The Step 3 permission change is
   permanently unrecorded. No later configuration can recover an event that was never
   written — which is the same lesson as Module 04's evidence-loss finding, arriving from
   the opposite direction: there, the record existed and was destroyed; here, it was never
   created.

# Reference

### Reading permissions

| Tool | Use |
|---|---|
| `icacls <path>` | quick, readable DACL — who's allowed and how it inherits |
| `Get-Acl <path> \| Format-List` | the same as PowerShell objects, scriptable |
| Properties → **Security** tab | the DACL in the GUI (the lock) |
| Properties → Security → Advanced → **Auditing** tab | the SACL in the GUI (the camera) |

### ACE shorthand (from `icacls`)

| Flag | Meaning |
|---|---|
| `F` / `M` / `RX` / `R` / `W` | full / modify / read+execute / read / write |
| `(OI)` | object inherit — files below inherit this |
| `(CI)` | container inherit — subfolders inherit this |
| `(I)` | this ACE was itself **inherited** from the parent |

### Event IDs

| ID | Log | Meaning |
|---|---|---|
| **4663** | Security | A right was *used* on an object — exists only where access succeeded |
| **4656** | Security | A handle was *requested* — carries the allow/deny decision; the denied-access event. Needs the `Handle Manipulation` subcategory (Step 4.1) |
| **4670** | Security | Permissions on an object were changed (the DACL / the lock). Needs the `Authorization Policy Change` subcategory (Step 4.1) — *not* `File System` |
| **4907** | Security | Auditing settings on an object were changed (the SACL / the camera). One per object affected, all in the same second |

### AccessMask cheats

| Hex | Right |
|---|---|
| `0x1` | read data / list directory |
| `0x2` | write data / create file |
| `0x4` | append data / create subdirectory |
| `0x10000` | delete |
| `0x20000` | read permissions (read control) |

### MITRE ATT&CK

| Technique | ID | Where it appears here |
|---|---|---|
| File and Directory Permissions Modification | T1222.001 | Step 6.4 permission change (4670) |
| File and Directory Discovery | T1083 | Step 5.2 unauthorized probe (4656 Failure) |
| Impair Defenses: Disable/Modify Auditing | T1562.002 | an unexpected 4907 removing the SACL |

---

## Notes & gotchas

- **The lock and the camera are separate switches.** No 4663 almost always means the
  **SACL is missing** (Step 4.2) or **File System auditing is off** (Step 4.1) — not that
  nothing happened. Check both before concluding "no access." Same "nothing vs can't see
  it" lesson as Module 04.
- **No event at all for a *denied* access means `Handle Manipulation` is off** (Step 4.1).
  This trap cost a run on 2026-09-05: the SACL's `AuditFlags` read `Success, Failure` and
  `auditpol /get /subcategory:"File System"` read `Success and Failure` — and the denial
  still logged nothing, because both of those govern 4663. The 4656 carrying the refusal
  needs a third switch, off by default. Check it *before* generating denied access, not
  after.
- **No 4670 for a permission change you definitely made** has *three* causes, and all
  three bit this module on 2026-09-07. (1) **`Authorization Policy Change` is off** — 4670
  is a *policy* event and comes from neither `File System` nor `Handle Manipulation`.
  (2) **The SACL doesn't audit `WRITE_DAC`** — "Change permissions" is not part of Read &
  execute, Write or Delete, so with the subcategory correctly enabled the change *still*
  logged nothing until that right was ticked (Step 4.2). (3) Most fundamental:
  **auditing is never retroactive.** Step 3's lock-down ran before Step 4 turned anything
  on, so no configuration fixed afterwards can produce that event — it has to be generated
  again (Step 6.4). Turn every gate on *before* the activity you want to see.
- **A 4670 with a blank `ObjectName` and `WS01` as the subject is not yours.** 4670 covers
  many object types, not just files; the machine account changing permissions on some
  system object is routine noise. Filter on `ObjectName -like '*Finance*'` before reading
  anything into a count.
- **Absence of an event is evidence too.** The first SACL apply on 2026-09-05 didn't
  persist, and it wrote **no 4907**. Since a SACL change that reaches disk always writes
  one, that silence says the apply *never committed* — as opposed to committing and being
  reverted later. Check the log hasn't rotated before leaning on an absence (`wevtutil gli
  Security`, per Module 04); here it was 7 MB of 20 MB, so nothing had been evicted.
- **4663 is noisy.** One file open can fire several 4663s (one per right). Filter by
  `ObjectName` and read `AccessMask` as *kinds* of access, not *number* of accesses.
- **4663 doesn't say allowed or denied by itself** — the **Keywords** field
  (`Audit Success` / `Audit Failure`) does, via `KeywordsDisplayNames`. But for a *denied*
  access, don't look for a Failure 4663 at all: use **4656 Failure**, which is the event
  the refusal actually writes.
- **NTFS vs share permissions are two different locks.** This module sets **NTFS** (local,
  on the folder). Over the network, the *effective* permission is the **more restrictive**
  of NTFS and the share's permissions. Local access ignores share permissions entirely —
  which is why this lab works without a share.
- **"Deny beats allow", but you rarely need Deny.** Removing the Allow (Step 3.2) denies
  by absence and is cleaner. An explicit **Deny** ACE overrides *every* Allow, including
  ones inherited later — powerful, and easy to lock yourself out with.
- **Inheritance flows down until you stop it.** You can't reliably remove an inherited ACE
  while inheritance is on (Step 3.1) — it returns. Convert-to-explicit first, then edit.
- **`runas` needs the account able to log on.** If it refuses, `Enable-LocalUser` the
  account; the goal is only to make it *reach* the folder, so any access method counts.
- **Always say which VM.** This whole module is WS01. A file-audit query run on DC01
  returns empty and reads like "no access happened" — it just happened somewhere else.
