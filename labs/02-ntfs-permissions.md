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
5. Find both in the logs (**4663**), plus the permission change (**4670**) and the
   audit-setting change (**4907**), and write up what you found

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
and read the DACL again to prove the lock took.** This is the Build step, and it writes
your first detection event (**4670**, a permission change).

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
2. **Add → Select a principal →** type `Finance` → **Check Names → OK**.
3. Tick **Modify** (which includes Read & write) → **OK**.
4. Leave `Administrators` and `SYSTEM` alone — you always keep an admin path in.
5. **Apply → OK** out of every window.

### 3.3 Prove the lock took

Back in **PowerShell** on **WS01**:

```powershell
icacls C:\Finance
```

`BUILTIN\Users` should be **gone**, and `WS01\Finance:(OI)(CI)(M)` should be present. No
`(I)` on your new entries — they're explicit now, not inherited. The lock is real and you
can *show* it changed, which is the whole point of reading before and after.

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

### 4.2 Point the camera at the folder — the SACL (writes 4907)

Back in **File Explorer → `C:\Finance` → Properties → Security → Advanced → Auditing tab**:

1. **Add → Select a principal →** type `Everyone` → **OK**. (Audit *everyone* — you want
   to catch the unauthorized user, who isn't in any group you'd name.)
2. **Type: All** (records both successful and failed attempts).
3. Tick **Read & execute**, **Write**, and **Delete** (enough to prove access without
   drowning in noise).
4. **OK** out of every window.

The moment you apply that SACL, Windows writes a **4907** ("auditing settings on an object
were changed") — your first evidence, and proof the camera was *installed* and when.

---

# Step 5 — Break: touch the folder as both users (WS01)

**Aim: generate the two events that matter — an allowed access and a denied one — so
Step 6 can tell them apart in the log.** Note the **time before each**; you'll filter by
it. Everything here is benign.

### 5.1 As the authorized user

Two ways; pick the one you're comfortable with on **WS01**.

- **Simple:** sign out, log in as **`fin_user`** / `Lab-Passw0rd!`, open
  `C:\Finance` in File Explorer, create a text file inside it, open and save it, then log
  back in as `administrator`.
- **Faster (no sign-out):** in a PowerShell window, run one command *as* fin_user:

  ```powershell
  runas /user:fin_user "notepad C:\Finance\authorized.txt"
  ```

  (Enter fin_user's password when prompted; type something, save, close.)

This should **succeed** — fin_user is in the Finance group. It leaves **Success** 4663s.

### 5.2 As the unauthorized user

```powershell
runas /user:helpdesk "notepad C:\Finance\blocked.txt"
```

Enter `helpdesk`'s password. When Notepad tries to save into `C:\Finance`, it should be
**refused** ("You don't have permission to save in this location"). Save it to the Desktop
instead or just close it — the *attempt* is what you're after. This leaves **Failure**
4663s: someone reached for the folder and Windows said no.

> If `runas` complains the account can't log on, `helpdesk` may lack "log on locally"
> rights or be disabled — enable it with `Enable-LocalUser -Name helpdesk` and retry. The
> event you want is the *access attempt*, so any method that makes helpdesk reach into
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

4663 alone tells you *who reached*, not whether they *got in*. The allow/deny split lives
in the **Keywords** field — `Audit Success` vs `Audit Failure`:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4663; StartTime=(Get-Date).AddHours(-1) } -MaxEvents 40 |
  Where-Object { $_.Message -like '*Finance*' } |
  Select-Object TimeCreated,
    @{ n='Who';    e={ (([xml]$_.ToXml()).Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text' } },
    @{ n='Result'; e={ $_.KeywordsDisplayNames -join ',' } } |
  Format-Table -AutoSize
```

`helpdesk` rows should read **Audit Failure**; `fin_user` rows **Audit Success**. *That*
is the finding: an unauthorized account was blocked reaching for a sensitive folder, and
you can name it, time it, and prove it was denied.

> **The related event to know:** **4656** ("a handle to an object was requested") is the
> cleaner allow/deny signal — it carries an explicit success/failure and fires when the
> handle is *asked for*, where 4663 fires on the *use*. If you want the sharpest "denied"
> alert, watch 4656 Failure. This lab uses 4663 because it's the roadmap's core ID and the
> Keywords split is enough to see it.

### 6.3 The two config changes — 4670 and 4907

These prove *the folder itself* was re-secured and put under watch — the tamper-relevant
events. A 4670 or 4907 you didn't expect means someone changed a lock or a camera.

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4670,4907; StartTime=(Get-Date).AddHours(-2) } |
  Format-Table TimeCreated, Id, @{ n='Object'; e={ (([xml]$_.ToXml()).Event.EventData.Data | Where-Object Name -eq 'ObjectName').'#text' } } -AutoSize
```

- **4670** — permissions changed (your Step 3 lock-down).
- **4907** — auditing settings (SACL) changed (your Step 4.2 camera install).

---

# Step 7 — Evidence for the portfolio

Save into `../assets/` (spaceless `02-*` names):

- [ ] `02-dacl-before-after.png` — `icacls C:\Finance` before (with `BUILTIN\Users`) and
      after (with `WS01\Finance`, no Users) side by side — proof of the lock-down
- [ ] `02-4663-denied.png` — the 4663 **Audit Failure** for `helpdesk` against
      `C:\Finance` (the best evidence in the module — an unauthorized access, named and
      timed)
- [ ] `02-4663-allowed.png` — a 4663 **Audit Success** for `fin_user`, for contrast
- [ ] `02-4907-sacl.png` — the 4907 showing the SACL was applied (the camera install)

Then a few sentences in your own words: who touched the folder, who was blocked, and how
you told allowed from denied.

---

# Findings

**Write after the run**, observation → inference → recommendation, kept strictly separate.
State timestamps in **UTC** (the event stores UTC; Event Viewer only converts for display,
and these VMs display local WAT, so subtract one hour). One is set up for you:

### Finding — Unauthorized access attempt on C:\Finance (WS01)

Observation: the 4663 **Audit Failure** naming `helpdesk`, the `ObjectName`
(`C:\Finance\…`), the `AccessMask`, and the time in UTC; alongside the 4663 **Audit
Success** for `fin_user`, and the 4907/4670 that show when the folder was secured and put
under audit.

Inference: labelled judgement — an account with no authorization reached for a protected
folder and was denied (**T1222.001** file/directory permissions context, **T1083**
File and Directory Discovery if the pattern is *probing many* folders). Be explicit about
what the logs settle (that `helpdesk` was denied, and when) versus what they don't (whether
it was a curious user or a real intrusion — one denied read is not yet an incident; a
*sequence* of denials across many folders is the escalation signal to watch for).

Recommendation: specific follow-ups — alert on 4663/4656 **Failure** against
`C:\Finance`; baseline who's in the `Finance` group so additions stand out (ties back to
Module 01's 4732 group-change events); and treat any unexpected **4670** or **4907** on
this folder as tampering with the lock or the camera.

---

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
| **4663** | Security | An attempt was made to access an object — Success or Failure via Keywords |
| **4656** | Security | A handle to an object was requested — the cleaner allow/deny signal |
| **4670** | Security | Permissions on an object were changed (the DACL / the lock) |
| **4907** | Security | Auditing settings on an object were changed (the SACL / the camera) |

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
| File and Directory Permissions Modification | T1222.001 | Step 3 lock-down (4670) |
| File and Directory Discovery | T1083 | Step 5.2 unauthorized probe (4663 Failure) |
| Impair Defenses: Disable/Modify Auditing | T1562.002 | an unexpected 4907 removing the SACL |

---

## Notes & gotchas

- **The lock and the camera are separate switches.** No 4663 almost always means the
  **SACL is missing** (Step 4.2) or **File System auditing is off** (Step 4.1) — not that
  nothing happened. Check both before concluding "no access." Same "nothing vs can't see
  it" lesson as Module 04.
- **4663 is noisy.** One file open can fire several 4663s (one per right). Filter by
  `ObjectName` and read `AccessMask` as *kinds* of access, not *number* of accesses.
- **4663 doesn't say allowed or denied by itself** — the **Keywords** field
  (`Audit Success` / `Audit Failure`) does, via `KeywordsDisplayNames`. For a crisp
  denied-access alert, prefer **4656 Failure**.
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
