# Module 01 — Users & Groups

> **Runs on:** DC01 and WS01 (both powered on)
> **Time:** ~2 hours, in one sitting or split up
> **Roll back to:** `01-domain-ready` · **Snapshot before starting:** `mod01-start`

---

## What you're going to do

Accounts are how attackers get in and stay in. They create accounts for persistence, add
themselves to powerful groups to escalate, and every one of those actions leaves a
specific event behind.

In this module you will:

1. Create users and groups — locally on WS01, then in the domain on DC01
2. Play attacker: create a backdoor admin, and guess a user's password until they lock out
3. Find both of those in the logs, and write up what you found

Follow the steps in order. Each one says **which VM** to run it on.

**Accounts used in this module**

| Account | Password | Where |
|---|---|---|
| `helpdesk` | `Lab-Passw0rd!` | local to WS01 |
| `asmith@corp.local` | `Lab-Passw0rd!` | domain |
| `svc_backup@corp.local` | `Temp-Passw0rd!` | domain (the fake backdoor) |

> **About the `\` character.** Your keyboard has produced the wrong character for `\`
> before, which breaks logins like `CORP\asmith`. This module uses the
> `name@corp.local` form everywhere instead — it means the same thing and avoids the
> problem entirely.

---

# Step 0 — Pre-flight

### 0.1 Start from a known state

Both VMs powered off. For each one: select it → **Snapshots** → restore
**`01-domain-ready`**.

Then start **DC01 first**, wait for its login screen, then start **WS01**.

### 0.2 Turn on auditing (DC01)

Windows does not log everything out of the box. This turns on the categories this
module needs. **Module 00 never did this**, so it has to happen here.

Log into DC01 as `administrator@corp.local` / `Lab-Passw0rd!`.

Right-click **Start → Windows PowerShell (Admin)**, and paste this whole block:

```powershell
auditpol /set /subcategory:"User Account Management"      /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management"    /success:enable /failure:enable
auditpol /set /subcategory:"Logon"                        /success:enable /failure:enable
auditpol /set /subcategory:"Logoff"                       /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout"              /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation"        /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
```

Each line should answer `The command was successfully executed.`

Check it took. Dump everything and filter to the lines that matter:

```powershell
auditpol /get /category:* | Select-String "Account Management|Logon|Logoff|Lockout|Credential Validation|Kerberos"
```

Every subcategory you enabled above should read **Success and Failure**.

> **Don't name categories with a comma.** `auditpol /get /category:"A","B"` looks
> reasonable, but PowerShell splits on the comma before `auditpol` sees it and you get
> `Error 0x00000057 The parameter is incorrect.` Use the `*` wildcard above, or query
> one category per command.
>
> `auditpol` also needs an elevated session — the window title must say
> **Administrator:**. Without it you get `Error 0x00000522: A required privilege is not
> held by the client`.

### 0.3 Turn on auditing (WS01)

Log into WS01 as `administrator@corp.local` / `Lab-Passw0rd!`.

Right-click **Start → Terminal (Admin)** and paste:

```powershell
auditpol /set /subcategory:"Logon"   /success:enable /failure:enable
auditpol /set /subcategory:"Logoff"  /success:enable /failure:enable
```

### 0.4 Snapshot

Shut both VMs down, snapshot each as **`mod01-start`**, then start them both again
(DC01 first). This is what you roll back to if you want to repeat the module.

---

# Step 1 — Local accounts (WS01)

Local accounts live only on this one machine. The domain knows nothing about them.

In **Terminal (Admin)** on WS01:

```powershell
$pw = ConvertTo-SecureString "Lab-Passw0rd!" -AsPlainText -Force
New-LocalUser -Name "helpdesk" -FullName "Helpdesk Tech" -Description "Local support" -Password $pw
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "helpdesk"
```

Look at what you made:

```powershell
Get-LocalUser
Get-LocalGroupMember -Group "Remote Desktop Users"
Get-LocalGroupMember -Group "Administrators"
```

**What you should see:** `helpdesk` in the user list and in Remote Desktop Users, but
**not** in Administrators.

---

# Step 2 — Names vs. SIDs (WS01)

A name is a label you can change. The **SID** is the identity Windows actually enforces
permissions against.

```powershell
Get-LocalUser helpdesk | Select-Object Name, SID
```

You'll get something like `S-1-5-21-1004336348-1177238915-682003330-1004`.

The last number is the **RID**, and a few are fixed everywhere in the world:

| RID | Who it is |
|---|---|
| `500` | the real built-in Administrator |
| `512` | Domain Admins |
| `501` | Guest |

**Why an analyst cares:** renaming the Administrator account does *not* change its SID.
An attacker using the renamed account still shows up as `…-500`. So when you hunt, you
pivot on the SID, not the name — names lie.

---

# Step 3 — A domain account (DC01)

Switch to **DC01**. Domain accounts live in Active Directory and work on every machine
in `corp.local`.

```powershell
$pw = ConvertTo-SecureString "Lab-Passw0rd!" -AsPlainText -Force
New-ADUser -Name "asmith" -SamAccountName "asmith" `
  -UserPrincipalName "asmith@corp.local" `
  -Path "CN=Users,DC=corp,DC=local" `
  -AccountPassword $pw -Enabled $true
```

Check it:

```powershell
Get-ADUser asmith -Properties MemberOf | Select-Object Name, SID, Enabled, MemberOf
```

**What you should see:** `Enabled : True`, and `MemberOf` empty — every domain user is
automatically in **Domain Users**, which doesn't show in this list because it's their
*primary* group.

---

# Step 4 — The groups attackers want (DC01)

Learn these. They are the escalation targets you will watch for the rest of your career.

| Group | Why it's a prize |
|---|---|
| **Domain Admins** | Full control of the whole domain |
| **Enterprise Admins** | Full control of the entire forest |
| **Administrators** (on a host) | Full control of that one machine |
| **Backup Operators** | Can read *any* file — including the AD database, `NTDS.dit` |
| **Account Operators** | Can create and modify most accounts |
| **Remote Desktop Users** | Remote interactive access — how attackers move sideways |

See who's in the crown jewel right now:

```powershell
Get-ADGroupMember "Domain Admins" | Select-Object name, objectClass
```

**What you should see:** just `Administrator`. Remember that — you're about to change it.

---

# Step 5 — Attack #1: the backdoor admin (DC01)

This is one of the most common persistence moves there is: make an account that looks
like a service account, then quietly give it full domain control.

Run these **one at a time**, and note the time.

```powershell
# 1) Create the fake service account
$pw = ConvertTo-SecureString "Temp-Passw0rd!" -AsPlainText -Force
New-ADUser -Name "svc_backup" -SamAccountName "svc_backup" `
  -UserPrincipalName "svc_backup@corp.local" `
  -Path "CN=Users,DC=corp,DC=local" `
  -AccountPassword $pw -Enabled $true
```

```powershell
# 2) Escalate it — this is the line that should wake somebody up
Add-ADGroupMember "Domain Admins" -Members "svc_backup"
```

```powershell
# 3) Confirm the damage
Get-ADGroupMember "Domain Admins" | Select-Object name
```

Leave `svc_backup` in place for now — you'll clean it up in Step 9, after you've found
it in the logs.

---

# Step 6 — Detect attack #1 (DC01)

Two ways to do this. Do **both** — the GUI teaches you what the event looks like, the
query teaches you how to hunt at scale.

### 6.1 In Event Viewer (the picture)

**Start → Event Viewer → Windows Logs → Security.**

Click **Filter Current Log…** on the right, put `4720,4728` in the **Event IDs** box,
click OK.

You should see a **4728** (member added to a group) and a **4720** (account created)
seconds apart. Click the 4728 and read the **General** tab:

| Field | What it tells you |
|---|---|
| **Subject → Account Name** | *who did it* — `Administrator` |
| **Member → Security ID** | *who was added* — `svc_backup`'s **SID** |
| **Group → Group Name** | `Domain Admins` |

Note that **Member** gives you a *SID*, not a name — often with **Member → Account Name**
showing `-`. That's the Step 2 RID lesson turning up in a real event. The **Group** field
does resolve to a name, because the group was resolved locally.

📸 **Screenshot this one.** It's your best piece of evidence for the write-up.

### 6.2 With PowerShell (the hunt)

Accounts created in the last day:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4720; StartTime=(Get-Date).AddDays(-7) } |
  ForEach-Object {
    [pscustomobject]@{
      Time    = $_.TimeCreated
      NewUser = $_.Properties[0].Value
      By      = $_.Properties[4].Value
    }
  } | Format-Table -AutoSize
```

Additions to any privileged group — the high-signal query:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4728,4732,4756; StartTime=(Get-Date).AddDays(-7) } |
  ForEach-Object {
    [pscustomobject]@{
      Time   = $_.TimeCreated
      Member = $_.Properties[0].Value
      Group  = $_.Properties[2].Value
      By     = $_.Properties[6].Value
    }
  } | Format-Table -AutoSize
```

📸 **Screenshot this output too.**

> **`StartTime` filters, it does not search.** Anything older than the window is
> invisible even though it's sitting in the log. When hunting something historical,
> start wide (`AddDays(-7)`) and narrow down — a too-narrow window returns nothing and
> looks exactly like an absence of evidence.
>
> Note also that `-MaxEvents` caps the **total** returned, newest first. Mixing rare
> events (4720, 4728) with high-volume ones (4624, 4768) in a single query lets the
> noisy IDs consume every slot, and the rare ones fall off the end. Query rare
> account-management events separately from the authentication baseline.

**Read it like an analyst:** an account created and added to Domain Admins within
seconds, outside a change window, by an account that doesn't normally do user admin.
That's not administration — that's persistence plus privilege escalation, and it's a
page-someone-at-3am alert.

---

# Step 7 — Attack #2: guessing a password until lockout

### 7.1 Turn on a lockout policy (DC01)

Fresh domains have **no lockout policy at all** — you can guess forever. Fix that first,
which is both a real hardening step and what makes the next part generate a `4740`.

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity corp.local `
  -LockoutThreshold 5 `
  -LockoutDuration 00:10:00 `
  -LockoutObservationWindow 00:10:00

Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration
```

Five bad tries within 10 minutes locks the account for 10 minutes.

### 7.2 Guess the password (WS01)

On **WS01**, sign out of the current session (**Start → your account picture → Sign
out**). At the login screen click **Other user**.

Now, **five times in a row**:

- Username: `asmith@corp.local`
- Password: `WrongPassword123`

You'll get "The user name or password is incorrect" each time. On the **fifth or sixth**
attempt the message changes to say the account is locked out. That's the policy working.

### 7.3 Unlock and log in properly (DC01, then WS01)

On **DC01**:

```powershell
Get-ADUser asmith -Properties LockedOut | Select-Object Name, LockedOut
Unlock-ADAccount -Identity asmith
```

Then on **WS01**, log in as `asmith@corp.local` / `Lab-Passw0rd!`. First login takes a
minute or two while Windows builds the profile — that's normal.

Once you're in, open PowerShell and run `whoami` — it should say `corp\asmith`.

---

# Step 8 — Detect attack #2

This is the important lesson in the whole module: **the failure is recorded in two
different places, and they say different things.**

### 8.1 On WS01 — the machine where it was typed

Sign back in as `administrator@corp.local` and open **Terminal (Admin)**:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-7) } |
  ForEach-Object {
    [pscustomobject]@{
      Time = $_.TimeCreated
      User = $_.Properties[5].Value
      Type = $_.Properties[10].Value
    }
  } | Format-Table -AutoSize
```

**What you should see:** five `4625` failures for `asmith`, all **Type 2** — interactive,
i.e. someone physically at that keyboard.

### 8.2 On DC01 — the machine that made the decision

WS01 didn't check the password; it asked the domain controller. So DC01 has its own
record:

```powershell
# Kerberos pre-authentication failures — "wrong password" in AD terms
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4771; StartTime=(Get-Date).AddDays(-7) } |
  Select-Object TimeCreated, @{n='User';e={ $_.Properties[0].Value }}, `
                @{n='From';e={ $_.Properties[6].Value }} |
  Format-Table -AutoSize
```

```powershell
# The lockout itself
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4740; StartTime=(Get-Date).AddDays(-7) } |
  Select-Object TimeCreated, @{n='LockedAccount';e={ $_.Properties[0].Value }}, `
                @{n='FromComputer';e={ $_.Properties[1].Value }} |
  Format-Table -AutoSize
```

```powershell
# And the successful login that followed
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4768; StartTime=(Get-Date).AddDays(-7) } |
  Select-Object TimeCreated, @{n='User';e={ $_.Properties[0].Value }} -First 5 |
  Format-Table -AutoSize
```

📸 **Screenshot the 4740 and the 4771 output.**

**The mental model to keep:**

| Where | What it knows |
|---|---|
| **WS01** | "Someone at *my* keyboard failed to log in" (4625) |
| **DC01** | "Someone *somewhere in the domain* failed, and here's which machine" (4771, 4740) |

The DC sees the whole domain's authentication. That's why, in a real SOC, DC logs are
the first thing you forward to the SIEM.

**And the pattern that matters:** a burst of failures for one account followed by a
success is a password guess that *worked*. Your next question is always "what did that
session then do?" — which is Module 05, process creation.

---

# Step 9 — Clean up (DC01)

```powershell
Remove-ADGroupMember "Domain Admins" -Members "svc_backup" -Confirm:$false
Remove-ADUser "svc_backup" -Confirm:$false
Get-ADGroupMember "Domain Admins" | Select-Object name
```

**What you should see:** just `Administrator` again.

Notice that removing the account generated *more* events — `4729` (removed from group)
and `4726` (account deleted). Attackers clean up after themselves too, and the cleanup
is itself evidence.

---

# Step 10 — Evidence for the portfolio

Save screenshots into `../assets/` with these names:

- [ ] `01-4728-domain-admins.png` — the 4728 in Event Viewer, showing `svc_backup` →
      Domain Admins
- [ ] `01-privileged-group-query.png` — the PowerShell output from 6.2
- [ ] `01-4740-lockout.png` — the lockout event on DC01
- [ ] `01-4625-failures.png` — the failed logons on WS01

Then write a few sentences **in your own words** — this is the part that shows you can
think, not just run commands:

> At 14:03 the account `svc_backup` was created on DC01 (4720) and 11 seconds later
> added to Domain Admins (4728), both by `CORP\Administrator`. No change ticket
> corresponds to this window. A create-then-escalate sequence this fast is automation,
> not a human doing account admin, and maps to persistence (T1136.002) followed by
> privilege escalation (T1098). Recommended response: disable the account, review all
> sessions authenticated by it, and audit Domain Admins membership against the approved
> list.

---

# Findings

Written from this lab run. Each follows **observation → inference → recommendation**,
with the three kept strictly separate: observation is only what the log literally says,
inference is labelled judgement, recommendation is what should happen next.

## Finding 1 — Backdoor domain administrator

**OBSERVATION.** On DC01 (Security log), 2026-08-11 at 02:50:04 local time, event
**4720** recorded creation of the domain account `svc_backup` by `CORP\Administrator`.
At 02:50:59 — 55 seconds later — event **4728** recorded that account being added to the
security-enabled global group **Domain Admins**, by the same subject. Domain Admins
previously contained only the built-in `Administrator` account. No corresponding change
ticket exists.

**INFERENCE.** The account name follows service-account convention, a common
masquerading choice (T1036) intended to blend with legitimate infrastructure and survive
casual review. Domain Admins confers full control of `corp.local`, so this is privilege
escalation rather than routine group assignment. I assess with high confidence that this
is persistence (T1136.002) followed by privilege escalation (T1098). The 55-second
interval is consistent with a human issuing two commands, not automation. I cannot
determine from these logs how `Administrator` credentials were obtained.

**RECOMMENDATION.**
1. Disable `svc_backup` immediately — do not delete; preserve it for investigation.
2. Identify all activity by the account: search 4624 and 4768 by its SID, then 4688
   process creation within any resulting sessions.
3. Audit current Domain Admins membership against the approved list.
4. Investigate `Administrator` itself — it is the subject of both events. Review its
   recent logons for source host and logon type.
5. Preserve the DC01 Security log before rotation.

**Evidence:** `assets/01-4728-domain-admins.png`, `assets/01-privileged-group-query.png`

## Finding 2 — Account lockout following repeated authentication failures

**OBSERVATION.** On DC01 (Security log), 2026-08-16 at 04:14:36 local time, event
**4771** recorded a Kerberos pre-authentication failure for `asmith@corp.local` with
failure code **0x18** (bad password), from client address 10.0.0.20. Four further 4771
events for the same account followed through 04:15:01, at which point event **4740**
recorded the account locked out, with Caller Computer Name **WS01** — consistent with the
domain lockout policy of 5 failed attempts within a 10-minute window. Corresponding
**4625** events on WS01 over the same window show **Logon Type 2**, indicating the
attempts were made interactively at that machine's console.

**INFERENCE.** All five pre-authentication attempts failed with code 0x18; no successful
authentication for `asmith` occurred before the lockout, so the password was not guessed
correctly during this sequence. A successful logon for the same account followed after
the account was unlocked. This establishes that valid credentials were used at that
point, but does **not** establish that the preceding attempts produced them — sequence
alone does not demonstrate causation.

Two explanations fit the evidence. The failures and subsequent success are consistent
with a legitimate user mistyping their password, being locked out by policy, and being
unlocked through normal administrative action — by far the more common pattern, and I
assess it the more likely here given all attempts originated from a single domain-joined
workstation console. The alternative, that credentials were obtained by other means
between lockout and success, cannot be excluded from these logs alone.

**RECOMMENDATION.**
1. **Confirm with the account owner.** Establish whether `asmith` locked themselves out.
   This resolves the ambiguity faster than any query.
2. **Retrieve the discriminating events.** Pull 4767 (account unlocked) and 4723/4724
   (password change or admin reset). A reset preceding the successful logon rules out
   the guessed password having been used.
3. **Review the resulting session.** Take the Logon ID from the successful 4624 and
   enumerate 4688 process creation within it.
4. **If compromise cannot be excluded**, force a password reset, terminate active
   sessions, and monitor the account for 30 days.
5. **Retain the lockout policy.** `corp.local` had no lockout policy configured before
   2026-08-16; unlimited password attempts were possible domain-wide.
6. **Detection improvement.** A single 4740 is routine and should not alert. Alert on
   the patterns that aren't: one account locked from multiple source hosts, several
   accounts locked within a short window (password spraying), or sustained 4771 `0x18`
   failures against a single account outside business hours.
7. **Preserve** the DC01 and WS01 Security logs covering 04:00–05:00 on 2026-08-16.

**Evidence:** `assets/01-4740-lockout.png`, `assets/01-4625-failures.png`

> **Open items in Finding 2.** The successful logon timestamp is not yet recorded, and
> the 4767 / 4723 / 4724 events named in recommendations 1–2 have not been pulled, so
> the two hypotheses remain unresolved. Fill these in before treating this finding as
> complete.

### Baseline artifact noted during this run

Historical 4728 events with an `ANONYMOUS LOGON` subject were identified as
domain-creation artifacts from DC promotion on 2026-08-09 and excluded from Finding 1.
Distinguishing baseline from incident is most of what triage actually is.

---

# Reference

### Event IDs from this module

| ID | Logged on | Meaning |
|---|---|---|
| 4720 | DC01 | Account **created** |
| 4722 | DC01 | Account enabled |
| 4725 | DC01 | Account disabled |
| 4726 | DC01 | Account **deleted** |
| 4728 | DC01 | Member added to a **global** group (e.g. Domain Admins) |
| 4729 | DC01 | Member **removed** from a global group |
| 4732 | either | Member added to a **local** group |
| 4756 | DC01 | Member added to a **universal** group |
| 4624 | where it happened | **Successful** logon — always read the Logon Type |
| 4625 | where it happened | **Failed** logon |
| 4740 | DC01 | Account **locked out** |
| 4768 | DC01 | Kerberos ticket granted — a domain logon succeeded |
| 4771 | DC01 | Kerberos pre-auth **failed** — usually a wrong password |

### Logon Types — memorize these

| Type | Meaning |
|---|---|
| **2** | Interactive — at the console |
| **3** | Network — file share, SMB |
| **4** | Batch — scheduled task |
| **5** | Service |
| **10** | RemoteInteractive — **RDP** |

Type 10 at 3am from an unusual source is a classic starting point for an investigation.

### MITRE ATT&CK

| Technique | ID | Where in this module |
|---|---|---|
| Create Account: Domain Account | T1136.002 | Step 5.1 |
| Account Manipulation | T1098 | Step 5.2 |
| Brute Force: Password Guessing | T1110.001 | Step 7.2 |
| Valid Accounts: Domain Accounts | T1078.002 | Step 7.3 |

---

# If something goes wrong

**No 4720 / 4728 events at all.**
Auditing didn't stick. Re-run Step 0.2 on DC01 and check with
`auditpol /get /category:"Account Management"`. Group Policy refresh can occasionally
overwrite local audit settings — if events stop appearing later, just run it again.

**`auditpol` returns `Error 0x00000057 The parameter is incorrect.`**
You combined two categories with a comma. PowerShell splits the argument before
`auditpol` receives it. Run one category per command, or use `auditpol /get /category:*`
to dump everything at once.

**`auditpol` returns `Error 0x00000522: A required privilege is not held by the client.`**
The PowerShell window isn't elevated. Close it and open it with right-click
**Start → Windows PowerShell (Admin)**.

**`Get-WinEvent` says "No events were found that match the specified criteria".**
That's not an error, it's an empty result. Work through these in order — this is the
most common wall in the whole module:

1. **Wrong machine.** `hostname` first. Domain account events (4720, 4728, 4740, 4771)
   are written on **DC01 only**. Workstation logon failures (4625) are on **WS01**.
   Running either query on the other box returns an empty table, not an error.
2. **Window too narrow.** Drop `StartTime` entirely and bound with `-MaxEvents 20`
   instead. If rows appear, the events were always there and only the window was wrong.
3. **Noise ate the results.** See the `-MaxEvents` note in Step 6.2 — high-volume IDs
   crowd out rare ones.
4. **Auditing genuinely off.** Only now is this worth checking:
   ```powershell
   auditpol /get /category:* | Select-String "User Account Management|Security Group Management"
   ```
   If this reads `No Auditing`, the events were never written and no query recovers
   them — re-run Step 0.2 and repeat the attack. Note that restoring the
   `01-domain-ready` snapshot reverts Step 0.2, since that snapshot predates it.

**A column in the query output looks wrong or empty.**
The `Properties[n]` positions differ per event ID. Stop guessing indices — ask for the
fields **by name**:
```powershell
$e = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4728 } -MaxEvents 1
([xml]$e.ToXml()).Event.EventData.Data | Format-Table Name, '#text' -AutoSize
```
That prints every field with its label. Do it once per event ID and you'll never guess
a position again.

**The summary column shows "A user account was created" but no account name.**
The first line of `.Message` is only the event's title. Either read the full text with
`Format-List TimeCreated, Message`, or pull `TargetUserName` / `SubjectUserName` by
name using the XML method above. Easiest of all: read it in Event Viewer, where the
General tab labels and resolves everything for you.

**A 4771 shows "Type: 2" — that is not a Logon Type.**
4771 has no Logon Type field. What you're seeing is **Pre-Authentication Type 2**
(`PA-ENC-TIMESTAMP`), the standard password-based Kerberos mechanism. It says nothing
about consoles or keyboards. Interactive-versus-network evidence comes from the
**4625 Logon Type on WS01**. What 4771 *does* give you is the **Failure Code** —
`0x18` is a bad password, `0x12` means the account is locked, disabled, or expired.

**A 4728 whose Subject is `ANONYMOUS LOGON`.**
Check the timestamp before escalating. Domain promotion populates the built-in groups,
and those membership events are logged with system-level or anonymous subjects. A 4728
dated to your domain build is a baseline artifact, not an incident. Compare against:
```powershell
Get-ADObject (Get-ADDomain).DistinguishedName -Properties whenCreated | Select-Object whenCreated
```

**The account never locked out.**
Step 7.1 didn't apply, or you spread the attempts over more than 10 minutes. Check with
`Get-ADDefaultDomainPasswordPolicy` and do the five tries quickly.

**`Add-ADGroupMember` says the server is not operational.**
DC01 hasn't finished booting, or you're running it on WS01 by mistake. All the `-AD`
cmdlets in this module run on DC01.

**Login as `asmith@corp.local` is rejected but the password is right.**
Check the account isn't still locked: on DC01,
`Get-ADUser asmith -Properties LockedOut | Select-Object LockedOut`.

---

**Next:** → [Module 02 — NTFS Permissions & File Auditing](./02-ntfs-permissions.md) *(not written yet)*
