# Module 01 — Users & Groups

> **Part:** I (Windows Administration)
> **Runs on:** DC01 (domain accounts) + WS01 (local accounts)
> **Est. time:** ~2–3 hours
> **Snapshot before starting:** `mod01-start`

---

## 1. Objective & SOC relevance

Accounts are the currency of every intrusion. Attackers create them for persistence,
add themselves to privileged groups for escalation, and their logons — successful and
failed — are the single most-triaged event class in any SOC. This module builds fluency
in creating and managing local and domain accounts, and in reading the authentication
and account-management events they generate.

**By the end you can:**
- [ ] Create/modify/delete local and domain users and groups from PowerShell
- [ ] Explain the difference between a SID and an account name, and why SIDs matter
- [ ] Identify the high-value built-in groups an attacker targets
- [ ] Read a 4624 and state the **Logon Type** and source
- [ ] Detect account creation, privileged-group changes, and logon brute force in the logs

---

## 2. Pre-flight

- Both VMs powered on, WS01 joined to `corp.local`.
- Command-line + logon auditing enabled (Phase 5 of the build guide). Verify on DC01:
  ```powershell
  auditpol /get /category:"Account Management","Logon/Logoff"
  ```
  Every listed subcategory should read **Success and Failure** (or at least Success).
- Take a snapshot of **both** VMs named `mod01-start`.

---

## 3. Build

### 3.1 — Local accounts on WS01

Log into WS01 as a local admin. Open **PowerShell as Administrator**.

```powershell
# Create a local user (you'll be prompted for a password)
New-LocalUser -Name "helpdesk" -FullName "Helpdesk Tech" -Description "Local support"

# Add them to a built-in group
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "helpdesk"

# Inspect
Get-LocalUser
Get-LocalGroupMember -Group "Administrators"
```

**Understand the SID.** A name is a label; the SID is the identity Windows actually
enforces on:

```powershell
Get-LocalUser helpdesk | Select-Object Name, SID
```

Expected — note the `S-1-5-21-…-<RID>` form. The trailing RID matters: `500` is always
the real Administrator, `512` is Domain Admins. Renaming the Administrator account does
**not** change its SID, which is exactly why "rename Administrator" is weak as a control
and why analysts pivot on SID, not name.

### 3.2 — Domain accounts on DC01

Log into DC01 as **CORP\Administrator**. In PowerShell:

```powershell
# A standard domain user
$pw = Read-Host -AsSecureString "Password for asmith"
New-ADUser -Name "asmith" -SamAccountName "asmith" `
  -UserPrincipalName "asmith@corp.local" `
  -Path "CN=Users,DC=corp,DC=local" `
  -AccountPassword $pw -Enabled $true

# Confirm
Get-ADUser asmith -Properties MemberOf | Select-Object Name, SID, Enabled, MemberOf
```

### 3.3 — Meet the high-value groups

Know these cold — they're the escalation targets an analyst watches:

| Group | Why attackers want it |
|-------|-----------------------|
| **Domain Admins** | Full control of the domain |
| **Enterprise Admins** | Full control of the entire forest |
| **Administrators** (on a host) | Full control of that machine |
| **Backup Operators** | Can read any file / back up the DC database (NTDS.dit) |
| **Account Operators** | Can create/modify most accounts |
| **Remote Desktop Users** | Interactive remote access (lateral movement) |

List the current membership of the crown jewel:

```powershell
Get-ADGroupMember "Domain Admins" | Select-Object name, objectClass
```

---

## 4. Break / Observe

Now generate the telemetry an analyst would actually investigate. All benign, all
inside `lab-net`.

### 4.1 — The "attacker adds a backdoor admin" sequence (on DC01)

```powershell
# 1) Create an account
$pw = ConvertTo-SecureString "Temp-Passw0rd!" -AsPlainText -Force
New-ADUser -Name "svc_backup" -SamAccountName "svc_backup" `
  -Path "CN=Users,DC=corp,DC=local" -AccountPassword $pw -Enabled $true

# 2) Escalate it into Domain Admins  ← the event that should page someone
Add-ADGroupMember "Domain Admins" -Members "svc_backup"

# 3) Clean up so you can repeat the module
Remove-ADGroupMember "Domain Admins" -Members "svc_backup" -Confirm:$false
Remove-ADUser "svc_backup" -Confirm:$false
```

### 4.2 — Simulate a logon brute force (from WS01)

Attempt to authenticate to the domain with a wrong password a few times, then succeed.
Easiest safe way — map a drive with bad creds:

```powershell
# Run 4-5 times with a WRONG password → generates 4625s on DC01
net use \\10.0.0.10\SYSVOL /user:CORP\asmith WrongPassword123

# Then once with the CORRECT password → a 4624
net use \\10.0.0.10\SYSVOL /user:CORP\asmith <correct-password>
net use \\10.0.0.10\SYSVOL /delete
```

Failed *domain* logons are recorded on **DC01** (the authenticator), not WS01 — an
important mental model: the DC sees the whole domain's authentication.

---

## 5. Detect

### Event ID reference

| Event ID | Log | Meaning |
|----------|-----|---------|
| 4720 | Security | A user account was **created** |
| 4722 | Security | Account enabled |
| 4725 | Security | Account disabled |
| 4726 | Security | Account **deleted** |
| 4728 | Security | Member added to a **global** security group (e.g. Domain Admins) |
| 4732 | Security | Member added to a **local** security group |
| 4756 | Security | Member added to a **universal** security group |
| 4624 | Security | **Successful** logon — read the **Logon Type** |
| 4625 | Security | **Failed** logon |
| 4740 | Security | Account **locked out** |

**Logon Types worth memorizing:** `2` interactive (at the console), `3` network
(SMB/file share), `10` RemoteInteractive (RDP), `5` service, `4` batch/scheduled task.

### Hunt queries (run on DC01)

**All accounts created in the last day:**
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4720; StartTime=(Get-Date).AddDays(-1) } |
  ForEach-Object {
    [pscustomobject]@{
      Time    = $_.TimeCreated
      NewUser = $_.Properties[0].Value
      By      = $_.Properties[4].Value
    }
  } | Format-Table -AutoSize
```

**Additions to Domain Admins (the high-signal one):**
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4728 } -MaxEvents 20 |
  Where-Object { $_.Message -match 'Domain Admins' } |
  Select-Object TimeCreated, @{n='Detail';e={ ($_.Message -split "`n")[0] }}
```

**Failed then successful logon for one user — the brute-force-that-worked pattern:**
```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624,4625 } -MaxEvents 50 |
  Where-Object { $_.Message -match 'asmith' } |
  Select-Object TimeCreated, Id, @{n='Type';e={ if($_.Id -eq 4625){'FAIL'}else{'ok'} }} |
  Sort-Object TimeCreated
```

**Analyst reading:** a cluster of 4625s for one account followed by a 4624 is a
password-guessing success. Pivot next on: what did that 4624's session *do*? (→ Module 5,
process creation.)

---

## 6. Evidence (for the portfolio)

- [ ] Screenshot of the **4728** event in Event Viewer showing `svc_backup` added to
      Domain Admins → `../assets/01-4728-domain-admins.png`
- [ ] Output of the failed→successful logon query → `../assets/01-bruteforce-query.png`
- [ ] A short "detection write-up" in your own words:
  > *At HH:MM, account `svc_backup` was created (4720) and within seconds added to
  > Domain Admins (4728) by CORP\Administrator. In a real environment this rapid
  > create-then-privilege sequence, outside a change window, is a high-severity alert
  > for persistence/privilege escalation.*

---

## 7. MITRE ATT&CK mapping

| Technique | ID | Where it appears here |
|-----------|-----|-----------------------|
| Create Account: Domain Account | T1136.002 | 4.1 step 1 (4720) |
| Account Manipulation | T1098 | 4.1 step 2 (4728) |
| Valid Accounts: Domain Accounts | T1078.002 | 4.2 successful logon (4624) |
| Brute Force: Password Guessing | T1110.001 | 4.2 failed logons (4625) |

---

## Notes & gotchas

- **No 4720 appearing?** Account Management auditing isn't on. Re-run the `auditpol`
  command from Phase 5 and confirm with `auditpol /get /category:"Account Management"`.
- Domain logon failures land on **DC01**, not the machine you typed the password on.
- `Properties[n]` indexes in the queries above are position-dependent per Event ID; if
  a field looks wrong, run `($event | Format-List *)` on one event to see the layout.
- Always roll back to `mod01-start` before repeating — deleted accounts leave residual
  SIDs in group ACLs that can confuse later runs.
