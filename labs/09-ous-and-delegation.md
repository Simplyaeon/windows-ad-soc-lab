# Module 09 — Organizational Units & Delegation

> **Runs on:** DC01 only. WS01 is not needed and should stay powered off — its computer *account*
> gets moved in Step 4, which happens entirely on DC01
> **Time:** ~2½ hours, split across two sittings
> **Roll back to:** `mod09-start` (DC01, taken in Step 0) · **Do not** roll back to `mod04-start` —
> it predates everything Module 08 left on DC01
> **Status:** written 2026-11-03. **Sitting 1 (Steps 0–4) ran 2026-11-03 11:32 → 2026-11-04 00:18
> UTC — run log below.** Sitting 2 (Steps 5–10) not yet run. Everything marked **prediction** is the
> expectation as written *before* the run. Where the run disagrees, a **Run result** note will say
> so — the run sheet is not rewritten to look as if it was right all along.

---

## What you're going to do

Up to now every account in `corp.local` has sat in one undifferentiated pile: users in the
`Users` container, computers in the `Computers` container. That works for two machines and a
handful of people. It does not work for a real organisation, where the Finance team's accounts are
looked after by different people from the IT team's, and where the helpdesk can reset a user's
password without being a Domain Admin.

**Organizational Units (OUs) are how a domain is divided up**, and **delegation is how power over
one part of it is handed to someone who is not an administrator.** In this module you will build a
small OU structure, move real objects into it, and give a helpdesk group the right to reset
passwords in **one** OU and nowhere else.

Then the SOC question: **did the log record the hand-over of that power, and did it record the
power being used?**

### Why a SOC analyst cares about this

Delegation is a permission entry — an ACE — written onto an OU. It is invisible in the places
people normally look: the helpdesk tech is not in any admin group, `Get-ADGroupMember 'Domain
Admins'` will not show them, and nothing about their account looks special. **The power lives on
the OU, not on the person.**

That is exactly why attackers look for it. A forgotten delegation that lets an ordinary group reset
passwords in an OU containing an admin's account is a path to that admin, and nothing in group
membership reveals it. Tools that map these paths read the permissions directly. **The defender's
version of that skill is knowing whether the change to those permissions was ever logged.**

### The question this module is really asking

Module 08 established, in a third store, that an AD change is only logged when **both** the
subcategory (`Directory Service Changes`) **and** the object's own SACL ask for it. It also read
the domain root's audit settings (its SACL) and found something that matters directly here:

> The domain root's broad entry — `WriteProperty, WriteDacl, WriteOwner`, Everyone — has
> **`InheritanceType None`**. It audits the domain object itself, **not** anything beneath it.
> *(Verified on DC01 2026-10-23, Module 08 Step 7.4b, `08-domain-sacl.png`.)*

Delegation is a change to an OU's permissions (its **DACL**). So:

**Hypothesis:** on an OU with no SACL of its own, delegating control writes **nothing at all** to
the Security log — even with `Directory Service Changes` switched on. On an OU whose SACL audits
**`Modify permissions`**, the same delegation writes a 5136 on `nTSecurityDescriptor` that
records, in its value, exactly who was given what.

> **This is a hypothesis, not a fact.** It follows from Module 08's evidence but has not been
> tested. Step 5 tests it by doing the identical delegation twice — once on an OU that is
> audited, once on one that is not — and Step 7 reads what came out.

And a second question the module adds: **when a delegated tech uses the power, and when they try
to use it somewhere they were not given it, what does each attempt leave behind?**

In this module you will:

1. Read where every object in the domain currently lives
2. Build a top-level `Corp` OU and put an audit rule on it
3. Build the rest of the structure underneath, one OU at a time
4. Move `asmith` and WS01 into it, and create a helpdesk group and tech
5. Delegate password reset to that group — on an audited OU and on an unaudited one
6. Use the delegation, and try to overstep it
7. Find all of it in the log
8. Write the OU design and the delegation record

**Every step says which VM, and for this module the answer is always DC01.**

---

### Four ideas you need first

**An OU is a folder in the directory that you can attach things to.** You can put users,
computers and groups in it, and — the reason OUs exist — you can attach **permissions** (this
module) and **Group Policy** (Module 10) to it, and they apply to everything inside.

**`CN=Users` and `CN=Computers` are not OUs.** They are *containers* — the default folders
Windows creates. They look the same in the GUI, but their names start `CN=` rather than `OU=`, and
**Group Policy cannot be linked to a container**. That is one practical reason this module moves
`asmith` and WS01 out of them: Module 10 needs them somewhere a policy can reach. *(That GPOs cannot
be linked to containers is recall; Module 10 will show it on the box.)*

**Permissions on an OU flow downwards.** An ACE written on `OU=Finance` with inheritance turned on
applies to every user inside `OU=Finance`, including users created after the ACE. That is how one
delegation covers a whole department — and it is also why a delegation on a high-level OU is far
more powerful than it looks.

**The DACL decides what you may do; the SACL decides what gets written down.** You met both in
Module 02 on files. Same idea here. **Delegation edits the DACL. Whether that edit is logged
depends on the SACL.** Those are two different lists on the same object.

---

### Accounts used in this module

| Account | Password | Where | Purpose |
|---|---|---|---|
| `administrator@corp.local` | `Lab-Passw0rd!` | domain | you, doing the build |
| `hd_tech@corp.local` | `Lab-Passw0rd!` | domain, created in Step 4 | the helpdesk tech the power is given to |
| `lab_fin09` | — | domain, created in Step 4, **disabled** | a test user inside the delegated OU |
| `lab_it09` | — | domain, created in Step 4, **disabled** | a test user **outside** it — the overstep target |

> **About the `\` character.** Every sign-in in this module uses `name@corp.local`, never
> `CORP\name` — the keyboard produces the wrong character for `\`.

---

### The ordering that matters

Three things in this module **must** happen in the order written. If they are swapped, the result
cannot be recovered, because **auditing is not retroactive**:

1. **The SACL on `Corp` goes on before anything is built underneath it** (Step 2.3 before
   Step 3). Otherwise the creations in Step 3 happen unaudited, and one of the module's questions
   can never be answered.
2. **The control OU, `Lab09Control`, never gets a SACL** — not in Step 2, not ever. It is the
   "what does the log say when nobody asked it to watch" half of the comparison.
3. **Every boundary time is written down in UTC before the action, not reconstructed after.**
   Sitting 2 happens on a different day; its queries depend on times written in sitting 1.

---

# Run log — Sitting 1 (2026-11-03 → 2026-11-04, Steps 0–4 complete, DC01)

Only what was pasted back or shown in a screenshot or photo is recorded as verified. The ordering
rules above all held: `Corp`'s SACL went on before anything was built under it, `Lab09Control` never
got one, and every change is bracketed in UTC. **Two things went off-plan and both were repaired
with every step timed** — `Finance`/`IT` created in the wrong place, and `hd_tech` half-created by
a command that printed an error.

**The sitting spanned a ~10-hour break** (12:28 → 22:47 UTC) in a fresh PowerShell window. Every
time below is read off `(Get-Date).ToUniversalTime()` output, not reconstructed.

## Boundaries — the table sitting 2 searches against

All UTC. 2026-11-03 unless marked.

| Name | Before | After | What happened in the window |
|---|---|---|---|
| `B0` | 11:32:35 | — | start of the module's changes; everything earlier is the control |
| `C` | 11:46:59 | 11:47:00 | `Corp` created under the domain root |
| `L` | 11:58:54 | 11:58:55 | `Lab09Control` created under the domain root |
| `S` | 12:02:11 | 12:08:30 | SACL added to `Corp` via `dsa.msc` |
| — | 12:25:41 | 12:25:46 | `Users` created under `Corp` |
| — | 12:27:45 | 12:27:45 | `Finance` created — **under `Corp`, not `Corp/Users`** (wrong `-Path`) |
| — | 12:27:58 | 12:27:58 | `IT` created — **under `Corp`, not `Corp/Users`** (wrong `-Path`) |
| — | 12:28:11 | 12:28:11 | `Workstations` created under `Corp` |
| — | 12:28:26 | 12:28:27 | `Servers` created under `Corp` |
| — | 12:28:42 | 12:28:42 | `Groups` created under `Corp` |
| `FU` | 22:47:17 | 22:47:21 | `Finance` accidental-deletion protection **off** |
| `FM` | 22:50:46 | 22:50:47 | `Finance` moved `Corp` → `Corp/Users` |
| — | 22:54:01 | 22:54:02 | re-protect attempted at `Finance`'s **old** path — `Directory object not found`; **no change** |
| `FP` | 22:54:37 | 22:54:37 | `Finance` protection **on**, at `OU=Finance,OU=Users,OU=Corp,…` |
| `IU` | 22:57:35 | 22:57:35 | `IT` protection **off** |
| `IM` | 22:58:14 | 22:58:14 | `IT` moved `Corp` → `Corp/Users` |
| `IP` | 22:58:40 | 22:58:41 | `IT` protection **on**, at `OU=IT,OU=Users,OU=Corp,…` |
| `M1`→`M2` | 23:12:26 | 23:17:07 | `asmith` moved `CN=Users` → `Corp/Users/Finance` |
| `M2`→`M3` | 23:17:07 | 23:18:14 | `WS01` (account) moved `CN=Computers` → `Corp/Workstations` |
| `T` | 23:30:04 | 23:31:29 | `lab_fin09` and `lab_IT09` created, disabled |
| `G` | 23:36:12 | 23:38:14 | `HelpDesk-Ops` created, Global, in `Corp/Groups` |
| `H` | 23:45:42 | — | `hd_tech` creation — three attempts, see 4.4 below. **No after-time; `P1` closes it** |
| `P` | 23:53:33 | 23:55:51 | Administrator **reset** `hd_tech`'s password (`Set-ADAccountPassword -Reset`) |
| `E` | 00:01:56 (11-04) | 00:05:15 (11-04) | `hd_tech` enabled |
| `A` | 00:07:21 (11-04) | 00:08:01 (11-04) | `hd_tech` added to `HelpDesk-Ops` |
| `S1end` | 00:18:33 (11-04) | — | end of sitting 1 |

## Step 0 — pre-flight

| Step | Read | Result |
|---|---|---|
| 0.1 | snapshot | VirtualBox title bar reads **`Windows 2022 (mod-09-start) [Running]`** — the snapshot exists, spelt **`mod-09-start`** (hyphens), not the sheet's `mod09-start`. Taken on 2026-11-03 is **assumed** — the title shows the snapshot, not its date |
| 0.2 | `hostname` | **`DC01`** |
| 0.3 | three `auditpol /get` | **all three predictions held.** `Directory Service Changes` **Success** (Module 08's setting survived); `User Account Management` and `Security Group Management` **Success and Failure**. `09-preflight.png` (`hostname` in frame) |
| 0.4 | `(Get-Acl -Path 'AD:/DC=corp,DC=local').Sddl -like '*(D;;DC;;;WD)*'` | **first: `Cannot find drive. A drive with the name 'AD' does not exist`**, fixed by `Import-Module ActiveDirectory` (see Notes). **Then `False` — a typo**: the pattern was typed `'*(D;;DC;;WD)*'`, **two** semicolons where there are three. Before the typo was spotted, `.Access \| Where-Object AccessControlType -eq 'Deny'` showed one entry: `DeleteChild`, `Everyone`, `Deny`, `InheritanceType None`, `IsInherited False`. **Retyped: `True`.** Domain root unchanged since Module 08 |
| 0.5 | `(Get-Date).ToUniversalTime()` | **`B0` = Tuesday, November 3, 2026 11:32:35 AM** |

## Step 1 — the starting picture

| Step | Read | Result |
|---|---|---|
| 1.1 | `Get-ADOrganizationalUnit -Filter *` | one OU, `Domain Controllers`, `OU=Domain Controllers,DC=corp,DC=local`. **First try printed `{}`** in the DN column — the property was typed `DistinguishedNamme`. `@(…).Count` → **1** |
| 1.2 | `Get-ADUser asmith`, `Get-ADComputer WS01` | `asmith` in `CN=Users`, `WS01` in `CN=Computers` — **as relayed** (typed back in lower case with spaces); predictions held |

## Step 2 — the top of the tree, and the control

| Step | Read | Result |
|---|---|---|
| 2.1 / 2.2 | readback | three OUs: `Domain Controllers`, `Corp`, `Lab09Control` (as relayed) |
| 2.3 | SACL via `dsa.msc` | dialog confirmed as **"for Corp"**. The new entry opened with **`Read all properties` and `List contents` pre-ticked** — unticked before OK (`Directory Service Access` is Success, so read auditing would flood the log; the flood is **reasoning, not tested here**). Ticked: `Write all properties`, `Modify permissions`, `Create all child objects` |
| 2.4 | `(Get-Acl 'AD:/OU=Corp,…' -Audit).Audit`, then `@(…).Count` | **prediction held. 3 entries.** (1) **`CreateChild, WriteProperty, WriteDacl`**, `InheritanceType All`, `ObjectType` all-zero, `Success`, `Everyone`, **`IsInherited False`** — `WriteDacl` printed by name. (2)/(3) `WriteProperty` on `f30e3bbe-…` / `f30e3bbf-…`, `InheritedObjectType bf967aa5-…`, **`IsInherited True`** — the same two Module 08 saw, GUIDs still unresolved |
| 2.5 | same on `Lab09Control` | **the control holds. 2 entries**, both the inherited `WriteProperty` pair; **no `WriteDacl`, nothing `IsInherited False`**. `09-sacl-corp-vs-control.png` (both readbacks and both counts in one frame; **no `hostname` in frame**) |

## Step 3 — the structure, and a wrong path

**Run result — `Finance` and `IT` were created in the wrong place.** Their `-Path` was typed as
`'OU=Corp,DC=corp,DC=local'`, not `'OU=Users,OU=Corp,…'`; a `-SearchBase` readback confirmed 7 OUs
with both directly under `Corp`. Both are **protected from accidental deletion by default**
(`ProtectedFromAccidentalDeletion` read `True` on each before the change), so the repair was, per
OU: protection off → `Move-ADObject` → protection on at the new path, each timed (table above), each
read back:

| Read | Result |
|---|---|
| `Finance` protection after `FU` | `False` |
| `Finance` DN after `FM` | `OU=Finance,OU=Users,OU=Corp,DC=corp,DC=local` |
| `Finance` protection after `FP` | `True` |
| `IT` at old path after `IP` | **`Directory object not found`** — proves it left `Corp`, not where it went |
| `IT` at new path | `IT  True` |
| 3.2 tree, `hostname` in frame | **7 OUs**, `Finance` and `IT` both `OU=…,OU=Users,OU=Corp,…`. `09-ou-tree.png` |

**Consequence for 7.7.** The by-product question — *does creating a protected OU add
`(D;;DC;;;WD)` to its parent?* — now has **more** to work with, not less, but its prediction no
longer fits as written. Nothing was ever *created* under `Corp/Users`; `Finance` and `IT` *arrived*
there by move, unprotected, and were protected afterwards. **Sitting 2 should line `Users`'
`nTSecurityDescriptor` 5136s up against `FP` and `IP` (protection turned on with `Users` as the
parent), and `Corp`'s against `FU`/`IU` as well as the creation times.** That protection-on is the
moment the parent gains the entry is a **hypothesis**, sharper than Module 08's but still untested.

## Step 4 — fill it

| Step | Read | Result |
|---|---|---|
| 4.1 | `Get-ADUser asmith \| Select-Object DistinguishedName` | `CN=asmith,OU=Finance,OU=Users,OU=Corp,DC=corp,DC=local`. **First try failed loudly**: `Move_ADObject` (underscore) — `is not recognized as the name of a cmdlet`; no change |
| 4.1 | `Get-ADComputer WS01 \| …` | `CN=WS01,OU=Workstations,OU=Corp,DC=corp,DC=local`. One `M3` attempt typed `(Get-Date)/ToUniversalTime()` — parser error, no time; retyped |
| 4.2 | `Get-ADUser -Filter "Name -like 'lab_*09'"` | `lab_fin09` `False` `CN=lab_fin09,OU=Finance,…`; **`lab_IT09`** `False` `CN=lab_IT09,OU=IT,…`. **Created as `lab_IT09`** (capital `IT`), not the sheet's `lab_it09` |
| 4.3 | `Get-ADGroup 'HelpDesk-Ops'` | **`HelpDesk-Ops`** `Global` `CN=HelpDesk-Ops,OU=Groups,OU=Corp,DC=corp,DC=local`. **Created as `HelpDesk-Ops`** (capital `D`), not the sheet's `Helpdesk-Ops` |
| 4.4 | see below | `hd_tech` `Enabled True`, `hd_tech@corp.local`, `CN=hd_tech,OU=IT,OU=Users,OU=Corp,DC=corp,DC=local` |
| 4.4 | `Get-ADGroupMember 'HelpDesk-Ops'` | **`hd_tech`**, one member |
| 4.5 | `(Get-Date).ToUniversalTime()` | **`S1end` = Wednesday, November 4, 2026 12:18:33 AM** |

AD matching is case-insensitive, so the sheet's later commands still work against `lab_IT09` and
`HelpDesk-Ops`. **Findings and hunts quote the stored case.**

**Run result — `hd_tech` was created by a command that printed an error.** Three `New-ADUser`
attempts after `H1`:

| Attempt | Error | What it did |
|---|---|---|
| 1 | `A positional parameter cannot be found that accepts argument ']'` — a stray `]` at the end | nothing; binding failed |
| 2 | **`The password does not meet the length, complexity, or history requirement of the domain`** (`ADPasswordComplexityException`) — the prompt showed 4 characters | **created the account anyway** |
| 3 | **`The specified account already exists`** (`ADIdentityAlreadyExistsException`) | nothing — but proves attempt 2 left an object |

Readback after attempt 3: **`Enabled False`, `PasswordLastSet` empty**, in the right OU. That
`New-ADUser` creates the object first and sets the password second is **recall**; the readback is
the evidence. Repaired with `Set-ADAccountPassword -Identity hd_tech -Reset` (`P`, no error) and
`Enable-ADAccount` (`E`). Final readback: **`Enabled True`, `PasswordLastSet 11/4/2026 12:55:41 AM`**
— local time; **23:55:41 UTC on 11-03, inside `P`**.

**Not verified: that the password set at `P` is `Lab-Passw0rd!`.** The domain accepted it, which
proves complexity, not value. Step 6.1 will show it — a failed credential there means one more
timed reset.

**Consequence for Step 7.** The sheet expected `hd_tech`'s creation to write 4720 + 4722 + 4724 in
one second. **That is not what happened.** Expect instead a 4720 near `H1` with no password, an
**Administrator-made 4724 on `hd_tech` inside `P`**, and an enable inside `E`. **So there is an
admin reset to tell apart from the delegated one** — Subject `Administrator`, Target `hd_tech`,
inside `P` — and the Target Account field still separates them. Which IDs actually appear is
**not established until read**.

## Open after sitting 1

- Whether the moves wrote anything (5139 is **recall — never observed**) — read in sitting 2.
- Whether `hd_tech`'s password is `Lab-Passw0rd!` — Step 6.1.
- The ~10-hour break inside the sitting is a gap with no lab activity planned in it; anything
  logged there is not this module's.

---

# Step 0 — Pre-flight (DC01)

**Aim: start from a state you have written down, so that every change afterwards has exactly one
cause — you.**

### 0.1 Snapshot first

DC01 powered **off** → VirtualBox → **Snapshots** → **Take** → name it **`mod09-start`**. Then
start DC01 and sign in as `administrator@corp.local`.

### 0.2 Prove which machine you are on

Open PowerShell as Administrator and maximise it.

```powershell
hostname
```

**Prediction:** `DC01`.

### 0.3 Read the two audit switches this module depends on

```powershell
auditpol /get /subcategory:"Directory Service Changes"
```

**Prediction:** `Success` — left on by decision at the end of Module 08 (2026-10-23). **Read it,
don't inherit it.** If it reads `No Auditing`, stop here and say so: that would be the
Group-Policy-overwrite hypothesis from Module 08's gotchas actually happening, which is a finding.

```powershell
auditpol /get /subcategory:"User Account Management"
```

**Prediction:** `Success and Failure` — set in Module 01. This is the switch that writes **4724**
(a password reset), which Step 7 needs.

```powershell
auditpol /get /subcategory:"Security Group Management"
```

**Prediction:** `Success and Failure` — also Module 01. It writes **4728** when `hd_tech` is added
to a group in Step 4.

> **No space after the colon** in `/subcategory:"…"`, or `auditpol` fails with `Error 0x00000057`
> and prints usage text that reads like a broken tool.

### 0.4 Check the one thing Module 08 left on the domain root

```powershell
(Get-Acl -Path 'AD:/DC=corp,DC=local').Sddl -like '*(D;;DC;;;WD)*'
```

**Prediction:** `True`. Module 08 left an `Everyone: AccessDenied (DeleteChild)` entry on the
domain root, most likely added by creating a protected OU. **It is known lab state, not an
anomaly.** It matters here because Step 2 creates two more protected OUs directly under the root.

### 0.5 Mark the boundary

```powershell
(Get-Date).ToUniversalTime()
```

**Write this down as `B0`.** Everything before it is the control for this module.

---

# Step 1 — Read where everything lives now (DC01)

**Aim: know what the directory looks like before you change it, so you can show the change rather
than describe it.**

### 1.1 Every OU in the domain

```powershell
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
```

**Prediction:** **one** OU — `Domain Controllers`. Module 08 created `LabAudit` and removed it in
its cleanup, readback-verified. If anything else appears, write it down before going further.

Count it, because a population of one has fooled this lab before:

```powershell
@(Get-ADOrganizationalUnit -Filter *).Count
```

### 1.2 Where `asmith` and WS01 sit

```powershell
Get-ADUser asmith | Select-Object DistinguishedName
```

```powershell
Get-ADComputer WS01 | Select-Object DistinguishedName
```

**Prediction:** `CN=asmith,CN=Users,DC=corp,DC=local` and `CN=WS01,CN=Computers,DC=corp,DC=local`.
Note the **`CN=`** on the second part of each — containers, not OUs.

### 1.3 Read a distinguished name right to left

`CN=asmith,CN=Users,DC=corp,DC=local` reads, right to left: the domain `corp.local` → the `Users`
container → the object `asmith`. Every path in this module is written this way. **The order is the
opposite of a file path**, which is the one thing that trips everyone up the first time.

---

# Step 2 — Build the top of the tree, and the control (DC01)

**Aim: create the two top-level OUs the experiment compares, and put a SACL on one of them only.**

### 2.1 The OU you will build under

Write the UTC time first, then create:

```powershell
(Get-Date).ToUniversalTime()
```

```powershell
New-ADOrganizationalUnit -Name 'Corp' -Path 'DC=corp,DC=local'
```

```powershell
(Get-Date).ToUniversalTime()
```

**Write both times down as `C1` and `C2`.** Module 08 could only place its OU creation "early in
Step 7", which is why its strongest inference stayed unestablished. **This time it is bracketed.**

### 2.2 The control OU

Same pattern — time, create, time:

```powershell
New-ADOrganizationalUnit -Name 'Lab09Control' -Path 'DC=corp,DC=local'
```

**This OU will never get a SACL.** It exists only so Step 5 can do the same delegation twice and
compare.

Read both back:

```powershell
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
```

**Prediction:** three OUs — `Domain Controllers`, `Corp`, `Lab09Control`.

### 2.3 Put the SACL on `Corp` — the GUI is better here

On **DC01**, open **Active Directory Users and Computers** (`dsa.msc`):

1. **View → Advanced Features** — make sure it is ticked. The Security tab does not appear
   without it
2. Right-click **`Corp`** → **Properties** → **Security** tab → **Advanced**
3. **Auditing** tab → **Add**
4. **Principal:** `Everyone` · **Type:** `Success` · **Applies to:** `This object and all
   descendant objects`
5. Tick **`Write all properties`**, **`Modify permissions`** and **`Create all child objects`**
6. OK out of all three dialogs

**`Modify permissions` is the new tick.** Module 08 did not audit it. It is the right that
should make a delegation visible — the same job `WRITE_DAC` did for files in Module 02.

> **Delete rights are deliberately not ticked.** Module 08 found no 5141 for two deletes and the
> test of why was closed as won't-do. Nothing in this module depends on deletes being logged.

### 2.4 Confirm the SACL took

```powershell
(Get-Acl -Path 'AD:/OU=Corp,DC=corp,DC=local' -Audit).Audit
```

**Prediction:** an entry for `Everyone`, `Success`, `InheritanceType All`, **`IsInherited False`**,
whose rights include **`CreateChild`**, **`WriteProperty`** and **`WriteDacl`**. Module 08 also saw
two inherited entries (`IsInherited True`) come down from the domain root — expect them again.

Count the entries so a frame without a prompt at the bottom cannot mislead you:

```powershell
@((Get-Acl -Path 'AD:/OU=Corp,DC=corp,DC=local' -Audit).Audit).Count
```

> **Test the names, then believe them.** Module 03 found the registry collapsing rights into
> composite names, so a right you ticked can be present without its own name printed. In Module 08
> AD printed `CreateChild, WriteProperty` by name. **If `WriteDacl` is not visible, do not assume
> the tick failed — say so and we resolve it before Step 3.**

### 2.5 Confirm the control has nothing of its own

```powershell
(Get-Acl -Path 'AD:/OU=Lab09Control,DC=corp,DC=local' -Audit).Audit
```

**Prediction:** only `IsInherited True` entries — the two that come down from the domain root —
and **no `WriteDacl` anywhere**. If a `WriteDacl` entry appears here, **the control is broken**:
stop and say so.

📸 `09-sacl-corp-vs-control.png` — both readbacks in one frame, `hostname` at the top.

---

# Step 3 — Build the rest of the structure (DC01)

**Aim: give the domain a shape a real organisation would recognise — and, because the SACL is now
on, record what each creation does to its parent.**

The structure:

```
corp.local
├── Domain Controllers      (built in — never move a DC out of here)
├── Lab09Control            (the control — removed in Step 9)
└── Corp
    ├── Users
    │   ├── Finance
    │   └── IT
    ├── Workstations
    ├── Servers
    └── Groups
```

> **`Servers` stays empty, deliberately.** DC01 is the only server, and a domain controller **must
> stay in `Domain Controllers`** — that OU carries the policy that makes it behave as a DC. The OU
> exists because a design has to say where servers *would* go.

### 3.1 Create them one at a time, timing each

For **each** OU below, run the three-line pattern from 2.1 — time, create, time — and write both
times down beside its name. **Do them in this order**, because each one needs its parent to exist:

```powershell
New-ADOrganizationalUnit -Name 'Users' -Path 'OU=Corp,DC=corp,DC=local'
```

```powershell
New-ADOrganizationalUnit -Name 'Finance' -Path 'OU=Users,OU=Corp,DC=corp,DC=local'
```

```powershell
New-ADOrganizationalUnit -Name 'IT' -Path 'OU=Users,OU=Corp,DC=corp,DC=local'
```

```powershell
New-ADOrganizationalUnit -Name 'Workstations' -Path 'OU=Corp,DC=corp,DC=local'
```

```powershell
New-ADOrganizationalUnit -Name 'Servers' -Path 'OU=Corp,DC=corp,DC=local'
```

```powershell
New-ADOrganizationalUnit -Name 'Groups' -Path 'OU=Corp,DC=corp,DC=local'
```

**Why time each one.** Module 08's leading explanation for the `(D;;DC;;;WD)` entry on the domain
root was: *creating a protected OU adds that entry to its **parent***. It was never established,
because the creation was not timed. Now the parents are audited (`Corp` and everything under it
carries the SACL from 2.3, including `Modify permissions`), so Step 7 can line each parent's 5136s
up against these times. **This answers one of Module 08's open questions as a by-product — it is
not extra work.**

**Prediction, and it is a hypothesis built on an unestablished one:** the **first** child created
under a parent writes a 5136 pair on that parent adding `(D;;DC;;;WD)`; a **second** child under
the same parent writes **nothing** on it, because the entry is already there. So: `Users` → pair on
`Corp`; `Finance` → pair on `Users`; `IT` → nothing; `Workstations`, `Servers`, `Groups` → nothing.
**Read what comes out; do not fit it to this.**

### 3.2 Read the tree back

```powershell
Get-ADOrganizationalUnit -Filter * -SearchBase 'OU=Corp,DC=corp,DC=local' | Select-Object DistinguishedName
```

`-SearchBase` limits the search to one branch of the tree — everything at or below `Corp`.

```powershell
@(Get-ADOrganizationalUnit -Filter * -SearchBase 'OU=Corp,DC=corp,DC=local').Count
```

**Prediction:** **7** — `Corp` itself plus the six beneath it.

📸 `09-ou-tree.png` — `dsa.msc` with the `Corp` branch expanded, or the 3.2 output with
`hostname` at the top.

---

# Step 4 — Fill it: move, create, and make the helpdesk (DC01)

**Aim: put real objects in the structure, and create the group and tech that the power will be
handed to.**

### 4.1 Move `asmith` and WS01 in

Mark the time:

```powershell
(Get-Date).ToUniversalTime()
```

**Write it down as `M1`.** Then move `asmith`:

```powershell
Get-ADUser asmith | Move-ADObject -TargetPath 'OU=Finance,OU=Users,OU=Corp,DC=corp,DC=local'
```

**The `|` passes the user object straight to `Move-ADObject`**, so you never type `asmith`'s full
distinguished name. Read it back:

```powershell
Get-ADUser asmith | Select-Object DistinguishedName
```

Then WS01 — same shape:

```powershell
Get-ADComputer WS01 | Move-ADObject -TargetPath 'OU=Workstations,OU=Corp,DC=corp,DC=local'
```

```powershell
Get-ADComputer WS01 | Select-Object DistinguishedName
```

**Prediction:** both readbacks show the new `OU=…` paths.

> **Moving these does not break anything that refers to them by SID** — `asmith`'s place in WS01's
> `Remote Desktop Users`, for instance. Those references are to the account's SID, which does not
> change when the account moves. **Expected, not established on this box**; WS01's next boot is
> where it would show.

### 4.2 The two test users

Both **disabled, no password** — they never need to sign in. One inside the OU that will be
delegated, one outside it:

```powershell
New-ADUser -Name 'lab_fin09' -Path 'OU=Finance,OU=Users,OU=Corp,DC=corp,DC=local' -Enabled $false
```

```powershell
New-ADUser -Name 'lab_it09' -Path 'OU=IT,OU=Users,OU=Corp,DC=corp,DC=local' -Enabled $false
```

### 4.3 The helpdesk group

```powershell
New-ADGroup -Name 'Helpdesk-Ops' -GroupScope Global -GroupCategory Security -Path 'OU=Groups,OU=Corp,DC=corp,DC=local'
```

**`Global`** is the group scope — and, from Module 01's traps, that decides the event ID: a member
added to a **global** group writes **4728**.

### 4.4 The helpdesk tech

This one **does** get a password and **is** enabled — Step 6 signs in as it:

```powershell
New-ADUser -Name 'hd_tech' -UserPrincipalName 'hd_tech@corp.local' -Path 'OU=IT,OU=Users,OU=Corp,DC=corp,DC=local' -AccountPassword (Read-Host -AsSecureString 'Password') -Enabled $true
```

Type `Lab-Passw0rd!` at the prompt. It will not echo.

> **Trap, written now so it does not bite in Step 7:** Module 01 found that `New-ADUser
> -AccountPassword` writes **4720, 4722 and 4724 in the same second**. **That 4724 is creation, not
> a password reset.** Step 7 is looking for a different 4724 — the one where `hd_tech` resets
> someone *else's* password. The difference is in the **Target Account** field.

Add the tech to the group:

```powershell
Add-ADGroupMember -Identity 'Helpdesk-Ops' -Members 'hd_tech'
```

```powershell
Get-ADGroupMember -Identity 'Helpdesk-Ops' | Select-Object Name
```

**Prediction:** `hd_tech`.

### 4.5 Close the sitting

```powershell
(Get-Date).ToUniversalTime()
```

**Write it down as `S1end`.** If this is where sitting 1 ends, that is a clean place to stop:
nothing has been delegated yet, so nothing is half-done.

---

# Step 5 — Delegate: the same hand-over twice (DC01)

**Aim: give `Helpdesk-Ops` the right to reset passwords — on one audited OU and on one unaudited
one — so Step 7 can show whether the hand-over is visible in the log.**

### 5.0 Mark the boundary

```powershell
(Get-Date).ToUniversalTime()
```

**Write it down as `D0`.** Then keep it for queries:

```powershell
$d0 = Get-Date
```

**The variable dies with the window.** If it closes, re-set it by hand from `D0` — converted to
DC01's local time, which is UTC+1 — exactly as Module 08 did.

### 5.1 The control first — delegate on `Lab09Control`

In **`dsa.msc`** on DC01:

1. Right-click **`Lab09Control`** → **Delegate Control…** → **Next**
2. **Add** → type `Helpdesk-Ops` → **Check Names** → **OK** → **Next**
3. Tick **`Reset user passwords and force password change at next logon`** → **Next** → **Finish**

Write down the UTC time straight after (`(Get-Date).ToUniversalTime()`) as **`D1`**.

**The control goes first on purpose.** If it went second, a 5136 from the audited delegation could
be mistaken for one belonging to the control, or vice versa, if the times were close.

### 5.2 Wait one minute, then delegate on `Finance`

Same wizard, same group, same task, on **`Corp → Users → Finance`**. Write the UTC time straight
after as **`D2`**.

**One variable has moved: whether the OU carries a SACL that audits `Modify permissions`.**
Everything else — the wizard, the group, the task, the account doing it — is identical.

### 5.3 Read both delegations back

**A wizard that said Finish is not a permission that exists** — Module 06's Finding 5 has three
instances of a command that reported success and left the old state in place.

```powershell
(Get-Acl -Path 'AD:/OU=Finance,OU=Users,OU=Corp,DC=corp,DC=local').Access | Where-Object IdentityReference -like '*Helpdesk*'
```

`.Access` is the **DACL** — the "who may do what" list. Module 08 read `.Audit`, the SACL; this is
the other list on the same object.

**Prediction, and it is recall:** **two** entries for `CORP\Helpdesk-Ops`, both inherited only by
**user** objects — one an `ExtendedRight` (the right to reset a password), one a `WriteProperty` on
a single attribute (to force a change at next logon). **Count them** rather than trusting a frame:

```powershell
@((Get-Acl -Path 'AD:/OU=Finance,OU=Users,OU=Corp,DC=corp,DC=local').Access | Where-Object IdentityReference -like '*Helpdesk*').Count
```

Then the same two commands with `Lab09Control` in the path. **Prediction:** the same entries — the
two delegations should be identical as permissions, differing only in whether they were audited.

> The `ObjectType` on those entries will be a GUID, not a name. **What each GUID names is not
> established until it is resolved on the box** — Step 7.4 shows how, and that same lookup is
> one route to Module 08's unresolved GUIDs.

📸 `09-delegation-readback.png` — the Finance readback and its count, `hostname` in frame.

---

# Step 6 — Use the power, then overstep it (DC01)

**Aim: make `hd_tech` reset a password where they are allowed to, and try where they are not, so
Step 7 can show what each attempt leaves behind.**

### 6.1 Get the tech's credentials into a variable

**One new construct this module: `-Credential`.** Most AD cmdlets accept it, and it makes that one
command run as a different account — without signing out, and without `hd_tech` needing the right
to sign into DC01 itself.

```powershell
$cred = Get-Credential
```

A sign-in dialog appears. User name **`hd_tech@corp.local`**, password `Lab-Passw0rd!`.

> **That `-Credential` works for a non-admin against this DC is expected, not established.** If
> Step 6.3 fails with a sign-in error rather than an access error, **stop and paste the exact
> message** — do not try other ways to sign in as `hd_tech` until we know what it said.

### 6.2 The new password, held the same way

```powershell
$pw = Read-Host -AsSecureString 'New password'
```

Type `Reset-Passw0rd!`. It meets the domain's complexity rule and is different from every other lab
password, so if it ever appears somewhere it should not, it is traceable to this step.

### 6.3 The allowed reset — `lab_fin09`, inside `Finance`

Mark the time first, as **`R1`**:

```powershell
(Get-Date).ToUniversalTime()
```

```powershell
Set-ADAccountPassword -Identity lab_fin09 -Reset -NewPassword $pw -Credential $cred
```

**Prediction:** no output — silence is success for this cmdlet. Read it back as Administrator (no
`-Credential`):

```powershell
Get-ADUser lab_fin09 -Properties PasswordLastSet | Select-Object Name, PasswordLastSet
```

**Prediction:** a `PasswordLastSet` of a minute ago. **That readback is the proof the reset
happened**, not the absence of an error.

### 6.4 The overstep — `lab_it09`, inside `IT`

Wait one minute. Mark the time as **`R2`**, then:

```powershell
Set-ADAccountPassword -Identity lab_it09 -Reset -NewPassword $pw -Credential $cred
```

**Prediction:** `Access is denied`. **`Helpdesk-Ops` was given nothing on `IT`.** Read it back:

```powershell
Get-ADUser lab_it09 -Properties PasswordLastSet | Select-Object Name, PasswordLastSet
```

**Prediction:** `PasswordLastSet` **empty** — the account was created with no password in 4.2 and
nothing has set one since.

Mark the closing time as **`R3`**:

```powershell
(Get-Date).ToUniversalTime()
```

**Paste the exact error text from 6.4**, not a summary. Module 08's run recorded two relayed values
that differed in case from what the log printed. The words of the error are evidence.

---

# Step 7 — Detect: what the log kept (DC01)

**Aim: answer four questions — was the hand-over logged, was the control silent, was the use
logged, and was the overstep logged — each from the log, not from memory.**

### 7.1 Count before concluding

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136; StartTime=$d0} | Measure-Object
```

**How many to expect is not established.** Module 08 found one user creation alone wrote three
5136s. This window covers two delegations and two resets, and may hold more than you would guess.
**Get the number first; interpret second.**

### 7.2 Narrow to permission changes only — one new key in a familiar filter

`-FilterHashtable` can filter on a **named field inside the event**, not only on log, ID and time.
You already know the field names from Module 08's 5136 (`ObjectDN`, `AttributeLDAPDisplayName`,
…). Add one:

```powershell
$p = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136; StartTime=$d0; AttributeLDAPDisplayName='nTSecurityDescriptor'}
```

```powershell
@($p).Count
```

**That this key works is expected, not established on this box.** If it errors, or returns
`NoMatchingEventsFound` while 7.1 counted 5136s, **suspect the filter before concluding** —
Module 07 found a filter *form* that returned nothing while the events sat in the channel. Fall back
to reading each event from 7.1 with `.Message`.

Now print which object each one is about — the same `foreach` Module 08 used in 9.4:

```powershell
foreach ($e in $p) { (([xml]$e.ToXml()).Event.EventData.Data | Where-Object Name -eq 'ObjectDN').'#text' }
```

And their times, in the same order (`Get-WinEvent` returns newest first, both times):

```powershell
$p | Select-Object TimeCreated
```

**Prediction:** a **pair** (one `Value Deleted`, one `Value Added`, per Module 08 Finding 2) for
`OU=Finance,OU=Users,OU=Corp,DC=corp,DC=local`, at or just before `D2` — and **nothing** for
`OU=Lab09Control,DC=corp,DC=local`.

**That combination is the result.** Two identical delegations, one recorded and one not, separated
only by the SACL. If **both** appear, the hypothesis is wrong and something is auditing the control
— that would be the more interesting finding. If **neither** appears, the instrument is unproven:
go back to 2.4 and check `WriteDacl` really is on `Corp`'s SACL before concluding anything.

### 7.3 Read the hand-over out of the event

Pick the Finance pair by content, not by position. Read them one at a time — `$p[0]`, then
`$p[1]`, and so on — until you have found both Finance events:

```powershell
$p[0].Message
```

One is `Value Added` (the new permissions), one is `Value Deleted` (the old), and they share a
Correlation ID. In the two commands below, **put the number of the `Value Added` one where `$p[0]`
is, and the `Value Deleted` one where `$p[1]` is** — then run the same diff Module 08 ran on the
domain root:

```powershell
$a = (([xml]$p[0].ToXml()).Event.EventData.Data | Where-Object Name -eq 'AttributeValue').'#text'
```

```powershell
$b = (([xml]$p[1].ToXml()).Event.EventData.Data | Where-Object Name -eq 'AttributeValue').'#text'
```

**Check neither is empty before comparing** — two empty values compare equal, a Module 08 trap:

```powershell
$a.Length; $b.Length
```

Then, with `$a` as the **added** value and `$b` as the **deleted** one:

```powershell
Compare-Object ($b -split '\(') ($a -split '\(')
```

**Prediction:** two pieces marked `=>` (present only in the new value), each containing the SID of
`Helpdesk-Ops` — the two ACEs read back in 5.3. Decode one with the command Module 08 proved:

```powershell
ConvertFrom-SddlString -Sddl 'D:(<paste one piece here, with its opening bracket>' -Type ActiveDirectoryRights
```

**This is the point of the module, in one event:** the Security log holds, inside a 5136 on
`nTSecurityDescriptor`, the exact permission that was handed over and the group it was handed to.
**If the OU was audited.**

📸 `09-5136-delegation.png` — the `Compare-Object` output and the decoded line.

### 7.4 Resolve what the GUID names (optional, but it closes a recall label)

The ACE that grants the reset carries a GUID. Extended rights are listed in the configuration
partition, each with a `rightsGuid`. Replace the GUID below with the one from your ACE:

```powershell
Get-ADObject -SearchBase 'CN=Extended-Rights,CN=Configuration,DC=corp,DC=local' -Filter "rightsGuid -eq '<guid>'" | Select-Object Name
```

**Prediction:** `User-Force-Change-Password`. **If it returns nothing**, the GUID is probably an
*attribute*, not an extended right, and that lookup works differently — note it and move on.

### 7.5 The use: the reset `hd_tech` made

```powershell
$r = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4724; StartTime=$d0}
```

```powershell
@($r).Count
```

**Prediction:** **1** — and not 2. `hd_tech`'s *creation* 4724 (Step 4.4) is before `$d0`, so it is
outside this window. Read it:

```powershell
$r[0].Message
```

**Prediction:** **Subject** `hd_tech`, **Target Account** `lab_fin09`. **The subject is the person
to watch:** a non-admin resetting someone else's password is exactly what a delegation permits and
exactly what an attacker holding that account would do.

📸 `09-4724-delegated-reset.png`.

### 7.6 The overstep — what did a refused reset leave behind?

**I don't know what this will show, and neither does the run sheet.** The prediction would be a
guess, so there is none. Instead, take the full inventory of the window around the attempt — every
event ID, counted — the way Module 07 broke down its 479 events. Set the window from what you wrote
down at `R2` and `R3`, in DC01's local time (UTC+1):

```powershell
$w = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date '<R2 local>'); EndTime=(Get-Date '<R3 local>')}
```

```powershell
$w | Group-Object Id | Select-Object Count, Name
```

**Then do the same for the allowed reset's window** (`R1` → `R2`) as the comparison. The question is
whether anything in the refused window **names `hd_tech` and `lab_it09` together**. Possibilities
include a failed 4724, a 4662, or **nothing at all**.

**If it is nothing:** that is a finding, not a failure — *a delegated account probing beyond its
scope leaves no trace with this lab's audit settings.* But before writing it, prove the window was
alive: the `R1` → `R2` inventory must contain the 7.5 4724, or the window is wrong.

### 7.7 The by-product: what creating protected OUs did to their parents

Run the 7.2 filter again with a wider window — from `B0`, re-set by hand — and line each
`nTSecurityDescriptor` 5136 up against the OU-creation times you wrote down in Steps 2 and 3. For
each pair, the `Compare-Object` from 7.3 shows what was added.

**What this can settle:** whether creating a protected OU adds `(D;;DC;;;WD)` to its parent —
Module 08's leading-but-unestablished explanation. **If the pairs line up with the first child under
each parent and nothing else, the explanation moves from "most likely" to "observed".** If they do
not, that is reported as it is.

### 7.8 Counts for the record

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5137; StartTime=$d0} | Measure-Object
```

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662; StartTime=$d0} | Measure-Object
```

**4662** is `Directory Service Access`, left at `Success` and never touched by this lab. **It may
or may not fire for these writes — not established.** Record the number; don't interpret it yet.

Also the moves from Step 4.1, from `M1` (re-set by hand):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5139; StartTime=(Get-Date '<M1 local>')} | Measure-Object
```

**5139 is "object moved" — recall, never seen in this lab.** `asmith` and WS01 moved *from*
unaudited containers *into* an audited OU. **Whether either side's SACL makes a move auditable is
not established.** Whatever the count, write it down as observed.

### 7.9 Freeze the evidence before photographing anything

```powershell
Set-Location 'C:/evidence'
```

```powershell
wevtutil epl Security 09-dc01-security.evtx
```

```powershell
Get-WinEvent -Path 09-dc01-security.evtx -Oldest -MaxEvents 1 | Select-Object TimeCreated
```

**Export first, photograph at leisure.** DC01's log has never wrapped (Module 08), but "recoverable
later" is how Modules 06 and 07 lost evidence on WS01.

---

# Step 8 — Deliverable: the OU design and the delegation record

**Aim: produce what a real job would ask for — a written statement of how this domain is divided,
who holds power over which part, and the log entry that proves it.**

### 8.1 The OU design

Fill this from readbacks (3.2, 4.1), not from the plan:

| OU | Holds | Audited (SACL)? | Delegations on it |
|---|---|---|---|
| `Corp` | the other OUs | yes — 2.4 | none |
| `Corp/Users/Finance` | `asmith`, `lab_fin09` | inherited from `Corp` | `Helpdesk-Ops`: reset password |
| `Corp/Users/IT` | `hd_tech`, `lab_it09` | inherited | none |
| `Corp/Workstations` | `WS01` | inherited | none |
| `Corp/Servers` | — (DC01 stays in `Domain Controllers`) | inherited | none |
| `Corp/Groups` | `Helpdesk-Ops` | inherited | none |

### 8.2 The delegation record

| Who | Was given | Over | When (UTC) | Logged as |
|---|---|---|---|---|
| `Helpdesk-Ops` | reset password, force change at next logon | `Corp/Users/Finance` | `D2` | the 5136 pair from 7.3 — Correlation ID, time |
| `Helpdesk-Ops` | the same | `Lab09Control` | `D1` | *whatever 7.2 found* |

### 8.3 Two sentences in your own words

> Why is a delegation on an OU harder to spot than a membership in an admin group?

> On a domain you had just been handed, how would you find out whether a delegation made last
> month was ever logged?

---

# Step 9 — Lab state and cleanup (DC01)

**Aim: leave a structure Module 10 can build on, remove only the experiment, and write the state
down from readbacks.**

### 9.1 Remove the control OU

```powershell
Set-ADOrganizationalUnit -Identity 'OU=Lab09Control,DC=corp,DC=local' -ProtectedFromAccidentalDeletion $false
```

```powershell
Remove-ADOrganizationalUnit -Identity 'OU=Lab09Control,DC=corp,DC=local' -Confirm:$false
```

```powershell
Get-ADOrganizationalUnit -Filter "Name -eq 'Lab09Control'"
```

**Prediction:** the readback prints nothing. `-Confirm:$false` means *don't ask*, not *don't do* —
the readback is the proof.

### 9.2 Remove the two test users

```powershell
Remove-ADUser -Identity lab_fin09 -Confirm:$false
```

```powershell
Remove-ADUser -Identity lab_it09 -Confirm:$false
```

Read each back with `Get-ADUser <name>` — **the error `Cannot find an object` is the
confirmation.**

### 9.3 Decide about `hd_tech`

**Recommendation: disable it and keep it**, with the delegation left in place and written down:

```powershell
Disable-ADAccount -Identity hd_tech
```

```powershell
Get-ADUser hd_tech | Select-Object Name, Enabled
```

Module 07's rule: an undocumented enabled account with special rights is the problem, not the
account itself. Disabled and documented, `hd_tech` and the Finance delegation are a ready-made
example for Module 12's attack-path work. **If you would rather remove them, say so — either is
fine, as long as the run log records which.**

### 9.4 Record the state

Into the run log, from readbacks:

- The `Corp` tree — the 3.2 count, re-run
- `asmith` and WS01 — their new distinguished names
- `Helpdesk-Ops`, its member, and the Finance delegation (5.3 count, re-run)
- `hd_tech` — enabled or disabled, as read
- `Lab09Control`, `lab_fin09`, `lab_it09` — removed, confirmed absent
- `Directory Service Changes` — re-read
- `C:\evidence\09-dc01-security.evtx` — present, and the window it covers

> **WS01 has not booted since its account moved.** Nothing is expected to change for it, but that
> is expectation. **Module 10's pre-flight should sign into WS01 as `asmith@corp.local` once** —
> both objects moved — before relying on either.

---

# Step 10 — Evidence for the portfolio

Save into `../assets/`. **Put `hostname` at the top of every terminal frame.** Frames captured
from the host show the host's taskbar — crop to the VM window before committing.

- [x] `09-preflight.png` — `hostname` and the three 0.3 `auditpol` reads (added; filed 2026-11-04)
- [x] `09-sacl-corp-vs-control.png` — `Corp`'s SACL with `WriteDacl`, and `Lab09Control`'s
      without (2.4–2.5). Filed 2026-11-04. **No `hostname` in frame**
- [x] `09-ou-tree.png` — the finished structure (3.2), `hostname` in frame. Filed 2026-11-04
- [ ] `09-delegation-readback.png` — the two `Helpdesk-Ops` ACEs on Finance, and the count (5.3)
- [ ] `09-5136-delegation.png` — the Finance 5136 diff and the decoded ACE (7.3)
- [ ] `09-control-silent.png` — the 7.2 `ObjectDN` list, showing Finance and **not**
      `Lab09Control`. **The absence only counts beside the presence**, as with Module 08's
      `08-no-trusts.png`
- [ ] `09-4724-delegated-reset.png` — Subject `hd_tech`, Target `lab_fin09` (7.5)
- [ ] `09-overstep-inventory.png` — the 7.6 `Group-Object` for the refused window, beside the
      allowed one

---

# Findings

> **Not yet written.** Findings follow the run, in **observation → inference → recommendation**
> form, timestamps in **UTC**. Expected subjects, none of them established: whether delegation is
> logged without an audited `Modify permissions`; what a delegated reset looks like in 4724; what a
> refused overstep leaves; and whether protected-OU creation explains `(D;;DC;;;WD)`.

---

# Reference

**Event IDs this module expects to meet**

| Event ID | Log | Meaning | Status in this lab |
|---|---|---|---|
| 5136 | Security | A directory service object was modified | **confirmed** in Module 08 |
| 5137 | Security | A directory service object was created | **confirmed** in Module 08 |
| 5139 | Security | A directory service object was moved | recall — never observed |
| 4724 | Security | An attempt was made to reset an account's password | **confirmed** in Module 01 (beside a 4720) |
| 4728 | Security | A member was added to a security-enabled global group | **confirmed** in Module 01 |
| 4662 | Security | An operation was performed on an object | recall — subcategory on, never read |

**Audit subcategories**

| Subcategory | Gives | This module |
|---|---|---|
| `Directory Service Changes` | 5136 / 5137 / 5139 / 5141 | read in 0.3, left on |
| `Directory Service Access` | 4662 | **left untouched** — counted in 7.8, never changed |
| `User Account Management` | 4720 / 4722 / 4724 | read in 0.3 |
| `Security Group Management` | 4728 / 4732 / 4756 | read in 0.3 |

**MITRE ATT&CK mapping**

| Technique | ID | Where it appears here |
|---|---|---|
| Account Manipulation | T1098 | Step 6 — a delegated password reset; the same event an attacker holding `hd_tech` would write |
| File and Directory Permissions Modification: Windows | T1222.001 | Step 5 — the closest ATT&CK fit for an ACE written onto an AD object. **The fit is imperfect**; AD permission changes do not have a technique of their own |
| Permission Groups Discovery: Domain Groups | T1069.002 | Step 5.3 — reading who holds rights over an OU is the defender's half of the same enumeration |

---

## Notes & gotchas

**Written before the run:**

- **Two 4724s, two meanings.** `hd_tech`'s creation (Step 4.4) writes one; the delegated reset
  (Step 6.3) writes another. Read **Target Account**, never the ID alone.
- **The DACL and the SACL are different lists on one object.** `.Access` is who may do what;
  `.Audit` is what gets written down. Delegation edits the first; whether it is logged depends on
  the second.
- **A distinguished name reads right to left**, the opposite of a file path.
- **`-SearchBase` limits a search to one branch.** Without it, `Get-ADOrganizationalUnit -Filter *`
  covers the whole domain.
- **Never move DC01 out of `Domain Controllers`.**

**Found in sitting 1 (2026-11-03):**

- **The `AD:` drive does not exist until the ActiveDirectory module loads.** `Get-Acl -Path 'AD:/…'`
  in a fresh window → `Cannot find drive. A drive with the name 'AD' does not exist`. `Get-AD…`
  cmdlets load the module themselves; `Get-Acl` does not. **Run `Import-Module ActiveDirectory`
  first in every new window** — sitting 2's Steps 5.3 and 7 use the drive.
- **A command that printed an error can still have changed the directory.** `New-ADUser` with a
  rejected password failed loudly and left `hd_tech` behind, disabled, no password. Read back after
  a failure too.
- **A misspelt property in `Select-Object` prints `{}` or blank, not an error** —
  `DistinguishedNamme`. Same family as the `-Name` trap.
- **A missing character in a `-like` pattern returns `False`, not an error** — `(D;;DC;;WD)` vs
  `(D;;DC;;;WD)`. Wrong value whispers, again.
- **`-Path` is where the new object goes *into*.** Read it right to left before pressing Enter;
  `Finance` and `IT` landed one level too high.
- **An OU is protected from accidental deletion by default**, so moving one means protection off →
  move → protection on, and **the readback after the move must use the new path** — the old one
  returns `Directory object not found`.
- **`Ctrl+C` at a `>>` continuation prompt discards the pending lines without running them**
  (observed: no output followed). Useful for abandoning a half-typed block.

**Carried in from earlier modules:**

- **Every command in this module runs on DC01.** A query on WS01 returns empty rather than an
  error.
- **Count with `@( )`.** A population of one prints blank for `.Count` and reads like zero.
- **Variables die with the window.** Every boundary is written down in UTC for that reason; re-set
  by hand in UTC+1 and check against a known count.
- **`-Confirm:$false` suppresses the prompt; the action runs.**
- **A command that reported success is not a state that exists.** Read back every change.
- **The newest matching event is not the right event.** Filter by time and content, then pick.
- **Relayed text drifts.** Quote what the log printed, including its capitals.
- **Wrong syntax shouts; wrong value whispers.** A mistyped event ID returns
  `NoMatchingEventsFound` — retype before theorising.
- **`-FilterHashtable` on live logs, `-FilterXPath` on exported `.evtx`.**
