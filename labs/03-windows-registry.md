# Module 03 — The Windows Registry & Persistence

> **Runs on:** WS01 (everything; no DC01 needed)
> **Time:** ~2.5 hours, best split across two sittings
> **Roll back to:** `mod03-start` (taken in Step 0.3) · **Snapshot before starting:** `mod03-start`
> **Status:** written 2026-09-10 · **MID-RUN — Steps 0–5 complete, resume at Step 6** (paused 2026-09-12)

---

## What you're going to do

An attacker who gets code running on a machine has one urgent problem: they lose
everything the moment it reboots. **Persistence** is how they solve it, and on Windows the
registry is where they solve it — a value pointing at their payload, planted in a key that
Windows reads at every startup or logon. It costs one line and survives reboots.

So the analyst's question in this module is: **what changed in the registry, who changed
it, and does it run something at startup?**

You'll answer it twice, with two completely different instruments:

1. **Native Windows auditing** → event **4657**. This is Module 02's SACL model again,
   moved from files to registry keys — same Object Access category, same four gates, same
   "camera pointed at one door" design. Nothing new to install.
2. **Sysmon** → event **13**. A third-party driver from Sysinternals that watches *every*
   key on the machine from the moment it's installed.

The contrast is the point of the module, and it's a real operational trade-off:

> **Native auditing is opt-in per object. Sysmon is opt-out per rule.**
> A 4657 only exists if you put a SACL on that exact key *beforehand* — so it can only
> ever tell you about keys you already suspected. Sysmon needs no SACL and no audit
> subcategory: install it once and every registry write on the box is a candidate, filtered
> down by a config file you control. Native is built in and free; Sysmon has to be deployed
> and maintained. Real SOCs run both, and this module shows you exactly which blind spot
> each one covers.

In this module you will:

1. Read the registry as a filesystem — hives, keys, values, types
2. Tour the persistence keys every analyst should know cold
3. Baseline the `Run` keys, so "what changed" has a *before* to compare against
4. Turn on registry auditing and put a SACL on one key — the camera again
5. Plant benign fake persistence in **three** places, only one of which is audited
6. Detect it natively (**4657**), and find the two you *missed* — the module's real lesson
7. Install and configure Sysmon, re-run the same activity, and catch all three (**13**)
8. Produce the deliverable: a top-10 registry persistence table with the hunt for each

Follow the steps in order. Every step says **which VM** — as in Module 02, it's always
WS01.

> **About backslashes.** Registry paths are nothing but backslashes, and this keyboard
> layout makes `\` awkward to type. Two ways around it, used throughout this module:
> **navigate the tree by clicking in `regedit`** rather than typing paths, and when you
> need a path as text, right-click the key → **Copy Key Name**, then paste. Step 1.2 also
> tests whether PowerShell will take `/` as a separator, which would sidestep the problem
> entirely for the `HKLM:` drive.

---

# Step 0 — Pre-flight

### 0.1 Start from the end of Module 02

**Aim: begin on a WS01 that already has Object Access auditing configured, so this module
adds one subcategory rather than starting from nothing.**

Module 02 left three audit subcategories enabled on this host. You want to keep them —
`Registry` is a *fourth* one in the same category, and having the others on makes the
comparison meaningful.

Boot **WS01** and log in as `administrator` / `Lab-Passw0rd!`. Confirm you're on the right
machine and the Module 02 config survived:

```powershell
auditpol /get /category:"Object Access"
```

You should see `File System`, `Handle Manipulation` and `Registry` listed among others —
`File System` and `Handle Manipulation` reading **Success and Failure** from Module 02, and
**`Registry` almost certainly reading `No Auditing`**. That last one is what Step 3 turns
on.

> If you restored a snapshot from before Module 02 and those read `No Auditing`, that's
> fine — Step 3 sets what this module needs. But re-read Module 02's four-gate table
> first, because this module assumes it.

### 0.2 Get Sysmon onto WS01

**Aim: have the Sysmon binary sitting on WS01 before you need it in Step 6, because the
lab has no internet and a failed transfer mid-module is a sitting lost.**

The Sysinternals Suite is already on the lab host. Move it in with VirtualBox's
bidirectional transfer:

1. With WS01 running, in the VirtualBox window: **Devices → Drag and Drop → Bidirectional**,
   and **Devices → Shared Clipboard → Bidirectional**.
2. Drag `Sysmon64.exe` (or the whole Sysinternals folder) from the host desktop onto the
   WS01 desktop.
3. On **WS01**, put it somewhere stable and easy to type:

```powershell
New-Item -Path 'C:\Tools' -ItemType Directory
```

Move `Sysmon64.exe` into `C:\Tools`, then confirm it arrived:

```powershell
Get-ChildItem C:\Tools
```

> **Drag and drop needs Guest Additions installed on WS01**, and the menu items stay greyed
> out without them. If they're missing: **Devices → Insert Guest Additions CD image**, run
> the installer inside WS01, reboot, then retry. If it still won't cooperate, the fallback
> is the one Module 00 used for ISOs — no internet needed either way, so don't be tempted
> to give the VM network access to fetch Sysmon.

### 0.3 Snapshot

**Aim: bookmark this state so you can replay the Break steps, which is worth doing here —
the whole module is "plant a thing, then find it."**

Shut WS01 down cleanly and take a snapshot named **`mod03-start`**. Boot back up.

---

# Step 1 — The registry as a filesystem (WS01)

**Aim: stop seeing the registry as a mysterious blob and start navigating it like a
directory tree, so that in Step 2 you can read a persistence key without help.**

Coming from Linux this is easier than it looks, because the shape is familiar:

| Registry | Filesystem equivalent |
|---|---|
| **hive** (`HKLM`, `HKCU`) | a mount point — a separate tree with its own file on disk |
| **key** | a directory |
| **subkey** | a subdirectory |
| **value** | a file inside that directory |
| **value data** | the file's contents |
| **value type** (`REG_SZ`, `REG_DWORD`) | the file's format |

The one place the analogy breaks: a key has a **default value** — an unnamed value, shown
by `regedit` as `(Default)`. Think of it as a directory that also holds contents.

### 1.1 The five hives, in the GUI

**Aim: know which hive you're in, because the same key path means different things in
different hives — and one of them is per-user.**

On **WS01**, press **Win+R**, type `regedit`, Enter, accept the UAC prompt. You'll see five
root nodes:

| Hive | Short | What lives there |
|---|---|---|
| `HKEY_LOCAL_MACHINE` | **HKLM** | machine-wide settings — applies to **every user**. Needs admin to write |
| `HKEY_CURRENT_USER` | **HKCU** | settings for **the user running right now**. Writable *without* admin |
| `HKEY_USERS` | **HKU** | every loaded user profile, one subkey per SID. `HKCU` is just a shortcut into one of these |
| `HKEY_CLASSES_ROOT` | HKCR | file associations and COM registrations (a merged view, not its own store) |
| `HKEY_CURRENT_CONFIG` | HKCC | current hardware profile (rarely interesting) |

> **The two that matter for this module are HKLM and HKCU, and the difference is the whole
> game.** Writing persistence to **HKLM** runs it for everyone and **needs admin**. Writing
> to **HKCU** runs it only for that one user but needs **no privileges at all** — any
> account that can run code can persist itself. That's why HKCU `Run` is one of the most
> common persistence locations in the wild, and it's the one Step 5 will show you missing.

### 1.2 The same tree in PowerShell

**Aim: read registry values from the shell, so your detection work and your admin work use
the same tool.**

PowerShell exposes hives as **drives**, exactly like `C:`. Start with the shortest useful
command — in **PowerShell (Admin)** on **WS01**:

```powershell
Get-PSDrive -PSProvider Registry
```

You'll get `HKCU` and `HKLM`. Now `cd` into one the way you would a directory:

```powershell
Set-Location HKLM:
```

```powershell
Get-ChildItem
```

`Get-ChildItem` in a registry drive lists **subkeys** — the directories. To see the
**values** — the files — you need a different verb, because they're properties of the key
rather than children of it:

```powershell
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion
```

> **This is the one structural surprise.** `Get-ChildItem` shows you subkeys and *no
> values at all* — so a key full of interesting values looks empty. If a registry key
> seems to contain nothing, you almost certainly used the wrong verb. Subkeys →
> `Get-ChildItem`. Values → `Get-ItemProperty`.

**Now test the backslash workaround.** Run the same command with forward slashes:

```powershell
Get-ItemProperty HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion
```

**Confirmed on WS01, 2026-09-10: this works.** PowerShell's registry provider normalises `/`
to `\`, so every path in this module can be typed the easy way — and the same goes for
`Get-Acl`, `Set-ItemProperty` and `Remove-ItemProperty` later on.

Two cautions on the limits of it. It does **not** work for **`reg.exe`** (Step 4.1), which is
a plain Win32 program and not provider-aware — that one needs real backslashes. And the
**event log always prints paths back with backslashes** regardless of how you typed them, so
this changes how you *write* queries, never how you *read* results.

### 1.3 Value types

**Aim: read a value's type as evidence, because a persistence entry is almost always a
string and a disabled-security-feature is almost always a DWORD of `0`.**

| Type | Holds | You'll see it as |
|---|---|---|
| `REG_SZ` | text | a path, a command line — **this is what a `Run` entry is** |
| `REG_EXPAND_SZ` | text with variables | `%SystemRoot%\system32\...` — expanded when read |
| `REG_DWORD` | a 32-bit number | `0`/`1` flags — feature on/off, including security features |
| `REG_BINARY` | raw bytes | opaque blobs; encoded payloads sometimes hide here |
| `REG_MULTI_SZ` | a list of strings | multiple entries in one value |

---

# Step 2 — The persistence keys, and a baseline (WS01)

**Aim: learn the handful of keys that carry most real-world persistence, and record what
they hold *now* — because "what changed" is unanswerable without a before.**

### 2.1 Read the two `Run` keys

`Run` is the simplest persistence there is: **every value in this key is a command Windows
executes at logon.** The value's *name* is arbitrary — it's just a label — and the value's
*data* is the command. That's the whole mechanism.

Machine-wide first, in **PowerShell (Admin)** on **WS01**:

```powershell
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

Then the current user's:

```powershell
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

You'll see a few legitimate entries (`SecurityHealth`, maybe VirtualBox Guest Additions)
mixed with PowerShell's own bookkeeping properties (`PSPath`, `PSParentPath`, `PSChildName`,
`PSDrive`, `PSProvider`). Those five are **not registry values** — they're metadata
PowerShell attaches to everything. Ignore them; they'll clutter every read you do.

### 2.2 Save the baseline

**Aim: produce a file you can diff against after the Break step — the same discipline as
reading a DACL before changing it in Module 02.**

```powershell
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Out-File C:\Tools\run-baseline-hklm.txt
```

Do the same for `HKCU`, into `run-baseline-hkcu.txt`. Open one to confirm it's not empty:

```powershell
Get-Content C:\Tools\run-baseline-hklm.txt
```

> **Why bother, when the log will tell you?** Because the log only tells you about changes
> made *while auditing was on and pointed at that key*. The baseline catches what was
> already there — including anything planted before you started watching. Auditing is not
> retroactive; a baseline is the only thing that reaches backwards.

### 2.3 Look at the other three, read-only

**Aim: recognise them on sight in an investigation. You are not changing any of these.**

Navigate in `regedit` by clicking (no path typing), and just *look*:

- **Services** — `HKLM\SYSTEM\CurrentControlSet\Services`. One subkey per service and
  driver. `ImagePath` is the binary that runs, `Start` is a DWORD controlling when
  (`2` = automatic at boot). A service runs as **SYSTEM**, so this is persistence *and*
  privilege in one move.
- **Winlogon** — `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`. Look at
  **`Shell`** (should be exactly `explorer.exe`) and **`Userinit`** (should be exactly
  `C:\Windows\system32\userinit.exe,`). Attackers **append** a second command after a
  comma — the original still runs, so nothing looks broken.
- **Image File Execution Options** — `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`.
  A subkey named after an executable with a **`Debugger`** value launches *that* instead of
  the program. The classic sticky-keys backdoor lives here.

> **Do not edit `Userinit` or `Shell` on this VM.** A typo in either one produces a machine
> that boots to a blank blue screen with no desktop and no shell — recoverable only by
> snapshot restore. They're in this module to be *recognised*, not exercised. Step 4 uses
> `Run` keys, which are harmless: a bad value there just fails to launch.

---

# Step 3 — Turn on the camera for registry keys (WS01)

**Aim: make Windows write an event when a registry value changes. This is Module 02's
model again — and every trap from it applies here unchanged.**

Same two-part structure, same independence:

- **The policy switch** — the `Registry` subcategory, which is *separate* from
  `File System`. Module 02 enabling `File System` did nothing for the registry.
- **The SACL** — an audit rule on one specific key. A key with no SACL is never logged.

### 3.1 Flip the policy switch

In **PowerShell (Admin)** on **WS01**, look before you set:

```powershell
auditpol /get /subcategory:"Registry"
```

Expect **No Auditing**. Turn it on:

```powershell
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
```

Confirm:

```powershell
auditpol /get /subcategory:"Registry"
```

You want **Success and Failure**. Success gives you the change that worked — which for
persistence is the one that matters. Failure gives you an unprivileged account *trying* to
write to HKLM and being refused, which is a nice signal in its own right.

> **The four gates from Module 02, translated to the registry.** Nothing about the
> structure changed — only the names:
>
> | # | Gate | Governs |
> |---|---|---|
> | 1 | **`Registry`** subcategory | **4657** — a registry value was changed |
> | 2 | `Handle Manipulation` subcategory | **4656** — a handle to the key was *requested*; carries allow/deny |
> | 3 | `Authorization Policy Change` subcategory | **4670** — the key's *permissions* changed |
> | 4 | The SACL's **audited rights** on the key | *which* actions any of the above records |
>
> Gates 2 and 3 you already enabled in Module 02 and they carry over — object access is one
> mechanism across files and registry keys. Gate 1 is registry-specific and off by default.
> Gate 4 is per-key, and Step 3.2 is where you set it. **And none of it is retroactive.**

### 3.2 Point the camera at one key — the SACL

**Aim: put an audit rule on `HKLM\...\Run` so a write to it produces a 4657.**

Do this in the GUI — the path is deep and clicking beats typing backslashes.

In **`regedit`** on **WS01**, expand down to:

`HKEY_LOCAL_MACHINE` → `SOFTWARE` → `Microsoft` → `Windows` → `CurrentVersion` → `Run`

Then **right-click the `Run` key → Permissions… → Advanced → Auditing tab**:

1. **Add → Select a principal →** type `Everyone` → **OK**
2. **Type: All** (records both successful and failed attempts)
3. **Applies to: This key and subkeys**
4. Click **Show advanced permissions**, then tick:
   - **Set Value** — the one that produces 4657. *Without this, nothing else matters.*
   - **Create Subkey** and **Delete** — catches a whole key being added or removed
   - **Write DAC** — the key's own permissions being changed (this is what feeds 4670)
5. **OK** out of every window.

Applying that SACL writes a **4907** immediately — same as Module 02, and your proof of
when the camera went up.

> **Gate 4, and why "Set Value" is the whole ballgame.** The rights you tick here *define*
> what gets recorded. A `Run` persistence entry is written with the **Set Value** right,
> and nothing else on that list implies it. Leave it unticked and planting persistence in
> this key produces **no 4657 at all**, with `auditpol /get /subcategory:"Registry"`
> cheerfully reading "Success and Failure". That is exactly the failure Module 02 hit with
> `WRITE_DAC` and 4670 — same gate, different right. **Verify the tick before you move on**,
> because the cost of not doing so is discovering it after the Break step, when it's too
> late to log.

### 3.3 Confirm the SACL landed

**Aim: prove the camera is installed rather than assume it — Module 02's SACL silently
failed to commit on its first apply.**

```powershell
(Get-Acl 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Audit).Audit
```

You want a rule for `Everyone` and `AuditFlags` reading `Success, Failure`. If `.Audit` comes
back empty, the apply didn't commit — redo 3.2 and check for a 4907 before continuing.

**Do not look for the literal string `SetValue` in `RegistryRights` — it will not be there.**
Measured on WS01, 2026-09-10: a correct SACL printed `Delete, WriteKey, ChangePermissions`.
`RegistryRights` is a **bit flag** enum, and .NET prints the *composite* name whenever all the
bits of a combination are set:

| Name | Value | Made of |
|---|---|---|
| `SetValue` | `2` | — |
| `CreateSubKey` | `4` | — |
| **`WriteKey`** | **`6`** | **`SetValue` + `CreateSubKey`** |
| `Delete` | `65536` | — |
| `ChangePermissions` | `262144` | `WRITE_DAC` |

So ticking both **Set Value** and **Create Subkey** in Step 3.2 makes the string `SetValue`
vanish into `WriteKey`. Reading the names would tell you gate 4 is closed when it is open —
and the natural response is to go back and re-tick it, or conclude the SACL never committed.

**Test the bit instead:**

```powershell
((Get-Acl HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion/Run -Audit).Audit[0].RegistryRights -band 2) -ne 0
```

`-band 2` masks off everything except the `SetValue` bit. **`True` means gate 4 is open.** This
is the check to trust — the friendly names are a rendering, the bitmask is the fact.

---

# Step 4 — Break: plant fake persistence in three places (WS01)

**Aim: generate the telemetry — and deliberately produce a detection *gap*, because the two
entries you plant outside the audited key are the lesson of this module.**

Everything here is benign: the payload is `notepad.exe`, and you'll remove it in Step 7.
**Note the time before you start** — you'll filter on it.

### 4.1 HKLM `Run` — the audited key, using `reg add`

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v LabPersist /t REG_SZ /d "notepad.exe" /f
```

`reg.exe` is the old Win32 tool, and worth knowing because it's what you'll see in *attacker*
command lines far more often than PowerShell. Read the switches: `/v` value name, `/t` type,
`/d` data, `/f` force (no prompt). **This one needs real backslashes** — `reg.exe` is not
provider-aware, so the forward-slash trick from Step 1.2 won't work here.

Confirm it's there:

```powershell
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### 4.2 HKCU `Run` — not audited, and no admin needed

```powershell
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name LabPersistUser -Value 'notepad.exe'
```

Same outcome, different tool and different hive. `Set-ItemProperty` is the PowerShell-native
way — and note what it *didn't* need: **no elevation.** This is the realistic attacker path.

### 4.3 HKLM `RunOnce` — also not audited

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v LabPersistOnce /t REG_SZ /d "notepad.exe" /f
```

`RunOnce` executes at the next logon and then **deletes itself** — which is precisely why
attackers like it. The entry is gone by the time anyone looks, so the *log* is the only
place it ever existed.

### 4.4 Confirm all three, then stop

```powershell
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

You now have three persistence entries planted, of which **exactly one sits under a SACL.**
Write down the time. Don't reboot — you don't need to, and `RunOnce` would consume itself.

---

# Step 5 — Detect natively: 4657, and the gap (WS01)

**Aim: find the planted entry in the Security log with its old and new values, then prove
to yourself that the other two are invisible — which is the finding.**

### 5.1 Start wide

In **PowerShell** on **WS01**:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4657; StartTime=(Get-Date).AddHours(-1) } -MaxEvents 20 |
  Format-Table TimeCreated, Id -AutoSize
```

Confirms 4657s exist and the plumbing works. If this is empty, stop and work the gate list
in Step 3 — do not proceed assuming the write didn't happen.

### 5.2 Pull the fields by name

The default view hides everything useful, exactly as in Modules 01/04/05. Add the fields
one at a time; start with just who and what:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4657; StartTime=(Get-Date).AddHours(-1) } -MaxEvents 20 |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
      Time   = $_.TimeCreated
      Who    = ($d | Where-Object Name -eq 'SubjectUserName').'#text'
      Object = ($d | Where-Object Name -eq 'ObjectName').'#text'
    }
  } | Format-Table -AutoSize
```

Look at the `Object` column before you go further — the path will **not** say `HKLM`.

> **4657 prints kernel object paths, not the names you typed.** `HKLM\…` comes back as
> **`\REGISTRY\MACHINE\…`**, and `HKCU\…` as **`\REGISTRY\USER\<SID>\…`**. So filtering on
> `'*HKLM*'` matches nothing and reads exactly like "no events" — the same false-negative
> shape as the wrong-VM and starved-`-MaxEvents` traps. Filter on the part that survives
> the translation: `'*CurrentVersion\Run*'`. Confirm the exact form during the run and
> record it, since every hunt query you write later depends on it.

### 5.3 The fields that make 4657 valuable

Now add the four that turn a "something changed" alert into a finding:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4657; StartTime=(Get-Date).AddHours(-1) } -MaxEvents 20 |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
      Time      = $_.TimeCreated
      Who       = ($d | Where-Object Name -eq 'SubjectUserName').'#text'
      Object    = ($d | Where-Object Name -eq 'ObjectName').'#text'
      ValueName = ($d | Where-Object Name -eq 'ObjectValueName').'#text'
      Operation = ($d | Where-Object Name -eq 'OperationType').'#text'
      OldValue  = ($d | Where-Object Name -eq 'OldValue').'#text'
      NewValue  = ($d | Where-Object Name -eq 'NewValue').'#text'
      Process   = ($d | Where-Object Name -eq 'ProcessName').'#text'
    }
  } | Where-Object { $_.Object -like '*CurrentVersion\Run*' } | Format-Table -AutoSize
```

You should see `LabPersist`, `OperationType` reading **"New registry value created"**,
`NewValue` reading `notepad.exe`, and `Process` reading `reg.exe`.

> **`OldValue` and `NewValue` are why 4657 beats most events.** Almost nothing else in the
> Security log tells you *what the data was before and after* — 4688 gives you a command
> line, 4663 gives you an access mask, but 4657 hands you the actual before-and-after
> string. For a Winlogon `Userinit` append, the diff between old and new **is** the payload.
> `OperationType` is the other one to read: *created* / *modified* / *deleted* distinguishes
> new persistence from a hijack of something legitimate.

### 5.4 Now go looking for the other two

**Aim: experience the blind spot deliberately, so you understand what native auditing can
and cannot promise.**

Search the same window for the HKCU entry:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4657; StartTime=(Get-Date).AddHours(-1) } -MaxEvents 50 |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    ($d | Where-Object Name -eq 'ObjectValueName').'#text'
  }
```

`LabPersistUser` and `LabPersistOnce` will not be there.

Before concluding anything, walk the checklist properly — an absence is only evidence once
you've excluded the boring explanations. Window too narrow? Widen to `AddDays(-1)`. Log
rotated? `wevtutil gli Security` and compare `FileSize` to `MaximumSizeInBytes`. Wrong
machine? You're on WS01 for all of it.

Once those are excluded, the absence is real and it means something precise:

> **This is the finding, and it is not a misconfiguration.** Registry auditing worked
> perfectly — for the one key you pointed it at. `HKCU\…\Run` and `HKLM\…\RunOnce` have no
> SACL, so writes to them are not events and never were. **Native registry auditing can
> only tell you about keys you already thought to watch**, which means it can never surface
> a persistence location you hadn't anticipated. Note also *which* one you missed: the HKCU
> write needed **no admin rights**, making it the easiest and commonest of the three to
> perform. That's the gap Sysmon exists to close.

---

# Step 6 — Install and configure Sysmon (WS01)

**Aim: get a driver-level view of every registry write on the machine, with no per-key
setup at all.**

### 6.1 Install

In **PowerShell (Admin)** on **WS01**:

```powershell
Set-Location C:\Tools
```

```powershell
.\Sysmon64.exe -i -accepteula
```

`-i` installs; `-accepteula` skips the licence dialog. Sysmon installs a **service and a
kernel driver**, so this needs elevation and takes a few seconds. Confirm it's running:

```powershell
Get-Service Sysmon64
```

And that its log now exists:

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
```

> **Note where Sysmon's events land: `Microsoft-Windows-Sysmon/Operational`, not
> Security.** Different log, its own retention, its own event IDs starting at 1. In Event
> Viewer it's under **Applications and Services Logs → Microsoft → Windows → Sysmon →
> Operational** — the same tree Module 04 explored. A `Get-WinEvent` query against
> `LogName='Security'` will never see a Sysmon event no matter how right the rest of it is.

### 6.2 Write a config

**Aim: filter Sysmon down to the persistence keys, because unfiltered registry logging will
bury you.**

> **Check the schema version against your own binary before writing the file.** Run
> `.\Sysmon64.exe -s | Select-Object -First 3`. `-s` dumps the config schema Sysmon was compiled
> with, and the root element carries the number you need. On WS01 (Sysmon **v15.15**) it returned
> `<manifest schemaversion="4.90" binary version=18>`, so the `4.90` below is correct *for that
> build* — but read it, don't inherit it. That dump is also the authoritative list of every field
> your build can filter on, which beats a blog post written against a different version.

**First, look at what the bare install is already doing** — before you change it, so you can tell
what your config actually altered:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational' } |
  Group-Object Id -NoElement | Sort-Object Count -Descending
```

> **Measured on WS01: 30 records, event IDs 1, 4, 5 and 16 — and no 13.** Process create,
> Sysmon service state change, process terminate, Sysmon config state change. **Sysmon's
> default rule set logs no registry events whatever.** That inverts the obvious assumption:
> the config below is not trimming a registry flood down to the interesting keys, it is
> **switching registry logging on for the first time**. Worth internalising, because "Sysmon
> is installed" and "Sysmon would have caught that" are completely different claims, and on a
> host with no config the second one is false.
>
> The flood warning is still real — it just belongs to the config, not the install. An
> `onmatch="include"` set that is too broad, or an `exclude` set, pointed at a hive Windows
> writes to constantly while idle, will bury you and (per Module 04) roll your older evidence
> out of the log.

To confirm the IDs rather than trust the list above, resolve them on the box:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational' } |
  Sort-Object Id -Unique |
  Select-Object Id, @{ n='What'; e={ ($_.Message -split "`r`n")[0] } }
```

Two constructs here. **`-Unique`** collapses the sorted results to one row per distinct `Id`.
**`@{ n='What'; e={ … } }`** is a *calculated property* — `n` names the column, `e` is an
expression evaluated per object to fill it; this one takes `.Message` and keeps only its first
line. That is the Module 04 lesson used deliberately: `Message`'s first line is useless when
every row is the same event ID, and exactly what you want when every row is a different one.

Create `C:\Tools\sysmon-registry.xml` on **WS01**. Use Notepad, and per Module 05's lesson
open it with an explicit path so the file lands where you think it does:

```powershell
notepad C:\Tools\sysmon-registry.xml
```

Paste this in and save:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="persistence" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">Winlogon\Shell</TargetObject>
        <TargetObject condition="contains">Winlogon\Userinit</TargetObject>
        <TargetObject condition="contains">Image File Execution Options</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Read what it says: **`onmatch="include"` means log *only* these and drop everything else.**
Each `TargetObject … contains` is one substring match against the key path. `CurrentVersion\Run`
catches `Run` **and** `RunOnce`, in **both** hives, from that single line — you're matching a
path fragment, not a hive. (An earlier draft of this config had a separate `CurrentVersion\RunOnce`
line; it was removed during the run as redundant, which is worth noticing: a substring rule
covers more than it looks like it does, and that cuts both ways when you're auditing someone
else's config for blind spots.)

**Backslashes here are real backslashes.** This is a text match against the path Sysmon reports
(`HKLM\…`), not a PowerShell provider path, so the forward-slash trick from Step 1.2 does not
apply. Paste the block rather than retyping it.

Monitoring `Winlogon\Shell` and `Userinit` is safe — the standing warning on WS01 is against
**writing** those two values, never against watching them. They are in the config precisely
because they are the dangerous ones.

Apply it:

```powershell
.\Sysmon64.exe -c C:\Tools\sysmon-registry.xml
```

Confirm what's loaded:

```powershell
.\Sysmon64.exe -c
```

> **If it rejects the schema version**, your Sysmon build is older or newer than `4.90`.
> Run `.\Sysmon64.exe -? config` to see the version it expects and change the number in the
> file to match — the rest of the config is stable across versions.

---

# Step 7 — Break again, and detect with Sysmon 13 (WS01)

**Aim: run the *identical* activity against the *identical* keys and watch all three land
this time — an A/B test where the only variable is the instrument.**

### 7.1 Clean up and replant

Remove the three entries from Step 4:

```powershell
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v LabPersist /f
```

Do the same for `LabPersistOnce` in `RunOnce`, and for the HKCU one:

```powershell
Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name LabPersistUser
```

> **If your run drifted from the script** — extra test values, or `LabPersist` already deleted
> during Step 5 — do **not** work from the names above. Re-read both `Run` keys and `RunOnce`
> first and clear what is actually there. `Remove-ItemProperty`'s `-Name` accepts an array, so
> several values go in one command:
>
> ```powershell
> Remove-ItemProperty -Path HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion/Run -Name LabPersistBoot,LabPersistPS,LabPersistRegNow
> ```
>
> Most cmdlet parameters that read as singular take multiple values this way — worth reaching
> for instead of writing the same line three times.

**Note the time in UTC before you touch anything** — `(Get-Date).ToUniversalTime()` — then
**replant all three exactly as in Steps 4.1–4.3.**

> **Watch the deletions too, not just the replant.** They happen with *both* instruments live:
> the SACL is still on the HKLM key and Sysmon is now configured. Native 4657 is already known
> to fire on deletes (verified in Step 5). Whether Sysmon reports a *value* deletion as an
> Event 12, an Event 13, or not at all is **not** something to answer from memory — check the
> log. It is a free observation the cleanup hands you before the real A/B begins.

### 7.2 Read the Sysmon log

Start wide, on **WS01**:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=13 } -MaxEvents 20 |
  Format-Table TimeCreated, Id -AutoSize
```

Then pull the fields by name — same technique, different log:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=13; StartTime=(Get-Date).AddMinutes(-30) } |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
      UtcTime = ($d | Where-Object Name -eq 'UtcTime').'#text'
      Target  = ($d | Where-Object Name -eq 'TargetObject').'#text'
      Details = ($d | Where-Object Name -eq 'Details').'#text'
      Image   = ($d | Where-Object Name -eq 'Image').'#text'
    }
  } | Format-List
```

Three deliberate choices in there, each one a lesson this repo paid for:

- **`StartTime` relative and local** (`AddMinutes(-30)`) rather than a typed timestamp, so
  there is no UTC-versus-local arithmetic to get wrong at the moment of querying.
- **`UtcTime` pulled from the event data, not converted from `TimeCreated`.** Sysmon writes
  UTC into a field of its own — read it directly. Module 04's eight-hour Pacific/WAT mess came
  from exactly the conversion this avoids.
- **`Format-List`, not `Format-Table`.** `Format-Table` truncates to the console width and
  registry paths are always wider than the console, so the value name — the last segment, and
  the part you actually need — is the first thing cut off.

**All three are here** — `LabPersist`, `LabPersistUser` and `LabPersistOnce` — with no SACL
on two of the three keys and no audit subcategory involved at all.

Measured on WS01, 2026-09-12:

| UTC | Value | Key | `Details` | `Image` |
|---|---|---|---|---|
| 21:00:22.880 | `LabPersist` | `HKLM\…\CurrentVersion\Run` | `notepad.exe` | `reg.exe` |
| 21:06:25.500 | `LabPersistUser` | `HKU\<SID>\…\CurrentVersion\Run` | `Notepad.exe` | `powershell.exe` |
| 21:08:15.088 | `LabPersistOnce` | `HKLM\…\CurrentVersion\RunOnce` | `notepad.exe` | `reg.exe` |

Two details in that table are worth more than they look.

**The user-hive path came back as `HKU\<SID>\…`, not `HKCU\…`.** You wrote it with `HKCU:`
and Sysmon logged it against the SID. **A hunt filtering on `'*HKCU*'` returns nothing** — and
it is the per-user `Run` key, the one an attacker reaches without admin. This is the exact
mirror of the 4657 lesson from Step 5: each log normalises paths its own way, and neither
matches the shorthand you type.

**`Details` preserved the case exactly as written** — `Notepad.exe` in one row, `notepad.exe`
in the others, because that is how each command was typed. Any hunt matching on value data
must be case-insensitive.

Note the differences from 4657 as you read it:

| | Native **4657** | Sysmon **13** |
|---|---|---|
| Needs a SACL on the key | **yes** | no |
| Needs an audit subcategory | **yes** (`Registry`) | no |
| Path format | `\REGISTRY\MACHINE\…` | `HKLM\…` for machine keys — but **`HKU\<SID>\…` for the user hive, never `HKCU\`** |
| Shows the old value | **yes** (`OldValue`) | no — `Details` is the new value only |
| Names the process | `ProcessName` | `Image`, plus `ProcessGuid` for correlation |
| Scope | one key, chosen in advance | every key, filtered by config |

> **Neither one wins outright, and that's the takeaway.** Sysmon has the coverage: it sees
> keys you never thought to watch, which is the only way to catch a persistence technique
> you didn't predict. Native 4657 has the **old value**, which Sysmon simply does not
> record — and for a *modified* rather than *created* value, the old data is often the
> single most important field in the event. Sysmon also has to be installed, configured and
> kept updated on every host; 4657 is already on every Windows machine in the estate.
> Run both, and know which question each one answers.

### 7.3 Sysmon's other two registry events — and where deletions really live

**Aim: find out what Sysmon does with a value *deletion*, because "the attacker cleaned up
after themselves" is a question you will be asked on shift.**

Sysmon splits registry activity across three IDs:

- **Event 12** — key created or deleted
- **Event 13** — **value set** — the one you just used, and the one that catches persistence
- **Event 14** — key or value **renamed**

Read that list and you would reasonably expect a deleted *value* to be a 13, or to have no
home at all. Don't guess — you deleted four values in Step 7.1, so the answer is already in
the log. Ask for all three IDs at once:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=12,13,14 } |
  Group-Object Id -NoElement
```

**`Id` takes an array**, the same way `-Name` did on `Remove-ItemProperty`. Asking for all
three matters: if you filtered to 13 alone and got nothing, you could not tell "Sysmon didn't
log it" from "Sysmon logged it as something else."

Note also what is *missing* from that query — there is no `-MaxEvents`. That is a deliberate
exception to the usual rule, safe only because this log is hours old and small. See the
gotcha at the end of this file for what happened when the cap was left in.

Now break the 12s down by what they actually did:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=12 } |
  ForEach-Object {
    $d = ([xml]$_.ToXml()).Event.EventData.Data
    [pscustomobject]@{
      Type   = ($d | Where-Object Name -eq 'EventType').'#text'
      Target = ($d | Where-Object Name -eq 'TargetObject').'#text'
    }
  } | Where-Object Type -eq 'DeleteValue' |
  Select-Object -ExpandProperty Target
```

Two things to notice about the shape of that pipeline. **`Where-Object` here is legitimate** —
it narrows a result set that `-FilterHashtable` already fetched correctly, which is the one
use this repo endorses; it is not standing in for a proper filter. And
**`Select-Object -ExpandProperty Target`** prints the raw strings one per line instead of a
table, which is what stops the truncation that would otherwise hide the value name at the end
of each path.

> **The answer, measured on WS01 2026-09-12: a deleted value is an Event 12 carrying
> `EventType = DeleteValue`.** Not a 13. All four Step 7.1 deletions were there with full
> paths. So **hunting for persistence cleanup means watching 12, not 13** — and a rule that
> only alerts on 13 will show you the attacker arriving and never leaving.

The `EventType` field is doing the real work here: `CreateKey`, `DeleteKey`, `DeleteValue`
all arrive under the same event ID, and the ID alone does not tell you which. This is the
Sysmon equivalent of 4657's `OperationType` — the event ID gets you to the right pile, and a
field inside it tells you what actually happened.

### 7.4 Clean up

Remove all three entries again, using the commands from 7.1, and confirm the keys match your
Step 2.2 baseline:

```powershell
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

Leave Sysmon installed — Modules 06 and 07 will use it.

---

# Step 8 — Deliverable: the persistence hunt table

**Aim: produce the artifact this module exists to create — a reference you'd actually use
on shift.**

Fill in the right-hand column as you verify each one on WS01. The MITRE IDs and locations
are given; the hunt is what you write.

| # | Location | Why it runs | MITRE | Hunt |
|---|---|---|---|---|
| 1 ✅ | `HKLM\…\CurrentVersion\Run` | at logon, all users, needs admin | T1547.001 | Sysmon 13 / 4657 where value **data** is not a signed Microsoft path. **Verified on WS01** — caught by both |
| 2 ✅ | `HKCU\…\CurrentVersion\Run` | at logon, one user, **no admin** | T1547.001 | Sysmon 13 — **match `HKU\<SID>\`, not `HKCU\`**, which is how Sysmon logs it. 4657 misses it entirely unless that profile's hive is SACL'd. **Verified on WS01 — 4657 missed it** |
| 3 ✅ | `HKLM\…\CurrentVersion\RunOnce` | next logon, then **self-deletes** | T1547.001 | Sysmon 13 — the entry won't exist by the time you look, so the log is the only record. **Verified on WS01 — 4657 missed it** |
| 4 | `HKCU\…\CurrentVersion\RunOnce` | next logon, one user, no admin | T1547.001 | as rows 2 and 3 combined — `HKU\<SID>\`, self-deleting, no admin needed. The worst case of the four |
| 5 | `HKLM\SYSTEM\CurrentControlSet\Services\*` (`ImagePath`) | at boot, **as SYSTEM** | T1543.003 | 4697 service install; Sysmon 13 on `ImagePath`; `Start`=2 |
| 6 | `…\Winlogon` → `Userinit` | at logon, before the shell | T1547.004 | 4657 `OldValue` vs `NewValue` — the appended command is the diff |
| 7 | `…\Winlogon` → `Shell` | at logon, replaces explorer | T1547.004 | any value that is not exactly `explorer.exe` |
| 8 | `…\Image File Execution Options\<exe>` → `Debugger` | when that exe launches | T1546.012 | Sysmon 13 on any new `Debugger` value |
| 9 | `HKLM\…\CurrentVersion\Windows` → `AppInit_DLLs` | into every GUI process | T1546.010 | any non-empty value |
| 10 | `HKCU\Environment` → `UserInitMprLogonScript` | at logon, no admin | T1037.001 | Sysmon 13 — rarely legitimate, high-signal |

✅ = planted and detected on WS01 during this run, not just listed.

**Two rules that apply to every row of this table, learned from the run:**

1. **Match the path form the log actually writes**, never the shorthand you type. Sysmon logs
   the per-user hive as `HKU\<SID>\…` and 4657 logs machine keys as `\REGISTRY\MACHINE\…`.
   Neither prints `HKCU\` or `HKLM\` the way you typed it, and a hunt string built from the
   shorthand returns nothing with no error to explain why.
2. **Match value data case-insensitively.** `Details` and `NewValue` preserve exactly what the
   writer typed; a single lab session produced both `notepad.exe` and `Notepad.exe`.

> **The pattern across the table:** the highest-value entries for an attacker are the ones
> needing **no admin** (2, 4, 10) and the one granting **SYSTEM** (5). Rows 2, 3, 4 and 10
> are also where native 4657 is weakest, because they're in per-user hives or self-deleting
> keys. That's your case for deploying Sysmon, written in evidence rather than opinion.

---

# Step 9 — Evidence for the portfolio

Save to `../assets/` using the spaceless `03-*` scheme.

**Captured (2026-09-12):**

- [x] `03-sysmon-config.png` — `Sysmon64.exe -c`: v15.15, the config path,
      `Rule configuration (version 4.90)`, `onmatch: include`, and all four
      `TargetObject … contains` rules. Proves the Sysmon half was configured deliberately
      rather than left on defaults
- [x] `03-sysmon-13-all-three.png` — the Step 7.2 `Format-List` with **all three** plants.
      The money shot: same activity, same machine, one instrument sees it all
- [x] `03-sysmon-12-deletevalue.png` — the Step 7.3 output proving a deleted value is an
      **Event 12 / `DeleteValue`**, with full untruncated paths
- [x] `03-event1-commandline.png` — the Sysmon **Event 1** field dump for `reg.exe`:
      `CommandLine`, `ParentImage`, `User`, `IntegrityLevel`, 63 ms before its Event 13. The
      evidence that turns "a value changed" into "this account ran this command"
- [x] `03-4657-one-of-three.png` — the three-hour 4657 query returning **five events, all
      from the one SACL'd key**, and nothing whatever from the other two. Side by side with
      `03-sysmon-13-all-three.png`, those two images *are* Finding 2
- [x] `03-notepad-parentimage-blank.png` — the Store-packaged Notepad events with an empty
      `ParentImage`. Supports the parked observation in Notes & gotchas, and is why the
      write → execution chain was left unproven

**Outstanding:**

- [ ] `03-auditpol-registry.png` — `auditpol /get /subcategory:"Registry"` reading Success
      and Failure, alongside the Module 02 subcategories
- [ ] `03-sacl-run-key.png` — the Auditing tab on `HKLM\…\Run`, `Everyone` / Type: All,
      with **Set Value** ticked. The gate-4 evidence
- [ ] `03-4657-value-set.png` — a 4657 detail pane showing `ObjectValueName`,
      `OperationType`, `OldValue`/`NewValue` and `ProcessName`. Note the
      `\REGISTRY\MACHINE\` path form
- [ ] `03-persistence-table.png` — the completed Step 8 deliverable

> **Redaction note.** `03-sysmon-13-all-three.png` and `03-sysmon-12-deletevalue.png` were
> committed **unredacted** and show this host's full machine SID. A deliberate call — the VM is
> a throwaway on an isolated network with no internet — but worth knowing before the repo is
> shared more widely, and worth *not* repeating on any host that matters.

Then a few sentences in your own words: what was planted, which instrument caught what, and
which of the two you'd deploy first given a budget.

---

# Findings

_Written from the run of 2026-09-12, observation → inference → recommendation, kept strictly
separate. All timestamps **UTC** — that is what `TimeCreated SystemTime` and Sysmon's `UtcTime`
field store; Event Viewer only converts for display, and these VMs display WAT (UTC+1), so
screenshots read one hour ahead. The host SID is abbreviated `S-1-5-21-…-500` throughout; the
trailing **500** is the built-in Administrator RID from Module 01 and is the analytically
meaningful part._

### Finding 1 — Registry persistence planted in three autostart locations (WS01)

**Observation.** On WS01, on 2026-09-12, three values were written to three separate autostart
keys, each with the data `notepad.exe`. Sysmon `Microsoft-Windows-Sysmon/Operational`
**Event 13** recorded all three:

| UTC | Value | Key as logged | `Details` | `Image` |
|---|---|---|---|---|
| 21:00:22.880 | `LabPersist` | `HKLM\…\CurrentVersion\Run` | `notepad.exe` | `C:\Windows\System32\reg.exe` |
| 21:06:25.500 | `LabPersistUser` | `HKU\S-1-5-21-…-500\…\CurrentVersion\Run` | `Notepad.exe` | `…\WindowsPowerShell\v1.0\powershell.exe` |
| 21:08:15.088 | `LabPersistOnce` | `HKLM\…\CurrentVersion\RunOnce` | `notepad.exe` | `C:\Windows\System32\reg.exe` |

For the third write, Sysmon **Event 1** (process create) at **21:08:15.025** — 63 milliseconds
earlier — recorded the process responsible, with `CommandLine`
`"C:\WINDOWS\system32\reg.exe" add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce /v LabPersistOnce /t REG_SZ /d notepad.exe /f`,
`ParentImage` `…\powershell.exe`, `User` `CORP\Administrator`, `IntegrityLevel` `High`, plus
`ProcessGuid`, `LogonId` `0x6243b` and a SHA256 of the image.

The Security log recorded **4657** for `LabPersist` only (see Finding 2).

**Inference.** I assess with **high confidence** that this activity corresponds to
**T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**, with
the writes themselves also mapping to **T1112 — Modify Registry**. The Event 1 / Event 13 pair
establishes an unusually complete account for a single artifact: the acting account, the
parent process, the exact command line, the integrity level, and the registry state that
resulted, correlated to within a tenth of a second and joinable on `ProcessGuid`.

Stated explicitly, because the evidence does **not** support it: **none of these events shows
that the planted data was ever executed.** A registry write is not an execution. Event 13
proves a value appeared; proving it *ran* requires a Sysmon Event 1 (or 4688) for the payload
at a subsequent logon, tied to a logon process as parent. That hunt was attempted and
**abandoned without result** — a candidate `Notepad.exe` process exists at **21:04:16.315**,
about a minute after a host reboot at ~21:03 and consistent in timing with a `Run`-key
execution, but its `ParentImage` field was empty, so nothing connects it to the logon. The
timing is suggestive and nothing more; it is recorded here as an open observation, not as a
link in the chain. (The blank-parent behaviour is itself unexplained — see Notes & gotchas.)

Also undetermined from this evidence alone: intent. In this lab the writer was the analyst and
the payload is benign. The events would look identical for a malicious actor, which is the
point — **the telemetry establishes what happened, never why.**

**Recommendation.**

1. **Alert on value *data*, not value *name*.** The name is attacker-chosen and arbitrary —
   `LabPersist` here, `Windows Update` or `OneDrive` in the wild. Key detections on `Details`:
   unsigned paths, `%TEMP%`/`%APPDATA%` locations, `powershell -enc` command lines (which ties
   straight back to Module 05's 4104/4688 pair), `rundll32`, `mshta`.
2. **Match case-insensitively.** `Details` preserves exactly what the writer typed —
   `Notepad.exe` and `notepad.exe` both appear in the table above, from the same lab session.
   A case-sensitive rule would have caught two of three.
3. **Do not match the payload string against `Image` on the execution side.** `notepad.exe` in
   the registry resolves on Windows 11 to
   `C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_…\Notepad.exe`. The string written
   and the string executed are different, so a rule correlating them literally will fail.
4. **Join Event 1 to Event 13 on `ProcessGuid`** to promote "a registry value changed" into
   "this command line, run by this account at this integrity level, changed this registry
   value." That pairing is what makes the artifact defensible in a report.
5. **Follow-up queries** for an analyst picking this up: Event 1 for the payload at the next
   logon with a logon-process parent; 4688 on hosts without Sysmon; and `reg.exe` command lines
   containing `Run`, `RunOnce` or `CurrentVersion` as a cheap, high-signal hunt in their own
   right.

### Finding 2 — Native registry auditing covered one key in three (WS01)

**The module's central result.**

**Observation.** The three writes above were performed on one host, inside eight minutes
(21:00:22 – 21:08:15 UTC on 2026-09-12), with **both** instruments configured and running:
the `Registry` audit subcategory enabled, a SACL auditing `Set Value` on
`HKLM\…\CurrentVersion\Run`, and Sysmon v15.15 loaded with a four-rule
`RegistryEvent onmatch="include"` config.

- **Security log, Event 4657:** returned **`LabPersist` only** — one of three.
- **Sysmon, Event 13:** returned **all three**.

Widening the 4657 query to a three-hour window covering the whole sitting sharpens it further.
It returned exactly five value names:

```
LabPersist
LabPersist
LabPersistRegNow
LabPersistPS
LabPersistBoot
```

**All five are writes to the one SACL'd key**, `HKLM\…\CurrentVersion\Run` — the two
`LabPersist` entries consistent with its creation and its later deletion, the other three with
the removal of the previous sitting's values from that same key. (The create-versus-delete
split is inference from the sequence; `OperationType` on each event is what would settle it
definitively.)

Across that identical window, the two unwatched keys saw **five** operations —
`LabPersistUser` deleted, re-planted and deleted again in `HKCU\…\Run`, and `LabPersistOnce`
planted and deleted in `HKLM\…\RunOnce`. **None of them produced a 4657.**

The negative result therefore carries its own control, twice over. The query that returned
nothing for those two keys **returned five events for the third**, from the same command, the
same window, the same log and the same host. The four standard causes of empty `Get-WinEvent`
output — wrong machine, window too narrow, log rotated, channel disabled — cannot account for
an absence that is *selective by key* within a single successful query. And the events it did
return span creation *and* deletion, so the instrument demonstrably covers the full lifecycle
of a value; it simply never saw the other two keys at all.

**Inference.** I assess with **high confidence** that this is a **coverage** failure and not a
configuration failure. Native registry auditing worked exactly as designed **for the one key
it was pointed at**. `HKCU\…\Run` and `HKLM\…\RunOnce` carried no SACL, so writes to them
were never auditable events in the first place — there was nothing to miss, log, or lose.

The consequence generalises past this lab: **native registry auditing can only report on keys
an administrator anticipated in advance.** It is structurally incapable of surfacing a
persistence location nobody thought to watch, which is the category that matters most.

Two aggravating details:

- **The miss includes the cheapest attack.** `LabPersistUser` was written to the per-user hive
  with **no elevation** — the most accessible of the three paths and the one requiring least
  from an attacker. Native auditing covered the write that needed admin and missed the one
  that did not.
- **The miss includes the self-erasing one.** `RunOnce` deletes itself after firing, so for
  that key the log is the *only* durable evidence the entry ever existed. Absence of native
  coverage there is absence of any record at all.

What this does **not** show: that Sysmon is generally superior. Sysmon saw all three only
because the config's `contains "CurrentVersion\Run"` rule happened to cover those paths; a key
outside its four rules would be equally invisible. Both tools are opt-in — **they differ in the
unit of opt-in** (per key and per hive versus per path-pattern, machine-wide), and that unit is
what decides coverage.

**Recommendation.**

1. **Deploy Sysmon with a path-pattern registry config as the primary control** for autostart
   persistence. One `contains` rule covered `Run` and `RunOnce` across both hives and every
   user profile simultaneously. The native equivalent would require a SACL on each key in each
   loaded profile under `HKU`, plus the default profile for users who have not yet logged on —
   which does not scale and silently degrades as accounts are added.
2. **Keep native 4657 rather than replacing it**, for two specific reasons: it carries
   `OldValue`, which Sysmon does not record at all and which is the single most important field
   when a value is *modified* rather than created (the displaced value is the evidence of a
   hijack); and it needs no agent, so it is available on every Windows host in the estate
   including those Sysmon has not reached.
3. **State the cost honestly.** Sysmon is a kernel driver requiring installation, configuration
   management and update discipline on every endpoint, and a careless config either floods the
   log — destroying older evidence, per Module 04 — or covers nothing, since the bare defaults
   log no registry events whatsoever.
4. **Audit the config, not just its presence.** "Sysmon is deployed" is not a coverage claim.
   Read every `TargetObject` as a substring and ask which of the top-ten persistence locations
   in Step 8 it actually matches; then treat the remainder as known blind spots and record them
   as such.

---

# Reference

### Hives

| Short | Full | Scope | Write needs admin? |
|---|---|---|---|
| `HKLM` | `HKEY_LOCAL_MACHINE` | whole machine | **yes** |
| `HKCU` | `HKEY_CURRENT_USER` | current user only | **no** |
| `HKU` | `HKEY_USERS` | all loaded profiles, by SID | yes (for others) |
| `HKCR` | `HKEY_CLASSES_ROOT` | file/COM associations (merged view) | yes |
| `HKCC` | `HKEY_CURRENT_CONFIG` | hardware profile | yes |

### Reading the registry

| Tool | Use |
|---|---|
| `regedit` | GUI tree — best for navigating and for SACLs (no backslash typing) |
| `Get-ChildItem HKLM:\…` | list **subkeys** (the directories) |
| `Get-ItemProperty HKLM:\…` | list **values** (the files) — the one you'll use most |
| `Set-ItemProperty` / `Remove-ItemProperty` | write / delete a value, PowerShell-native |
| `reg add` / `reg query` / `reg delete` | the Win32 tool — what attacker command lines use |
| `(Get-Acl <key> -Audit).Audit` | read the key's **SACL** — the camera |

### Event IDs

| ID | Log | Meaning |
|---|---|---|
| **4657** | Security | A registry **value was changed**. Carries `OldValue`/`NewValue` and `OperationType`. Needs the **`Registry`** subcategory *and* a SACL auditing **Set Value** |
| **4656** | Security | Handle to the key requested — carries allow/deny. Needs `Handle Manipulation` |
| **4663** | Security | A right was *used* on the key — success only |
| **4670** | Security | The key's **permissions** changed. Needs `Authorization Policy Change` *and* `WRITE_DAC` audited |
| **4907** | Security | The key's **auditing settings** changed — your SACL install |
| **4697** | Security | A service was installed — the `Services`-key persistence route |
| **12** | Sysmon/Operational | Registry key created or deleted — **and a value *deleted*** (`EventType = DeleteValue`). Verified WS01 2026-09-12. Deletions are **not** 13s |
| **13** | Sysmon/Operational | Registry **value set** — the persistence event. **No SACL required** |
| **14** | Sysmon/Operational | Registry key or value renamed |

### `OperationType` values on 4657

| Value | Means |
|---|---|
| New registry value created | fresh persistence — nothing was there before |
| Existing registry value modified | a **hijack** — read `OldValue` to see what was displaced |
| Existing registry value deleted | cleanup, or a defence being removed |

### MITRE ATT&CK

| Technique | ID | Where it appears here |
|---|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | Step 4, all three plants |
| Boot or Logon Autostart Execution: Winlogon Helper DLL | T1547.004 | Step 2.3, `Userinit` / `Shell` |
| Create or Modify System Process: Windows Service | T1543.003 | Step 2.3, the `Services` key |
| Event Triggered Execution: IFEO Injection | T1546.012 | Step 2.3, `Debugger` value |
| Modify Registry | T1112 | any of the writes in Step 4 |
| Impair Defenses: Disable or Modify Tools | T1562.001 | an unexpected 4907 or Sysmon service stop |

---

## Notes & gotchas

- **`Get-ChildItem` does not show values.** Subkeys are children; values are properties. A
  key stuffed with persistence entries looks completely empty to `Get-ChildItem`. Use
  `Get-ItemProperty`. This is the single most common registry-in-PowerShell mistake.
- **`RegistryRights` hides `SetValue` inside `WriteKey`.** `WriteKey` (6) = `SetValue` (2) +
  `CreateSubKey` (4), so a correct SACL prints `Delete, WriteKey, ChangePermissions` and the
  string `SetValue` never appears. Verified WS01 2026-09-10. Test the bit (`-band 2`), never
  grep the name — see Step 3.3.
- **`OperationType` comes out of the XML as a raw message-table reference** (`%%1904` and
  friends), not English. Field-by-name extraction gives you truth but not language for
  enumerated fields. Resolve it with `.Message` or Event Viewer's General tab — **never from
  memory.** This is the one place the "pull fields by name, don't trust `Message`" rule needs a
  caveat.
- **A 4907 count follows the number of *objects*, not the number of applies.** One 4907 here
  (the `Run` key has no subkeys) versus two in Module 02 (folder + file). A count that looks
  too low is usually arithmetic, not failure — ask how many objects the SACL should have
  touched before assuming something broke.
- **⚠️ Unexplained, observed 2026-09-10/12 — parked, not a finding.** The first two `reg add`
  writes to the audited `Run` key produced **no 4657** when checked, while every write from the
  third onward logged normally (create, modify *and* delete, via both `reg.exe` and
  `Set-ItemProperty`). All four gates verified open at the time, and 4656/4663 were firing for
  `Key` objects throughout. **No cause has been established.** Three explanations were proposed
  during the run and all three were killed by later evidence. The discriminating test, not yet
  run: restore a clean pre-write snapshot, apply the SACL fresh, write immediately, and see
  whether the first write is silent again. Do not write this up as a finding until that test
  has been run.
- **4657 prints `\REGISTRY\MACHINE\…`, not `HKLM\…`** — **confirmed on WS01, 2026-09-10** —
  and `\REGISTRY\USER\<SID>\…` rather
  than `HKCU\…`. Filtering on `'*HKLM*'` returns nothing and reads like "no events."
  Filter on `'*CurrentVersion\Run*'` — the fragment that survives translation. Sysmon does
  **not** do this; it normalises paths back to `HKLM\`, so the same hunt string won't work
  against both logs.
- **No 4657 for a write you definitely made** has the same three causes as Module 02's
  missing 4670: the **`Registry` subcategory is off** (separate from `File System` — Module
  02 enabling that one did nothing here); the **SACL doesn't audit `Set Value`**; or
  **auditing wasn't on yet**, because it is never retroactive.
- **HKCU auditing is per-profile, and this bites.** Setting a SACL on `HKCU\…\Run` as
  Administrator audits **Administrator's** profile — not `fin_user`'s, not anyone else's.
  `HKCU` is a shortcut into `HKU\<your SID>`. Covering all users natively means walking
  `HKU` and SACL'ing each profile, plus the default profile for accounts that haven't
  logged on yet. This is a large part of why Sysmon exists.
- **Sysmon events are in a different log.** `Microsoft-Windows-Sysmon/Operational`, not
  Security. A perfect query against `LogName='Security'` will never see event 13.
- **Sysmon without a config is a firehose.** Registry writes happen constantly on an idle
  machine. `onmatch="include"` with a short `TargetObject` list is the difference between a
  detection and a log-rotation problem — and per Module 04, filling the log *destroys older
  evidence*.
- **Don't touch `Userinit` or `Shell` on this VM.** A bad value there boots to a blank
  screen with no shell, recoverable only by snapshot restore. `Run` keys fail harmlessly;
  Winlogon keys do not.
- **`RunOnce` deletes itself after it fires.** If it has run, the registry holds no trace
  and the *event log is the only evidence the entry ever existed*. Never conclude "no
  persistence" from a clean `RunOnce` key.
- **The value's name means nothing; the value's data means everything.** Attackers name
  entries `Windows Update` or `OneDrive`. Alert on the data — an unsigned path, a
  `%TEMP%` location, a `powershell -enc` command line (which ties straight back to Module
  05's 4104/4688 pair) — never on the label.
- **A registry write is not an execution.** 4657 and Sysmon 13 prove the entry was
  *planted*. Proving it *ran* needs a 4688 or Sysmon 1 at the next logon. Keep the two
  claims separate in any finding — this is exactly the "never let sequence imply causation"
  rule.
- **Always say which VM.** This whole module is WS01. Registry queries run on DC01 return
  that machine's registry, cheerfully and wrongly.
- **Sysmon's bare-install defaults log no registry events at all.** Verified WS01
  2026-09-12: between install and config the log held 30 records across IDs **1, 4, 5 and
  16 only** — process create, service state, process terminate, config state. **No 13.** So
  the config in Step 6.2 *switches registry logging on*; it does not trim an existing flood.
  Carry the distinction: "Sysmon is installed" and "Sysmon would have caught that" are
  different claims, and on an unconfigured host the second one is false.
- **`contains` rules match more than you aimed at.** `CurrentVersion\Run` also matches
  `CurrentVersion\RunNotification`, which is how the entries below turned up uninvited. That
  is convenient here and is the mechanism behind config-driven floods everywhere else —
  when auditing someone's Sysmon config for blind spots, read every `contains` as a
  substring, not a key name.
- **Windows writes its own second copy of your persistence, via `sihost.exe`.** Observed
  WS01 2026-09-12: after each `Run` value was written, Shell Infrastructure Host created a
  matching `…\CurrentVersion\RunNotification\StartupTNoti<valuename>` entry in the **per-user
  hive**, and deleted it again when the `Run` value was deleted. **No such entry appeared for
  `RunOnce`.** Potentially useful as corroboration — an attacker who cleans the `Run` key may
  not know to clean this — but note the limits honestly: the delay is **variable** (10 seconds
  for one plant, 2m36s for another, same session), and the entry's DWORD payload differed
  between the two (`0x00000000` vs `0x00000001`) with **no established meaning**. Recorded as
  an observation, not a finding: no controlled test has been run.
- **`Format-Table` truncates; registry paths are longer than the console.** The value name is
  the *last* segment of `TargetObject`, so table output cuts off precisely the part you need.
  Use `Format-List`, or `Select-Object -ExpandProperty` for raw one-per-line strings.
- **A partial paste reads exactly like a small result — and this one cost time.** During the
  run, three rows from a `-MaxEvents 5` query were read as "only three Event 1s exist," which
  made the host look like it had stopped logging process creation and produced a confident,
  entirely fictional anomaly. The real count was **1311**. This is the mirror image of the
  filter-first trap in Module 04: there, a cap hid *old* matches; here, a cap plus an
  incomplete paste invented a *missing* population. **Confirm a count with `Measure-Object`
  before treating a small number as a finding** — and when a result is surprising, suspect
  the query and the transcription before inventing a mechanism.
- **`Where-Object { $_.Message -like '…' }` matches the whole event, not the field you meant.**
  Hunting Sysmon Event 1 for `'*Notepad.exe*'` returned a **`reg.exe`** process — because
  `Message` contains every field, and that process's *command line* had `notepad.exe` in it.
  Convenient and imprecise. Extract the field first, then filter on it. (The accident was
  productive here — it surfaced the Event 1 that made Finding 1 — but productive accidents are
  not a method.)
- **⚠️ Unexplained, observed 2026-09-12 — an observation, not a finding.** Sysmon Event 1
  records for the Store-packaged Notepad
  (`C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_…\Notepad.exe`) came back with an
  **empty `ParentImage`**, on every one of a dozen such events. The field is not
  mis-spelled and the extraction is not at fault: the same pipeline returned
  `ParentImage = …\powershell.exe` correctly for a `reg.exe` event in the same log.
  **No cause established** — it was not investigated further, deliberately, to avoid a
  speculative chase. The practical consequence is real though: **parent-process correlation
  cannot be assumed available** for packaged/Store applications on this host, so a detection
  that depends on `ParentImage` needs a fallback (`LogonId`, `ParentProcessGuid`, or session
  correlation) before it is relied upon.
