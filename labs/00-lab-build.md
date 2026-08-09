# Module 00 — Lab Build

**Objective:** stand up the two-VM lab environment every other module depends on —
two isolated Windows hosts, a working `corp.local` domain, and clean snapshots to
roll back to.

> This module deliberately does **not** follow the standard
> Build → Break/Observe → Detect structure of the other labs. There is nothing to
> detect yet; this is the environment those labs run inside.

**End state**

```
        ┌─────────────────────────┐         lab-net          ┌─────────────────────────┐
        │  DC01                    │      (internal net)      │  WS01                    │
        │  Windows Server 2022     │◄────────────────────────►│  Windows 11 Enterprise   │
        │  Domain Controller · DNS │                          │  Domain member           │
        │  10.0.0.10 · corp.local  │                          │  10.0.0.20 · DNS → DC01  │
        └─────────────────────────┘                          └─────────────────────────┘
```

**You need:** VirtualBox 7.x, a Windows Server 2022 ISO, a Windows 11 Enterprise ISO,
~120 GB free disk, and 8 GB+ RAM on the host.

---

## Part 1 — Build the two VMs

### A · Create DC01

**Machine → New**, then set:

| Field | Value |
|---|---|
| Name | `DC01` |
| ISO Image | your Server 2022 ISO |
| **Skip Unattended Installation** | ✅ **tick this box** |
| Base Memory | `4096 MB` |
| Processors | `2` |
| Disk | `60 GB` |

Click through to **Finish**. Don't start it yet.

**Select DC01 → Settings → Network → Adapter 1:**
- Attached to: **Internal Network**
- Name: type `lab-net`

Click OK. → **Start.**

> `lab-net` doesn't need to be created anywhere — an Internal Network exists as soon as
> you name it on an adapter. It has **no internet, no host access, and no DHCP**, which is
> the entire point: the lab is sealed, and both machines get static IPs by hand.

### B · Install Server 2022

1. Press any key when it says to.
2. Pick **Windows Server 2022 Standard (Desktop Experience)** — the one with
   "Desktop Experience" in the name. Not Core; you need the GUI for Event Viewer,
   ADUC, and GPMC later.
3. **Custom** install → pick the empty 60 GB drive → Next → wait.
4. Set the Administrator password: `Lab-Passw0rd!`
5. To log in, use the menu bar: **Input → Keyboard → Insert Ctrl-Alt-Del**.

### C · Install Guest Additions

Do this **before** the command-line steps — it's what gives you copy-paste into the VM.

On the running VM window's own menu bar (not the VirtualBox Manager window):

```
File   Machine   View   Input   Devices   Help
                                   ▲
```

**Devices → Insert Guest Additions CD image…** (last item in the menu).

> Menu bar not visible? The VM is in full-screen or scaled mode — press
> **Right Ctrl + F** to return to windowed mode.

Nothing happens automatically; Server 2022 has autorun disabled. Inside the VM:

1. **Windows key + E** → **This PC**
2. Open the CD drive named **VirtualBox Guest Additions** (usually `D:`)
3. Run **`VBoxWindowsAdditions`** → Next → Next → Install → **Install** if prompted
   about device software
4. **Reboot now** → Finish

Then set **Devices → Shared Clipboard → Bidirectional**. The screen resizing when you
drag the window is how you know it took.

### D · Baseline DC01

Right-click **Start → Windows PowerShell (Admin)**. Paste the whole block:

```powershell
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.0.0.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 10.0.0.10
Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In
Rename-Computer -NewName DC01 -Restart
```

The machine reboots itself.

| Line | Why |
|---|---|
| `New-NetIPAddress` | Static IP — there's no DHCP on an internal network |
| `Set-DnsClientServerAddress` | Points DNS at itself, ready for the DNS role in Part 2 |
| `Enable-NetFirewallRule` | Windows blocks inbound ping by default; this lets you verify connectivity |
| `Rename-Computer` | Must happen **before** promotion to a domain controller |

### E · Create WS01

Same as A, plus the Windows 11 hardware requirements:

| Field | Value |
|---|---|
| Name | `WS01` |
| ISO Image | your Windows 11 ISO |
| **Skip Unattended Installation** | ✅ tick |
| Base Memory | `4096 MB` |
| Processors | `2` |
| Disk | `60 GB` |

**Settings → System → Motherboard** — Windows 11 will refuse to install without both:
- **TPM:** `v2.0`
- **Enable Secure Boot:** ✅

**Settings → Network → Adapter 1:** Internal Network, name `lab-net`.

### F · Install Windows 11 — bypassing the network requirement

Install normally until **"Let's connect you to a network."** There is no network by
design, so setup stalls here. To get past it:

1. Press **Shift + F10** — a command prompt opens.
2. Type and press Enter:
   ```
   start ms-cxh:localonly
   ```
3. A local-account dialog appears. Create: **`labadmin`** / `Lab-Passw0rd!`

> **If nothing happens at step 2** (builds 23H2 and earlier), type `oobe\bypassnro`
> instead. The VM reboots, and the network screen then offers **"I don't have internet"**
> → **"Continue with limited setup."**

Decline all the privacy/telemetry toggles.

### G · Finish WS01

Guest Additions exactly as in **C** (**Devices → Insert Guest Additions CD image**,
run `VBoxWindowsAdditions`, reboot, set Shared Clipboard to Bidirectional).

Then right-click **Start → Terminal (Admin)** and paste:

```powershell
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.0.0.20 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 10.0.0.10
Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In
Rename-Computer -NewName WS01 -Restart
```

### H · Verify

**Both VMs must be running** — ping is a conversation, not a broadcast. Start DC01 and
let it reach the login screen (no need to log in), then start WS01 and log in.

On WS01:

```powershell
ping 10.0.0.10
```

You want **`Reply from 10.0.0.10`**.

**If it fails**, in order of likelihood:
1. The network name isn't spelled exactly `lab-net` on **both** VMs (Settings → Network).
2. `Enable-NetFirewallRule` wasn't run on one of them.
3. The adapter isn't named `Ethernet` — run `Get-NetAdapter` to find the real name and
   substitute it into the commands.

### I · Snapshot

Shut both VMs down. For each: select it → **Snapshots** → **Take** → name it
**`00-clean-install`** → OK.

---

## Part 2 — Create the domain

### A · Promote DC01

Start **DC01 only**. In **Windows PowerShell (Admin)**:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
```

Wait for `Success`, then:

```powershell
Install-ADDSForest -DomainName corp.local -DomainNetbiosName CORP -InstallDNS
```

This one is interactive:

| Prompt | Response |
|---|---|
| `SafeModeAdministratorPassword:` | `Lab-Passw0rd!` — **characters won't display as you type.** Normal. |
| `Confirm SafeModeAdministratorPassword:` | Same again |
| `Do you want to continue? [Y] Yes [A] Yes to All…` | `Y` |

It runs for several minutes and emits **yellow warnings** about DNS delegation and
cryptography settings. **Expected** — they're artifacts of a lab with no upstream DNS.
The server reboots on its own when done.

> The Safe Mode (DSRM) password is a separate credential used to boot the DC into
> directory recovery mode. Reusing the lab password keeps this simple; in production it
> would be distinct and vaulted.

### B · Confirm the domain

The login screen now reads **CORP\Administrator**. Log in with `Lab-Passw0rd!`, then:

```powershell
Get-ADDomain | Select-Object Name, DNSRoot, DomainMode
```

Expect `corp` / `corp.local`.

### C · Join WS01

Leave DC01 running. Start **WS01**, log in as `labadmin`.

Check WS01 can resolve the domain first:

```powershell
nslookup corp.local
```

Should return `10.0.0.10`. If not, stop and fix DNS before going further.

Then:

```powershell
Add-Computer -DomainName corp.local -Credential CORP\Administrator -Restart
```

A credential popup appears with `CORP\Administrator` pre-filled — enter `Lab-Passw0rd!`
and click OK. WS01 reboots into the domain.

### D · Log in as a domain user

At WS01's login screen, click **Other user** (bottom-left):

- Username: `CORP\Administrator`
- Password: `Lab-Passw0rd!`

The first domain logon takes a minute while the profile is created. Verify:

```powershell
whoami        # corp\administrator
```

**If the join fails:**

| Message | Cause |
|---|---|
| `The specified domain either does not exist…` | DNS — re-check `nslookup corp.local` on WS01 |
| `The network path was not found` | DC01 isn't running or hasn't finished booting |
| Credential errors | You used `WS01\Administrator` instead of `CORP\Administrator` |

### E · Snapshot

Shut both down and snapshot each as **`01-domain-ready`**.

This is the state every subsequent module starts from — the snapshot you'll roll back
to most often.

---

## Notes

**Both VMs run simultaneously** from here on. If the host struggles, drop each to
`2048 MB` (Settings → System → Base Memory, VM powered off) — plenty for this lab.

**Host performance.** VirtualBox can't take exclusive control of VT-x/AMD-V when the
Hyper-V hypervisor is running, and falls back to a slower path via the Windows
Hypervisor Platform — indicated by a **turtle icon** in the VM status bar. Hyper-V is
started by **Memory Integrity** (Core Isolation), WSL2, Docker Desktop, and Windows
Sandbox, whether or not the Hyper-V role itself is installed.

Only act on this if the lab is genuinely sluggish — disabling Memory Integrity removes
real kernel-driver protection on your host, which is a poor trade for a lab that spends
most of its time idle.

---

## Credentials used in this lab

| Host | Account | Password |
|---|---|---|
| DC01 | `CORP\Administrator` | `Lab-Passw0rd!` |
| DC01 | DSRM / Safe Mode | `Lab-Passw0rd!` |
| WS01 | `WS01\labadmin` (local) | `Lab-Passw0rd!` |

These are throwaway credentials for a sealed, offline environment. Never reuse them
anywhere real.

---

## Next

→ [Module 01 — Users & Groups](./01-users-and-groups.md)
