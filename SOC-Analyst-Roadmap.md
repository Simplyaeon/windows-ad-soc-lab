# SOC Analyst Competency Roadmap — Windows & Active Directory

A project-based plan to build the foundational skills for a SOC analyst role. Every
module is hands-on work performed on the **DC01 + WS01** VirtualBox lab, and every
skill is tied back to the SOC payoff: the log, Event ID, or artifact you'd actually
see on the job.

> **Prerequisite:** The lab from the *SOC Lab Build Guide* — DC01 (Server 2022,
> `10.0.0.10`, domain `corp.local`) and WS01 (Windows 11, `10.0.0.20`, domain-joined),
> on the isolated `lab-net` internal network, with auditing and Sysmon enabled.

---

## How to use this plan

- **Work top to bottom.** Part I (Windows Administration) is the ground floor;
  Part II (Active Directory) builds directly on it.
- **Each module has three parts:** *Build* (do the admin task), *Break/Observe*
  (generate the telemetry), *Detect* (find it in the logs). The third part is the
  SOC skill — the first two exist to produce something worth detecting.
- **Snapshot before each module** so you can roll back and repeat.
- **Keep a lab journal.** For every module, record: what you did, the exact Event
  IDs produced, the log path, and one detection query. This journal *is* your
  portfolio.

---

# Part I — Windows Administration

**Goal:** Understand the OS a SOC analyst defends — where identity, access, and
configuration live, and what each leaves behind in the logs.

## Module 1 — Users & Groups
**Build**
- Create local users (`net user`, `New-LocalUser`) and domain users on DC01.
- Add users to groups; understand the built-in high-value groups: Administrators,
  Domain Admins, Enterprise Admins, Backup Operators, Remote Desktop Users.
- Explore local vs. domain accounts, and the difference between a user's SID and name.

**Break/Observe**
- Create a user, add them to Administrators, then disable and delete them.
- Perform 3 failed logons followed by a success.

**Detect** — the bread-and-butter authentication events
| Event ID | Meaning |
|---|---|
| 4720 | User account created |
| 4722 / 4725 | Account enabled / disabled |
| 4726 | Account deleted |
| 4728 / 4732 | Added to a (global / local) security group |
| 4624 | Successful logon (note the **Logon Type**: 2=interactive, 3=network, 10=RDP) |
| 4625 | Failed logon |
| 4740 | Account locked out |

**Deliverable:** A one-page "account lifecycle" cheat sheet mapping each action to
its Event ID, plus a PowerShell query that lists all 4720s in the last 24h.

## Module 2 — NTFS Permissions & File Auditing
**Build**
- Understand NTFS ACLs vs. share permissions; read a DACL with `icacls` and
  `Get-Acl`. Learn the ACE components: principal, rights, inheritance.
- Set up a "Finance" folder readable only by a specific group; test access as a
  denied user.
- Grasp ownership, inheritance, and the "deny beats allow" rule.

**Break/Observe**
- Enable object-access auditing (`auditpol` + a SACL on the folder).
- Access the folder as an authorized and an unauthorized user.

**Detect**
| Event ID | Meaning |
|---|---|
| 4663 | An attempt was made to access an object (file/folder) |
| 4670 | Permissions on an object were changed |
| 4907 | Auditing settings (SACL) on an object changed |

**Deliverable:** A documented "sensitive folder" with a working audit trail, plus a
screenshot of a 4663 triggered by unauthorized access.

## Module 3 — Windows Registry
**Build**
- Learn the hives (HKLM, HKCU, HKU) and what lives where.
- Tour the persistence-relevant keys every analyst should know cold:
  - `HKLM\...\Run` and `HKCU\...\Run` (autoruns)
  - `HKLM\SYSTEM\CurrentControlSet\Services` (services & drivers)
  - Winlogon keys (Shell, Userinit)
- Edit values with `reg`, `Set-ItemProperty`, and Autoruns (Sysinternals).

**Break/Observe**
- Add a fake persistence entry to a `Run` key.

**Detect**
- Sysmon **Event ID 13** (RegistryValue Set) captures the write.
- Enable registry auditing → Event **4657** (registry value modified).

**Deliverable:** A list of the top 10 registry persistence locations with the Sysmon
Event 13 you'd hunt for each.

## Module 4 — Event Viewer & the Windows Logging Model
**Build**
- Master the three classic logs (Application, System, Security) plus the
  "Applications and Services Logs" tree (PowerShell/Operational, Sysmon/Operational).
- Learn XML views and custom filtered views; build a saved view for "logon failures."
- Understand log sizing, retention, and why default log sizes are a blind spot.

**Break/Observe**
- Generate a mix of events from the earlier modules.

**Detect**
- Build custom views that a SOC analyst would live in daily.
- Use `wevtutil` and `Get-WinEvent` with XPath and FilterHashtable queries.

**Deliverable:** A set of 3–4 saved custom views (failed logons, account changes,
new process creation) exported as XML.

## Module 5 — PowerShell for Defenders
**Build**
- Core cmdlets: `Get-WinEvent`, `Get-Process`, `Get-Service`, `Get-NetTCPConnection`,
  `Get-LocalUser`, `Get-CimInstance`.
- Learn `Get-WinEvent -FilterHashtable` deeply — it's the analyst's query language.
- Write a triage script: pull recent 4624/4625/4688 and summarize.

**Break/Observe**
- Run an obfuscated/encoded PowerShell one-liner (a benign one, e.g. base64 that
  prints text) to see what logging captures.

**Detect**
| Event ID | Log | Meaning |
|---|---|---|
| 4104 | PowerShell/Operational | Script block logging (deobfuscated code) |
| 4103 | PowerShell/Operational | Module/pipeline logging |
| 4688 | Security | Process creation w/ full command line |
| Sysmon 1 | Sysmon/Operational | Process creation (richer: hashes, parent) |

**Deliverable:** A reusable `Invoke-Triage.ps1` that dumps a host's recent
authentication and process-creation activity to a readable report.

## Module 6 — Windows Firewall
**Build**
- The three profiles (Domain, Private, Public) and why they matter.
- Create inbound/outbound rules with `New-NetFirewallRule`; allow ICMP; scope a
  rule to the `lab-net` subnet.
- Understand default-deny inbound and what RDP/SMB rules look like.

**Break/Observe**
- Enable firewall connection logging (dropped + allowed packets).
- Trigger a blocked connection from WS01 to a closed port on DC01.

**Detect**
| Event ID | Meaning |
|---|---|
| 5156 / 5157 | Windows Filtering Platform allowed / blocked a connection |
| 4946–4948 | Firewall rule added / changed / deleted |
- Parse the firewall log at `%systemroot%\System32\LogFiles\Firewall\pfirewall.log`.

**Deliverable:** A firewall baseline for both VMs plus a documented example of a
blocked connection appearing in both the WFP events and the text log.

## Module 7 — Remote Desktop (RDP)
**Build**
- Enable RDP on WS01; add a user to Remote Desktop Users; connect from DC01.
- Understand Network Level Authentication (NLA) and why it matters.

**Break/Observe**
- Perform a successful RDP logon and a failed one (wrong password).

**Detect** — RDP is the #1 lateral-movement and initial-access vector; know these cold
| Event ID | Log | Meaning |
|---|---|---|
| 4624 (Type 10) | Security | Successful RemoteInteractive logon |
| 4625 | Security | Failed logon (RDP brute force shows as a flood here) |
| 1149 | TerminalServices-RemoteConnectionManager | User authentication succeeded |
| 21 / 24 / 25 | TerminalServices-LocalSessionManager | Session logon / disconnect / reconnect |

**Deliverable:** An "RDP access story" — trace a single remote session across all
four log sources and write the timeline as an analyst would in a ticket.

---

# Part II — Active Directory

**Goal:** Understand the identity backbone of an enterprise, how authentication
actually works, and the attacks and detections that dominate SOC work.

## Module 8 — Domains, Forests & Domain Controllers
**Build**
- Concepts: forest vs. domain vs. tree; the DC's role; the SYSVOL and NTDS.dit.
- Explore `corp.local` with `Get-ADDomain`, `Get-ADForest`, `Get-ADDomainController`.
- Understand FSMO roles at a high level.

**Detect**
- DC health/replication basics; where AD events live (Security log on the DC,
  Directory Service log).

**Deliverable:** A network + trust diagram of your lab with the DC's roles labeled.

## Module 9 — Organizational Units & Delegation
**Build**
- Design an OU structure (e.g. `Corp > Departments > {IT, Finance, HR}`; separate
  OUs for Users, Workstations, Servers).
- Move objects between OUs; delegate control of an OU to a helpdesk group.

**Detect**
| Event ID | Meaning |
|---|---|
| 5136 | A directory service object was modified |
| 5137 / 5141 | Object created / deleted |
| 4662 | An operation was performed on an AD object (DACL-level) |

**Deliverable:** A documented OU design with a delegation example and the 5136 that
recorded it.

## Module 10 — Group Policy (GPO)
**Build**
- Create GPOs and link them to OUs; understand precedence (LSDOU), inheritance,
  blocking, and enforcement.
- Practical policies: password policy, screen lock, disable a service, deploy the
  audit settings from the lab guide *as a GPO* instead of local commands.
- Learn where GPOs live (SYSVOL) and how clients pull them (`gpupdate`, `gpresult`).

**Break/Observe**
- Change a policy and force a refresh on WS01.

**Detect**
| Event ID | Meaning |
|---|---|
| 5136 | GPO object modified (in AD) |
| 4739 | Domain policy changed |
| 5145 | SYSVOL share access (GPO file reads) |
- Understand why attackers love GPO abuse (mass code execution).

**Deliverable:** An audit-policy GPO applied domain-wide, verified with `gpresult /r`
on WS01, replacing the manual per-host commands from Phase 5 of the build guide.

## Module 11 — DNS
**Build**
- Why AD *is* DNS: SRV records, `_ldap._tcp`, `_kerberos._tcp`.
- Explore zones on DC01; use `Resolve-DnsName` and `nslookup`.
- Understand dynamic updates and the DNS the domain join depends on.

**Break/Observe**
- Enable DNS debug/analytical logging; generate lookups from WS01.

**Detect**
- DNS Server analytic log (Event **256/257** query/response) — the basis of DNS
  exfiltration and C2 beacon hunting.

**Deliverable:** A short write-up: "How a domain-joined client finds its DC via DNS
SRV records," with the actual records from your lab.

## Module 12 — Kerberos & LDAP (the capstone)
**Build**
- Kerberos flow end to end: AS-REQ/REP (TGT), TGS-REQ/REP (service ticket), and
  what a service ticket is used for. Understand the KDC = the DC.
- LDAP as the query protocol; run LDAP queries (`Get-ADUser -LDAPFilter`) to
  enumerate the directory the way both admins and attackers do.

**Break/Observe** — the marquee AD attacks, run safely in your isolated lab
- **Kerberoasting:** request the service ticket for `svc_sql` (the SPN account you
  seeded). This is why that account exists in the build guide.
- **AS-REP roasting:** flag an account "Do not require Kerberos preauth" and observe.
- **Password spray:** a handful of 4625s across multiple accounts.
- (Use built-in tooling / benign scripts — no need for offensive frameworks to see
  the telemetry.)

**Detect** — the events that define AD threat hunting
| Event ID | Meaning |
|---|---|
| 4768 | Kerberos TGT requested (AS-REQ) — the logon itself |
| 4769 | Kerberos service ticket requested (TGS) — **encryption type 0x17 (RC4) = Kerberoasting signal** |
| 4771 | Kerberos pre-auth failed |
| 4776 | NTLM authentication attempt |
| 4662 | AD object operation (DCSync detection) |

**Deliverable:** The portfolio centerpiece — a "Detecting Kerberoasting" write-up:
the attack, the 4769 with RC4 encryption you generated, and a `Get-WinEvent` query
that isolates it from normal ticket traffic.

---

# Cross-cutting: build a mini-SIEM

Once Modules 1–12 are producing telemetry, tie it together:

1. **Windows Event Forwarding (WEF):** configure WS01 to forward its Security and
   Sysmon logs to DC01 (collector). This mirrors real SOC log centralization.
2. **Optional:** ship logs into a free SIEM tier (Elastic, Splunk Free, or Wazuh) to
   practice writing detection rules and dashboards on data *you* generated.

**Deliverable:** A single pane where events from both hosts land — and 3–5 saved
detection queries drawn from the modules above.

---

# Suggested pacing

| Weeks | Focus |
|---|---|
| 1–2 | Modules 1–4 (users, NTFS, registry, Event Viewer) |
| 3–4 | Modules 5–7 (PowerShell, firewall, RDP) |
| 5 | Modules 8–9 (domains, OUs) |
| 6 | Modules 10–11 (GPO, DNS) |
| 7 | Module 12 (Kerberos/LDAP capstone) |
| 8 | Cross-cutting mini-SIEM + portfolio polish |

Adjust freely — depth beats speed. The goal isn't to finish; it's to be able to
open any Windows Security log and explain what every line means.

---

# Portfolio outcomes

By the end you will have, all demonstrable in an interview:
- A working, documented AD lab you built from ISOs.
- A per-module journal mapping admin actions → Event IDs → detection queries.
- Reusable PowerShell triage tooling.
- A Kerberoasting detection write-up (the single most impressive SOC-junior artifact).
- A log-centralization setup showing you understand how a SOC actually operates.

Map each module to the **MITRE ATT&CK** techniques it covers (e.g. T1078 Valid
Accounts, T1547 Boot/Logon Autostart, T1558.003 Kerberoasting) to speak the
language SOC teams use.
