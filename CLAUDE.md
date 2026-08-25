# Windows & AD SOC Lab — working notes

A hands-on lab and project journal for building **SOC analyst** competency in Windows
and Active Directory, with **detection** as the point. Every module follows the same
loop: **Build** an admin capability → **Break/Observe** by generating activity →
**Detect** it in the logs. Published as a portfolio.

## The lab

| Host | Role | Address |
|---|---|---|
| **DC01** | Windows Server 2022 — Domain Controller + DNS | `10.0.0.10` |
| **WS01** | Windows 11 Enterprise — domain member | `10.0.0.20` |

Domain `corp.local` (NetBIOS `CORP`), VirtualBox internal network `lab-net`, no
internet by design. Snapshots: `00-clean-install` (pre-domain), `01-domain-ready`,
`mod01-start`; `mod04-start` still to be taken. Credentials are documented in
`labs/00-lab-build.md` — throwaway lab passwords, never reused anywhere real.

**Both VMs are on `W. Central Africa Standard Time` (UTC+1)** as of 2026-08-24. They ran
on the Windows install default of Pacific until then, so any timestamp recorded before
that date and *displayed* rather than read from XML is eight hours out.

**DC01's Windows Server evaluation licence has expired** — it shuts itself down every
hour (`1074`, "license period ... has expired"). Not yet fixed; `slmgr /rearm` + reboot
is the fix, and `slmgr /dlv` shows the remaining rearm count. Two consequences: schedule
DC01 work in short blocks, and note that **the licence state lives in the snapshots**,
so restoring `01-domain-ready` reinstates the expired licence. Rearm *before* taking
`mod04-start`. WS01's Windows 11 evaluation will hit the same wall later.

**The VMs run on a separate Windows PC.** They cannot be reached from a Claude Code
session on this Mac. All lab commands are for the user to run there; ask for output
rather than trying to inspect anything directly.

## Layout

```
README.md                  landing page — module index + dated progress log
summary.md                 current status and next steps — read this first
SOC-Analyst-Roadmap.md     the full 12-module plan
labs/                      one file per module (00, 01, 04 written)
templates/                 module-lab-template.md
assets/                    screenshots referenced by the labs
```

## Where things stand

*As of 2026-08-25. `summary.md` carries the fuller version.*

Modules 00 and 01 **complete**, both findings closed. Module 01's Finding 2 was resolved
during the Module 04 run: 4767 unlock at 11:23:00 UTC by `CORP\Administrator`, 4768
success 29 seconds later, and no 4723/4724 anywhere in 30 days, which excludes the
competing hypothesis.

**Module 04 is written and nearly run.** Steps 0–5 done. **Step 6 (clear the log → find
the 1102) is in progress** — at the point of reading the 1102's Subject via
`.Event.UserData.LogFileCleared`, then clearing Application to see the 104 land in System.

Step 5 ran on 2026-08-25 and produced Finding 1: the log would **not** shrink on this host
(Security log min 1028 KB, 64 KB granularity; even valid small sizes refused, GUI and
`wevtutil` both), so evidence was overwritten by **volume** — ~27,800 `cmd.exe` process
creations pushed `oldestRecordNumber` from 1 to 8378, evicting the 16 August 4625 sequence
(highest RecordId 6007). Live 4625 query now returns 4 (all 24–25 Aug); the pre-flood
export `C:\evidence\WS01-Security-before.evtx` still holds all 14. `oldestRecordNumber` is
the evidence-loss odometer: it never decreases, never reuses numbers, so `oldest − 1` is
how many records the log has destroyed in its life.

Then **05 (PowerShell for Defenders)**, then 02 and 03. The Module 01 run showed the
bottleneck is log mechanics, not Windows administration.

Measured on WS01, 2026-08-24 — useful baselines: Security log holds **8764 records /
7.07 MB of 20 MB**, oldest event 28 July, ~845 bytes per event, ~0.26 MB/day, so ~76 days
to fill and nothing has ever been overwritten.

Outstanding: Module 01's four screenshots and Module 04's still aren't in `assets/`
(incl. `04-overwritten-vs-archive.png`, the live-4 vs export-14 side-by-side); Module 04's
custom Views 1 and 3 not built; Step 6 not finished; DC01 **and WS01** eval licences both
expired and shutting down hourly, neither rearmed (WS01 died mid-flood during Step 5 —
harmless, record numbers persist across reboot, resume the batch); `mod04-start` was not
confirmed taken; **nothing pushed to GitHub** (7 commits local).

## How to work on this

**The user comes from Linux and is new to Windows and PowerShell.** Keep guides heavily
simplified. Prefer GUI clicks where GUI and command line both work. Introduce one new
construct at a time.

- **Always say which VM a command runs on.** Wrong-machine queries return empty results
  rather than errors, and that has cost real time.
- **Use UPN form** (`administrator@corp.local`), never `CORP\administrator` — the user's
  keyboard layout produces the wrong character for `\`.
- **Event Viewer first** when the goal is reading a handful of events; its General tab
  labels and resolves every field. The GUI also filters at the log, so it *cannot* be
  starved the way a PowerShell pipeline can. Save `Get-WinEvent` for genuine scale.
- **Build commands up across several runs** — shortest useful form first, run it, add one
  piece, run it again. Do not hand over a finished multi-line pipeline; the user is
  building the ability to write these, and pasting a working block produces output
  without competence.
- **Lead every step with its aim** — one sentence on what it lets you do afterwards,
  before any instructions. Steps given as bare instructions read as busywork.

### Get-WinEvent traps already hit

- **Filter first, limit second.** `-MaxEvents 500 | Where-Object Id -eq 4625` takes the
  newest 500 events and *then* filters, so older matches never reach the filter — and the
  low count reads as an answer rather than a failure. Measured on WS01 2026-08-24: that
  form returned **1**, `-FilterHashtable @{LogName='Security'; Id=4625}` returned **11**,
  same log, same moment. Use `-FilterHashtable` on live logs, `-FilterXPath` on exported
  `.evtx`. Keep `Where-Object` for narrowing already-correct results.
- `StartTime` **filters, it does not search** — anything older than the window is
  invisible. Start wide (`AddDays(-7)`), then narrow.
- `-MaxEvents` caps the **total**, newest first. Mixing rare IDs (4720, 4728) with
  high-volume ones (4624, 4768) lets the noisy ones consume every slot.
- **Default output columns hide the answer.** `Message`'s first line is boilerplate —
  every 4768 reads "A Kerberos authentication ticket (TGT) was requested", so rows look
  identical. Pull the field by name, or use Event Viewer's **Find** (`Ctrl+F`).
- **4728 vs 4732 vs 4756** is group *scope*: global / local / universal. Domain Admins is
  4728, Backup Operators and Remote Desktop Users are 4732, Enterprise Admins is 4756 —
  so watching only 4728 misses real escalation paths. A 4732 can also mean a machine-local
  group on WS01; the `Computer` field distinguishes them.
- **4728's `Member → Account Name` is a distinguished name**, not the logon name
  (`CN=svc_backup,CN=Users,DC=corp,DC=local`). 4732 is the one that often shows `-`.
- **A 4724 beside a 4720** is account creation, not a password reset —
  `New-ADUser -AccountPassword` writes 4720/4722/4724 in the same second. A 4724 *alone*
  against an existing account is the suspicious one.
- **Automatic lockout expiry writes no 4767.** A 4767 existing at all is evidence of
  deliberate administrative action.
- Get fields **by name**, not `Properties[n]`:
  ```powershell
  ([xml]$e.ToXml()).Event.EventData.Data | Format-Table Name, '#text'
  ```
  Most events keep their fields under `.Event.EventData.Data`, but some use `UserData`
  instead — **1102** stores its subject at `.Event.UserData.LogFileCleared`
  (`SubjectUserName`), and 104 similarly. If `EventData.Data` is empty, check `UserData`.
- **Read an exported log with `-Path <file>.evtx`**, and filter it with `-FilterXPath`
  (not `-FilterHashtable`, which is live-log only), e.g.
  `Get-WinEvent -Path C:\evidence\x.evtx -FilterXPath "*[System[(EventID=4625)]]"`. An
  `.evtx` is a **frozen snapshot** taken at export time — it does not track the live log,
  which is exactly why it survives overwrite/clear. `wevtutil epl <log> <file>` exports;
  reads work on any machine, not just the source host.
- 4771 has **no Logon Type** — "Type: 2" there is Pre-Authentication Type
  (`PA-ENC-TIMESTAMP`). Interactive-vs-network evidence comes from 4625 on WS01.
- Empty output is not an error. Check in order: wrong machine → window too narrow or
  starved → **events overwritten** (`wevtutil gli <log>`, and compare `FileSize` to
  `MaximumSizeInBytes` — if the log has never filled, the oldest event is the machine's
  true beginning, not a rotation boundary) → channel disabled → auditing actually off.

## Module and findings conventions

Each lab file is a **step-by-step run sheet**, ordered, each step naming its VM — not a
reference document. Structure: objective → pre-flight → build → break/observe → detect →
evidence → MITRE mapping, then a Findings section and a troubleshooting section.

Findings use **observation → inference → recommendation**, kept strictly separate:

- **Observation** — only what the log literally says. Host, log, event ID, timestamp,
  accounts. Reproducible by someone else. **State timestamps in UTC** — that is what the
  event stores (`TimeCreated SystemTime`); Event Viewer only converts for display. The
  lab VMs were installed on Pacific while the analyst is on WAT (UTC+1), so displayed
  hours ran eight hours out and mid-morning activity looked like 3 AM. Name the offset
  if you also give a local time.
- **Inference** — labelled judgement, with confidence language ("I assess with high
  confidence"), MITRE technique IDs, and an explicit statement of what *cannot* be
  determined from the evidence.
- **Recommendation** — specific and actionable, naming the follow-up queries.

Where evidence supports more than one story, name the competing hypotheses, say which is
favoured and why, and state what would discriminate between them. Never let sequence
imply causation.

## Git

Remote is `github.com/Simplyaeon/windows-ad-soc-lab`. **Treat the repo as public.**
Commit when asked; **do not push without explicit confirmation** — screenshots can leak
host names, IPs, and usernames, and should be checked before anything is published.
Keep the README progress log and `summary.md` current as modules complete.
