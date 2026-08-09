# Module NN — <Title>

> **Part:** I (Windows Admin) / II (Active Directory)
> **Runs on:** DC01 / WS01 / both
> **Est. time:** ~N hours
> **Snapshot before starting:** `<name>`

---

## 1. Objective & SOC relevance

<2–3 sentences: what capability you build, and why a SOC analyst cares — what real
attack or investigation this underpins.>

**By the end you can:**
- [ ] <skill 1>
- [ ] <skill 2>
- [ ] <detection skill — the one that matters>

---

## 2. Pre-flight

- VM state expected: <e.g. domain-joined, auditing enabled>
- Take a snapshot named `<name>` so you can repeat the Break step.
- Confirm auditing is on (if relevant): `auditpol /get /category:*`

---

## 3. Build

<Numbered admin steps with exact commands in fenced blocks. Show expected output.>

```powershell
# command
```

---

## 4. Break / Observe

<The activity that generates telemetry. Benign, isolated, repeatable.>

```powershell
# command
```

---

## 5. Detect

**Event ID reference**

| Event ID | Log | Meaning |
|----------|-----|---------|
| | | |

**Hunt query**

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=<id> } -MaxEvents 20 |
  Format-Table TimeCreated, Id, Message -AutoSize
```

---

## 6. Evidence (for the portfolio)

- [ ] Screenshot: <what to capture> → save to `../assets/NN-<name>.png`
- [ ] Query output showing the detection
- [ ] One-paragraph analyst write-up: what happened, how you'd triage it

---

## 7. MITRE ATT&CK mapping

| Technique | ID | Where it appears here |
|-----------|----|-----------------------|
| | | |

---

## Notes & gotchas

<Anything that tripped you up — future-you and readers will thank you.>
