# Scenario 3 — Persistence & Correlation

---

## 1. Alert Summary

User `j.smith` created a scheduled task on host `ENG-WS-022` that executes a hidden PowerShell script every 30 minutes:

`schtasks /create /sc minute /mo 30 /tn "Updater" /tr "powershell.exe -WindowStyle Hidden -File C:\Users\j.smith\AppData\Local\update.ps1"`

The script downloads and executes a binary from an external IP (`91.214.124.77`). The combination of persistence, hidden execution, external payload retrieval, and execution indicates **high-confidence malicious activity**.

---

## 2. Initial Context

- Host role: Engineering workstation  
- User: `j.smith` (non-administrative user)  
- Baseline: Development tools and occasional scripting; no requirement to create scheduled tasks or run hidden PowerShell for system persistence  

**Risk implication:**

The behavior deviates from baseline by introducing persistence and external code execution on a non-admin user workstation, indicating potential compromise and ongoing unauthorized access.

---

## 3. SOC Case Note

### Alert Assessment

**Likely Malicious — Containment Required**

---

### Key Observations

- `powershell.exe` spawned `cmd.exe`, which executed `schtasks.exe`  
- Scheduled task `"Updater"` created to run every 30 minutes  
- PowerShell executed with `-WindowStyle Hidden`  
- Script created at: `C:\Users\j.smith\AppData\Local\update.ps1`  
- Script downloads `payload.exe` from `91.214.124.77`  
- Downloaded file saved as `temp.exe` and executed  
- Outbound network connection to external IP over HTTP  

---

### Investigation Reasoning

**Step 1 — Persistence Mechanism**

`schtasks` is used to create a scheduled task that executes every 30 minutes (`/sc minute /mo 30`).  
This ensures repeated execution of the malicious script, establishing persistence on the host.

---

**Step 2 — Script Behavior**

The script uses `WebClient.DownloadFile` to retrieve an executable from an external IP and then runs it using `Start-Process`.  
This indicates payload delivery followed by execution, a common malware pattern.

---

**Step 3 — Execution Pattern**

The scheduled task runs continuously at fixed intervals, allowing the attacker to maintain access, re-establish execution, or update payloads over time.

---

**Step 4 — Location Analysis**

The script is stored in the user’s `AppData\Local` directory, a writable location commonly used by malware to avoid detection and blend with normal user activity.

---

**Step 5 — Full Correlation**

The sequence shows:

- PowerShell used to initiate command execution  
- Scheduled task created for persistence  
- Malicious script written to disk  
- Script downloads external payload  
- Payload executed repeatedly  

This represents a full compromise chain: **execution → persistence → payload delivery → repeated execution**.

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
- Review for lateral movement or additional persistence  

---

## 4. Key Takeaways

- Scheduled tasks are a common and effective persistence mechanism  
- Repeated execution intervals indicate sustained attacker access  
- External payload download and execution is a high-confidence indicator of compromise  
- Use of trusted binaries (PowerShell, schtasks) enables stealthy attacks  
- Correlating multiple weak signals reveals full attack intent  

---

## 5. What This Demonstrates

- Ability to correlate endpoint telemetry into a complete attack chain  
- Identification of persistence mechanisms and execution patterns  
- Understanding of attacker techniques using LOLBins  
- Strong SOC-level reasoning and confident incident classification  

---
