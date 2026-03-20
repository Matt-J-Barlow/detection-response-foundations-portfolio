# Scenario 1 — Suspicious PowerShell Execution

---

## Alert Summary

- **Alert Name:** Encoded PowerShell Execution  
- **Severity:** Medium  
- **Host:** FIN-WS-023  
- **User:** j.smith  
- **Time:** 2026-02-26 09:14:22 ICT  
- **Detection Rule:** PowerShell executed with encoded command (`-enc`)  

---

## Initial Context

- **Asset:** Finance department workstation  
- **User role:** Accounts Payable (non-technical)  
- **PowerShell usage:** Not typical for this role  
- **EDR:** Active  
- **Prior alerts:** None associated with this host  

---

## SOC Case Note

### 1. Alert Assessment

This alert is assessed as **Likely Malicious** because:

- PowerShell was executed with an encoded command (`-enc`), indicating obfuscation  
- The process originated from **OUTLOOK.EXE via cmd.exe**, suggesting a phishing-based execution chain  
- The command was executed in **hidden mode**, indicating stealth behavior  
- The host initiated a connection to **a known malicious IP associated with C2 infrastructure**  

---

### 2. Key Observations

- **Process chain:**  
  OUTLOOK.EXE → cmd.exe → powershell.exe  

- **PowerShell execution details:**
  - Flag used: `-enc` (encoded command)  
  - Execution visibility: Hidden (`-WindowStyle Hidden`)  

- **Network activity:**
  - Destination IP: 185.243.115.84  
  - Destination Port: 443  
  - Reputation: Known malicious (C2 infrastructure)  

---

### 3. Investigation Reasoning

The alert indicates a likely attack chain beginning with an email opened in OUTLOOK, which likely triggered execution of a malicious attachment (e.g., `.bat` file), leading to command execution via `cmd.exe` and subsequent PowerShell execution.

The presence of `-enc` indicates the command is intentionally obfuscated, a technique commonly used to hide malicious payloads and evade detection.

The use of hidden execution (`-WindowStyle Hidden`) suggests an attempt to avoid user awareness during execution.

The outbound connection to **185.243.115.84 over port 443**, identified as known malicious C2 infrastructure, indicates the host is likely communicating with attacker-controlled systems, confirming high-confidence malicious activity.

---

### 4. Decision

**Escalate to Tier 2**

**Justification:**

This activity demonstrates obfuscated command execution, stealth behavior via hidden PowerShell, and confirmed communication with known malicious C2 infrastructure, which are consistent with high-confidence malicious activity requiring further investigation and containment.

---

### 5. Recommended Actions

- **Isolate host:**  
  Isolate FIN-WS-023 from the network to prevent further C2 communication and potential lateral movement  

- **Block destination IP:**  
  Block outbound traffic to 185.243.115.84 at firewall or proxy level  

- **Investigate user activity:**  
  Review user j.smith’s recent email activity, including attachments and links opened in Outlook  

- **Collect additional artifacts:**  
  - Retrieve the `.bat` file from `AppData\Local\Temp`  
  - Collect full process tree from Sysmon logs  
  - Review additional network connections from the host  

- **Escalate to:**  
  Tier 2 / Incident Response team  

---

## Key Takeaways

- Encoded PowerShell (`-enc`) indicates obfuscation  
- Hidden execution is used to avoid user detection  
- Process chains reveal attack origin (Outlook → script → PowerShell)  
- Known malicious IP communication is a high-confidence compromise indicator  
- Multiple aligned signals increase detection confidence  

---

## What This Demonstrates

- SOC alert triage and escalation decision-making  
- Correlation of process execution and network telemetry to reconstruct attacker behavior  
- Identification of obfuscated execution techniques (encoded PowerShell)  
- Recognition of command-and-control (C2) communication patterns  
- Evidence-based analysis aligned with real SOC workflows  
