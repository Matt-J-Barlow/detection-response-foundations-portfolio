# Module 4 — Endpoint Monitoring & Host Visibility

---

## Overview

This module demonstrates endpoint-level detection and investigation using host telemetry.  
The focus is on analyzing process execution, command-line activity, and behavioral patterns to identify potentially malicious activity on a compromised system.

Unlike previous modules, this work emphasizes host-based reasoning rather than log aggregation or alert triage alone.

This module simulates real-world endpoint investigations using representative telemetry based on common enterprise attack patterns.

---

## What Makes This Module Different

Unlike traditional SIEM-focused analysis, this module emphasizes host-level visibility and behavioral reasoning.

The scenarios require:

- Correlating multiple low-signal events  
- Interpreting attacker intent from process behavior  
- Making defensible decisions under uncertainty  

This reflects real SOC and MDR investigation workflows.

---

## Objectives

- Perform endpoint-level investigation using host telemetry  
- Identify malicious behavior through process execution and command-line analysis  
- Correlate process, network, and file activity into a coherent attack chain  
- Distinguish between legitimate and malicious activity in ambiguous scenarios  
- Identify persistence mechanisms and attacker tradecraft on endpoints  
- Produce SOC-ready, defensible analysis  

---

## Key Concepts Demonstrated

### Process Creation Analysis
- Sysmon Event ID 1  
- Windows Security Event ID 4688  
- Process command-line inspection  

### Parent-Child Relationships
- Office applications spawning interpreters (e.g. Word → cmd → PowerShell)  
- Identifying abnormal execution chains  

### Command-Line Analysis
- PowerShell flags:
  - `-ExecutionPolicy Bypass`
  - `-NoProfile`
  - `-WindowStyle Hidden`
- Detection of in-memory execution:
  - `IEX (Invoke-Expression)`
  - `DownloadString`

### Network Activity Correlation
- Sysmon Event ID 3  
- Outbound connections to unknown external IPs  
- Linking execution to network behavior  

### Living-off-the-Land Techniques (LOLBins)
- PowerShell  
- cmd.exe  
- rundll32.exe  

### Persistence & Execution Indicators
- Execution from temporary directories  
- Scheduled task persistence  
- Suspicious use of system binaries  

---

## Key Techniques Covered

- Macro-based initial access  
- Fileless execution via PowerShell  
- Living-off-the-land binaries (LOLBins)  
- Scheduled task persistence  
- Internal vs external behavior analysis  
- Ambiguous alert triage  

---

## Scenarios

### Scenario 1 — Suspicious Process Execution

Analysis of a phishing-driven attack chain involving:

- Outlook → Word (macro-enabled document)  
- Word spawning `cmd.exe` and `powershell.exe`  
- PowerShell downloading and executing remote code  
- Execution of payload via `rundll32.exe`  

**Focus:**
- Process chain reasoning  
- Command-line interpretation  
- Detection of fileless execution techniques  

---

### Scenario 2 — Ambiguous Activity

Investigation of behavior that may be legitimate or malicious depending on context.

**Focus:**
- Reducing false positives  
- Context-driven decision making  
- Differentiating administrative vs attacker behavior  

---

### Scenario 3 — Persistence & Correlation

Multi-event endpoint investigation involving persistence mechanisms and chained activity.

**Focus:**
- Linking multiple weak signals  
- Identifying persistence techniques  
- Building a full attack narrative from host data  

---

## Skills Developed

- Endpoint telemetry analysis (EDR/Sysmon mindset)  
- Behavioral detection reasoning  
- Command-line threat analysis  
- Process chain reconstruction  
- Risk-based decision making  
- SOC/MDR-style investigation documentation  

---

## Tools & Data Sources

- Sysmon (Event ID 1, Event ID 3)  
- Windows Security Logs (Event ID 4688)  
- Simulated EDR telemetry  
- Process command-line data  

---

## Why This Module Matters

This module demonstrates the ability to:

- Move beyond alerts into host-level investigation  
- Understand how attacks execute and persist on endpoints  
- Translate technical findings into defensible security decisions  

These are core skills required for:

- SOC Analyst roles  
- MDR Analyst roles  
- Incident Response positions  

---

## Portfolio Positioning

This module builds directly on:

- **Module 2 — Detection Engineering**  
- **Module 3 — SIEM Triage Simulation**  

And strengthens readiness for:

- Incident reporting and documentation  
- Risk-based analysis and business impact assessment  

---

## Notes

- All scenarios are based on realistic attack patterns observed in enterprise environments  
- Analysis focuses on observable behavior and evidence, not assumptions  
- Evidence sections are included to demonstrate how conclusions are derived from observable telemetry  
- Conclusions are written to be defensible in a SOC or interview setting  

---
