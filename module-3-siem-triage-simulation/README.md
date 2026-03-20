# Module 3 — SIEM Triage Simulation

---

## Overview

This module demonstrates practical Security Operations Center (SOC) alert triage and investigation skills.

The focus is on analyzing alerts, correlating multiple data sources, and making evidence-based decisions aligned with real-world SOC workflows.

Each scenario simulates a realistic alert and documents the full triage process from initial assessment through escalation.

---

## Objectives

- Simulate real SOC alert triage scenarios  
- Apply structured investigation methodology  
- Correlate process, network, and contextual data  
- Distinguish between benign, suspicious, and malicious activity  
- Make defensible escalation decisions  
- Recommend appropriate containment actions  

---

## Methodology

Each scenario follows a consistent triage structure:

1. **Alert Assessment**  
   Initial classification based on available indicators  

2. **Key Observations**  
   Extraction of high-signal data from logs  

3. **Investigation Reasoning**  
   Correlation of events to reconstruct activity  

4. **Decision**  
   Escalation or closure based on evidence  

5. **Recommended Actions**  
   Immediate SOC response and containment steps  

---

## Scenarios Included

- Scenario 1 — Suspicious PowerShell Execution  
- Scenario 2 — *(In Progress)*  
- Scenario 3 — *(In Progress)*  

---

## Tools & Data Sources

- SIEM (Splunk-style detection logic)  
- Windows Event Logs  
- Sysmon telemetry  
  - Event ID 1 — Process Creation  
  - Event ID 3 — Network Connection  
- Threat intelligence enrichment  

---

## Skills Demonstrated

### Core Skills (All Scenarios)

- SOC alert triage and escalation decision-making  
- Correlation of process execution and network telemetry  
- Structured and defensible incident documentation  
- Evidence-based reasoning aligned with SOC workflows  

---

### Scenario-Specific Skill Progression

**Scenario 1 — High-Confidence Malicious Activity**
- Identification of obfuscated execution techniques (encoded PowerShell)  
- Recognition of command-and-control (C2) communication patterns  
- Clear escalation based on strong threat intelligence  

---

**Scenario 2 — Ambiguous / Suspicious Activity**
- Analysis without confirmed threat intelligence  
- Differentiating legitimate vs suspicious administrative behavior  
- Handling potential false positives  
- Applying baseline vs anomaly reasoning  

---

**Scenario 3 — Advanced Triage & Correlation**
- Multi-event correlation across systems or time  
- Identification of attacker patterns (e.g., lateral movement or persistence)  
- Prioritization and risk-based decision-making under uncertainty  

---

## Key Concepts

- Process chain analysis (parent-child relationships)  
- Obfuscation techniques (`-enc`, hidden execution)  
- Threat intelligence enrichment  
- Behavioral analysis vs signature-based detection  
- Baseline vs anomaly detection  
- Evidence-based decision-making under uncertainty  

---

## Notes

This module is part of a broader **Detection & Response Foundations Portfolio**, designed to demonstrate practical SOC and blue-team capabilities.

Scenarios are structured to reflect real analyst workflows, progressing from clear malicious activity to more ambiguous and complex investigation scenarios.
