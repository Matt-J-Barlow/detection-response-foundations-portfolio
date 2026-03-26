# Scenario 3 — Suspicious Lateral Movement Indicators

---

## Alert Summary

- **Alert Name:** Suspicious Authentication & Process Activity  
- **Severity:** Medium  
- **Primary Host:** ENG-WS-022  
- **User:** j.smith  
- **Time:** 2026-02-28 10:42:13 ICT  
- **Detection Rule:** Multiple logons across hosts + process execution on server  

---

## Initial Context

- **User:** j.smith (Engineering department)  
- **Normal behavior:**  
  - Logs into ENG-WS-022 only  
  - Does not access servers  
- **Environment:** Domain-joined network  
- **Prior alerts:** None associated with this user  

---

## SOC Case Note

### 1. Alert Assessment

This alert is assessed as **Likely Malicious** because:

- The user **j.smith** performed **multiple logons across hosts and process execution**, which is abnormal for their role  
- The account accessed **FILE-SRV-01**, which is unexpected based on known behavior  
- A **network logon (Logon Type 3)** was observed from **ENG-WS-022 to FILE-SRV-01**  
- **Elevated privileges (Event ID 4672)** were assigned unexpectedly  
- **PowerShell execution (Event ID 4688)** was observed on the server, indicating activity inconsistent with baseline and possible credential misuse or unauthorized access  

---

### 2. Key Observations

- **User account:** j.smith  

- **Initial logon:**
  - Event ID: 4624  
  - Logon Type: 2 (Interactive)  
  - Host: ENG-WS-022  
  - Time: 10:42:13  

- **Subsequent logon:**
  - Event ID: 4624  
  - Logon Type: 3 (Network)  
  - Source: ENG-WS-022  
  - Destination: FILE-SRV-01  
  - Time: 10:45:02  

- **Privilege assignment:**
  - Event ID: 4672  
  - Host: FILE-SRV-01  
  - Privileges: SeBackupPrivilege, SeRestorePrivilege  

- **Process execution:**
  - Event ID: 4688  
  - Process: powershell.exe  
  - Parent process: cmd.exe  
  - Host: FILE-SRV-01  

---

### 3. Investigation Reasoning

The alert indicates **suspicious cross-system activity involving the account j.smith**.

The user **j.smith**, who is typically expected to log into **ENG-WS-022 only**, accessed **FILE-SRV-01**, which is abnormal based on baseline behavior.

The presence of a **Logon Type 3 from ENG-WS-022 to FILE-SRV-01** indicates **network-based access to a server**, suggesting potential **lateral movement**.

The assignment of **elevated privileges (Event ID 4672)** indicates that the account obtained **high-level access**, which is not expected for this user.

The execution of **powershell.exe via cmd.exe (Event ID 4688)** on **FILE-SRV-01** suggests **command execution on the server**, which is unusual and may indicate **post-compromise activity**.

The sequence of events —  
**Initial logon (Type 2) → Network logon (Type 3) → Privileged logon (Event ID 4672) → Process execution (Event ID 4688)** —  
is consistent with **lateral movement and privilege escalation behavior**, increasing the likelihood of **potential compromise**.

---

### 4. Decision

**Escalate to Tier 2**

**Justification:**

This activity demonstrates **lateral movement, elevated privilege assignment, and command execution on a server**, which indicates **high risk**.

Although there is no confirmed malicious payload, the observed behavior is **abnormal and inconsistent with the user’s baseline activity**, requiring further investigation and escalation.

---

### 5. Recommended Actions

- **Validate user activity:**  
  Confirm whether **j.smith’s access to FILE-SRV-01** was authorized  

- **Review authentication activity:**  
  Investigate additional **logon and process creation events** for this account across systems  

- **Analyze cross-system access:**  
  Review activity between **ENG-WS-022 and FILE-SRV-01** around the time of the alert (10:42–10:50 ICT)  

- **Investigate server activity:**  
  Analyze activity on **FILE-SRV-01**, including:
  - Process execution  
  - Command history  
  - Accessed resources  

- **Review privilege usage:**  
  Assess how **SeBackupPrivilege and SeRestorePrivilege** were used during the session  

- **Monitor or restrict account:**  
  Consider temporarily restricting the account while validation is performed; disable the account if unauthorized activity is confirmed  

- **Escalate to:**  
  Tier 2 / Incident Response team  

---

## Key Takeaways

- Lateral movement often involves valid credentials used across multiple systems  
- Logon Type 3 (network logon) can indicate movement between hosts  
- Unexpected server access by non-admin users is a strong anomaly  
- Privilege assignment (Event ID 4672) significantly increases risk  
- Process execution on a server following authentication may indicate post-compromise activity  
- Correlating multiple events in sequence is critical for identifying attack patterns  

---

## What This Demonstrates

- Multi-event correlation across authentication and process logs  
- Identification of lateral movement and privilege escalation patterns  
- Behavioral analysis beyond single-event detection  
- Risk-based escalation decision-making in complex scenarios  
- Structured, professional SOC documentation aligned with real-world workflows  
