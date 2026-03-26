# Scenario 2 — Unusual Administrative Logon Activity

---

## Alert Summary

- **Alert Name:** Unusual Remote Logon Activity  
- **Severity:** Medium  
- **Host:** HR-WS-011  
- **User:** admin.svc  
- **Time:** 2026-02-27 02:18:44 ICT  
- **Detection Rule:** Successful remote logon outside business hours  

---

## Initial Context

- **Account:** admin.svc (service account)  
- **Department:** IT / Infrastructure  
- **Typical usage:**  
  - Used for scheduled tasks and services  
  - Not expected to perform interactive logins  
- **Host type:** Workstation (HR user system, not a server)  
- **Business hours:** 08:00 – 18:00  

---

## SOC Case Note

### 1. Alert Assessment

This alert is assessed as **Suspicious (High Risk)** because:

- The account **admin.svc** was used for an **interactive remote login**, which is abnormal for a service account  
- The logon type was **10**, indicating **Remote Desktop (RDP) access**  
- The activity occurred at **02:18:44 ICT**, which is outside normal business hours  
- Multiple **failed logon attempts (Event ID 4625)** were observed prior to a **successful logon (Event ID 4624)**  
- A **privileged logon (Event ID 4672)** occurred immediately after authentication  

---

### 2. Key Observations

- **Account used:** admin.svc  

- **Logon details:**
  - Event ID: 4624  
  - Logon Type: 10 (Remote Interactive / RDP)  

- **Source of login:**
  - Source IP: 10.10.25.8  
  - Host: HR-WS-011  

- **Time of activity:**
  - Timestamp: 2026-02-27 02:18:44 ICT  
  - Context: Outside standard business hours (08:00–18:00)  

- **Authentication pattern:**
  - Failed logons (Event ID 4625): 4 attempts  
  - Successful logon (Event ID 4624): Logon Type 10  

- **Privilege assignment:**
  - Event ID: 4672  
  - Privileges observed: SeDebugPrivilege, SeBackupPrivilege  

---

### 3. Investigation Reasoning

The alert indicates **suspicious authentication activity involving the service account admin.svc**.

The use of a service account for **interactive logons** is abnormal, as service accounts are typically used for **automated processes rather than direct user access**.

The logon type **10** indicates **remote interactive (RDP) access**, which is unexpected for this type of account.

The presence of **multiple failed logon attempts (Event ID 4625)** followed by a successful login suggests **possible credential misuse or unauthorized access**.

The activity occurring at **02:18:44 ICT** further increases concern, as it is **outside standard business hours**.

The assignment of **special privileges (Event ID 4672)** indicates that the session has **elevated privileges**, increasing the potential impact of misuse.

---

### 4. Decision

**Escalate to Tier 2**

**Justification:**

This activity demonstrates **possible credential misuse, remote interactive logon (RDP), and elevated privilege assignment**, which indicates **high risk**.

Although there is no confirmed malicious indicator, the observed behavior is **unexpected and inconsistent with normal service account usage**, requiring further investigation and escalation.

---

### 5. Recommended Actions

- **Validate account activity:**  
  Confirm whether the use of account **admin.svc** at **02:18:44 ICT** was authorized by the relevant team  

- **Review authentication logs:**  
  Investigate additional **authentication events** related to this account, including:
  - Source IP usage  
  - Frequency of login attempts  
  - Any additional failed or successful logons  

- **Analyze historical usage (baseline):**  
  Review previous login patterns for **admin.svc** to determine whether interactive logons or out-of-hours activity are normal  

- **Investigate source system:**  
  Analyze activity originating from **10.10.25.8** to determine whether the source system is expected for this account or potentially compromised  

- **Review privilege usage:**  
  Assess how **elevated privileges** were used during the session  

- **Monitor or restrict account:**  
  Consider **temporarily restricting or disabling the account if unauthorized activity is confirmed**  

- **Escalate to:**  
  Tier 2 / Incident Response team for further investigation  

---

## Key Takeaways

- Service accounts should not perform interactive logons (RDP)  
- Logon Type 10 indicates remote interactive access, which is high-risk for non-user accounts  
- Failed logon attempts followed by success may indicate credential guessing or misuse  
- Out-of-hours activity increases suspicion when inconsistent with baseline behavior  
- Elevated privileges significantly increase potential impact  
- Correlation of multiple weak signals can indicate high-risk activity even without confirmed malicious indicators  

---

## What This Demonstrates

- SOC triage under ambiguous conditions without confirmed threat intelligence  
- Ability to distinguish between normal and abnormal account behavior  
- Baseline vs anomaly analysis in authentication events  
- Identification of potential credential misuse patterns  
- Risk-based escalation decision-making under uncertainty  
- Structured and defensible SOC documentation aligned with real-world workflows  
