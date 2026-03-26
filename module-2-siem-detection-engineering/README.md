## Module 2 — SIEM Detection Engineering

This module demonstrates the design and implementation of SIEM-based detection rules using Windows Security Event Logs. The focus is on identifying suspicious behavior through log analysis, including credential abuse, lateral movement, and privilege escalation.

Two detection rules are developed:

- Detection 1: Suspicious Remote Logon (Event ID 4624)
- Detection 2: Privileged Logon Anomaly (Event ID 4672)

---

# Detection 1 — Suspicious Remote Logon Detection

### Threat Scenario
An attacker uses valid credentials to access systems remotely and move laterally across the network.

---

### Detection Objective
Detect suspicious successful remote logons because they may indicate unauthorized access using compromised credentials.

---

### Log Source
Windows Security Logs

---

### Primary Event ID
4624 – Successful logon

---

### Suspicious Signals
- Logon Type 3 (network) or 10 (RDP)
- Logon occurs outside business hours
- Source IP not previously observed for the user

---

### Splunk Detection Logic
```sql
index=windows sourcetype=WinEventLog:Security EventCode=4624
| search Logon_Type IN (3, 10)
| eval hour=tonumber(strftime(_time,"%H"))
| where hour < 8 OR hour > 17
| stats earliest(_time) as first_seen latest(_time) as last_seen count by Account_Name, Source_Network_Address, Logon_Type
| where count = 1
```

---

### Detection Logic Explanation
This query identifies successful remote logons (Logon Type 3 and 10) occurring outside business hours and highlights rare user/IP combinations within the search window. By filtering for events that occur only once, it surfaces potentially unusual or unauthorized access attempts while reducing noise from normal repeated activity.

---

### Baseline / Hunting Query
```sql
index=windows sourcetype=WinEventLog:Security EventCode=4624
| search Logon_Type IN (3, 10)
| stats count by Account_Name, Source_Network_Address
| sort - count
```

This query helps establish normal remote logon patterns by showing the most frequently used source IPs per user.

---

### False Positives
- IT administrator accessing systems remotely
- Employee connecting via VPN from a new location

---

### MITRE ATT&CK Mapping
- Tactic: Lateral Movement
- Technique: Remote Services (T1021)

---

### Tuning Considerations
- Whitelist known admin accounts
- Exclude known corporate/VPN IP ranges
- Baseline normal user login patterns

---

# Detection 2 — Privileged Logon Anomaly Detection

### Threat Scenario
An attacker gains access to a system and obtains elevated privileges, potentially indicating privilege escalation or misuse of administrative accounts.

---

### Detection Objective
Detect privileged logons because they may indicate unauthorized elevation of access or misuse of high-privilege accounts.

---

### Log Source
Windows Security Logs

---

### Primary Event ID
4672 – Special privileges assigned to new logon

---

### Suspicious Signals
- Privileged logon occurs outside business hours
- Account is not a known administrative account
- Logon originates from an unusual host

---

### Splunk Detection Logic
```sql
index=windows sourcetype=WinEventLog:Security EventCode=4672
| eval hour=tonumber(strftime(_time,"%H"))
| where hour < 8 OR hour > 17
| stats count by Account_Name, ComputerName
```

---

### Detection Logic Explanation
This query identifies privileged logons (Event ID 4672) occurring outside normal business hours. Since privileged access is typically restricted and predictable, unusual timing or accounts can indicate potential misuse or escalation.

---

### False Positives
- System administrators performing maintenance outside business hours
- Automated processes or scheduled administrative tasks

---

### MITRE ATT&CK Mapping
- Tactic: Privilege Escalation
- Technique: Valid Accounts (T1078)

---

### Tuning Considerations
- Whitelist known administrative/service accounts
- Monitor expected maintenance windows
- Correlate with other events such as 4624 or 4688 for context

---

### Improvement Note
A production-level detection would correlate privileged logons with preceding authentication events and historical user behavior to better identify abnormal privilege usage patterns.
