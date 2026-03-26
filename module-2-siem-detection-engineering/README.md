## Module 2 — SIEM Detection Engineering

This module demonstrates the design and implementation of SIEM-based detection rules using Windows Security Event Logs. The focus is on identifying suspicious behavior through authentication and privilege-related events, with an emphasis on real-world SOC detection logic.

The detections in this module progress from single-event analysis to basic event correlation, reflecting how modern SOC teams identify abnormal behavior across multiple signals.

---

# Detection 1 — Suspicious Remote Logon Detection (Event ID 4624)

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
- Source IP not previously observed for the user (approximated via rarity)

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

This query establishes normal remote logon behavior by identifying commonly used IP addresses per user, supporting detection tuning and false positive reduction.

---

### False Positives
- IT administrators accessing systems remotely
- Employees connecting via VPN from new locations

---

### MITRE ATT&CK Mapping
- Tactic: Lateral Movement  
- Technique: Remote Services (T1021)

---

### Tuning Considerations
- Whitelist known administrative accounts
- Exclude corporate VPN and internal IP ranges
- Baseline normal user login patterns over time

---

# Detection 2 — Correlated Privileged Logon Detection (4624 + 4672)

### Threat Scenario
An attacker gains access to a system using valid credentials and is assigned elevated privileges, indicating potential misuse of administrative access or privilege escalation.

---

### Detection Objective
Detect correlated successful and privileged logons because they may indicate unauthorized elevation of access or compromised administrative credentials.

---

### Log Source
Windows Security Logs

---

### Primary Event IDs
- 4624 – Successful logon  
- 4672 – Special privileges assigned to new logon  

---

### Suspicious Signals
- Successful logon followed by privileged access on the same host
- Activity occurs outside business hours
- Repeated or clustered authentication activity

---

### Splunk Detection Logic
```sql
index=windows sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4672)
| eval hour=tonumber(strftime(_time,"%H"))
| where hour < 8 OR hour > 17
| stats count values(EventCode) as events earliest(_time) as first_seen latest(_time) as last_seen by Account_Name, ComputerName
| where mvcount(events) > 1 AND count >= 2
```

---

### Detection Logic Explanation
This query correlates successful logon events (4624) with privileged logon events (4672) occurring on the same host outside business hours. By requiring both event types and multiple occurrences, it strengthens detection of potentially unauthorized privileged access while reducing isolated noise from single events.

---

### False Positives
- System administrators performing scheduled maintenance
- Automated administrative tasks or service account activity

---

### MITRE ATT&CK Mapping
- Tactic: Privilege Escalation  
- Technique: Valid Accounts (T1078)

---

### Tuning Considerations
- Whitelist known administrative and service accounts
- Align detection with approved maintenance windows
- Correlate with process creation events (4688) for deeper validation

---

## Improvement Note

A production-level implementation would incorporate historical baselining to identify deviations in user behavior over time, including new source IP addresses, unusual host access patterns, and abnormal privilege usage. Additional correlation with process execution (Event ID 4688) and authentication failures (4625) would further improve detection accuracy.

---

## Key Learning Outcome

This module demonstrates the transition from single-event detection to multi-event correlation, reflecting real-world SOC practices where context, timing, and behavioral patterns are critical for identifying true security threats.
