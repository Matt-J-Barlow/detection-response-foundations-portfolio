## Module 2 — SIEM Detection Engineering

### Detection Name
Suspicious Remote Logon Detection

---

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
(paste your query here — we are about to finish it)

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
