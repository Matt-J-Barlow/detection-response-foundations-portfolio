# Scenario 2 — Ambiguous PowerShell Activity

---

## 1. Alert Summary

User `admin.svc` executed PowerShell on host `IT-ADMIN-02` outside standard working hours using the command:

`powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\backup.ps1`

The activity involved accessing internal Finance directory data via an internal file server. While PowerShell usage aligns with the account’s baseline behavior, the after-hours execution and lack of documented scheduling introduces uncertainty requiring further validation.

---

## 2. Initial Context

- Host role: IT administrative workstation used for system management and automation  
- Typical user activity: Frequent use of PowerShell for administrative scripting, remote management, and maintenance tasks  
- Why this behavior may be normal: The account `admin.svc` is a service account commonly used for automated scripts and administrative operations, including PowerShell execution  

**Risk implication of this deviation:**

Although the behavior aligns with expected administrative activity, the execution occurred outside standard working hours using a shared service account and involved access to Finance-related data. This introduces risk due to reduced accountability and the potential for unauthorized or misconfigured activity.

---

## 3. SOC Case Note

### Alert Assessment

**Suspicious — Requires Validation**

The activity demonstrates both legitimate and potentially concerning characteristics. While the use of PowerShell and script execution aligns with the account’s baseline behavior, the timing, lack of documented scheduling, and access to sensitive data warrant further investigation before classification.

---

### Key Observations

- PowerShell executed by: `admin.svc`  
- Parent process: `explorer.exe`  
- Command used:  
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\backup.ps1`  
- Script location: `C:\Scripts\backup.ps1`  
- Network destination: `10.0.5.12` (internal file server)  
- No external communication observed  
- No use of `IEX`, `DownloadString`, or obfuscated commands  

---

### Investigation Reasoning

**Step 1 — Parent Process**

- `explorer.exe → powershell.exe`  

This indicates interactive execution by a logged-in user, which is consistent with administrative activity and differs from automated or exploit-driven execution chains.

---

**Step 2 — Command-Line Analysis**

- `-ExecutionPolicy Bypass` → allows the script to run without being restricted by PowerShell execution policies, commonly used in administrative scripting  
- `-NoProfile` → ensures PowerShell runs without loading user-specific configurations, providing a clean and predictable environment  
- `-File C:\Scripts\backup.ps1` → executes a predefined script stored locally on disk, which can be reviewed and is not dynamically generated  

**Why this is different from Scenario 1:**

- Scenario 1 involved dynamic remote code execution using `IEX (DownloadString)`, which is high-risk and fileless  
- This scenario involves execution of a known local script with no external communication, aligning more closely with legitimate administrative behavior  

---

**Step 3 — Network Behavior**

- Internal connection to `10.0.5.12`  

This suggests access to internal resources rather than external communication, significantly reducing the likelihood of command-and-control or data exfiltration activity.

---

**Step 4 — Script Execution**

- Script is stored on disk and accessible  

This allows for direct inspection and validation of its purpose, unlike fileless or dynamically generated scripts which are harder to analyze and more commonly associated with malicious activity.

---

**Step 5 — Time & Account Context**

- Execution occurred outside standard working hours using a shared service account  

This introduces risk due to reduced accountability and lack of traceability to a specific individual. Additionally, the absence of a documented scheduled task or approved change increases the possibility of unauthorized or unintended activity.

---

### Decision

**Suspicious — Validation Required**

The activity does not present clear indicators of compromise but deviates from expected operational patterns sufficiently to require confirmation.

---

### Recommended Actions

**Immediate Actions:**

- Verify whether the script execution was part of an approved or scheduled administrative task  
- Confirm with IT or system owners whether after-hours execution is expected behavior  

**Follow-up Actions:**

- Review the contents of `backup.ps1` for intended functionality  
- Audit historical activity of `admin.svc` for similar behavior patterns  
- Implement logging or monitoring for service account usage outside standard hours  
- Consider enforcing stricter controls or accountability for shared service accounts  

---

## 4. Key Takeaways

- Not all PowerShell activity is malicious; context and baseline behavior are critical for accurate assessment  
- Execution of local, known scripts is lower risk than dynamic or fileless execution techniques  
- Internal network communication reduces likelihood of external compromise but does not eliminate risk  
- Shared service accounts and after-hours activity introduce accountability and governance concerns  
- Analysts must balance technical signals with environmental context before making a determination  

---

## 5. What This Demonstrates

- Ability to assess ambiguous activity without over-escalation  
- Understanding of legitimate vs suspicious PowerShell usage  
- Context-driven investigation and decision-making  
- Application of SOC-level reasoning under uncertainty  
- Professional and defensible incident analysis  

---
