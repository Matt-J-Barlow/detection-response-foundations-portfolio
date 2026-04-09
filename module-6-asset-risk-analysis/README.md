# Module 6 — Asset & Risk Contextualization

## 1. Asset Classification

The affected asset is an enterprise user workstation operating within the corporate network. This endpoint serves as an access point for an authenticated employee, enabling interaction with internal systems, business applications, and shared resources. Its value lies not in the hardware itself, but in the identity and access it provides within the environment. Compromise of this asset allows an attacker to operate under legitimate user context, enabling internal reconnaissance, credential harvesting, and potential lateral movement. As a result, the workstation represents a strategic foothold that could facilitate broader compromise rather than an isolated endpoint issue.

---

## 2. Data Sensitivity

The compromised endpoint may provide access to internal business data including local files, shared documents, and email content associated with the user. While there is no confirmed evidence of sensitive data exfiltration, the presence of authenticated access introduces the potential for exposure of internal information and user-specific data. Of particular concern is the potential access to stored credentials, browser sessions, or authentication tokens, which could enable further access to internal systems. At this stage, the primary sensitivity lies not in confirmed data loss, but in the potential for credential compromise and subsequent expansion of access within the environment.

---

## 3. Likelihood vs Impact Analysis

The likelihood of further malicious activity is elevated due to confirmed execution of obfuscated PowerShell commands and the establishment of persistence via scheduled task. This indicates active attacker control and the ability to re-engage with the system over time. Persistence significantly increases the probability of continued attacker activity, including credential harvesting, lateral movement, and escalation attempts.

The potential impact is moderate to high, depending on the level of access associated with the compromised user. While no direct evidence of data exfiltration or privilege escalation has been observed, the attacker’s ability to operate within a legitimate user context creates a pathway to internal systems and resources. If left uncontained, this could lead to broader compromise of additional endpoints or accounts.

---

## 4. Risk Severity Rating

**Risk Level: High**

This rating is justified by the combination of confirmed system compromise, persistence mechanisms, and the ability for the attacker to operate under legitimate user credentials. Although the full extent of impact is not yet realized, the conditions for further compromise are present, and the likelihood of escalation increases over time without effective containment. The uncertainty surrounding attacker objectives further contributes to the elevated risk level.

---

## 5. Business Impact

From a business perspective, the primary concern is not immediate disruption, but the potential for undetected attacker presence within the internal environment. A compromised user endpoint introduces risk to internal data integrity, user trust, and system security. If leveraged further, this access could result in unauthorized access to internal systems, misuse of employee accounts, or propagation to additional assets. This creates potential for operational disruption, data exposure, and reputational impact if escalation occurs.

---

## 6. Control Gaps

The incident highlights several control weaknesses within the environment:

- Insufficient prevention of malicious macro-enabled document execution  
- Lack of effective restrictions on PowerShell usage and script execution  
- Inadequate detection or prevention of scheduled task persistence mechanisms  
- Potential gaps in endpoint detection and response visibility  
- Limited early-stage containment before persistence was established  

These gaps indicate that while detection may exist, it is not sufficiently preventative or timely.

---

## 7. Security Improvement Recommendations

To reduce future risk and improve defensive posture, the following actions are recommended:

- Implement stricter controls on macro execution and user-delivered documents  
- Enforce PowerShell logging, monitoring, and constrained execution policies  
- Enhance endpoint detection capabilities to identify suspicious process chains and persistence mechanisms  
- Improve alerting and response workflows to reduce dwell time  
- Strengthen user awareness training to reduce susceptibility to phishing-based entry  

These improvements focus on reducing initial access success, limiting attacker execution capability, and improving detection speed.
