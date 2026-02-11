# TryHackMe SOC Lab – Introduction to Phishing Email Analysis & Triage

## 🏆 Results & Achievement

**Scenario Outcome:** ✅ **Victory - Security Breach Prevented**

[![100% True Positive Rate Badge](https://tryhackme-badges.s3.amazonaws.com/ShakeZula.png)](https://tryhackme.com/ShakeZula/badges/soc-sim-100-percent-true-positive-rate?utm_campaign=social_share&utm_medium=social&utm_content=badge&utm_source=copy&sharerId=6633c4c0cbb9fb5facaac5b6)

**[View Full Results Summary →](https://tryhackme.com/soc-sim/public-summary/45d4f7c6d4f057100ee8462c6bb6bd135de70c65a6dce6909839eba3b5817ccc950240c2a01fd93a01f48588428bc8ea?utm_campaign=social_share&utm_medium=social&utm_content=soc-sim-run-share&utm_source=linkedin)**

### Performance Metrics
- ✅ **True Positive Identification Rate**: 100% (3/3 malicious alerts correctly identified)
- ✅ **False Positive Identification Rate**: 100% (1/1 benign alert correctly identified)
- ⏱️ **Mean Time to Resolve (MTTR)**: 19 minutes
- 🕐 **Mean Dwell Time**: 61 minutes
- 📊 **Alerts Closed**: 4/4

### Alert Breakdown
| Alert ID | Alert Rule | Severity | Type | Time to Resolve | Classification |
|----------|-----------|----------|------|-----------------|----------------|
| 8816 | Blacklisted External URL Blocked | High | Firewall | 27.17 min | ✅ True Positive |
| 8815 | Suspicious External Link | Medium | Phishing | 22.78 min | ✅ True Positive |
| 8817 | Suspicious External Link | Medium | Phishing | 9.92 min | ✅ True Positive |
| 8814 | Suspicious External Link | Medium | Phishing | 15.1 min | ✅ False Positive |

### AI-Powered Feedback
*"Your reports provide a good level of detail, particularly in identifying affected entities and attack indicators. However, there is room for improvement in consistently addressing the 'Where' and 'Why' aspects. While you mention the devices and emails involved, it would be beneficial to clarify the specific locations or systems impacted. Additionally, while you explain the reasons for classifying incidents as true positives, further elaboration on the underlying motivations or potential impacts of these threats would enhance the reports' comprehensiveness."*

---

## Overview
This case study documents the investigation and triage of four phishing-related security alerts in a simulated SOC environment. The exercise demonstrates alert queue management, threat classification, URL analysis, and incident response decision-making aligned with standard SOC playbooks.

**Platform**: TryHackMe  
**Role**: SOC Analyst (L1)  
**Tools Used**: Alert queue management system, TryDetectThis (URL/IP analysis), Splunk (log correlation)  
**Focus Areas**: Phishing detection, URL analysis, threat classification, false positive identification

---

## Lab Environment
- **SIEM**: Splunk for log correlation and host lookup
- **Detection Tool**: TryDetectThis for URL and IP reputation analysis
- **Network Segmentation**: Internal subnet 10.20.2.0/24
- **Security Controls**: Firewall with blacklist enforcement
- **Alert Queue**: Real-time phishing detection rules

---

## Alert Investigations

### Alert 8814: Suspicious Link Characteristics – False Positive

**Alert Details**
- **Time**: 18:30
- **Severity**: Medium
- **Rule**: Link containing suspicious characteristics
- **From**: onboarding@hrconnext.thm
- **To**: j.garcia@thetrydaily.thm
- **Subject**: Complete Onboarding Process
- **Attachment**: None
- **Link**: [Sanitized onboarding URL]

**Investigation Steps**
1. Reviewed alert metadata and email contents
2. Followed playbook steps 3.1 and 3.2 for suspicious link analysis
3. Submitted URL to TryDetectThis for reputation check
4. Analyzed sender domain legitimacy
5. Reviewed email context and business justification

**Analysis**
- URL returned **clean** reputation from threat intelligence
- Sender domain appears legitimate for HR onboarding system
- Email content matches expected onboarding workflow
- No obfuscation or suspicious redirect patterns detected
- No credential harvesting indicators present

**Verdict**: ✅ **False Positive**  
**Action**: Closed alert with notation for tuning detection rule  
**Recommendation**: Whitelist hrconnext.thm domain to reduce false positive rate

---

### Alert 8816: Blacklisted Destination IP – True Positive (Blocked)

**Alert Details**
- **Time**: 18:32
- **Severity**: High
- **User**: Hannah Harris (HR Department)
- **Source IP**: 10.20.2.17
- **Source Port**: 34257
- **Destination IP**: 67.199.248.11
- **Destination Port**: 80 (HTTP)
- **URL**: http://bit.ly/3sHkX3da12340 (obfuscated TinyURL)
- **Action**: **Blocked by firewall**

**Investigation Steps**
1. Reviewed firewall block event and trigger conditions
2. Identified URL shortener obfuscation technique (bit.ly)
3. Queried Splunk for source IP 10.20.2.17 to correlate host activity
4. Submitted destination IP to TryDetectThis for reputation analysis
5. Confirmed blacklist presence and threat classification

**Analysis**
- Destination IP **67.199.248.11** confirmed **malicious** via TryDetectThis
- IP present on organizational blacklist (active threat intelligence)
- URL obfuscation via bit.ly indicates attempt to bypass detection
- Firewall successfully blocked connection attempt
- No evidence of successful C2 communication or data exfiltration

**Verdict**: 🚨 **True Positive – Successfully Blocked**  
**Action**: Escalated to L2 for user education and endpoint validation  
**Recommendation**: Conduct follow-up with Hannah Harris regarding phishing awareness; verify no additional compromise indicators on endpoint win-3457

**Security Impact**
- Firewall prevented potential malware download or credential theft
- Blacklist enforcement demonstrated effective threat intelligence integration
- Early detection prevented lateral movement opportunity

---

### Alert 8815: Phishing Email with Malicious Link – True Positive

**Alert Details**
- **Time**: 18:31
- **Severity**: High
- **User**: h.harris@thetrydaily.thm
- **Device**: win-3457
- **From**: urgents@amazon.biz
- **Subject**: Amazon Package Undeliverable
- **Link**: http://bit.ly/3sHkX3da12340 (obfuscated TinyURL)

**Investigation Steps**
1. Analyzed sender domain for spoofing indicators
2. Reviewed email content for social engineering tactics
3. Submitted obfuscated URL to TryDetectThis
4. Cross-referenced URL hash with Alert 2 (same malicious link)
5. Assessed grammatical and domain legitimacy

**Analysis**
**Phishing Indicators Identified:**
- ❌ **Spoofed sender domain**: "urgents@amazon.biz" (legitimate Amazon emails use @amazon.com)
- ❌ **Grammatical error**: "urgents" is not a valid English word (likely "urgent")
- ❌ **URL obfuscation**: Bit.ly shortener hides true destination
- ❌ **Malicious destination**: TryDetectThis classified URL as malicious
- ❌ **Social engineering**: Urgency tactic ("undeliverable package") to prompt immediate action

**Verdict**: 🚨 **True Positive – Phishing Campaign**  
**Action**: Marked email for quarantine; escalated to L2 for user notification and email purge  
**Recommendation**: 
- Block sender domain "amazon.biz" organization-wide
- Add URL hash to threat intelligence feed
- Notify user of phishing attempt; provide security awareness training
- Scan endpoint win-3457 for compromise indicators

**Security Impact**
- Prevented credential theft or malware installation
- Identified campaign targeting HR department (Alert 2 & 3 correlation)
- Detection rule successfully flagged malicious link before user interaction

---

### Alert 8817: Spoofed Microsoft Support Domain – True Positive

**Alert Details**
- **Time**: 18:33
- **Severity**: High
- **User**: Charlotte Allen
- **Device**: win-3463
- **From**: no-reply@m1crosoftsupport.co
- **Subject**: Unusual Activity Detected on Microsoft Account
- **Link**: https://m1crosoftsupport.co/login

**Investigation Steps**
1. Analyzed sender domain for typosquatting
2. Compared domain to legitimate Microsoft support domains
3. Submitted URL to TryDetectThis for threat classification
4. Reviewed email content for credential harvesting indicators
5. Assessed spoofing techniques and social engineering tactics

**Analysis**
**Phishing Indicators Identified:**
- ❌ **Domain typosquatting**: "m1crosoftsupport.co" (numeral "1" replacing letter "i")
- ❌ **Invalid TLD**: Legitimate Microsoft support uses ".microsoft.com" or ".live.com"
- ❌ **Malicious URL**: TryDetectThis flagged domain as credential harvesting site
- ❌ **Social engineering**: Fear tactic ("unusual activity") to create urgency
- ❌ **Credential request**: Link directs to fake login page designed to steal credentials

**Verdict**: 🚨 **True Positive – Credential Harvesting Campaign**  
**Action**: Quarantined email; escalated to L2 for user notification and domain blocking  
**Recommendation**:
- Block domain "m1crosoftsupport.co" at DNS and web proxy
- Notify Charlotte Allen of phishing attempt
- Require password reset if user clicked link
- Add domain to threat intelligence feeds for rapid response

**Security Impact**
- Prevented potential account compromise
- Detection prevented credential theft and potential account takeover
- Identified sophisticated typosquatting technique for awareness training

---

## Summary & Key Takeaways

### Incident Statistics
| Alert ID | Alert Rule | Classification | Severity | Time to Resolve | Status |
|----------|-----------|---------------|----------|-----------------|--------|
| 8814 | Suspicious External Link | False Positive | Medium | 15.1 min | ✅ Correct |
| 8816 | Blacklisted External URL | True Positive | High | 27.17 min | ✅ Correct |
| 8815 | Suspicious External Link | True Positive | Medium | 22.78 min | ✅ Correct |
| 8817 | Suspicious External Link | True Positive | Medium | 9.92 min | ✅ Correct |

**Overall Accuracy**: 100% (4/4 alerts correctly classified)  
**True Positive Detection Rate**: 100% (3/3 malicious threats identified)  
**False Positive Recognition Rate**: 100% (1/1 benign alert correctly dismissed)

### SOC Skills Demonstrated
✅ **Alert Triage**: Prioritized and investigated 4 alerts efficiently  
✅ **Threat Analysis**: Distinguished legitimate traffic from malicious activity  
✅ **Tool Proficiency**: Utilized SIEM (Splunk) and threat intelligence (TryDetectThis)  
✅ **Playbook Adherence**: Followed standardized investigation procedures  
✅ **Incident Documentation**: Maintained detailed records for escalation  
✅ **Threat Intelligence**: Cross-referenced IOCs across multiple alerts  
✅ **Escalation Judgment**: Correctly identified L2 escalation criteria

### Threat Patterns Identified
- **Campaign Correlation**: Alerts 8816 & 8815 shared identical malicious URL, indicating coordinated phishing campaign targeting HR department
- **Attack Techniques**: URL obfuscation (bit.ly), domain spoofing (typosquatting), social engineering (urgency/fear tactics)
- **Attack Chain Prevention**: Firewall and email filtering successfully blocked threats before user interaction

### Security Recommendations
1. **User Education**: Conduct targeted phishing awareness training for HR department (2 targeted attempts)
2. **Detection Tuning**: Whitelist legitimate hrconnext.thm domain to reduce false positives
3. **Threat Intelligence**: Add identified IOCs (domains, IPs, URL hashes) to organizational blocklists
4. **Endpoint Validation**: Scan win-3457 and win-3463 for compromise indicators
5. **Policy Enhancement**: Implement URL shortener blocking to prevent obfuscation techniques

---

## Lessons Learned
- **Context is critical**: False positives can be minimized by understanding business workflows (Alert 8814 onboarding process)
- **Tool validation**: Always verify threat intelligence findings with multiple sources
- **Correlation analysis**: Cross-referencing alerts reveals campaign patterns and threat actor TTPs
- **Defense in depth works**: Layered controls (firewall + email filtering) prevented successful compromise
- **Documentation matters**: Detailed notes enable L2 analysts to take swift action
- **Areas for improvement** (per AI feedback):
  - Enhance "Where" analysis: Specify exact system locations and network segments impacted
  - Deepen "Why" analysis: Elaborate on attacker motivations and potential business impacts
  - Provide more context on threat landscape and attack trends

---

## Tools & Techniques

### Analysis Tools
- **TryDetectThis**: URL and IP reputation analysis
- **Splunk**: Log correlation and host activity review
- **Email Headers**: Sender validation and SPF/DKIM verification

### MITRE ATT&CK Mapping
- **T1566.002** - Phishing: Spearphishing Link
- **T1204.001** - User Execution: Malicious Link
- **T1598.003** - Phishing for Information: Spearphishing Link
- **T1583.001** - Acquire Infrastructure: Domains (typosquatting)

### Detection Methods
- Email content analysis (sender validation, grammatical anomalies)
- URL reputation and threat intelligence
- Domain typosquatting identification
- Firewall blacklist enforcement
- SIEM correlation and pattern matching

---

*This case study demonstrates practical SOC analyst capabilities in a simulated enterprise environment, including alert triage, threat classification, tool utilization, and incident response decision-making.*
