# CVE Analysis - 2017

## 📊 Overview

2017 was marked by some of the most widespread and damaging cyberattacks in history, including WannaCry and NotPetya ransomware, as well as the Equifax breach.

## 🔴 Critical Vulnerabilities (9.0 - 10.0)

| CVE ID | CVSS Score | Software/Service | Description | Tags |
|--------|------------|------------------|-------------|------|
| [CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144) | 8.1 | Windows SMBv1 | EternalBlue - WannaCry | `Windows`, `SMB`, `Ransomware`, `RCE` |
| [CVE-2017-5638](https://nvd.nist.gov/vuln/detail/CVE-2017-5638) | 10.0 | Apache Struts 2 | RCE via Content-Type | `Java`, `Web Framework`, `Equifax Breach` |
| [CVE-2017-0199](https://nvd.nist.gov/vuln/detail/CVE-2017-0199) | 7.8 | Microsoft Office | HTA Handler RCE | `Microsoft`, `Office`, `RCE` |
| [CVE-2017-11882](https://nvd.nist.gov/vuln/detail/CVE-2017-11882) | 7.8 | Microsoft Office | Memory Corruption | `Microsoft`, `Office`, `Equation Editor` |
| [CVE-2017-10271](https://nvd.nist.gov/vuln/detail/CVE-2017-10271) | 7.5 | Oracle WebLogic | Deserialization RCE | `Oracle`, `WebLogic`, `Java` |

## 🟠 High Severity (7.0 - 8.9)

| CVE ID | CVSS Score | Software/Service | Description | Tags |
|--------|------------|------------------|-------------|------|
| [CVE-2017-0143](https://nvd.nist.gov/vuln/detail/CVE-2017-0143) | 8.1 | Windows SMBv1 | EternalBlue Variant | `Windows`, `SMB`, `RCE` |
| [CVE-2017-8464](https://nvd.nist.gov/vuln/detail/CVE-2017-8464) | 7.8 | Windows LNK | LNK File RCE | `Windows`, `USB`, `RCE` |
| [CVE-2017-7494](https://nvd.nist.gov/vuln/detail/CVE-2017-7494) | 10.0 | Samba | SambaCry RCE | `Linux`, `Samba`, `RCE` |
| [CVE-2017-0145](https://nvd.nist.gov/vuln/detail/CVE-2017-0145) | 8.1 | Windows SMBv1 | EternalBlue Chain | `Windows`, `SMB`, `RCE` |

## 🟡 Medium Severity (4.0 - 6.9)

| CVE ID | CVSS Score | Software/Service | Description | Tags |
|--------|------------|------------------|-------------|------|
| [CVE-2017-3066](https://nvd.nist.gov/vuln/detail/CVE-2017-3066) | 9.8 | Adobe ColdFusion | Java Deserialization | `Adobe`, `ColdFusion`, `RCE` |

## 🔍 Notable CVE Deep Dive

### CVE-2017-0144: EternalBlue / WannaCry (CRITICAL)

**CVSS Score**: 8.1  
**Affected Software**: Windows SMBv1 (Windows XP to Windows 10, Server 2003 to 2016)  
**Attack Vector**: Network  
**Impact**: Global Ransomware Pandemic

#### Description
EternalBlue is an exploit developed by the NSA and leaked by the Shadow Brokers group. It exploits a vulnerability in Microsoft's SMBv1 protocol, allowing remote code execution. WannaCry ransomware weaponized this exploit to create one of the most devastating cyberattacks in history.

#### WannaCry Attack Timeline

```mermaid
timeline
    title WannaCry Global Outbreak 2017
    2017-04-14 : Shadow Brokers leak EternalBlue
    2017-05-12 : WannaCry outbreak begins
    2017-05-12 : 230,000 computers infected in 150 countries
    2017-05-13 : Kill switch discovered and activated
    2017-05-14 : Variants without kill switch appear
    2017-05-15 : Global recovery efforts begin
```

#### Attack Propagation

```mermaid
graph TD
    A[Initial Infection] -->|EternalBlue Exploit| B[Scan Network for SMBv1]
    B --> C{Port 445 Open?}
    C -->|Yes| D[Send EternalBlue Payload]
    C -->|No| E[Continue Scanning]
    D --> F[Execute DoublePulsar Backdoor]
    F --> G[Download WannaCry Payload]
    G --> H[Encrypt Files]
    G --> I[Propagate to Other Machines]
    H --> J[Display Ransom Note]
    I --> B
    
    style A fill:#ff0000
    style H fill:#ff4444
    style J fill:#ff4444
```

#### Global Impact

```mermaid
pie title "WannaCry Impact by Sector"
    "Healthcare (NHS)" : 30
    "Manufacturing" : 25
    "Government" : 20
    "Education" : 15
    "Other" : 10
```

#### Notable Victims
- **UK National Health Service (NHS)**: 80 hospitals affected, surgeries cancelled
- **Renault**: Production halted at multiple plants
- **FedEx**: Operations disrupted
- **Deutsche Bahn**: Train station displays affected
- **Telefónica**: Spanish telecom giant hit

#### Technical Details

```mermaid
sequenceDiagram
    participant Attacker System
    participant SMBv1 Server
    participant Memory
    
    Attacker System->>SMBv1 Server: Send specially crafted SMB packet
    SMBv1 Server->>Memory: Process packet (buffer overflow)
    Memory->>Memory: Overwrite execution pointer
    SMBv1 Server->>Attacker System: Execute malicious shellcode
    Attacker System->>SMBv1 Server: Install DoublePulsar backdoor
    Attacker System->>SMBv1 Server: Deploy WannaCry ransomware
    
    Note over SMBv1 Server: System Encrypted
```

#### Mitigation
1. **Immediate Actions**:
   - Apply MS17-010 security patch
   - Disable SMBv1: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`
   - Block TCP ports 139 and 445 at firewall
   
2. **Long-term Actions**:
   - Implement network segmentation
   - Regular backup strategy
   - Update legacy systems
   - Security awareness training

#### References
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2017-0144)
- [Microsoft Security Bulletin MS17-010](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- [Malware Tech Kill Switch Analysis](https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html)

---

### CVE-2017-5638: Apache Struts 2 / Equifax Breach

**CVSS Score**: 10.0  
**Affected Software**: Apache Struts 2.3.5 - 2.3.31, 2.5 - 2.5.10  
**Attack Vector**: Network  
**Impact**: One of the Largest Data Breaches in History

#### Description
Remote code execution vulnerability in Apache Struts 2 when using the Jakarta Multipart parser. Attackers can execute arbitrary commands by sending a malicious Content-Type header. This vulnerability was exploited to breach Equifax, exposing personal data of 147 million people.

#### Exploitation Mechanism

```mermaid
sequenceDiagram
    participant Attacker
    participant Struts Application
    participant Server OS
    participant Database
    
    Attacker->>Struts Application: HTTP Request with malicious Content-Type
    Note over Attacker,Struts Application: Content-Type: %{(#cmd='whoami')...}
    Struts Application->>Struts Application: Parse Content-Type as OGNL
    Struts Application->>Server OS: Execute OS command
    Server OS->>Struts Application: Return command output
    Struts Application->>Attacker: Command output in response
    Attacker->>Database: Enumerate and exfiltrate data
    
    Note over Database: 147M records stolen
```

#### Equifax Breach Timeline

```mermaid
gantt
    title Equifax Breach Timeline
    dateFormat YYYY-MM-DD
    
    section Vulnerability
    CVE Published           :2017-03-07, 1d
    Patch Available         :2017-03-07, 1d
    
    section Breach
    Initial Compromise      :2017-05-13, 1d
    Data Exfiltration       :2017-05-13, 76d
    Breach Discovered       :2017-07-29, 1d
    
    section Response
    Public Disclosure       :2017-09-07, 1d
    CEO Resignation         :2017-09-26, 1d
```

#### Data Compromised
- **147.9 million** US consumers
- **15.2 million** UK residents
- **19,000** Canadian residents

**Stolen Information**:
- Social Security Numbers
- Birth dates
- Addresses
- Driver's license numbers
- Credit card numbers (209,000 consumers)

#### Attack Flow

```mermaid
graph LR
    A[Public Struts Vulnerability] -->|Delayed Patching| B[Equifax Vulnerable]
    B --> C[Initial Reconnaissance]
    C --> D[Exploit CVE-2017-5638]
    D --> E[Web Shell Installation]
    E --> F[Network Mapping]
    F --> G[Database Access]
    G --> H[76 Days of Exfiltration]
    H --> I[147M Records Stolen]
    
    style A fill:#ff8800
    style B fill:#ff4444
    style I fill:#ff0000
```

#### Consequences
- **$575 million** settlement with FTC
- **$1.4 billion** total breach cost
- CEO and CSO resignations
- Congressional hearings
- Major reputational damage

#### Mitigation
- Update to Struts 2.3.32 or 2.5.10.1 or later
- Implement WAF rules to block malicious Content-Type headers
- Regular vulnerability scanning
- Prompt patch management
- Network segmentation

#### References
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)
- [Apache Struts Advisory S2-045](https://cwiki.apache.org/confluence/display/WW/S2-045)
- [Equifax Congressional Report](https://www.hsgac.senate.gov/wp-content/uploads/imo/media/doc/HSGAC_Finance_Report_FINAL.pdf)

---

### CVE-2017-7494: SambaCry

**CVSS Score**: 10.0  
**Affected Software**: Samba 3.5.0 - 4.6.4/4.5.10/4.4.14  
**Attack Vector**: Network  
**Impact**: Remote Code Execution on Linux/Unix Systems

#### Description
Critical remote code execution vulnerability in Samba allowing attackers to upload a shared library to a writable share and execute arbitrary code on the server. Dubbed "SambaCry" due to similarities with WannaCry's propagation potential.

#### Vulnerability Mechanism

```mermaid
graph TD
    A[Attacker] -->|1. Connect to Writable Share| B[Samba Server]
    B -->|2. Upload Malicious .so File| C[Shared Directory]
    C -->|3. Trigger Module Load| D[Samba Process]
    D -->|4. Execute Malicious Code| E[System Compromise]
    E --> F[Install Backdoor]
    E --> G[Lateral Movement]
    E --> H[Data Exfiltration]
    
    style A fill:#ff4444
    style E fill:#ff0000
```

#### Affected Systems
- Linux file servers
- NAS devices
- Routers and embedded systems
- IoT devices running Samba

#### Impact Comparison

```mermaid
graph LR
    A[EternalBlue/WannaCry] -->|Inspired| B[Similar Concern]
    C[SambaCry] -->|Potential For| B
    B --> D[Worm-like Propagation]
    B --> E[Massive Infection]
    B --> F[Critical Infrastructure]
    
    Note1[Windows SMB] -.-> A
    Note2[Linux/Unix Samba] -.-> C
```

#### Mitigation
- Update Samba to versions 4.6.4, 4.5.10, or 4.4.14
- Disable loading of external libraries with: `nt pipe support = no`
- Implement firewall rules to restrict SMB access
- Use SELinux or AppArmor policies
- Regular security audits

#### References
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2017-7494)
- [Samba Security Announcement](https://www.samba.org/samba/security/CVE-2017-7494.html)
- [Rapid7 Analysis](https://www.rapid7.com/blog/post/2017/05/24/r7-2017-10-samba-remote-code-execution-vulnerability-cve-2017-7494/)

---

## 📈 2017 Vulnerability Trends

```mermaid
mindmap
  root((2017 Cyber Landscape))
    Ransomware Pandemic
      WannaCry
      NotPetya
      Bad Rabbit
    Mega Breaches
      Equifax
      Uber
      Yahoo
    State Sponsored
      Shadow Brokers Leaks
      APT Groups Active
    IoT Vulnerabilities
      Mirai Botnet
      Home Routers
```

```mermaid
pie title "2017 Attack Types Distribution"
    "Ransomware" : 35
    "Data Breach" : 30
    "RCE Exploits" : 20
    "DDoS" : 10
    "Other" : 5
```

## 🏷️ Technology Tags Summary

- **Windows**: 25+ CVEs (EternalBlue variants)
- **Java**: 15+ CVEs (Struts, WebLogic)
- **Linux/Unix**: 10 CVEs (Samba, etc.)
- **Microsoft Office**: 12 CVEs
- **Network Protocols**: 8 CVEs

## 💡 Lessons Learned from 2017

1. **Patch Management is Critical**: Equifax breach happened months after patch availability
2. **Legacy Systems are Dangerous**: WannaCry affected unsupported Windows XP systems
3. **Supply Chain Security**: NSA exploit leak showed government tool risks
4. **Worm Capabilities**: Modern malware can spread globally in hours
5. **Data Protection**: Even major corporations struggle with security basics

## 📚 Additional Resources

- [WannaCry Technical Analysis](https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html)
- [Equifax Breach Investigation Report](https://www.hsgac.senate.gov/equifax-breach)
- [Shadow Brokers Timeline](https://en.wikipedia.org/wiki/The_Shadow_Brokers)
- [NVD 2017 Database](https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&pub_start_date=01/01/2017&pub_end_date=12/31/2017)

---

**Note**: 2017 marked a turning point in cybersecurity awareness, with WannaCry and Equifax demonstrating the real-world impact of unpatched vulnerabilities.
