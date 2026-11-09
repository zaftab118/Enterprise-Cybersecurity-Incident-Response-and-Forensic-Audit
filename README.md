# Enterprise-Cybersecurity-Incident-Response-and-Forensic-Audit

Enterprise incident response, root cause investigation, and systems hardening on a legacy Linux host. Documents forensic preservation, root bindshell eradication, attack surface reduction, and automated post-remediation auditing via custom Bash scripting. 

[![Incident Status](https://img.shields.io/badge/Status-Remediated%20%26%20Hardened-brightgreen.svg)]()
[![Classification](https://img.shields.io/badge/Classification-Internal%20Security%20Audit-blue.svg)]()
[![Target OS](https://img.shields.io/badge/Target%20OS-Ubuntu%20Linux-orange.svg)]()
[![Frameworks](https://img.shields.io/badge/Frameworks-NIST%20IR%20%7C%20MITRE%20ATT%26CK%20%7C%20CWE-informational.svg)]()

> **Target Infrastructure:** `192.168.128.2` (Legacy Production Ubuntu Server)  
> **Lead Security Analyst:** Zohaib Aftab  
> **Documentation:** [Full Technical Incident Report (PDF)](./Enterprise%20Security%20Audit%20Report.pdf)

---

## Executive Summary

In November 2026, network monitoring telemetry identified anomalous, unauthorized outbound traffic originating from an isolated production server (`192.168.128.2`). An end-to-end incident response engagement was initiated to investigate host posture, contain active vectors, eradicate unauthorized backdoors, eliminate exposed attack surfaces, and implement an automated post-remediation audit framework.

### Root-Cause Finding
Triage confirmed an active, unauthenticated root backdoor listening on **TCP Port 1524 (`ingreslock`)**. Rather than running as a detached rogue binary, the backdoor was weaponized directly through the Internet Super-Server (`openbsd-inetd`) configuration (`/bin/bash -i`), granting immediate, interactive `UID 0` (root) shell access upon connection without authentication credentials.

### Outcome & Business Impact
* **Containment:** Executed surgical host-based firewall containment via UFW, terminating attack traffic without taking core web and business services offline.
* **Eradication:** Backdoor directive permanently de-registered from `/etc/inetd.conf`, active sockets terminated, and zero-persistence verified across reboots.
* **Hardening:** Decommissioned obsolete cleartext Telnet (Port 23) and backdoored UnrealIRCd (Port 6667, CVE-2010-2075).
* **Automated Audit:** Deployed a custom Bash health-check script validating 100% exploit port closure and continuous operational uptime for production services (SSH Port 22, HTTP Port 80).

---

## Investigation Timeline

| Timestamp (EST) | IR Phase | Technical Action | Impact |
| :--- | :--- | :--- | :--- |
| **2026-11-04 13:07** | **1. Environment Isolation** | Configured isolated Host-Only hypervisor networking (UTM); verified layer-3 reachability. | Zero external packet leakage; target online at `192.168.128.2` (0% packet loss). |
| **2026-11-04 13:22** | **1. Service Discovery** | Full TCP SYN service scan (`nmap -sS -sV -O -v`). | Identified 20+ listening services including Telnet (23), Bindshell (1524), and UnrealIRCd (6667). |
| **2026-11-04 14:37** | **2. Vulnerability Audit** | Automated NSE vulnerability assessment (`nmap --script vuln`). | Flagged SQL Injection vectors and obsolete daemon exposures. |
| **2026-11-05 10:33** | **2. Threat Profiling** | Correlated service banners to MITRE CWE taxonomies with AI CTI profiling. | Classified Port 1524 listener as **CVSS 10.0 (Critical)** under **CWE-78** and **CWE-284**. |
| **2026-11-06 10:17** | **3. Evidence Preservation** | Dumped active sockets and preserved volatile log directories to `/tmp/evidence/`. | Maintained forensic chain of custody for `auth_logs`, `daemon_logs`, `apache2_logs`, and `samba_logs`. |
| **2026-11-06 16:50** | **3. Host Containment** | Enforced packet-level firewall drop via `sudo ufw deny 1524`. | Active backdoor connection severed; traffic dropped at kernel boundary without rebooting host. |
| **2026-11-06 17:02** | **3. Containment Check** | External validation via Netcat (`nc -vn -w 5`) and Nmap (`nmap -p 1524 -Pn`). | Netcat timed out; Nmap confirmed port state transitioned to `filtered`. |
| **2026-11-06 17:27** | **4. Eradication & Hardening** | De-registered `ingreslock` directive in `/etc/inetd.conf` and reloaded super-server daemon. | Sockets unbound (`netstat -tlpn`); localhost port verified `closed`; persistence eliminated post-reboot. |
| **2026-11-06 17:44** | **4. Attack Surface Reduction** | Purged unencrypted Telnet (`inetd.conf`) and unlinked UnrealIRCd init runlevels. | Attack surface minimized to essential business needs; Ports 23 and 6667 verified `closed`. |
| **2026-11-06 18:42** | **5. Automated Audit** | Executed remote `health_check.sh` verification from Kali workstation. | Post-remediation audit passed: all exploit ports closed, production services operational. |

---

## Vulnerability Matrix

| Service | Port / Protocol | Classification / CVE | CVSS v3 | Threat Assessment & Action Taken |
| :--- | :--- | :--- | :---: | :--- |
| **Root Bindshell** | `1524/tcp` | CWE-78 / CWE-284 | **10.0** | Unauthenticated interactive root shell listener spawned by `inetd`. **Action:** UFW packet containment, configuration purge, socket termination. |
| **UnrealIRCd** | `6667/tcp` | CVE-2010-2075 | **9.8** | Backdoored chat daemon allowing unauthenticated remote code execution. **Action:** Revoked execution permissions, unlinked init runlevels. |
| **Telnet** | `23/tcp` | CWE-319 | **7.5** | Cleartext administrative protocol vulnerable to packet sniffing and credential capture. **Action:** Decommissioned in favor of SSH (Port 22). |
| **Java RMI Registry** | `1099/tcp` | CVE-2011-3556 | **9.8** | Arbitrary codebase loading and remote class execution. **Action:** Identified and documented for runtime parameter patching. |
| **Apache Tomcat** | `8180/tcp` | CVE-2014-3566 | **3.4** | SSL 3.0 POODLE vulnerability vulnerable to cryptographic downgrade attacks. **Action:** Recommended TLS 1.2+ connector transition. |

---

## Automated Health Check Script (`health_check.sh`)

To eliminate manual auditing steps and guarantee that eradicated services do not reappear after system maintenance or reboots, an automated verification script was developed and deployed on the management workstation.

```bash
#!/usr/bin/env bash
# ==============================================================================
# Enterprise Security Audit & System Health Check Script
# Author: Zohaib Aftab
# Date: 2026-11-06
# Target Host: 192.168.128.2 (Legacy Ubuntu Server)
# Description: Automated remote health validation post-incident remediation.
#              Audits eradication of backdoor (TCP 1524), confirms attack
#              surface reduction (TCP 23, TCP 6667), and validates business uptime.
# ==============================================================================

TARGET_IP="192.168.128.2"
TIMEOUT_SEC=3
local status=$?

# ANSI Color Codes for Executive Output Formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BLUE}${BOLD}================================================================${NC}"
echo -e "${BLUE}${BOLD}      HOST INTEGRITY & INCIDENT REMEDIATION HEALTH CHECK        ${NC}"
echo -e "${BLUE}${BOLD}================================================================${NC}"
echo -e "Target Host    : ${YELLOW}${TARGET_IP}${NC}"
echo -e "Audit Date     : $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
echo -e "Operator       : Zohaib Aftab (Analyst)"
echo -e "${BLUE}----------------------------------------------------------------${NC}"

# 1. Host Reachability Pre-check (ICMP Echo)
echo -ne "Testing Network Connectivity (ICMP Echo)... "
if ping -c 2 -W 2 "${TARGET_IP}" > /dev/null 2>&1; then
    echo -e "${GREEN}${BOLD}[REACHABLE]${NC}"
else
    echo -e "${RED}${BOLD}[UNREACHABLE]${NC} - Host offline or blocking ICMP."
    exit 1
fi

echo -e "\n${BOLD}[SECTION 1: EXPLOIT & ATTACK SURFACE AUDIT]${NC}"

# Function to audit decommissioned/backdoor ports (PASS = CLOSED)
check_closed_port() {
    local port="$1"
    local service="$2"
    
    nc -z -v -w "${TIMEOUT_SEC}" "${TARGET_IP}" "${port}" > /dev/null 2>&1
    local status=$?

    if [ ${status} -ne 0 ]; then
        echo -e "  * Port ${port} (${service}) : ${GREEN}${BOLD}[SECURE - CLOSED]${NC}"
    else
        echo -e "  * Port ${port} (${service}) : ${RED}${BOLD}[ALERT - PORT LISTENING!]${NC}"
    fi
}

# Audit primary vulnerability and hardened ports
check_closed_port 1524 "Root Bindshell Backdoor"
check_closed_port 23   "Unencrypted Telnet Protocol"
check_closed_port 6667 "UnrealIRCd Chat Daemon"

echo -e "\n${BOLD}[SECTION 2: APPROVED PRODUCTION BUSINESS SERVICES]${NC}"

# Function to audit authorized business services (PASS = OPERATIONAL)
check_open_port() {
    local port="$1"
    local service="$2"
    
    nc -z -v -w "${TIMEOUT_SEC}" "${TARGET_IP}" "${port}" > /dev/null 2>&1
    local status=$?

    if [ ${status} -eq 0 ]; then
        echo -e "  * Port ${port} (${service}) : ${GREEN}${BOLD}[ONLINE - OPERATIONAL]${NC}"
    else
        echo -e "  * Port ${port} (${service}) : ${YELLOW}${BOLD}[DEGRADED / INACTIVE]${NC}"
    fi
}

# Audit verified business services
check_open_port 22  "OpenSSH Management"
check_open_port 80  "Apache HTTP Server"

echo -e "${BLUE}----------------------------------------------------------------${NC}"
echo -e "${GREEN}${BOLD}[AUDIT COMPLETE] System posture matches baseline remediation goals.${NC}\n"
```

--- 

## Execution Output

```bash
================================================================
       HOST INTEGRITY & INCIDENT REMEDIATION HEALTH CHECK       
================================================================
Target Host : 192.168.128.2
Audit Date  : 2026-11-06 23:41:36 UTC
Operator    : Zohaib Aftab (Analyst)
----------------------------------------------------------------
Testing Network Connectivity (ICMP Echo)... [REACHABLE]

[SECTION 1: EXPLOIT & ATTACK SURFACE AUDIT]
  * Port 1524 (Root Bindshell Backdoor) : [SECURE - CLOSED]
  * Port 23 (Unencrypted Telnet Protocol) : [SECURE - CLOSED]
  * Port 6667 (UnrealIRCd Chat Daemon)   : [SECURE - CLOSED]

[SECTION 2: APPROVED PRODUCTION BUSINESS SERVICES]
  * Port 22 (OpenSSH Management)         : [ONLINE - OPERATIONAL]
  * Port 80 (Apache HTTP Server)         : [ONLINE - OPERATIONAL]
----------------------------------------------------------------
[AUDIT COMPLETE] System posture matches baseline remediation goals.
```

---

## Lessons Learned

### Operational Challenge
The most significant troubleshooting challenge encountered during the remediation phase was isolating and permanently eradicating the `ingreslock` backdoor on TCP port 1524. Initial attempts focused on standard process termination using `kill` commands; however, the listener persistently reappeared upon system reboot. Root-cause analysis revealed that the backdoor was not a standalone binary process, but rather an active socket registered within the host’s internet super-server (`openbsd-inetd`). Simply killing the spawned shell process left the parent daemon listening on the socket. True eradication required editing `/etc/inetd.conf` to comment out the `ingreslock` directive, restarting the inetd daemon, and verifying socket closure via post-reboot persistence testing. 

### Key Technical Takeaway
A vital takeaway from the engagement was learning how to independently cross-reference disparate technical resources when resolving unfamiliar system behaviors. When initial eradication attempts stalled, diagnosing the underlying mechanisms required correlating information across CVE databases, technical forums (such as Reddit and administrative communities), official Linux documentation, and targeted OSINT searches. In modern incident response, an analyst cannot rely on siloed tools or memorized runbooks alone; bridging the gap between automated scan anomalies and true system remediation demands an investigative mindset that synthesizes technical documentation, community intelligence, and authoritative vulnerability registries to track an exploit to its actual root cause. 

### AI Utilization
Leveraging an AI Virtual Analyst significantly accelerated threat intelligence profiling, rapidly correlating port banners to MITRE CWE taxonomies (CWE-78, CWE-284), and drafting base automation logic for the health check script. However, the simulation reinforced the critical necessity of the “Trust but Verify” mandate: manual validation against authoritative NVD repositories and live terminal execution was essential to eliminate non-applicable CVE suggestions, resolve syntax discrepancies in legacy environments, and ensure remediation commands directly addressed the actual state and configuration of the system. 
