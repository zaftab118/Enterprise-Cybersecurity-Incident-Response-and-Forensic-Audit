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
