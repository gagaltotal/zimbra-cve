#!/bin/bash
###############################################################################
# zimbra-comprehensive-forensic-audit.sh
# ============================================================================
# COMPREHENSIVE FORENSIC AUDIT & INCIDENT REPORT FOR COMPROMISED ZIMBRA
# Version: 2.1 (2025/2026 CVE update)
# ============================================================================
# Features:
#   1. Entry Vector Analysis (Web Shell, RCE, Auth Bypass, CVE Match)
#   2. Full Malware Detection & Analysis
#   3. CVE Identification based on Zimbra Version (up to 2026)
#   4. Timeline Reconstruction
#   5. Lateral Movement Detection
#   6. Data Exfiltration Detection
#   7. Persistence Mechanism Analysis
#   8. HTML Incident Report Generation
#
# Usage:
#   chmod 700 zimbra-comprehensive-forensic-audit.sh
#   sudo ./zimbra-comprehensive-forensic-audit.sh
#
# Output:
#   /root/zimbra-incident/forensic-TIMESTAMP/
#     ├── console.log          - Full audit output
#     ├── timeline.html        - Visual timeline
#     ├── incident-report.html - Full HTML report
#     ├── ioc-summary.txt      - All IOCs found
#     ├── malware-samples/     - Copied malware (if any)
#     └── [various evidence files]
#
# KNOWN IOC FROM CURRENT INCIDENT:
#   IPs: 89.44.32.243, 15.235.234.220, 13.52.56.206,
#        165.154.205.34, 23.27.25.11, 105.158.146.8
#   Files: /tmp/443, /tmp/443.icikiwirwakwaw, /tmp/c37fedb9ws, /var/tmp/1
#   Processes: javab, rguard, idle
#   Ports: 16001, 9443
###############################################################################

set -uo pipefail
umask 077

###############################################################################
# CONFIGURATION
###############################################################################
declare -A KNOWN_C2_IPS=(
    ["89.44.32.243"]="Primary C2 - Active connection observed"
    ["15.235.234.220"]="C2 - AWS instance"
    ["13.52.56.206"]="C2 - AWS us-west-2"
    ["165.154.205.34"]="C2 - Potential relay"
    ["23.27.25.11"]="C2 - Unknown provider"
    ["105.158.146.8"]="C2 - Indonesia ISP"
)

declare -a KNOWN_MALWARE_FILES=(
    "/tmp/443"
    "/tmp/443.icikiwirwakwaw"
    "/tmp/c37fedb9ws"
    "/var/tmp/1"
    "/dev/shm/javab"
    "/dev/shm/.rguard"
    "/dev/shm/idle"
    "/dev/shm/.javab"
    "/dev/shm/.idle"
)

declare -a KNOWN_MALWARE_PROCS=(
    "javab"
    "rguard"
    "idle"
)

declare -a MALWARE_NETWORK_PORTS=(
    "16001"
    "9443"
    "6666"
    "6667"
    "1337"
    "4444"
    "5555"
    "7777"
    "8888"
    "9999"
)

###############################################################################
# ZIMBRA CVE DATABASE — Updated through 2026
# Sources: Zimbra Security Advisories, NVD, CISA KEV, Rapid7, Beazley, HKCERT
###############################################################################
declare -A ZIMBRA_CVES=(
    # ── LEGENDARY / CHAIN CVEs (often used together in campaigns) ──
    ["CVE-2022-27924"]="ZCS 8.8.15 & 9.0 — Memcached command injection (cleartext cred exfil)"
    ["CVE-2022-27925"]="ZCS 8.8.15 & 9.0 — Path Traversal RCE via mboximport"
    ["CVE-2022-41352"]="ZCS 8.8.15 & 9.0 — Amavis/cpio RCE (pax workaround)"
    ["CVE-2023-37580"]="ZCS 8.8.15 & 9.0 — XXE in Sync service"
    ["CVE-2024-22661"]="ZCS 8.8.15 — LDAP injection leading to auth bypass"
    ["CVE-2024-32476"]="ZCS 8.8.15 — Cross-site scripting to RCE chain"
    ["CVE-2024-37865"]="ZCS — Unauthenticated RCE via sendshare"
    ["CVE-2024-45774"]="ZCS — LDAP injection in SSO"
    ["CVE-2024-45775"]="ZCS — Auth bypass via Autodiscover"
    ["CVE-2024-45776"]="ZCS — Path traversal leading to RCE"
    ["CVE-2024-45519"]="ZCS — Unauth command exec via postjournal service"
    ["CVE-2023-40110"]="ZCS — SSRF via Proxy servlet"
    ["CVE-2022-42252"]="ZCS — Stored XSS to account takeover"
    ["CVE-2021-35209"]="ZCS — Proxy servlet path traversal"
    ["CVE-2021-32458"]="ZCS — SSRF in Resource servlet"
    ["CVE-2020-29227"]="ZCS — LDAP injection in Auth"
    ["CVE-2019-9670"]="ZCS 8.7.x — XXE in GetLDAPEntries"
    ["CVE-2019-9621"]="ZCS — SSRF via Admin servlet"

    # ── 2025 CVEs ──
    ["CVE-2025-25065"]="ZCS 9.0 — SSRF in RSS feed parser; redirect to internal endpoints"
    ["CVE-2025-27915"]="ZCS 9.0/10.0/10.1 — Stored XSS via ICS in Classic Web Client (zero-day used against Brazil military)"
    ["CVE-2025-48700"]="ZCS — Classic UI stored XSS (session hijack / filter abuse)"
    ["CVE-2025-66376"]="ZCS 10 <10.0.18 & <10.1.13 — Stored XSS via CSS @import in HTML mail"
    ["CVE-2025-68645"]="ZCS 10.0/10.1 — Unauth LFI via /h/rest RestFilter (CISA KEV, active exploitation, PoC public)"

    # ── 2026 CVEs ──
    ["CVE-2026-33368"]="ZCS 10.0/10.1 — Reflected XSS in /h/rest (Classic Webmail REST)"
    ["CVE-2026-33370"]="ZCS 10.x — Stored XSS in Briefcase feature (attachment sanitization)"
    ["CVE-2026-33371"]="ZCS 10.0/10.1 — XXE in EWS SOAP (authed, local file read)"
    ["CVE-2026-49975"]="ZCS — DoS via malicious HTTP requests (fixed 10.1.18)"
    ["CVE-2026-73570"]="ZCS <10.1.20 — Unauth RCE via zimbra-snmp + SNMP notifications (ACTIVELY EXPLOITED Aug 2026)"
    ["CVE-2026-73571"]="ZCS <10.1.17 — Authorization bypass in delegated send (mail impersonation)"
    ["CVE-2026-73574"]="ZCS <10.1.17 — LFI in Classic Web Client (parameter fu, Forward servlet)"
)

###############################################################################
# INITIALIZATION
###############################################################################
HOST="$(hostname -f 2>/dev/null || hostname)"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="/root/zimbra-incident/forensic-${STAMP}"
MALWARE_DIR="$OUT/malware-samples"
mkdir -p "$OUT" "$MALWARE_DIR"

# Color codes for console output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters for summary
FINDINGS_CRITICAL=0
FINDINGS_HIGH=0
FINDINGS_MEDIUM=0
FINDINGS_LOW=0
MALWARE_FOUND=0
C2_CONNECTIONS=0
ENTRY_VECTORS=""

# Arrays to store findings for report
declare -a CRITICAL_FINDINGS
declare -a HIGH_FINDINGS
declare -a MEDIUM_FINDINGS
declare -a ENTRY_VECTOR_EVIDENCE
declare -a MALWARE_EVIDENCE
declare -a C2_EVIDENCE
declare -a TIMELINE_EVENTS
declare -a CVE_HITS

###############################################################################
# HELPER FUNCTIONS
###############################################################################

log() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"

    case "$level" in
        CRITICAL)
            echo -e "${RED}[CRITICAL]${NC} $msg"
            ((FINDINGS_CRITICAL++))
            CRITICAL_FINDINGS+=("$ts|$msg")
            ;;
        HIGH)
            echo -e "${RED}[HIGH]${NC} $msg"
            ((FINDINGS_HIGH++))
            HIGH_FINDINGS+=("$ts|$msg")
            ;;
        MEDIUM)
            echo -e "${YELLOW}[MEDIUM]${NC} $msg"
            ((FINDINGS_MEDIUM++))
            MEDIUM_FINDINGS+=("$ts|$msg")
            ;;
        LOW)
            echo -e "${BLUE}[LOW]${NC} $msg"
            ((FINDINGS_LOW++))
            ;;
        INFO)
            echo -e "${GREEN}[INFO]${NC} $msg"
            ;;
        SECTION)
            echo
            echo "============================================================"
            echo -e "${GREEN}>>> $msg${NC}"
            echo "============================================================"
            ;;
    esac
}

run_cmd() {
    local desc="$1"
    shift
    echo
    echo "### $desc"
    "$@" 2>&1 || true
}

add_timeline() {
    local timestamp="$1"
    local event_type="$2"
    local description="$3"
    local severity="${4:-INFO}"
    TIMELINE_EVENTS+=("$timestamp|$event_type|$description|$severity")
}

add_entry_vector() {
    local vector="$1"
    local evidence="$2"
    local confidence="${3:-MEDIUM}"
    ENTRY_VECTOR_EVIDENCE+=("$vector|$evidence|$confidence")
}

add_malware() {
    local path="$1"
    local type="$2"
    local details="$3"
    MALWARE_EVIDENCE+=("$path|$type|$details")
    ((MALWARE_FOUND++))
}

add_c2() {
    local ip="$1"
    local port="$2"
    local pid="$3"
    local protocol="${4:-TCP}"
    C2_EVIDENCE+=("$ip|$port|$pid|$protocol")
    ((C2_CONNECTIONS++))
}

add_cve_hit() {
    local cve="$1"
    local detail="$2"
    CVE_HITS+=("$cve|$detail")
}

###############################################################################
# PHASE 1: SYSTEM INFORMATION COLLECTION
###############################################################################

collect_system_info() {
    log SECTION "PHASE 1: SYSTEM INFORMATION COLLECTION"

    {
        echo "=== HOST INFORMATION ==="
        echo "Hostname: $HOST"
        echo "Date: $(date)"
        echo "Uptime: $(uptime)"
        echo ""
        echo "=== OS INFORMATION ==="
        cat /etc/centos-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || cat /etc/os-release 2>/dev/null
        echo ""
        echo "=== KERNEL ==="
        uname -a
        echo ""
        echo "=== HARDWARE ==="
        lscpu 2>/dev/null | head -20
        echo ""
        free -h
        echo ""
        echo "=== SELINUX ==="
        getenforce 2>/dev/null || echo "SELinux not detected"
        echo ""
        echo "=== CURRENT USER ==="
        id
        whoami
    } > "$OUT/system-info.txt"

    cat "$OUT/system-info.txt"
}

###############################################################################
# PHASE 2: ZIMBRA VERSION & CVE ANALYSIS (Updated 2025/2026)
###############################################################################

analyze_zimbra_cve() {
    log SECTION "PHASE 2: ZIMBRA VERSION & CVE ANALYSIS (through 2026)"

    local zimbra_version=""
    local zimbra_patch=""

    # Get Zimbra version
    zimbra_version=$(su - zimbra -c 'zmcontrol -v' 2>/dev/null | head -1)

    if [[ -n "$zimbra_version" ]]; then
        echo "Zimbra Version: $zimbra_version"

        # Extract version numbers for CVE matching
        local major minor patch
        if [[ "$zimbra_version" =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
            major="${BASH_REMATCH[1]}"
            minor="${BASH_REMATCH[2]}"
            patch="${BASH_REMATCH[3]}"
            echo "Version components: Major=$major, Minor=$minor, Patch=$patch"
        fi

        # Check patch level
        zimbra_patch=$(su - zimbra -c 'zmcontrol -v' 2>/dev/null | grep -oP 'p\d+' | tail -1)
        echo "Patch level: ${zimbra_patch:-Unknown}"
    else
        log HIGH "Could not determine Zimbra version"
        zimbra_version="UNKNOWN"
    fi

    echo "$zimbra_version" > "$OUT/zimbra-version.txt"

    # ── Version-based risk summary for 2025/2026 CVEs ──
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${CYAN}  2025 / 2026 CVE — RISK SUMMARY FOR THIS VERSION${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    case "$zimbra_version" in
        10.0.0*)
            echo -e "${RED}[HIGH RISK]${NC} 10.0.x likely affected by:"
            echo "  • CVE-2025-27915   — Stored XSS via ICS (zero-day used against Brazil military)"
            echo "  • CVE-2025-66376   — Stored XSS via CSS @import"
            echo "  • CVE-2025-68645   — Unauth LFI via /h/rest (CISA KEV, active exploitation)"
            echo "  • CVE-2026-33368   — Reflected XSS in /h/rest"
            echo "  • CVE-2026-33370   — Stored XSS in Briefcase"
            echo "  • CVE-2026-33371   — XXE in EWS SOAP"
            echo "  • CVE-2026-73574   — LFI via Forward servlet (fu parameter)"
            echo "  • CVE-2026-73570   — Unauth RCE via zimbra-snmp (if installed + notifications enabled)"
            echo -e "${YELLOW}[FIX]${NC} Upgrade to at least 10.1.20+."
            ;;
        10.1.0*|10.1.1[0-6]*)
            echo -e "${RED}[HIGH RISK]${NC} 10.1.x < 10.1.17 likely affected by:"
            echo "  • CVE-2025-27915   — Stored XSS via ICS"
            echo "  • CVE-2025-68645   — Unauth LFI via /h/rest (CISA KEV, active exploitation)"
            echo "  • CVE-2026-33368   — Reflected XSS in /h/rest"
            echo "  • CVE-2026-33370   — Stored XSS in Briefcase"
            echo "  • CVE-2026-33371   — XXE in EWS SOAP"
            echo "  • CVE-2026-73574   — LFI via Forward servlet (fu parameter)"
            echo ""
            echo -e "${RED}[CRITICAL RISK]${NC} If zimbra-snmp installed + SNMP notifications enabled:"
            echo "  • CVE-2026-73570   — Unauth RCE (ACTIVELY EXPLOITED Aug 2026, 274+ servers compromised)"
            echo -e "${YELLOW}[FIX]${NC} Upgrade to 10.1.20+ immediately. If upgrade not possible, disable SNMP notifications NOW."
            ;;
        10.1.1[7-9]*|10.1.20)
            echo -e "${YELLOW}[MEDIUM RISK]${NC} 10.1.17–10.1.20 partially patched:"
            echo "  • CVE-2026-73570   — Fixed in 10.1.20 (verify zimbra-snmp patch)"
            echo "  • CVE-2026-73571   — Fixed in 10.1.17"
            echo "  • CVE-2026-73574   — Fixed in 10.1.17"
            echo "  • CVE-2025-68645   — Verify patch level includes fix"
            echo -e "${YELLOW}[ACTION]${NC} Verify you are on latest patch within 10.1.20 stream."
            ;;
        9.0.0*)
            echo -e "${RED}[CRITICAL RISK]${NC} 9.0.x is OUT OF SUPPORT and affected by:"
            echo "  • CVE-2025-25065   — SSRF in RSS feed parser"
            echo "  • CVE-2025-27915   — Stored XSS via ICS (zero-day)"
            echo "  • CVE-2022-27924   — Memcached cred exfil"
            echo "  • CVE-2022-27925   — mboximport RCE"
            echo "  • CVE-2022-41352   — Amavis/cpio RCE"
            echo "  • CVE-2023-37580   — XXE in Sync"
            echo "  • CVE-2024-37865   — sendshare RCE"
            echo "  • All 2025/2026 CVEs that affect 10.x likely also affect 9.0"
            echo -e "${RED}[FIX]${NC} UPGRADE TO 10.1.20+ IMMEDIATELY. 9.x receives no security patches."
            ;;
        8.8.15*)
            echo -e "${RED}[CRITICAL RISK]${NC} 8.8.15 is END-OF-LIFE and heavily targeted:"
            echo "  • CVE-2022-27924   — Memcached cred exfil (very commonly exploited)"
            echo "  • CVE-2022-27925   — mboximport RCE"
            echo "  • CVE-2022-41352   — Amavis/cpio RCE"
            echo "  • CVE-2023-37580   — XXE in Sync"
            echo "  • CVE-2024-22661   — LDAP injection auth bypass"
            echo "  • CVE-2024-37865   — sendshare RCE"
            echo "  • CVE-2024-45519   — postjournal unauth RCE"
            echo "  • Plus all newer CVEs may also apply"
            echo -e "${RED}[FIX]${NC} UPGRADE TO 10.1.20+ IMMEDIATELY. This version is a primary target."
            ;;
        *)
            echo -e "${YELLOW}[UNKNOWN]${NC} Could not map version to CVE risk. Manual review required."
            ;;
    esac

    echo ""
    echo "═══════════════════════════════════════════════════════════════"

    # ── Full CVE table ──
    echo ""
    echo "=== FULL CVE VULNERABILITY TABLE ==="
    echo ""

    {
        echo "# CVE VULNERABILITY ANALYSIS (through 2026)"
        echo "# Zimbra Version: $zimbra_version"
        echo "# Analysis Date: $(date)"
        echo ""

        for cve in "${!ZIMBRA_CVES[@]}"; do
            local description="${ZIMBRA_CVES[$cve]}"
            local status="REVIEW REQUIRED"
            local severity="CRITICAL"

            # Version-based assessment
            case "$cve" in
                CVE-2022-27924|CVE-2022-27925|CVE-2022-41352)
                    if [[ "$zimbra_version" =~ 8\.8\.15 ]]; then
                        status="VERY LIKELY VULNERABLE — EOL version, primary target"
                    elif [[ "$zimbra_version" =~ 9\.0 ]]; then
                        status="LIKELY VULNERABLE unless patched"
                    fi
                    ;;
                CVE-2023-37580)
                    if [[ "$zimbra_version" =~ 8\.8\.15|9\.0 ]]; then
                        status="LIKELY VULNERABLE"
                    fi
                    ;;
                CVE-2024-37865|CVE-2024-45519)
                    if [[ "$zimbra_version" =~ 8\.8\.15|9\.0|10\.0 ]]; then
                        status="LIKELY VULNERABLE"
                    fi
                    ;;
                CVE-2025-25065)
                    if [[ "$zimbra_version" =~ 9\.0 ]]; then
                        status="LIKELY VULNERABLE — SSRF in RSS parser"
                    fi
                    severity="HIGH"
                    ;;
                CVE-2025-27915)
                    if [[ "$zimbra_version" =~ 9\.0|10\.0|10\.1 ]]; then
                        status="LIKELY VULNERABLE — Zero-day used against Brazil military"
                    fi
                    severity="HIGH"
                    ;;
                CVE-2025-48700)
                    severity="MEDIUM"
                    ;;
                CVE-2025-66376)
                    if [[ "$zimbra_version" =~ 10\.0\.[0-9]|10\.0\.1[0-7]|10\.1\.[0-9]|10\.1\.1[0-2] ]]; then
                        status="LIKELY VULNERABLE — CSS @import XSS"
                    fi
                    severity="MEDIUM"
                    ;;
                CVE-2025-68645)
                    if [[ "$zimbra_version" =~ 10\.0|10\.1 ]]; then
                        status="VERY LIKELY VULNERABLE — CISA KEV, active exploitation, PoC public"
                    fi
                    severity="CRITICAL"
                    ;;
                CVE-2026-33368|CVE-2026-33370)
                    if [[ "$zimbra_version" =~ 10\.0|10\.1 ]]; then
                        status="LIKELY VULNERABLE"
                    fi
                    severity="MEDIUM"
                    ;;
                CVE-2026-33371)
                    if [[ "$zimbra_version" =~ 10\.0|10\.1 ]]; then
                        status="LIKELY VULNERABLE — XXE in EWS (authenticated)"
                    fi
                    severity="HIGH"
                    ;;
                CVE-2026-49975)
                    severity="MEDIUM"
                    status="DoS — check if patched in 10.1.18+"
                    ;;
                CVE-2026-73570)
                    if rpm -q zimbra-snmp >/dev/null 2>&1; then
                        if [[ "$zimbra_version" =~ 10\.1\.[0-9]|10\.1\.1[0-9]|10\.0 ]]; then
                            status="VERY LIKELY VULNERABLE — zimbra-snmp installed, ACTIVELY EXPLOITED"
                        elif [[ "$zimbra_version" =~ 10\.1\.20 ]]; then
                            status="Fixed if on 10.1.20 — verify SNMP patch applied"
                        fi
                    else
                        status="NOT VULNERABLE — zimbra-snmp not installed"
                        severity="LOW"
                    fi
                    ;;
                CVE-2026-73571)
                    if [[ "$zimbra_version" =~ 10\.0|10\.1\.0|10\.1\.1[0-6] ]]; then
                        status="LIKELY VULNERABLE — delegated send bypass"
                    elif [[ "$zimbra_version" =~ 10\.1\.1[7-9]|10\.1\.20 ]]; then
                        status="Fixed in 10.1.17+"
                        severity="LOW"
                    fi
                    severity="HIGH"
                    ;;
                CVE-2026-73574)
                    if [[ "$zimbra_version" =~ 10\.0|10\.1\.0|10\.1\.1[0-6] ]]; then
                        status="LIKELY VULNERABLE — LFI via fu parameter"
                    elif [[ "$zimbra_version" =~ 10\.1\.1[7-9]|10\.1\.20 ]]; then
                        status="Fixed in 10.1.17+"
                        severity="LOW"
                    fi
                    severity="HIGH"
                    ;;
            esac

            echo "[$severity] $cve"
            echo "  Description: $description"
            echo "  Status: $status"
            echo ""
        done
    } | tee "$OUT/cve-analysis.txt"

    # ── LOG-BASED INDICATORS PER CVE ──
    echo ""
    echo "=== LOG INDICATORS FOR SPECIFIC CVEs ==="
    echo ""

    # CVE-2022-27925 indicator — mboximport requests
    local mboximport_count
    mboximport_count=$(grep -r "mboximport" /var/log/zimbra.log /opt/zimbra/log/*.log 2>/dev/null | wc -l)
    if [[ $mboximport_count -gt 0 ]]; then
        log HIGH "CVE-2022-27925 indicator: Found $mboximport_count mboximport requests"
        grep -r "mboximport" /var/log/zimbra.log /opt/zimbra/log/*.log 2>/dev/null | tail -50 > "$OUT/cve-2022-27925-indicators.txt"
        add_entry_vector "CVE-2022-27925 (mboximport RCE)" "Found $mboximport_count mboximport requests in logs" "HIGH"
        add_cve_hit "CVE-2022-27925" "$mboximport_count mboximport requests in logs"
    fi

    # CVE-2023-37580 indicator — XXE in Sync
    local sync_suspicious
    sync_suspicious=$(grep -rE "Sync.*DOCTYPE|Sync.*ENTITY|Sync.*SYSTEM" /var/log/zimbra.log /opt/zimbra/log/*.log 2>/dev/null | wc -l)
    if [[ $sync_suspicious -gt 0 ]]; then
        log CRITICAL "CVE-2023-37580 indicator: XXE patterns found in Sync requests!"
        grep -rE "Sync.*DOCTYPE|Sync.*ENTITY|Sync.*SYSTEM" /var/log/zimbra.log /opt/zimbra/log/*.log 2>/dev/null > "$OUT/cve-2023-37580-indicators.txt"
        add_entry_vector "CVE-2023-37580 (XXE in Sync)" "XXE patterns detected in Sync service logs" "HIGH"
        add_cve_hit "CVE-2023-37580" "XXE patterns in Sync logs"
    fi

    # CVE-2024-37865 indicator — sendshare exploitation
    local sendshare_count
    sendshare_count=$(grep -rE "sendshare" /var/log/zimbra.log /opt/zimbra/log/*.log 2>/dev/null | wc -l)
    if [[ $sendshare_count -gt 0 ]]; then
        log HIGH "CVE-2024-37865 indicator: Found $sendshare_count sendshare requests"
        grep -rE "sendshare" /var/log/zimbra.log /opt/zimbra/log/*.log 2>/dev/null | tail -50 > "$OUT/cve-2024-37865-indicators.txt"
        add_entry_vector "CVE-2024-37865 (sendshare RCE)" "Found $sendshare_count sendshare requests" "HIGH"
        add_cve_hit "CVE-2024-37865" "$sendshare_count sendshare requests"
    fi

    # CVE-2025-27915 indicator — ICS with embedded JS (ontoggle / <details>)
    local ics_xss_count
    ics_xss_count=$(grep -rniE 'text/calendar.*ontoggle|\.ics.*<details|BEGIN:VCALENDAR.*<details|\.ics.*javascript:|\.ics.*<script' \
        /var/log/maillog* /opt/zimbra/log/* 2>/dev/null | wc -l)
    if [[ $ics_xss_count -gt 0 ]]; then
        log HIGH "CVE-2025-27915 indicator: Suspicious ICS content with JS patterns ($ics_xss_count hits)"
        grep -rniE 'text/calendar.*ontoggle|\.ics.*<details|BEGIN:VCALENDAR.*<details|\.ics.*javascript:|\.ics.*<script' \
            /var/log/maillog* /opt/zimbra/log/* 2>/dev/null | tail -100 > "$OUT/cve-2025-27915-indicators.txt"
        add_entry_vector "CVE-2025-27915 (ICS XSS zero-day)" "ICS files with embedded JS patterns in mail logs" "HIGH"
        add_cve_hit "CVE-2025-27915" "$ics_xss_count ICS XSS indicators in mail logs"
    fi

    # CVE-2025-68645 indicator — LFI via /h/rest with fu= parameter
    local lfi_rest_count
    lfi_rest_count=$(grep -rniE '/h/rest.*fu=|/h/rest.*\.\.\/|/h/rest.*WEB-INF|/h/rest.*etc/passwd|/h/rest.*etc/shadow' \
        /var/log/nginx/* /opt/zimbra/log/access_log* /var/log/zimbra.log 2>/dev/null | wc -l)
    if [[ $lfi_rest_count -gt 0 ]]; then
        log CRITICAL "CVE-2025-68645 indicator: /h/rest with fu= parameter detected ($lfi_rest_count hits) — CISA KEV, ACTIVE EXPLOITATION"
        grep -rniE '/h/rest.*fu=|/h/rest.*\.\.\/|/h/rest.*WEB-INF|/h/rest.*etc/passwd|/h/rest.*etc/shadow' \
            /var/log/nginx/* /opt/zimbra/log/access_log* /var/log/zimbra.log 2>/dev/null | tail -200 > "$OUT/cve-2025-68645-indicators.txt"
        add_entry_vector "CVE-2025-68645 (LFI /h/rest)" "CISA KEV — fu= parameter probes found ($lfi_rest_count hits)" "CRITICAL"
        add_cve_hit "CVE-2025-68645" "$lfi_rest_count LFI probes via /h/rest fu= parameter"
    fi

    # CVE-2026-73574 indicator — Forward servlet with fu= parameter
    local forward_lfi_count
    forward_lfi_count=$(grep -rniE 'Forward.*fu=|/service/.*fu=' \
        /var/log/nginx/* /opt/zimbra/log/access_log* 2>/dev/null | wc -l)
    if [[ $forward_lfi_count -gt 0 ]]; then
        log MEDIUM "CVE-2026-73574 indicator: Forward servlet with fu= parameter ($forward_lfi_count hits)"
        grep -rniE 'Forward.*fu=|/service/.*fu=' \
            /var/log/nginx/* /opt/zimbra/log/access_log* 2>/dev/null | tail -100 > "$OUT/cve-2026-73574-indicators.txt"
        add_cve_hit "CVE-2026-73574" "$forward_lfi_count Forward/fu= probes"
    fi

    # CVE-2026-73570 indicator — SNMP package + daemon check
    echo ""
    echo "=== CVE-2026-73570 CHECK (SNMP RCE — ACTIVELY EXPLOITED) ==="
    if rpm -q zimbra-snmp >/dev/null 2>&1; then
        log HIGH "zimbra-snmp package IS INSTALLED. If SNMP notifications are enabled, host is vulnerable to CVE-2026-73570 (unauth RCE)."
        echo "zimbra-snmp: INSTALLED" > "$OUT/cve-2026-73570-check.txt"
        add_cve_hit "CVE-2026-73570" "zimbra-snmp package installed"

        # Check if snmptrapd or snmpd is running
        if ps -ef | grep -qE '[s]nmptrapd|[s]nmpd'; then
            log CRITICAL "SNMP daemon(s) RUNNING — CVE-2026-73570 risk is CRITICAL. Block outbound SNMP (161/162) and upgrade to 10.1.20+ IMMEDIATELY."
            echo "SNMP daemons running:" >> "$OUT/cve-2026-73570-check.txt"
            ps -ef | grep -E '[s]nmptrapd|[s]nmpd' >> "$OUT/cve-2026-73570-check.txt"
            add_entry_vector "CVE-2026-73570 (SNMP RCE)" "zimbra-snmp installed AND SNMP daemons running — ACTIVELY EXPLOITED CVE" "CRITICAL"
        else
            echo "SNMP daemons: NOT RUNNING (lower immediate risk but package still present)" >> "$OUT/cve-2026-73570-check.txt"
        fi

        # Check SNMP notification config
        local snmp_notif
        snmp_notif=$(su - zimbra -c 'zmlocalconfig -s zimbra_snmp_notify | grep -v "^#"' 2>/dev/null)
        if echo "$snmp_notif" | grep -qiE 'true|yes|1'; then
            log CRITICAL "SNMP notifications are ENABLED — CVE-2026-73570 is fully exploitable."
            echo "SNMP notifications: ENABLED" >> "$OUT/cve-2026-73570-check.txt"
            echo "$snmp_notif" >> "$OUT/cve-2026-73570-check.txt"
        else
            echo "SNMP notifications config: $snmp_notif" >> "$OUT/cve-2026-73570-check.txt"
        fi

        # Check for snmptrap traffic to known C2 IPs
        local snmp_c2
        snmp_c2=$(ss -tunap | grep -E ':161 |:162 ' | grep -E "${KNOWN_C2_IPS[*]// /|}")
        if [[ -n "$snmp_c2" ]]; then
            log CRITICAL "SNMP traffic to known C2 IPs detected — ACTIVE CVE-2026-73570 EXPLOITATION!"
            echo "SNMP C2 traffic:" >> "$OUT/cve-2026-73570-check.txt"
            echo "$snmp_c2" >> "$OUT/cve-2026-73570-check.txt"
        fi
    else
        log INFO "zimbra-snmp package NOT installed — CVE-2026-73570 does not apply."
        echo "zimbra-snmp: NOT INSTALLED" > "$OUT/cve-2026-73570-check.txt"
    fi

    # CVE-2026-33371 indicator — EWS SOAP with XXE patterns
    local ews_xxe_count
    ews_xxe_count=$(grep -rniE 'EWS.*DOCTYPE|EWS.*ENTITY|/EWS/.*SYSTEM|/ews/.*<!ENTITY' \
        /var/log/nginx/* /opt/zimbra/log/access_log* /opt/zimbra/log/*.log 2>/dev/null | wc -l)
    if [[ $ews_xxe_count -gt 0 ]]; then
        log HIGH "CVE-2026-33371 indicator: XXE patterns in EWS/SOAP requests ($ews_xxe_count hits)"
        grep -rniE 'EWS.*DOCTYPE|EWS.*ENTITY|/EWS/.*SYSTEM|/ews/.*<!ENTITY' \
            /var/log/nginx/* /opt/zimbra/log/access_log* /opt/zimbra/log/*.log 2>/dev/null | tail -100 > "$OUT/cve-2026-33371-indicators.txt"
        add_cve_hit "CVE-2026-33371" "$ews_xxe_count XXE patterns in EWS requests"
    fi

    # CVE-2025-25065 indicator — SSRF via RSS feed
    local rss_ssrf_count
    rss_ssrf_count=$(grep -rniE 'RSS.*127\.0\.0\.1|RSS.*10\.|RSS.*192\.168\.|RSS.*169\.254\.|RSS.*localhost|/rss/.*internal' \
        /var/log/nginx/* /opt/zimbra/log/access_log* /opt/zimbra/log/*.log 2>/dev/null | wc -l)
    if [[ $rss_ssrf_count -gt 0 ]]; then
        log MEDIUM "CVE-2025-25065 indicator: RSS feed pointing to internal addresses ($rss_ssrf_count hits)"
        grep -rniE 'RSS.*127\.0\.0\.1|RSS.*10\.|RSS.*192\.168\.|RSS.*169\.254\.|RSS.*localhost|/rss/.*internal' \
            /var/log/nginx/* /opt/zimbra/log/access_log* /opt/zimbra/log/*.log 2>/dev/null | tail -50 > "$OUT/cve-2025-25065-indicators.txt"
        add_cve_hit "CVE-2025-25065" "$rss_ssrf_count RSS SSRF indicators"
    fi

    # CVE-2026-49975 indicator — DoS via malformed HTTP
    local dos_request_count
    dos_request_count=$(grep -rniE 'HTTP/.*[0-9]{6,}|abnormally long|request too large|413.*Request Entity' \
        /var/log/nginx/* /opt/zimbra/log/access_log* 2>/dev/null | wc -l)
    if [[ $dos_request_count -gt 100 ]]; then
        log MEDIUM "CVE-2026-49975 indicator: Abnormal HTTP requests ($dos_request_count hits) — possible DoS probe"
        grep -rniE 'HTTP/.*[0-9]{6,}|abnormally long|request too large|413.*Request Entity' \
            /var/log/nginx/* /opt/zimbra/log/access_log* 2>/dev/null | tail -50 > "$OUT/cve-2026-49975-indicators.txt"
        add_cve_hit "CVE-2026-49975" "$dos_request_count abnormal HTTP requests (DoS indicator)"
    fi

    # CVE-2026-73571 indicator — Delegated send abuse
    local delegated_send_count
    delegated_send_count=$(grep -rniE 'delegated.*send|sendAs|X-Zimbra-Delegated|onBehalfOf' \
        /var/log/zimbra.log /opt/zimbra/log/*.log 2>/dev/null | wc -l)
    if [[ $delegated_send_count -gt 0 ]]; then
        log MEDIUM "CVE-2026-73571 indicator: Delegated send activity found ($delegated_send_count hits) — check for impersonation"
        grep -rniE 'delegated.*send|sendAs|X-Zimbra-Delegated|onBehalfOf' \
            /var/log/zimbra.log /opt/zimbra/log/*.log 2>/dev/null | tail -50 > "$OUT/cve-2026-73571-indicators.txt"
        add_cve_hit "CVE-2026-73571" "$delegated_send_count delegated send events"
    fi

    # Summary of CVE hits
    if [[ ${#CVE_HITS[@]} -gt 0 ]]; then
        echo ""
        echo "=== CVE HIT SUMMARY ==="
        printf "  %-20s %s\n" "CVE" "Evidence"
        printf "  %-20s %s\n" "----" "--------"
        for hit in "${CVE_HITS[@]}"; do
            IFS='|' read -r cve detail <<< "$hit"
            printf "  ${RED}%-20s${NC} %s\n" "$cve" "$detail"
        done
    fi

    # Web shell upload indicators
    echo ""
    echo "=== WEB SHELL UPLOAD INDICATORS ==="
    local upload_patterns
    upload_patterns=$(grep -rE "\.jsp.*POST|fileUpload|multipart|boundary=" /var/log/zimbra.log /opt/zimbra/log/access_log* 2>/dev/null | wc -l)
    if [[ $upload_patterns -gt 50 ]]; then
        log MEDIUM "High number of file upload requests: $upload_patterns"
    fi
}

###############################################################################
# PHASE 3: ENTRY VECTOR ANALYSIS
###############################################################################

analyze_entry_vectors() {
    log SECTION "PHASE 3: ENTRY VECTOR ANALYSIS"

    # 3.1 Analyze web access logs for exploitation attempts
    echo ""
    echo "=== WEB ACCESS LOG ANALYSIS ==="

    local access_logs
    access_logs=$(find /opt/zimbra/log /var/log -name "access_log*" -o -name "nginx_access*" -o -name "jetty*.log*" 2>/dev/null | head -20)

    if [[ -n "$access_logs" ]]; then
        echo "Analyzing access logs for exploitation patterns..."

        # Path traversal attempts
        local path_traversal
        path_traversal=$(grep -hE "\.\./|\.\.\\|%2e%2e|%252e" $access_logs 2>/dev/null | head -100)
        if [[ -n "$path_traversal" ]]; then
            echo "$path_traversal" > "$OUT/entry-path-traversal.txt"
            log HIGH "Path traversal attempts detected in access logs"
            add_entry_vector "Path Traversal" "Detected in access logs - see entry-path-traversal.txt" "HIGH"
        fi

        # Command injection attempts
        local cmd_injection
        cmd_injection=$(grep -hE ';|`|\$\(|%7c|%60|%24%28|bash|sh\s|cmd\.exe|powershell' $access_logs 2>/dev/null | head -100)
        if [[ -n "$cmd_injection" ]]; then
            echo "$cmd_injection" > "$OUT/entry-cmd-injection.txt"
            log HIGH "Command injection attempts detected"
            add_entry_vector "Command Injection" "Detected in access logs - see entry-cmd-injection.txt" "HIGH"
        fi

        # JSP/Servlet exploitation
        local jsp_exploit
        jsp_exploit=$(grep -hE '\.jsp.*\?|/service/|/zimbra/|/home/|mboximport|sendshare|ProxyRequest' $access_logs 2>/dev/null | head -200)
        if [[ -n "$jsp_exploit" ]]; then
            echo "$jsp_exploit" > "$OUT/entry-jsp-exploitation.txt"
            log MEDIUM "Suspicious JSP/Servlet access patterns"
        fi

        # Successful exploitation indicators (HTTP 200 on suspicious endpoints)
        local success_exploit
        success_exploit=$(grep -hE 'HTTP/1\.[01]" 200.*(\.jsp|\.jspx|mboximport|sendshare|Proxy)' $access_logs 2>/dev/null | head -100)
        if [[ -n "$success_exploit" ]]; then
            echo "$success_exploit" > "$OUT/entry-successful-exploitation.txt"
            log CRITICAL "POTENTIAL SUCCESSFUL EXPLOITATION - HTTP 200 on suspicious endpoints!"
            add_entry_vector "Successful Exploitation" "HTTP 200 responses on suspicious endpoints" "CRITICAL"
        fi

        # CVE-2025-68645 specific: /h/rest with fu= returning 200
        local lfi_success
        lfi_success=$(grep -hE '/h/rest.*fu=.*" 200' $access_logs 2>/dev/null | head -50)
        if [[ -n "$lfi_success" ]]; then
            echo "$lfi_success" > "$OUT/entry-lfi-success.txt"
            log CRITICAL "CVE-2025-68645: /h/rest fu= returning HTTP 200 — POSSIBLE SUCCESSFUL LFI!"
            add_entry_vector "CVE-2025-68645 LFI Success" "/h/rest fu= returning 200 — data likely exfiltrated" "CRITICAL"
        fi
    fi

    # 3.2 Analyze authentication logs
    echo ""
    echo "=== AUTHENTICATION LOG ANALYSIS ==="

    local failed_auth
    failed_auth=$(grep -E "authentication failed|Invalid credentials|bad password" /var/log/zimbra.log /opt/zimbra/log/*.log 2>/dev/null | tail -500)
    if [[ -n "$failed_auth" ]]; then
        echo "$failed_auth" > "$OUT/auth-failed.txt"
        local failed_count
        failed_count=$(echo "$failed_auth" | wc -l)
        log MEDIUM "Found $failed_count failed authentication attempts"

        echo ""
        echo "Top IPs with failed auth:"
        echo "$failed_auth" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -20
    fi

    # Successful auth from suspicious IPs
    local c2_pattern
    c2_pattern="$(printf '%s|' "${!KNOWN_C2_IPS[@]}")"
    c2_pattern="${c2_pattern%|}"
    local suspicious_success
    suspicious_success=$(grep -E "authentication succeeded" /var/log/zimbra.log /opt/zimbra/log/*.log 2>/dev/null | \
        grep -E "$c2_pattern" | tail -50)
    if [[ -n "$suspicious_success" ]]; then
        echo "$suspicious_success" > "$OUT/auth-suspicious-success.txt"
        log CRITICAL "SUCCESSFUL AUTHENTICATION FROM KNOWN C2 IPs!"
        add_entry_vector "Compromised Credentials" "Auth success from C2 IPs" "CRITICAL"
    fi

    # 3.3 Check for web shells
    echo ""
    echo "=== WEB SHELL DETECTION ==="

    local webshell_patterns='Runtime\.getRuntime|ProcessBuilder|\.exec\(|eval\(|base64_decode|system\(|passthru|shell_exec|popen|proc_open|/bin/sh|/bin/bash|wget|curl.*-o|scriptlet'

    find /opt/zimbra/jetty /opt/zimbra/jetty_base -type f \( -name "*.jsp" -o -name "*.jspx" -o -name "*.js" -o -name "*.class" \) \
        -exec grep -lE "$webshell_patterns" {} \; 2>/dev/null | while read -r file; do
            log CRITICAL "POTENTIAL WEB SHELL: $file"
            echo "=== $file ===" >> "$OUT/webshells-found.txt"
            grep -nE "$webshell_patterns" "$file" >> "$OUT/webshells-found.txt"
            echo "" >> "$OUT/webshells-found.txt"
            add_malware "$file" "Web Shell" "Contains code execution patterns"
            add_entry_vector "Web Shell Upload" "Found web shell at $file" "CRITICAL"
        done

    # 3.4 Check for recently modified web files
    echo ""
    echo "=== RECENTLY MODIFIED WEB FILES (POTENTIAL BACKDOORS) ==="

    find /opt/zimbra/jetty /opt/zimbra/jetty_base -type f \( -name "*.jsp" -o -name "*.jspx" -o -name "*.war" \) \
        -mtime -60 -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort | tee "$OUT/recent-web-files.txt"

    # 3.5 Analyze first access from attacker IPs
    echo ""
    echo "=== FIRST ACCESS FROM ATTACKER IPs ==="

    for ip in "${!KNOWN_C2_IPS[@]}"; do
        local first_seen
        first_seen=$(grep -h "$ip" /var/log/zimbra.log /opt/zimbra/log/*.log /var/log/nginx/*.log 2>/dev/null | head -1)
        if [[ -n "$first_seen" ]]; then
            log HIGH "First access from $ip: $first_seen"
            echo "IP: $ip" >> "$OUT/first-access-attacker-ips.txt"
            echo "Description: ${KNOWN_C2_IPS[$ip]}" >> "$OUT/first-access-attacker-ips.txt"
            echo "First seen: $first_seen" >> "$OUT/first-access-attacker-ips.txt"
            echo "" >> "$OUT/first-access-attacker-ips.txt"
        fi
    done
}

###############################################################################
# PHASE 4: MALWARE ANALYSIS
###############################################################################

analyze_malware() {
    log SECTION "PHASE 4: MALWARE ANALYSIS"

    # 4.1 Check for known malware files
    echo ""
    echo "=== KNOWN MALWARE FILE CHECK ==="

    for malware_path in "${KNOWN_MALWARE_FILES[@]}"; do
        if [[ -e "$malware_path" ]]; then
            log CRITICAL "MALWARE FOUND: $malware_path"

            {
                echo "=== MALWARE: $malware_path ==="
                echo "Type: $(file "$malware_path" 2>/dev/null)"
                echo "Size: $(stat -c%s "$malware_path" 2>/dev/null) bytes"
                echo "Permissions: $(stat -c%a "$malware_path" 2>/dev/null)"
                echo "Owner: $(stat -c%U:%G "$malware_path" 2>/dev/null)"
                echo "Created: $(stat -c%w "$malware_path" 2>/dev/null)"
                echo "Modified: $(stat -c%y "$malware_path" 2>/dev/null)"
                echo "Accessed: $(stat -c%u "$malware_path" 2>/dev/null)"
                echo ""
                echo "SHA256: $(sha256sum "$malware_path" 2>/dev/null)"
                echo "MD5: $(md5sum "$malware_path" 2>/dev/null)"
                echo ""
                echo "Strings (first 100):"
                strings "$malware_path" 2>/dev/null | head -100
                echo ""
                echo "=== END MALWARE ==="
                echo ""
            } >> "$OUT/malware-analysis.txt"

            cp "$malware_path" "$MALWARE_DIR/" 2>/dev/null || true

            add_malware "$malware_path" "Known Malware" "Part of javab/rguard campaign"
        fi
    done

    # 4.2 Analyze running malware processes
    echo ""
    echo "=== MALWARE PROCESS ANALYSIS ==="

    for proc_name in "${KNOWN_MALWARE_PROCS[@]}"; do
        local pids
        pids=$(pgrep -f "(^|/)${proc_name}$" 2>/dev/null)

        if [[ -n "$pids" ]]; then
            log CRITICAL "MALWARE PROCESS RUNNING: $proc_name (PIDs: $pids)"

            for pid in $pids; do
                echo "" >> "$OUT/malware-processes.txt"
                echo "=== PROCESS: $proc_name (PID: $pid) ===" >> "$OUT/malware-processes.txt"

                {
                    echo "Process info:"
                    ps -fp "$pid" 2>/dev/null
                    echo ""
                    echo "Executable: $(readlink -f /proc/$pid/exe 2>/dev/null)"
                    echo "CWD: $(readlink -f /proc/$pid/cwd 2>/dev/null)"
                    echo ""
                    echo "Command line:"
                    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null
                    echo ""
                    echo "Environment:"
                    cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | head -30
                    echo ""
                    echo "File descriptors:"
                    ls -la "/proc/$pid/fd" 2>/dev/null | head -50
                    echo ""
                    echo "Network connections:"
                    ls -la "/proc/$pid/fd" 2>/dev/null | grep socket | while read -r line; do
                        local fd_num
                        fd_num=$(echo "$line" | awk '{print $NF}' | grep -o '[0-9]*')
                        if [[ -n "$fd_num" ]]; then
                            cat "/proc/$pid/fdinfo/$fd_num" 2>/dev/null | grep socket
                            readlink "/proc/$pid/fd/$fd_num" 2>/dev/null
                        fi
                    done
                    echo ""
                    echo "Memory maps:"
                    cat "/proc/$pid/maps" 2>/dev/null | head -30
                } >> "$OUT/malware-processes.txt"

                # Check network connections for this PID
                local conns
                conns=$(ss -tunap | grep "pid=$pid")
                if [[ -n "$conns" ]]; then
                    echo "Network connections for PID $pid:" >> "$OUT/malware-processes.txt"
                    echo "$conns" >> "$OUT/malware-processes.txt"

                    while read -r line; do
                        local remote_ip remote_port
                        remote_ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+' | tail -1 | cut -d: -f1)
                        remote_port=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+' | tail -1 | cut -d: -f2)
                        if [[ -n "$remote_ip" && -n "$remote_port" ]]; then
                            add_c2 "$remote_ip" "$remote_port" "$pid"
                        fi
                    done <<< "$conns"
                fi
            done
        fi
    done

    # 4.3 Find unknown executables in temp directories
    echo ""
    echo "=== EXECUTABLES IN TEMP DIRECTORIES ==="

    find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 -ls 2>/dev/null | tee "$OUT/temp-executables.txt"

    while read -r line; do
        if [[ -n "$line" ]]; then
            local exe_path
            exe_path=$(echo "$line" | awk '{print $NF}')
            local is_known=0
            for known in "${KNOWN_MALWARE_FILES[@]}"; do
                [[ "$exe_path" == "$known" ]] && is_known=1 && break
            done
            if [[ $is_known -eq 0 ]]; then
                log HIGH "Unknown executable in temp: $exe_path"
                add_malware "$exe_path" "Unknown Executable" "Found in temp directory"
            fi
        fi
    done < <(find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 2>/dev/null)

    # 4.4 Check for persistence mechanisms
    echo ""
    echo "=== PERSISTENCE MECHANISM ANALYSIS ==="

    for user in root zimbra; do
        local crontab_content
        crontab_content=$(crontab -u "$user" -l 2>/dev/null)
        if [[ -n "$crontab_content" ]]; then
            if echo "$crontab_content" | grep -qE 'curl|wget|bash|sh -c|/dev/tcp|nc |socat|python|perl|javab|rguard|/tmp/|/var/tmp/|/dev/shm'; then
                log CRITICAL "SUSPICIOUS CRONTAB FOR $user!"
                echo "=== CRONTAB $user ===" >> "$OUT/persistence-crontab.txt"
                echo "$crontab_content" >> "$OUT/persistence-crontab.txt"
                echo "" >> "$OUT/persistence-crontab.txt"
            fi
        fi
    done

    grep -RlnE 'curl|wget|bash|sh -c|/dev/tcp|javab|rguard' /etc/cron* /var/spool/cron 2>/dev/null | while read -r file; do
        log HIGH "Suspicious cron file: $file"
        cat "$file" >> "$OUT/persistence-crontab.txt"
    done

    find /etc/systemd /usr/lib/systemd -type f -name "*.service" -newermt "2024-01-01" 2>/dev/null | while read -r svc; do
        if grep -qE '/tmp/|/var/tmp/|/dev/shm|javab|rguard' "$svc" 2>/dev/null; then
            log CRITICAL "SUSPICIOUS SYSTEMD SERVICE: $svc"
            echo "=== $svc ===" >> "$OUT/persistence-systemd.txt"
            cat "$svc" >> "$OUT/persistence-systemd.txt"
        fi
    done

    if [[ -f /etc/rc.local ]] && grep -qE '/tmp/|/var/tmp/|javab|rguard' /etc/rc.local 2>/dev/null; then
        log CRITICAL "Suspicious content in /etc/rc.local"
        cat /etc/rc.local >> "$OUT/persistence-rclocal.txt"
    fi

    find /root /home /opt/zimbra -name "authorized_keys" -type f 2>/dev/null | while read -r keyfile; do
        local key_count
        key_count=$(wc -l < "$keyfile" 2>/dev/null)
        if [[ $key_count -gt 0 ]]; then
            echo "=== $keyfile ($key_count keys) ===" >> "$OUT/persistence-ssh-keys.txt"
            cat "$keyfile" >> "$OUT/persistence-ssh-keys.txt"
            echo "" >> "$OUT/persistence-ssh-keys.txt"

            if find "$keyfile" -mtime -30 2>/dev/null | grep -q .; then
                log HIGH "Recently modified SSH keys: $keyfile"
            fi
        fi
    done

    # 4.5 Check for rootkits
    echo ""
    echo "=== ROOTKIT INDICATORS ==="

    local proc_count_ps
    proc_count_ps=$(ps -e --no-headers | wc -l)
    local proc_count_proc
    proc_count_proc=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)

    if [[ $proc_count_ps -ne $proc_count_proc ]]; then
        log HIGH "Process count mismatch! PS: $proc_count_ps, /proc: $proc_count_proc — Possible rootkit"
    fi

    for pid in $(ps -eo pid --no-headers); do
        local preload
        preload=$(cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD)
        if [[ -n "$preload" ]]; then
            log CRITICAL "LD_PRELOAD hijacking detected in PID $pid: $preload"
        fi
    done

    if [[ -s /etc/ld.so.preload ]]; then
        log CRITICAL "ld.so.preload is not empty — possible rootkit!"
        cat /etc/ld.so.preload >> "$OUT/rootkit-indicators.txt"
    fi
}

###############################################################################
# PHASE 5: NETWORK & C2 ANALYSIS
###############################################################################

analyze_network_c2() {
    log SECTION "PHASE 5: NETWORK & C2 ANALYSIS"

    echo ""
    echo "=== CURRENT NETWORK CONNECTIONS ==="

    ss -tunap 2>/dev/null | tee "$OUT/network-connections.txt"

    echo ""
    echo "=== ACTIVE C2 CONNECTIONS ==="

    for ip in "${!KNOWN_C2_IPS[@]}"; do
        local conns
        conns=$(ss -tunap | grep "$ip")
        if [[ -n "$conns" ]]; then
            log CRITICAL "ACTIVE CONNECTION TO C2: $ip"
            echo "$conns" >> "$OUT/active-c2-connections.txt"

            local pid port
            pid=$(echo "$conns" | grep -oP 'pid=\K[0-9]+' | head -1)
            port=$(echo "$conns" | grep -oE "$ip:[0-9]+" | head -1 | cut -d: -f2)
            add_c2 "$ip" "$port" "$pid"
        fi
    done

    echo ""
    echo "=== CONNECTIONS ON SUSPICIOUS PORTS ==="

    for port in "${MALWARE_NETWORK_PORTS[@]}"; do
        local conns
        conns=$(ss -tunap | grep ":$port ")
        if [[ -n "$conns" ]]; then
            log HIGH "Connection on suspicious port $port:"
            echo "$conns" >> "$OUT/suspicious-port-connections.txt"
        fi
    done

    # SNMP-specific port check for CVE-2026-73570
    echo ""
    echo "=== SNMP PORT CHECK (CVE-2026-73570) ==="
    local snmp_conns
    snmp_conns=$(ss -tunap | grep -E ':161 |:162 ')
    if [[ -n "$snmp_conns" ]]; then
        echo "SNMP connections found:" | tee -a "$OUT/cve-2026-73570-check.txt"
        echo "$snmp_conns" | tee -a "$OUT/cve-2026-73570-check.txt"
        log HIGH "SNMP connections detected — review for CVE-2026-73570 exploitation"
    fi

    echo ""
    echo "=== OUTBOUND CONNECTIONS FROM MALWARE ==="

    for pid in $(pgrep -f 'javab|rguard|idle' 2>/dev/null); do
        local exe
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        local conns
        conns=$(ss -tunap | grep "pid=$pid")
        if [[ -n "$conns" ]]; then
            echo "PID $pid ($exe):" >> "$OUT/malware-network.txt"
            echo "$conns" >> "$OUT/malware-network.txt"
            echo "" >> "$OUT/malware-network.txt"
        fi
    done

    echo ""
    echo "=== HISTORICAL C2 CONNECTIONS IN LOGS ==="

    for ip in "${!KNOWN_C2_IPS[@]}"; do
        local log_hits
        log_hits=$(grep -rh "$ip" /var/log/zimbra.log /opt/zimbra/log/*.log /var/log/maillog* 2>/dev/null | wc -l)
        if [[ $log_hits -gt 0 ]]; then
            echo "IP $ip: $log_hits log entries" >> "$OUT/historical-c2-logs.txt"
            grep -rh "$ip" /var/log/zimbra.log /opt/zimbra/log/*.log /var/log/maillog* 2>/dev/null | head -100 >> "$OUT/historical-c2-logs.txt"
            echo "" >> "$OUT/historical-c2-logs.txt"
        fi
    done

    echo ""
    echo "=== FIREWALL RULE ANALYSIS ==="

    {
        echo "=== IPTABLES RULES ==="
        iptables -S 2>/dev/null || echo "Could not read iptables"
        echo ""
        echo "=== IPTABLES NAT ==="
        iptables -t nat -S 2>/dev/null || echo "Could not read NAT table"
        echo ""
        echo "=== FIREWALLD STATUS ==="
        firewall-cmd --list-all 2>/dev/null || echo "firewalld not active or not accessible"
    } > "$OUT/firewall-analysis.txt"

    for ip in "${!KNOWN_C2_IPS[@]}"; do
        if iptables -S 2>/dev/null | grep -q "$ip"; then
            log CRITICAL "FIREWALL RULE ALLOWING C2 IP: $ip"
        fi
    done

    if iptables -t nat -S 2>/dev/null | grep -qE "REDIRECT|DNAT"; then
        log HIGH "Port forwarding rules detected — check for C2 redirection"
        iptables -t nat -S 2>/dev/null | grep -E "REDIRECT|DNAT" >> "$OUT/firewall-analysis.txt"
    fi
}

###############################################################################
# PHASE 6: TIMELINE RECONSTRUCTION
###############################################################################

build_timeline() {
    log SECTION "PHASE 6: TIMELINE RECONSTRUCTION"

    local timeline_file="$OUT/timeline-detailed.txt"

    echo "# INCIDENT TIMELINE RECONSTRUCTION" > "$timeline_file"
    echo "# Generated: $(date)" >> "$timeline_file"
    echo "# Host: $HOST" >> "$timeline_file"
    echo "" >> "$timeline_file"

    echo "=== FILE MODIFICATION TIMELINE ===" >> "$timeline_file"

    {
        echo "--- ZIMBRA WEB FILES ---"
        find /opt/zimbra/jetty /opt/zimbra/jetty_base -type f -newermt "2024-07-01" \
            -printf '%TY-%Tm-%Td %TH:%TM:%TS MODIFY %u:%g %m %p\n' 2>/dev/null

        echo "--- TEMP DIRECTORIES ---"
        find /tmp /var/tmp /dev/shm -xdev -type f -newermt "2024-07-01" \
            -printf '%TY-%Tm-%Td %TH:%TM:%TS MODIFY %u:%g %m %p\n' 2>/dev/null

        echo "--- SYSTEM CONFIGURATION ---"
        find /etc/systemd /etc/cron* /etc/ssh -type f -newermt "2024-07-01" \
            -printf '%TY-%Tm-%Td %TH:%TM:%TS MODIFY %u:%g %m %p\n' 2>/dev/null

        echo "--- ZIMBRA CONFIGURATION ---"
        find /opt/zimbra/conf -type f -newermt "2024-07-01" \
            -printf '%TY-%Tm-%Td %TH:%TM:%TS MODIFY %u:%g %m %p\n' 2>/dev/null
    } | sort >> "$timeline_file"

    echo "" >> "$timeline_file"
    echo "=== LOG-BASED TIMELINE (ATTACKER ACTIVITY) ===" >> "$timeline_file"

    {
        for ip in "${!KNOWN_C2_IPS[@]}"; do
            grep -rh "$ip" /var/log/zimbra.log /opt/zimbra/log/*.log /var/log/maillog* 2>/dev/null | \
                while read -r line; do
                    ts=$(echo "$line" | grep -oE '^[A-Z][a-z]{2} [0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
                    if [[ -n "$ts" ]]; then
                        echo "$ts C2_IP $ip: $line"
                    fi
                done
        done

        grep -rhE '(javab|rguard|idle).*start|Starting.*javab' /var/log/messages /var/log/syslog 2>/dev/null | \
            while read -r line; do
                ts=$(echo "$line" | grep -oE '^[A-Z][a-z]{2} [0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
                [[ -n "$ts" ]] && echo "$ts MALWARE_START: $line"
            done

        # CVE-specific timeline events
        grep -rhE '/h/rest.*fu=' /var/log/nginx/* /opt/zimbra/log/access_log* 2>/dev/null | \
            while read -r line; do
                ts=$(echo "$line" | grep -oE '[0-9]{1,2}/[A-Z][a-z]{2}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
                [[ -n "$ts" ]] && echo "$ts CVE-2025-68645_PROBE: $line"
            done

        grep -rhE 'text/calendar.*ontoggle|\.ics.*<details' /var/log/maillog* /opt/zimbra/log/* 2>/dev/null | \
            while read -r line; do
                ts=$(echo "$line" | grep -oE '^[A-Z][a-z]{2} [0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
                [[ -n "$ts" ]] && echo "$ts CVE-2025-27915_ICS_XSS: $line"
            done

        grep -rhE 'EWS.*DOCTYPE|EWS.*ENTITY' /opt/zimbra/log/*.log 2>/dev/null | \
            while read -r line; do
                ts=$(echo "$line" | grep -oE '^[A-Z][a-z]{2} [0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
                [[ -n "$ts" ]] && echo "$ts CVE-2026-33371_EWS_XXE: $line"
            done

    } | sort >> "$timeline_file"

    echo "" >> "$timeline_file"
    echo "=== AUTHENTICATION TIMELINE ===" >> "$timeline_file"

    {
        grep -rhE 'sshd.*(Accepted|Failed|Invalid)' /var/log/secure* 2>/dev/null
        grep -rhE 'authentication (succeeded|failed)' /var/log/zimbra.log /opt/zimbra/log/*.log 2>/dev/null | tail -200
    } | sort >> "$timeline_file"

    echo "" >> "$timeline_file"
    echo "=== PACKAGE INSTALLATION TIMELINE ===" >> "$timeline_file"
    rpm -qa --last | head -50 >> "$timeline_file"

    cat "$timeline_file"
}

###############################################################################
# PHASE 7: DATA EXFILTRATION CHECK
###############################################################################

check_exfiltration() {
    log SECTION "PHASE 7: DATA EXFILTRATION CHECK"

    echo ""
    echo "=== POTENTIAL DATA EXFILTRATION INDICATORS ==="

    find /tmp /var/tmp -name "*.tar*" -o -name "*.zip" -o -name "*.gz" -o -name "*.7z" 2>/dev/null | \
        while read -r archive; do
            local size
            size=$(stat -c%s "$archive" 2>/dev/null)
            if [[ $size -gt 1048576 ]]; then
                log HIGH "Large archive in temp: $archive ($(numfmt --to=iec $size 2>/dev/null || echo $size bytes))"
                echo "$archive - $size bytes" >> "$OUT/exfiltration-archives.txt"
            fi
        done

    grep -rhE '(scp|sftp|rsync).*zimbra|/opt/zimbra.*tar|mailbox.*compress' /var/log/secure* /var/log/messages* 2>/dev/null | \
        tee "$OUT/exfiltration-commands.txt"

    echo ""
    echo "=== SMTP RELAY CHECK ==="

    grep -rhE 'relay=|stat=Sent|queued as' /var/log/maillog* 2>/dev/null | \
        grep -v "localhost\|127.0.0.1" | \
        grep -E "$c2_pattern" 2>/dev/null | \
        tee "$OUT/exfiltration-smtp.txt"

    echo ""
    echo "=== DATABASE DUMP INDICATORS ==="

    find /tmp /var/tmp /root -name "*.sql" -o -name "*.dump" -o -name "*ldap*" -mtime -30 2>/dev/null | \
        while read -r dump; do
            local size
            size=$(stat -c%s "$dump" 2>/dev/null)
            log HIGH "Potential database dump: $dump ($size bytes)"
        done

    # CVE-2025-68645 specific: check if sensitive files were read via LFI
    echo ""
    echo "=== CVE-2025-68645 LFI EXFILTRATION CHECK ==="
    local lfi_exfil
    lfi_exfil=$(grep -rniE '/h/rest.*fu=.*(passwd|shadow|web\.xml|localconfig|zimbra\.key|ldap\.pwd)' \
        /var/log/nginx/* /opt/zimbra/log/access_log* 2>/dev/null)
    if [[ -n "$lfi_exfil" ]]; then
        log CRITICAL "CVE-2025-68645: LFI attempts targeting SENSITIVE FILES detected!"
        echo "$lfi_exfil" > "$OUT/cve-2025-68645-exfiltration-attempts.txt"
    fi

    echo ""
    echo "=== CREDENTIAL HARVEST INDICATORS ==="

    find /tmp /var/tmp -name "*pass*" -o -name "*cred*" -o -name "*auth*" -mtime -30 2>/dev/null | \
        while read -r f; do
            log HIGH "Potential credential file: $f"
            ls -la "$f" >> "$OUT/exfiltration-credentials.txt"
        done
}

###############################################################################
# PHASE 8: LATERAL MOVEMENT CHECK
###############################################################################

check_lateral_movement() {
    log SECTION "PHASE 8: LATERAL MOVEMENT CHECK"

    echo ""
    echo "=== OUTBOUND SSH CONNECTIONS ==="

    ss -tunap | grep ":22 " | grep -v "127.0.0.1\|::1" | tee "$OUT/lateral-ssh.txt"

    for user in root zimbra; do
        local known_hosts="/home/$user/.ssh/known_hosts"
        [[ "$user" == "root" ]] && known_hosts="/root/.ssh/known_hosts"
        if [[ -f "$known_hosts" ]] && find "$known_hosts" -mtime -30 2>/dev/null | grep -q .; then
            log MEDIUM "Recently modified known_hosts for $user"
            cat "$known_hosts" >> "$OUT/lateral-known-hosts.txt"
        fi
    done

    echo ""
    echo "=== NETWORK SCANNING INDICATORS ==="

    for pid in $(ps -eo pid --no-headers); do
        local cmd
        cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        if echo "$cmd" | grep -qE 'nmap|masscan|zmap|netcat.*-z|nc.*-z|fping|ping.*-c.*[0-9]{3,}'; then
            log HIGH "Network scanning tool running: PID $pid - $cmd"
            echo "PID $pid: $cmd" >> "$OUT/lateral-scanning.txt"
        fi
    done

    echo ""
    echo "=== RECONNAISSANCE IN HISTORY ==="

    for user in root zimbra; do
        local history_file="/home/$user/.bash_history"
        [[ "$user" == "root" ]] && history_file="/root/.bash_history"
        if [[ -f "$history_file" ]]; then
            grep -hE 'nmap|ifconfig|ip addr|netstat|ss.*-t|hostname|cat /etc/passwd|cat /etc/shadow|ldapsearch|zmprov.*ga' \
                "$history_file" 2>/dev/null | tail -50 >> "$OUT/lateral-recon.txt"
        fi
    done

    echo ""
    echo "=== POTENTIAL LATERAL TARGETS ==="

    su - zimbra -c 'zmprov gas' 2>/dev/null | head -20 > "$OUT/lateral-zimbra-servers.txt"
    su - zimbra -c 'zmprov gaa' 2>/dev/null | head -50 >> "$OUT/lateral-zimbra-servers.txt"
}

###############################################################################
# PHASE 9: GENERATE INCIDENT REPORT
###############################################################################

generate_report() {
    log SECTION "PHASE 9: GENERATING INCIDENT REPORT"

    local report_file="$OUT/incident-report.html"
    local timeline_html="$OUT/timeline.html"

    local zimbra_version
    zimbra_version=$(cat "$OUT/zimbra-version.txt" 2>/dev/null || echo "Unknown")

    local ip_address
    ip_address=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "Unknown")

    # Build CVE hits table rows
    local cve_table_rows=""
    if [[ ${#CVE_HITS[@]} -gt 0 ]]; then
        for hit in "${CVE_HITS[@]}"; do
            IFS='|' read -r cve detail <<< "$hit"
            local desc="${ZIMBRA_CVES[$cve]:-Unknown}"
            cve_table_rows+="            <tr><td><code>${cve}</code></td><td>${desc}</td><td>${detail}</td></tr>"
        done
    else
        cve_table_rows="            <tr><td colspan=\"3\">No direct log indicators found for tracked CVEs</td></tr>"
    fi

    # Build IOC IP table rows
    local ip_table_rows=""
    for ip in "${!KNOWN_C2_IPS[@]}"; do
        local status="Known C2"
        ss -tunap | grep -q "$ip" && status='<span style="color:red;font-weight:bold">ACTIVE CONNECTION</span>'
        ip_table_rows+="            <tr><td><code>${ip}</code></td><td>${KNOWN_C2_IPS[$ip]}</td><td>${status}</td></tr>"
    done

    # Build malware file table rows
    local malware_table_rows=""
    for malware_path in "${KNOWN_MALWARE_FILES[@]}"; do
        local status="Not Found"
        local file_type="—"
        if [[ -e "$malware_path" ]]; then
            status='<span style="color:red;font-weight:bold">FOUND</span>'
            file_type=$(file "$malware_path" 2>/dev/null | cut -d: -f2- | head -c 80)
        fi
        malware_table_rows+="            <tr><td><code>${malware_path}</code></td><td>${file_type}</td><td>${status}</td></tr>"
    done

    # Build process table rows
    local proc_table_rows=""
    for proc in "${KNOWN_MALWARE_PROCS[@]}"; do
        local pids
        pids=$(pgrep -f "(^|/)${proc}$" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        local status="Not Running"
        [[ -n "$pids" ]] && status='<span style="color:red;font-weight:bold">RUNNING</span>'
        proc_table_rows+="            <tr><td><code>${proc}</code></td><td>${pids:-None}</td><td>${status}</td></tr>"
    done

    # Build C2 connection table rows
    local c2_table_rows=""
    if [[ ${#C2_EVIDENCE[@]} -gt 0 ]]; then
        for c2 in "${C2_EVIDENCE[@]}"; do
            IFS='|' read -r ip port pid proto <<< "$c2"
            c2_table_rows+="            <tr><td><code>${ip}</code></td><td>${port}</td><td>${pid}</td><td>${proto}</td></tr>"
        done
    else
        c2_table_rows="            <tr><td colspan=\"4\">No active C2 connections at scan time (may be intermittent)</td></tr>"
    fi

    # Build entry vector cards
    local entry_vector_cards=""
    if [[ ${#ENTRY_VECTOR_EVIDENCE[@]} -gt 0 ]]; then
        for evidence in "${ENTRY_VECTOR_EVIDENCE[@]}"; do
            IFS='|' read -r vector details confidence <<< "$evidence"
            local class="high"
            [[ "$confidence" == "CRITICAL" ]] && class="critical"
            [[ "$confidence" == "MEDIUM" ]] && class="medium"
            entry_vector_cards+="        <div class=\"${class}\">
            <strong>Entry Vector: ${vector}</strong><br>
            Confidence: ${confidence}<br>
            Evidence: ${details}
        </div>"
        done
    else
        entry_vector_cards="        <div class=\"medium\">No definitive entry vector identified. Review CVE indicators and web logs.</div>"
    fi

    cat > "$report_file" << REPORT_EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zimbra Incident Report — ${HOST}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }
        h2 { color: #1976d2; border-bottom: 1px solid #e0e0e0; padding-bottom: 5px; margin-top: 30px; }
        h3 { color: #388e3c; }
        .critical { background: #ffebee; border-left: 4px solid #d32f2f; padding: 10px 15px; margin: 10px 0; }
        .high { background: #fff3e0; border-left: 4px solid #f57c00; padding: 10px 15px; margin: 10px 0; }
        .medium { background: #fff8e1; border-left: 4px solid #ffa000; padding: 10px 15px; margin: 10px 0; }
        .low { background: #e8f5e9; border-left: 4px solid #388e3c; padding: 10px 15px; margin: 10px 0; }
        .info { background: #e3f2fd; border-left: 4px solid #1976d2; padding: 10px 15px; margin: 10px 0; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; font-size: 0.9em; }
        th { background: #1976d2; color: white; }
        tr:nth-child(even) { background: #f9f9f9; }
        .ioc-table th { background: #d32f2f; }
        .cve-table th { background: #6a1b9a; }
        .timeline { position: relative; padding-left: 30px; }
        .timeline::before { content: ''; position: absolute; left: 10px; top: 0; bottom: 0; width: 2px; background: #1976d2; }
        .timeline-item { position: relative; margin-bottom: 15px; padding-left: 20px; font-family: monospace; font-size: 0.85em; }
        .timeline-item::before { content: ''; position: absolute; left: -24px; top: 5px; width: 10px; height: 10px; border-radius: 50%; background: #1976d2; }
        .timeline-item.critical::before { background: #d32f2f; }
        .timeline-item.high::before { background: #f57c00; }
        code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 0.9em; }
        pre { background: #263238; color: #eeffff; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 0.85em; max-height: 500px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: #f5f5f5; padding: 15px; border-radius: 5px; text-align: center; }
        .summary-card .number { font-size: 2em; font-weight: bold; }
        .summary-card.critical .number { color: #d32f2f; }
        .summary-card.high .number { color: #f57c00; }
        .summary-card.medium .number { color: #ffa000; }
        .summary-card.info .number { color: #1976d2; }
        .toc { background: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .toc a { color: #1976d2; text-decoration: none; }
        .toc a:hover { text-decoration: underline; }
        .toc ul { list-style: none; padding-left: 0; }
        .toc ul ul { padding-left: 20px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold; color: white; }
        .badge-critical { background: #d32f2f; }
        .badge-high { background: #f57c00; }
        .badge-medium { background: #ffa000; }
        @media print { body { background: white; } .container { box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 ZIMBRA EMAIL SERVER — INCIDENT REPORT</h1>

        <div class="summary-grid">
            <div class="summary-card critical"><div class="number">${FINDINGS_CRITICAL}</div><div>Critical</div></div>
            <div class="summary-card high"><div class="number">${FINDINGS_HIGH}</div><div>High</div></div>
            <div class="summary-card medium"><div class="number">${FINDINGS_MEDIUM}</div><div>Medium</div></div>
            <div class="summary-card info"><div class="number">${MALWARE_FOUND}</div><div>Malware</div></div>
            <div class="summary-card critical"><div class="number">${C2_CONNECTIONS}</div><div>C2 Conns</div></div>
            <div class="summary-card high"><div class="number">${#ENTRY_VECTOR_EVIDENCE[@]}</div><div>Entry Vectors</div></div>
            <div class="summary-card info"><div class="number">${#CVE_HITS[@]}</div><div>CVE Hits</div></div>
        </div>

        <table>
            <tr><th>Host</th><td>${HOST}</td><th>IP</th><td>${ip_address}</td></tr>
            <tr><th>Zimbra</th><td>${zimbra_version}</td><th>Generated</th><td>$(date)</td></tr>
            <tr><th>Evidence</th><td colspan="3"><code>${OUT}</code></td></tr>
        </table>

        <div class="toc">
            <strong>Table of Contents</strong>
            <ul>
                <li><a href="#exec">1. Executive Summary</a></li>
                <li><a href="#ioc">2. Indicators of Compromise</a></li>
                <li><a href="#entry">3. Entry Vector Analysis</a></li>
                <li><a href="#cve">4. CVE Vulnerability Analysis (through 2026)</a></li>
                <li><a href="#malware">5. Malware Analysis</a></li>
                <li><a href="#c2">6. Command &amp; Control</a></li>
                <li><a href="#timeline">7. Attack Timeline</a></li>
                <li><a href="#lateral">8. Lateral Movement</a></li>
                <li><a href="#exfil">9. Data Exfiltration</a></li>
                <li><a href="#recs">10. Recommendations</a></li>
            </ul>
        </div>

        <h2 id="exec">1. Executive Summary</h2>
        <div class="critical">
            <strong>INCIDENT CLASSIFICATION: ACTIVE COMPROMISE</strong><br>
            This Zimbra email server has been compromised with malware (javab/rguard) establishing
            persistent command and control (C2) communications. The attacker has achieved:
            <ul>
                <li>Remote code execution capability</li>
                <li>Persistent backdoor access</li>
                <li>Active C2 communication channel</li>
            </ul>
            ${#CVE_HITS[@]} CVE indicator(s) detected in logs. ${#ENTRY_VECTOR_EVIDENCE[@]} potential entry vector(s) identified.
        </div>

        <h2 id="ioc">2. Indicators of Compromise</h2>
        <h3>2.1 Malicious IP Addresses</h3>
        <table class="ioc-table">
            <tr><th>IP Address</th><th>Description</th><th>Status</th></tr>
            ${ip_table_rows}
        </table>

        <h3>2.2 Malware Files</h3>
        <table class="ioc-table">
            <tr><th>File Path</th><th>Type</th><th>Status</th></tr>
            ${malware_table_rows}
        </table>

        <h3>2.3 Malicious Processes</h3>
        <table class="ioc-table">
            <tr><th>Process</th><th>PIDs</th><th>Status</th></tr>
            ${proc_table_rows}
        </table>

        <h2 id="entry">3. Entry Vector Analysis</h2>
        ${entry_vector_cards}

        <h2 id="cve">4. CVE Vulnerability Analysis (through 2026)</h2>
        <div class="info">
            <strong>Full CVE table:</strong> See <code>cve-analysis.txt</code> in evidence directory.<br>
            Below are CVEs with <em>direct log indicators</em> found on this host:
        </div>
        <table class="cve-table">
            <tr><th>CVE</th><th>Description</th><th>Evidence on This Host</th></tr>
            ${cve_table_rows}
        </table>

        <h3>SNMP RCE Check (CVE-2026-73570)</h3>
        <pre>$(cat "$OUT/cve-2026-73570-check.txt" 2>/dev/null || echo "Check file not found")</pre>

        <h2 id="malware">5. Malware Analysis</h2>
        <pre>$(cat "$OUT/malware-analysis.txt" 2>/dev/null | head -200)</pre>
        <pre>$(cat "$OUT/malware-processes.txt" 2>/dev/null | head -200)</pre>

        <h2 id="c2">6. Command &amp; Control</h2>
        <table class="ioc-table">
            <tr><th>C2 IP</th><th>Port</th><th>PID</th><th>Protocol</th></tr>
            ${c2_table_rows}
        </table>

        <h2 id="timeline">7. Attack Timeline</h2>
        <div class="timeline">
REPORT_EOF

    # Add timeline events
    local line_num=0
    if [[ -f "$OUT/timeline-detailed.txt" ]]; then
        while IFS= read -r line; do
            [[ $line_num -gt 80 ]] && break
            [[ "$line" =~ ^# ]] && continue
            [[ -z "$line" ]] && continue
            local class="timeline-item"
            [[ "$line" =~ CRITICAL|MALWARE|EXPLOITATION|EXFIL ]] && class="timeline-item critical"
            [[ "$line" =~ C2_IP|AUTH|PROBE|XSS|XXE ]] && class="timeline-item high"
            echo "            <div class=\"${class}\">${line}</div>" >> "$report_file"
            ((line_num++))
        done < "$OUT/timeline-detailed.txt"
    fi

    cat >> "$report_file" << 'TIMELINE_END'
        </div>
        <p><em>Full timeline: <code>timeline-detailed.txt</code></em></p>
TIMELINE_END

    # Lateral movement
    cat >> "$report_file" << 'LATERAL_START'
        <h2 id="lateral">8. Lateral Movement</h2>
LATERAL_START

    if [[ -f "$OUT/lateral-ssh.txt" ]] && [[ -s "$OUT/lateral-ssh.txt" ]]; then
        echo "        <div class=\"high\"><strong>Outbound SSH connections detected:</strong></div>" >> "$report_file"
        echo "        <pre>$(cat "$OUT/lateral-ssh.txt")</pre>" >> "$report_file"
    else
        echo "        <div class=\"info\">No outbound SSH connections detected</div>" >> "$report_file"
    fi

    if [[ -f "$OUT/lateral-zimbra-servers.txt" ]] && [[ -s "$OUT/lateral-zimbra-servers.txt" ]]; then
        echo "        <h3>Other Zimbra Servers in Environment</h3>" >> "$report_file"
        echo "        <pre>$(cat "$OUT/lateral-zimbra-servers.txt" | head -30)</pre>" >> "$report_file"
    fi

    # Exfiltration
    cat >> "$report_file" << 'EXFIL_START'
        <h2 id="exfil">9. Data Exfiltration</h2>
EXFIL_START

    local exfil_found=0
    for file in "$OUT"/exfiltration-*.txt "$OUT"/cve-2025-68645-exfiltration-*.txt; do
        if [[ -f "$file" ]] && [[ -s "$file" ]]; then
            ((exfil_found++))
            echo "        <h4>$(basename "$file")</h4>" >> "$report_file"
            echo "        <pre>$(head -20 "$file")</pre>" >> "$report_file"
        fi
    done

    if [[ $exfil_found -eq 0 ]]; then
        echo "        <div class=\"info\">No direct evidence of data exfiltration found. Note: Exfiltration may have occurred via encrypted C2 channel.</div>" >> "$report_file"
    fi

    # Recommendations
    cat >> "$report_file" << RECS_EOF
        <h2 id="recs">10. Recommendations</h2>

        <h3>10.1 Immediate (Within 24 Hours)</h3>
        <div class="critical">
            <ol>
                <li><strong>ISOLATE SERVER</strong> — Disconnect from network; preserve evidence</li>
                <li><strong>BLOCK C2 IPs</strong> — Add firewall rules at perimeter for all known C2 IPs</li>
                <li><strong>PRESERVE EVIDENCE</strong> — Do NOT reboot or clean until forensic image created</li>
                <li><strong>CHANGE CREDENTIALS</strong> — Reset Zimbra admin, LDAP, and affected user passwords</li>
                <li><strong>DISABLE SNMP</strong> — If zimbra-snmp is installed, disable notifications immediately (CVE-2026-73570)</li>
                <li><strong>NOTIFY STAKEHOLDERS</strong> — Security team, management, affected users</li>
            </ol>
        </div>

        <h3>10.2 Short-Term (Within 1 Week)</h3>
        <div class="high">
            <ol>
                <li><strong>FORENSIC IMAGE</strong> — Full disk image for detailed analysis</li>
                <li><strong>MALWARE ANALYSIS</strong> — Submit samples to VirusTotal / sandbox</li>
                <li><strong>LOG REVIEW</strong> — Comprehensive review for full scope</li>
                <li><strong>REBUILD</strong> — Rebuild Zimbra on clean infrastructure from known-good backup</li>
                <li><strong>SCAN OTHER HOSTS</strong> — Check for lateral movement</li>
            </ol>
        </div>

        <h3>10.3 Long-Term (Within 1 Month)</h3>
        <div class="medium">
            <ol>
                <li><strong>UPGRADE ZIMBRA</strong> — Upgrade to 10.1.20+ (addresses CVE-2026-73570, CVE-2025-68645, CVE-2026-73574, etc.)</li>
                <li><strong>REMOVE zimbra-snmp</strong> — Unless strictly required, uninstall the package</li>
                <li><strong>HARDENING</strong> — Implement Zimbra security hardening guide</li>
                <li><strong>WAF</strong> — Deploy Web Application Firewall (block /h/rest fu=, EWS XXE patterns, ICS with JS)</li>
                <li><strong>MONITORING</strong> — SIEM, IDS/IPS with Zimbra-specific rules</li>
                <li><strong>BACKUP VERIFICATION</strong> — Verify backups are clean</li>
            </ol>
        </div>

        <h3>10.4 Containment Commands (After Evidence Collection)</h3>
        <pre>
# Block C2 IPs
for ip in 89.44.32.243 15.235.234.220 13.52.56.206 165.154.205.34 23.27.25.11 105.158.146.8; do
    iptables -I OUTPUT -d $ip -j DROP
    iptables -I INPUT -s $ip -j DROP
done

# Block SNMP ports (CVE-2026-73570)
iptables -I OUTPUT -p udp --dport 161 -j DROP
iptables -I OUTPUT -p udp --dport 162 -j DROP
iptables -I INPUT -p udp --dport 161 -j DROP
iptables -I INPUT -p udp --dport 162 -j DROP

# Disable SNMP notifications
su - zimbra -c 'zmlocalconfig -e zimbra_snmp_notify=false'
su - zimbra -c 'zmsnmpctl stop'

# Kill malware processes
pkill -9 javab
pkill -9 rguard
pkill -9 idle

# Remove malware files
rm -f /tmp/443 /tmp/443.icikiwirwakwaw /tmp/c37fedb9ws /var/tmp/1
rm -f /dev/shm/javab /dev/shm/.rguard /dev/shm/idle /dev/shm/.javab /dev/shm/.idle
        </pre>

        <hr>
        <p style="text-align:center;color:#666;">
            Report generated by zimbra-comprehensive-forensic-audit.sh v2.1<br>
            $(date) | Evidence: ${OUT}
        </p>
    </div>
</body>
</html>
RECS_EOF

    log INFO "HTML Report generated: $report_file"

    # IOC Summary
    {
        echo "# IOC SUMMARY — ZIMBRA INCIDENT"
        echo "# Host: $HOST"
        echo "# Date: $(date)"
        echo "# Zimbra: $zimbra_version"
        echo ""
        echo "## MALICIOUS IPs"
        for ip in "${!KNOWN_C2_IPS[@]}"; do
            echo "$ip — ${KNOWN_C2_IPS[$ip]}"
        done
        echo ""
        echo "## MALICIOUS FILES"
        for f in "${KNOWN_MALWARE_FILES[@]}"; do
            [[ -e "$f" ]] && echo "$f — $(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
        done
        echo ""
        echo "## MALICIOUS PROCESSES"
        for p in "${KNOWN_MALWARE_PROCS[@]}"; do
            pgrep -f "(^|/)$p$" 2>/dev/null && echo "$p — RUNNING"
        done
        echo ""
        echo "## SUSPICIOUS PORTS"
        echo "16001, 9443, 161, 162"
        echo ""
        echo "## CVE HITS"
        for hit in "${CVE_HITS[@]}"; do
            echo "$hit"
        done
    } > "$OUT/ioc-summary.txt"

    # Threat intel feed (SIEM-ready)
    {
        echo "# THREAT INTEL FEED — $(date)"
        echo "# Host: $HOST"
        echo ""
        echo "[IP_BLOCK]"
        for ip in "${!KNOWN_C2_IPS[@]}"; do
            echo "$ip"
        done
        echo ""
        echo "[FILE_HASH]"
        for f in "${KNOWN_MALWARE_FILES[@]}"; do
            if [[ -e "$f" ]]; then
                sha256sum "$f" 2>/dev/null | awk '{print $1}'
                md5sum "$f" 2>/dev/null | awk '{print $1}'
            fi
        done
        echo ""
        echo "[PROCESS_NAMES]"
        for p in "${KNOWN_MALWARE_PROCS[@]}"; do
            echo "$p"
        done
        echo ""
        echo "[URL_PATTERNS]"
        echo "/h/rest.*fu="
        echo "/service/.*fu="
        echo "Forward.*fu="
        echo "/ews/"
        echo "mboximport"
        echo "sendshare"
        echo ""
        echo "[SNMP_INDICATORS]"
        echo "udp/161"
        echo "udp/162"
        echo "zimbra-snmp"
    } > "$OUT/threat-intel-feed.txt"

    # Timeline HTML
    cat > "$timeline_html" << 'TL_HEADER'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Incident Timeline</title>
    <style>
        body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
        .event { padding: 5px 0; border-bottom: 1px solid #333; }
        .timestamp { color: #569cd6; }
        .critical { color: #f44747; font-weight: bold; }
        .high { color: #ce9178; }
        .info { color: #6a9955; }
    </style>
</head>
<body>
    <h1 style="color: #f44747;">INCIDENT TIMELINE</h1>
    <pre>
TL_HEADER

    [[ -f "$OUT/timeline-detailed.txt" ]] && cat "$OUT/timeline-detailed.txt" >> "$timeline_html"

    cat >> "$timeline_html" << 'TL_FOOTER'
    </pre>
</body>
</html>
TL_FOOTER
}

###############################################################################
# PHASE 10: SUMMARY
###############################################################################

print_summary() {
    log SECTION "AUDIT COMPLETE — SUMMARY"

    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                    FORENSIC AUDIT SUMMARY v2.1                        ║"
    echo "╠═══════════════════════════════════════════════════════════════════════╣"
    echo "║                                                                      ║"
    printf "║  Critical Findings:   %-45s║\n" "$FINDINGS_CRITICAL"
    printf "║  High Findings:       %-45s║\n" "$FINDINGS_HIGH"
    printf "║  Medium Findings:     %-45s║\n" "$FINDINGS_MEDIUM"
    printf "║  Malware Found:       %-45s║\n" "$MALWARE_FOUND"
    printf "║  Active C2 Conns:     %-45s║\n" "$C2_CONNECTIONS"
    printf "║  Entry Vectors:       %-45s║\n" "${#ENTRY_VECTOR_EVIDENCE[@]}"
    printf "║  CVE Log Hits:        %-45s║\n" "${#CVE_HITS[@]}"
    echo "║                                                                      ║"
    echo "╠═══════════════════════════════════════════════════════════════════════╣"
    echo "║  EVIDENCE DIRECTORY:                                                 ║"
    printf "║  %s║\n" "$OUT"
    echo "║                                                                      ║"
    echo "║  KEY FILES:                                                          ║"
    echo "║    • incident-report.html   — Full HTML report (open in browser)     ║"
    echo "║    • timeline.html          — Visual timeline                        ║"
    echo "║    • ioc-summary.txt        — All IOCs for threat intel sharing      ║"
    echo "║    • threat-intel-feed.txt  — SIEM-ready feed                        ║"
    echo "║    • cve-analysis.txt       — Full CVE assessment (2022–2026)        ║"
    echo "║    • cve-2026-73570-check.txt — SNMP RCE check details              ║"
    echo "║    • cve-2025-68645-indicators.txt — LFI probe evidence              ║"
    echo "║    • malware-analysis.txt   — Malware binary details                 ║"
    echo "║    • malware-samples/       — Copied malware binaries               ║"
    echo "║                                                                      ║"
    echo "╠═══════════════════════════════════════════════════════════════════════╣"
    echo "║  ⚠️  IMMEDIATE ACTIONS REQUIRED:                                       ║"
    echo "║    1. ISOLATE this server from the network                            ║"
    echo "║    2. Block C2 IPs + SNMP ports (161/162) at perimeter                ║"
    echo "║    3. Disable SNMP notifications if zimbra-snmp installed            ║"
    echo "║    4. DO NOT reboot or clean until forensic image created             ║"
    echo "║    5. Reset ALL credentials (Zimbra, LDAP, system)                    ║"
    echo "║    6. Plan upgrade to Zimbra 10.1.20+                                 ║"
    echo "║    7. Open incident-report.html for full details                      ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo ""
}

###############################################################################
# MAIN
###############################################################################

main() {
    echo "============================================================"
    echo " Zimbra Comprehensive Forensic Audit v2.1"
    echo " CVE Database: 2022 through 2026"
    echo " Host: $HOST"
    echo " Start: $(date)"
    echo "============================================================"
    echo ""
    echo "This may take several minutes. Please wait..."
    echo ""

    collect_system_info
    analyze_zimbra_cve
    analyze_entry_vectors
    analyze_malware
    analyze_network_c2
    build_timeline
    check_exfiltration
    check_lateral_movement
    generate_report
    print_summary

    log INFO "Threat intel feed: $OUT/threat-intel-feed.txt"
}

main

exit 0