#!/bin/bash
# Comprehensive Validation Script for Packer Images
# Runs basic checks, InSpec tests, Goss tests, and generates validation report
# Exit codes:
#   0 - All validations passed
#   1 - Critical failures detected
#   2 - Warnings but no critical failures
#   3 - Validation tools not available (when required)

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="${REPORT_DIR:-/tmp/validation-reports}"
INSPEC_PROFILE="${INSPEC_PROFILE:-$PROJECT_ROOT/inspec/cis-benchmark}"
GOSS_FILE="${GOSS_FILE:-$PROJECT_ROOT/goss/goss.yaml}"
CIS_SCORE_THRESHOLD="${CIS_SCORE_THRESHOLD:-80}"
REQUIRE_INSPEC="${REQUIRE_INSPEC:-false}"
REQUIRE_GOSS="${REQUIRE_GOSS:-false}"
TARGET_HOST="${TARGET_HOST:-}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-text}"

# Counters
ERRORS=0
WARNINGS=0
PASSED=0
SKIPPED=0

# Results storage for report generation
declare -a RESULTS=()

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
    RESULTS+=("PASS|$1")
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ERRORS=$((ERRORS + 1))
    RESULTS+=("FAIL|$1")
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARNINGS=$((WARNINGS + 1))
    RESULTS+=("WARN|$1")
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    RESULTS+=("INFO|$1")
}

skip() {
    echo -e "${CYAN}[SKIP]${NC} $1"
    SKIPPED=$((SKIPPED + 1))
    RESULTS+=("SKIP|$1")
}

section() {
    echo ""
    echo -e "${CYAN}=== $1 ===${NC}"
    echo ""
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Comprehensive validation script for Packer-built images.

OPTIONS:
    -h, --help              Show this help message
    -t, --target HOST       Target host for remote validation (SSH)
    -i, --inspec-profile    Path to InSpec profile (default: $INSPEC_PROFILE)
    -g, --goss-file         Path to Goss file (default: $GOSS_FILE)
    -s, --cis-threshold     CIS compliance score threshold (default: $CIS_SCORE_THRESHOLD)
    -r, --report-dir        Directory for validation reports (default: $REPORT_DIR)
    -f, --format            Output format: text, json, junit (default: text)
    --require-inspec        Fail if InSpec is not available
    --require-goss          Fail if Goss is not available
    --skip-basic            Skip basic system checks
    --skip-inspec           Skip InSpec validation
    --skip-goss             Skip Goss validation

ENVIRONMENT VARIABLES:
    TARGET_HOST             Same as --target
    INSPEC_PROFILE          Same as --inspec-profile
    GOSS_FILE               Same as --goss-file
    CIS_SCORE_THRESHOLD     Same as --cis-threshold
    REPORT_DIR              Same as --report-dir
    REQUIRE_INSPEC          Same as --require-inspec (true/false)
    REQUIRE_GOSS            Same as --require-goss (true/false)

EXIT CODES:
    0 - All validations passed
    1 - Critical failures detected
    2 - Warnings but no critical failures
    3 - Required validation tools not available

EXAMPLES:
    # Run all validations locally
    $(basename "$0")

    # Run validation against a remote host
    $(basename "$0") -t user@192.168.1.100

    # Run with custom CIS threshold
    $(basename "$0") -s 90

    # Generate JSON report
    $(basename "$0") -f json -r /var/log/validation

EOF
    exit 0
}

# Parse command line arguments
SKIP_BASIC=false
SKIP_INSPEC=false
SKIP_GOSS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -t|--target)
            TARGET_HOST="$2"
            shift 2
            ;;
        -i|--inspec-profile)
            INSPEC_PROFILE="$2"
            shift 2
            ;;
        -g|--goss-file)
            GOSS_FILE="$2"
            shift 2
            ;;
        -s|--cis-threshold)
            CIS_SCORE_THRESHOLD="$2"
            shift 2
            ;;
        -r|--report-dir)
            REPORT_DIR="$2"
            shift 2
            ;;
        -f|--format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --require-inspec)
            REQUIRE_INSPEC=true
            shift
            ;;
        --require-goss)
            REQUIRE_GOSS=true
            shift
            ;;
        --skip-basic)
            SKIP_BASIC=true
            shift
            ;;
        --skip-inspec)
            SKIP_INSPEC=true
            shift
            ;;
        --skip-goss)
            SKIP_GOSS=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Create report directory
mkdir -p "$REPORT_DIR"

# Store validation start time
VALIDATION_START=$(date +%s)
VALIDATION_DATE=$(date -Iseconds)

echo "=========================================="
echo "  Comprehensive Image Validation"
echo "=========================================="
echo ""
info "Validation started at: $(date)"
info "Report directory: $REPORT_DIR"
if [ -n "$TARGET_HOST" ]; then
    info "Target host: $TARGET_HOST"
else
    info "Target: localhost"
fi
echo ""

# Helper function to run commands locally or remotely
run_cmd() {
    if [ -n "$TARGET_HOST" ]; then
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$TARGET_HOST" "$@"
    else
        eval "$@"
    fi
}

# ============================================================================
# Basic System Checks
# ============================================================================

run_basic_checks() {
    section "Basic System Checks"

    # System Information
    info "OS: $(run_cmd 'cat /etc/redhat-release 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d \"')"
    info "Kernel: $(run_cmd 'uname -r')"
    info "Architecture: $(run_cmd 'uname -m')"
    echo ""

    echo "--- Root/Permissions Checks ---"

    # Check if running as root (locally)
    if [ -z "$TARGET_HOST" ]; then
        if [ "$EUID" -eq 0 ]; then
            pass "Running as root"
        else
            warn "Not running as root - some checks may fail"
        fi
    fi

    # Check bootloader
    if run_cmd '[ -d /sys/firmware/efi ]'; then
        pass "UEFI boot mode detected"
    else
        warn "BIOS boot mode detected (expected UEFI)"
    fi

    echo ""
    echo "--- Filesystem Checks ---"

    # Check filesystem type for root
    ROOT_FS=$(run_cmd "df -T / | tail -1 | awk '{print \$2}'")
    if [ "$ROOT_FS" = "xfs" ]; then
        pass "Root filesystem is XFS"
    else
        warn "Root filesystem is $ROOT_FS (expected XFS)"
    fi

    # Check LVM
    if run_cmd 'pvs 2>/dev/null | grep -q pv'; then
        pass "LVM is configured"
    else
        warn "LVM not detected"
    fi

    # Check disk space
    ROOT_USAGE=$(run_cmd "df / | tail -1 | awk '{print \$5}' | tr -d '%'")
    if [ "$ROOT_USAGE" -lt 50 ]; then
        pass "Root filesystem usage: ${ROOT_USAGE}%"
    elif [ "$ROOT_USAGE" -lt 80 ]; then
        warn "Root filesystem usage: ${ROOT_USAGE}%"
    else
        fail "Root filesystem usage critical: ${ROOT_USAGE}%"
    fi

    BOOT_USAGE=$(run_cmd "df /boot 2>/dev/null | tail -1 | awk '{print \$5}' | tr -d '%'" || echo "0")
    if [ -n "$BOOT_USAGE" ] && [ "$BOOT_USAGE" != "0" ]; then
        if [ "$BOOT_USAGE" -lt 50 ]; then
            pass "Boot filesystem usage: ${BOOT_USAGE}%"
        else
            warn "Boot filesystem usage: ${BOOT_USAGE}%"
        fi
    fi

    echo ""
    echo "--- Security Checks ---"

    # Check if packer user exists (should be removed)
    if run_cmd 'id packer &>/dev/null'; then
        fail "Packer user still exists (should be removed)"
    else
        pass "Packer user removed"
    fi

    # Check if SSH host keys exist
    if run_cmd 'ls /etc/ssh/ssh_host_* 1>/dev/null 2>&1'; then
        warn "SSH host keys exist (may need regeneration on first boot)"
    else
        pass "SSH host keys removed (will regenerate on first boot)"
    fi

    # Check machine-id
    MACHINE_ID=$(run_cmd 'cat /etc/machine-id 2>/dev/null' || echo "")
    if [ -z "$MACHINE_ID" ]; then
        pass "Machine-id is empty (will regenerate on first boot)"
    else
        warn "Machine-id is set: $MACHINE_ID"
    fi

    # Check SELinux status
    if run_cmd 'command -v getenforce &>/dev/null'; then
        SELINUX_STATUS=$(run_cmd 'getenforce')
        if [ "$SELINUX_STATUS" = "Enforcing" ]; then
            pass "SELinux is enforcing"
        elif [ "$SELINUX_STATUS" = "Permissive" ]; then
            warn "SELinux is permissive (expected enforcing)"
        else
            warn "SELinux is disabled"
        fi
    else
        warn "SELinux tools not found"
    fi

    # Check firewall
    if run_cmd 'systemctl is-active firewalld &>/dev/null'; then
        pass "Firewalld is active"
    else
        warn "Firewalld is not active"
    fi

    echo ""
    echo "--- Service Checks ---"

    # Check SSH
    if run_cmd 'systemctl is-enabled sshd &>/dev/null'; then
        pass "SSH service is enabled"
    else
        fail "SSH service is not enabled"
    fi

    # Check critical services
    for service in auditd chronyd rsyslog; do
        if run_cmd "systemctl is-enabled $service &>/dev/null"; then
            pass "Service $service is enabled"
        else
            warn "Service $service is not enabled"
        fi
    done

    echo ""
    echo "--- Package Checks ---"

    # Check package manager
    if run_cmd 'command -v dnf &>/dev/null'; then
        pass "DNF package manager available"
    else
        fail "DNF package manager not found"
    fi

    # Check for required packages
    for pkg in openssh-server sudo curl; do
        if run_cmd "rpm -q $pkg &>/dev/null"; then
            pass "Package $pkg is installed"
        else
            fail "Package $pkg is NOT installed"
        fi
    done

    echo ""
    echo "--- Cleanup Checks ---"

    # Check for leftover temporary files
    TMP_COUNT=$(run_cmd 'find /tmp -mindepth 1 2>/dev/null | wc -l')
    if [ "$TMP_COUNT" -eq 0 ]; then
        pass "/tmp is clean"
    else
        warn "/tmp contains $TMP_COUNT items"
    fi

    # Check for bash history
    if run_cmd '[ -f /root/.bash_history ]'; then
        HISTORY_SIZE=$(run_cmd 'wc -l < /root/.bash_history')
        if [ "$HISTORY_SIZE" -gt 0 ]; then
            warn "Root bash history exists ($HISTORY_SIZE lines)"
        else
            pass "Root bash history is empty"
        fi
    else
        pass "No root bash history file"
    fi

    # Check for kickstart files
    if run_cmd '[ -f /root/anaconda-ks.cfg ]'; then
        warn "Kickstart file exists at /root/anaconda-ks.cfg"
    else
        pass "Kickstart files cleaned up"
    fi
}

# ============================================================================
# InSpec Validation
# ============================================================================

run_inspec_validation() {
    section "InSpec CIS Benchmark Validation"

    # Check if InSpec is available
    if ! command -v inspec &>/dev/null; then
        if [ "$REQUIRE_INSPEC" = "true" ]; then
            fail "InSpec is required but not installed"
            return 3
        else
            skip "InSpec not available - skipping CIS benchmark validation"
            return 0
        fi
    fi

    # Check if profile exists
    if [ ! -d "$INSPEC_PROFILE" ]; then
        warn "InSpec profile not found at $INSPEC_PROFILE"
        return 0
    fi

    info "Running InSpec profile: $INSPEC_PROFILE"

    # Build target string
    INSPEC_TARGET=""
    if [ -n "$TARGET_HOST" ]; then
        INSPEC_TARGET="--target ssh://$TARGET_HOST"
    fi

    # Run InSpec and capture results
    INSPEC_OUTPUT="$REPORT_DIR/inspec-results.json"
    INSPEC_HTML="$REPORT_DIR/inspec-results.html"

    set +e
    inspec exec "$INSPEC_PROFILE" $INSPEC_TARGET \
        --reporter json:"$INSPEC_OUTPUT" cli \
        --chef-license accept-silent 2>&1
    INSPEC_EXIT=$?
    set -e

    # Parse results
    if [ -f "$INSPEC_OUTPUT" ]; then
        TOTAL_CONTROLS=$(jq '.profiles[0].controls | length' "$INSPEC_OUTPUT" 2>/dev/null || echo "0")
        PASSED_CONTROLS=$(jq '[.profiles[0].controls[].results[] | select(.status == "passed")] | length' "$INSPEC_OUTPUT" 2>/dev/null || echo "0")
        FAILED_CONTROLS=$(jq '[.profiles[0].controls[].results[] | select(.status == "failed")] | length' "$INSPEC_OUTPUT" 2>/dev/null || echo "0")
        SKIPPED_CONTROLS=$(jq '[.profiles[0].controls[].results[] | select(.status == "skipped")] | length' "$INSPEC_OUTPUT" 2>/dev/null || echo "0")

        # Calculate compliance score
        if [ "$TOTAL_CONTROLS" -gt 0 ]; then
            COMPLIANCE_SCORE=$((PASSED_CONTROLS * 100 / (PASSED_CONTROLS + FAILED_CONTROLS)))
        else
            COMPLIANCE_SCORE=0
        fi

        echo ""
        echo "InSpec Results Summary:"
        echo "  Total Controls: $TOTAL_CONTROLS"
        echo "  Passed: $PASSED_CONTROLS"
        echo "  Failed: $FAILED_CONTROLS"
        echo "  Skipped: $SKIPPED_CONTROLS"
        echo "  Compliance Score: ${COMPLIANCE_SCORE}%"
        echo ""

        # Check against threshold
        if [ "$COMPLIANCE_SCORE" -ge "$CIS_SCORE_THRESHOLD" ]; then
            pass "CIS compliance score (${COMPLIANCE_SCORE}%) meets threshold (${CIS_SCORE_THRESHOLD}%)"
        else
            fail "CIS compliance score (${COMPLIANCE_SCORE}%) below threshold (${CIS_SCORE_THRESHOLD}%)"
        fi

        # Store score for report
        echo "$COMPLIANCE_SCORE" > "$REPORT_DIR/cis-score.txt"
    else
        warn "Could not parse InSpec results"
    fi

    return 0
}

# ============================================================================
# Goss Validation
# ============================================================================

run_goss_validation() {
    section "Goss Server Validation"

    # Check if Goss is available
    if ! command -v goss &>/dev/null; then
        if [ "$REQUIRE_GOSS" = "true" ]; then
            fail "Goss is required but not installed"
            return 3
        else
            skip "Goss not available - skipping server validation"
            return 0
        fi
    fi

    # Check if goss file exists
    if [ ! -f "$GOSS_FILE" ]; then
        warn "Goss file not found at $GOSS_FILE"
        return 0
    fi

    info "Running Goss validation: $GOSS_FILE"

    # Build target options
    GOSS_OPTS=""
    if [ -n "$TARGET_HOST" ]; then
        # For remote execution, we need to use goss serve or copy files
        warn "Remote Goss validation requires goss to be installed on target"
        skip "Remote Goss validation not implemented - run locally on target"
        return 0
    fi

    # Run Goss and capture results
    GOSS_OUTPUT="$REPORT_DIR/goss-results.json"

    set +e
    cd "$PROJECT_ROOT" && goss -g "$GOSS_FILE" validate --format json > "$GOSS_OUTPUT" 2>&1
    GOSS_EXIT=$?
    set -e

    # Also run with human-readable output
    echo ""
    cd "$PROJECT_ROOT" && goss -g "$GOSS_FILE" validate --format documentation 2>&1 || true
    echo ""

    # Parse results
    if [ -f "$GOSS_OUTPUT" ]; then
        GOSS_TOTAL=$(jq '.summary."test-count"' "$GOSS_OUTPUT" 2>/dev/null || echo "0")
        GOSS_FAILED=$(jq '.summary."failed-count"' "$GOSS_OUTPUT" 2>/dev/null || echo "0")
        GOSS_DURATION=$(jq '.summary."total-duration"' "$GOSS_OUTPUT" 2>/dev/null || echo "0")

        echo "Goss Results Summary:"
        echo "  Total Tests: $GOSS_TOTAL"
        echo "  Failed: $GOSS_FAILED"
        echo "  Duration: ${GOSS_DURATION}ns"
        echo ""

        if [ "$GOSS_FAILED" -eq 0 ]; then
            pass "All Goss tests passed ($GOSS_TOTAL tests)"
        else
            fail "Goss validation failed ($GOSS_FAILED of $GOSS_TOTAL tests failed)"
        fi
    else
        warn "Could not parse Goss results"
    fi

    return 0
}

# ============================================================================
# Generate Summary Report
# ============================================================================

generate_report() {
    section "Generating Validation Report"

    VALIDATION_END=$(date +%s)
    VALIDATION_DURATION=$((VALIDATION_END - VALIDATION_START))

    # Generate markdown report
    REPORT_FILE="$REPORT_DIR/validation-report.md"

    cat > "$REPORT_FILE" << EOF
# Validation Report

**Generated:** $VALIDATION_DATE
**Duration:** ${VALIDATION_DURATION} seconds
**Target:** ${TARGET_HOST:-localhost}

## Summary

| Metric | Count |
|--------|-------|
| Passed | $PASSED |
| Failed | $ERRORS |
| Warnings | $WARNINGS |
| Skipped | $SKIPPED |

## Overall Status

EOF

    if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
        echo "**PASSED** - All validations passed successfully." >> "$REPORT_FILE"
    elif [ $ERRORS -eq 0 ]; then
        echo "**PASSED WITH WARNINGS** - $WARNINGS warning(s) detected." >> "$REPORT_FILE"
    else
        echo "**FAILED** - $ERRORS error(s) and $WARNINGS warning(s) detected." >> "$REPORT_FILE"
    fi

    # Add CIS score if available
    if [ -f "$REPORT_DIR/cis-score.txt" ]; then
        CIS_SCORE=$(cat "$REPORT_DIR/cis-score.txt")
        cat >> "$REPORT_FILE" << EOF

## CIS Benchmark Compliance

**Score:** ${CIS_SCORE}%
**Threshold:** ${CIS_SCORE_THRESHOLD}%

EOF
    fi

    # Add detailed results
    cat >> "$REPORT_FILE" << EOF

## Detailed Results

| Status | Check |
|--------|-------|
EOF

    for result in "${RESULTS[@]}"; do
        STATUS=$(echo "$result" | cut -d'|' -f1)
        MESSAGE=$(echo "$result" | cut -d'|' -f2-)
        case $STATUS in
            PASS) EMOJI="PASS" ;;
            FAIL) EMOJI="FAIL" ;;
            WARN) EMOJI="WARN" ;;
            SKIP) EMOJI="SKIP" ;;
            INFO) EMOJI="INFO" ;;
            *) EMOJI="--" ;;
        esac
        echo "| $EMOJI | $MESSAGE |" >> "$REPORT_FILE"
    done

    # Add artifact references
    cat >> "$REPORT_FILE" << EOF

## Artifacts

EOF

    if [ -f "$REPORT_DIR/inspec-results.json" ]; then
        echo "- InSpec Results: \`$REPORT_DIR/inspec-results.json\`" >> "$REPORT_FILE"
    fi
    if [ -f "$REPORT_DIR/goss-results.json" ]; then
        echo "- Goss Results: \`$REPORT_DIR/goss-results.json\`" >> "$REPORT_FILE"
    fi

    info "Validation report generated: $REPORT_FILE"

    # Generate JSON report if requested
    if [ "$OUTPUT_FORMAT" = "json" ]; then
        JSON_REPORT="$REPORT_DIR/validation-report.json"
        cat > "$JSON_REPORT" << EOF
{
  "timestamp": "$VALIDATION_DATE",
  "duration_seconds": $VALIDATION_DURATION,
  "target": "${TARGET_HOST:-localhost}",
  "summary": {
    "passed": $PASSED,
    "failed": $ERRORS,
    "warnings": $WARNINGS,
    "skipped": $SKIPPED
  },
  "cis_threshold": $CIS_SCORE_THRESHOLD,
  "status": "$([ $ERRORS -eq 0 ] && echo "passed" || echo "failed")"
}
EOF
        info "JSON report generated: $JSON_REPORT"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    # Run basic checks
    if [ "$SKIP_BASIC" != "true" ]; then
        run_basic_checks
    else
        skip "Basic system checks (--skip-basic)"
    fi

    # Run InSpec validation
    if [ "$SKIP_INSPEC" != "true" ]; then
        run_inspec_validation
        INSPEC_RESULT=$?
        if [ $INSPEC_RESULT -eq 3 ]; then
            ERRORS=$((ERRORS + 1))
        fi
    else
        skip "InSpec validation (--skip-inspec)"
    fi

    # Run Goss validation
    if [ "$SKIP_GOSS" != "true" ]; then
        run_goss_validation
        GOSS_RESULT=$?
        if [ $GOSS_RESULT -eq 3 ]; then
            ERRORS=$((ERRORS + 1))
        fi
    else
        skip "Goss validation (--skip-goss)"
    fi

    # Generate report
    generate_report

    # Final summary
    echo ""
    echo "=========================================="
    echo "  Validation Summary"
    echo "=========================================="
    echo ""
    echo "  Passed:   $PASSED"
    echo "  Failed:   $ERRORS"
    echo "  Warnings: $WARNINGS"
    echo "  Skipped:  $SKIPPED"
    echo ""

    if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
        echo -e "${GREEN}All validations passed!${NC}"
        exit 0
    elif [ $ERRORS -eq 0 ]; then
        echo -e "${YELLOW}Validation completed with $WARNINGS warning(s)${NC}"
        exit 2
    else
        echo -e "${RED}Validation failed with $ERRORS error(s) and $WARNINGS warning(s)${NC}"
        exit 1
    fi
}

# Run main function
main
