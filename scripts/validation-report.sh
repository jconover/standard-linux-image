#!/bin/bash
# Validation Report Generator
# Generates a comprehensive markdown report from validation results
# Consolidates InSpec, Goss, and basic validation results

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="${1:-/tmp/validation-reports}"
OUTPUT_FILE="${2:-$REPORT_DIR/validation-report.md}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [REPORT_DIR] [OUTPUT_FILE]

Generate a comprehensive validation report from test results.

Arguments:
    REPORT_DIR      Directory containing validation results (default: /tmp/validation-reports)
    OUTPUT_FILE     Output report file path (default: REPORT_DIR/validation-report.md)

The script looks for the following files in REPORT_DIR:
    - inspec-results.json    InSpec CIS benchmark results
    - goss-results.json      Goss server validation results
    - cis-score.txt          CIS compliance score
    - validation-summary.json General validation summary

Examples:
    $(basename "$0")
    $(basename "$0") /var/log/validation
    $(basename "$0") /var/log/validation /tmp/report.md

EOF
    exit 0
}

# Parse arguments
if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    usage
fi

# Ensure report directory exists
if [ ! -d "$REPORT_DIR" ]; then
    log_error "Report directory not found: $REPORT_DIR"
    exit 1
fi

log_info "Generating validation report from: $REPORT_DIR"

# Initialize report variables
REPORT_DATE=$(date -Iseconds)
HOSTNAME=$(hostname)
OS_INFO=$(cat /etc/redhat-release 2>/dev/null || grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Unknown")
KERNEL_VERSION=$(uname -r)

# Initialize counters
TOTAL_PASSED=0
TOTAL_FAILED=0
TOTAL_SKIPPED=0
TOTAL_WARNINGS=0

# Parse InSpec results
INSPEC_AVAILABLE=false
INSPEC_PASSED=0
INSPEC_FAILED=0
INSPEC_SKIPPED=0
INSPEC_SCORE=0
INSPEC_CONTROLS=""

if [ -f "$REPORT_DIR/inspec-results.json" ]; then
    INSPEC_AVAILABLE=true
    INSPEC_PASSED=$(jq '[.profiles[0].controls[].results[] | select(.status == "passed")] | length' "$REPORT_DIR/inspec-results.json" 2>/dev/null || echo 0)
    INSPEC_FAILED=$(jq '[.profiles[0].controls[].results[] | select(.status == "failed")] | length' "$REPORT_DIR/inspec-results.json" 2>/dev/null || echo 0)
    INSPEC_SKIPPED=$(jq '[.profiles[0].controls[].results[] | select(.status == "skipped")] | length' "$REPORT_DIR/inspec-results.json" 2>/dev/null || echo 0)

    INSPEC_TOTAL=$((INSPEC_PASSED + INSPEC_FAILED))
    if [ "$INSPEC_TOTAL" -gt 0 ]; then
        INSPEC_SCORE=$((INSPEC_PASSED * 100 / INSPEC_TOTAL))
    fi

    TOTAL_PASSED=$((TOTAL_PASSED + INSPEC_PASSED))
    TOTAL_FAILED=$((TOTAL_FAILED + INSPEC_FAILED))
    TOTAL_SKIPPED=$((TOTAL_SKIPPED + INSPEC_SKIPPED))

    # Get failed controls for detailed reporting
    INSPEC_CONTROLS=$(jq -r '.profiles[0].controls[] | select(.results[].status == "failed") | "- **\(.id)**: \(.title)"' "$REPORT_DIR/inspec-results.json" 2>/dev/null | head -20 || echo "")
fi

# Parse Goss results
GOSS_AVAILABLE=false
GOSS_PASSED=0
GOSS_FAILED=0
GOSS_DURATION=0
GOSS_FAILURES=""

if [ -f "$REPORT_DIR/goss-results.json" ]; then
    GOSS_AVAILABLE=true
    GOSS_TOTAL=$(jq '.summary."test-count"' "$REPORT_DIR/goss-results.json" 2>/dev/null || echo 0)
    GOSS_FAILED=$(jq '.summary."failed-count"' "$REPORT_DIR/goss-results.json" 2>/dev/null || echo 0)
    GOSS_PASSED=$((GOSS_TOTAL - GOSS_FAILED))
    GOSS_DURATION=$(jq '.summary."total-duration"' "$REPORT_DIR/goss-results.json" 2>/dev/null || echo 0)

    TOTAL_PASSED=$((TOTAL_PASSED + GOSS_PASSED))
    TOTAL_FAILED=$((TOTAL_FAILED + GOSS_FAILED))

    # Get failed tests for detailed reporting
    GOSS_FAILURES=$(jq -r '.results[] | select(.successful == false) | "- **\(.resource-type)/\(.resource-id)**: \(.property) - \(.summary-line)"' "$REPORT_DIR/goss-results.json" 2>/dev/null | head -20 || echo "")
fi

# Read CIS score if available
CIS_SCORE_FILE="$REPORT_DIR/cis-score.txt"
if [ -f "$CIS_SCORE_FILE" ]; then
    CIS_SCORE=$(cat "$CIS_SCORE_FILE")
else
    CIS_SCORE=$INSPEC_SCORE
fi

# Determine overall status
if [ "$TOTAL_FAILED" -eq 0 ]; then
    OVERALL_STATUS="PASSED"
    STATUS_COLOR="green"
    STATUS_EMOJI="[PASS]"
else
    OVERALL_STATUS="FAILED"
    STATUS_COLOR="red"
    STATUS_EMOJI="[FAIL]"
fi

# Generate the report
cat > "$OUTPUT_FILE" << EOF
# Validation Report

## Executive Summary

| Property | Value |
|----------|-------|
| **Status** | $STATUS_EMOJI **$OVERALL_STATUS** |
| **Generated** | $REPORT_DATE |
| **Host** | $HOSTNAME |
| **OS** | $OS_INFO |
| **Kernel** | $KERNEL_VERSION |
| **CIS Score** | ${CIS_SCORE}% |

## Test Summary

| Category | Passed | Failed | Skipped | Total |
|----------|--------|--------|---------|-------|
| **InSpec CIS** | $INSPEC_PASSED | $INSPEC_FAILED | $INSPEC_SKIPPED | $((INSPEC_PASSED + INSPEC_FAILED + INSPEC_SKIPPED)) |
| **Goss** | $GOSS_PASSED | $GOSS_FAILED | 0 | $((GOSS_PASSED + GOSS_FAILED)) |
| **Total** | $TOTAL_PASSED | $TOTAL_FAILED | $TOTAL_SKIPPED | $((TOTAL_PASSED + TOTAL_FAILED + TOTAL_SKIPPED)) |

EOF

# Add CIS Benchmark section
if [ "$INSPEC_AVAILABLE" = "true" ]; then
    cat >> "$OUTPUT_FILE" << EOF
## CIS Benchmark Compliance

**Compliance Score: ${INSPEC_SCORE}%**

### Summary by Result

- Passed Controls: $INSPEC_PASSED
- Failed Controls: $INSPEC_FAILED
- Skipped Controls: $INSPEC_SKIPPED

EOF

    if [ -n "$INSPEC_CONTROLS" ] && [ "$INSPEC_FAILED" -gt 0 ]; then
        cat >> "$OUTPUT_FILE" << EOF
### Failed Controls

$INSPEC_CONTROLS

EOF
        if [ "$INSPEC_FAILED" -gt 20 ]; then
            echo "_Note: Showing first 20 failed controls. See full report for details._" >> "$OUTPUT_FILE"
            echo "" >> "$OUTPUT_FILE"
        fi
    fi
else
    cat >> "$OUTPUT_FILE" << EOF
## CIS Benchmark Compliance

_InSpec results not available_

EOF
fi

# Add Goss section
if [ "$GOSS_AVAILABLE" = "true" ]; then
    # Convert duration from nanoseconds to milliseconds
    DURATION_MS=$((GOSS_DURATION / 1000000))

    cat >> "$OUTPUT_FILE" << EOF
## Server Validation (Goss)

**Test Duration: ${DURATION_MS}ms**

### Summary

- Total Tests: $((GOSS_PASSED + GOSS_FAILED))
- Passed: $GOSS_PASSED
- Failed: $GOSS_FAILED

EOF

    if [ -n "$GOSS_FAILURES" ] && [ "$GOSS_FAILED" -gt 0 ]; then
        cat >> "$OUTPUT_FILE" << EOF
### Failed Tests

$GOSS_FAILURES

EOF
        if [ "$GOSS_FAILED" -gt 20 ]; then
            echo "_Note: Showing first 20 failed tests. See full report for details._" >> "$OUTPUT_FILE"
            echo "" >> "$OUTPUT_FILE"
        fi
    fi
else
    cat >> "$OUTPUT_FILE" << EOF
## Server Validation (Goss)

_Goss results not available_

EOF
fi

# Add system information section
cat >> "$OUTPUT_FILE" << EOF
## System Information

### Operating System

| Property | Value |
|----------|-------|
| Distribution | $OS_INFO |
| Kernel | $KERNEL_VERSION |
| Architecture | $(uname -m) |
| Hostname | $HOSTNAME |

### Security Status

EOF

# Check SELinux
if command -v getenforce &>/dev/null; then
    SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Unknown")
    echo "- **SELinux**: $SELINUX_STATUS" >> "$OUTPUT_FILE"
fi

# Check Firewall
if systemctl is-active firewalld &>/dev/null; then
    echo "- **Firewall**: Active (firewalld)" >> "$OUTPUT_FILE"
else
    echo "- **Firewall**: Inactive" >> "$OUTPUT_FILE"
fi

# Check SSH
if systemctl is-enabled sshd &>/dev/null; then
    echo "- **SSH**: Enabled" >> "$OUTPUT_FILE"
fi

# Check audit
if systemctl is-enabled auditd &>/dev/null; then
    echo "- **Audit**: Enabled" >> "$OUTPUT_FILE"
fi

# Add recommendations section
cat >> "$OUTPUT_FILE" << EOF

## Recommendations

EOF

if [ "$TOTAL_FAILED" -gt 0 ]; then
    cat >> "$OUTPUT_FILE" << EOF
Based on the validation results, the following actions are recommended:

1. **Review Failed Controls**: Examine the failed InSpec and Goss tests above
2. **Prioritize by Impact**: Address high-impact CIS controls first
3. **Re-validate**: After remediation, re-run validation to confirm fixes
4. **Document Exceptions**: For controls that cannot be remediated, document risk acceptance

EOF
else
    cat >> "$OUTPUT_FILE" << EOF
All validations passed. The image meets the compliance requirements.

**Recommended Next Steps:**
1. Proceed with image deployment
2. Schedule periodic re-validation
3. Monitor for configuration drift

EOF
fi

# Add artifact references
cat >> "$OUTPUT_FILE" << EOF
## Artifacts

The following files contain detailed validation results:

EOF

[ -f "$REPORT_DIR/inspec-results.json" ] && echo "- \`inspec-results.json\` - Detailed InSpec results" >> "$OUTPUT_FILE"
[ -f "$REPORT_DIR/goss-results.json" ] && echo "- \`goss-results.json\` - Detailed Goss results" >> "$OUTPUT_FILE"
[ -f "$REPORT_DIR/cis-score.txt" ] && echo "- \`cis-score.txt\` - CIS compliance score" >> "$OUTPUT_FILE"
[ -f "$REPORT_DIR/validation-summary.json" ] && echo "- \`validation-summary.json\` - Validation summary" >> "$OUTPUT_FILE"

# Add footer
cat >> "$OUTPUT_FILE" << EOF

---

_Report generated by validation-report.sh_
_Project: Standard Linux Image_
_Timestamp: $REPORT_DATE_
EOF

log_success "Report generated: $OUTPUT_FILE"

# Also output a quick summary to console
echo ""
echo "=========================================="
echo "  Validation Report Summary"
echo "=========================================="
echo ""
echo "Status:      $OVERALL_STATUS"
echo "CIS Score:   ${CIS_SCORE}%"
echo "Total Tests: $((TOTAL_PASSED + TOTAL_FAILED + TOTAL_SKIPPED))"
echo "  Passed:    $TOTAL_PASSED"
echo "  Failed:    $TOTAL_FAILED"
echo "  Skipped:   $TOTAL_SKIPPED"
echo ""
echo "Report:      $OUTPUT_FILE"
echo ""

# Exit with appropriate code
if [ "$TOTAL_FAILED" -eq 0 ]; then
    exit 0
else
    exit 1
fi
