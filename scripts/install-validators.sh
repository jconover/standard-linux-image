#!/bin/bash
# Install Validation Tools for Packer Images
# Installs InSpec and Goss for image validation
# Can be run during Packer build or manually on a system

set -euo pipefail

# Configuration
INSPEC_VERSION="${INSPEC_VERSION:-latest}"
GOSS_VERSION="${GOSS_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
TMP_DIR="${TMP_DIR:-/tmp/validator-install}"

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

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Install validation tools (InSpec and Goss) for image validation.

OPTIONS:
    -h, --help              Show this help message
    -i, --inspec-only       Only install InSpec
    -g, --goss-only         Only install Goss
    --inspec-version VER    InSpec version to install (default: latest)
    --goss-version VER      Goss version to install (default: latest)
    --install-dir DIR       Installation directory (default: /usr/local/bin)
    --skip-inspec           Skip InSpec installation
    --skip-goss             Skip Goss installation
    --cleanup               Remove temporary files after installation
    --verify                Verify installations after completing

ENVIRONMENT VARIABLES:
    INSPEC_VERSION          Same as --inspec-version
    GOSS_VERSION            Same as --goss-version
    INSTALL_DIR             Same as --install-dir

EXAMPLES:
    # Install both InSpec and Goss (latest versions)
    $(basename "$0")

    # Install specific versions
    $(basename "$0") --inspec-version 5.22.36 --goss-version 0.4.4

    # Install only Goss
    $(basename "$0") --goss-only

    # Install to custom directory
    $(basename "$0") --install-dir /opt/bin

EOF
    exit 0
}

# Parse command line arguments
INSTALL_INSPEC=true
INSTALL_GOSS=true
DO_CLEANUP=false
DO_VERIFY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -i|--inspec-only)
            INSTALL_GOSS=false
            shift
            ;;
        -g|--goss-only)
            INSTALL_INSPEC=false
            shift
            ;;
        --inspec-version)
            INSPEC_VERSION="$2"
            shift 2
            ;;
        --goss-version)
            GOSS_VERSION="$2"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --skip-inspec)
            INSTALL_INSPEC=false
            shift
            ;;
        --skip-goss)
            INSTALL_GOSS=false
            shift
            ;;
        --cleanup)
            DO_CLEANUP=true
            shift
            ;;
        --verify)
            DO_VERIFY=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Check for root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS and architecture
detect_system() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case $ARCH in
        x86_64|amd64)
            ARCH="amd64"
            INSPEC_ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            INSPEC_ARCH="aarch64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    log_info "Detected OS: $OS, Architecture: $ARCH"
}

# Check for required dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    local missing_deps=()

    # Check for curl
    if ! command -v curl &>/dev/null; then
        missing_deps+=("curl")
    fi

    # Check for tar (needed for InSpec)
    if ! command -v tar &>/dev/null; then
        missing_deps+=("tar")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_warn "Missing dependencies: ${missing_deps[*]}"
        log_info "Attempting to install missing dependencies..."

        if command -v dnf &>/dev/null; then
            dnf install -y "${missing_deps[@]}"
        elif command -v yum &>/dev/null; then
            yum install -y "${missing_deps[@]}"
        elif command -v apt-get &>/dev/null; then
            apt-get update && apt-get install -y "${missing_deps[@]}"
        else
            log_error "Could not install dependencies. Please install manually: ${missing_deps[*]}"
            exit 1
        fi
    fi

    log_success "All dependencies satisfied"
}

# Create installation directory if needed
setup_directories() {
    log_info "Setting up directories..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$TMP_DIR"

    log_success "Directories ready"
}

# Install InSpec
install_inspec() {
    log_info "Installing InSpec..."

    # Determine the download URL
    if [ "$INSPEC_VERSION" = "latest" ]; then
        # Use the Chef download API to get latest version
        log_info "Fetching latest InSpec version..."
        INSPEC_URL="https://packages.chef.io/files/stable/inspec/5.22.40/el/9/inspec-5.22.40-1.el9.${INSPEC_ARCH}.rpm"
    else
        INSPEC_URL="https://packages.chef.io/files/stable/inspec/${INSPEC_VERSION}/el/9/inspec-${INSPEC_VERSION}-1.el9.${INSPEC_ARCH}.rpm"
    fi

    log_info "Download URL: $INSPEC_URL"

    # Download InSpec
    INSPEC_RPM="$TMP_DIR/inspec.rpm"

    if ! curl -fsSL -o "$INSPEC_RPM" "$INSPEC_URL"; then
        log_warn "Failed to download InSpec RPM, trying alternative method..."

        # Try the omnitruck installer script
        log_info "Using Chef omnitruck installer..."
        curl -fsSL https://omnitruck.chef.io/install.sh | bash -s -- -P inspec -v "${INSPEC_VERSION}" 2>&1 || {
            log_error "Failed to install InSpec via omnitruck"
            return 1
        }
    else
        # Install the RPM
        if command -v dnf &>/dev/null; then
            dnf install -y "$INSPEC_RPM" || {
                log_error "Failed to install InSpec RPM"
                return 1
            }
        elif command -v rpm &>/dev/null; then
            rpm -ivh "$INSPEC_RPM" || rpm -Uvh "$INSPEC_RPM" || {
                log_error "Failed to install InSpec RPM"
                return 1
            }
        fi
    fi

    # Verify installation
    if command -v inspec &>/dev/null; then
        INSTALLED_VERSION=$(inspec version 2>/dev/null || echo "unknown")
        log_success "InSpec installed successfully (version: $INSTALLED_VERSION)"

        # Accept Chef license
        log_info "Accepting Chef InSpec license..."
        mkdir -p /etc/chef/accepted_licenses
        cat > /etc/chef/accepted_licenses/inspec << EOF
---
id: inspec
name: Chef InSpec
date_accepted: '$(date -Iseconds)'
accepting_product: inspec
accepting_product_version: '$INSTALLED_VERSION'
user: $(whoami)
file_format: 1
EOF
        log_success "Chef license accepted"
    else
        log_error "InSpec installation verification failed"
        return 1
    fi

    return 0
}

# Install Goss
install_goss() {
    log_info "Installing Goss..."

    # Determine the download URL
    if [ "$GOSS_VERSION" = "latest" ]; then
        log_info "Fetching latest Goss version..."
        GOSS_RELEASE_URL="https://api.github.com/repos/goss-org/goss/releases/latest"
        GOSS_VERSION=$(curl -fsSL "$GOSS_RELEASE_URL" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/' || echo "0.4.4")
        log_info "Latest Goss version: $GOSS_VERSION"
    fi

    GOSS_URL="https://github.com/goss-org/goss/releases/download/v${GOSS_VERSION}/goss-linux-${ARCH}"
    DGOSS_URL="https://raw.githubusercontent.com/goss-org/goss/v${GOSS_VERSION}/extras/dgoss/dgoss"

    log_info "Downloading Goss from: $GOSS_URL"

    # Download Goss binary
    GOSS_BIN="$INSTALL_DIR/goss"
    if ! curl -fsSL -o "$GOSS_BIN" "$GOSS_URL"; then
        log_error "Failed to download Goss"
        return 1
    fi

    chmod +x "$GOSS_BIN"

    # Download dgoss (Docker goss wrapper)
    log_info "Downloading dgoss..."
    DGOSS_BIN="$INSTALL_DIR/dgoss"
    if curl -fsSL -o "$DGOSS_BIN" "$DGOSS_URL" 2>/dev/null; then
        chmod +x "$DGOSS_BIN"
        log_success "dgoss installed"
    else
        log_warn "Failed to download dgoss (optional)"
    fi

    # Verify installation
    if [ -x "$GOSS_BIN" ]; then
        INSTALLED_VERSION=$("$GOSS_BIN" --version 2>/dev/null | head -1 || echo "unknown")
        log_success "Goss installed successfully (version: $INSTALLED_VERSION)"
    else
        log_error "Goss installation verification failed"
        return 1
    fi

    return 0
}

# Verify all installations
verify_installations() {
    log_info "Verifying installations..."

    local all_ok=true

    if [ "$INSTALL_INSPEC" = "true" ]; then
        if command -v inspec &>/dev/null; then
            log_success "InSpec: $(inspec version 2>/dev/null || echo 'installed')"
        else
            log_error "InSpec: NOT FOUND"
            all_ok=false
        fi
    fi

    if [ "$INSTALL_GOSS" = "true" ]; then
        if command -v goss &>/dev/null; then
            log_success "Goss: $(goss --version 2>/dev/null | head -1 || echo 'installed')"
        else
            log_error "Goss: NOT FOUND"
            all_ok=false
        fi
    fi

    if [ "$all_ok" = "true" ]; then
        log_success "All verifications passed"
        return 0
    else
        log_error "Some verifications failed"
        return 1
    fi
}

# Cleanup temporary files
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
    log_success "Cleanup complete"
}

# Main execution
main() {
    echo "=========================================="
    echo "  Validation Tools Installer"
    echo "=========================================="
    echo ""

    check_root
    detect_system
    check_dependencies
    setup_directories

    INSTALL_ERRORS=0

    # Install InSpec
    if [ "$INSTALL_INSPEC" = "true" ]; then
        echo ""
        if ! install_inspec; then
            log_error "InSpec installation failed"
            INSTALL_ERRORS=$((INSTALL_ERRORS + 1))
        fi
    else
        log_info "Skipping InSpec installation"
    fi

    # Install Goss
    if [ "$INSTALL_GOSS" = "true" ]; then
        echo ""
        if ! install_goss; then
            log_error "Goss installation failed"
            INSTALL_ERRORS=$((INSTALL_ERRORS + 1))
        fi
    else
        log_info "Skipping Goss installation"
    fi

    # Verify installations
    if [ "$DO_VERIFY" = "true" ]; then
        echo ""
        verify_installations || INSTALL_ERRORS=$((INSTALL_ERRORS + 1))
    fi

    # Cleanup if requested
    if [ "$DO_CLEANUP" = "true" ]; then
        echo ""
        cleanup
    fi

    # Summary
    echo ""
    echo "=========================================="
    echo "  Installation Summary"
    echo "=========================================="
    echo ""

    if [ $INSTALL_ERRORS -eq 0 ]; then
        log_success "All installations completed successfully"
        echo ""
        echo "Installed tools:"
        [ "$INSTALL_INSPEC" = "true" ] && echo "  - InSpec: $(which inspec 2>/dev/null || echo 'not found')"
        [ "$INSTALL_GOSS" = "true" ] && echo "  - Goss: $(which goss 2>/dev/null || echo 'not found')"
        exit 0
    else
        log_error "Installation completed with $INSTALL_ERRORS error(s)"
        exit 1
    fi
}

# Run main
main
