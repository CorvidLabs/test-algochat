#!/bin/bash
#
# Cross-implementation test runner for AlgoChat
#
# Usage:
#   ./tests/run-all.sh          # Run all tests
#   ./tests/run-all.sh crypto   # Run only crypto tests
#   ./tests/run-all.sh localnet # Run only localnet tests
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}! $1${NC}"
}

print_skip() {
    echo -e "${YELLOW}⊘ $1${NC}"
}

# Test result counters
SUITES_PASSED=0
SUITES_FAILED=0
SUITES_SKIPPED=0

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check Swift
    if command -v swift &> /dev/null; then
        SWIFT_VERSION=$(swift --version 2>&1 | head -1)
        print_success "Swift: $SWIFT_VERSION"
    else
        print_error "Swift not found"
        exit 1
    fi

    # Check Bun
    if command -v bun &> /dev/null; then
        BUN_VERSION=$(bun --version)
        print_success "Bun: v$BUN_VERSION"
    else
        print_error "Bun not found"
        echo "  Install: curl -fsSL https://bun.sh/install | bash"
        exit 1
    fi

    # Check algokit (optional for localnet tests)
    if command -v algokit &> /dev/null; then
        ALGOKIT_VERSION=$(algokit --version 2>&1 | head -1)
        print_success "AlgoKit: $ALGOKIT_VERSION"
    else
        print_warning "AlgoKit not found (needed for localnet tests)"
    fi
}

# Install dependencies
install_deps() {
    print_header "Installing Dependencies"

    echo "Installing TypeScript dependencies..."
    bun install

    echo ""
    echo "Resolving Swift dependencies..."
    swift package resolve
}

# Run Swift crypto tests
run_swift_crypto() {
    print_header "Swift Crypto Tests"
    swift run TestAlgoChat crypto
}

# Run TypeScript crypto tests
run_ts_crypto() {
    print_header "TypeScript Crypto Tests"
    bun test ts/crypto.test.ts
}

# Check if localnet is running
check_localnet() {
    curl -s http://localhost:4001/health > /dev/null 2>&1
}

# Run localnet tests
run_localnet_tests() {
    print_header "Localnet Integration Tests"

    if ! check_localnet; then
        print_warning "Localnet not running"
        echo ""
        echo "To run localnet tests:"
        echo "  1. algokit localnet start"
        echo "  2. ./tests/run-all.sh localnet"
        echo ""
        return 1
    fi

    print_success "Localnet is running"
    echo ""

    # Run Swift localnet tests first (sends a message)
    echo "Running Swift localnet tests..."
    swift run TestAlgoChat localnet

    echo ""

    # Run TypeScript localnet tests (reads Swift message, sends its own)
    echo "Running TypeScript localnet tests..."
    bun test ts/localnet.test.ts
}

# Print test vectors
print_vectors() {
    print_header "Test Vectors"
    swift run TestAlgoChat vectors
}

# Main
main() {
    local command="${1:-all}"

    case "$command" in
        prereq|prerequisites)
            check_prerequisites
            ;;
        install)
            check_prerequisites
            install_deps
            ;;
        vectors)
            print_vectors
            ;;
        crypto)
            check_prerequisites
            install_deps
            run_swift_crypto
            run_ts_crypto
            ;;
        localnet)
            check_prerequisites
            install_deps
            run_localnet_tests
            ;;
        all)
            check_prerequisites
            install_deps

            if run_swift_crypto; then
                SUITES_PASSED=$((SUITES_PASSED + 1))
            else
                SUITES_FAILED=$((SUITES_FAILED + 1))
            fi

            if run_ts_crypto; then
                SUITES_PASSED=$((SUITES_PASSED + 1))
            else
                SUITES_FAILED=$((SUITES_FAILED + 1))
            fi

            if check_localnet; then
                if run_localnet_tests; then
                    SUITES_PASSED=$((SUITES_PASSED + 1))
                else
                    SUITES_FAILED=$((SUITES_FAILED + 1))
                fi
            else
                SUITES_SKIPPED=$((SUITES_SKIPPED + 1))
                print_skip "Localnet tests: Skipped (localnet not running)"
            fi

            print_header "Summary"
            print_success "Passed: $SUITES_PASSED"
            if [ "$SUITES_FAILED" -gt 0 ]; then
                print_error "Failed: $SUITES_FAILED"
            else
                echo "Failed: $SUITES_FAILED"
            fi
            if [ "$SUITES_SKIPPED" -gt 0 ]; then
                print_skip "Skipped: $SUITES_SKIPPED"
            else
                echo "Skipped: $SUITES_SKIPPED"
            fi

            if [ "$SUITES_FAILED" -gt 0 ]; then
                exit 1
            fi
            ;;
        *)
            echo "Usage: $0 {prereq|install|vectors|crypto|localnet|all}"
            exit 1
            ;;
    esac
}

main "$@"
