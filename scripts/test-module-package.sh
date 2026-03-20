#!/bin/bash
# test-module-package.sh — Post-install test for valkey-ldap packages
#
# Auto-detects RPM vs DEB. Tests:
#   1. Package installs cleanly
#   2. libvalkey_ldap.so exists at expected path
#   3. Valid ELF shared object
#   4. Correct architecture
#   5. Module entry point symbol present
#   6. Package removes cleanly
#
# Expected env vars:
#   PACKAGE_FILE  — path to the .rpm or .deb file
#   EXPECTED_ARCH — expected architecture (x86_64/aarch64 for RPM, amd64/arm64 for DEB)
#
# Expected mounts:
#   /packages — directory containing the package file
set -euo pipefail

PASS=0
FAIL=0
TOTAL=0

check() {
    local desc="$1"
    shift
    TOTAL=$((TOTAL + 1))
    echo -n "  TEST ${TOTAL}: ${desc} ... "
    if "$@"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

PKG_PATH="/packages/${PACKAGE_FILE}"

if [ ! -f "$PKG_PATH" ]; then
    echo "ERROR: Package file not found: ${PKG_PATH}" >&2
    exit 1
fi

# Detect package type
case "$PACKAGE_FILE" in
    *.rpm)
        PKG_TYPE="rpm"
        MODULE_PATH="/usr/lib64/valkey/modules/libvalkey_ldap.so"
        ;;
    *.deb)
        PKG_TYPE="deb"
        MODULE_PATH="/usr/lib/valkey/modules/libvalkey_ldap.so"
        ;;
    *)
        echo "ERROR: Unknown package type: ${PACKAGE_FILE}" >&2
        exit 1
        ;;
esac

echo "==> Testing ${PKG_TYPE} package: ${PACKAGE_FILE}"
echo "    Expected arch: ${EXPECTED_ARCH}"
echo ""

# ── Install test utilities (file, binutils) ──
if [ "$PKG_TYPE" = "rpm" ]; then
    yum install -y file binutils &>/dev/null || dnf install -y file binutils &>/dev/null || true
else
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq &>/dev/null
    apt-get install -y --no-install-recommends file binutils &>/dev/null
fi

# ── Test 1: Package installs cleanly ──
install_deb() {
    dpkg -i "$PKG_PATH" 2>/dev/null || apt-get install -f -y
    # Verify it's actually installed
    dpkg -s valkey-ldap &>/dev/null
}
if [ "$PKG_TYPE" = "rpm" ]; then
    check "Package installs cleanly" rpm -ivh --nodeps "$PKG_PATH"
else
    check "Package installs cleanly" install_deb
fi

# ── Test 2: Module file exists ──
check "libvalkey_ldap.so exists" test -f "$MODULE_PATH"

# ── Test 3: Valid ELF shared object ──
check "Valid ELF shared object" bash -c "file '$MODULE_PATH' | grep -q 'ELF.*shared object'"

# ── Test 4: Correct architecture ──
check_arch() {
    local file_output
    file_output=$(file "$MODULE_PATH")
    case "$EXPECTED_ARCH" in
        x86_64|amd64)
            echo "$file_output" | grep -qE 'x86-64|x86_64'
            ;;
        aarch64|arm64)
            echo "$file_output" | grep -qE 'ARM aarch64|aarch64'
            ;;
        *)
            echo "Unknown expected arch: $EXPECTED_ARCH" >&2
            return 1
            ;;
    esac
}
check "Correct architecture (${EXPECTED_ARCH})" check_arch

# ── Test 5: Module entry point symbol present ──
check_entry_point() {
    # Check for either ValkeyModule_OnLoad or RedisModule_OnLoad
    nm -D "$MODULE_PATH" 2>/dev/null | grep -qE 'ValkeyModule_OnLoad|RedisModule_OnLoad'
}
check "Module entry point symbol present" check_entry_point

# ── Test 6: Package removes cleanly ──
if [ "$PKG_TYPE" = "rpm" ]; then
    PKG_INSTALLED=$(rpm -qa | grep valkey-ldap | head -1)
    check "Package removes cleanly" rpm -e "$PKG_INSTALLED"
else
    check "Package removes cleanly" dpkg -r valkey-ldap
fi

# ── Summary ──
echo ""
echo "==> Results: ${PASS}/${TOTAL} passed, ${FAIL} failed"
if [ $FAIL -gt 0 ]; then
    exit 1
fi
echo "==> All tests passed!"
