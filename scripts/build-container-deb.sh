#!/bin/bash
# build-container-deb.sh — Build DEB packages inside a container
#
# Expected env vars:
#   PLATFORM_ID       — e.g. "debian-12", "ubuntu-22.04"
#   PLATFORM_CODENAME — e.g. "bookworm", "jammy"
#   EXPECTED_ARCH     — "amd64" or "arm64"
#   MODULE_VERSION    — e.g. "1.1.0" or "1.1.0-dev+abc1234"
#
# Expected mounts:
#   /source    — source tarball (valkey-ldap-VERSION.tar.gz)
#   /packaging — packaging/ directory from repo
#   /scripts   — scripts/ directory from repo
#   /output    — directory for built DEBs
set -euo pipefail

echo "==> Building DEB for valkey-ldap ${MODULE_VERSION} on ${PLATFORM_ID} (${EXPECTED_ARCH})"

export DEBIAN_FRONTEND=noninteractive

# ── Step 1: Install build dependencies ──
apt-get update
apt-get install -y --no-install-recommends \
    build-essential \
    debhelper-compat \
    devscripts \
    libssl-dev \
    libclang-dev \
    curl \
    ca-certificates \
    pkg-config \
    fakeroot
# libldap-dev was renamed to libldap2-dev on older Debian/Ubuntu
apt-get install -y --no-install-recommends libldap-dev ||
    apt-get install -y --no-install-recommends libldap2-dev

# ── Step 2: Install Rust toolchain ──
bash /scripts/install-rust-toolchain.sh
. /usr/local/cargo/env

# ── Step 3: Extract source and set up debian/ ──
DEB_VERSION=$(echo "$MODULE_VERSION" | tr - '~')

BUILDDIR="/tmp/build"
mkdir -p "$BUILDDIR"
cd "$BUILDDIR"

tar xzf /source/valkey-ldap-${MODULE_VERSION}.tar.gz
SRCDIR="$BUILDDIR/valkey-ldap-${MODULE_VERSION}"
cd "$SRCDIR"

# Copy debian packaging into source
cp -r /packaging/debian .

# On older distros that need the compat file, keep it; on newer ones
# debhelper-compat in Build-Depends is sufficient
DH_VERSION=$(dpkg-query -W -f='${Version}' debhelper 2>/dev/null || echo "0")
DH_MAJOR=$(echo "$DH_VERSION" | cut -d. -f1)
if [ "$DH_MAJOR" -ge 13 ] 2>/dev/null; then
    # debhelper >= 13 reads compat from Build-Depends, file not needed
    rm -f debian/compat
fi

# ── Step 4: Update changelog with correct version and codename ──
dch --newversion "${DEB_VERSION}-1" \
    --distribution "$PLATFORM_CODENAME" \
    --urgency medium \
    "Build for ${PLATFORM_ID} — version ${MODULE_VERSION}"

# Create orig tarball (required by quilt format)
cp /source/valkey-ldap-${MODULE_VERSION}.tar.gz \
   "$BUILDDIR/valkey-ldap_${DEB_VERSION}.orig.tar.gz"

# ── Step 5: Build ──
echo "==> Running dpkg-buildpackage"
dpkg-buildpackage -b -us -uc

# ── Step 6: Sanity checks ──
echo "==> Sanity checks"
# Match only the main package, not the -dbgsym package
DEB_FILE=$(find "$BUILDDIR" -maxdepth 1 -name "valkey-ldap_*.deb" ! -name "*-dbgsym*" | head -1)
if [ -z "$DEB_FILE" ]; then
    echo "ERROR: No DEB produced!" >&2
    exit 1
fi

# Check the .so is inside (capture output to avoid SIGPIPE with pipefail)
DEB_CONTENTS=$(dpkg-deb -c "$DEB_FILE" || true)
if ! echo "$DEB_CONTENTS" | grep -q 'libvalkey_ldap.so'; then
    echo "ERROR: libvalkey_ldap.so not found in DEB!" >&2
    exit 1
fi

# Check architecture
DEB_ARCH=$(dpkg-deb --info "$DEB_FILE" | grep '^ Architecture:' | awk '{print $2}')
if [ "$DEB_ARCH" != "$EXPECTED_ARCH" ]; then
    echo "ERROR: Expected arch ${EXPECTED_ARCH}, got ${DEB_ARCH}" >&2
    exit 1
fi

echo "==> DEB built successfully: $(basename "$DEB_FILE")"

# ── Step 7: Copy DEBs to output ──
cp "$BUILDDIR"/valkey-ldap_*.deb /output/
cp "$BUILDDIR"/valkey-ldap_*.changes /output/ 2>/dev/null || true
cp "$BUILDDIR"/valkey-ldap_*.buildinfo /output/ 2>/dev/null || true

echo "==> Output:"
ls -la /output/valkey-ldap*
