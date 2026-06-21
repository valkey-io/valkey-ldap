#!/bin/bash
# install-rust-toolchain.sh — Install Rust toolchain for multi-arch builds
# Used by both RPM and DEB container build scripts.
set -euo pipefail

RUST_VERSION="${RUST_VERSION:-1.87.0}"
CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}"
RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"

export CARGO_HOME RUSTUP_HOME

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        RUSTUP_ARCH="x86_64-unknown-linux-gnu"
        ;;
    aarch64)
        RUSTUP_ARCH="aarch64-unknown-linux-gnu"
        ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

echo "==> Installing Rust ${RUST_VERSION} for ${RUSTUP_ARCH}"

RUSTUP_URL="https://static.rust-lang.org/rustup/dist/${RUSTUP_ARCH}/rustup-init"

curl -sSf -o /tmp/rustup-init "$RUSTUP_URL"
chmod +x /tmp/rustup-init

/tmp/rustup-init \
    --default-toolchain "$RUST_VERSION" \
    --no-modify-path \
    --profile minimal \
    -y

rm -f /tmp/rustup-init

# Make cargo/rustc available system-wide
export PATH="${CARGO_HOME}/bin:${PATH}"

echo "==> Rust installed:"
rustc --version
cargo --version

# Write an env file that other scripts can source
cat > "${CARGO_HOME}/env" <<EOF
export CARGO_HOME="${CARGO_HOME}"
export RUSTUP_HOME="${RUSTUP_HOME}"
export PATH="${CARGO_HOME}/bin:\${PATH}"
EOF

echo "==> Source ${CARGO_HOME}/env to use Rust in subsequent steps"
