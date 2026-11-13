#!/usr/bin/env bash
# cloud_env_setup.sh - setup script for a "Claude Code on the web" environment (claude.ai/code).
#
# Use when the challenge PC is browser-only (no admin, no Claude Code install): cloud sessions
# give you real Claude Code on an Ubuntu VM from a browser tab. Paste this file into the
# environment's "Setup script" box (claude.ai/code > environment settings). It runs as root on
# Ubuntu 24.04 before the session starts and the result is cached.
#
# Kept lean on purpose: a setup script that runs longer than ~5 minutes is not cached. Heavy,
# rarely-needed tools (angr, hashcat, sqlmap) are left out - install them in-session if needed.
# Each package installs on its own so one bad name or failed build cannot abort the rest.

set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

APT_PKGS="python3 python3-pip file xxd binutils unzip p7zip-full binwalk foremost libimage-exiftool-perl
  steghide zbar-tools tshark ffmpeg sox qpdf mupdf-tools upx-ucl
  gdb ltrace strace netcat-openbsd john ruby ruby-dev build-essential"

PY_LIBS="pycryptodome sympy gmpy2 z3-solver Pillow numpy scipy py7zr pikepdf requests
  pwntools flask-unsign lz4"

FAILED=""

$SUDO apt-get update -qq || echo "apt-get update failed (network access level too low?)"
for pkg in $APT_PKGS; do
  $SUDO apt-get install -y -qq --no-install-recommends "$pkg" >/dev/null 2>&1 || FAILED="$FAILED apt:$pkg"
done

# zsteg is a Ruby gem (PNG/BMP LSB scanner); optional.
$SUDO gem install zsteg --no-document >/dev/null 2>&1 || FAILED="$FAILED gem:zsteg"

# Ubuntu 24.04 marks system Python as externally managed; this VM is disposable, so override.
for lib in $PY_LIBS; do
  python3 -m pip install --quiet --break-system-packages "$lib" >/dev/null 2>&1 \
    || python3 -m pip install --quiet "$lib" >/dev/null 2>&1 \
    || FAILED="$FAILED pip:$lib"
done

echo "cloud_env_setup: done.${FAILED:+ FAILED:$FAILED}"
exit 0
