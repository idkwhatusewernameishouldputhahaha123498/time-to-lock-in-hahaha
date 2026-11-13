#!/usr/bin/env bash
# install.sh - provision the CTF toolchain on a machine where you ARE allowed to install.
# Run preflight_check.sh first to see what's missing. This installs the common set.
# Review before running. It uses sudo for system packages on Linux.
#
#   bash setup/install.sh            # install everything it can
#   bash setup/install.sh --pip-only # just the Python libs (no sudo / no system pkgs)

set -uo pipefail
PIP_ONLY=0
[ "${1:-}" = "--pip-only" ] && PIP_ONLY=1

PY_LIBS="pwntools angr py7zr pikepdf pycryptodome numpy Pillow requests sympy z3-solver gmpy2 ROPgadget ropper flask-unsign lz4"

install_pip() {
  echo "== pip libs =="
  python3 -m pip install --user --upgrade pip 2>/dev/null || true
  # install individually so one failure (e.g. gmpy2 needing headers) doesn't abort the rest
  for lib in $PY_LIBS; do
    echo "-- $lib"
    python3 -m pip install --user "$lib" || echo "   (failed: $lib - may need system headers; skip or fix later)"
  done
}

install_mac() {
  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew not found. Install from https://brew.sh then re-run, or use --pip-only."
    return
  fi
  echo "== brew packages =="
  brew install python git curl jq binwalk exiftool p7zip wireshark \
    steghide zbar radare2 upx binutils gdb nmap ffuf gobuster hashcat john sqlmap \
    ffmpeg mupdf-tools qpdf multimon-ng || true
  echo "zsteg/one_gadget are Ruby gems:"
  gem install zsteg one_gadget 2>/dev/null || echo "   (gem install may need Ruby; optional)"
}

install_apt() {
  echo "== apt packages =="
  sudo apt-get update
  sudo apt-get install -y python3 python3-pip git curl jq xxd file binwalk \
    libimage-exiftool-perl foremost p7zip-full tshark steghide zbar-tools \
    radare2 upx-ucl binutils gdb nmap hashcat john sqlmap ruby \
    ffmpeg mupdf-tools qpdf multimon-ng || true
  echo "zsteg/one_gadget via gem:"
  sudo gem install zsteg one_gadget 2>/dev/null || echo "   (optional)"
  echo "ffuf/gobuster: apt may lack them; try 'go install' or snap if needed."
}

echo "CTF toolchain installer"
if [ "$PIP_ONLY" = 1 ]; then
  install_pip
else
  case "$(uname)" in
    Darwin) install_mac ;;
    Linux)
      if command -v apt-get >/dev/null 2>&1; then install_apt
      else echo "Non-apt Linux: install system pkgs manually (see preflight_check.sh), then:"; fi ;;
    MINGW*|MSYS*|CYGWIN*)
      echo "Windows (Git Bash) detected. System tools install via PowerShell + winget, not bash."
      echo "Run this instead for the full Windows toolchain:"
      echo "    powershell -ExecutionPolicy Bypass -File setup/install_windows.ps1"
      echo "Doing the pip libs here now (those work the same on Windows):" ;;
    *) echo "Unknown OS: doing pip libs only." ;;
  esac
  install_pip
fi

echo
echo "Done. Re-run 'bash preflight_check.sh' to confirm."
echo "For gdb, also install pwndbg (https://github.com/pwndbg/pwndbg) or GEF for pwn work."
