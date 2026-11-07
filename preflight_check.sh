#!/usr/bin/env bash
# preflight_check.sh - verify the CTF toolchain on a fresh (provided) machine.
# Read-only: it checks what's installed and PRINTS install commands for what's missing.
# It does NOT install anything. Run it first thing on finals day.
#
#   bash preflight_check.sh
#
# Tailors suggestions to macOS (brew) or Debian/Ubuntu (apt). Python libs via pip.

set -u
have()  { command -v "$1" >/dev/null 2>&1; }
pylib() { python3 -c "import $1" >/dev/null 2>&1; }

OS="unknown"; PKG=""
if [ "$(uname)" = "Darwin" ]; then OS="macOS"; PKG="brew install";
elif have apt-get; then OS="Debian/Ubuntu"; PKG="sudo apt-get install -y";
elif have dnf; then OS="Fedora"; PKG="sudo dnf install -y";
elif have pacman; then OS="Arch"; PKG="sudo pacman -S"; fi

GREEN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
MISSING=()

echo "== CTF preflight =="
echo "OS: $OS    package manager: ${PKG:-<none detected>}"
echo

# $1 = check type (cmd|py), $2 = name to test, $3 = human label, $4 = install hint
chk() {
  local kind="$1" name="$2" label="$3" hint="$4" ok=1
  case "$kind" in
    cmd) have "$name" || ok=0 ;;
    py)  pylib "$name" || ok=0 ;;
  esac
  if [ "$ok" = 1 ]; then
    printf "  %s[ok]%s   %s\n" "$GREEN" "$RST" "$label"
  else
    printf "  %s[--]%s   %-22s %s%s%s\n" "$RED" "$RST" "$label" "$DIM" "$hint" "$RST"
    MISSING+=("$label :: $hint")
  fi
}

echo "-- Core --"
chk cmd python3 "python3"     "$PKG python3"
chk cmd pip3    "pip3"        "$PKG python3-pip"
chk cmd git     "git"         "$PKG git"
chk cmd curl    "curl"        "$PKG curl"
chk cmd jq      "jq"          "$PKG jq"
chk cmd xxd     "xxd"         "$PKG xxd (or vim-common)"
chk cmd file    "file"        "$PKG file"

echo "-- Forensics / files --"
chk cmd binwalk  "binwalk"    "$PKG binwalk"
chk cmd exiftool "exiftool"   "$PKG libimage-exiftool-perl  (mac: brew install exiftool)"
chk cmd foremost "foremost"   "$PKG foremost"
chk cmd 7z       "7z/7za"     "$PKG p7zip-full  (mac: brew install p7zip)"
chk cmd tshark   "tshark"     "$PKG tshark  (mac: brew install wireshark)"
chk py  py7zr    "py7zr (AES-7z)"   "pip3 install py7zr"
chk py  pikepdf  "pikepdf"    "pip3 install pikepdf"

echo "-- Stego --"
chk cmd steghide "steghide"   "$PKG steghide"
chk cmd zsteg    "zsteg"      "gem install zsteg"
chk cmd zbarimg  "zbarimg"    "$PKG zbar-tools  (mac: brew install zbar)"
chk py  PIL      "Pillow"     "pip3 install Pillow"
chk py  numpy    "numpy"      "pip3 install numpy"

echo "-- Crypto --"
chk py  Crypto   "pycryptodome"  "pip3 install pycryptodome"
chk py  gmpy2    "gmpy2"      "pip3 install gmpy2"
chk py  sympy    "sympy"      "pip3 install sympy"
chk py  z3       "z3-solver"  "pip3 install z3-solver"
chk cmd sage     "sagemath"   "$PKG sagemath  (optional, heavy)"
chk cmd hashcat  "hashcat"    "$PKG hashcat"
chk cmd john     "john"       "$PKG john"

echo "-- Reverse engineering --"
chk cmd objdump  "objdump"    "$PKG binutils"
chk cmd readelf  "readelf"    "$PKG binutils"
chk cmd gdb      "gdb"        "$PKG gdb  (+ install pwndbg/GEF)"
chk cmd r2       "radare2"    "$PKG radare2"
chk cmd upx      "upx"        "$PKG upx"
chk py  angr     "angr"       "pip3 install angr"

echo "-- Binary / pwn --"
chk py  pwn      "pwntools"   "pip3 install pwntools"
chk cmd ROPgadget "ROPgadget" "pip3 install ROPgadget"
chk cmd ropper   "ropper"     "pip3 install ropper"
chk cmd one_gadget "one_gadget" "gem install one_gadget"
chk cmd checksec "checksec"   "$PKG checksec  (or pwntools provides it)"

echo "-- Web --"
chk cmd ffuf     "ffuf"       "$PKG ffuf  (or: go install github.com/ffuf/ffuf/v2@latest)"
chk cmd gobuster "gobuster"   "$PKG gobuster"
chk cmd nmap     "nmap"       "$PKG nmap"
chk cmd sqlmap   "sqlmap"     "$PKG sqlmap  (or pip3 install sqlmap)"

echo
if [ "${#MISSING[@]}" -eq 0 ]; then
  echo "${GREEN}All checked tools present. You're ready.${RST}"
else
  echo "${YEL}${#MISSING[@]} missing. Install the ones you expect to need:${RST}"
  for m in "${MISSING[@]}"; do echo "  - $m"; done
  echo
  echo "${DIM}Tip: on the provided machine you may not have sudo/brew. The bundled Python"
  echo "scripts fall back to pure stdlib where possible, so python3 alone solves a lot.${RST}"
fi
