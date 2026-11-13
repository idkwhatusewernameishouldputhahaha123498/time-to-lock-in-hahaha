<#
  install_windows.ps1 - provision the CTF toolchain on a Windows PC (the finals machine).

  Claude Code runs in the terminal on the provided Windows PCs, so this is the finals-day
  installer. It uses winget for system tools and pip for the Python libs. Run it in PowerShell:

      powershell -ExecutionPolicy Bypass -File setup\install_windows.ps1
      powershell -ExecutionPolicy Bypass -File setup\install_windows.ps1 -PipOnly   # just Python libs

  No admin password is required for winget per-user installs or for pip --user. A few tools
  (pwntools runtime, steghide, zbar, multimon-ng, john-jumbo, gobuster) are painful or partial
  on native Windows - for pwn/binary-heavy work, enable WSL Ubuntu (see the note at the end) and
  run setup/install.sh inside it. Everything else below works natively.
#>
param([switch]$PipOnly)

$ErrorActionPreference = "Continue"

# Python libs - identical set to setup/install.sh. Installed individually so one failure
# (e.g. a missing wheel) doesn't abort the rest.
$PyLibs = @(
  "pwntools","angr","py7zr","pikepdf","pycryptodome","numpy","Pillow","requests",
  "sympy","z3-solver","gmpy2","ROPgadget","ropper","flask-unsign","lz4",
  "binwalk","pyzbar"   # binwalk & pyzbar are pip-installable on Windows (native binwalk/zbar are not)
)

function Install-PyLibs {
  Write-Host "== pip libs ==" -ForegroundColor Cyan
  python -m pip install --user --upgrade pip 2>$null
  foreach ($lib in $PyLibs) {
    Write-Host "-- $lib"
    python -m pip install --user $lib
    if ($LASTEXITCODE -ne 0) {
      Write-Host "   (failed: $lib - may need a C toolchain or a prebuilt wheel; skip or fix later)" -ForegroundColor Yellow
    }
  }
}

# winget id -> human label. Skipped cleanly if winget or the package is unavailable.
$WingetPkgs = [ordered]@{
  "Python.Python.3.12"                 = "Python 3.12"
  "Git.Git"                            = "git"
  "jqlang.jq"                          = "jq"
  "7zip.7zip"                          = "7-Zip"
  "OliverBetz.ExifTool"                = "exiftool"
  "WiresharkFoundation.Wireshark"      = "Wireshark/tshark"
  "Insecure.Nmap"                      = "nmap"
  "radareorg.radare2"                  = "radare2"
  "Gyan.FFmpeg"                        = "ffmpeg"
  "UPX.UPX"                            = "upx"
  "hashcat.hashcat"                    = "hashcat"
  "qpdf.qpdf"                          = "qpdf"
  "SQLite.SQLite"                      = "sqlite3"
  "RubyInstallerTeam.Ruby.3.3"         = "Ruby (for zsteg/one_gadget gems)"
}

function Install-Winget {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "winget not found. Install 'App Installer' from the Microsoft Store, or run -PipOnly." -ForegroundColor Yellow
    Write-Host "Alternatives: scoop (https://scoop.sh) or choco (https://chocolatey.org) with equivalent package names." -ForegroundColor Yellow
    return
  }
  Write-Host "== winget packages ==" -ForegroundColor Cyan
  foreach ($id in $WingetPkgs.Keys) {
    Write-Host ("-- {0} ({1})" -f $WingetPkgs[$id], $id)
    winget install --id $id -e --accept-package-agreements --accept-source-agreements --silent 2>$null
  }
  Write-Host "zsteg / one_gadget are Ruby gems (after Ruby installs, reopen the shell):" -ForegroundColor Cyan
  Write-Host "    gem install zsteg one_gadget"
}

Write-Host "CTF toolchain installer (Windows)" -ForegroundColor Green
if ($PipOnly) {
  Install-PyLibs
} else {
  Install-Winget
  Install-PyLibs
}

Write-Host ""
Write-Host "Done. Re-run the preflight to confirm:" -ForegroundColor Green
Write-Host "    bash preflight_check.sh        # if you have Git Bash"
Write-Host "    (or just test tools individually: exiftool -ver; python -c 'import pwn')"
Write-Host ""
Write-Host "HARD-ON-WINDOWS tools (steghide, zbarimg, multimon-ng, john-jumbo, gobuster, and" -ForegroundColor Yellow
Write-Host "full pwntools/gdb for pwn): the robust fix is WSL Ubuntu, then run the Linux installer:" -ForegroundColor Yellow
Write-Host "    wsl --install -d Ubuntu        # needs admin + a reboot; do this the night before"
Write-Host "    # inside Ubuntu:  bash setup/install.sh"
Write-Host "If WSL is blocked, pyzbar covers QR/barcodes and binwalk is pip-installed above; for" -ForegroundColor Yellow
Write-Host "pwn challenges without WSL, fall back to the browser claude.ai path or a teammate's Linux." -ForegroundColor Yellow
