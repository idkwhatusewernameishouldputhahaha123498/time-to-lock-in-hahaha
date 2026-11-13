# Flag Hunters Arsenal

A CTF-solving skill set for **Flag Hunters 2026** (AFKAR · IIT Delhi — Abu Dhabi). It makes Claude
classify a challenge fast and solve it correctly: a **triage router** (`ctf-triage`) that reads a
challenge and hands off to a **specialist** — `ctf-crypto`, `ctf-web`, `ctf-forensics`,
`ctf-stego`, `ctf-osint`, `ctf-rev`, `ctf-binary`, `ctf-misc` — plus an **`investigation`**
workflow for the finals' "victim's computer" murder mystery. Methodology is **clue-first** (find
the leaked artifact; brute force is last), and proven solves are bundled as **ready-to-run offline
scripts**.

> **Scope / ethics.** Everything here is for solving the **organisers' own challenge systems
> only**, which the rulebook explicitly allows (AI tools included). Attacking any other system,
> network, or website — including the university's — is out of scope and a disqualification. Keep
> it in scope.

Flag format: **`flag{...}`** (letters, numbers, underscores only).

---

## Install — pick what matches finals day (4 options)

The finals use **provided computers**. **Confirmed for FH-2026: those PCs run Claude Code in the
terminal (no admin password needed) — so Option 1 (plugin) is the finals-day path**, giving you a
real agent with direct file access to the victim's machine. Option 3 (browser-only claude.ai
skills) is the fallback if a given PC turns out to be locked down. All four paths work from this one
repo.

### 1. As a Claude Code plugin (best — one command, whole team)
Push this repo to a GitHub the team can reach, then each teammate runs (this repo is
`arvinth2007-alt/CTF-2026`):
```
/plugin marketplace add arvinth2007-alt/CTF-2026
/plugin install flag-hunters@flag-hunters-arsenal
```
Or from a local clone (no GitHub needed):
```
/plugin marketplace add /path/to/flag-hunters-arsenal
/plugin install flag-hunters@flag-hunters-arsenal
```
Verify with `/plugin` (you should see `flag-hunters` and its skills).

### 2. As personal skills (if the plugin system isn't available)
Copy the skill folders into your Claude skills directory:
```
cp -r plugins/flag-hunters/skills/* ~/.claude/skills/
```
Each `ctf-*` and `investigation` folder becomes an available skill.

### 3. Browser-only PC (no admin, no Claude Code install) — claude.ai custom skills
Do this **before** finals, from any machine; skills attach to your claude.ai account, not the
device. Each teammate does it on their own account.
```
python3 -I setup/build_web_skills.py      # -> dist/claude-ai-skills/*.zip (10 ZIPs)
```
1. claude.ai → Settings → Capabilities → turn on **Code execution and file creation**
   (may be labelled *Create and edit files*).
2. claude.ai → Customize → Skills → **+** → upload each ZIP, and make sure each is enabled.
3. On the PC: open claude.ai, start a chat, attach the challenge file, describe the challenge.

The web builds carry a short description (the uploader caps it at 200 characters) and a note
telling Claude it is in a sandbox that cannot reach live targets, so it hands you PowerShell /
DevTools commands to run on the PC instead.

**A real agent without an admin install.** Claude Code is not banned at the finals; the PCs
just can't run installers that need the admin password. Three ways around that, best first:

- **Per-user install on the PC.** The official Windows installer does not need Administrator
  (`irm https://claude.ai/install.ps1 | iex` in PowerShell; it installs into your user
  profile). Ask the organisers before installing anything on their machine, and expect that a
  locked-down lab PC may still block it.
- **GitHub Codespace workbench (browser tab only).** This repo has a `.devcontainer/`: on
  github.com open the repo → *Code → Codespaces → Create codespace*. It builds a Linux machine
  with the CTF tools, Claude Code and this plugin. Run `claude`, sign in, then drag challenge
  files from the PC into the `challenges/` folder (git-ignored). Create it and sign in the
  night before; on the day just reopen it from github.com/codespaces.
- **Claude Code on the web (claude.ai/code).** Also browser-only, but it has no direct file
  upload (files go in through a GitHub repo) and outputs come back through git. Paste
  `setup/cloud_env_setup.sh` into the environment's setup script. Skills enabled on claude.ai
  load there too.

The cloud options work on copies of files you upload and can reach the public internet; they
cannot see the PC's own disk or anything on the campus network.

> **Finals caveat (read the rulebook).** The finals rulebook says **"NO PERSONAL DEVICES ·
> COMPUTERS PROVIDED"**, so anything that runs on your own laptop (and any option that needs you to
> *upload the organisers' challenge files* to a third-party cloud) may be disallowed or out of
> scope — confirm with the organisers. The safe finals-day path is **Option 3 on the provided PC's
> browser** (skills live on your claude.ai account, not the device; nothing leaves the PC). Keep
> the laptop/Codespace/cloud options for the online **prelims** and practice.

### 4. Paste-in fallback (if there's only a plain chatbox)
Open **`FIELD_PLAYBOOK.md`** and paste it in as context (or load it as a claude.ai Project
knowledge file). It's a self-contained condensed version of the whole arsenal — the triage tree,
every category's quick checklist, the pattern table, and the flag rules.

---

## Finals-day first moves
```bash
bash preflight_check.sh      # what's installed on this machine + how to get the rest
bash setup/install.sh        # macOS / Linux (review it first)
```
**On a Windows PC** (the FH-2026 finals machines) use the PowerShell installer instead — it pulls
the system tools via winget and the Python libs via pip, no admin password needed:
```powershell
powershell -ExecutionPolicy Bypass -File setup\install_windows.ps1
```
Pwn/binary-heavy tools (full pwntools, gdb, steghide, zbar, multimon-ng) are weak on native
Windows — if you expect those, enable WSL Ubuntu the night before (`wsl --install -d Ubuntu`, needs
admin + reboot) and run `bash setup/install.sh` inside it.
Then just describe the challenge to Claude (or drop the file / paste the URL). `ctf-triage`
triggers, classifies, and routes. For the murder mystery, say you're working the victim's
computer and the `investigation` skill drives.

## What's inside
```
plugins/flag-hunters/skills/
  ctf-triage/      router + references/clue-first.md + references/playbook.md + scripts/flag_grep.py
  ctf-crypto/      classical, RSA, AES, XOR, hashes, PRNG sweep, PDF verifier
  ctf-web/         recon, SQLi, XSS, SSTI, auth bypass, Sec-Fetch replay
  ctf-forensics/   archives/nested, pcap, disk/mem, logs, zero-width decode
  ctf-stego/       image (LSB/threshold/bit-plane) + audio (spectrogram)
  ctf-osint/       geolocation, reverse image search, EXIF, public records
  ctf-rev/         static/dynamic RE, crackmes, angr template
  ctf-binary/      pwn methodology + pwntools template (organiser binaries only)
  ctf-misc/        encoding zoo, esolangs, QR, decode cascade
  investigation/   murder-mystery: enumerate the machine, tie story to flags, dispatch
FIELD_PLAYBOOK.md  portable paste-in version
preflight_check.sh / setup/install.sh
```

## Helper scripts (run standalone, mostly pure-stdlib)
`python3 -I <skill>/scripts/<name>.py ...` — e.g. `flag_grep.py` (hunt flags in any file/dir),
`prng_sweep.py`, `pdf_rc4_verify.py`, `railfence.py`, `nested_archive_peel.py`,
`zerowidth_decode.py`, `log_filter.py`, `spectrogram.py`, `image_amplify.py`, `secfetch_replay.py`,
`angr_template.py`, `pwn_template.py`, `decode_cascade.py`.

## Testing & practice
- **Regression harness (committed):** `bash tests/run_tests.sh` — self-contained checks that the
  bundled scripts still work, using generated fixtures (no challenge files needed). Run it after
  any edit. The plugin/marketplace also validate with `claude plugin validate .`.
- **Blind capability test:** `tests/BLIND_RESULTS.md` records how the arsenal did on fresh,
  previously-unseen public challenges — the honest measure (not re-solving challenges we already
  had the answers to).
- **Keep improving it:** add each new solve as a war story in `references/clue-first.md` (the
  single source of truth that `playbook.md` and `FIELD_PLAYBOOK.md` condense).
