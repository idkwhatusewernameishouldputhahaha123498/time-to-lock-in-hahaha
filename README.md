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

## Install — pick what matches finals day (3 options)

The finals use **provided computers**, so we don't yet know exactly what's on them. All three
paths work from this one repo; set up #1 for practice now, and you're covered either way.

### 1. As a Claude Code plugin (best — one command, whole team)
Push this repo to a GitHub the team can reach, then each teammate runs:
```
/plugin marketplace add <your-org>/flag-hunters-arsenal
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

### 3. Paste-in fallback (if there's only a browser / a plain chatbox)
Open **`FIELD_PLAYBOOK.md`** and paste it in as context (or load it as a claude.ai Project
knowledge file). It's a self-contained condensed version of the whole arsenal — the triage tree,
every category's quick checklist, the pattern table, and the flag rules.

---

## Finals-day first moves
```bash
bash preflight_check.sh      # what's installed on this machine + how to get the rest
bash setup/install.sh        # only if you're allowed to install (review it first)
```
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

## Practice before finals (13 Nov)
1. Confirm it reproduces the **already-solved** challenges in `~/CTF/*` fast (the sanity check).
2. Run it on fresh public challenges (picoCTF-style) to tune speed, triage accuracy, hint
   discipline. The arsenal improves as you add new war stories to `references/clue-first.md`.
