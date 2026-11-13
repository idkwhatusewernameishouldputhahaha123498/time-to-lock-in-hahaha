#!/usr/bin/env python3
"""Build claude.ai-uploadable skill ZIPs from the plugin's skills.

Why this exists: on a browser-only machine (no Claude Code install) the arsenal can still be
loaded into claude.ai as custom skills (Customize > Skills > + > upload). The web uploader is
stricter than Claude Code:
  * description must be <= 200 characters (ours are 250-620, tuned for Claude Code)
  * the ZIP root must be a single folder whose name equals the skill name
So this script writes one ZIP per skill with a short description and a small "sandbox mode"
note, leaving the Claude Code originals untouched.

Usage:  python3 -I setup/build_web_skills.py            # -> dist/claude-ai-skills/*.zip
"""
import re
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILLS = REPO / "plugins" / "flag-hunters" / "skills"
OUT = REPO / "dist" / "claude-ai-skills"
MAX_DESC = 200
MAX_NAME = 64

# Short, trigger-dense descriptions for the web uploader. No colons, quotes or angle brackets,
# so they stay valid as plain YAML scalars.
DESCRIPTIONS = {
    "ctf-triage": (
        "START HERE for any CTF challenge, flag hunt or find-the-flag task. Classifies the "
        "challenge (file, URL, text, screenshot), applies the clue-first method, routes to the "
        "right ctf specialist skill."
    ),
    "ctf-crypto": (
        "Solve CTF crypto - ciphertext, base64 or hex blobs, classical ciphers, XOR, RSA (n e c "
        "or pem), AES, hashes, leaked PRNG seeds or timestamps. Decode cascade, clue mining, "
        "offline verifier."
    ),
    "ctf-web": (
        "Solve CTF web challenges - a URL, login page, cookies, robots.txt, admin panel, API "
        "endpoint, SQLi, XSS, SSTI, JWT, IDOR, LFI, SSRF, auth bypass, default creds. "
        "Curl-first recon."
    ),
    "ctf-forensics": (
        "CTF forensics for any provided file - zip, 7z, rar, pcap, disk or memory dump, PDF or "
        "image metadata, logs, hidden or zero-width text, carving. Greps raw bytes for the "
        "flag first."
    ),
    "ctf-stego": (
        "CTF steganography in image or audio files (PNG, JPG, BMP, GIF, WAV, MP3) - blank or "
        "washed-out images, LSB, bit planes, spectrograms, steghide, zsteg, hidden messages."
    ),
    "ctf-osint": (
        "CTF OSINT and geolocation - locate a photo, identify landmarks or street signs, EXIF "
        "GPS, username lookup, social media pivoting, whois, DNS and certificate history, Wayback."
    ),
    "ctf-rev": (
        "Reverse-engineer a CTF binary for the flag, password or key - ELF, PE, exe, crackme, "
        "keygen, pyc, class, .NET, jar, packed or obfuscated code, disassemble, decompile."
    ),
    "ctf-binary": (
        "CTF binary exploitation (pwn) - an ELF plus nc host port, buffer overflow, format "
        "string, ROP, ret2libc, ret2win, heap bugs, canary, PIE, GDB, pwntools."
    ),
    "ctf-misc": (
        "Decode mystery blobs in CTFs - unknown encodings (base64, base32, base58, hex, morse, "
        "ROT), esolangs (Brainfuck, JSFuck, Whitespace), QR codes, JWT, protobuf, pickle, "
        "logic puzzles."
    ),
    "investigation": (
        "Finals murder-mystery workflow - investigate a victim's computer or whole system, "
        "follow the visual-novel story, hunt multiple flags across files, accounts, messages "
        "and browser data."
    ),
}

SANDBOX_NOTE = """\
> **Browser / sandbox mode (read first).** This copy of the skill is built for claude.ai and
> cloud sessions. You are running in a remote Linux sandbox, **not** on the challenge machine.
> The user is on a locked-down Windows PC with only a browser (no admin, nothing installable)
> and gets challenge files to you by uploading them.
> - Bundled scripts live next to this SKILL.md (`scripts/...`); sibling skills (`ctf-*`,
>   `investigation`) sit in the same parent directory. Run scripts by absolute path.
> - Work on the files the user uploaded; save anything the user should look at (images,
>   decoded files) as an output file they can open.
> - Assume you **cannot reach challenge servers, `nc` services or the campus network** unless a
>   quick probe proves otherwise (a cloud session with full network access can reach public
>   HTTP hosts; the claude.ai chat sandbox cannot). When a live target is out of reach, never
>   invent its response: give the user exact commands to run on their PC and ask them to paste
>   the output or upload the saved response. No-admin Windows options: PowerShell
>   `curl.exe -i -s URL`, `curl.exe -o out.bin URL`, `Get-FileHash`, `Format-Hex`,
>   `certutil -decode`, `tar -xf`; or browser DevTools (Network tab "Copy as cURL",
>   Application tab for cookies/storage, Console `fetch`).
> - Tool hints below that say `brew install ...` do not apply here. Prefer pure Python; try
>   `pip install <pkg>` when a library is needed; if a native tool is missing, reimplement the
>   step in Python rather than stopping.
> - Scope is unchanged: organisers' challenge systems only.

"""

FRONTMATTER = re.compile(r"\A---\n.*?\n---\n", re.S)


def build_skill(src: Path) -> Path:
    name = src.name
    desc = DESCRIPTIONS[name]
    if len(desc) > MAX_DESC:
        raise SystemExit(f"{name}: description is {len(desc)} chars (max {MAX_DESC})")
    if len(name) > MAX_NAME or not re.fullmatch(r"[a-z0-9-]+", name):
        raise SystemExit(f"{name}: invalid skill name for the web uploader")

    text = (src / "SKILL.md").read_text(encoding="utf-8")
    if not FRONTMATTER.match(text):
        raise SystemExit(f"{name}: SKILL.md has no YAML frontmatter")
    body = FRONTMATTER.sub("", text, count=1)
    web_md = f"---\nname: {name}\ndescription: {desc}\n---\n\n{SANDBOX_NOTE}{body.lstrip()}"

    zpath = OUT / f"{name}.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{name}/SKILL.md", web_md)
        for f in sorted(src.rglob("*")):
            rel = f.relative_to(src)
            if not f.is_file() or rel == Path("SKILL.md"):
                continue
            if "__pycache__" in rel.parts or f.name == ".DS_Store" or f.suffix in {".pyc", ".pyo"}:
                continue
            z.write(f, f"{name}/{rel.as_posix()}")
    return zpath


def main() -> int:
    skills = sorted(p for p in SKILLS.iterdir() if (p / "SKILL.md").is_file())
    missing = [p.name for p in skills if p.name not in DESCRIPTIONS]
    if missing:
        raise SystemExit(f"no web description defined for: {', '.join(missing)}")
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.zip"):
        old.unlink()
    for src in skills:
        zpath = build_skill(src)
        with zipfile.ZipFile(zpath) as z:
            n = len(z.namelist())
        print(f"  {zpath.name:22} {zpath.stat().st_size:>7} bytes  {n:>2} files  "
              f"desc {len(DESCRIPTIONS[src.name])}/{MAX_DESC}")
    print(f"\n{len(skills)} ZIPs in {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
