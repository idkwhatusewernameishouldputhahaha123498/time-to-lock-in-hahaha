#!/usr/bin/env python3
"""
log_filter.py - translate prose clues into regex, AND them over a log, and
surface the real flag{...} token while ignoring decoy token formats.

WHY: "needle in a 10k-line log" challenges give you clues in English ("the
entry logged at :02 seconds, for the user whose id has these fragments in
order"). Each clue is one regex. AND them together and usually one line
survives. That line holds the token -- but decoys use `sha1:` / `sess-` /
`Bearer `; the winner is the flag{...}-shaped one. This tool does exactly that.

Stdlib only.

Examples:
    # AND two clues, auto-surface the flag token:
    python3 -I log_filter.py app.log -r ':02\\s' -r 'UserID=Am.*Ch.*th.*st\\b'

    # pull just the Token field from surviving lines:
    python3 -I log_filter.py app.log -r ':02\\s' -e 'Token=(\\S+)'

    # show count only:
    python3 -I log_filter.py app.log -r 'ERROR' -c
"""
import re
import sys
import argparse

FLAG_RE = re.compile(r"(?:flag|ﬂag|ﬁlag)\{[^}]{0,200}\}", re.IGNORECASE)

# Token shapes used as DECOYS in these challenges -- never the answer.
DECOY_PREFIXES = ("sha1:", "sha256:", "md5:", "sess-", "sess_", "session:",
                  "bearer ", "token-", "uuid:", "0x")
DECOY_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", re.I)


def is_decoy(tok: str) -> bool:
    low = tok.lower()
    if any(low.startswith(p) for p in DECOY_PREFIXES):
        return True
    if DECOY_RE.match(tok):
        return True
    return False


def main(argv):
    ap = argparse.ArgumentParser(
        description="AND-filter a log by regex and surface the flag{...} token.",
        epilog="Each -r is one clue; a line must match ALL of them (AND).")
    ap.add_argument("logfile")
    ap.add_argument("-r", "--regex", action="append", default=[],
                    help="filter regex; repeat for AND. Omit to scan every line.")
    ap.add_argument("-e", "--extract", default=None,
                    help="extractor regex with ONE capture group (e.g. 'Token=(\\S+)').")
    ap.add_argument("-i", "--ignore-case", action="store_true",
                    help="case-insensitive filtering.")
    ap.add_argument("-c", "--count", action="store_true",
                    help="print only the count of surviving lines.")
    ap.add_argument("--show-decoys", action="store_true",
                    help="also list extracted decoy tokens (default: hidden).")
    args = ap.parse_args(argv[1:])

    flags = re.I if args.ignore_case else 0
    try:
        filters = [re.compile(r, flags) for r in args.regex]
    except re.error as e:
        print(f"[!] bad filter regex: {e}")
        return 2
    extractor = None
    if args.extract:
        try:
            extractor = re.compile(args.extract, flags)
        except re.error as e:
            print(f"[!] bad extractor regex: {e}")
            return 2

    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as e:
        print(f"[!] cannot read {args.logfile}: {e}")
        return 2

    survivors = []
    for ln, line in enumerate(lines, 1):
        if all(f.search(line) for f in filters):
            survivors.append((ln, line.rstrip("\n")))

    print(f"[*] {len(survivors)}/{len(lines)} line(s) matched "
          f"{len(filters)} filter(s).")
    if args.count:
        return 0

    # Narrow output: with many survivors, don't dump thousands of lines.
    if 0 < len(survivors) <= 40:
        for ln, line in survivors:
            print(f"  {ln}: {line}")
    elif len(survivors) > 40:
        print(f"  (too many to print; add more -r clues to narrow down. "
              f"First 5:)")
        for ln, line in survivors[:5]:
            print(f"  {ln}: {line}")

    # --- surface the real token --------------------------------------------
    real_tokens = []
    decoy_tokens = []
    flag_hits = []
    for ln, line in survivors:
        for m in FLAG_RE.finditer(line):
            flag_hits.append((ln, m.group(0)))
        if extractor:
            for m in extractor.finditer(line):
                tok = m.group(1) if m.groups() else m.group(0)
                (decoy_tokens if is_decoy(tok) else real_tokens).append((ln, tok))

    print("\n==================== RESULT ====================")
    if flag_hits:
        print(f"[+] flag{{...}} token(s):")
        for ln, f in flag_hits:
            print(f"    line {ln}: {f}")
    if extractor:
        if real_tokens:
            print(f"[+] non-decoy extracted token(s):")
            for ln, t in real_tokens:
                star = "  <-- flag-shaped" if FLAG_RE.search(t) else ""
                print(f"    line {ln}: {t}{star}")
        if args.show_decoys and decoy_tokens:
            print(f"[.] decoy token(s) (ignored):")
            for ln, t in decoy_tokens:
                print(f"    line {ln}: {t}")
        elif decoy_tokens:
            print(f"[.] {len(decoy_tokens)} decoy token(s) hidden "
                  f"(--show-decoys to see).")
    if not flag_hits and not (extractor and real_tokens):
        print("[-] No flag-shaped token in survivors. Loosen/rephrase a clue, "
              "or the token may be encoded (base64/hex) -- decode then re-grep.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
