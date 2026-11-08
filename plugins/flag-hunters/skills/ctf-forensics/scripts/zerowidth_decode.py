#!/usr/bin/env python3
"""
zerowidth_decode.py - extract invisible / zero-width / unicode-tag characters
from a file and brute the common stego bit-mappings to recover hidden text.

WHY: "Now You See Me"-style challenges hide a message in characters that render
to nothing: ZWSP, ZWNJ, ZWJ, BOM, word-joiner. A run of them encodes BINARY ->
ASCII. You rarely know which char means 0 and which means 1, so this tries BOTH
orderings for every pair of symbols actually present, both bit orders (MSB/LSB),
and also decodes the Unicode TAG block (U+E0000..U+E007F), which maps straight
to ASCII by subtracting 0xE0000. Homoglyph/tag presence is reported too.

Stdlib only. Run isolated so a planted module can't hijack imports.

Usage:
    python3 -I zerowidth_decode.py <file>
"""
import sys
import unicodedata

# The invisible "zero-width family" most used for stego.
ZW_NAMES = {
    0x200B: "ZWSP (zero-width space)",
    0x200C: "ZWNJ (zero-width non-joiner)",
    0x200D: "ZWJ (zero-width joiner)",
    0x2060: "WORD JOINER",
    0xFEFF: "BOM / zero-width no-break space",
    0x200E: "LRM (left-to-right mark)",
    0x200F: "RLM (right-to-left mark)",
    0x061C: "ALM (arabic letter mark)",
    0x00AD: "SOFT HYPHEN",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
}
# Unicode TAG block: direct ASCII carrier (also used in emoji tag sequences).
TAG_START, TAG_END = 0xE0000, 0xE007F

# Variation Selectors ("emoji smuggling"): one invisible selector carries one byte.
#   byte 0..15  -> U+FE00 + byte      (VS1..VS16)
#   byte 16..255-> U+E0100 + (byte-16)(Variation Selectors Supplement)
VS16_START, VS16_END = 0xFE00, 0xFE0F
VSSUP_START, VSSUP_END = 0xE0100, 0xE01EF


def vs_to_byte(cp):
    if VS16_START <= cp <= VS16_END:
        return cp - VS16_START            # 0..15
    if VSSUP_START <= cp <= VSSUP_END:
        return cp - VSSUP_START + 16      # 16..255
    return None


# A few homoglyphs worth flagging (Cyrillic/Greek look-alikes).
HOMOGLYPHS = {
    0x0430: "CYRILLIC a", 0x0435: "CYRILLIC e", 0x043E: "CYRILLIC o",
    0x0440: "CYRILLIC p", 0x0441: "CYRILLIC c", 0x0445: "CYRILLIC x",
    0x0455: "CYRILLIC s", 0x0456: "CYRILLIC i", 0x0410: "CYRILLIC A",
    0x0391: "GREEK Alpha", 0x039F: "GREEK Omicron", 0x0392: "GREEK Beta",
}


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\n\r\t")
    return ok / len(s)


def bits_to_text(bits: str, msb_first=True) -> str:
    out = []
    for i in range(0, len(bits) - 7, 8):
        byte = bits[i:i + 8]
        if len(byte) < 8:
            break
        if not msb_first:
            byte = byte[::-1]
        out.append(chr(int(byte, 2)))
    return "".join(out)


def report_candidate(label, text):
    flag = "flag{" in text.lower() or "ﬂag{" in text.lower()
    ratio = printable_ratio(text)
    if flag or ratio >= 0.85:
        tag = "  <<< FLAG" if flag else ""
        preview = text if len(text) <= 300 else text[:300] + "..."
        print(f"[decode] {label} (printable={ratio:.0%}){tag}")
        print(f"         {preview!r}")
        return flag
    return False


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]
    try:
        with open(path, "r", encoding="utf-8", errors="surrogatepass") as fh:
            text = fh.read()
    except Exception:
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "ignore")

    cps = [ord(c) for c in text]

    # --- inventory -----------------------------------------------------------
    zw_present = {}
    tag_chars = []
    vs_chars = []
    homo = {}
    for cp in cps:
        if cp in ZW_NAMES:
            zw_present[cp] = zw_present.get(cp, 0) + 1
        if TAG_START <= cp <= TAG_END:
            tag_chars.append(cp)
        if vs_to_byte(cp) is not None:
            vs_chars.append(cp)
        if cp in HOMOGLYPHS:
            homo[cp] = homo.get(cp, 0) + 1

    print(f"[*] file: {path}  ({len(cps)} codepoints)")
    if zw_present:
        print("[*] zero-width / invisible chars present:")
        for cp, n in sorted(zw_present.items()):
            print(f"      U+{cp:04X}  x{n:<6}  {ZW_NAMES[cp]}")
    if tag_chars:
        print(f"[*] Unicode TAG-block chars (U+E00xx): {len(tag_chars)}")
    if vs_chars:
        print(f"[*] Variation-selector chars (U+FE00-0F / U+E0100-E01EF): {len(vs_chars)}")
    if homo:
        print("[*] HOMOGLYPHS detected (look-alike letters) -- inspect visible text too:")
        for cp, n in sorted(homo.items()):
            print(f"      U+{cp:04X}  x{n}  {HOMOGLYPHS[cp]}")
    if not zw_present and not tag_chars and not vs_chars:
        print("[-] No zero-width or tag characters found. "
              "Try: `grep -P '[\\x{200b}-\\x{200f}\\x{2060}\\x{feff}]'`, or check "
              "whitespace stego (trailing spaces/tabs) and variation selectors.")

    found_any = False

    # --- 1) Unicode TAG block -> ASCII --------------------------------------
    if tag_chars:
        decoded = "".join(chr(cp - TAG_START) for cp in tag_chars
                          if 0x20 <= (cp - TAG_START) < 0x7F)
        if report_candidate("TAG-block -> ASCII", decoded):
            found_any = True

    # --- 1b) Variation selectors -> bytes -----------------------------------
    if vs_chars:
        raw = bytes(vs_to_byte(cp) for cp in vs_chars)
        txt = raw.decode("utf-8", "replace")
        if report_candidate("variation-selectors -> bytes", txt):
            found_any = True

    # --- 2) zero-width binary brute -----------------------------------------
    # Keep only the zero-width family stream, in document order.
    stream = [cp for cp in cps if cp in ZW_NAMES]
    distinct = sorted(set(stream))

    # Canonical mappings people actually use, tried first for readability.
    canonical = [
        (0x200B, 0x200C), (0x200C, 0x200B),
        (0x200C, 0x200D), (0x200D, 0x200C),
        (0x200B, 0x200D), (0x200D, 0x200B),
        (0xFEFF, 0x200B), (0x200B, 0xFEFF),
    ]
    tried = set()

    def attempt(zero_cp, one_cp):
        key = (zero_cp, one_cp)
        if key in tried:
            return False
        tried.add(key)
        bits = "".join("0" if cp == zero_cp else "1"
                       for cp in stream if cp in (zero_cp, one_cp))
        if len(bits) < 8:
            return False
        z = ZW_NAMES.get(zero_cp, hex(zero_cp)).split()[0]
        o = ZW_NAMES.get(one_cp, hex(one_cp)).split()[0]
        hit = False
        for msb in (True, False):
            order = "MSB" if msb else "LSB"
            txt = bits_to_text(bits, msb_first=msb)
            if report_candidate(f"0={z} 1={o} ({order}-first)", txt):
                hit = True
        return hit

    for z, o in canonical:
        if z in distinct and o in distinct:
            if attempt(z, o):
                found_any = True

    # Then every ordered pair of symbols actually present (covers odd schemes).
    for z in distinct:
        for o in distinct:
            if z != o and attempt(z, o):
                found_any = True

    # --- 3) multi-symbol (base-N) fallback ----------------------------------
    # If exactly 3 or 4 distinct symbols, try base-N digit mapping -> bytes.
    if 3 <= len(distinct) <= 4:
        base = len(distinct)
        idx = {cp: i for i, cp in enumerate(distinct)}
        digits = [idx[cp] for cp in stream]
        # pack base-N digits into a big integer, then to bytes, as a long shot
        val = 0
        for d in digits:
            val = val * base + d
        nbytes = (val.bit_length() + 7) // 8
        if nbytes:
            raw = val.to_bytes(nbytes, "big")
            txt = raw.decode("latin-1", "replace")
            if report_candidate(f"base-{base} packed -> bytes", txt):
                found_any = True

    if not found_any and (stream or tag_chars or vs_chars):
        print("[-] No printable/flag decode from the standard schemes. "
              "The payload may use a delimiter symbol, 7-bit packing, or a custom "
              "alphabet -- inspect the U+XXXX sequence above by hand.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
