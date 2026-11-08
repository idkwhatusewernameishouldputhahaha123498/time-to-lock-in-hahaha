#!/usr/bin/env python3
"""
hid_keyboard_decode.py - reconstruct typed text from USB HID keyboard reports.

Feed it `usb.capdata` from a pcap (hex, one 8-byte report per line):
    tshark -r cap.pcapng -Y 'usb.transfer_type==0x01' -T fields -e usb.capdata \
        | python3 -I hid_keyboard_decode.py -
Or a file / '-' for stdin. Report layout: byte0=modifiers, byte1=0, byte2..7=keycodes.
Shift = modifier & 0x22. byte2==0 => key release (skipped). Stdlib only; run with -I.

    python3 -I hid_keyboard_decode.py reports.txt            # straight decode
    python3 -I hid_keyboard_decode.py reports.txt --arrows   # track up/down-arrow line cursor
"""
import sys, re

HID = {0x28: "\n", 0x2a: "\b", 0x2b: "\t", 0x2c: " ", 0x2d: "-", 0x2e: "=",
       0x2f: "[", 0x30: "]", 0x31: "\\", 0x33: ";", 0x34: "'", 0x35: "`",
       0x36: ",", 0x37: ".", 0x38: "/"}
for i in range(0x04, 0x1e):              # a-z
    HID[i] = chr(ord('a') + i - 0x04)
for i in range(0x1e, 0x27):              # 1-9
    HID[i] = chr(ord('1') + i - 0x1e)
HID[0x27] = "0"
SHIFT = {"1": "!", "2": "@", "3": "#", "4": "$", "5": "%", "6": "^", "7": "&",
         "8": "*", "9": "(", "0": ")", "-": "_", "=": "+", "[": "{", "]": "}",
         "\\": "|", ";": ":", "'": '"', "`": "~", ",": "<", ".": ">", "/": "?"}
ARROWS = {0x4f: "right", 0x50: "left", 0x51: "down", 0x52: "up"}


def parse_reports(text):
    out = []
    for line in text.splitlines():
        h = re.sub(r"[^0-9a-fA-F]", "", line)
        if len(h) < 16:
            continue
        raw = bytes.fromhex(h)
        raw = raw[-8:] if len(raw) >= 8 else raw      # trailing 8 bytes = the report
        out.append(raw)
    return out


def char_for(keycode, mod):
    ch = HID.get(keycode)
    if ch is None:
        return None
    if mod & 0x22:                                    # L or R shift
        return SHIFT.get(ch, ch.upper())
    return ch


def decode(reports, arrows=False):
    lines = {0: []}
    cur = 0
    prev = None
    for r in reports:
        if len(r) < 3:
            continue
        mod, key = r[0], r[2]
        if key == 0 or (mod, key) == prev:            # release or auto-repeat
            prev = (mod, key) if key else None
            continue
        prev = (mod, key)
        if arrows and key in (0x51, 0x52):
            cur += 1 if key == 0x51 else -1
            lines.setdefault(cur, [])
            continue
        if key == 0x2a:                               # backspace
            if lines.get(cur):
                lines[cur].pop()
            continue
        ch = char_for(key, mod)
        if ch is not None:
            lines.setdefault(cur, []).append(ch)
    if arrows:
        return "\n".join("".join(lines[k]) for k in sorted(lines))
    return "".join(lines[0])


def main(argv):
    if "--help" in argv or "-h" in argv:
        print(__doc__)
        return 0
    arrows = "--arrows" in argv
    argv = [a for a in argv if a != "--arrows"]
    src = argv[1] if len(argv) > 1 else "-"
    text = sys.stdin.read() if src == "-" else open(src, "r", errors="replace").read()
    result = decode(parse_reports(text), arrows=arrows)
    print(result)
    for m in re.findall(r"flag\{[^}]*\}", result, re.IGNORECASE):
        print("[+] FLAG:", m)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
