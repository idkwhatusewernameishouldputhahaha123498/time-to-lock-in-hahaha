#!/usr/bin/env python3
"""
esolang.py - run the esolangs that actually show up in CTF misc: Brainfuck and Ook!.

Brainfuck and Ook! are the common ones (a wall of +-<>[]. or of "Ook. Ook?"). This
runs them with a step cap so a buggy/looping program can't hang you.

Usage:
    python3 -I esolang.py bf  "<program or ->"  [--input STR] [--steps N]
    python3 -I esolang.py ook "<program or ->"  [--input STR] [--steps N]
    cat prog.bf | python3 -I esolang.py bf -

Other esolangs you may meet (not run here): Whitespace (space/tab/newline only -
use an online interp), Malbolge (use a solver), Piet (an image - use npiet),
Rockstar (song-like prose - use the rockstar interpreter). decode_cascade.py
handles pure ENCODINGS; this handles the two common programming esolangs.
"""
import sys

DEFAULT_STEPS = 50_000_000


def run_bf(program, input_data=b"", max_steps=DEFAULT_STEPS):
    code = [c for c in program if c in "+-<>[],."]
    # precompute bracket matches
    stack, match = [], {}
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                raise ValueError(f"unmatched ] at {i}")
            j = stack.pop()
            match[i] = j
            match[j] = i
    if stack:
        raise ValueError(f"unmatched [ at {stack[-1]}")

    tape = bytearray(30000)
    ptr = ip = inp = steps = 0
    out = bytearray()
    while ip < len(code):
        steps += 1
        if steps > max_steps:
            raise RuntimeError(f"step cap {max_steps} hit (likely an infinite loop)")
        c = code[ip]
        if c == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif c == ">":
            ptr += 1
            if ptr >= len(tape):
                tape.extend(b"\x00" * 30000)
        elif c == "<":
            ptr -= 1
            if ptr < 0:
                raise RuntimeError("pointer moved left of tape start")
        elif c == ".":
            out.append(tape[ptr])
        elif c == ",":
            tape[ptr] = input_data[inp] if inp < len(input_data) else 0
            inp += 1
        elif c == "[":
            if tape[ptr] == 0:
                ip = match[ip]
        elif c == "]":
            if tape[ptr] != 0:
                ip = match[ip]
        ip += 1
    return bytes(out)


def ook_to_bf(program):
    """Map Ook! tokens to Brainfuck. Ook pairs: .? ?. .. !! !. .! !? ?!"""
    toks = program.replace("Ook", "").split()
    pairs = {".?": ">", "?.": "<", "..": "+", "!!": "-",
             "!.": ".", ".!": ",", "!?": "[", "?!": "]"}
    if len(toks) % 2:
        toks = toks[:-1]
    bf = []
    for i in range(0, len(toks), 2):
        bf.append(pairs.get(toks[i] + toks[i + 1], ""))
    return "".join(bf)


def _read(arg):
    return sys.stdin.read() if arg == "-" else arg


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    mode = argv[0]
    rest = argv[1:]
    opts = {"--input": "", "--steps": DEFAULT_STEPS}
    pos = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in opts:
            if i + 1 >= len(rest):
                print(f"{a} needs a value", file=sys.stderr); return 2
            opts[a] = int(rest[i + 1]) if a == "--steps" else rest[i + 1]
            i += 2; continue
        pos.append(a); i += 1
    program = _read(pos[0]) if pos else sys.stdin.read()
    input_data = opts["--input"].encode("latin-1")

    try:
        if mode == "bf":
            out = run_bf(program, input_data, opts["--steps"])
        elif mode == "ook":
            out = run_bf(ook_to_bf(program), input_data, opts["--steps"])
        else:
            print(f"unknown mode {mode!r}; use bf|ook", file=sys.stderr)
            return 2
    except (ValueError, RuntimeError) as ex:
        print(f"[!] {ex}", file=sys.stderr)
        return 1

    sys.stdout.buffer.write(out)
    if not out.endswith(b"\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
