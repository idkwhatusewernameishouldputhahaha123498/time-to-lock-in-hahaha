#!/usr/bin/env python3
# angr_template.py -- symbolic-execution solver for crackmes / keygens.
#
# WHAT IT DOES: loads a binary, symbolically explores until it reaches a SUCCESS
# path (FIND) while pruning FAILURE paths (AVOID), then prints the stdin/argv
# bytes that get there. This finds "the correct input" WITHOUT you reversing the
# check by hand -- angr's solver does the algebra.
#
# WHEN TO USE: a crackme that validates ONE input (password/key/flag) against a
# self-contained check (XOR, arithmetic, per-char constraints, a state machine).
# WHEN NOT TO: heavy loops/hashing/crypto (path explosion -> use static/dynamic
# instead), network I/O, or anti-debug. If it runs > a few minutes, stop and
# read the check in Ghidra instead.
#
# SAFE USAGE (binary is untrusted data -- angr does NOT execute it natively, it
# lifts to IR, but still run isolated):
#   python3 -I angr_template.py ./challenge
#   python3 -I angr_template.py ./challenge --argv       # input via argv[1]
#   python3 -I angr_template.py ./challenge --len 32 --printable
#
# INSTALL (do this yourself; the script will NOT auto-install):
#   python3 -m pip install angr            # pulls in claripy, cle, pyvex
#   (heavy dep; a venv is recommended:  python3 -m venv venv && . venv/bin/activate)

import argparse
import sys

try:
    import angr
    import claripy
except ImportError:
    sys.exit(
        "[!] angr not installed. Run:  python3 -m pip install angr\n"
        "    (big dependency; prefer a venv. This script will not auto-install.)"
    )

# =============================================================================
# STEP 1 -- FIND the success / failure addresses, then EDIT the two vars below.
# =============================================================================
# The cleanest, most robust way needs NO addresses at all: match on the program's
# OUTPUT (see --by-output below, enabled by default). Only fall back to addresses
# when output matching is ambiguous.
#
# To get addresses from a decompiler (Ghidra / radare2 / Binary Ninja):
#   * Open the binary, find main(), find the branch after the input check.
#   * FIND  = address of the "Correct!" / "Access granted" / winning puts/printf,
#             OR the basic block on the success side of the compare.
#   * AVOID = address of the "Wrong!" / "Try again" print, and any obvious
#             early-exit / failure blocks. More AVOIDs = faster, fewer paths.
#   * In Ghidra the address is the one in the listing margin (e.g. 00101234).
#
# PIE / ASLR note: Ghidra and angr may use different load bases. If your binary
# is PIE (checksec / `file` says "pie"), do NOT paste the raw Ghidra address --
# rebase it:   angr_addr = proj.loader.main_object.min_addr + (ghidra_addr - ghidra_image_base)
# Ghidra's image base is Window > Memory Map (often 0x100000 for PIE). The
# --by-output path sidesteps all of this, so try it first.

FIND_ADDR = 0x0          # e.g. 0x401234  -> the "Correct!" print / win block
AVOID_ADDRS = [0x0]      # e.g. [0x4011a0, 0x401210] -> "Wrong!" / exit blocks

# Strings that identify success / failure in the program's stdout (used by the
# default --by-output mode). Edit to match what the binary actually prints.
SUCCESS_MARKERS = [b"Correct", b"Congratulations", b"Access granted", b"flag{", b"Well done"]
FAILURE_MARKERS = [b"Wrong", b"Incorrect", b"Try again", b"Denied", b"nope"]


def build_find_avoid(args):
    """Return (find, avoid) suitable for simgr.explore(). Either can be an
    address, a list of addresses, or a predicate function over a state."""
    if args.by_output:
        def find(state):
            out = state.posix.dumps(1)
            return any(m in out for m in SUCCESS_MARKERS)

        def avoid(state):
            out = state.posix.dumps(1)
            return any(m in out for m in FAILURE_MARKERS)

        return find, avoid

    # Address mode (requires you to have edited FIND_ADDR / AVOID_ADDRS above).
    if FIND_ADDR == 0x0:
        sys.exit("[!] Edit FIND_ADDR/AVOID_ADDRS, or run with --by-output (default).")
    return FIND_ADDR, [a for a in AVOID_ADDRS if a]


def main():
    ap = argparse.ArgumentParser(description="angr crackme solver template")
    ap.add_argument("binary", help="path to the target binary")
    ap.add_argument("--argv", action="store_true",
                    help="feed symbolic input via argv[1] instead of stdin")
    ap.add_argument("--len", type=int, default=32,
                    help="number of symbolic input bytes (default 32)")
    ap.add_argument("--printable", action="store_true",
                    help="constrain every input byte to printable ASCII 0x20-0x7e")
    ap.add_argument("--by-address", dest="by_output", action="store_false",
                    help="use FIND_ADDR/AVOID_ADDRS instead of output matching")
    ap.add_argument("--veritesting", action="store_true",
                    help="enable veritesting (helps some branchy binaries)")
    ap.set_defaults(by_output=True)
    args = ap.parse_args()

    # auto_load_libs=False keeps angr from wandering into libc; much faster and
    # usually all you need for a self-contained check.
    proj = angr.Project(args.binary, auto_load_libs=False)

    n = args.len
    # A symbolic bitvector of n bytes -- this is the unknown input angr solves for.
    sym_input = claripy.BVS("input", n * 8)

    # ---- Choose the input channel: STDIN (default) or ARGV -------------------
    if args.argv:
        # Input arrives as argv[1]. Many crackmes: ./chall <key>
        # NOTE: we do NOT enable options.unicorn here. Unicorn accelerates
        # *concrete* execution; with fully-symbolic input it rarely helps and can
        # misbehave. Add `add_options=angr.options.unicorn` only if a binary has a
        # heavy concrete pre-amble and you've confirmed it speeds things up.
        state = proj.factory.full_init_state(args=[args.binary, sym_input])
    else:
        # Input arrives on stdin. Passing the BVS as `stdin` makes angr read
        # exactly these symbolic bytes (handles scanf/fgets/read).
        state = proj.factory.full_init_state(
            args=[args.binary],
            stdin=sym_input,
        )

    # Optional: force every byte to printable ASCII. Turn on if the solver
    # returns garbage bytes, or when the input is clearly a typed key/flag.
    if args.printable:
        for byte in sym_input.chop(8):
            state.solver.add(byte >= 0x20, byte <= 0x7e)

    # Build the simulation manager and explore.
    simgr = proj.factory.simgr(state)
    if args.veritesting:
        simgr.use_technique(angr.exploration_techniques.Veritesting())

    find, avoid = build_find_avoid(args)
    print(f"[*] exploring {args.binary}  (channel={'argv' if args.argv else 'stdin'}, "
          f"len={n}, mode={'output' if args.by_output else 'address'})")
    simgr.explore(find=find, avoid=avoid)

    # ---- Report --------------------------------------------------------------
    if not simgr.found:
        print("[!] no solution found. Try: adjust --len, flip SUCCESS/FAILURE "
              "markers, use --by-address with real addrs, add --veritesting, or "
              "the check is too heavy for symbolic execution -- reverse it by hand.")
        print(f"    stashes: {simgr}")
        return 1

    found = simgr.found[0]
    # Concretize the solved input. eval of the BVS = exact bytes; dumps(0) = what
    # actually went to stdin (equivalent, and works even for odd input plumbing).
    solution = found.solver.eval(sym_input, cast_to=bytes)
    stdin_bytes = found.posix.dumps(0)
    stdout_bytes = found.posix.dumps(1)

    print("\n[+] SOLVED INPUT")
    print("    raw bytes :", solution)
    print("    printable :", solution.split(b"\x00")[0].decode("latin-1").rstrip())
    if not args.argv:
        print("    stdin dump:", stdin_bytes)
    print("    program output:", stdout_bytes.decode("latin-1", "replace").strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
