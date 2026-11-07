---
name: ctf-rev
description: Reverse-engineer a CTF challenge binary to find the flag/password/key. USE WHEN given an executable/binary, ELF/PE/.exe/.so/.dll, a crackme or keygen, ".pyc/.class/.NET/.jar", obfuscated/packed code, or asked to disassemble, decompile, "find the password/key", or "what's the correct input". Fast triage first, angr only when needed.
---

# CTF Reverse Engineering

Goal: get the flag FAST. Most crackmes either embed the flag or build it at runtime.
Do not reach for heavy tools first. Work the fast path, then escalate.

## KEY INSIGHT (read this first)
- The flag is usually **decoded at runtime** (XOR / base64 / per-char math), not stored
  in plaintext. **Setting a breakpoint AFTER the decode (at `strcmp`/`printf`/`puts`)
  and reading memory beats statically deobfuscating it by hand.**
- When you only need the flag, **patch the failing branch** or **solve for the input**
  (angr). Do NOT write a full keygen unless the task explicitly asks for one.
- The "check" compares your input to an expected value. Find that compare; the
  expected value is often sitting in a register/memory right before it.

## FAST PATH — always run these first (minutes, often solves it)
```bash
file ./chall                        # ELF? PE? arch? stripped? PIE? interpreter?
chmod +x ./chall
strings -n 6 ./chall | grep -iE 'flag\{|ctf|passw|key|correct|congrat'
strings --encoding=l ./chall | grep -iE 'flag|pass'   # UTF-16LE (Windows wide strings)
nm -C ./chall 2>/dev/null | grep -iE 'main|check|verify|flag|decrypt'   # symbols
readelf -p .rodata ./chall 2>/dev/null | grep -iE 'flag|pass'          # read-only data
```
- **FLOSS** (recovers *obfuscated/stacked/decoded* strings static `strings` misses — the
  single highest-value triage tool for crackmes):
  `floss ./chall | grep -iE 'flag|pass|correct'`
- **Run it in a sandbox** to see behavior (isolated dir, it is untrusted):
  `./chall` then `echo test | ./chall` and `./chall AAAA` — note prompts, what it
  compares, success vs failure wording (you will need those strings for angr/gdb).
- If `file` says **"UPX compressed"** / packed → `upx -d ./chall -o chall.unpacked` first.

If any of the above reveals `flag{...}`, you are done — jump to **Flag extraction**.

## DECISION TREE (by what `file` reports)
- **ELF / PE / Mach-O (native)** → triage above, then **Static** + **Dynamic** below;
  **angr** if the check is self-contained math/constraints.
- **.NET / PE "Mono"/"CIL" / `.dll`** → decompile with **dnSpy** or **ILSpy** (near-source).
- **Java `.class` / `.jar`** → **CFR** / **procyon** / **jd-gui** (`cfr chall.jar`).
- **Python `.pyc` / PyInstaller `.exe`** → `pyinstxtractor`/`pyinstxtractor-ng` to unpack,
  then decompile `.pyc` with **decompyle3** (py<=3.8) or **pycdc** (newer).
- **Go (native, usually stripped, huge)** → use Ghidra + a Go function-recovery script
  (`golang_loader_assist` / IDA `go_parser`); strings & `main.main` still the entry.
- **WASM `.wasm`** → `wasm2wat chall.wasm -o chall.wat`, read the text; or `wasm-decompile`.
- **Rust (native)** → Ghidra; look for `panic`/`unwrap` strings to locate the check.
- **Packed/obfuscated native** → unpack (UPX) or dump from memory at runtime, then retriage.

## STATIC ANALYSIS — find and read the check
Tools (any one): **Ghidra** (free, best decompiler), **radare2/r2** (`r2 -A`), **objdump**,
**Binary Ninja**, **IDA**.
```bash
objdump -d -M intel ./chall | less          # quick disasm, no GUI
r2 -A ./chall                               # then: afl ; s main ; pdf ; VV (graph)
```
Workflow:
1. Locate `main` (symbols, or entry → first big user function).
2. Find where **user input meets a comparison**: `strcmp`/`memcmp`/`strncmp`, a loop of
   per-char `cmp`, or `== / !=` against a constant or a decoded buffer.
3. Trace **backwards** from the compare: what is the expected value, and how is it built
   (constant table? XOR key? arithmetic on index)? That IS the flag/key.
4. Note the **address of the success block** and the **failure block** — you need both for
   gdb breakpoints, binary patching, and angr FIND/AVOID.

## DYNAMIC ANALYSIS — let the program decode it for you
Best when the flag is assembled at runtime. **Break after the decode, read memory.**
```bash
ltrace ./chall        # watch libc calls: strcmp("yourinput","EXPECTED") <- expected is right there
strace ./chall        # syscalls (read/write/openat) when ltrace is stripped/static
```
gdb + **pwndbg** (or GEF) — stop at the comparison and dump the expected value:
```gdb
gdb ./chall
pie break *main+0x120          # or: break strcmp / break memcmp / break strncmp
run
# at a strcmp break, the two args are the pointers being compared:
x/s $rdi            # arg1 (often your input)
x/s $rsi            # arg2 (often the EXPECTED flag/key)   <-- read the flag here
# per-char loops: set a breakpoint in the loop, inspect the built buffer:
x/40xb $rbp-0x40    # dump the buffer being compared
```
- `scanf`/multiple inputs: break *after* input is read, then inspect — or start angr from
  a `blank_state` at that address.
- See the flag in memory even if never printed: break at the `strcmp`/`puts` and `x/s`.

## COMMON PATTERNS (pick the cheapest that yields the flag)
1. **Extract the embedded/decoded flag** — run under gdb, break after decode, `x/s`. Done.
2. **Reverse the validation** — read the transform (e.g. `out[i] = in[i] ^ key[i]`) and
   invert it in a 5-line Python script to recover the required input.
3. **Patch the conditional jump** — when you just need the program to say "Correct" (or to
   print a flag it builds on the success path): flip the branch.
   - Find the `jz/jne` guarding success in objdump/Ghidra.
   - `jne`(0x75)→`je`(0x74), or NOP it (`90`), or force-take with `jmp`(0xeb).
   - Patch bytes: find file offset, then
     `printf '\x74' | dd of=chall conv=notrunc bs=1 seek=<offset>` (or r2 `w`, Ghidra patch).
   - Re-run; read the success output.

## STRING OBFUSCATION (XOR / base64 / stacked strings)
Flag is built in a buffer then compared — do **not** solve the math statically.
- **Run and break after the decode** (dynamic section above) — the plaintext is in memory.
- If you must do it offline: dump the ciphertext bytes + key from `.rodata`/the disasm,
  then XOR/decode in Python:
  ```python
  ct = bytes.fromhex("...."); key = b"...."
  print(bytes(c ^ key[i % len(key)] for i, c in enumerate(ct)))
  ```
- Base-decoded at runtime → spot `base64`/charset tables in strings; decode the literal.

## SYMBOLIC EXECUTION with angr — "solve for the correct input"
Use when the check is **self-contained** (per-char constraints, XOR/arith, small state
machine) and you do NOT want to reverse it by hand. **Avoid** for hashing/crypto/big loops
(path explosion) — reverse those statically instead.

Script: `scripts/angr_template.py` (edit the FIND/AVOID section; run with `-I`):
```bash
python3 -I scripts/angr_template.py ./chall                 # stdin, match on output (default)
python3 -I scripts/angr_template.py ./chall --argv --len 24 # input via argv[1]
python3 -I scripts/angr_template.py ./chall --printable     # force ASCII; add --veritesting if branchy
```
- **FIND** = success-print address or block; **AVOID** = "Wrong!"/exit blocks (from Ghidra/r2).
  Easiest: the default `--by-output` mode matches success/failure *strings* in stdout, so you
  need NO addresses and it ignores PIE rebasing. Edit `SUCCESS_MARKERS`/`FAILURE_MARKERS`.
- If using addresses on a **PIE** binary, rebase the Ghidra address (the script header shows
  the formula) — or just use `--by-output`.
- No solution? widen `--len`, fix the markers, add `--printable`/`--veritesting`, or accept it
  is too heavy for angr and reverse the check by hand.
- angr install (do it yourself, not auto): `python3 -m pip install angr` (prefer a venv).

## FLAG EXTRACTION & VERIFICATION (finish here)
- Format: `flag{...}` — letters, numbers, underscores. Grab with:
  `./chall <solved-input> | grep -oE 'flag\{[A-Za-z0-9_]+\}'`
  or from memory in gdb: `grep -aoE 'flag\{[A-Za-z0-9_]+\}'` over a memory dump.
- **Verify**: feed the recovered input back into the ORIGINAL binary and confirm it prints
  the success message / the flag. A flag from angr/patching is only trusted once the
  unpatched binary accepts it.
- If the flag is decoded but mangled, re-check endianness, off-by-one on length, and that you
  stripped trailing `\x00`/newline. Then submit.
