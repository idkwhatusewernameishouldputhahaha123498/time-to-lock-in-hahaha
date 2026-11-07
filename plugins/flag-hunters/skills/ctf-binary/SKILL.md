---
name: ctf-binary
description: Solve binary-exploitation ("pwn") CTF challenges FAST. Use when given a provided ELF with a network service (`nc host port`), or anything about buffer overflow, format string, "get a shell"/"pop a shell", ROP/ret2libc/ret2win, stack/heap corruption, use-after-free, GOT overwrite, segfault/SIGSEGV, canary, PIE/ASLR, GDB/pwndbg, or pwntools.
---

# ctf-binary — pwn methodology

Authorized CTF only: exploit ONLY the organiser's provided binary/service. Build the real
exploit live against the actual binary — this skill is methodology + a reusable scaffold.
Always get it working LOCALLY first, then flip to the remote.

Golden rule: **don't guess, measure.** Use `checksec`, `cyclic`, and GDB to find exact
offsets and addresses. Brute force is almost never the intended path.

---

## 1. FAST-PATH triage (do this first, in order)

```bash
file ./chall                      # arch (x86-64 / i386 / arm), static/dynamic, stripped?
checksec --file=./chall           # RELRO / Canary / NX / PIE  (pwntools ships checksec)
strings -n 6 ./chall | grep -iE 'flag|/bin/sh|system|cat |win|back'   # freebies
nm ./chall 2>/dev/null | grep -iE 'win|flag|system|shell|secret|admin'  # win() funcs
./chall                           # run it: what does it read? how many bytes? echo back?
```

Then, before writing any exploit, answer these:

- **Where is input read?** `gets`, `scanf("%s")`, `read(0,buf,BIG)`, `fgets` with a bad size.
- **Is there an obvious overflow?** A small stack buffer fed a large/unbounded read.
- **Is there a `win`/backdoor function** (prints flag, calls `system("/bin/sh")`, `cat flag`)?
  If yes → the challenge is usually "redirect control flow to it" (ret2win).
- **Is there a format-string sink?** `printf(user_input)` with no format → `%p`/`%n` bug.
- **Decompile** for the real logic: `ghidra` / `objdump -d -M intel ./chall` / r2 `aaa; pdf @main`.

Run the binary and poke it before theorising. Overflow it with `cyclic 200` piped in and
watch for a crash.

---

## 2. Mitigations — WHAT they block and HOW they steer technique

`checksec` prints four things. Each one changes the plan:

| Mitigation | On means | Your move |
|---|---|---|
| **NX** (No-eXecute) | stack/heap not executable → injected shellcode won't run | **Reuse existing code**: ROP / ret2libc / ret2win, not shellcode. NX off → shellcode on stack is viable. |
| **PIE** | binary base randomised each run → your `win`/gadget addrs aren't fixed | Need a **leak** of a binary address, OR overwrite only the low bytes (partial overwrite), OR use relative targets. Without PIE, binary symbols are at fixed addresses. |
| **Stack Canary** | a secret value sits before saved RBP/RET; a linear overflow smashes it → `__stack_chk_fail` aborts | Need to **leak the canary** (format string / off-by-one read) and write it back, OR use a bug that doesn't cross it (overwrite a saved pointer/index, exploit a different function, partial write). |
| **RELRO** | **Full** = GOT read-only (can't overwrite GOT entries); **Partial** = GOT still writable | Full RELRO → target the **return address / saved pointers / `__malloc_hook`/`exit` handlers** instead of GOT. Partial/No RELRO → **GOT overwrite** is open (format string / arbitrary write). |

Typical reads:
- **No PIE, NX on, has win()** → ret2win (easiest). Overflow → overwrite RET with `&win`.
- **NX on, dynamic libc, no win()** → ret2libc: leak a libc addr (e.g. `puts(puts@got)`),
  compute libc base, return to `system("/bin/sh")`.
- **Partial RELRO + format string** → write `system` addr over a GOT entry (e.g. `printf@got`).
- **PIE + canary, everything on** → you need a leak first; find an info-leak primitive.

---

## 3. Decision tree BY BUG CLASS

### A. Stack buffer overflow
1. Find the offset to the saved return address with `cyclic`:
   send `cyclic(200)`, let it crash, read the faulting value (RSP/RIP) in GDB,
   `cyclic_find(0x6161...)` → exact offset.
2. Pick the target by mitigations:
   - **ret2win**: `payload = b"A"*offset + p64(win_addr)`. If it crashes inside a libc call
     (movaps alignment on x86-64), prepend a bare `ret` gadget to realign the stack.
   - **ROP to call a function**: `p64(pop_rdi) + p64(arg) + p64(func)`. On x86-64 args go in
     rdi, rsi, rdx, rcx, r8, r9 — need the matching `pop` gadgets.
   - **ret2libc** (no win, NX on): leak → compute base → return to `system`:
     1. `rop1 = pop_rdi + puts@got + puts@plt + main` (print a real libc addr, re-loop)
     2. `libc.address = leak - libc.sym['puts']`
     3. `rop2 = ret + pop_rdi + binsh + system`  (`binsh = next(libc.search(b"/bin/sh"))`)
   - **one_gadget**: after a libc leak, a single magic gadget may pop a shell if constraints
     hold (`one_gadget ./libc.so.6`).

### B. Format string (`printf(user)` with no format specifier)
- **Find your arg position**: send `AAAA.%p.%p.%p.%p.%p.%p` → count dots until `0x41414141`.
- **Arbitrary read / leak**: `%7$p` leaks the 7th stack slot; `%s` with a planted pointer
  reads a string. Great for leaking canary, libc, PIE base.
- **Arbitrary write**: `%n` writes the number-of-bytes-printed to a pointed-at address.
  Use `%<N>c` width padding + `$hn`/`$hhn` to write a value in 2-/1-byte chunks.
  pwntools automates this: `fmtstr_payload(offset, {addr: value})`.
- **Targets**: GOT entry (partial RELRO) → point a function to `system`; or saved return addr.

### C. Integer / size bugs
- Signedness: a negative "length" passed to `memcpy`/`read` becomes a huge `size_t`.
- Truncation: `short`/`int` size wraps → under-allocation then overflow.
- Off-by-X arithmetic in bounds checks → write just past a buffer. Look for `<=` vs `<`.

### D. Off-by-one
- A single-byte overflow often smashes the **LSB of saved RBP** (stack pivot) or a
  **null-terminator** past a buffer. On heap, a one-byte overflow into the next chunk's
  size field = "poison null byte" → chunk overlap.

### E. Heap (high level — confirm the exact glibc/allocator first)
- **Use-after-free (UAF)**: freed chunk still referenced → read leaks heap/libc pointers
  (fd/bk), write corrupts freelist. Classic: free → allocate same size → control old object.
- **Double-free**: free the same chunk twice → tcache/fastbin poisoning → return an
  arbitrary pointer from `malloc` → write anywhere (e.g. `__free_hook` = `system`).
- **Tcache poisoning** (glibc ≥ 2.26): overwrite a freed chunk's `fd` to point `malloc` at
  a target (note the `fd` pointer mangling in glibc ≥ 2.32: `fd ^ (chunk_addr >> 12)`).
- Identify libc version early — heap technique depends entirely on it.

---

## 4. Tooling

- **pwntools** — scripting: `ELF`, `process`/`remote`, `ROP`, `cyclic`, `p64/u64`,
  `fmtstr_payload`, `shellcraft`. Template in `scripts/pwn_template.py`.
- **gdb + pwndbg** (or GEF) — `b main`, `r`, `c`, `cyclic 200`, `context`, `vmmap`,
  `telescope $rsp`, `got`, `canary`, `search`. Crash → inspect `$rip`/`$rsp`.
- **ROPgadget** / **ropper** — find gadgets:
  `ROPgadget --binary ./chall | grep 'pop rdi'`, `ropper -f ./chall --search 'pop rdi'`.
- **one_gadget** — `one_gadget ./libc.so.6` → single-call `execve("/bin/sh")` gadgets + their
  register/stack constraints.
- **Matching the REMOTE libc** (ret2libc needs the right one):
  - leak 2+ function addresses, look them up at <https://libc.rip> or **libc-database**
    (`./find puts 0x7f...e0 system 0x7f...90`) to identify the exact build.
  - download it, then **patchelf** your local copy to test against it:
    `patchelf --set-interpreter ./ld-x.xx.so --set-rpath . ./chall`
    (or run with `pwninit`, which fetches libc+ld and patches automatically).
- **cyclic** — De Bruijn offset finder: `cyclic(200)` to send, `cyclic_find(leak)` to solve.
- **seccomp**: `seccomp-tools dump ./chall` — if syscalls are filtered, `system` may be
  blocked → need an `open`/`read`/`write` ROP chain (ORW) to read `flag.txt` directly.

---

## 5. The template

`scripts/pwn_template.py` is a neutral, EDITABLE pwntools scaffold (TODOs marked). It sets
`context.binary`, has a `conn()` that switches LOCAL vs REMOTE, offset-finding with
`cyclic`, ELF GOT/PLT/symbol lookups, a libc slot for leak math, and `interactive()`.

```bash
cp scripts/pwn_template.py exploit.py     # copy next to the challenge binary
# edit BINARY/HOST/PORT and the payload section, then:
python3 exploit.py                        # LOCAL  (process('./chall'))
python3 exploit.py GDB                    # LOCAL under gdb (gdb.attach / gdb.debug)
python3 exploit.py REMOTE                 # REMOTE (remote(HOST, PORT))
```

Workflow: get the LOCAL crash → find offset → build payload → confirm LOCAL shell/flag →
run with `REMOTE`.

---

## 6. Get the flag / verify

Once control flow or a write primitive lands:

- **Shell popped** (`system("/bin/sh")` / one_gadget / `execve`): after `p.interactive()`,
  ```
  $ ls; cat flag.txt; cat /flag*; id
  ```
  Flag format is `flag{...}`. If `cat` is blocked, try `/bin/cat`, `head`, or shell globs.
- **win() prints the flag**: it appears directly in the program output — scrape it with
  `p.recvall()` / `p.recvuntil(b'flag{')`.
- **ORW chain** (seccomp blocks `system`): the chain `open("flag.txt")` → `read` →
  `write(1,...)` dumps the flag to stdout; read it from `p.recvall()`.
- **Format-string leak of the flag**: if the flag is in memory, `%s` at the right offset
  may print it without any control-flow hijack.

Confirm the flag matches `flag{...}`, then submit. If it worked locally but not remotely:
re-check the **libc** (ret2libc) and that addresses aren't stale from a different PIE/ASLR
base — remote needs a fresh leak each run.
