#!/usr/bin/env python3
"""
Reusable pwntools exploit scaffold  (ctf-binary skill).

NEUTRAL BOILERPLATE — not an exploit for any specific target. Copy it next to the
organiser's challenge binary, fill in the TODOs, and build the real exploit live.
Authorized CTF use only: run this against the organiser's OWN provided binary/service.

Usage:
    cp pwn_template.py exploit.py        # work in a copy next to ./chall
    python3 exploit.py                   # LOCAL   -> process(BINARY)
    python3 exploit.py GDB               # LOCAL under gdb (pwndbg/gef)
    python3 exploit.py REMOTE            # REMOTE  -> remote(HOST, PORT)

The LOCAL/GDB/REMOTE switch uses pwntools' magic `args` (any ARGV token in CAPS
becomes args.TOKEN). No flags are auto-installed.
"""

# --- import guard: print an install hint instead of a raw traceback ----------
try:
    from pwn import *
except ImportError:
    import sys
    sys.exit(
        "[!] pwntools not found. Install it yourself (this script will NOT auto-install):\n"
        "      python3 -m pip install --user pwntools\n"
        "    docs: https://docs.pwntools.com/"
    )

# =============================================================================
# CONFIG  — TODO: edit these for the challenge
# =============================================================================
BINARY = "./chall"              # TODO: path to the provided ELF
HOST   = "chall.example.ctf"    # TODO: remote host from the `nc host port` prompt
PORT   = 1337                   # TODO: remote port
LIBC   = None                   # TODO: "./libc.so.6" if you have the challenge libc, else None

# context.binary auto-sets arch / bits / endianness / os from the ELF.
context.binary = exe = ELF(BINARY, checksec=True)
# context.arch = "amd64"        # override only if there is no local ELF (amd64/i386/aarch64/arm)
context.log_level = "info"      # set "debug" to dump every byte sent/received
context.terminal = ["tmux", "splitw", "-h"]   # how gdb.attach opens a window (edit for your term)

libc = ELF(LIBC, checksec=False) if LIBC else None

# gdb script used with the GDB arg. TODO: add your breakpoints.
GDBSCRIPT = """
# b *main
# b *0x0000000000401234
continue
""".strip()


# =============================================================================
# CONNECTION  — LOCAL vs REMOTE vs GDB
# =============================================================================
def conn():
    """Return a tube: remote if 'REMOTE' in argv, gdb-attached if 'GDB', else local."""
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug([BINARY], gdbscript=GDBSCRIPT)
    return process([BINARY])


# =============================================================================
# HELPERS
# =============================================================================
def find_offset(pattern_len=200):
    """One-shot offset finder for a stack overflow.

    Sends a cyclic De Bruijn pattern, lets the target crash, then reads the
    faulting value from the core dump and prints the exact offset to the saved
    return address. Run this ONCE (locally), note the offset, then hardcode it.
    """
    p = process([BINARY])
    p.sendline(cyclic(pattern_len))     # TODO: match how the program reads input
    p.wait()
    core = p.corefile
    # x86-64: RSP points just past the overwritten return addr after the ret.
    fault = core.read(core.rsp, 8)
    off = cyclic_find(fault[:4])        # cyclic default n=4; use cyclic_find(fault) if n was set
    log.success(f"crash fault bytes = {fault!r}  ->  offset = {off}")
    return off


def leak_to_libc_base(leak_addr, symbol="puts"):
    """Given a leaked libc address of `symbol`, rebase the libc ELF.

    After this, libc.sym['system'], libc.search(b'/bin/sh'), etc. are correct.
    """
    assert libc, "set LIBC to the challenge's libc.so.6 first"
    libc.address = leak_addr - libc.sym[symbol]
    log.success(f"libc base = {hex(libc.address)}")
    return libc.address


# =============================================================================
# SYMBOLS  — handy lookups via the ELF object (edit names to match the binary)
# =============================================================================
# exe.sym['main']           # function / symbol address (0 or raises if stripped)
# exe.got['puts']           # GOT entry address (overwrite target under partial RELRO)
# exe.plt['puts']           # PLT stub to CALL a function already imported
# exe.address               # PIE base (0 until you set it from a leak: exe.address = leak - off)
# next(exe.search(b'/bin/sh\x00'))        # find bytes in the binary
# rop = ROP(exe); rop.rdi.address ...     # ROP(exe)/ROP(libc) build chains & find gadgets


# =============================================================================
# EXPLOIT
# =============================================================================
def main():
    p = conn()

    # -- 1. receive any banner / prompt -----------------------------------
    # p.recvuntil(b"> ")                  # TODO: sync to the program's prompt

    # -- 2. build the payload ---------------------------------------------
    offset = 0                            # TODO: from find_offset(), e.g. 40 or 72

    # Example skeletons (DELETE the ones you don't use, fill in real addresses):
    #
    #  ret2win:
    #     payload = flat({ offset: exe.sym['win'] })
    #
    #  ret2win with stack-alignment fix (x86-64 movaps):
    #     rop = ROP(exe)
    #     payload = flat({ offset: [rop.ret.address, exe.sym['win']] })
    #
    #  leak libc via puts, then re-loop to main:
    #     rop = ROP(exe)
    #     rop.call('puts', [exe.got['puts']])
    #     rop.call(exe.sym['main'])
    #     payload = flat({ offset: rop.chain() })
    #
    #  format string arbitrary write (partial RELRO):
    #     payload = fmtstr_payload(FMT_OFFSET, { exe.got['printf']: libc.sym['system'] })
    #
    payload = b"A" * offset               # TODO: replace with the real payload
    # payload += p64(0xdeadbeef)          # TODO: return address / ROP chain

    # -- 3. send it -------------------------------------------------------
    p.sendline(payload)                   # TODO: use send/sendlineafter to match input

    # -- 4. (ret2libc only) parse the leak, rebase, send stage 2 ----------
    # leak = u64(p.recvline().strip().ljust(8, b"\x00"))
    # leak_to_libc_base(leak, "puts")
    # rop2 = ROP(libc)
    # rop2.call('system', [next(libc.search(b'/bin/sh\x00'))])
    # p.sendline(flat({ offset: rop2.chain() }))

    # -- 5. hand over: get the shell / read the flag ----------------------
    # In the shell:  ls ; cat flag.txt ; cat /flag* ; id
    p.interactive()


if __name__ == "__main__":
    main()
