#!/usr/bin/env python3
"""
run_tests.py - self-contained regression harness for the Flag Hunters arsenal.

Generates its OWN fixtures (never depends on the private challenge files) and
asserts the bundled scripts still work. Two kinds of check:
  HARD  - a deterministic assertion; a failure fails the suite.
  SMOKE - the script must run without crashing (exit 0 / clean import guard);
          a bonus flag-recovery is reported but does not fail the suite, so a
          fixture that doesn't match a script's exact expected encoding is not
          a false alarm.

Usage:  python3 tests/run_tests.py        (from the repo root, or anywhere)
Exit code 0 = all HARD checks passed.
"""
import os
import re
import io
import subprocess
import sys
import tempfile
import base64
import zipfile
import struct
import wave
import math

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS = os.path.join(ROOT, "plugins", "flag-hunters", "skills")


def script(rel):
    return os.path.join(SKILLS, rel)


def run(args, stdin=None, timeout=120):
    """Run a python script with -I; return (rc, stdout+stderr)."""
    p = subprocess.run([sys.executable, "-I", *args],
                       input=stdin, capture_output=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


results = []  # (name, kind, ok, detail)


def hard(name, ok, detail=""):
    results.append((name, "HARD", bool(ok), detail))


def smoke(name, ok, detail=""):
    results.append((name, "SMOKE", bool(ok), detail))


def main():
    tmp = tempfile.mkdtemp(prefix="fh_tests_")

    # 0) py_compile every script -------------------------------------------
    pyfiles = []
    for d, _s, fs in os.walk(SKILLS):
        for f in fs:
            if f.endswith(".py"):
                pyfiles.append(os.path.join(d, f))
    rc, out = run(["-m", "py_compile", *pyfiles])
    hard("py_compile all scripts", rc == 0, out.strip()[:300])

    # 1) JSON manifests -----------------------------------------------------
    import json
    try:
        json.load(open(os.path.join(ROOT, ".claude-plugin", "marketplace.json")))
        json.load(open(os.path.join(ROOT, "plugins", "flag-hunters",
                                    ".claude-plugin", "plugin.json")))
        hard("JSON manifests parse", True)
    except Exception as e:
        hard("JSON manifests parse", False, repr(e))

    # 2) prng_sweep: Random Encounter math (seed 1183075200 -> minstd0 #1) --
    rc, out = run([script("ctf-crypto/scripts/prng_sweep.py"),
                   "1183075200", "--grep", "32285335"])
    hard("prng_sweep minstd0 idx1 == 32285335",
         rc == 0 and "32285335" in out and "minstd_rand0" in out and "MATCH" in out)
    # the removed-bug: grep must NOT flood matches on a low value
    rc, out2 = run([script("ctf-crypto/scripts/prng_sweep.py"), "1", "--grep", "35"])
    n_match = out2.count("<<< MATCH")
    hard("prng_sweep --grep no %100 false-flood (<=2 matches for 35)", n_match <= 2,
         f"{n_match} matches")

    # 3) flag_grep: plain / base64 / utf-16 / leet -------------------------
    fg = os.path.join(tmp, "fg"); os.makedirs(fg, exist_ok=True)
    open(os.path.join(fg, "a.txt"), "w").write("flag{plain_ok}\n")
    open(os.path.join(fg, "b.txt"), "w").write("x " + base64.b64encode(b"flag{b64_ok}").decode())
    open(os.path.join(fg, "d.bin"), "wb").write("flag{wide_ok}".encode("utf-16-le"))
    rc, out = run([script("ctf-triage/scripts/flag_grep.py"), fg])
    hard("flag_grep finds plain+base64+utf16",
         all(x in out for x in ("flag{plain_ok}", "flag{b64_ok}", "flag{wide_ok}")))

    # 4) railfence: encode then recover via brute --------------------------
    rc, enc = run([script("ctf-crypto/scripts/railfence.py"),
                   "encode", "flag{rail_ok}", "--rails", "5", "--offset", "2"])
    ct = enc.strip().splitlines()[-1] if enc.strip() else ""
    rc, out = run([script("ctf-crypto/scripts/railfence.py"), "brute", ct])
    hard("railfence encode->brute recovers flag", "flag{rail_ok}" in out, f"ct={ct!r}")

    # 5) classical_cipher: rot13 is involutive -----------------------------
    rc, out = run([script("ctf-crypto/scripts/classical_cipher.py"), "rot13",
                   "synt{ebg13_bx}"])   # rot13 of flag{rot13_ok}
    hard("classical rot13 decodes", "flag{rot13_ok}" in out)

    # 6) xor_tools: single-byte known key ----------------------------------
    key = 0x42
    ct = bytes(b ^ key for b in b"flag{xor_ok}").hex()
    rc, out = run([script("ctf-crypto/scripts/xor_tools.py"), "single", ct, "--in", "hex"])
    hard("xor_tools single-byte surfaces plaintext", "flag{xor_ok}" in out)

    # 7) decode_cascade: nested base64 -------------------------------------
    blob = base64.b64encode(base64.b64encode(b"flag{cascade_ok}")).decode()
    rc, out = run([script("ctf-misc/scripts/decode_cascade.py"), blob])
    hard("decode_cascade peels nested base64", "flag{cascade_ok}" in out)

    # 8) zerowidth_decode: SMOKE + best-effort -----------------------------
    payload = b"flag{zw_ok}"
    bits = "".join(f"{byte:08b}" for byte in payload)
    zw = "".join("​" if b == "0" else "‌" for b in bits)
    zwf = os.path.join(tmp, "zw.txt")
    open(zwf, "w", encoding="utf-8").write("cover text " + zw + " more")
    rc, out = run([script("ctf-forensics/scripts/zerowidth_decode.py"), zwf])
    hard("zerowidth_decode recovers ZWSP/ZWNJ-encoded flag",
         rc == 0 and "flag{zw_ok}" in out)

    # 8b) decode_cascade must RETURN on large high-entropy input (regression for the
    #     exponential-hang bug) ------------------------------------------------
    import time as _t
    big = base64.b64encode(os.urandom(6000)).decode()
    t0 = _t.time()
    rc, out = run([script("ctf-misc/scripts/decode_cascade.py"), big, "--timeout", "5"])
    dur = _t.time() - t0
    hard("decode_cascade returns on 6KB random input (no hang)",
         rc == 0 and dur < 20, f"{dur:.1f}s")

    # 9) nested_archive_peel: plain nested zip -----------------------------
    inner = os.path.join(tmp, "inner.zip")
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("secret.bin", b"....flag{nested_ok}....")
    outer = os.path.join(tmp, "outer.zip")
    with zipfile.ZipFile(outer, "w") as z:
        z.write(inner, "inner.zip")
    rc, out = run([script("ctf-forensics/scripts/nested_archive_peel.py"), outer])
    hard("nested_archive_peel recovers flag from nested zip",
         rc == 0 and "flag{nested_ok}" in out)

    # 10) log_filter: AND regex + decoy rejection --------------------------
    logf = os.path.join(tmp, "s.log")
    with open(logf, "w") as fh:
        fh.write("12:00:01 UserID=zoe Token=sha1:deadbeef\n")
        fh.write("12:00:02 UserID=amy Token=flag{log_ok}\n")
        fh.write("12:00:02 UserID=bob Token=sess-9999\n")
    rc, out = run([script("ctf-forensics/scripts/log_filter.py"), logf,
                   "-r", r":02\s", "-r", "UserID=amy"])
    hard("log_filter ANDs clues and surfaces flag", "flag{log_ok}" in out)

    # 11) image_amplify: SMOKE (runs, writes to --outdir, no crash) --------
    try:
        import numpy as np
        from PIL import Image
        imgp = os.path.join(tmp, "t.png")
        arr = np.full((20, 60, 3), 255, dtype=np.uint8)
        arr[5:10, 5:40] = 254   # faint off-white band
        Image.fromarray(arr).save(imgp)
        od = os.path.join(tmp, "amp")
        rc, out = run([script("ctf-stego/scripts/image_amplify.py"), imgp, "--outdir", od])
        smoke("image_amplify runs and writes outputs",
              rc == 0 and os.path.isdir(od) and os.listdir(od))
    except ImportError:
        smoke("image_amplify (needs numpy+Pillow)", True, "skipped: deps absent")

    # 12) spectrogram: SMOKE -----------------------------------------------
    try:
        import numpy as np  # noqa: F811
        wavp = os.path.join(tmp, "t.wav")
        with wave.open(wavp, "w") as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000)
            frames = b"".join(struct.pack("<h", int(3000 * math.sin(2 * math.pi * 440 * i / 8000)))
                              for i in range(4000))
            w.writeframes(frames)
        rc, out = run([script("ctf-stego/scripts/spectrogram.py"), wavp])
        smoke("spectrogram renders a wav", rc == 0)
    except ImportError:
        smoke("spectrogram (needs numpy)", True, "skipped: deps absent")

    # 13) arg parsers fail CLEANLY (exit!=0, no raw traceback) on a missing value
    argcrash = [
        # missing option values
        ("prng_sweep", "ctf-crypto/scripts/prng_sweep.py", ["123", "--grep"]),
        ("xor_tools", "ctf-crypto/scripts/xor_tools.py", ["single", "ab", "--in"]),
        ("classical_cipher", "ctf-crypto/scripts/classical_cipher.py", ["vigenere", "x", "--key"]),
        ("flag_grep", "ctf-triage/scripts/flag_grep.py", [".", "--wrappers"]),
        ("decode_cascade", "ctf-misc/scripts/decode_cascade.py", ["x", "--depth"]),
        ("railfence_norails", "ctf-crypto/scripts/railfence.py", ["encode", "flag{x}"]),
        ("pdf_rc4_nofields", "ctf-crypto/scripts/pdf_rc4_verify.py", ["--pw", "x"]),
        # malformed positionals / values
        ("prng_badseed", "ctf-crypto/scripts/prng_sweep.py", ["abc"]),
        ("prng_optsonly", "ctf-crypto/scripts/prng_sweep.py", ["--mod", "5"]),
        ("xor_badhex", "ctf-crypto/scripts/xor_tools.py", ["single", "zz", "--in", "hex"]),
        ("xor_nofile", "ctf-crypto/scripts/xor_tools.py", ["multi", "--in", "file", "/no/such/f"]),
        ("vig_numkey", "ctf-crypto/scripts/classical_cipher.py", ["vigenere", "hi", "--key", "123"]),
    ]
    clean, detail = True, ""
    for nm, rel, extra in argcrash:
        rc, out = run([script(rel), *extra])
        if rc == 0 or "Traceback (most recent call last)" in out:
            clean = False
            detail += f"{nm}(rc={rc},tb={'Traceback' in out}) "
    hard("arg parsers fail cleanly (no tracebacks) on bad args", clean, detail)

    # 14) flag_grep: format-agnostic (picoCTF{} not truncated) + NUL-interleaved
    fg2 = os.path.join(tmp, "fg2"); os.makedirs(fg2, exist_ok=True)
    open(os.path.join(fg2, "p.txt"), "w").write("x picoCTF{not_truncated} y")
    open(os.path.join(fg2, "n.bin"), "wb").write(
        b"".join(bytes([ch]) + b"\x00" for ch in b"picoCTF{nul_ok}"))
    rc, out = run([script("ctf-triage/scripts/flag_grep.py"), fg2])
    hard("flag_grep keeps full picoCTF{} (no CTF{} truncation)",
         "picoCTF{not_truncated}" in out)
    hard("flag_grep finds NUL-interleaved flag",
         "picoCTF{nul_ok}" in out)

    # 15) carve.py: appended ZIP after a PNG (polyglot) -> extract + flag --------
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("hidden.txt", b"flag{carved_ok}")
    poly = os.path.join(tmp, "poly.png")
    # minimal but real PNG header + IEND, then the appended zip
    png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    with open(poly, "wb") as fh:
        fh.write(png + zbuf.getvalue())
    od = os.path.join(tmp, "carved")
    rc, out = run([script("ctf-forensics/scripts/carve.py"), poly, "--outdir", od])
    hard("carve.py extracts appended zip and finds flag",
         rc == 0 and "flag{carved_ok}" in out)

    # 16) rsa_attacks: known-p decrypt, and low-exponent cube root --------------
    m = int.from_bytes(b"flag{rsa_ok}", "big")
    p, q = (2**61 - 1), (2**89 - 1)          # Mersenne primes
    n = p * q; e = 65537
    c = pow(m, e, n)
    rc, out = run([script("ctf-crypto/scripts/rsa_attacks.py"),
                   "--n", str(n), "--e", str(e), "--c", str(c), "--p", str(p)])
    hard("rsa_attacks decrypts with known p", "flag{rsa_ok}" in out)
    p2, q2 = (2**127 - 1), (2**521 - 1)      # big n so m**3 < n (plain cube root)
    n2 = p2 * q2; m2 = int.from_bytes(b"flag{low_e}", "big")
    c2 = pow(m2, 3, n2)
    rc, out = run([script("ctf-crypto/scripts/rsa_attacks.py"),
                   "--n", str(n2), "--e", "3", "--c", str(c2)])
    hard("rsa_attacks low-exponent cube root", "flag{low_e}" in out)

    # 17) esolang bf: 8*8+1 = 65 = 'A' -----------------------------------------
    rc, out = run([script("ctf-misc/scripts/esolang.py"), "bf",
                   "++++++++[>++++++++<-]>+."])
    hard("esolang bf interpreter runs", rc == 0 and "A" in out)

    # 18) decode_cascade honors timeout on large base58 (O(n^2) decoder is capped)
    import time as _t2
    t0 = _t2.time()
    rc, out = run([script("ctf-misc/scripts/decode_cascade.py"), "1" * 300000, "--timeout", "5"])
    dur = _t2.time() - t0
    hard("decode_cascade bounded on 300KB base58 (no timeout overshoot)",
         rc == 0 and dur < 20, f"{dur:.1f}s")

    # 19) flag_grep: ROT-n pass must NOT flood candidates on plain text ----------
    noise = os.path.join(tmp, "noise.txt")
    with open(noise, "w") as fh:
        fh.write("the quick brown fox jumps over the lazy dog " * 60 + " ab{y}")
    rc, out = run([script("ctf-triage/scripts/flag_grep.py"), noise])
    ncand = out.count("    <- ")
    hard("flag_grep no ROT flood (<=3 candidates on plain text)", ncand <= 3, f"{ncand} candidates")

    # 20) flag_grep: odd-length NUL (distinct from the clean UTF-16 path) --------
    open(os.path.join(fg2, "odd.bin"), "wb").write(
        b"".join(bytes([ch]) + b"\x00" for ch in b"picoCTF{odd_nul}")[:-1])  # drop final NUL
    rc, out = run([script("ctf-triage/scripts/flag_grep.py"), os.path.join(fg2, "odd.bin")])
    hard("flag_grep finds odd-length NUL flag (nul-strip path)", "picoCTF{odd_nul}" in out)

    # 21) flag_grep --wrappers does not truncate picoCTF via 'ctf' --------------
    rc, out = run([script("ctf-triage/scripts/flag_grep.py"),
                   os.path.join(fg2, "p.txt"), "--wrappers", "ctf"])
    hard("flag_grep --wrappers ctf does NOT match inside picoCTF",
         "picoCTF{not_truncated}" not in out and "CTF{not_truncated}" not in out)

    # --- report -----------------------------------------------------------
    hard_fail = [r for r in results if r[1] == "HARD" and not r[2]]
    print("\n==================== TEST RESULTS ====================")
    for name, kind, ok, detail in results:
        mark = "PASS" if ok else ("FAIL" if kind == "HARD" else "warn")
        line = f"  [{kind:5}] {mark:4}  {name}"
        if detail and not ok:
            line += f"   -- {detail}"
        print(line)
    n_hard = sum(1 for r in results if r[1] == "HARD")
    n_hard_ok = sum(1 for r in results if r[1] == "HARD" and r[2])
    print(f"\nHARD {n_hard_ok}/{n_hard} passed; "
          f"{sum(1 for r in results if r[1]=='SMOKE' and r[2])}/"
          f"{sum(1 for r in results if r[1]=='SMOKE')} smoke ok.")
    return 1 if hard_fail else 0


if __name__ == "__main__":
    sys.exit(main())
