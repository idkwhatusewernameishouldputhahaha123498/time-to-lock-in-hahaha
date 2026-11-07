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
    smoke("zerowidth_decode runs; recovers standard scheme",
          rc == 0, "recovered" if "flag{zw_ok}" in out else "ran; scheme not matched")

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
