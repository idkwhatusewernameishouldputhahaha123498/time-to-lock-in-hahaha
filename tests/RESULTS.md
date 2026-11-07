# Regression results

Run `bash tests/run_tests.sh` to reproduce. Self-contained (generated fixtures; no challenge
files needed). HARD = deterministic assertion (fails the suite); SMOKE = must run without crashing.

## Latest run (Cycle 3, 2026-11-07) — full suite in ~1.5s

```
HARD 24/24 passed; SMOKE 2/2 ok.
Cycle-3 additions lock the two MAJORs the convergence review found: decode_cascade
bounded on 300KB base58 (O(n^2) decoder capped); flag_grep no ROT-n flood; plus
malformed-input clean-fail, odd-length NUL recovery, and --wrappers no-truncation.

py_compile all scripts · JSON manifests parse
prng_sweep minstd0 idx1 == 32285335 · prng_sweep --grep no %100 false-flood (F6)
flag_grep plain+base64+utf16 · flag_grep full picoCTF{} no truncation · flag_grep NUL-interleaved
railfence encode->brute · classical rot13 · xor_tools single-byte (ranking fix)
decode_cascade nested base64 · decode_cascade returns on 6KB random input, no hang (MAJOR fix)
zerowidth_decode recovers ZWSP/ZWNJ · nested_archive_peel nested zip · log_filter AND + decoy
arg parsers fail cleanly on bad args (F2 regression lock)
carve.py appended-zip polyglot · rsa_attacks known-p + low-exponent cube root · esolang bf
image_amplify writes outputs (--outdir) · spectrogram renders wav
```

Plugin + marketplace pass `claude plugin validate .` (LICENSE added; relative-string marketplace
source confirmed valid; one-command team install structurally sound).

## Blind capability test
See `BLIND_RESULTS.md`: an independent agent scored **8/9 on fresh, unseen public picoGym
challenges** (answers unknown to the author). Its gaps drove the Cycle-2 additions: `carve.py`
(pure-Python binwalk substitute), `rsa_attacks.py` (RSA tooling), `esolang.py` (Brainfuck/Ook),
format-agnostic `flag_grep`/`nested_archive_peel`, and NUL-interleave handling.

## Known residual (below the material bar)
- No monoalphabetic-substitution auto-solver (freq table only); Substitution0 still solved via it.
- No Rockstar/Whitespace/Piet interpreters (niche); SKILL points to external tools.
- Bundled scripts are the fallback when system tools (binwalk/exiftool/zsteg/tshark) aren't on
  the provided machine; SKILL fast-paths still list those tools first where they're best.
