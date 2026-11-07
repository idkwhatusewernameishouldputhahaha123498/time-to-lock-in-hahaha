# Regression results

Run `bash tests/run_tests.sh` to reproduce. Self-contained (generated fixtures; no challenge
files needed). HARD = deterministic assertion (fails the suite); SMOKE = must run without crashing.

## Latest run (Cycle 1, 2026-11-07)

```
HARD  11/11 passed; SMOKE 3/3 ok.

[HARD ] PASS  py_compile all scripts
[HARD ] PASS  JSON manifests parse
[HARD ] PASS  prng_sweep minstd0 idx1 == 32285335          (Random Encounter math)
[HARD ] PASS  prng_sweep --grep no %100 false-flood        (F6 fix verified)
[HARD ] PASS  flag_grep finds plain+base64+utf16           (F8 fix: wide-char added)
[HARD ] PASS  railfence encode->brute recovers flag
[HARD ] PASS  classical rot13 decodes
[HARD ] PASS  xor_tools single-byte surfaces plaintext     (ranking bug found+fixed this round)
[HARD ] PASS  decode_cascade peels nested base64
[HARD ] PASS  nested_archive_peel recovers flag from nested zip
[HARD ] PASS  log_filter ANDs clues and surfaces flag
[SMOKE] PASS  zerowidth_decode runs; recovers standard scheme
[SMOKE] PASS  image_amplify runs and writes outputs        (F21 fix: --outdir honored)
[SMOKE] PASS  spectrogram renders a wav
```

Plugin + marketplace manifests pass `claude plugin validate .` (relative-string marketplace
source confirmed valid; the one-command team install path is structurally sound).

## Note on honesty
These are self-contained regression checks — they prove the scripts work on generated fixtures.
They are NOT a generalization proof. For that, see `BLIND_RESULTS.md` (fresh, unseen challenges).
