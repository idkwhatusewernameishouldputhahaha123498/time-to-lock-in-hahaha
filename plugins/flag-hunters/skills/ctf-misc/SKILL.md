---
name: ctf-misc
description: Decode the mystery blob FAST. Use when you have a wall of weird text and ask "what encoding/format is this?" — base64/hex/binary/base32/58/85, morse, ROT/atbash, URL/HTML entities, esolangs (Brainfuck, Ook, Whitespace, Malbolge, JSFuck, Piet), QR/barcodes, emoji/braille ciphers, JWT/protobuf/pickle, "decode this", or a logic/math/programming puzzle. The MISC grab-bag.
---

# CTF MISC — the encoding zoo & puzzle grab-bag

MISC is mostly **nested encodings peeled one layer at a time** (like CyberChef
"Magic"). Do not guess — **identify by the alphabet/shape**, decode, repeat until
you see `flag{`. Run the cascade first; reach for hand tools only when it stalls.

## FAST PATH (do this first)

1. **Look at the character set.** The alphabet tells you the encoding (table below).
2. **Run the cascade** — it auto-detects and peels layers, printing any `flag{`:
   ```
   python3 -I scripts/decode_cascade.py <file|"blob">
   # or:  cat blob.txt | python3 -I scripts/decode_cascade.py
   ```
   Flags: `--pattern 'CTF\{'` (other formats), `--depth 15`, `--all` (show every
   printable layer when no hit).
3. **Still stuck?** Match the shape below and use the right hand tool / esolang
   interpreter, then feed the result back into the cascade.

### WHY: recognize the alphabet (this is the whole skill)

| You see ONLY these chars | It is | Decode |
|---|---|---|
| `A-Z a-z 0-9 + / =` | **base64** | `base64 -d`; `-`/`_` → base64**url** |
| `A-Z 2-7 =` (upper, no 0/1/8/9) | **base32** | `base64.b32decode` |
| `0-9 a-f` (even length) | **hex** | `xxd -r -p` / `bytes.fromhex` |
| `0` and `1`, groups of 8 | **binary** | 8-bit chunks → chr |
| `0-7` groups | **octal** | base-8 → chr |
| printable, no `0 O I l` | **base58** | bitcoin alphabet |
| `!"#$...~` wide ASCII, `<~ ~>` | **ascii85 / base85** | `a85decode`/`b85decode` |
| `.` and `-` (and `/` spaces) | **morse** | lookup table |
| letters, looks shifted | **ROT13 / Caesar / atbash** | brute 0-25; atbash = reverse-alphabet |
| `%` + 2 hex | **URL / percent** | `urllib.parse.unquote` |
| `&...;` tokens | **HTML entities** | `html.unescape` |
| `! ( ) [ ] { } +` ONLY | **JSFuck** (JS) | run in JS console / node sandbox |
| `+ - < > [ ] . ,` ONLY | **Brainfuck** | bf interpreter |
| `Ook. Ook? Ook!` | **Ook!** | → Brainfuck mapping |
| only spaces/tabs/newlines | **Whitespace** | whitespace interpreter |
| garbled printable, ~short | **Malbolge** | malbolge interpreter (don't hand-do) |
| numbers 1-26 | **A1Z26** | n → letter |
| `....` / `.--.` 5-bit groups of `/`,`A`,`B` | **baconian** | A/B → bits → letter |
| `⠁⠃⠉` dot patterns | **braille** | unicode braille map |
| emoji / exotic unicode | **emoji cipher / homoglyph** | map or `unicodedata` |

The cascade already covers base16/32/58/62/64/85, ascii85, binary/octal/decimal,
hex, URL, HTML entities, morse, ROT13/47, atbash, A1Z26, reverse, and Caesar brute.

## WHEN THE CASCADE STALLS — hand tools by shape

**Esolangs** (install nothing untrusted; use known interpreters / online or node):
- **Brainfuck** `+-<>[].,` and **Ook!** → bundled: `python3 -I scripts/esolang.py bf
  "<prog|->"` (or `ook` for Ook!). Step-capped so a looping program can't hang you.
- **Whitespace** (only ` `\t\n) → `wspace`/online interpreter. `cat -A file` to see it.
- **Malbolge / Piet** → dedicated interpreters; Piet is an **image** (npiet).
- **JSFuck / `[]()!+` / aaencode / jjencode** → it's JavaScript. Run in a node
  `-e` sandbox or browser console; replace `eval`/`console.log` to print output.
- **Rockstar** → a real language; run with a rockstar interpreter.

**Barcodes / QR** (it's an image):
```
zbarimg image.png        # QR, EAN, Code128, etc.  (brew install zbar)
```
No zbar? Try an online QR decoder or `zxing`. For damaged QR, fix the finder
patterns / quiet zone in an editor first.

**Data formats:**
- **JWT** = `xxx.yyy.zzz` (3 base64url parts) → decode header+payload; check `alg:none`
  / weak-secret for web crossover. `jwt.io` or `base64 -d` each part.
- **protobuf** → `protoc --decode_raw < blob` (no schema needed).
- **msgpack** → `python3 -I -c "import msgpack,sys;print(msgpack.unpackb(sys.stdin.buffer.read()))"`.
- **pickle / serialized** → **CAREFUL: never unpickle untrusted data** (RCE).
  Inspect bytes with `pickletools.dis` instead of loading:
  ```
  python3 -I -c "import pickletools,sys;pickletools.dis(sys.stdin.buffer.read())" < blob
  ```

**Classic paper ciphers:** tap code (pairs 1-5 → 5x5 grid), leetspeak
(`4=a 3=e 1=i 0=o 7=t`), uuencode (`begin 644` header → `uudecode`).

**Numbers that are really text / symbol ciphers (the cascade won't catch these):**
- **Decimal column = ASCII:** a CSV/spreadsheet column of ints in 32-126 is char codes —
  `''.join(chr(int(v)) for v in column)`. (CyberChef: "From Decimal", LF delimiter.)
- **IEEE-754 floats hiding bytes:** reinterpret each float as its raw bytes —
  `b''.join(struct.pack('>f', f) for f in floats)` (try `>d` for doubles, `<f`/`<d` little-endian).
- **Pigpen / Masonic:** angular grid glyphs (clue often "dusty crypto"/Peanuts) → map to the
  3×3 + X grids, or dcode.fr Pigpen decoder.
- **Keyboard-shift:** text looks like fingers shifted one key on QWERTY → dcode.fr "Keyboard Shift
  Cipher" (auto mode).

## Manual quick tool

**CyberChef "Magic"** (gchq.github.io/CyberChef) auto-detects and chains recipes —
the fastest manual equivalent of the cascade. Paste blob → Magic → read candidates.
Use it to confirm an ambiguous layer or to try recipes the script lacks.

## Logic / math / programming puzzles

If it's not an encoding, it's a **puzzle — just write a script.** Don't solve by
hand or brute-force blindly:
- Sequence/number puzzle → compute it in Python.
- "Find input where hash/output = X" → constrain, then search the small space.
- Interactive netcat puzzle (`nc host port`) → `pwntools` to automate the Q&A loop.
- Obfuscated program → run it in a sandbox and read what it prints; don't reverse by eye.

Per workflow: **no blind brute force** — narrow the space first, script the rest.

## Flag extraction & verification

- The cascade prints `[HIT] ... FLAG: flag{...}` with the transform chain. Note the
  chain so you can reproduce/explain it.
- Grep any decoded output: `grep -aoiE 'flag\{[^}]+\}'` (also try `CTF{`, the
  event's prefix, and base64 of `flag{` = `ZmxhZ3`).
- Confirm format: `flag{...}`, chars `[A-Za-z0-9_]` (and sometimes symbols) inside.
- If a layer decodes to more encoded-looking text, **re-run the cascade on it** —
  deep nesting beyond auto-depth may need a manual peel then another pass.
- Sanity check: a wrong layer gives high-entropy garbage; a right layer gives
  printable text or a recognizable next alphabet.
