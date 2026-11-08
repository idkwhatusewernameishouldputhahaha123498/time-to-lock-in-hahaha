---
name: ctf-stego
description: Crack steganography CTF challenges hiding a flag in an IMAGE or AUDIO file (PNG/JPG/BMP/GIF, WAV/MP3). Reach for this the instant you get a media file, a "blank"/"washed-out"/all-white image, a "hidden message", or clues like spectrogram, LSB, steghide, zsteg, "listen"/"hum"/"frequency"/"hidden in the air". Runs a fast triage first, then image and audio branches with two bundled scripts.
---

# CTF Steganography (image + audio)

Find the flag hidden *in* a picture or sound. The flag format is `flag{...}`
(letters/digits/underscores). Work the CLUE first, amplify second, brute force never.

## Mindset (read the memory lessons)
- **Clue-first.** The challenge text, title, hints, filename and metadata almost always
  name the technique ("listen to the hum", "it looks blank", "keys to my lock is 8").
  Translate the prose into the exact method before touching a tool.
- **The easy LLM path is defended.** Do the mechanical extraction with the scripts here,
  then spot the human-findable artifact the designer leaked.
- **Glyph ambiguity.** Hidden text is often *drawn* (thresholded pixels, frequency-domain
  font, Morse). Faint/blocky glyphs confuse `l/1/!`, `O/0`, `s/5`, `B/8`, `rn/m`.
  Zoom in and compare shapes before you commit a character. Try both readings when you
  submit (e.g. `flag{5p...}` and `flag{sp...}`).
- Stego output often feeds a *crypto* step (rail-fence, base64, XOR). Hand the recovered
  ciphertext + clues to the **ctf-crypto** skill.

---

## 0. FAST PATH — run on ANY media file, image or audio, BEFORE anything else

```bash
F=challenge.png                          # the file you were given
file "$F"                                # true type (ext often lies: a "png" that's a zip)
strings -n 8 "$F" | grep -iE 'flag\{|flag|ctf|key|pass|secret'   # flag sitting in plain bytes
binwalk "$F"                             # embedded/appended files (zip, another image, text)
exiftool "$F"                            # metadata: Comment/Artist/Description often hold text
```

Why: a huge fraction of "stego" challenges are just **data appended after the real file's
end**, a flag in a metadata field, or a flag in the raw strings. These four take seconds and
win outright surprisingly often.

**Check for data after the image EOF** (nothing valid should follow it):

```bash
# PNG ends at IEND; JPG ends at FF D9. If bytes continue past it, carve them out.
binwalk -e "$F"                          # auto-extract; look in _"$F".extracted/
# manual carve once you know the offset N of the trailing archive:
dd if="$F" bs=1 skip=N of=payload.bin && file payload.bin && unzip -o payload.bin
```

Also try `unzip "$F"` and `7z l "$F"` directly — many PNG/JPG files are valid ZIPs when a
`.zip` was concatenated on (a "polyglot"). If FAST PATH finds nothing, pick the branch below.

> Tools not installed? `file`/`strings`/`python3`+numpy+Pillow are enough for most of this.
> For the rest (macOS): `brew install binwalk exiftool steghide outguess sox` ·
> `gem install zsteg` · `pip install pillow numpy`. Don't block on installs — the two
> bundled scripts are pure numpy+Pillow and cover the headline techniques.

---

## Branch A — IMAGE  (PNG / JPG / BMP / GIF / TIFF)

### A1. "Blank", all-white, washed-out, or all-black image  ← do this FIRST for faint images
Text is drawn in pixels a hair off pure white (e.g. 226–254) or off pure black. Amplify it:

```bash
python3 -I scripts/image_amplify.py <image> [tolerance]
```

It writes `<stem>_amplified/` next to the input with:
- `threshold_offwhite.png` — every non-pure-white pixel → black (the **Pixel Perfect** win:
  text at 226–254 on a 255 background jumps out).
- `threshold_offblack.png` — every non-pure-black pixel → white.
- `contrast_autocontrast.png` / `contrast_equalized.png` — lift faint gradients.
- `channel_<R/G/B/A>.png` and `bitplane_<chan>_bit0..7.png` — one image per channel & bit.

`tolerance` (default 0) widens "pure": `tolerance 10` treats 245–255 as white, useful when
the background itself is slightly off-255 or there's JPEG noise. The script also runs a quick
**LSB byte scan** and prints any `flag{...}` it finds directly.

Recovered clues/ciphertext? The Pixel Perfect flag then needed a **Rail Fence** decode
("keys to my lock is 8" = 8 rails, "move up by 5" = offset) — go to **ctf-crypto**.

### A2. LSB / bit-plane data (the classic)
`image_amplify.py` already (a) renders every bit-plane as an image — eyeball `bit0` of each
channel for drawn text or a QR — and (b) reads the plain LSB stream in several orders and
greps for `flag{`. For anything fancier, `zsteg` is the gold standard on **PNG/BMP**:

```bash
zsteg -a <image>                         # try ALL bit/channel/order combos, auto
zsteg -E 'b1,rgb,lsb,xy' <image>         # extract one specific payload zsteg flagged
```

`zsteg` reports the winning spec (e.g. `b1,r,lsb,xy`). GUI equivalent: **StegSolve**
(browse planes, "Data Extract", XOR). Try: each channel; LSB vs MSB first; row-major (`xy`)
vs column-major (`yx`); 1-bit and 2-bit depths.

### A3. Appended archives / carved files
If A0/binwalk hinted at embedded data: `binwalk -e <image>`, then inspect the extracted
folder. Peel nested archives (seen in prior challenges: `.zip.zip` → `.7z` AES). A ZIP/7z
password is usually in the challenge text or a planted file — reverse-psychology names like
`dontlook/`, `nobody_read_this.txt` are **signposts, not warnings**. For AES-7z use the
**ctf-forensics** / nested-archive workflow (`py7zr` in pure Python).

### A4. steghide / outguess (JPEG/BMP/WAV; password-protected)
`steghide` embeds in **JPEG, BMP, WAV, AU** (not PNG) and is almost always passworded —
the password is usually a word from the challenge prompt, title, or image text.

```bash
steghide info <file>                              # does it even contain a steghide payload?
steghide extract -sf <file> -p ''                 # try empty password first
steghide extract -sf <file> -p '<word-from-clue>' # then the clue word(s)
outguess -k '<password>' -r <file.jpg> out.txt    # the other common JPEG tool
```

Only if the clue gives a wordlist should you loop a handful of candidate words — not a
blind dictionary. (`stegcracker <file> wordlist` exists but is last resort.)

### A5. The rest of the image toolbox
- **PNG chunks:** `pngcheck -v <png>` — hidden/duplicate/oversized `tEXt`/`zTXt`/`iTXt`
  chunks carry comments; malformed dims can hide rows (fix width/height to reveal).
- **Palette / colormap:** indexed PNG/GIF — remap or flatten the palette (a nearly-identical
  colormap can hide a drawn image). In `image_amplify` the channel/threshold views expose it.
- **Alpha channel:** data hidden in transparency — see `channel_A.png` and `bitplane_A_*`.
- **QR / barcode drawn in a plane:** if a bit-plane looks like a QR, screenshot and decode
  (`zbarimg`, or any phone/online QR reader).
- **Two images / XOR / diff:** given a pair, XOR or `compare`/subtract them to reveal text.
- **Metadata text:** re-check `exiftool`'s Comment/UserComment/Description/XMP fields.

---

## Branch B — AUDIO  (WAV / MP3 / FLAC / OGG)

MP3/OGG/FLAC first → convert to WAV: `ffmpeg -i in.mp3 out.wav` (or `sox in.mp3 out.wav`).

### B1. Spectrogram — text drawn in the frequency domain  ← do this FIRST for audio
Clues "hum / frequency / listen / hidden in the air / spectrum" mean the message is **drawn
in the spectrogram**, often buried under noise (the **Killer Frequencies** win: `crickets.wav`).

```bash
python3 -I scripts/spectrogram.py <file.wav> [nfft] [hop]
# e.g. python3 -I scripts/spectrogram.py crickets.wav 1024 256
```

For each channel it writes next to the input:
- `<stem>.spectrogram_ch<n>.png` — STFT magnitude in dB, **low frequency at the bottom**.
- `<stem>.spectrogram_ch<n>_medsub.png` — same, minus each frequency's median over time.
  **Open this one first:** subtracting the per-frequency median erases steady background
  (cricket/white noise) and lifts the faint drawn glyphs out.

Bigger `nfft` (e.g. 2048) = finer frequency detail; smaller `hop` = finer time detail.
GUI alternative: **Audacity** (Spectrogram view) or **Sonic Visualiser**. Beware `s/5`,
`l/1`, `O/0` in the drawn font.

### B2. LSB in WAV samples
Same idea as image LSB, over 16-bit samples. Quick pure-Python extract:

```bash
python3 -I - <<'PY' <file.wav>
import sys, wave, numpy as np, re
w=wave.open(sys.argv[1],'rb'); d=np.frombuffer(w.readframes(w.getnframes()),np.int16)
for order in ('big','little'):
    b=np.packbits((d&1).astype(np.uint8),bitorder=order).tobytes()
    m=re.search(rb'flag\{[ -~]{1,120}?\}',b,re.I)
    if m: print(order,m.group().decode()); break
PY
```

### B3. Tones that encode symbols — Morse / DTMF / SSTV
If the spectrogram shows short/long tone bursts or dual tones instead of drawn text:
- **Morse:** dots/dashes as tone-on/tone-off. Read off the spectrogram or decode by ear;
  map `· —` → letters. Tools: online Morse decoders, `morse2ascii`.

  **Auto-decode Morse (no ear needed):** split stereo (L=`samples[0::2]`, R=`[1::2]`); pick the Morse
  channel = **highest peak-to-mean** of its RMS envelope (beeps+silence spike it, music doesn't);
  RMS envelope = sqrt(movavg(signal², ~50 ms)); threshold at ~0.15×max → beep/gap runs; classify
  beep <~200 ms = dot else dash, gap >~500 ms = char boundary; map via Morse table. Tune thresholds
  off the printed beep/gap duration histogram.
  **DTMF:** `multimon-ng -a DTMF -t wav file.wav` → digits → multi-tap keypad for letters.
- **DTMF** (phone keypad, pairs of tones): `multimon-ng -a DTMF -t wav <file.wav>`.
- **SSTV** (slow-scan TV — audio that decodes to a *picture* holding the flag): play into
  **QSSTV** (Linux) or **Robot36** (Android), or `pip install sstv` → `sstv -d <file.wav>`.
  Modes: Martin, Scottie, Robot36.

### B4. Reversed, tempo/pitch-shifted, multi-channel
- **Backmasked:** reverse and listen/re-spectrogram: `sox in.wav rev.wav reverse`.
- **Tempo/pitch:** slow it down to expose hidden speech/tones: `sox in.wav out.wav speed 0.5`
  or `tempo 0.5`.
- **Stereo carries two messages:** `spectrogram.py` already renders each channel separately.
  Also try the channel *difference*: `sox in.wav mono.wav remix 1-2` (L−R) can isolate a
  signal hidden only in the side channel.

---

## Branch C — VIDEO  (MP4 / MKV / AVI / GIF)
Pull frames first, then treat them as images / the audio track as audio:
```bash
ffprobe -hide_banner file.mp4                 # enumerate streams — a 2nd video stream is often the flag
ffmpeg -i file.mp4 -map 0:1 -frames:v 1 flag.png   # extract the (red-herring-hidden) secondary stream
ffmpeg -i file.mp4 -vsync 0 frames/%04d.png   # dump every frame, then composite:
```
- **Frame accumulation** (icons/shapes flash at positions → a QR/picture): per-pixel **maximum**
  across all frames → `accumulated.png` (`np.maximum.reduce`), then `zbarimg`.
- **Frame averaging** (content buried in motion/noise): per-pixel **mean** across frames
  (`sum(frame/N)`), then `ImageOps.equalize` to lift it. Reveals faint text/QR/watermark.
- **Audio track:** `ffmpeg -i file.mp4 -vn -acodec pcm_s16le a.wav` → run **Branch B** on `a.wav`;
  try reversed too (`sox a.wav r.wav reverse`).

---

## Verify & submit
1. Confirm the match is a real flag: `grep -aoE 'flag\{[A-Za-z0-9_]+\}'` over any recovered
   bytes/text. Watch for ligatures/odd glyphs breaking the regex.
2. If the flag came from *drawn* text, re-read every ambiguous glyph (`l/1/!`, `O/0`, `s/5`,
   `B/8`) against the clearest copy; keep a second reading ready in case the first is rejected.
3. If you recovered ciphertext instead of a flag, pass it + the clues to **ctf-crypto**
   (rail-fence, base64, XOR, Vigenère...).
4. Submit exactly `flag{...}` — no surrounding quotes or spaces.

**Last resort only:** blind brute force (steghide/zip dictionaries). There is almost always
a clue; find it first.
