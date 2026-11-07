#!/usr/bin/env python3
"""image_amplify.py -- reveal content hidden in a "blank"/washed-out/stego image.

Usage:
    python3 -I image_amplify.py <image> [tolerance] [--outdir DIR] [--all]

<image>      PNG/JPG/BMP/GIF/TIFF... anything Pillow can open.
[tolerance]  int 0..254 (default 0). Widens what counts as "pure" white/black for
             the threshold views, e.g. tolerance 10 treats 245..255 as white.
--outdir DIR write outputs to DIR instead of a sibling folder (keep a read-only
             challenge folder clean; defaults to "<stem>_amplified/" next to input).
--all        write ALL 8 bit-planes per channel. Default writes only the high-value
             planes (bit 0,1,7) so you review ~a dozen images, not forty.

Writes into the output folder:
  threshold_offwhite.png   pixels NOT pure white -> black   (Pixel Perfect: text at 226-254)
  threshold_offblack.png   pixels NOT pure black -> white   (text drawn just above 0)
  contrast_autocontrast.png / contrast_equalized.png        (faint low-contrast detail)
  bitplane_<chan>_bit<n>.png  high-value planes by default, all with --all
  channel_<chan>.png       each channel (+ alpha) as grayscale

It ALSO reads the LSB stream (several channel/bit orders, MSB- and LSB-first) and
prints any flag{...} or long printable ASCII run it finds -- a quick zsteg stand-in.

Pure numpy + Pillow, no network, no scipy. Run with -I so a planted module in the
input's directory can't be imported.
"""
import sys
import os
import re

HELP = __doc__


def die(msg, code=2):
    sys.stderr.write(msg.rstrip() + "\n")
    sys.exit(code)


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(HELP)
        return 0
    outdir_opt = None
    all_planes = False
    positional = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--outdir":
            if i + 1 >= len(argv):
                die("--outdir needs a directory")
            outdir_opt = argv[i + 1]; i += 2; continue
        if a == "--all":
            all_planes = True; i += 1; continue
        positional.append(a); i += 1
    if not positional:
        print(HELP); return 0
    path = os.path.abspath(positional[0])
    tol = 0
    if len(positional) >= 2:
        try:
            tol = max(0, min(254, int(positional[1])))
        except ValueError:
            die("tolerance must be an integer 0..254")

    try:
        import numpy as np
        from PIL import Image, ImageOps
    except ImportError as e:
        die("Missing dependency: %s\n  pip install numpy pillow" % getattr(e, "name", e))

    if not os.path.isfile(path):
        die("No such file: %s" % path)

    try:
        img = Image.open(path)
        img.load()
    except Exception as e:  # noqa: BLE001 -- report any decode failure plainly
        die("Could not open image (%s). Is it really an image? Try `file` / binwalk." % e)

    print("[*] %s  mode=%s size=%sx%s" % (path, img.mode, img.width, img.height))

    stem = os.path.splitext(os.path.basename(path))[0]
    outdir = (os.path.abspath(outdir_opt) if outdir_opt
              else os.path.join(os.path.dirname(path), stem + "_amplified"))
    os.makedirs(outdir, exist_ok=True)
    written = []

    def save(name, arr):
        p = os.path.join(outdir, name)
        Image.fromarray(np.asarray(arr, dtype=np.uint8)).save(p)
        written.append(p)

    rgb = np.asarray(img.convert("RGB"))          # (H, W, 3)
    bands = img.getbands()
    alpha = None
    if "A" in bands:
        alpha = np.asarray(img.convert("RGBA"))[:, :, 3]

    # (a) THRESHOLD views -----------------------------------------------------
    # off-white: background is near-255; text is anything darker -> black on white.
    white_bg = np.all(rgb >= (255 - tol), axis=2)
    save("threshold_offwhite.png", np.where(white_bg, 255, 0))
    # off-black: background is near-0; text is anything brighter -> white on black.
    black_bg = np.all(rgb <= tol, axis=2)
    save("threshold_offblack.png", np.where(black_bg, 0, 255))

    # (c) CONTRAST views ------------------------------------------------------
    rgb_im = Image.fromarray(rgb)
    save("contrast_autocontrast.png", np.asarray(ImageOps.autocontrast(rgb_im, cutoff=1)))
    # histogram-equalize per channel for maximum lift of faint gradients.
    save("contrast_equalized.png", np.asarray(ImageOps.equalize(rgb_im)))

    # (d) CHANNEL splits ------------------------------------------------------
    chans = [("R", rgb[:, :, 0]), ("G", rgb[:, :, 1]), ("B", rgb[:, :, 2])]
    if alpha is not None:
        chans.append(("A", alpha))
    for name, ch in chans:
        save("channel_%s.png" % name, ch)

    # (b) BIT-PLANES ----------------------------------------------------------
    # Default to the high-value planes (LSBs + MSB); --all writes every plane.
    bit_list = range(8) if all_planes else (0, 1, 7)
    for name, ch in chans:
        for bit in bit_list:
            plane = ((ch >> bit) & 1) * 255
            save("bitplane_%s_bit%d.png" % (name, bit), plane)

    # LSB -> bytes scan (zsteg-lite) -----------------------------------------
    print("\n[*] LSB scan (flag{...} / printable runs):")
    hits = lsb_scan(np, rgb, alpha)
    if hits:
        for label, kind, text in hits:
            print("    [%s] %-18s %s" % (kind, label, text))
    else:
        print("    (nothing obvious in plain LSB -- try: zsteg -a, higher bit-planes,")
        print("     or steghide/outguess with a password from the challenge text)")

    print("\n[+] %d images written to:\n    %s" % (len(written), outdir))
    for p in written:
        print("    " + p)
    print("\n[>] Eyeball every file. Threshold/bit0 images reveal most drawn text.")
    print("[>] Faint text confuses l/1/!, O/0, s/5, B/8 -- zoom & compare to disambiguate.")
    return 0


def lsb_scan(np, rgb, alpha):
    """Extract common LSB bit-orderings and search for flags / printable text."""
    streams = []
    r, g, b = rgb[:, :, 0], rgb[:, :, 1], rgb[:, :, 2]
    # per-channel LSB, row-major
    streams.append(("R lsb xy", (r & 1).reshape(-1)))
    streams.append(("G lsb xy", (g & 1).reshape(-1)))
    streams.append(("B lsb xy", (b & 1).reshape(-1)))
    # interleaved RGB LSB (zsteg's b1,rgb,lsb,xy), row-major
    streams.append(("RGB lsb xy", (rgb & 1).reshape(-1)))
    if alpha is not None:
        streams.append(("A lsb xy", (alpha & 1).reshape(-1)))

    found = []
    flag_re = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,24}\{[ -~]{1,120}?\}")  # flag{}, picoCTF{}, ...
    for label, bits in streams:
        bits = np.asarray(bits, dtype=np.uint8)
        for order in ("big", "little"):
            data = np.packbits(bits, bitorder=order).tobytes()
            for m in flag_re.finditer(data):
                found.append((label, "flag/" + order, m.group().decode("latin1")))
            if not any(h[0] == label for h in found):
                run = longest_printable(data)
                if run and len(run) >= 10:
                    found.append((label, "ascii/" + order, run[:80]))
    # de-dup while keeping order
    seen, uniq = set(), []
    for h in found:
        key = (h[1], h[2])
        if key not in seen:
            seen.add(key)
            uniq.append(h)
    return uniq


def longest_printable(data):
    best = b""
    cur = bytearray()
    for byte in data[:200000]:  # bound the scan
        if 32 <= byte < 127:
            cur.append(byte)
        else:
            if len(cur) > len(best):
                best = bytes(cur)
            cur = bytearray()
    if len(cur) > len(best):
        best = bytes(cur)
    return best.decode("latin1")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
