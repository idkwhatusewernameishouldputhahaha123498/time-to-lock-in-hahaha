#!/usr/bin/env python3
"""spectrogram.py -- render a WAV's spectrogram to reveal text drawn in the frequency domain.

Usage:
    python3 -I spectrogram.py <file.wav> [nfft] [hop]
    python3 -I spectrogram.py <file.wav> nfft=2048 hop=256

<file.wav>  PCM WAV (stdlib `wave`); 8/16/24/32-bit, mono or stereo.
[nfft]      FFT window size (default 1024). Bigger = finer frequency detail.
[hop]       samples between windows (default 256). Smaller = finer time detail.

For EACH channel it writes, NEXT TO the input:
  <stem>.spectrogram_ch<n>.png          STFT magnitude in dB, low freq at BOTTOM
  <stem>.spectrogram_ch<n>_medsub.png   same, minus each frequency's median over time
                                        -> lifts faint DRAWN text out of steady noise
                                        (the Killer Frequencies win: crickets.wav)

Clues that point here: "hum", "frequency", "listen", "hidden in the air", "spectrum".
Pure numpy + stdlib `wave`, output via Pillow. No network, no scipy. Run with -I.
"""
import sys
import os
import wave

HELP = __doc__


def die(msg, code=2):
    sys.stderr.write(msg.rstrip() + "\n")
    sys.exit(code)


def parse_args(argv):
    path, nfft, hop = None, 1024, 256
    pos = []
    for a in argv[1:]:
        if a in ("-h", "--help"):
            print(HELP)
            sys.exit(0)
        if "=" in a:
            k, v = a.split("=", 1)
            if k == "nfft":
                nfft = int(v)
            elif k == "hop":
                hop = int(v)
            else:
                die("unknown option: %s" % a)
        else:
            pos.append(a)
    if not pos:
        print(HELP)
        sys.exit(0)
    path = pos[0]
    if len(pos) >= 2:
        nfft = int(pos[1])
    if len(pos) >= 3:
        hop = int(pos[2])
    return os.path.abspath(path), max(16, nfft), max(1, hop)


def read_wav(np, path):
    """Return (samples float64 shape (N, nch), framerate)."""
    try:
        w = wave.open(path, "rb")
    except Exception as e:  # noqa: BLE001
        die("Not a readable PCM WAV (%s). If it's MP3/other, convert first:\n"
            "  ffmpeg -i in.mp3 out.wav   (or `sox in.mp3 out.wav`)" % e)
    nch, sw, fr, nframes = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
    raw = w.readframes(nframes)
    w.close()
    if sw == 1:  # unsigned 8-bit
        data = np.frombuffer(raw, dtype=np.uint8).astype(np.float64) - 128.0
    elif sw == 2:
        data = np.frombuffer(raw, dtype=np.int16).astype(np.float64)
    elif sw == 4:
        data = np.frombuffer(raw, dtype=np.int32).astype(np.float64)
    elif sw == 3:  # packed 24-bit little-endian
        a = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3).astype(np.int32)
        v = a[:, 0] | (a[:, 1] << 8) | (a[:, 2] << 16)
        data = np.where(v >= (1 << 23), v - (1 << 24), v).astype(np.float64)
    else:
        die("unsupported sample width: %d bytes" % sw)
    data = data.reshape(-1, nch)
    print("[*] %s  %d ch, %d Hz, %d-bit, %.2fs" % (path, nch, fr, sw * 8, len(data) / fr))
    return data, fr


def stft_db(np, sig, nfft, hop):
    """Short-time Fourier transform magnitude in dB, shape (freqbins, frames)."""
    from numpy.lib.stride_tricks import sliding_window_view
    if len(sig) < nfft:
        die("signal shorter than nfft=%d (only %d samples)" % (nfft, len(sig)))
    window = np.hanning(nfft)
    frames = sliding_window_view(sig, nfft)[::hop]       # (nframes, nfft) view
    frames = frames * window                             # copy + taper
    spec = np.fft.rfft(frames, axis=1)                   # (nframes, nfft/2+1)
    mag = np.abs(spec).T                                 # (freqbins, nframes)
    return 20.0 * np.log10(mag + 1e-9)


def to_png(np, Image, db, path):
    """Normalize dB (1st-99th pct), low freq at bottom, save grayscale PNG."""
    lo, hi = np.percentile(db, 1), np.percentile(db, 99)
    if hi <= lo:
        hi = lo + 1.0
    norm = np.clip((db - lo) / (hi - lo), 0, 1)
    img = np.flipud((norm * 255).astype(np.uint8))      # flip so low freq is at bottom
    Image.fromarray(img, "L").save(path)
    return img.shape


def main(argv):
    path, nfft, hop = parse_args(argv)
    try:
        import numpy as np
        from PIL import Image
    except ImportError as e:
        die("Missing dependency: %s\n  pip install numpy pillow" % getattr(e, "name", e))
    if not os.path.isfile(path):
        die("No such file: %s" % path)

    data, fr = read_wav(np, path)
    stem = os.path.splitext(path)[0]
    nch = data.shape[1]
    written = []

    for ch in range(nch):
        db = stft_db(np, data[:, ch].copy(), nfft, hop)
        p1 = "%s.spectrogram_ch%d.png" % (stem, ch)
        shape = to_png(np, Image, db, p1)
        written.append(p1)
        # per-frequency median subtraction: kill steady background, keep drawn text
        med = np.median(db, axis=1, keepdims=True)
        p2 = "%s.spectrogram_ch%d_medsub.png" % (stem, ch)
        to_png(np, Image, db - med, p2)
        written.append(p2)
        print("    ch%d -> %d freq bins x %d frames (nfft=%d hop=%d)"
              % (ch, shape[0], shape[1], nfft, hop))

    print("\n[+] %d images written next to the input:" % len(written))
    for p in written:
        print("    " + p)
    print("\n[>] Open the *_medsub.png first -- drawn text pops once the noise floor is removed.")
    print("[>] No text but rhythmic tones? Suspect Morse (dot/dash), DTMF, or SSTV -- see SKILL.")
    print("[>] Drawn glyphs confuse s/5, l/1, O/0, B/8 -- zoom & compare before you commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
