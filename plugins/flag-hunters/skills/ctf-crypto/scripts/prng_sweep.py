#!/usr/bin/env python3
"""prng_sweep.py -- seed in, candidate outputs out.

Given a numeric SEED, reimplement the common standard PRNGs *platform-independently*
and print their first N outputs in RAW form plus a few bounded forms (% mod, ranges).
A human (or grep) then matches a known candidate value against the table.

WHY this exists (the "Random Encounter" lesson):
  A leaked timestamp/metadata value is very often the RNG seed, and the secret
  (a password, a token) is ONE OUTPUT of a *standard* seeded generator. The trap is
  that `rand()` differs by platform: macOS rand() != Linux glibc rand() != MSVC.
  So never trust the local libc -- reimplement every candidate generator here and
  compare. In that challenge the winner was:
      std::minstd_rand0 (Park-Miller, a=16807, m=2147483647)
      seed = 1183075200  ->  OUTPUT INDEX 1 (the 2nd draw) = 32285335
  You can confirm it below:  python3 -I prng_sweep.py 1183075200

Index convention: index 0 = FIRST draw after seeding, index 1 = SECOND draw, ...
(so the Random Encounter password sits at index 1).

Usage:
  python3 -I prng_sweep.py <seed> [count] [--mod N] [--grep VALUE]
    count     how many outputs per generator (default 8)
    --mod N   also print each raw output % N (e.g. --mod 1000000)
    --grep V  highlight any generator/index whose raw OR bounded output == V
              (give an integer; this is how you auto-find the matching generator)

Everything is stdlib-only except optional numpy (used only if importable).
"""
import sys

M31 = 2147483647          # 2**31 - 1, the Mersenne prime used by minstd/glibc TYPE_3
U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF


# --------------------------------------------------------------------------- #
# Generators. Each returns a list of `count` raw integer outputs for `seed`.
# Keep them independent of the host libc so results are reproducible anywhere.
# --------------------------------------------------------------------------- #

def gen_minstd(seed, count, a):
    """C++ std::linear_congruential_engine (minstd). a=16807 -> minstd_rand0,
    a=48271 -> minstd_rand. c=0, m=2**31-1. State seeded to seed%m (1 if 0);
    operator() advances THEN returns, so out[0] = (a*seed) % m."""
    x = seed % M31
    if x == 0:
        x = 1
    out = []
    for _ in range(count):
        x = (a * x) % M31
        out.append(x)
    return out


def gen_glibc_rand(seed, count):
    """glibc random()/rand() default TYPE_3 additive feedback (deg 31, sep 3).
    This is what Linux `rand()` actually returns (range 0 .. 2**31-1)."""
    r = [0] * (344 + count)
    r[0] = seed & U32
    for i in range(1, 31):
        # 16807*r[i-1] % 2147483647 done the signed way glibc uses
        hi, lo = divmod(r[i - 1], 127773)
        word = 16807 * lo - 2836 * hi
        if word < 0:
            word += M31
        r[i] = word
    for i in range(31, 34):
        r[i] = r[i - 31]
    for i in range(34, 344 + count):
        r[i] = (r[i - 31] + r[i - 3]) & U32
    out = []
    for i in range(344, 344 + count):
        out.append((r[i] >> 1) & 0x7FFFFFFF)
    return out


def gen_ansi_c(seed, count):
    """ANSI C / classic LCG: next = next*1103515245 + 12345; rand = (next>>16)&0x7fff."""
    x = seed & U32
    out = []
    for _ in range(count):
        x = (x * 1103515245 + 12345) & U32
        out.append((x >> 16) & 0x7FFF)
    return out


def gen_msvc(seed, count):
    """Microsoft MSVC rand(): state = state*214013 + 2531011; (state>>16)&0x7fff."""
    x = seed & U32
    out = []
    for _ in range(count):
        x = (x * 214013 + 2531011) & U32
        out.append((x >> 16) & 0x7FFF)
    return out


def gen_java(seed, count):
    """java.util.Random: 48-bit LCG. nextInt() = next(32) as signed int32."""
    s = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)
    out = []
    for _ in range(count):
        s = (s * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        v = s >> (48 - 32)          # next(32)
        if v >= (1 << 31):          # Java int is signed
            v -= (1 << 32)
        out.append(v)
    return out


def gen_musl(seed, count):
    """musl libc rand(): seed=s-1; seed=6364136223846793005*seed+1; return seed>>33."""
    s = (seed - 1) & U64
    out = []
    for _ in range(count):
        s = (6364136223846793005 * s + 1) & U64
        out.append(s >> 33)
    return out


def _mt_seed(seed):
    """Reference MT19937 init_genrand(seed)."""
    mt = [0] * 624
    mt[0] = seed & U32
    for i in range(1, 624):
        mt[i] = (1812433253 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & U32
    return mt


def _mt_temper(y):
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    return y & U32


def gen_mt19937_c(seed, count):
    """Reference C MT19937 genrand_int32 (NOT Python's seeding -- matches C/C++
    std::mt19937 and many libraries). Returns 32-bit outputs."""
    mt = _mt_seed(seed)
    idx = 624
    out = []
    for _ in range(count):
        if idx >= 624:
            for i in range(624):
                y = (mt[i] & 0x80000000) | (mt[(i + 1) % 624] & 0x7FFFFFFF)
                mt[i] = mt[(i + 397) % 624] ^ (y >> 1)
                if y & 1:
                    mt[i] ^= 0x9908B0DF
            idx = 0
        out.append(_mt_temper(mt[idx]))
        idx += 1
    return out


def gen_php_mt_rand(seed, count):
    """PHP mt_rand(): MT19937 with PHP's (historically buggy) reload where the
    twist uses loBit of the WRONG word. Output is php_mt_rand() >> 1."""
    mt = _mt_seed(seed)

    def twist_php(m, u, v):
        return (m ^ (((u & 0x80000000) | (v & 0x7FFFFFFF)) >> 1)
                ^ ((0xFFFFFFFF * (v & 1)) & 0x9908B0DF)) & U32

    def reload():
        for i in range(624 - 397):
            mt[i] = twist_php(mt[i + 397], mt[i], mt[i + 1])
        for i in range(624 - 397, 623):
            mt[i] = twist_php(mt[i + 397 - 624], mt[i], mt[i + 1])
        mt[623] = twist_php(mt[396], mt[623], mt[0])

    idx = 624
    out = []
    for _ in range(count):
        if idx >= 624:
            reload()
            idx = 0
        out.append(_mt_temper(mt[idx]) >> 1)
        idx += 1
    return out


def gen_python_random(seed, count):
    """Python's own random.Random(seed) via getrandbits(32). Shown for completeness;
    note Python uses init_by_array seeding, so it differs from gen_mt19937_c."""
    import random
    r = random.Random(seed)
    return [r.getrandbits(32) for _ in range(count)]


def gen_numpy(seed, count):
    """Legacy numpy MT (RandomState) 32-bit ints, only if numpy is importable."""
    try:
        import numpy as np
    except Exception:
        return None
    rs = np.random.RandomState(seed & U32)
    return [int(x) for x in rs.randint(0, 1 << 32, size=count, dtype=np.uint32)]


GENERATORS = [
    ("minstd_rand0 (a=16807, m=2^31-1)", lambda s, c: gen_minstd(s, c, 16807)),
    ("minstd_rand  (a=48271, m=2^31-1)", lambda s, c: gen_minstd(s, c, 48271)),
    ("glibc rand()/random() TYPE_3", gen_glibc_rand),
    ("ANSI C LCG (1103515245,12345)", gen_ansi_c),
    ("MSVC rand() (214013,2531011)", gen_msvc),
    ("Java util.Random nextInt()", gen_java),
    ("musl libc rand()", gen_musl),
    ("MT19937 (C/C++ reference seeding)", gen_mt19937_c),
    ("PHP mt_rand() (php reload)", gen_php_mt_rand),
    ("Python random.Random", gen_python_random),
    ("numpy RandomState (if available)", gen_numpy),
]


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    # parse args
    seed = None
    count = 8
    mod = None
    grep = None
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--mod":
            mod = int(argv[i + 1]); i += 2; continue
        if a == "--grep":
            grep = int(argv[i + 1], 0); i += 2; continue
        positional.append(a); i += 1
    seed = int(positional[0], 0)
    if len(positional) > 1:
        count = int(positional[1])

    print(f"# seed = {seed}  (0x{seed & U64:x})   count = {count}"
          + (f"   mod = {mod}" if mod else "")
          + (f"   grep = {grep}" if grep is not None else ""))
    print("# index 0 = first draw after seeding (Random Encounter password was index 1)\n")

    hits = []
    for name, fn in GENERATORS:
        outs = fn(seed, count)
        if outs is None:
            print(f"== {name}: (unavailable)\n")
            continue
        print(f"== {name}")
        for idx, v in enumerate(outs):
            line = f"   [{idx}] {v}"
            extras = []
            if mod:
                extras.append(f"%{mod}={v % mod}")
            # a couple of always-useful bounded forms
            extras.append(f"%100={v % 100}")
            if extras:
                line += "   (" + " ".join(extras) + ")"
            if grep is not None and (v == grep or (mod and v % mod == grep)
                                     or v % 100 == grep):
                line += "   <<< MATCH"
                hits.append((name, idx, v))
            print(line)
        print()

    if grep is not None:
        print("# MATCHES:" if hits else "# no matches for grep value")
        for name, idx, v in hits:
            print(f"#   {name}  index {idx}  value {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
