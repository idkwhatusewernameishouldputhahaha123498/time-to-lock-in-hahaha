#!/usr/bin/env python3
"""
rsa_attacks.py - common RSA attacks in pure stdlib (no gmpy2/sympy/pycryptodome).

Give it n, e, c (decimal or 0x-hex) and it tries, in order: a direct decrypt if you
supply p/q, small-e / low-exponent e-th root, Fermat factorization (primes close
together), Pollard p-1, and Wiener's attack (small d). Optionally query factordb
with --factordb (needs internet). Prints the message as int and as bytes.

Usage:
    python3 -I rsa_attacks.py --n <N> --e <E> --c <C>
    python3 -I rsa_attacks.py --n <N> --e <E> --c <C> --p <P>        # p (or q) known
    python3 -I rsa_attacks.py --n <N> --e <E> --c <C> --factordb      # try factordb first

All values accept decimal or 0x-hex. Stdlib only; uses pow(e,-1,m) (Python 3.8+).
"""
import sys
import math


def iroot(x, n):
    """Integer n-th root (floor): returns r with r**n <= x < (r+1)**n.

    Newton from a guaranteed OVERESTIMATE (2**ceil(bits/n)) so it converges in
    O(log) big-int steps with no float (float guesses undershoot huge x and the
    old linear fix-up then looped ~forever) and at most a 1-step final adjust."""
    if x < 0:
        raise ValueError("negative")
    if x == 0:
        return 0
    if n == 1:
        return x
    r = 1 << ((x.bit_length() + n - 1) // n)      # >= true root
    while True:
        t = ((n - 1) * r + x // r ** (n - 1)) // n
        if t >= r:
            break
        r = t
    while r ** n > x:
        r -= 1
    return r


def to_bytes(m):
    if m <= 0:
        return b""
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def decrypt(n, e, c, p, q):
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return pow(c, d, n)


def small_e_root(n, e, c):
    """If m**e < n (low exponent, short message), c == m**e over the integers."""
    for k in range(0, 1 << 14):          # c + k*n might be the true e-th power
        cand = c + k * n
        r = iroot(cand, e)
        if r ** e == cand:
            return r
    return None


def fermat(n, rounds=1_000_000):
    """Factor n when p and q are close (n = a**2 - b**2)."""
    a = iroot(n, 2)
    if a * a < n:
        a += 1
    for _ in range(rounds):
        b2 = a * a - n
        b = iroot(b2, 2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def pollard_pm1(n, bound=100000):
    a = 2
    for j in range(2, bound):
        a = pow(a, j, n)
        if j % 64 == 0:
            d = math.gcd(a - 1, n)
            if 1 < d < n:
                return d, n // d
    d = math.gcd(a - 1, n)
    return (d, n // d) if 1 < d < n else None


def wiener(n, e):
    """Wiener's attack: recover small d via continued-fraction convergents of e/n."""
    def cf(x, y):
        while y:
            a = x // y
            yield a
            x, y = y, x - a * y

    def convergents(seq):
        n0, n1, d0, d1 = 0, 1, 1, 0
        for a in seq:
            n0, n1 = n1, a * n1 + n0
            d0, d1 = d1, a * d1 + d0
            yield n0, d0

    for k, d in convergents(cf(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # solve x^2 - (n-phi+1)x + n = 0 ; integer roots => p,q
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        r = iroot(disc, 2)
        if r * r == disc and (b + r) % 2 == 0:
            return d
    return None


def factordb(n):
    try:
        import urllib.request, json
        url = f"http://factordb.com/api?query={n}"
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        factors = []
        for base, power in data.get("factors", []):
            factors += [int(base)] * int(power)
        if len(factors) >= 2 and math.prod(factors) == n:
            # return two coprime cofactors
            if len(factors) == 2:
                return factors[0], factors[1]
            p = factors[0]
            return p, n // p
    except Exception as ex:
        print(f"  (factordb failed: {ex})", file=sys.stderr)
    return None


def _int(s):
    return int(s, 0)


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    opts = {"--n": None, "--e": None, "--c": None, "--p": None, "--q": None}
    use_factordb = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--factordb":
            use_factordb = True; i += 1; continue
        if a in opts:
            if i + 1 >= len(argv):
                print(f"[!] {a} needs a value", file=sys.stderr); return 2
            opts[a] = _int(argv[i + 1]); i += 2; continue
        print(f"[!] unknown arg {a!r}", file=sys.stderr); return 2

    n, e, c = opts["--n"], opts["--e"], opts["--c"]
    if n is None or e is None:
        print("[!] need at least --n and --e (and --c to recover the message)", file=sys.stderr)
        return 2
    p, q = opts["--p"], opts["--q"]

    def finish(p, q, how):
        print(f"[+] factored via {how}:\n    p = {p}\n    q = {q}")
        if c is not None:
            m = decrypt(n, e, c, p, q)
            print(f"[+] m = {m}")
            print(f"[+] bytes = {to_bytes(m)!r}")
        return 0

    if p and not q:
        q = n // p
    if p and q and p * q == n:
        return finish(p, q, "given p/q")

    if use_factordb:
        r = factordb(n)
        if r:
            return finish(r[0], r[1], "factordb")

    # Cheapest / most-specific attacks first; Fermat's big loop runs LAST so a
    # Wiener- or Pollard-solvable key doesn't pay the Fermat tax.
    if c is not None:
        m = small_e_root(n, e, c)
        if m is not None:
            print(f"[+] low-exponent e-th root worked (m**{e} < n or c+k*n).")
            print(f"[+] m = {m}\n[+] bytes = {to_bytes(m)!r}")
            return 0

    d = wiener(n, e)
    if d is not None:
        print(f"[+] Wiener's attack recovered d = {d}")
        if c is not None:
            m = pow(c, d, n)
            print(f"[+] m = {m}\n[+] bytes = {to_bytes(m)!r}")
        return 0

    r = pollard_pm1(n)
    if r:
        return finish(r[0], r[1], "Pollard p-1")

    print("[*] trying Fermat (up to 1e6 rounds; only finds CLOSE primes)...", file=sys.stderr)
    r = fermat(n)
    if r:
        return finish(r[0], r[1], "Fermat (close primes)")

    print("[-] none of the built-in attacks worked. Try: --factordb, RsaCtfTool, "
          "or check for shared factors / common modulus across multiple keys.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
