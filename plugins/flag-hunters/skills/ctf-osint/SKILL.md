---
name: ctf-osint
description: Use for OSINT & geolocation CTF challenges — a photo to locate, "where was this taken", geolocation, landmark/building/street-sign ID, username/handle lookup, social-media pivoting, EXIF GPS, "find the person/place", whois/domain, DNS/cert history, or Wayback. Run exiftool FIRST, then reverse-image-search, then reason from visual clues.
---

# CTF OSINT & Geolocation

OSINT only against the in-scope challenge target / game world. Do NOT target real
private individuals outside the challenge. Goal: locate a place/person/asset FAST,
then do EXACTLY whatever transform the prompt demands on the facts you found.

## FAST PATH (do in this order, stop when you have the answer)

1. **EXIF / metadata FIRST** — free GPS, cheapest win:
   ```
   exiftool image.jpg
   exiftool -gps:all -n image.jpg          # raw lat/long numbers
   exiftool -GPSLatitude -GPSLongitude -GPSPosition -DateTimeOriginal -Model image.jpg
   ```
   - If GPS is present → paste `lat, long` straight into a map. Done.
   - Also note `Make/Model` (device), `DateTimeOriginal` (time of day → sun angle),
     `Software` (editing hints), thumbnails (`exiftool -b -ThumbnailImage` may differ
     from a cropped/edited main image — a classic reveal).
   - No exiftool? `strings image.jpg | grep -iE 'gps|exif|lat|lon'`, or any online EXIF viewer.
   - Stripped metadata (social-media re-uploads strip EXIF) → go to step 2.

2. **Reverse image search** — find the same/similar image on the web.
   Pick the engine by job:
   - **Google Lens** (images.google.com / lens.google.com) — best general matcher,
     great at landmarks, products, text-in-image. Start here.
   - **Yandex** — BEST for *places, buildings, faces, and anything outside the
     Anglosphere*. If Lens fails on a street scene, Yandex usually wins. Always try it.
   - **TinEye** — best for finding the ORIGINAL / oldest copy, crops, and where an
     image was first posted (good for "who posted this" pivots). Sorts by date.
   - **Bing Visual Search** — second opinion; sometimes beats Lens on logos/signage.
   - Try **crops**: search the sign, the logo, the mountain, the building alone.
     Cropping to one distinctive object dramatically improves matches.

3. **Read the photo for clues** — if reverse search is inconclusive, geolocate by
   reasoning (next section). This is the core skill; reverse search is just a shortcut.

## CLUE LADDER — reason country → city → exact spot

Work top-down; each rung narrows the search. State WHAT you see and WHY it implies where.

- **Language / script on signage** → country/region. Latin vs Cyrillic vs Arabic vs
  CJK vs Thai, etc. Then dialect/spelling (e.g. accented chars, umlauts → German-speaking;
  "ç/ã" → Portuguese). Translate any text (that's often the literal answer).
- **Architecture & street furniture** → city/era. Bollards, traffic-light style,
  utility pole shape, fire hydrants, chimney styles, window shutters, brick vs stucco.
- **Public transit livery** → specific city. Tram/bus/metro COLORS + logos are nearly
  unique per city. (e.g. Zürich = BLUE trams; London = red double-deckers.) Google
  "<color> tram <clue>" or match the transit authority logo.
- **License plates** → country (color, EU blue strip, aspect ratio) and sometimes region code.
- **Road markings & driving side** → which side they drive, line colors (yellow vs white),
  crosswalk style.
- **Sun position & shadows** → hemisphere + rough time/date (combine with EXIF timestamp);
  shadow direction gives bearing.
- **Vegetation & climate** → latitude band (palms, conifers, tropical, arid).
- **Business names / storefronts / phone numbers** → GOOGLE THEM. A single shop name,
  domain, or phone area code often pins the exact street. Then open Street View to confirm
  the facade matches.
- **Landmarks / skyline** → name the building, then look up its coordinates.

Confirm by dropping into **Google/Apple/Bing Maps + Street View** at the candidate spot
and matching building details one-for-one.

## USERNAME / HANDLE & SOCIAL-MEDIA PIVOTING

Challenges give a handle and want a profile, a leaked fact, or a flag in a bio/post.

- **Concept**: people reuse the same username everywhere. Enumerate it across platforms.
- **Manual**: try the handle on github, twitter/x, instagram, reddit, keybase, tiktok,
  gitlab, telegram, etc. Google `"<username>"` in quotes; add site filters
  (`site:github.com "<username>"`).
- **Tooling (mention)**: `sherlock <username>` and `maigret <username>` check hundreds of
  sites at once. (Don't install anything not already present — list availability first.)
- **Pivot**: from one profile harvest email, real name, avatar (reverse-image it!),
  linked sites, pinned repos, commit emails (`git log` on a public repo), follower graph.
  Check bios/READMEs/gists for the flag or next clue. An avatar reused across accounts
  links identities.

## PUBLIC RECORDS — domains, DNS, certs, history

- **whois** `whois example.com` — registrant, dates, nameservers (privacy often redacts;
  old records may not — see Wayback/historical whois).
- **DNS** `dig example.com any`, `dig +short txt example.com`, subdomains via certs below.
- **crt.sh certificate transparency** — `https://crt.sh/?q=%25.example.com` lists every
  subdomain ever issued a cert. Goldmine for hidden/dev/staging hosts holding flags.
- **Wayback Machine** (web.archive.org) — old versions of a page. Flags/secrets deleted
  from the live site often survive in an archived snapshot. Try
  `http://web.archive.org/web/*/example.com/*` and diff old vs new. Also
  `archive.today`. Check robots.txt / sitemap.xml snapshots too.
- **Google cache / dorking** — `site:`, `inurl:`, `intitle:`, `filetype:` to surface
  the exact page.

## FLAG EXTRACTION & VERIFICATION

- The located place/person is usually NOT the raw flag — read the prompt for the final
  transform. Translate ANY puzzle arithmetic / transform EXACTLY, step by step, no rounding
  shortcuts unless told. Re-read the wording ("2 significant figures" ≠ "2 decimals").
- **VERIFY every fact you plug into a formula** (station/landmark name, OPENING YEAR,
  exact COORDINATES) via web search before computing. A wrong year/coord cascades.
- When a resulting place name has non-ASCII letters, submit BOTH the accented form AND
  the ASCII-folded form. Also try spaces→underscores, lowercase, and name-only vs
  name+country.

## WORKED EXAMPLE — "How Did We Get Here?" (SOLVED)

Street photo of a train station. Reasoning:
- **BLUE trams** + the **Stadelhofen arcade** + a **Starbucks** → Zürich Stadelhofen
  station (geolocated from transit livery + architecture + a googleable business).
- VERIFIED via search: station opened **1894**; coords ≈ **47.37 N, 8.55 E**.

Then the prompt demanded EXACT arithmetic on those facts:
- `a` = latitude to 2 sig figs = **47**
- `b` = longitude to 2 sig figs = **8.5**
- `c` = opening year = **1894**
- `d` = (first two digits of c = 18) + a = 18 + 47 = **65**
- `e` = b − c/75 = 8.5 − (1894/75) = 8.5 − 25.253 = **−16.753**
- Point **(65, −16.753)** → the **Askja** caldera; its closest lake is **Öskjuvatn**, Iceland.
- Flag: `flag{oskjuvatn_iceland}` (also try accented `flag{öskjuvatn_iceland}`).

### Reusable principles proven by this win
1. Geolocate from **transit livery + signage + architecture + a googleable business**.
2. **VERIFY** the landmark name, its **opening year**, and its **coordinates** by web
   search before using them in any formula.
3. Follow any arithmetic in the prompt **to the letter** (mind sig-figs vs decimals, and
   do divisions exactly).
4. When a place name has non-ASCII letters, submit **BOTH** accented and ASCII-folded
   flag variants.
