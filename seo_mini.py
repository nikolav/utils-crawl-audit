#!/usr/bin/env python3
"""
seo_mini.py

Reads URLs from a text file (one URL per line), audits key SEO blockers, and writes a CSV report.

Checks:
- HTTP status + redirects
- Content-Type
- robots.txt allow/disallow (Googlebot + wildcard)
- X-Robots-Tag header
- meta robots tag + noindex detection
- canonical + self-canonical check
- <title>
- SPA/content presence for Googlebot UA (simple heuristic)
- sitemap.xml exists (HEAD/GET fallback)

Usage:
  python seo_mini_audit.py urls.txt report.csv

Input file format:
  - One URL per line
  - Empty lines and lines starting with # are ignored

$ python seo_mini.py urls.txt report.csv
"""

from __future__ import annotations

import csv
import re
import sys
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, urlunparse, urljoin
from urllib.robotparser import RobotFileParser

import requests

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
DEFAULT_UA = "Mozilla/5.0 (SEO Mini Audit Script)"
TIMEOUT = 20


@dataclass
class RobotsDecision:
    googlebot_allowed: Optional[bool]
    wildcard_allowed: Optional[bool]
    robots_url: str
    error: Optional[str] = None


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url


def get_origin(url: str) -> str:
    p = urlparse(url)
    scheme = p.scheme or "https"
    netloc = p.netloc
    return urlunparse((scheme, netloc, "", "", "", ""))


def safe_get_text(html: str, pattern: re.Pattern) -> Optional[str]:
    m = pattern.search(html)
    if not m:
        return None
    return m.group(1).strip() if m.group(1) else None


def fetch_robots_decision(session: requests.Session, origin: str, test_url: str) -> RobotsDecision:
    robots_url = urljoin(origin + "/", "robots.txt")
    rp = RobotFileParser()
    rp.set_url(robots_url)

    try:
        resp = session.get(robots_url, headers={"User-Agent": DEFAULT_UA}, timeout=TIMEOUT, allow_redirects=True)
        if resp.status_code >= 400:
            # No robots.txt or not accessible -> treat as allowed (common behavior)
            return RobotsDecision(True, True, robots_url, error=f"robots.txt HTTP {resp.status_code}")
        rp.parse(resp.text.splitlines())

        # Two checks: for Googlebot UA and generic "*"
        gb_allowed = rp.can_fetch(GOOGLEBOT_UA, test_url)
        wc_allowed = rp.can_fetch("*", test_url)
        return RobotsDecision(gb_allowed, wc_allowed, robots_url, error=None)
    except Exception as e:
        # On error, don't guess too hard; return unknown
        return RobotsDecision(None, None, robots_url, error=str(e))


def extract_meta_robots(html: str) -> Optional[str]:
    # naive but effective regex for: <meta name="robots" content="...">
    # handles single/double quotes, arbitrary whitespace and attr order
    meta_pat = re.compile(
        r"""<meta\b[^>]*\bname\s*=\s*["']robots["'][^>]*>""",
        re.I,
    )
    content_pat = re.compile(r"""\bcontent\s*=\s*["']([^"']+)["']""", re.I)

    m = meta_pat.search(html)
    if not m:
        return None
    tag = m.group(0)
    c = content_pat.search(tag)
    return c.group(1).strip() if c else None


def extract_canonical(html: str) -> Optional[str]:
    # <link rel="canonical" href="...">
    link_pat = re.compile(r"""<link\b[^>]*\brel\s*=\s*["']canonical["'][^>]*>""", re.I)
    href_pat = re.compile(r"""\bhref\s*=\s*["']([^"']+)["']""", re.I)
    m = link_pat.search(html)
    if not m:
        return None
    tag = m.group(0)
    h = href_pat.search(tag)
    return h.group(1).strip() if h else None


def extract_title(html: str) -> Optional[str]:
    # <title>...</title> (first)
    title_pat = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
    t = safe_get_text(html, title_pat)
    if not t:
        return None
    # collapse whitespace
    return re.sub(r"\s+", " ", t).strip()


def is_spa_content_present(html: str) -> bool:
    """
    Simple heuristic:
    - If body text contains some letters outside scripts/styles and isn't just a shell like "<div id=app></div>"
    We'll strip scripts/styles and tags, then check if there's enough text.
    """
    # remove scripts/styles
    html2 = re.sub(r"<script\b[^>]*>.*?</script>", " ", html, flags=re.I | re.S)
    html2 = re.sub(r"<style\b[^>]*>.*?</style>", " ", html2, flags=re.I | re.S)
    # remove tags
    text = re.sub(r"<[^>]+>", " ", html2)
    text = re.sub(r"\s+", " ", text).strip()
    # require some meaningful length and letters
    if len(text) < 80:
        return False
    if not re.search(r"[A-Za-zÀ-žА-Яа-я]", text):
        return False
    return True


def check_sitemap(session: requests.Session, origin: str) -> Tuple[bool, str]:
    sitemap_url = urljoin(origin + "/", "sitemap.xml")
    try:
        r = session.head(sitemap_url, headers={"User-Agent": DEFAULT_UA}, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code == 405:  # method not allowed -> try GET
            r = session.get(sitemap_url, headers={"User-Agent": DEFAULT_UA}, timeout=TIMEOUT, allow_redirects=True)
        ok = (200 <= r.status_code < 300) and ("xml" in (r.headers.get("Content-Type", "").lower()))
        # some servers return application/octet-stream; accept if body starts like xml
        if not ok and (200 <= r.status_code < 300):
            body = ""
            try:
                body = (r.text or "")[:200].lstrip()
            except Exception:
                body = ""
            if body.startswith("<?xml") or "<urlset" in body or "<sitemapindex" in body:
                ok = True
        return ok, sitemap_url
    except Exception:
        return False, sitemap_url


def audit_url(session: requests.Session, input_url: str) -> Dict[str, str]:
    input_url = normalize_url(input_url)
    origin = get_origin(input_url)

    # Robots decision
    robots = fetch_robots_decision(session, origin, input_url)

    # Fetch page (Googlebot UA to match “can Google render it?” mindset)
    notes = []
    try:
        resp = session.get(
            input_url,
            headers={"User-Agent": GOOGLEBOT_UA, "Accept": "text/html,application/xhtml+xml"},
            timeout=TIMEOUT,
            allow_redirects=True,
        )
    except Exception as e:
        return {
            "input_url": input_url,
            "final_url": "",
            "status": "",
            "redirected": "",
            "content_type": "",
            "robots_googlebot_allowed": str(robots.googlebot_allowed),
            "robots_wildcard_allowed": str(robots.wildcard_allowed),
            "robots_url": robots.robots_url,
            "x_robots_tag": "",
            "meta_robots": "",
            "has_noindex": "",
            "canonical": "",
            "canonical_is_self": "",
            "html_title": "",
            "spa_content_present": "",
            "sitemap_found": "",
            "sitemap_url": urljoin(origin + "/", "sitemap.xml"),
            "notes": f"FETCH_ERROR: {e}; ROBOTS_ERROR: {robots.error or ''}".strip(),
        }

    final_url = resp.url
    status = resp.status_code
    redirected = str(final_url != input_url)
    content_type = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()

    x_robots = resp.headers.get("X-Robots-Tag", "") or resp.headers.get("x-robots-tag", "") or ""
    x_robots_l = x_robots.lower()

    html = resp.text if "text/html" in content_type or "<html" in (resp.text[:500].lower()) else ""

    meta_robots = extract_meta_robots(html) if html else None
    meta_robots_l = (meta_robots or "").lower()

    has_noindex = False
    if "noindex" in x_robots_l:
        has_noindex = True
        notes.append("X-Robots-Tag contains noindex")
    if meta_robots_l and "noindex" in meta_robots_l:
        has_noindex = True
        notes.append("meta robots contains noindex")

    canonical = extract_canonical(html) if html else None
    canonical_is_self = ""
    if canonical:
        # canonical can be relative
        canon_abs = urljoin(final_url, canonical)
        canonical = canon_abs
        # compare normalized without fragment
        def norm(u: str) -> str:
            p = urlparse(u)
            return urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/", p.params, p.query, ""))

        canonical_is_self = "yes" if norm(canon_abs) == norm(final_url) else "no"

    title = extract_title(html) if html else None
    spa_present = is_spa_content_present(html) if html else False
    if html and not spa_present:
        notes.append("Low visible text for Googlebot (possible client-only SPA)")

    # sitemap
    sitemap_ok, sitemap_url = check_sitemap(session, origin)
    if not sitemap_ok:
        notes.append("sitemap.xml missing/invalid")

    # robots interpretation: if either googlebot or wildcard explicitly false, it's a red flag
    if robots.googlebot_allowed is False or robots.wildcard_allowed is False:
        notes.append("robots.txt disallows this URL")

    if status >= 400:
        notes.append(f"HTTP {status}")

    return {
        "input_url": input_url,
        "final_url": final_url,
        "status": str(status),
        "redirected": redirected,
        "content_type": content_type,
        "robots_googlebot_allowed": "" if robots.googlebot_allowed is None else ("yes" if robots.googlebot_allowed else "no"),
        "robots_wildcard_allowed": "" if robots.wildcard_allowed is None else ("yes" if robots.wildcard_allowed else "no"),
        "robots_url": robots.robots_url,
        "x_robots_tag": x_robots,
        "meta_robots": meta_robots or "",
        "has_noindex": "yes" if has_noindex else "no",
        "canonical": canonical or "",
        "canonical_is_self": canonical_is_self or "",
        "html_title": title or "",
        "spa_content_present": "yes" if spa_present else ("no" if html else ""),
        "sitemap_found": "yes" if sitemap_ok else "no",
        "sitemap_url": sitemap_url,
        "notes": "; ".join(notes) if notes else (robots.error or ""),
    }


def read_urls(path: str) -> list[str]:
    urls: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: python seo_mini_audit.py urls.txt report.csv", file=sys.stderr)
        return 2

    in_path = sys.argv[1]
    out_path = sys.argv[2]

    urls = read_urls(in_path)
    if not urls:
        print("No URLs found in input file.", file=sys.stderr)
        return 2

    fieldnames = [
        "input_url",
        "final_url",
        "status",
        "redirected",
        "content_type",
        "robots_googlebot_allowed",
        "robots_wildcard_allowed",
        "robots_url",
        "x_robots_tag",
        "meta_robots",
        "has_noindex",
        "canonical",
        "canonical_is_self",
        "html_title",
        "spa_content_present",
        "sitemap_found",
        "sitemap_url",
        "notes",
    ]

    session = requests.Session()
    session.headers.update({"Accept-Language": "sr,en;q=0.8"})

    rows = []
    for u in urls:
        row = audit_url(session, u)
        rows.append(row)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"✅ Done. Wrote {len(rows)} rows to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
