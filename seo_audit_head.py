#!/usr/bin/env python3
"""
seo_audit_head.py

Reads a list of URLs from a .txt file (one URL per line),
fetches each page, extracts Titles / Meta / Head tags,
rates them, and saves a CSV report.

Install:
  pip install requests beautifulsoup4

Usage:
  python seo_audit_head.py urls.txt report.csv
  python seo_audit_head.py urls.txt report.csv --googlebot --workers 10 --timeout 20
  python seo_audit_head.py urls.txt report.csv --no-redirects

Input file format:
  - One URL per line
  - Blank lines allowed
  - Lines starting with # are ignored
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

UA_DEFAULT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
UA_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


# -----------------------------
# Helpers
# -----------------------------
def norm_ws(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def safe_len(s: Optional[str]) -> int:
    return len(s or "")


def domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def read_urls(path: str) -> List[str]:
    urls: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def fetch_html(url: str, timeout: int, ua: str, allow_redirects: bool) -> Tuple[int, str, str, Dict[str, str], Optional[str]]:
    try:
        r = requests.get(
            url,
            headers={
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
            timeout=timeout,
            allow_redirects=allow_redirects,
        )
        headers = {k.lower(): v for k, v in r.headers.items()}
        ct = headers.get("content-type", "")
        return int(r.status_code), str(r.url), r.text or "", headers, None
    except Exception as e:
        return 0, url, "", {}, str(e)


def get_meta(soup: BeautifulSoup, name: str) -> Optional[str]:
    tag = soup.find("meta", attrs={"name": re.compile(f"^{re.escape(name)}$", re.I)})
    if tag and tag.get("content"):
        return norm_ws(tag.get("content", ""))
    return None


def get_meta_prop(soup: BeautifulSoup, prop: str) -> Optional[str]:
    tag = soup.find("meta", attrs={"property": re.compile(f"^{re.escape(prop)}$", re.I)})
    if tag and tag.get("content"):
        return norm_ws(tag.get("content", ""))
    return None


def get_link_rel(soup: BeautifulSoup, rel: str) -> Optional[str]:
    tag = soup.find("link", attrs={"rel": re.compile(rf"\b{re.escape(rel)}\b", re.I)})
    if tag and tag.get("href"):
        return norm_ws(tag.get("href", ""))
    return None


def get_hreflangs(soup: BeautifulSoup) -> List[str]:
    out: List[str] = []
    for tag in soup.find_all("link", rel=True, href=True):
        rels = " ".join(tag.get("rel") or [])
        if re.search(r"\balternate\b", rels, re.I) and tag.get("hreflang"):
            out.append(f'{tag.get("hreflang")}:{tag.get("href")}')
    return out


# -----------------------------
# Scoring
# -----------------------------
@dataclass
class Score:
    points: int
    max_points: int
    notes: List[str]


def score_title(title: Optional[str]) -> Score:
    notes: List[str] = []
    maxp = 30
    if not title:
        return Score(0, maxp, ["Missing <title>."])

    t = title.strip()
    L = len(t)

    pts = 10  # base for having a title
    if L < 15:
        notes.append("Title too short (<15 chars).")
    elif 15 <= L <= 60:
        pts += 15
    elif 61 <= L <= 70:
        pts += 10
        notes.append("Title a bit long (>60 chars).")
    else:
        pts += 3
        notes.append("Title likely too long (>70 chars).")

    if re.search(r"\b(home|welcome)\b", t, re.I) and L < 25:
        notes.append('Title looks generic ("Home/Welcome").')

    return Score(min(pts, maxp), maxp, notes)


def score_meta_description(desc: Optional[str]) -> Score:
    notes: List[str] = []
    maxp = 25
    if not desc:
        return Score(0, maxp, ['Missing meta description (<meta name="description">).'])

    d = desc.strip()
    L = len(d)
    pts = 10  # present

    if L < 50:
        pts += 3
        notes.append("Description short (<50 chars).")
    elif 50 <= L <= 160:
        pts += 15
    elif 161 <= L <= 180:
        pts += 10
        notes.append("Description a bit long (>160 chars).")
    else:
        pts += 5
        notes.append("Description likely too long (>180 chars).")

    if re.search(r"\b(click|buy now|best price)\b", d, re.I):
        notes.append("Description looks spammy/salesy (check tone).")

    return Score(min(pts, maxp), maxp, notes)


def score_canonical(canonical: Optional[str], final_url: str) -> Score:
    notes: List[str] = []
    maxp = 15
    if not canonical:
        return Score(0, maxp, ["Missing canonical (<link rel='canonical'>)."])

    pts = 10
    # quick checks
    if canonical.startswith("/"):
        pts += 2
        notes.append("Canonical is relative (often OK, but absolute is safer).")
    if canonical == final_url:
        pts += 5
    else:
        # allow minor differences (trailing slash, http/https)
        def norm(u: str) -> str:
            u = u.strip()
            u = re.sub(r"^http://", "https://", u, flags=re.I)
            u = u.rstrip("/")
            return u

        if norm(canonical) == norm(final_url):
            pts += 4
        else:
            notes.append("Canonical differs from final URL (might be intentional, verify).")
            pts += 1

    return Score(min(pts, maxp), maxp, notes)


def score_robots(robots: Optional[str]) -> Score:
    notes: List[str] = []
    maxp = 10
    if not robots:
        return Score(6, maxp, ["No meta robots tag (usually OK; defaults to indexable)."])

    pts = 8
    r = robots.lower()
    if "noindex" in r:
        pts = 0
        notes.append("⚠️ noindex present (page won't be indexed).")
    if "nofollow" in r:
        notes.append("nofollow present (links not followed).")
    if "none" in r:
        notes.append("robots=none implies noindex,nofollow.")
        pts = 0

    return Score(min(pts, maxp), maxp, notes)


def score_social(og_title: Optional[str], og_desc: Optional[str], og_image: Optional[str], tw_card: Optional[str]) -> Score:
    notes: List[str] = []
    maxp = 10
    pts = 0

    if og_title:
        pts += 3
    else:
        notes.append("Missing og:title.")
    if og_desc:
        pts += 2
    else:
        notes.append("Missing og:description.")
    if og_image:
        pts += 3
    else:
        notes.append("Missing og:image.")
    if tw_card:
        pts += 2
    else:
        notes.append("Missing twitter:card.")

    return Score(pts, maxp, notes)


def score_hreflang(hreflangs: List[str]) -> Score:
    maxp = 10
    if not hreflangs:
        return Score(7, maxp, ["No hreflang alternates (OK unless site is multilingual)."])
    pts = 10
    notes: List[str] = []
    # basic sanity
    if not any(h.lower().startswith("x-default:") for h in hreflangs):
        notes.append("No x-default hreflang (optional, but recommended for multilingual sites).")
        pts -= 1
    return Score(max(0, pts), maxp, notes)


def total_score(parts: List[Score]) -> Tuple[int, int, List[str]]:
    pts = sum(p.points for p in parts)
    mx = sum(p.max_points for p in parts)
    notes: List[str] = []
    for p in parts:
        notes.extend(p.notes)
    return pts, mx, notes


def grade(percent: float) -> str:
    if percent >= 90:
        return "A"
    if percent >= 80:
        return "B"
    if percent >= 70:
        return "C"
    if percent >= 60:
        return "D"
    return "F"


# -----------------------------
# Audit one URL
# -----------------------------
def audit_url(url: str, timeout: int, ua: str, allow_redirects: bool) -> Dict[str, str]:
    status, final_url, html, headers, error = fetch_html(url, timeout, ua, allow_redirects)

    row: Dict[str, str] = {
        "input_url": url,
        "final_url": final_url,
        "status": str(status),
        "content_type": headers.get("content-type", ""),
        "title": "",
        "title_len": "0",
        "meta_description": "",
        "meta_description_len": "0",
        "canonical": "",
        "canonical_is_self": "",
        "meta_robots": "",
        "og_title": "",
        "og_description": "",
        "og_image": "",
        "twitter_card": "",
        "h1_count": "0",
        "hreflang_count": "0",
        "hreflangs": "",
        "head_score": "0",
        "head_score_max": "0",
        "head_score_pct": "0",
        "grade": "",
        "notes": "",
        "error": error or "",
    }

    # If non-HTML or fetch error
    if error:
        row["notes"] = "Fetch error."
        return row
    if status >= 400 or status == 0:
        row["notes"] = f"HTTP error status {status}."
        return row
    if "text/html" not in (headers.get("content-type", "").lower()):
        row["notes"] = "Non-HTML content."
        return row

    soup = BeautifulSoup(html, "html.parser")

    title = norm_ws(soup.title.string if soup.title and soup.title.string else "")
    desc = get_meta(soup, "description") or ""
    canonical = get_link_rel(soup, "canonical") or ""
    robots = get_meta(soup, "robots") or ""
    og_title = get_meta_prop(soup, "og:title") or ""
    og_desc = get_meta_prop(soup, "og:description") or ""
    og_image = get_meta_prop(soup, "og:image") or ""
    tw_card = get_meta(soup, "twitter:card") or ""

    h1_count = len(soup.find_all("h1"))
    hreflangs = get_hreflangs(soup)

    # Canonical self check
    canonical_is_self = ""
    if canonical:
        def norm(u: str) -> str:
            u = u.strip()
            u = re.sub(r"^http://", "https://", u, flags=re.I)
            u = u.rstrip("/")
            return u

        canonical_is_self = "yes" if norm(canonical) == norm(final_url) else "no"

    # Score
    parts = [
        score_title(title or None),
        score_meta_description(desc or None),
        score_canonical(canonical or None, final_url),
        score_robots(robots or None),
        score_social(og_title or None, og_desc or None, og_image or None, tw_card or None),
        score_hreflang(hreflangs),
    ]
    pts, mx, notes = total_score(parts)
    pct = (pts / mx * 100.0) if mx else 0.0

    row.update(
        {
            "title": title,
            "title_len": str(len(title)),
            "meta_description": desc,
            "meta_description_len": str(len(desc)),
            "canonical": canonical,
            "canonical_is_self": canonical_is_self,
            "meta_robots": robots,
            "og_title": og_title,
            "og_description": og_desc,
            "og_image": og_image,
            "twitter_card": tw_card,
            "h1_count": str(h1_count),
            "hreflang_count": str(len(hreflangs)),
            "hreflangs": " | ".join(hreflangs),
            "head_score": str(pts),
            "head_score_max": str(mx),
            "head_score_pct": f"{pct:.1f}",
            "grade": grade(pct),
            "notes": " ; ".join(notes),
        }
    )

    return row


# -----------------------------
# Main
# -----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Audit Titles, Meta & Head tags for a list of URLs and export CSV.")
    ap.add_argument("input_file", help="Path to .txt file with URLs (one per line).")
    ap.add_argument("output_csv", help="Output CSV file path.")
    ap.add_argument("--timeout", type=int, default=15, help="Request timeout seconds (default: 15).")
    ap.add_argument("--workers", type=int, default=6, help="Parallel workers (default: 6).")
    ap.add_argument("--googlebot", action="store_true", help="Fetch using Googlebot User-Agent.")
    ap.add_argument("--no-redirects", action="store_true", help="Do not follow redirects.")
    args = ap.parse_args()

    urls = read_urls(args.input_file)
    if not urls:
        print("No URLs found in input file.", file=sys.stderr)
        return 2

    ua = UA_GOOGLEBOT if args.googlebot else UA_DEFAULT
    allow_redirects = not args.no_redirects

    fieldnames = [
        "input_url",
        "final_url",
        "status",
        "content_type",
        "title",
        "title_len",
        "meta_description",
        "meta_description_len",
        "canonical",
        "canonical_is_self",
        "meta_robots",
        "og_title",
        "og_description",
        "og_image",
        "twitter_card",
        "h1_count",
        "hreflang_count",
        "hreflangs",
        "head_score",
        "head_score_max",
        "head_score_pct",
        "grade",
        "notes",
        "error",
    ]

    results: List[Dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {
            ex.submit(audit_url, url, args.timeout, ua, allow_redirects): url for url in urls
        }
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                row = fut.result()
            except Exception as e:
                row = {
                    "input_url": url,
                    "final_url": url,
                    "status": "0",
                    "content_type": "",
                    "title": "",
                    "title_len": "0",
                    "meta_description": "",
                    "meta_description_len": "0",
                    "canonical": "",
                    "canonical_is_self": "",
                    "meta_robots": "",
                    "og_title": "",
                    "og_description": "",
                    "og_image": "",
                    "twitter_card": "",
                    "h1_count": "0",
                    "hreflang_count": "0",
                    "hreflangs": "",
                    "head_score": "0",
                    "head_score_max": "0",
                    "head_score_pct": "0",
                    "grade": "",
                    "notes": "",
                    "error": f"Unhandled error: {e}",
                }
            results.append(row)

    # stable order: same as input
    idx = {u: i for i, u in enumerate(urls)}
    results.sort(key=lambda r: idx.get(r["input_url"], 10**9))

    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in results:
            w.writerow(r)

    print(f"✅ Wrote report: {args.output_csv} ({len(results)} URLs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
