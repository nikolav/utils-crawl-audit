#!/usr/bin/env python3
"""
SEO Audit: Image SEO
- Input: urls.txt (one URL per line)
- Output: report.csv

Run:
  python seo_audit_images.py --in urls.txt --out report.csv
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


DEFAULT_UA = "Mozilla/5.0 (compatible; SEO-ImageAudit/1.0; +https://example.com/bot)"
TIMEOUT = 20

MODERN_EXTS = {".webp", ".avif"}
RASTER_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif"}
# Heuristics: "bad" filename patterns
NON_DESCRIPTIVE_PATTERNS = [
    re.compile(r"^(img|image|photo|pic|screenshot|screen|banner|hero|logo)[-_]?\d*$", re.I),
    re.compile(r"^dsc\d+$", re.I),                 # camera filenames
    re.compile(r"^p?xl_\d+$", re.I),
    re.compile(r"^\d{6,}$"),                       # pure numbers
    re.compile(r"^[a-f0-9]{8,}$", re.I),           # hashes
]


@dataclass
class Row:
    url: str
    final_url: str
    status: str
    content_type: str

    img_count: int
    unique_img_src: int

    alt_missing: int
    alt_empty: int
    alt_ok: int
    alt_coverage_pct: float

    lazy_images: int
    lazy_pct: float

    modern_format_images: int
    modern_format_pct: float

    non_descriptive_filenames: int
    descriptive_filename_pct: float

    checked_image_files: int
    large_images_over_200kb: int
    large_images_over_500kb: int
    large_images_over_1000kb: int
    avg_image_kb: float

    score_alt: int
    score_compression: int
    score_modern: int
    score_lazy: int
    score_filenames: int
    score_total: int
    grade: str
    notes: str


def read_urls(path: str) -> List[str]:
    out = []
    seen = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            u = line.strip()
            if not u or u.startswith("#"):
                continue
            if u not in seen:
                out.append(u)
                seen.add(u)
    return out


def fetch_html(url: str, timeout: int) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        r = requests.get(
            url,
            headers={"User-Agent": DEFAULT_UA, "Accept": "text/html,application/xhtml+xml"},
            timeout=timeout,
            allow_redirects=True,
        )
        return r, None
    except requests.RequestException as e:
        return None, str(e)


def get_ext_from_url(u: str) -> str:
    try:
        path = urlparse(u).path
        if "." in path:
            ext = "." + path.rsplit(".", 1)[-1].lower()
            return ext
    except Exception:
        pass
    return ""


def filename_is_descriptive(u: str) -> bool:
    """
    Heuristic: descriptive if it's not just 'img-1', 'dsc1234', 'abcdef123', etc,
    and it has at least one letter word-like segment length>=3.
    """
    path = urlparse(u).path
    name = path.rsplit("/", 1)[-1]
    name = name.split("?", 1)[0].split("#", 1)[0]
    base = name.rsplit(".", 1)[0].strip().lower()
    base = re.sub(r"[-_]+", "-", base)

    if not base:
        return False

    for pat in NON_DESCRIPTIVE_PATTERNS:
        if pat.match(base):
            return False

    # must contain at least one alpha segment length >=3
    parts = [p for p in base.split("-") if p]
    if any(re.search(r"[a-z]", p) and len(p) >= 3 for p in parts):
        return True
    return False


def image_size_bytes(session: requests.Session, img_url: str, timeout: int) -> Optional[int]:
    """
    Try HEAD first; if no Content-Length, fallback to GET with stream and read small chunk.
    We DO NOT download the whole file.
    """
    try:
        h = session.head(img_url, headers={"User-Agent": DEFAULT_UA}, timeout=timeout, allow_redirects=True)
        cl = h.headers.get("Content-Length")
        if cl and cl.isdigit():
            return int(cl)
    except requests.RequestException:
        pass

    # fallback GET (stream) and if Content-Length present there, use it
    try:
        g = session.get(img_url, headers={"User-Agent": DEFAULT_UA}, timeout=timeout, allow_redirects=True, stream=True)
        cl = g.headers.get("Content-Length")
        if cl and cl.isdigit():
            return int(cl)
        return None
    except requests.RequestException:
        return None


def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def audit_page(url: str, html: str, resp: requests.Response, max_images_to_sizecheck: int, timeout: int) -> Row:
    soup = BeautifulSoup(html, "lxml")
    imgs = soup.find_all("img")

    img_count = len(imgs)

    # collect normalized srcs
    srcs: List[str] = []
    for img in imgs:
        src = (img.get("src") or "").strip()
        if not src:
            # support lazy patterns like data-src
            src = (img.get("data-src") or img.get("data-lazy-src") or "").strip()
        if src:
            srcs.append(urljoin(resp.url, src))

    # unique image urls
    uniq = []
    seen = set()
    for s in srcs:
        if s not in seen:
            uniq.append(s)
            seen.add(s)

    unique_img_src = len(uniq)

    # ALT checks
    alt_missing = 0
    alt_empty = 0
    alt_ok = 0
    for img in imgs:
        if img.get("src") is None and img.get("data-src") is None and img.get("data-lazy-src") is None:
            continue
        if not img.has_attr("alt"):
            alt_missing += 1
        else:
            alt = (img.get("alt") or "").strip()
            if alt == "":
                alt_empty += 1
            else:
                alt_ok += 1

    alt_total_considered = alt_missing + alt_empty + alt_ok
    alt_coverage_pct = (alt_ok / alt_total_considered * 100.0) if alt_total_considered else 100.0

    # Lazy load checks
    lazy_images = 0
    for img in imgs:
        if (img.get("loading") or "").strip().lower() == "lazy":
            lazy_images += 1
    lazy_pct = (lazy_images / img_count * 100.0) if img_count else 0.0

    # Format checks
    modern_format_images = 0
    for s in uniq:
        ext = get_ext_from_url(s)
        if ext in MODERN_EXTS:
            modern_format_images += 1
    modern_format_pct = (modern_format_images / unique_img_src * 100.0) if unique_img_src else 0.0

    # Filename descriptiveness
    non_desc = 0
    checked_names = 0
    for s in uniq:
        ext = get_ext_from_url(s)
        if ext and ext in RASTER_EXTS:
            checked_names += 1
            if not filename_is_descriptive(s):
                non_desc += 1
    descriptive_filename_pct = (
        ((checked_names - non_desc) / checked_names * 100.0) if checked_names else 100.0
    )

    # Size checks (sample up to N unique images)
    checked_image_files = 0
    large_200 = 0
    large_500 = 0
    large_1000 = 0
    sizes: List[int] = []

    with requests.Session() as sess:
        for s in uniq[:max_images_to_sizecheck]:
            ext = get_ext_from_url(s)
            if ext and ext in RASTER_EXTS:
                sz = image_size_bytes(sess, s, timeout=timeout)
                if sz is None:
                    continue
                checked_image_files += 1
                sizes.append(sz)
                if sz > 200 * 1024:
                    large_200 += 1
                if sz > 500 * 1024:
                    large_500 += 1
                if sz > 1000 * 1024:
                    large_1000 += 1

    avg_image_kb = (sum(sizes) / len(sizes) / 1024.0) if sizes else 0.0

    # -----------------------------
    # Scoring (0–100)
    # -----------------------------
    # ALT (0–35)
    if img_count == 0:
        score_alt = 35
    else:
        # penalize missing/empty alts
        miss = alt_missing + alt_empty
        miss_rate = miss / max(1, alt_total_considered)
        score_alt = clamp(int(round(35 * (1 - miss_rate))), 0, 35)

    # Compression / size (0–25)
    # Use large_200 rate based on checked files (sample)
    if checked_image_files == 0:
        score_compression = 15  # unknown
    else:
        big_rate = large_200 / checked_image_files
        # heavy penalty if many >200kb
        score_compression = clamp(int(round(25 * (1 - big_rate))), 0, 25)
        # extra penalty for very large images
        if large_1000 > 0:
            score_compression = clamp(score_compression - 6, 0, 25)

    # Modern formats (0–15)
    if unique_img_src == 0:
        score_modern = 15
    else:
        # reward modern usage; 60%+ modern => max
        if modern_format_pct >= 60:
            score_modern = 15
        elif modern_format_pct >= 30:
            score_modern = 11
        elif modern_format_pct >= 10:
            score_modern = 7
        else:
            score_modern = 3

    # Lazy load (0–10)
    if img_count == 0:
        score_lazy = 10
    else:
        if lazy_pct >= 80:
            score_lazy = 10
        elif lazy_pct >= 50:
            score_lazy = 7
        elif lazy_pct >= 20:
            score_lazy = 4
        else:
            score_lazy = 1

    # Filenames (0–15)
    if checked_names == 0:
        score_filenames = 10  # unknown / non-raster
    else:
        score_filenames = clamp(int(round(15 * (descriptive_filename_pct / 100.0))), 0, 15)

    score_total = score_alt + score_compression + score_modern + score_lazy + score_filenames
    g = grade(score_total)

    notes = []
    if img_count == 0:
        notes.append("No <img> found on page.")
    else:
        if alt_missing + alt_empty > 0:
            notes.append("Add meaningful alt text (avoid empty alt unless decorative).")
        if checked_image_files and large_200 > 0:
            notes.append("Compress large images (target <200KB where possible).")
        if modern_format_pct < 10 and unique_img_src > 0:
            notes.append("Use WebP/AVIF for raster images.")
        if lazy_pct < 50 and img_count > 3:
            notes.append('Add loading="lazy" for offscreen images.')
        if checked_names and descriptive_filename_pct < 60:
            notes.append("Use more descriptive image filenames.")

    return Row(
        url=url,
        final_url=resp.url,
        status=str(resp.status_code),
        content_type=resp.headers.get("Content-Type", ""),

        img_count=img_count,
        unique_img_src=unique_img_src,

        alt_missing=alt_missing,
        alt_empty=alt_empty,
        alt_ok=alt_ok,
        alt_coverage_pct=round(alt_coverage_pct, 2),

        lazy_images=lazy_images,
        lazy_pct=round(lazy_pct, 2),

        modern_format_images=modern_format_images,
        modern_format_pct=round(modern_format_pct, 2),

        non_descriptive_filenames=non_desc,
        descriptive_filename_pct=round(descriptive_filename_pct, 2),

        checked_image_files=checked_image_files,
        large_images_over_200kb=large_200,
        large_images_over_500kb=large_500,
        large_images_over_1000kb=large_1000,
        avg_image_kb=round(avg_image_kb, 2),

        score_alt=score_alt,
        score_compression=score_compression,
        score_modern=score_modern,
        score_lazy=score_lazy,
        score_filenames=score_filenames,
        score_total=score_total,
        grade=g,
        notes=" ".join(notes).strip(),
    )


def write_csv(path: str, rows: List[Row]) -> None:
    fields = list(Row.__annotations__.keys())
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r.__dict__)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Input .txt with URLs (one per line)")
    ap.add_argument("--out", dest="out", default="report.csv", help="Output CSV path")
    ap.add_argument("--timeout", type=int, default=TIMEOUT, help="Request timeout seconds")
    ap.add_argument("--max-images", type=int, default=25, help="Max unique images per page to size-check")
    args = ap.parse_args()

    urls = read_urls(args.inp)
    if not urls:
        print("No URLs found in input file.", file=sys.stderr)
        return 2

    rows: List[Row] = []
    for i, url in enumerate(urls, 1):
        resp, err = fetch_html(url, timeout=args.timeout)
        if resp is None or err:
            rows.append(Row(
                url=url, final_url=url, status="ERR", content_type="",
                img_count=0, unique_img_src=0,
                alt_missing=0, alt_empty=0, alt_ok=0, alt_coverage_pct=0.0,
                lazy_images=0, lazy_pct=0.0,
                modern_format_images=0, modern_format_pct=0.0,
                non_descriptive_filenames=0, descriptive_filename_pct=0.0,
                checked_image_files=0,
                large_images_over_200kb=0, large_images_over_500kb=0, large_images_over_1000kb=0,
                avg_image_kb=0.0,
                score_alt=0, score_compression=0, score_modern=0, score_lazy=0, score_filenames=0,
                score_total=0, grade="F",
                notes=f"Request failed: {err}",
            ))
            continue

        ct = resp.headers.get("Content-Type", "")
        if "html" not in ct.lower():
            rows.append(Row(
                url=url, final_url=resp.url, status=str(resp.status_code), content_type=ct,
                img_count=0, unique_img_src=0,
                alt_missing=0, alt_empty=0, alt_ok=0, alt_coverage_pct=0.0,
                lazy_images=0, lazy_pct=0.0,
                modern_format_images=0, modern_format_pct=0.0,
                non_descriptive_filenames=0, descriptive_filename_pct=0.0,
                checked_image_files=0,
                large_images_over_200kb=0, large_images_over_500kb=0, large_images_over_1000kb=0,
                avg_image_kb=0.0,
                score_alt=0, score_compression=0, score_modern=0, score_lazy=0, score_filenames=0,
                score_total=0, grade="F",
                notes="Non-HTML content (skipped).",
            ))
            continue

        row = audit_page(url, resp.text or "", resp, max_images_to_sizecheck=args.max_images, timeout=args.timeout)
        rows.append(row)
        print(f"[{i}/{len(urls)}] {url} -> {row.grade} ({row.score_total})")

    write_csv(args.out, rows)
    print(f"\nSaved CSV report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
