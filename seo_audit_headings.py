#!/usr/bin/env python3
"""
SEO Audit: Headings & Semantic Structure
- Input: urls.txt (one URL per line)
- Output: report.csv

Install:
  pip install requests beautifulsoup4 lxml

Run:
  python seo_audit_headings.py --in urls.txt --out report.csv
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

import requests
from bs4 import BeautifulSoup


SEMANTIC_TAGS = [
    "main", "header", "nav", "footer", "article", "section",
    "aside", "figure", "figcaption", "address", "time"
]

DEFAULT_UA = "Mozilla/5.0 (compatible; SEO-HeadingsAudit/1.0; +https://example.com/bot)"


@dataclass
class PageResult:
    url: str
    final_url: str
    status: str
    content_type: str
    h1_count: int
    h1_text: str
    h2_count: int
    h3_count: int
    h4_count: int
    heading_order_issues: int
    heading_order_notes: str
    semantic_tags_present: str
    semantic_tags_count: int
    div_count: int
    semantic_to_div_ratio: float
    score_h1: int
    score_hierarchy: int
    score_semantics: int
    score_div_soup: int
    score_total: int
    grade: str
    notes: str


def read_urls(path: str) -> List[str]:
    urls: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    # de-dup preserving order
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out


def fetch(url: str, timeout: int = 20) -> Tuple[Optional[requests.Response], Optional[str]]:
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


def extract_headings_sequence(soup: BeautifulSoup) -> List[int]:
    seq: List[int] = []
    for tag in soup.find_all(re.compile(r"^h[1-6]$", re.I)):
        try:
            level = int(tag.name[1])
            seq.append(level)
        except Exception:
            continue
    return seq


def analyze_heading_order(seq: List[int]) -> Tuple[int, str]:
    """
    Basic hierarchy checks:
    - H3 without any prior H2
    - H4 without prior H3, etc.
    - Skips >1 level jump (e.g., H2 -> H4)
    """
    if not seq:
        return 0, "No headings found"

    seen_levels = set()
    issues = 0
    notes: List[str] = []

    last = None
    for i, lvl in enumerate(seq):
        seen_levels.add(lvl)

        # Jump check (e.g., H2 -> H4)
        if last is not None and lvl - last > 1:
            issues += 1
            notes.append(f"Jump: H{last} → H{lvl} at #{i+1}")

        # “Missing parent” check (e.g., H3 without any H2 so far)
        if lvl > 1:
            parent = lvl - 1
            if parent not in seen_levels:
                issues += 1
                notes.append(f"Missing parent: H{lvl} appears before any H{parent} (#{i+1})")

        last = lvl

    return issues, "; ".join(notes) if notes else "OK"


def compute_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def audit_html(url: str, html: str, resp: Optional[requests.Response]) -> PageResult:
    soup = BeautifulSoup(html, "lxml")

    # headings
    h1 = soup.find_all("h1")
    h2 = soup.find_all("h2")
    h3 = soup.find_all("h3")
    h4 = soup.find_all("h4")

    h1_count = len(h1)
    h1_text = ""
    if h1_count >= 1:
        h1_text = " | ".join(
            [" ".join(x.get_text(" ", strip=True).split())[:120] for x in h1[:2]]
        )

    seq = extract_headings_sequence(soup)
    issues, order_notes = analyze_heading_order(seq)

    # semantic tags usage
    semantic_counts: Dict[str, int] = {}
    for t in SEMANTIC_TAGS:
        semantic_counts[t] = len(soup.find_all(t))
    semantic_present = [t for t, c in semantic_counts.items() if c > 0]
    semantic_tags_count = sum(semantic_counts.values())
    semantic_tags_present = ",".join(semantic_present) if semantic_present else ""

    # div soup signal
    div_count = len(soup.find_all("div"))
    ratio = (semantic_tags_count / div_count) if div_count else float(semantic_tags_count)

    # -----------------------------
    # Scoring (0–100 total)
    # -----------------------------
    # 1) One clear H1 (0–35)
    # - 1 H1: 35
    # - 0 H1: 10 (some SPAs render later)
    # - 2+ H1: downscale
    if h1_count == 1:
        score_h1 = 35
    elif h1_count == 0:
        score_h1 = 10
    else:
        score_h1 = clamp(35 - (h1_count - 1) * 10, 0, 35)

    # 2) Heading hierarchy (0–35)
    # Start at 35 and subtract per issue; floor at 0
    score_hierarchy = clamp(35 - issues * 8, 0, 35)

    # 3) Semantic tags presence (0–20)
    # Reward presence + diversity
    diversity = len(semantic_present)
    # base: any semantic tags
    base = 8 if semantic_tags_count > 0 else 0
    # diversity bonus
    bonus = clamp(diversity * 2, 0, 12)
    score_semantics = clamp(base + bonus, 0, 20)

    # 4) Div soup penalty / score (0–10)
    # ratio guidance:
    # - >= 0.10 => good (10)
    # - 0.05–0.10 => ok (7)
    # - 0.02–0.05 => weak (4)
    # - < 0.02 => bad (1)
    if div_count == 0:
        score_div_soup = 10
    elif ratio >= 0.10:
        score_div_soup = 10
    elif ratio >= 0.05:
        score_div_soup = 7
    elif ratio >= 0.02:
        score_div_soup = 4
    else:
        score_div_soup = 1

    score_total = score_h1 + score_hierarchy + score_semantics + score_div_soup
    grade = compute_grade(score_total)

    notes: List[str] = []
    if h1_count == 0:
        notes.append("No H1 found (could be client-rendered SPA).")
    elif h1_count > 1:
        notes.append("Multiple H1s found; keep one primary H1 per page.")
    if issues > 0:
        notes.append("Fix heading order: avoid level jumps and missing parents.")
    if semantic_tags_count == 0:
        notes.append("No semantic tags found (consider header/main/nav/article/section).")

    final_url = resp.url if resp is not None else url
    status = str(resp.status_code) if resp is not None else "ERR"
    content_type = resp.headers.get("Content-Type", "") if resp is not None else ""

    return PageResult(
        url=url,
        final_url=final_url,
        status=status,
        content_type=content_type,
        h1_count=h1_count,
        h1_text=h1_text,
        h2_count=len(h2),
        h3_count=len(h3),
        h4_count=len(h4),
        heading_order_issues=issues,
        heading_order_notes=order_notes,
        semantic_tags_present=semantic_tags_present,
        semantic_tags_count=semantic_tags_count,
        div_count=div_count,
        semantic_to_div_ratio=round(ratio, 4) if div_count else round(ratio, 4),
        score_h1=score_h1,
        score_hierarchy=score_hierarchy,
        score_semantics=score_semantics,
        score_div_soup=score_div_soup,
        score_total=score_total,
        grade=grade,
        notes=" ".join(notes).strip(),
    )


def write_csv(path: str, rows: List[PageResult]) -> None:
    fieldnames = [
        "url", "final_url", "status", "content_type",
        "h1_count", "h1_text", "h2_count", "h3_count", "h4_count",
        "heading_order_issues", "heading_order_notes",
        "semantic_tags_present", "semantic_tags_count",
        "div_count", "semantic_to_div_ratio",
        "score_h1", "score_hierarchy", "score_semantics", "score_div_soup",
        "score_total", "grade", "notes",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r.__dict__)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Input .txt with URLs (one per line)")
    ap.add_argument("--out", dest="out", default="headings_report.csv", help="Output CSV path")
    ap.add_argument("--timeout", type=int, default=20, help="Request timeout (seconds)")
    args = ap.parse_args()

    urls = read_urls(args.inp)
    if not urls:
        print("No URLs found in input file.", file=sys.stderr)
        return 2

    results: List[PageResult] = []

    for i, url in enumerate(urls, 1):
        resp, err = fetch(url, timeout=args.timeout)
        if err or resp is None:
            results.append(PageResult(
                url=url,
                final_url=url,
                status="ERR",
                content_type="",
                h1_count=0,
                h1_text="",
                h2_count=0,
                h3_count=0,
                h4_count=0,
                heading_order_issues=0,
                heading_order_notes="",
                semantic_tags_present="",
                semantic_tags_count=0,
                div_count=0,
                semantic_to_div_ratio=0.0,
                score_h1=0,
                score_hierarchy=0,
                score_semantics=0,
                score_div_soup=0,
                score_total=0,
                grade="F",
                notes=f"Request failed: {err}",
            ))
            continue

        # skip non-HTML
        ct = resp.headers.get("Content-Type", "")
        if "html" not in ct.lower():
            results.append(PageResult(
                url=url,
                final_url=resp.url,
                status=str(resp.status_code),
                content_type=ct,
                h1_count=0,
                h1_text="",
                h2_count=0,
                h3_count=0,
                h4_count=0,
                heading_order_issues=0,
                heading_order_notes="",
                semantic_tags_present="",
                semantic_tags_count=0,
                div_count=0,
                semantic_to_div_ratio=0.0,
                score_h1=0,
                score_hierarchy=0,
                score_semantics=0,
                score_div_soup=0,
                score_total=0,
                grade="F",
                notes="Non-HTML content (skipped).",
            ))
            continue

        res = audit_html(url, resp.text or "", resp)
        results.append(res)

        print(f"[{i}/{len(urls)}] {url} -> {res.grade} ({res.score_total})")

    write_csv(args.out, results)
    print(f"\nSaved CSV report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
