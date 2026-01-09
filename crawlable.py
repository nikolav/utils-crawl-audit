#!/usr/bin/env python3
"""
One-command crawl audit from a .txt list of URLs -> CSV

Usage:
  python crawlable.py urls.txt
  python crawlable.py urls.txt --out report.csv
  python crawlable.py urls.txt --concurrency 12 --timeout 20 --follow-redirects

Input file format:
  - one URL per line
  - blank lines and lines starting with # are ignored

Outputs:
  - CSV with crawlability/indexing signals (status, redirects, robots/noindex, canonical, title, meta desc, h1, wordcount, etc.)

Deps:
  pip install requests beautifulsoup4 lxml
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, urldefrag

import requests
from bs4 import BeautifulSoup
from urllib import robotparser


UA_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def norm_url(u: str) -> str:
    u = u.strip()
    u, _ = urldefrag(u)
    return u


def is_http_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def safe_text(s: str | None) -> str:
    if not s:
        return ""
    return re.sub(r"\s+", " ", s).strip()


def is_probably_html(content_type: str | None) -> bool:
    if not content_type:
        return False
    ct = content_type.split(";")[0].strip().lower()
    return ct in ("text/html", "application/xhtml+xml")


def get_site_base(u: str) -> str:
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}"


def load_urls(path: str) -> list[str]:
    urls: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            u = norm_url(line)
            if not is_http_url(u):
                continue
            urls.append(u)
    # preserve order, drop duplicates
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out


def build_robot_parser(base: str, session: requests.Session, timeout: float) -> robotparser.RobotFileParser:
    robots_url = urljoin(base, "/robots.txt")
    rp = robotparser.RobotFileParser()
    rp.set_url(robots_url)
    try:
        r = session.get(robots_url, timeout=timeout, allow_redirects=True)
        if 200 <= r.status_code < 300:
            rp.parse(r.text.splitlines())
        else:
            rp.parse([])  # treat as allowed
    except Exception:
        rp.parse([])  # treat as allowed
    return rp


def x_robots_tag(headers: dict) -> str:
    v = headers.get("X-Robots-Tag") or headers.get("x-robots-tag") or ""
    return safe_text(v).lower()


def meta_robots_from_soup(soup: BeautifulSoup) -> str:
    m = soup.find("meta", attrs={"name": re.compile(r"robots", re.I)})
    if m and m.get("content"):
        return safe_text(m["content"]).lower()
    return ""


def canonical_from_soup(soup: BeautifulSoup, page_url: str) -> str:
    link = soup.find("link", attrs={"rel": re.compile(r"\bcanonical\b", re.I)})
    if link and link.get("href"):
        return norm_url(urljoin(page_url, link["href"]))
    return ""


def title_from_soup(soup: BeautifulSoup) -> str:
    t = soup.find("title")
    return safe_text(t.get_text()) if t else ""


def meta_description_len(soup: BeautifulSoup) -> int:
    m = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
    if m and m.get("content"):
        return len(safe_text(m["content"]))
    return 0


def h1_count(soup: BeautifulSoup) -> int:
    return len(soup.find_all("h1"))


def word_count(soup: BeautifulSoup) -> int:
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    text = soup.get_text(" ", strip=True)
    if not text:
        return 0
    return len(re.findall(r"\b\w+\b", text))


def has_noindex(meta_robots: str, xrt: str) -> bool:
    return ("noindex" in (meta_robots or "")) or ("noindex" in (xrt or ""))


@dataclass
class Row:
    input_url: str
    final_url: str
    status: int
    redirected: bool
    redirect_chain_len: int
    fetch_ms: int
    content_type: str

    robots_allowed: str
    robots_reason: str

    x_robots_tag: str
    meta_robots: str
    has_noindex: str

    canonical: str
    canonical_is_self: str

    title: str
    title_len: int
    meta_description_len: int
    h1_count: int
    word_count: int

    notes: str


def audit_one(
    url: str,
    session: requests.Session,
    rp: robotparser.RobotFileParser,
    timeout: float,
    follow_redirects: bool,
) -> Row:
    url = norm_url(url)
    base = get_site_base(url)

    # Respect robots.txt
    if not rp.can_fetch(UA_GOOGLEBOT, url):
        return Row(
            input_url=url,
            final_url=url,
            status=0,
            redirected=False,
            redirect_chain_len=0,
            fetch_ms=0,
            content_type="",
            robots_allowed="no",
            robots_reason="robots.txt disallow",
            x_robots_tag="",
            meta_robots="",
            has_noindex="no",
            canonical="",
            canonical_is_self="unknown",
            title="",
            title_len=0,
            meta_description_len=0,
            h1_count=0,
            word_count=0,
            notes="Skipped fetch: blocked by robots.txt",
        )

    t0 = time.perf_counter()
    try:
        r = session.get(url, timeout=timeout, allow_redirects=follow_redirects)
        fetch_ms = int((time.perf_counter() - t0) * 1000)
    except requests.RequestException as e:
        fetch_ms = int((time.perf_counter() - t0) * 1000)
        return Row(
            input_url=url,
            final_url=url,
            status=0,
            redirected=False,
            redirect_chain_len=0,
            fetch_ms=fetch_ms,
            content_type="",
            robots_allowed="yes",
            robots_reason="",
            x_robots_tag="",
            meta_robots="",
            has_noindex="no",
            canonical="",
            canonical_is_self="unknown",
            title="",
            title_len=0,
            meta_description_len=0,
            h1_count=0,
            word_count=0,
            notes=f"Request error: {type(e).__name__}",
        )

    status = int(r.status_code)
    headers = dict(r.headers or {})
    ct = safe_text(headers.get("Content-Type", "")).lower()
    final_url = norm_url(r.url)
    redirected = final_url != url
    chain_len = len(getattr(r, "history", []) or []) if follow_redirects else 0

    xrt = x_robots_tag(headers)
    mr = ""
    can = ""
    title = ""
    mdesc_len = 0
    h1c = 0
    wc = 0

    notes = []
    if not is_probably_html(ct):
        notes.append("Non-HTML (skipped parse)")

    if is_probably_html(ct) and status < 400:
        soup = BeautifulSoup(r.text, "lxml")
        mr = meta_robots_from_soup(soup)
        can = canonical_from_soup(soup, final_url)
        title = title_from_soup(soup)
        mdesc_len = meta_description_len(soup)
        h1c = h1_count(soup)
        wc = word_count(soup)

    noindex = "yes" if has_noindex(mr, xrt) else "no"

    can_is_self = "unknown"
    if can:
        can_is_self = "yes" if norm_url(can) == norm_url(final_url) else "no"

    # A few helpful quick notes
    if status >= 400:
        notes.append(f"HTTP_{status}")
    if follow_redirects and chain_len >= 3:
        notes.append("Redirect chain 3+")
    if noindex == "yes":
        notes.append("NOINDEX")
    if is_probably_html(ct) and wc < 80 and status == 200:
        notes.append("Thin content (<80w)")
    if is_probably_html(ct) and not title:
        notes.append("Missing <title>")
    if is_probably_html(ct) and mdesc_len == 0:
        notes.append("Missing meta description")
    if is_probably_html(ct) and h1c == 0:
        notes.append("Missing H1")
    if can and can_is_self == "no":
        notes.append("Canonical points elsewhere")

    return Row(
        input_url=url,
        final_url=final_url,
        status=status,
        redirected=redirected,
        redirect_chain_len=chain_len,
        fetch_ms=fetch_ms,
        content_type=ct,
        robots_allowed="yes",
        robots_reason="",
        x_robots_tag=xrt,
        meta_robots=mr,
        has_noindex=noindex,
        canonical=can,
        canonical_is_self=can_is_self,
        title=title,
        title_len=len(title),
        meta_description_len=mdesc_len,
        h1_count=h1c,
        word_count=wc,
        notes="; ".join(notes),
    )


def write_csv(rows: list[Row], out_path: str) -> None:
    fields = [f.name for f in Row.__dataclass_fields__.values()]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r.__dict__)


def main():
    ap = argparse.ArgumentParser(description="Audit a list of URLs for crawlability/indexing signals -> CSV")
    ap.add_argument("urls_txt", help="Path to .txt file (one URL per line)")
    ap.add_argument("--out", default="report.csv", help="Output CSV (default: report.csv)")
    ap.add_argument("--timeout", type=float, default=15.0, help="Request timeout seconds (default: 15)")
    ap.add_argument("--concurrency", type=int, default=10, help="Parallel requests (default: 10)")
    ap.add_argument("--follow-redirects", action="store_true", help="Follow redirects (default: off)")
    ap.add_argument("--respect-robots", action="store_true", help="Respect robots.txt (default: off)")
    args = ap.parse_args()

    urls = load_urls(args.urls_txt)
    if not urls:
        print("No valid URLs found in input file.", file=sys.stderr)
        sys.exit(2)

    # group by site base, so we can load robots.txt per host
    groups: dict[str, list[str]] = {}
    for u in urls:
        groups.setdefault(get_site_base(u), []).append(u)

    # shared session per thread is NOT safe; make per-task lightweight sessions
    # but we DO want a shared robots cache
    robots_cache: dict[str, robotparser.RobotFileParser] = {}

    def task(u: str) -> Row:
        sess = requests.Session()
        sess.headers.update({"User-Agent": UA_GOOGLEBOT, "Accept": "text/html,application/xhtml+xml"})
        base = get_site_base(u)

        if args.respect_robots:
            rp = robots_cache.get(base)
            if rp is None:
                rp = build_robot_parser(base, sess, args.timeout)
                robots_cache[base] = rp
        else:
            # treat as allowed
            rp = robotparser.RobotFileParser()
            rp.parse([])

        return audit_one(
            u,
            session=sess,
            rp=rp,
            timeout=max(1.0, args.timeout),
            follow_redirects=bool(args.follow_redirects),
        )

    rows: list[Row] = []
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        futs = [ex.submit(task, u) for u in urls]
        for fut in as_completed(futs):
            rows.append(fut.result())

    # Keep original order in output
    order = {u: i for i, u in enumerate(urls)}
    rows.sort(key=lambda r: order.get(r.input_url, 10**9))

    write_csv(rows, args.out)

    # quick terminal summary
    total = len(rows)
    bad = sum(1 for r in rows if (r.status >= 400 or r.has_noindex == "yes" or r.robots_allowed == "no"))
    print(f"\n✅ Done. Audited {total} URLs -> {args.out}")
    if bad:
        print(f"⚠️ Potential blockers found in {bad}/{total} URLs (4xx/5xx, noindex, or robots blocked).")
        sys.exit(1)
    print("🎉 No obvious blockers found.")
    sys.exit(0)


if __name__ == "__main__":
    main()
