#!/usr/bin/env python3

"""
crawlable.py
--------------------
Reads URLs from a text file (one per line), crawls them, and reports whether each
page is crawlable/indexable for Googlebot.

Checks:
- HTTP status + redirects
- Content-Type (HTML vs non-HTML)
- robots.txt allow/disallow (Googlebot + *)
- X-Robots-Tag header (noindex/nofollow)
- <meta name="robots"> + <meta name="googlebot"> (noindex/nofollow)
- rel=canonical (present? self? points elsewhere?)
- Basic "SPA shell" detection (thin HTML likely needs SSR/prerender)
Outputs: CSV report

$ python crawlable.py urls.txt -o report.csv
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from urllib.robotparser import RobotFileParser


UA_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
UA_GENERIC = "Mozilla/5.0 (compatible; CrawlabilityAudit/1.0)"


@dataclass
class Result:
    input_url: str
    final_url: str
    status: int
    redirected: bool
    redirect_chain: str
    content_type: str

    robots_txt_allowed: str  # yes/no/unknown
    robots_txt_checked: str  # robots.txt url or empty

    x_robots_tag: str
    meta_robots: str
    meta_googlebot: str
    has_noindex: bool
    has_nofollow: bool

    canonical: str
    canonical_is_self: str  # yes/no/unknown

    is_html: bool
    spa_shell_suspected: bool
    notes: str


def normalize_url(u: str) -> str:
    u = u.strip()
    if not u:
        return u
    if not re.match(r"^https?://", u, flags=re.I):
        u = "https://" + u
    return u


def get_redirect_chain(resp: requests.Response) -> str:
    chain = [r.url for r in resp.history] + [resp.url]
    return " -> ".join(chain)


def parse_x_robots_tag(headers: Dict[str, str]) -> str:
    # X-Robots-Tag can appear multiple times; requests merges headers case-insensitively.
    # We'll just read the combined value if present.
    for k, v in headers.items():
        if k.lower() == "x-robots-tag":
            return v.strip()
    return ""


def meta_directives_from_html(html: str) -> Tuple[str, str]:
    """
    Return (meta_robots, meta_googlebot) as comma-separated directives if present.
    """
    soup = BeautifulSoup(html, "html.parser")

    def read_meta(name: str) -> str:
        tag = soup.find("meta", attrs={"name": re.compile(rf"^{re.escape(name)}$", re.I)})
        if tag and tag.get("content"):
            return re.sub(r"\s+", " ", tag["content"]).strip()
        return ""

    return read_meta("robots"), read_meta("googlebot")


def has_directive(directives: str, directive: str) -> bool:
    if not directives:
        return False
    parts = [p.strip().lower() for p in directives.split(",")]
    return directive.lower() in parts


def get_canonical(final_url: str, html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    link = soup.find("link", rel=re.compile(r"\bcanonical\b", re.I))
    if not link:
        return ""
    href = link.get("href", "").strip()
    if not href:
        return ""
    return urljoin(final_url, href)


def canonical_is_self(final_url: str, canonical: str) -> str:
    if not canonical:
        return "unknown"
    # Compare scheme+netloc+path without trailing slash differences
    def norm(u: str) -> str:
        p = urlparse(u)
        path = p.path or "/"
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        return f"{p.scheme}://{p.netloc}{path}"

    return "yes" if norm(final_url) == norm(canonical) else "no"


def get_robots_parser_for(url: str, timeout: int = 15) -> Tuple[Optional[RobotFileParser], str]:
    """
    Build RobotFileParser for the URL's origin.
    Returns (parser_or_none, robots_txt_url)
    """
    p = urlparse(url)
    base = f"{p.scheme}://{p.netloc}"
    robots_url = urljoin(base, "/robots.txt")

    rp = RobotFileParser()
    rp.set_url(robots_url)

    try:
        # RobotFileParser.read() uses urllib internally without custom UA/timeouts.
        # We'll fetch ourselves with requests and feed it.
        r = requests.get(robots_url, headers={"User-Agent": UA_GENERIC}, timeout=timeout, allow_redirects=True)
        if r.status_code >= 400:
            return None, robots_url
        rp.parse(r.text.splitlines())
        return rp, robots_url
    except Exception:
        return None, robots_url


def robots_allowed(rp: Optional[RobotFileParser], url: str, user_agent: str) -> str:
    if rp is None:
        return "unknown"
    try:
        return "yes" if rp.can_fetch(user_agent, url) else "no"
    except Exception:
        return "unknown"


def is_html_content_type(ct: str) -> bool:
    if not ct:
        return False
    ct = ct.lower()
    return ("text/html" in ct) or ("application/xhtml+xml" in ct)


def spa_shell_detector(html: str) -> bool:
    """
    Very simple heuristic:
    - extremely little visible text
    - body mostly empty container like #app / #__nuxt / root
    - lots of script tags relative to text
    This is not perfect but helpful for spotting CSR-only pages.
    """
    soup = BeautifulSoup(html, "html.parser")

    # remove non-content nodes
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text(" ", strip=True)
    text_len = len(text)

    # count scripts in original (roughly)
    scripts_count = len(BeautifulSoup(html, "html.parser").find_all("script"))

    # common SPA root ids
    has_spa_root = bool(
        BeautifulSoup(html, "html.parser").find(id=re.compile(r"^(app|root|__nuxt|__next)$", re.I))
    )

    # Heuristic thresholds (tweakable)
    if text_len < 200 and (scripts_count >= 5 or has_spa_root):
        return True
    return False


def fetch(url: str, timeout: int = 20) -> requests.Response:
    return requests.get(
        url,
        headers={
            "User-Agent": UA_GOOGLEBOT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en,sr;q=0.8",
        },
        timeout=timeout,
        allow_redirects=True,
    )


def audit_url(url: str, timeout: int) -> Result:
    input_url = url
    notes: List[str] = []

    try:
        resp = fetch(url, timeout=timeout)
    except requests.RequestException as e:
        return Result(
            input_url=input_url,
            final_url="",
            status=0,
            redirected=False,
            redirect_chain="",
            content_type="",
            robots_txt_allowed="unknown",
            robots_txt_checked="",
            x_robots_tag="",
            meta_robots="",
            meta_googlebot="",
            has_noindex=False,
            has_nofollow=False,
            canonical="",
            canonical_is_self="unknown",
            is_html=False,
            spa_shell_suspected=False,
            notes=f"fetch_error: {e.__class__.__name__}",
        )

    final_url = resp.url
    status = resp.status_code
    redirected = len(resp.history) > 0
    chain = get_redirect_chain(resp)
    ct = resp.headers.get("Content-Type", "").split(";")[0].strip()

    xrt = parse_x_robots_tag(dict(resp.headers))
    xrt_lower = xrt.lower()

    # robots.txt
    rp, robots_url = get_robots_parser_for(final_url, timeout=min(timeout, 15))
    robots_ok = robots_allowed(rp, final_url, UA_GOOGLEBOT)
    if robots_ok == "no":
        notes.append("blocked_by_robots_txt")

    is_html = is_html_content_type(resp.headers.get("Content-Type", ""))

    meta_robots = ""
    meta_googlebot = ""
    canonical = ""
    canon_self = "unknown"
    has_noindex = False
    has_nofollow = False
    spa_suspected = False

    if is_html and resp.text:
        meta_robots, meta_googlebot = meta_directives_from_html(resp.text)

        # Determine index directives
        has_noindex = (
            ("noindex" in xrt_lower)
            or has_directive(meta_robots, "noindex")
            or has_directive(meta_googlebot, "noindex")
        )
        has_nofollow = (
            ("nofollow" in xrt_lower)
            or has_directive(meta_robots, "nofollow")
            or has_directive(meta_googlebot, "nofollow")
        )

        canonical = get_canonical(final_url, resp.text)
        canon_self = canonical_is_self(final_url, canonical)
        if canonical and canon_self == "no":
            notes.append("canonical_points_elsewhere")

        spa_suspected = spa_shell_detector(resp.text)
        if spa_suspected:
            notes.append("spa_shell_suspected_needs_ssr_or_prerender")

    else:
        if status == 200 and not is_html:
            notes.append("non_html_content")

    # Status notes
    if status >= 500:
        notes.append("server_error_5xx")
    elif status >= 400:
        notes.append("client_error_4xx")
    elif status in (301, 302, 307, 308):
        notes.append("redirect_status")

    # Crawlability / indexability summary notes
    if has_noindex:
        notes.append("noindex_detected")
    if "noindex" in xrt_lower and not is_html:
        notes.append("x_robots_noindex_header")

    return Result(
        input_url=input_url,
        final_url=final_url,
        status=status,
        redirected=redirected,
        redirect_chain=chain,
        content_type=ct,
        robots_txt_allowed=robots_ok,
        robots_txt_checked=robots_url,
        x_robots_tag=xrt,
        meta_robots=meta_robots,
        meta_googlebot=meta_googlebot,
        has_noindex=has_noindex,
        has_nofollow=has_nofollow,
        canonical=canonical,
        canonical_is_self=canon_self,
        is_html=is_html,
        spa_shell_suspected=spa_suspected,
        notes=";".join(notes),
    )


def read_urls(path: str) -> List[str]:
    urls: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(normalize_url(line))
    return urls


def write_csv(results: List[Result], out_path: str) -> None:
    fieldnames = [f.name for f in Result.__dataclass_fields__.values()]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in results:
            w.writerow(r.__dict__)


def main() -> int:
    ap = argparse.ArgumentParser(description="Crawlability audit for a list of URLs.")
    ap.add_argument("input", help="Path to text file with URLs (one per line).")
    ap.add_argument("-o", "--output", default="crawlability_report.csv", help="Output CSV path.")
    ap.add_argument("--timeout", type=int, default=20, help="Request timeout seconds.")
    ap.add_argument("--stop-after", type=int, default=0, help="Stop after N URLs (0 = all).")
    args = ap.parse_args()

    urls = read_urls(args.input)
    if not urls:
        print("No URLs found in input file.", file=sys.stderr)
        return 2

    if args.stop_after and args.stop_after > 0:
        urls = urls[: args.stop_after]

    results: List[Result] = []
    for i, u in enumerate(urls, start=1):
        print(f"[{i}/{len(urls)}] {u}", file=sys.stderr)
        results.append(audit_url(u, timeout=args.timeout))

    write_csv(results, args.output)
    print(f"\nWrote: {args.output}")
    print("Tip: filter rows where notes contains blocked_by_robots_txt / noindex_detected / spa_shell_suspected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
