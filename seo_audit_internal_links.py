#!/usr/bin/env python3
"""
Internal link audit (single-domain) from a list of URLs in a .txt file.

What it does
- Reads URLs from a text file (one URL per line; ignores blanks and # comments)
- Detects the "common domain" (most frequent base domain) and ignores external links
- Crawls ONLY the provided pages (does not discover new pages)
- Extracts internal links, builds a link graph, and reports:
  - Orphan pages (no inlinks from the provided set)
  - Broken internal links (>=400 or request errors) found on provided pages
  - Coverage of internal linking between provided pages (how many pages link to others)
  - Per-page counts: outlinks, unique outlinks, inlinks, and “links_to_provided”
- Saves reports to an output folder as:
  - summary.json
  - pages.csv
  - broken_links.csv
  - graph_edges.csv

Install:
  pip install requests beautifulsoup4

Usage:
  python seo_audit_internal_links.py urls.txt --out report.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, urldefrag

import requests
from bs4 import BeautifulSoup


# ----------------------------
# URL helpers
# ----------------------------

def _guess_base_domain(hostname: str) -> str:
    """
    Heuristic "base domain" extractor (eTLD+1-ish).
    NOTE: This is a best-effort heuristic and may be imperfect for some ccTLDs (e.g. .co.uk).
    """
    if not hostname:
        return ""
    hostname = hostname.lower().strip(".")
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    # common second-level ccTLD patterns (very small heuristic list)
    second_level_cc = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au"}
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in second_level_cc or last3 in second_level_cc:
        return last3
    return last2


def normalize_url(url: str, *, drop_query: bool = False) -> str:
    """
    Normalize:
    - Resolve fragment
    - Lowercase scheme + host
    - Remove default ports (:80, :443)
    - Normalize path
    - Optionally drop query
    - Normalize trailing slash (remove unless root)
    """
    url = url.strip()
    url, _frag = urldefrag(url)

    p = urlparse(url)
    scheme = (p.scheme or "https").lower()

    host = (p.hostname or "").lower()
    port = p.port
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"

    path = re.sub(r"/{2,}", "/", p.path or "/")
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    query = "" if drop_query else (p.query or "")
    rebuilt = urlunparse((scheme, netloc, path, "", query, ""))
    return rebuilt


def is_http_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


# ----------------------------
# Fetch / parse
# ----------------------------

@dataclass
class FetchResult:
    url: str
    final_url: str
    status: Optional[int]
    error: Optional[str]
    html: Optional[str]
    elapsed_ms: int


def fetch_html(session: requests.Session, url: str, timeout: int) -> FetchResult:
    t0 = time.time()
    try:
        r = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent": "InternalLinkAudit/1.0 (+https://example.local)",
                "Accept": "text/html,application/xhtml+xml",
            },
        )
        elapsed = int((time.time() - t0) * 1000)
        ctype = (r.headers.get("Content-Type") or "").lower()
        if "text/html" not in ctype:
            return FetchResult(url, r.url, r.status_code, f"Non-HTML content-type: {ctype}", None, elapsed)
        return FetchResult(url, r.url, r.status_code, None, r.text, elapsed)
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        return FetchResult(url, url, None, str(e), None, elapsed)


def extract_internal_links(page_url: str, html: str) -> Set[str]:
    soup = BeautifulSoup(html, "html.parser")
    links: Set[str] = set()

    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        # skip mailto/tel/javascript anchors etc.
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        absolute = urljoin(page_url, href)
        if not is_http_url(absolute):
            continue
        links.add(absolute)

    return links


def check_link_status(session: requests.Session, url: str, timeout: int) -> Tuple[str, Optional[int], Optional[str]]:
    try:
        # Try HEAD first, fallback to GET if blocked
        r = session.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "InternalLinkAudit/1.0"},
        )
        if r.status_code in (405, 403) or r.status_code < 100:
            r = session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "InternalLinkAudit/1.0", "Accept": "text/html,*/*"},
            )
        return (url, r.status_code, None)
    except Exception as e:
        return (url, None, str(e))


# ----------------------------
# Main audit logic
# ----------------------------

def read_urls(file_path: Path) -> List[str]:
    urls: List[str] = []
    for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        urls.append(s)
    return urls


def pick_common_base_domain(urls: List[str]) -> str:
    bases = []
    for u in urls:
        if not is_http_url(u):
            continue
        hn = urlparse(u).hostname or ""
        bases.append(_guess_base_domain(hn))
    if not bases:
        return ""
    return Counter(bases).most_common(1)[0][0]


def audit(urls: List[str], out_dir: Path, *, drop_query_for_matching: bool, timeout: int, workers: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Normalize input URLs
    input_urls = [u for u in urls if is_http_url(u)]
    if not input_urls:
        raise SystemExit("No valid http(s) URLs found in the input file.")

    common_base = pick_common_base_domain(input_urls)
    if not common_base:
        raise SystemExit("Could not determine a common domain.")

    # Build canonical map for matching "provided pages"
    provided_norm_to_original: Dict[str, str] = {}
    provided_set: Set[str] = set()
    for u in input_urls:
        nu = normalize_url(u, drop_query=drop_query_for_matching)
        provided_norm_to_original[nu] = u
        provided_set.add(nu)

    # Requests session
    session = requests.Session()

    # 1) Fetch all provided pages
    fetch_results: Dict[str, FetchResult] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fetch_html, session, u, timeout): u for u in input_urls}
        for fut in as_completed(futs):
            original = futs[fut]
            res = fut.result()
            key = normalize_url(res.final_url or original, drop_query=drop_query_for_matching)
            fetch_results[key] = res

    # 2) Parse links per page and filter internal (common base domain)
    page_outlinks_all: Dict[str, Set[str]] = {}
    page_outlinks_internal: Dict[str, Set[str]] = {}
    page_outlinks_to_provided: Dict[str, Set[str]] = {}

    for page_norm, res in fetch_results.items():
        if not res.html:
            page_outlinks_all[page_norm] = set()
            page_outlinks_internal[page_norm] = set()
            page_outlinks_to_provided[page_norm] = set()
            continue

        raw_links = extract_internal_links(res.final_url or res.url, res.html)
        page_outlinks_all[page_norm] = raw_links

        internal = set()
        to_provided = set()

        for link in raw_links:
            p = urlparse(link)
            base = _guess_base_domain(p.hostname or "")
            if base != common_base:
                continue  # ignore external domains
            ln = normalize_url(link, drop_query=drop_query_for_matching)
            internal.add(ln)
            if ln in provided_set:
                to_provided.add(ln)

        page_outlinks_internal[page_norm] = internal
        page_outlinks_to_provided[page_norm] = to_provided

    # 3) Build inlinks among provided pages
    inlinks: Dict[str, Set[str]] = {p: set() for p in provided_set}
    edges: Set[Tuple[str, str]] = set()

    for src in provided_set:
        for dst in page_outlinks_to_provided.get(src, set()):
            if src == dst:
                continue
            inlinks[dst].add(src)
            edges.add((src, dst))

    # 4) Orphans within provided set (no inlinks from other provided pages)
    orphans = sorted([p for p in provided_set if len(inlinks.get(p, set())) == 0])

    # 5) Broken link checking (only internal links, not external)
    #    Check internal links found on provided pages (can include internal targets NOT in provided set).
    all_internal_links: Set[str] = set()
    for s in page_outlinks_internal.values():
        all_internal_links |= s

    broken: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check_link_status, session, u, timeout): u for u in all_internal_links}
        status_map: Dict[str, Tuple[Optional[int], Optional[str]]] = {}
        for fut in as_completed(futs):
            url, status, err = fut.result()
            status_map[url] = (status, err)

    # Attribute broken links back to source pages
    for src in provided_set:
        for target in page_outlinks_internal.get(src, set()):
            status, err = status_map.get(target, (None, "Unknown"))
            is_broken = (status is None) or (status >= 400)
            if is_broken:
                broken.append(
                    {
                        "source_page": src,
                        "target_link": target,
                        "status": status,
                        "error": err,
                    }
                )

    # 6) Compute basic “quality/completeness” metrics
    provided_count = len(provided_set)
    pages_linking_to_others = sum(1 for p in provided_set if len(page_outlinks_to_provided.get(p, set())) > 0)
    pages_with_internal_links = sum(1 for p in provided_set if len(page_outlinks_internal.get(p, set())) > 0)

    possible_edges = provided_count * (provided_count - 1) if provided_count > 1 else 0
    edge_density = (len(edges) / possible_edges) if possible_edges else 0.0

    summary = {
        "common_base_domain": common_base,
        "provided_pages_count": provided_count,
        "fetched_pages_count": len(fetch_results),
        "pages_with_any_internal_links_count": pages_with_internal_links,
        "pages_linking_to_other_provided_pages_count": pages_linking_to_others,
        "provided_graph_edges_count": len(edges),
        "provided_graph_edge_density_0_to_1": round(edge_density, 4),
        "orphan_pages_count": len(orphans),
        "broken_internal_link_instances_count": len(broken),  # each source->target occurrence
        "unique_internal_links_checked_count": len(all_internal_links),
        "notes": [
            "External domains are ignored; only links under the most common base domain are counted.",
            "This script audits linking among the provided pages only; it does not crawl discovered pages.",
            "Base-domain detection is heuristic; for perfect eTLD+1 handling, use `tldextract`.",
        ],
    }

    # ----------------------------
    # Write outputs
    # ----------------------------

    # summary.json
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    # pages.csv (per provided page)
    with (out_dir / "pages.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "page",
                "fetch_status",
                "final_url",
                "fetch_error",
                "elapsed_ms",
                "outlinks_total_found",
                "outlinks_internal_unique",
                "outlinks_to_provided_unique",
                "inlinks_from_provided_unique",
                "is_orphan",
            ],
        )
        w.writeheader()
        for p in sorted(provided_set):
            res = fetch_results.get(p)
            w.writerow(
                {
                    "page": p,
                    "fetch_status": res.status if res else None,
                    "final_url": res.final_url if res else None,
                    "fetch_error": res.error if res else None,
                    "elapsed_ms": res.elapsed_ms if res else None,
                    "outlinks_total_found": len(page_outlinks_all.get(p, set())),
                    "outlinks_internal_unique": len(page_outlinks_internal.get(p, set())),
                    "outlinks_to_provided_unique": len(page_outlinks_to_provided.get(p, set())),
                    "inlinks_from_provided_unique": len(inlinks.get(p, set())),
                    "is_orphan": "yes" if p in orphans else "no",
                }
            )

    # broken_links.csv
    with (out_dir / "broken_links.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["source_page", "target_link", "status", "error"])
        w.writeheader()
        for row in broken:
            w.writerow(row)

    # graph_edges.csv (only among provided pages)
    with (out_dir / "graph_edges.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["source_page", "target_page"])
        for src, dst in sorted(edges):
            w.writerow([src, dst])

    # Print short console summary
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\nSaved report to: {out_dir.resolve()}")


def main():
    ap = argparse.ArgumentParser(description="Audit internal linking for a provided list of pages (single-domain).")
    ap.add_argument("input_file", type=str, help="Path to .txt file with one URL per line")
    ap.add_argument("--out", type=str, default="internal_link_report", help="Output directory")
    ap.add_argument("--timeout", type=int, default=15, help="Request timeout (seconds)")
    ap.add_argument("--workers", type=int, default=12, help="Number of concurrent workers")
    ap.add_argument(
        "--match-drop-query",
        action="store_true",
        help="Drop querystrings when matching links to provided pages (recommended).",
    )
    args = ap.parse_args()

    inp = Path(args.input_file)
    if not inp.exists():
        raise SystemExit(f"Input file not found: {inp}")

    urls = read_urls(inp)
    audit(
        urls=urls,
        out_dir=Path(args.out),
        drop_query_for_matching=args.match_drop_query,
        timeout=args.timeout,
        workers=args.workers,
    )


if __name__ == "__main__":
    main()
