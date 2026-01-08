#!/usr/bin/env python3
"""
URL Structure & Routing audit (normalization + duplicates) for a list of URLs.

Reads:  input .txt file with one URL per line
Writes: .csv report with findings + optimization suggestions

What it checks:
- Long or messy URLs (length, deep paths, many params, tracking params)
- Duplicate URLs (same content / same normalized target, based on rules)
- Trailing slash inconsistencies
- http vs https, www vs non-www hints
- Mixed casing, double slashes, default index pages
- Query normalization (sort params, remove known tracking params)
- Suggests a canonical normalized URL and whether a 301 redirect is recommended

Usage:
  python seo_audit_urls.py urls.txt report.csv

Optional:
  python seo_audit_urls.py urls.txt report.csv --prefer-https --prefer-non-www --slash-policy no-trailing
  python seo_audit_urls.py urls.txt report.csv --tracking-params utm_,gclid,fbclid

Notes:
- This script does NOT crawl pages; it analyzes URL structure only.
- You can extend TRACKING_PARAMS / DEFAULT_INDEX_FILES for your project.
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, quote, unquote

DEFAULT_INDEX_FILES = {
    "index.html", "index.htm", "index.php", "default.html", "default.htm", "home.html"
}

# Any param starting with one of these is considered tracking/noise by default.
DEFAULT_TRACKING_PREFIXES = [
    "utm_",  # utm_source, utm_medium, ...
]

# Exact param names to treat as tracking/noise by default.
DEFAULT_TRACKING_EXACT = {
    "gclid", "fbclid", "msclkid", "yclid", "dclid",
    "ref", "ref_src", "ref_url",
}


def is_probably_url(s: str) -> bool:
    s = s.strip()
    return bool(s) and not s.startswith("#")


def ensure_scheme(url: str) -> str:
    """If a URL has no scheme, assume https://"""
    if "://" not in url:
        return "https://" + url.lstrip("/")
    return url


def normalize_path(path: str) -> Tuple[str, List[str]]:
    """
    Normalize path for URL cleanliness.
    Returns (normalized_path, notes)
    """
    notes: List[str] = []

    # Decode then re-encode safely (keeps slashes).
    raw = unquote(path)

    # Collapse multiple slashes
    if re.search(r"//+", raw):
        raw = re.sub(r"//+", "/", raw)
        notes.append("Path had double slashes")

    # Remove "/./" and resolve simple "/../" patterns conservatively
    # (we avoid complex filesystem semantics; just a common cleanup)
    segments: List[str] = []
    for seg in raw.split("/"):
        if seg == "" and segments == []:
            # keep leading slash
            segments.append("")
            continue
        if seg == ".":
            notes.append("Removed '.' segment")
            continue
        if seg == "..":
            if len(segments) > 1:
                segments.pop()
                notes.append("Resolved '..' segment")
            continue
        segments.append(seg)

    raw = "/".join(segments)
    if raw == "":
        raw = "/"

    # Remove default index pages
    parts = raw.split("/")
    if parts and parts[-1] in DEFAULT_INDEX_FILES:
        parts = parts[:-1]
        raw = "/".join(parts) or "/"
        notes.append("Removed default index file")

    # Ensure leading slash
    if not raw.startswith("/"):
        raw = "/" + raw
        notes.append("Added leading slash")

    # Re-encode path (keep "/" safe)
    norm = quote(raw, safe="/~:@!$&'()*+,;=")

    return norm, notes


def split_host(host: str) -> Tuple[str, str]:
    """Returns (subdomain, registrable-ish). Very naive; good enough for www detection."""
    host = host.lower().strip(".")
    if host.startswith("www."):
        return "www", host[4:]
    return "", host


def normalize_query(
    query: str,
    tracking_prefixes: List[str],
    tracking_exact: set[str],
) -> Tuple[str, Dict[str, str], List[str]]:
    """
    Normalize query: remove tracking params, sort params, drop empty values.
    Returns (normalized_query, removed_params_map, notes)
    """
    notes: List[str] = []
    removed: Dict[str, str] = {}

    pairs = parse_qsl(query, keep_blank_values=True)

    cleaned: List[Tuple[str, str]] = []
    for k, v in pairs:
        k_l = k.lower()
        is_tracking = (k_l in tracking_exact) or any(k_l.startswith(pfx) for pfx in tracking_prefixes)
        if is_tracking:
            removed[k] = v
            continue

        # drop empty params like ?foo= or ?foo
        if v is None or v == "":
            notes.append(f"Dropped empty query param: {k}")
            continue

        cleaned.append((k, v))

    # Sort for stable canonicalization
    cleaned.sort(key=lambda kv: (kv[0].lower(), kv[1]))

    norm_query = urlencode(cleaned, doseq=True)
    if removed:
        notes.append(f"Removed tracking params: {', '.join(sorted(removed.keys()))}")
    return norm_query, removed, notes


def apply_slash_policy(path: str, policy: str) -> Tuple[str, Optional[str]]:
    """
    policy: 'keep', 'trailing', 'no-trailing'
    Returns (path, note)
    """
    if policy == "keep":
        return path, None

    # root stays root
    if path == "/":
        return path, None

    if policy == "trailing":
        if not path.endswith("/"):
            return path + "/", "Add trailing slash"
        return path, None

    if policy == "no-trailing":
        if path.endswith("/"):
            return path.rstrip("/"), "Remove trailing slash"
        return path, None

    return path, None


@dataclass
class AuditRow:
    input_url: str
    parsed_ok: bool
    scheme: str
    host: str
    path: str
    query: str
    fragment_present: bool

    normalized_url: str
    normalized_components: str  # short readable summary
    issues: str
    suggestions: str
    should_301_to_normalized: bool

    duplicate_group_key: str
    duplicates_in_input: int


def build_normalized_url(
    url: str,
    prefer_https: bool,
    prefer_non_www: bool,
    slash_policy: str,
    tracking_prefixes: List[str],
    tracking_exact: set[str],
) -> Tuple[str, str, List[str], List[str], str]:
    """
    Returns:
      normalized_url,
      normalized_components_str,
      issues(list),
      suggestions(list),
      duplicate_group_key
    """
    issues: List[str] = []
    suggestions: List[str] = []

    original = url
    u = ensure_scheme(url.strip())
    parts = urlsplit(u)

    scheme = parts.scheme.lower() if parts.scheme else "https"
    netloc = parts.netloc
    path = parts.path or "/"
    query = parts.query or ""
    fragment = parts.fragment or ""

    if fragment:
        issues.append("Has fragment (#...) — not sent to server (usually fine, but not canonical)")
        suggestions.append("Avoid fragments in canonical URLs")

    # Scheme preference
    if prefer_https and scheme != "https":
        suggestions.append("Prefer HTTPS: redirect http → https")
        issues.append("Uses HTTP (not HTTPS)")
        scheme = "https"

    # Host normalization (www)
    host = netloc.lower()
    sub, bare = split_host(host)

    if prefer_non_www:
        if sub == "www":
            issues.append("Uses www subdomain")
            suggestions.append("Prefer non-www (pick one canonical host)")
            host = bare

    # Lowercase host is always good
    if netloc != netloc.lower():
        issues.append("Host has uppercase characters")
        suggestions.append("Lowercase the hostname")

    # Path normalization
    norm_path, path_notes = normalize_path(path)
    for n in path_notes:
        issues.append(n)

    # Mixed-case path warning (often causes duplicates on some servers)
    if re.search(r"[A-Z]", unquote(path)):
        issues.append("Path contains uppercase letters")
        suggestions.append("Use lowercase paths to avoid duplicates")

    # Apply slash policy
    norm_path2, slash_note = apply_slash_policy(norm_path, slash_policy)
    if slash_note:
        issues.append(slash_note)
        suggestions.append("Normalize trailing slash site-wide (one policy)")

    # Query normalization
    norm_query, removed_params, query_notes = normalize_query(query, tracking_prefixes, tracking_exact)
    for n in query_notes:
        issues.append(n)
    if query and not norm_query:
        # had query but it was all removed/dropped
        suggestions.append("Remove tracking/empty params from canonical URLs")

    # "Messy" heuristics
    full_len = len(original)
    if full_len >= 100:
        issues.append("URL is long (>=100 chars)")
        suggestions.append("Shorten URLs: remove unnecessary folders/params")

    # Too deep path
    depth = len([seg for seg in norm_path2.split("/") if seg])
    if depth >= 6:
        issues.append(f"Deep path (depth={depth})")
        suggestions.append("Flatten URL structure where possible")

    # Too many params
    param_count = len(parse_qsl(query, keep_blank_values=True)) if query else 0
    if param_count >= 5:
        issues.append(f"Many query parameters (count={param_count})")
        suggestions.append("Use clean, parameter-free URLs when possible")

    # Build normalized URL (drop fragment always for canonical)
    normalized = urlunsplit((scheme, host, norm_path2, norm_query, ""))

    # Duplicate grouping key:
    # A key that treats common variants as same page target.
    duplicate_key = f"{host}{norm_path2}?{norm_query}".rstrip("?")

    # Should 301?
    should_301 = (ensure_scheme(original) != normalized)

    # Components summary
    comp = f"{scheme}://{host}{norm_path2}"
    if norm_query:
        comp += f"?{norm_query}"

    return normalized, comp, issues, suggestions, duplicate_key


def read_urls(path: str) -> List[str]:
    urls: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not is_probably_url(s):
                continue
            urls.append(s)
    return urls


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit URL structure & routing from a list of URLs.")
    ap.add_argument("input_txt", help="Input .txt file with one URL per line")
    ap.add_argument("output_csv", help="Output .csv file report")
    ap.add_argument("--prefer-https", action="store_true", default=True,
                    help="Prefer https scheme (default: on)")
    ap.add_argument("--no-prefer-https", dest="prefer_https", action="store_false",
                    help="Disable https preference")
    ap.add_argument("--prefer-non-www", action="store_true", default=True,
                    help="Prefer non-www host (default: on)")
    ap.add_argument("--no-prefer-non-www", dest="prefer_non_www", action="store_false",
                    help="Disable non-www preference")
    ap.add_argument("--slash-policy", choices=["keep", "trailing", "no-trailing"], default="no-trailing",
                    help="Trailing slash normalization policy (default: no-trailing)")
    ap.add_argument("--tracking-params", default="utm_,gclid,fbclid,msclkid",
                    help="Comma list. Items ending with '_' are treated as prefixes (default: utm_,gclid,fbclid,msclkid)")
    args = ap.parse_args()

    # Build tracking lists
    tracking_prefixes = DEFAULT_TRACKING_PREFIXES.copy()
    tracking_exact = set(DEFAULT_TRACKING_EXACT)

    custom = [x.strip() for x in args.tracking_params.split(",") if x.strip()]
    for item in custom:
        if item.endswith("_"):
            if item.lower() not in tracking_prefixes:
                tracking_prefixes.append(item.lower())
        else:
            tracking_exact.add(item.lower())

    urls = read_urls(args.input_txt)

    # First pass: compute normalized and duplicate keys
    temp: List[Tuple[str, Optional[AuditRow], str]] = []
    dup_counter: Dict[str, int] = {}

    for u in urls:
        try:
            normalized, comp, issues, suggestions, dup_key = build_normalized_url(
                u,
                prefer_https=args.prefer_https,
                prefer_non_www=args.prefer_non_www,
                slash_policy=args.slash_policy,
                tracking_prefixes=tracking_prefixes,
                tracking_exact=tracking_exact,
            )

            parts = urlsplit(ensure_scheme(u))
            row = AuditRow(
                input_url=u,
                parsed_ok=True,
                scheme=parts.scheme.lower() if parts.scheme else "",
                host=parts.netloc.lower(),
                path=parts.path or "/",
                query=parts.query or "",
                fragment_present=bool(parts.fragment),

                normalized_url=normalized,
                normalized_components=comp,
                issues="; ".join(sorted(set(issues))) if issues else "",
                suggestions="; ".join(sorted(set(suggestions))) if suggestions else "",
                should_301_to_normalized=(normalized != ensure_scheme(u)),

                duplicate_group_key=dup_key,
                duplicates_in_input=0,  # fill later
            )
            temp.append((u, row, dup_key))
            dup_counter[dup_key] = dup_counter.get(dup_key, 0) + 1
        except Exception as e:
            # If parse fails, still record it
            parts = urlsplit(ensure_scheme(u))
            row = AuditRow(
                input_url=u,
                parsed_ok=False,
                scheme=parts.scheme.lower() if parts.scheme else "",
                host=parts.netloc.lower(),
                path=parts.path or "",
                query=parts.query or "",
                fragment_present=bool(parts.fragment),

                normalized_url="",
                normalized_components="",
                issues=f"Parse/normalize error: {type(e).__name__}: {e}",
                suggestions="Fix URL format",
                should_301_to_normalized=False,

                duplicate_group_key="",
                duplicates_in_input=0,
            )
            temp.append((u, row, ""))

    # Second pass: fill duplicates count
    rows: List[AuditRow] = []
    for _, row, dup_key in temp:
        if row is None:
            continue
        row.duplicates_in_input = dup_counter.get(dup_key, 0) if dup_key else 0
        rows.append(row)

    # Write CSV
    fieldnames = [
        "input_url",
        "parsed_ok",
        "scheme",
        "host",
        "path",
        "query",
        "fragment_present",
        "normalized_url",
        "normalized_components",
        "issues",
        "suggestions",
        "should_301_to_normalized",
        "duplicate_group_key",
        "duplicates_in_input",
    ]

    with open(args.output_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({
                "input_url": r.input_url,
                "parsed_ok": r.parsed_ok,
                "scheme": r.scheme,
                "host": r.host,
                "path": r.path,
                "query": r.query,
                "fragment_present": r.fragment_present,
                "normalized_url": r.normalized_url,
                "normalized_components": r.normalized_components,
                "issues": r.issues,
                "suggestions": r.suggestions,
                "should_301_to_normalized": r.should_301_to_normalized,
                "duplicate_group_key": r.duplicate_group_key,
                "duplicates_in_input": r.duplicates_in_input,
            })

    print(f"✅ Wrote report: {args.output_csv}")
    print(f"URLs analyzed: {len(rows)}")
    # Quick hint: show duplicate groups >1
    dups = sum(1 for k, c in dup_counter.items() if c > 1)
    if dups:
        print(f"⚠️ Duplicate groups found: {dups} (see duplicates_in_input column)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
