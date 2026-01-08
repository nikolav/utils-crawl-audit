#!/usr/bin/env python3
"""
seo_render_strategy_guess.py

Best-effort heuristic checker that:
- fetches a URL (optionally also as Googlebot)
- inspects server-sent HTML + a few headers
- prints a "best guess" of current rendering strategy (CSR / SSR / SSG / Hybrid)
- recommends the "optimal" strategy for SEO

Usage:
  python guess_render_strategy_4seo.py https://example.com
  python guess_render_strategy_4seo.py https://example.com --json
  python guess_render_strategy_4seo.py https://example.com --timeout 20

"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional, Tuple

import requests

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None  # type: ignore


DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    content_type: str
    headers: Dict[str, str]
    html: str
    error: Optional[str] = None


@dataclass
class PageSignals:
    # content
    html_len: int
    visible_text_len: int
    visible_text_words: int
    h1_count: int
    link_count: int

    # head/meta
    has_title: bool
    has_meta_desc: bool
    has_canonical: bool
    has_meta_robots: bool
    meta_robots_value: Optional[str]

    # js/app shell indicators
    has_app_shell_root: bool
    app_shell_root_id: Optional[str]
    script_count: int
    module_script_count: int
    inline_script_bytes: int
    has_loading_text: bool

    # framework markers
    marker_next: bool
    marker_nuxt: bool
    marker_angular: bool
    marker_sveltekit: bool

    # caching-ish hints
    has_set_cookie: bool
    cache_control: Optional[str]
    age: Optional[str]
    server: Optional[str]


@dataclass
class StrategyGuess:
    current_strategy: str  # CSR / SSR / SSG / HYBRID / UNKNOWN
    confidence: float      # 0..1
    optimal_for_seo: str   # CSR / SSR / SSG / ISR/Hybrid
    reasoning: Tuple[str, ...]
    signals: PageSignals
    diff_googlebot_note: Optional[str] = None


def fetch(url: str, ua: str, timeout: int) -> FetchResult:
    try:
        r = requests.get(
            url,
            headers={
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
            timeout=timeout,
            allow_redirects=True,
        )
        ct = r.headers.get("content-type", "")
        # keep text (requests decodes using apparent encoding)
        html = r.text or ""
        headers = {k.lower(): v for k, v in r.headers.items()}
        return FetchResult(
            url=url,
            final_url=str(r.url),
            status=int(r.status_code),
            content_type=ct,
            headers=headers,
            html=html,
        )
    except Exception as e:
        return FetchResult(
            url=url,
            final_url=url,
            status=0,
            content_type="",
            headers={},
            html="",
            error=str(e),
        )


def _strip_scripts_styles(soup: Any) -> None:
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()


def _safe_get_text(soup: Any) -> str:
    text = soup.get_text(" ", strip=True)
    # collapse whitespace
    return re.sub(r"\s+", " ", text).strip()


def analyze_html(fr: FetchResult) -> PageSignals:
    html = fr.html or ""
    html_len = len(html)

    # Basic regex fallbacks (in case BS4 missing)
    def rx_count(pat: str) -> int:
        return len(re.findall(pat, html, flags=re.I | re.S))

    def rx_first(pat: str) -> Optional[str]:
        m = re.search(pat, html, flags=re.I | re.S)
        return m.group(1).strip() if m else None

    # Framework markers
    marker_next = bool(re.search(r"__NEXT_DATA__", html, re.I))
    marker_nuxt = bool(re.search(r"__NUXT__|data-nuxt", html, re.I))
    marker_angular = bool(re.search(r"ng-version|_nghost|_ngcontent", html, re.I))
    marker_sveltekit = bool(re.search(r"data-sveltekit", html, re.I))

    # Head/meta via regex (works OK even without BS4)
    has_title = bool(re.search(r"<title[^>]*>.*?</title>", html, re.I | re.S))
    has_meta_desc = bool(re.search(r'<meta[^>]+name=["\']description["\']', html, re.I))
    has_canonical = bool(re.search(r'<link[^>]+rel=["\']canonical["\']', html, re.I))
    has_meta_robots = bool(re.search(r'<meta[^>]+name=["\']robots["\']', html, re.I))
    meta_robots_value = rx_first(r'<meta[^>]+name=["\']robots["\'][^>]+content=["\']([^"\']+)["\']')

    # App shell root detection
    root_id = rx_first(r'<div[^>]+id=["\'](app|root|__next|__nuxt|svelte|main)["\']')
    has_app_shell_root = root_id is not None
    app_shell_root_id = root_id

    # Scripts
    script_count = rx_count(r"<script\b")
    module_script_count = rx_count(r"<script\b[^>]*type=['\"]module['\"]")
    # rough inline script bytes
    inline_script_bytes = 0
    for m in re.finditer(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, flags=re.I | re.S):
        inline_script_bytes += len(m.group(1) or "")

    # Loading-ish placeholders
    has_loading_text = bool(re.search(r"\bloading\b|please wait|app:loading|__loading", html, re.I))

    # Visible text + links + headings
    if BeautifulSoup:
        soup = BeautifulSoup(html, "html.parser")
        h1_count = len(soup.find_all("h1"))
        link_count = len([a for a in soup.find_all("a", href=True) if (a.get("href") or "").strip()])

        # remove non-visible-ish
        _strip_scripts_styles(soup)
        text = _safe_get_text(soup)
        visible_text_len = len(text)
        visible_text_words = len(text.split()) if text else 0
    else:
        # fallback: extremely rough
        h1_count = rx_count(r"<h1\b")
        link_count = rx_count(r"<a\b[^>]*href=")
        text = re.sub(r"<script\b.*?</script>", " ", html, flags=re.I | re.S)
        text = re.sub(r"<style\b.*?</style>", " ", text, flags=re.I | re.S)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        visible_text_len = len(text)
        visible_text_words = len(text.split()) if text else 0

    # Header hints
    headers = fr.headers or {}
    has_set_cookie = "set-cookie" in headers
    cache_control = headers.get("cache-control")
    age = headers.get("age")
    server = headers.get("server")

    return PageSignals(
        html_len=html_len,
        visible_text_len=visible_text_len,
        visible_text_words=visible_text_words,
        h1_count=h1_count,
        link_count=link_count,
        has_title=has_title,
        has_meta_desc=has_meta_desc,
        has_canonical=has_canonical,
        has_meta_robots=has_meta_robots,
        meta_robots_value=meta_robots_value,
        has_app_shell_root=has_app_shell_root,
        app_shell_root_id=app_shell_root_id,
        script_count=script_count,
        module_script_count=module_script_count,
        inline_script_bytes=inline_script_bytes,
        has_loading_text=has_loading_text,
        marker_next=marker_next,
        marker_nuxt=marker_nuxt,
        marker_angular=marker_angular,
        marker_sveltekit=marker_sveltekit,
        has_set_cookie=has_set_cookie,
        cache_control=cache_control,
        age=age,
        server=server,
    )


def guess_strategy(sig: PageSignals) -> Tuple[str, float, Tuple[str, ...]]:
    reasons = []

    # High-level SEO readiness
    meta_good = sig.has_title and (sig.has_meta_desc or sig.has_canonical)
    content_good = sig.visible_text_words >= 120 or sig.visible_text_len >= 800
    content_some = sig.visible_text_words >= 40 or sig.visible_text_len >= 250

    heavy_js = sig.script_count >= 8 or sig.inline_script_bytes >= 20000
    app_shell_like = sig.has_app_shell_root and sig.visible_text_words < 60 and sig.link_count < 5

    if sig.has_loading_text and sig.visible_text_words < 80:
        reasons.append("Found loading/app-shell text with little visible content in raw HTML.")

    if app_shell_like and heavy_js:
        reasons.append("HTML looks like an app shell (root div) + many scripts; little visible content.")
        return ("CSR", 0.90, tuple(reasons))

    if content_good and meta_good:
        reasons.append("Raw HTML includes substantial visible content and key meta tags.")
        # Try to separate SSR vs SSG (weak heuristics)
        cachey = (sig.cache_control or "").lower()
        if (not sig.has_set_cookie) and (
            "immutable" in cachey or "max-age" in cachey or "s-maxage" in cachey
        ):
            reasons.append("Headers suggest cache-friendly HTML (no set-cookie + cache-control hints).")
            return ("SSG", 0.75, tuple(reasons))
        return ("SSR", 0.75, tuple(reasons))

    if content_some and meta_good:
        reasons.append("Some content + meta tags exist in raw HTML, but not a lot.")
        if heavy_js:
            reasons.append("Still a lot of JS present; could be hybrid SSR + client rendering.")
            return ("HYBRID", 0.65, tuple(reasons))
        return ("SSR", 0.60, tuple(reasons))

    if meta_good and not content_some and heavy_js:
        reasons.append("Meta tags exist, but visible content is thin; likely JS-driven content.")
        return ("HYBRID", 0.55, tuple(reasons))

    reasons.append("Could not strongly classify; HTML signals are mixed.")
    return ("UNKNOWN", 0.40, tuple(reasons))


def recommend_optimal(sig: PageSignals, current: str) -> Tuple[str, Tuple[str, ...]]:
    # Heuristic: assume public SEO page if it has title and canonical/desc and some links.
    publicish = sig.has_title and (sig.has_meta_desc or sig.has_canonical) and sig.link_count >= 3
    dynamicish = sig.has_set_cookie  # could indicate personalization
    reasons = []

    if not publicish:
        # probably app/dashboard; CSR can be fine
        reasons.append("Page doesn't look strongly SEO-targeted (weak meta/link signals).")
        return ("CSR (OK for non-SEO pages)", tuple(reasons))

    if current == "CSR":
        # For SEO pages, CSR is risky: recommend SSR/SSG depending on content
        if dynamicish:
            reasons.append("Set-Cookie suggests per-user variation; SSR is safer for SEO pages.")
            return ("SSR", tuple(reasons))
        reasons.append("Public SEO page + CSR signals → recommend SSG/SSR so content is in initial HTML.")
        return ("SSG (or SSR if highly dynamic)", tuple(reasons))

    # If already SSR/SSG/hybrid:
    if current == "SSG":
        reasons.append("SSG is typically optimal for SEO: fast HTML + best CWV potential.")
        return ("SSG", tuple(reasons))

    if current == "SSR":
        if not dynamicish:
            reasons.append("SSR is good for SEO; if content is mostly static, consider SSG/ISR for speed.")
            return ("SSG/ISR (if mostly static), otherwise SSR", tuple(reasons))
        reasons.append("SSR fits SEO pages with personalization or frequently changing content.")
        return ("SSR", tuple(reasons))

    if current == "HYBRID":
        reasons.append("Hybrid can work, but ensure key content+meta are server-rendered on SEO routes.")
        return ("SSR/SSG for SEO routes, CSR for app routes", tuple(reasons))

    reasons.append("Default safe recommendation for SEO pages: SSR or SSG.")
    return ("SSR/SSG", tuple(reasons))


def compare_googlebot(fr_a: FetchResult, sig_a: PageSignals,
                      fr_b: FetchResult, sig_b: PageSignals) -> Optional[str]:
    # Compare whether Googlebot receives materially different HTML/content
    diff_words = abs(sig_a.visible_text_words - sig_b.visible_text_words)

    if diff_words >= 80:
        return (
            f"Googlebot-visible text differs a lot (default={sig_a.visible_text_words} words vs "
            f"Googlebot={sig_b.visible_text_words} words). Make sure you're not serving different content "
            f"to crawlers unintentionally."
        )

    if fr_a.status != fr_b.status:
        return f"Default vs Googlebot HTTP status differs ({fr_a.status} vs {fr_b.status}). Check bot blocking / WAF rules."

    if abs(sig_a.html_len - sig_b.html_len) > 20000:
        return "Default vs Googlebot HTML size differs significantly; verify bots aren’t blocked or treated differently."

    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Guess JS rendering strategy & recommend SEO-optimal approach.")
    ap.add_argument("url", help="Page URL to test (include https://)")
    ap.add_argument("--timeout", type=int, default=15, help="Request timeout seconds (default: 15)")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of human text")
    args = ap.parse_args()

    fr_default = fetch(args.url, DEFAULT_UA, args.timeout)
    fr_bot = fetch(args.url, GOOGLEBOT_UA, args.timeout)

    if fr_default.error:
        print(f"❌ Fetch failed: {fr_default.error}", file=sys.stderr)
        return 2

    sig_default = analyze_html(fr_default)
    sig_bot = analyze_html(fr_bot) if not fr_bot.error else sig_default

    current, conf, reasons = guess_strategy(sig_default)
    optimal, opt_reasons = recommend_optimal(sig_default, current)
    diff_note = compare_googlebot(fr_default, sig_default, fr_bot, sig_bot)

    guess = StrategyGuess(
        current_strategy=current,
        confidence=conf,
        optimal_for_seo=optimal,
        reasoning=reasons + opt_reasons,
        signals=sig_default,
        diff_googlebot_note=diff_note,
    )

    if args.json:
        print(json.dumps(asdict(guess), ensure_ascii=False, indent=2))
        return 0

    # Human output
    print(f"🔎 URL: {fr_default.final_url}")
    print(f"📶 Status: {fr_default.status} | Content-Type: {fr_default.content_type.split(';')[0].strip() or 'unknown'}")
    print()
    print(f"🧠 Current strategy guess: {guess.current_strategy} (confidence ~ {guess.confidence:.0%})")
    print(f"✅ Optimal for SEO (best guess): {guess.optimal_for_seo}")
    print()

    if guess.diff_googlebot_note:
        print(f"⚠️ Googlebot note: {guess.diff_googlebot_note}")
        print()

    print("📌 Key signals:")
    print(f"  • Visible text: {sig_default.visible_text_words} words ({sig_default.visible_text_len} chars)")
    print(f"  • H1 count: {sig_default.h1_count} | Link count: {sig_default.link_count}")
    print(f"  • Meta: title={sig_default.has_title}, desc={sig_default.has_meta_desc}, canonical={sig_default.has_canonical}, robots={sig_default.has_meta_robots}")
    if sig_default.meta_robots_value:
        print(f"  • robots content: {sig_default.meta_robots_value}")
    print(f"  • Scripts: {sig_default.script_count} (module: {sig_default.module_script_count}, inline bytes: {sig_default.inline_script_bytes})")
    print(f"  • App-shell root: {sig_default.has_app_shell_root} (id={sig_default.app_shell_root_id})")
    print(f"  • Loading text detected: {sig_default.has_loading_text}")
    print(f"  • Framework markers: next={sig_default.marker_next}, nuxt={sig_default.marker_nuxt}, angular={sig_default.marker_angular}, sveltekit={sig_default.marker_sveltekit}")
    print(f"  • Headers: set-cookie={sig_default.has_set_cookie}, cache-control={sig_default.cache_control or '—'}, age={sig_default.age or '—'}")
    print()

    print("🧾 Reasoning:")
    for r in guess.reasoning:
        print(f"  - {r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
