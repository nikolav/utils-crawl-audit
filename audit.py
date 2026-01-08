
import asyncio
import csv
import re
import sys
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, urljoin

import aiohttp
from bs4 import BeautifulSoup
from urllib import robotparser

USER_AGENT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
TIMEOUT_SEC = 25
CONCURRENCY = 12

ROBOTS_CACHE = {}  # host -> RobotFileParser or None


@dataclass
class Result:
    input_url: str
    final_url: str = ""
    status: int = 0
    redirected: bool = False
    content_type: str = ""
    robots_allowed: str = ""  # "yes"/"no"/"unknown"
    x_robots_tag: str = ""
    meta_robots: str = ""
    has_noindex: bool = False
    canonical: str = ""
    canonical_is_self: str = ""  # "yes"/"no"/"unknown"
    html_title: str = ""
    notes: str = ""


def norm_url(u: str) -> str:
    u = u.strip()
    if not u:
        return ""
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    return u


def get_host_base(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


async def get_robots_parser(session: aiohttp.ClientSession, base: str):
    # Cache per host
    if base in ROBOTS_CACHE:
        return ROBOTS_CACHE[base]

    robots_url = urljoin(base, "/robots.txt")
    rp = robotparser.RobotFileParser()
    try:
        async with session.get(robots_url, timeout=TIMEOUT_SEC, allow_redirects=True) as r:
            if r.status >= 400:
                ROBOTS_CACHE[base] = None
                return None
            text = await r.text(errors="ignore")
            rp.parse(text.splitlines())
            ROBOTS_CACHE[base] = rp
            return rp
    except Exception:
        ROBOTS_CACHE[base] = None
        return None


def parse_x_robots(headers) -> str:
    # Headers can include multiple X-Robots-Tag values
    vals = []
    for k, v in headers.items():
        if k.lower() == "x-robots-tag":
            vals.append(v)
    return " | ".join(vals).strip()


def extract_meta_robots(soup: BeautifulSoup) -> str:
    # Look for <meta name="robots" content="..."> (and googlebot)
    parts = []
    for name in ("robots", "googlebot"):
        tag = soup.find("meta", attrs={"name": re.compile(f"^{name}$", re.I)})
        if tag and tag.get("content"):
            parts.append(f"{name}:{tag.get('content').strip()}")
    return " | ".join(parts)


def has_noindex_flag(xrobots: str, meta: str) -> bool:
    blob = f"{xrobots} {meta}".lower()
    return "noindex" in blob


def extract_canonical(soup: BeautifulSoup, final_url: str) -> str:
    link = soup.find("link", attrs={"rel": re.compile(r"\bcanonical\b", re.I)})
    if link and link.get("href"):
        return urljoin(final_url, link["href"].strip())
    return ""


def canonical_self_check(canonical: str, final_url: str) -> str:
    if not canonical:
        return "unknown"
    # compare without trailing slash differences (simple)
    def tidy(u: str) -> str:
        u = u.strip()
        if u.endswith("/") and len(u) > 8:
            u = u[:-1]
        return u

    return "yes" if tidy(canonical) == tidy(final_url) else "no"


async def fetch_one(session: aiohttp.ClientSession, url: str) -> Result:
    res = Result(input_url=url)
    try:
        async with session.get(
            url,
            timeout=TIMEOUT_SEC,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
        ) as r:
            res.status = r.status
            res.final_url = str(r.url)
            res.redirected = (res.final_url != url)

            res.content_type = (r.headers.get("Content-Type") or "").split(";")[0].strip()
            res.x_robots_tag = parse_x_robots(r.headers)

            # robots.txt check (best-effort)
            base = get_host_base(res.final_url or url)
            rp = await get_robots_parser(session, base)
            if rp is None:
                res.robots_allowed = "unknown"
            else:
                try:
                    allowed = rp.can_fetch(USER_AGENT, res.final_url or url)
                    res.robots_allowed = "yes" if allowed else "no"
                except Exception:
                    res.robots_allowed = "unknown"

            # Only parse HTML-ish responses
            if "html" in res.content_type.lower():
                html = await r.text(errors="ignore")
                soup = BeautifulSoup(html, "lxml")

                title = soup.find("title")
                res.html_title = title.get_text(strip=True) if title else ""

                res.meta_robots = extract_meta_robots(soup)
                res.canonical = extract_canonical(soup, res.final_url or url)
                res.canonical_is_self = canonical_self_check(res.canonical, res.final_url or url)

                res.has_noindex = has_noindex_flag(res.x_robots_tag, res.meta_robots)
            else:
                res.notes = f"Non-HTML content-type: {res.content_type or 'unknown'}"

            # Add notes for common indexability blockers
            notes = []
            if res.status >= 400:
                notes.append(f"HTTP {res.status}")
            if res.robots_allowed == "no":
                notes.append("Blocked by robots.txt")
            if res.has_noindex:
                notes.append("NOINDEX present (meta/header)")
            if res.canonical_is_self == "no":
                notes.append("Canonical points elsewhere")
            if res.status in (301, 302, 307, 308):
                notes.append("Redirect response")
            res.notes = res.notes + ("; " if res.notes and notes else "") + "; ".join(notes)

            return res

    except asyncio.TimeoutError:
        res.notes = "Timeout"
        return res
    except Exception as e:
        res.notes = f"Error: {type(e).__name__}: {e}"
        return res


async def run(urls):
    connector = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SEC)

    sem = asyncio.Semaphore(CONCURRENCY)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async def bound_fetch(u):
            async with sem:
                return await fetch_one(session, u)

        tasks = [bound_fetch(u) for u in urls]
        return await asyncio.gather(*tasks)


def main():
    in_path = "urls.txt"
    out_path = "indexability_audit.csv"

    if len(sys.argv) >= 2:
        in_path = sys.argv[1]
    if len(sys.argv) >= 3:
        out_path = sys.argv[2]

    with open(in_path, "r", encoding="utf-8") as f:
        urls = [norm_url(line) for line in f.readlines()]
        urls = [u for u in urls if u]

    if not urls:
        print("No URLs found. Put them in urls.txt (one per line).")
        sys.exit(1)

    results = asyncio.run(run(urls))

    # Write CSV
    fieldnames = list(asdict(Result(input_url="")).keys())
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in results:
            w.writerow(asdict(r))

    # Quick summary
    blockers = 0
    for r in results:
        if r.status >= 400 or r.robots_allowed == "no" or r.has_noindex or r.canonical_is_self == "no":
            blockers += 1

    print(f"Done. Wrote: {out_path}")
    print(f"Checked: {len(results)} URLs | Potential blockers: {blockers}")


if __name__ == "__main__":
    main()

