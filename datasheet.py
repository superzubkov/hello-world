#!/usr/bin/env python3
"""Simple CLI: asks for a SKU and returns datasheet links from HPE or Juniper."""

from __future__ import annotations

import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterator, List, Optional

USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]
RESULT_CACHE: dict[str, List[str]] = {}
HPE_DOC_RE = re.compile(r"https://(?:[a-z0-9-]+\.)*hpe\.com/psnow/doc/[a-z0-9]+", flags=re.I)
JUNIPER_URL_RE = re.compile(r"https://(?:[a-z0-9-]+\.)*juniper\.net/[^\s\"'<>]+", flags=re.I)
BLOCK_PAGE_MARKERS = ("captcha", "unusual traffic", "verify you are human", "access denied", "cloudflare")


@dataclass
class SearchOutcome:
    links: List[str]
    temporary_empty: bool


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[override]
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self.links.append(href)


def user_agent_cycle() -> Iterator[str]:
    pool = USER_AGENTS[:]
    random.shuffle(pool)
    while True:
        for ua in pool:
            yield ua


def fetch_text(url: str, ua: str, timeout: int = 8) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": ua,
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        encoding = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(encoding, errors="ignore")


def fetch_text_with_retries(url: str, ua_iter: Iterator[str], retries: int = 2) -> str:
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            return fetch_text(url, ua=next(ua_iter))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            # Small backoff for temporary anti-bot/rate-limit responses.
            time.sleep(0.35 + attempt * 0.35)
    if last_error:
        raise last_error
    raise RuntimeError("Failed to fetch search page")


def unwrap_search_redirect(raw_link: str) -> str:
    link = raw_link
    if link.startswith("//"):
        link = "https:" + link

    parsed = urllib.parse.urlparse(link)

    if link.startswith("/l/?") or (
        "duckduckgo.com" in parsed.netloc.lower() and parsed.path.startswith("/l/")
    ):
        uddg = urllib.parse.parse_qs(parsed.query).get("uddg", [None])[0]
        if uddg:
            return urllib.parse.unquote(uddg)

    if "google." in parsed.netloc.lower() and parsed.path == "/url":
        q = urllib.parse.parse_qs(parsed.query).get("q", [None])[0]
        if q:
            return urllib.parse.unquote(q)

    return link


def canonicalize_hpe_doc(link: str) -> str:
    parsed = urllib.parse.urlparse(link)
    if "hpe.com" not in parsed.netloc.lower():
        return link

    params = urllib.parse.parse_qs(parsed.query)
    if "downloadDoc" in parsed.path and params.get("id"):
        return f"https://www.hpe.com/psnow/doc/{params['id'][0]}"

    return link


def normalize_candidate(raw_link: str) -> Optional[str]:
    link = unwrap_search_redirect(raw_link)
    parsed = urllib.parse.urlparse(link)

    if parsed.scheme not in {"http", "https"}:
        return None

    host = parsed.netloc.lower()
    if "hpe.com" not in host and "juniper.net" not in host:
        return None

    return canonicalize_hpe_doc(link)


def looks_like_datasheet(link: str) -> bool:
    value = link.lower()
    return (
        "datasheet" in value
        or "data-sheet" in value
        or "collateral" in value
        or "/psnow/doc/" in value
        or value.endswith(".pdf")
    )


def extract_links_from_html(html: str) -> List[str]:
    parser = LinkExtractor()
    parser.feed(html)

    found: List[str] = []
    seen = set()

    def add(raw: str) -> None:
        normalized = normalize_candidate(raw)
        if normalized and normalized not in seen:
            seen.add(normalized)
            found.append(normalized)

    for href in parser.links:
        add(href)

    for enc in re.findall(r"uddg=([^&\"'<>\\s]+)", html):
        add(urllib.parse.unquote(enc))
    for enc in re.findall(r"[?&]q=(https?%3A%2F%2F[^&\"'<>\\s]+)", html, flags=re.I):
        add(urllib.parse.unquote(enc))
    for match in HPE_DOC_RE.findall(html):
        add(match)
    for match in JUNIPER_URL_RE.findall(html):
        add(match)
    for enc in re.findall(
        r"https?%3A%2F%2F(?:[a-z0-9-]+%2E)*(?:hpe\.com|juniper\.net)%2F[^&\"'<>\\s]+",
        html,
        flags=re.I,
    ):
        add(urllib.parse.unquote(enc))

    return found


def find_datasheet_links(
    sku: str,
    limit: int = 3,
    search_url_templates: Optional[List[str]] = None,
    use_cache: bool = True,
) -> SearchOutcome:
    sku_key = sku.strip().upper()
    if use_cache and sku_key in RESULT_CACHE and RESULT_CACHE[sku_key]:
        return SearchOutcome(links=RESULT_CACHE[sku_key][:limit], temporary_empty=False)

    templates = search_url_templates or [
        "https://duckduckgo.com/html/?q={q}",
        "https://lite.duckduckgo.com/lite/?q={q}",
        "https://www.bing.com/search?q={q}",
    ]

    query_variants = [
        f"{sku} datasheet",
        f"{sku} data sheet",
        f"{sku} pdf",
        f"{sku} datasheet site:hpe.com",
        f"{sku} datasheet site:juniper.net",
        f'"{sku}" datasheet',
    ]

    ua_iter = user_agent_cycle()
    links: List[str] = []
    seen = set()
    total_fetches = 0
    failed_fetches = 0
    block_like_pages = 0

    for query_text in query_variants:
        encoded_query = urllib.parse.quote_plus(query_text)
        search_urls = [template.format(q=encoded_query) for template in templates]

        for url in search_urls:
            total_fetches += 1
            try:
                html = fetch_text_with_retries(url, ua_iter=ua_iter, retries=2)
            except Exception:
                failed_fetches += 1
                continue

            html_lc = html.lower()
            if any(marker in html_lc for marker in BLOCK_PAGE_MARKERS):
                block_like_pages += 1

            for link in extract_links_from_html(html):
                if link not in seen:
                    seen.add(link)
                    links.append(link)

            ranked = [link for link in links if looks_like_datasheet(link)]
            if len(ranked) >= limit:
                RESULT_CACHE[sku_key] = ranked[:limit]
                return SearchOutcome(links=RESULT_CACHE[sku_key], temporary_empty=False)

    ranked = [link for link in links if looks_like_datasheet(link)]
    if len(ranked) < limit:
        ranked.extend([link for link in links if link not in ranked])

    result = ranked[:limit]
    if result:
        RESULT_CACHE[sku_key] = result

    temporary_empty = (
        not result
        and (
            failed_fetches == total_fetches
            or block_like_pages > 0
            or failed_fetches > 0
        )
    )
    return SearchOutcome(links=result, temporary_empty=temporary_empty)


def main() -> int:
    while True:
        try:
            sku = input("Enter SKU (or 'exit' to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            return 0

        if not sku:
            print("SKU must not be empty.")
            continue

        if sku.lower() in {"exit", "quit"}:
            print("Exiting.")
            return 0

        print("Searching for '<SKU> datasheet'...")
        primary_templates = [
            "https://duckduckgo.com/html/?q={q}",
            "https://lite.duckduckgo.com/lite/?q={q}",
        ]
        fallback_templates = [
            "https://www.bing.com/search?q={q}",
            "https://www.google.com/search?q={q}",
        ]

        outcome = find_datasheet_links(
            sku,
            limit=3,
            search_url_templates=primary_templates,
            use_cache=True,
        )
        if not outcome.links and outcome.temporary_empty:
            print("Primary search returned temporary empty results. Trying fallback search engine...")
            outcome = find_datasheet_links(
                sku,
                limit=3,
                search_url_templates=fallback_templates,
                use_cache=False,
            )

        if not outcome.links:
            if outcome.temporary_empty:
                print("Temporary empty search results (search engine/network/anti-bot). Please try again.")
            else:
                print("No results found for this SKU.")
            continue

        for idx, link in enumerate(outcome.links, start=1):
            print(f"{idx}. {link}")


if __name__ == "__main__":
    sys.exit(main())
