#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl_website(start_url, max_depth=2):
    visited = set()

    def get_domain(url):
        parsed = urlparse(url)
        return parsed.netloc

    def crawl(url, current_depth, start_domain):
        if current_depth > max_depth or url in visited:
            return

        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except requests.exceptions.RequestException:
            return

        parsed_url = urlparse(url)
        if parsed_url.netloc != start_domain:
            return

        visited.add(url)
        print(f"Crawling: {url}")

        if current_depth < max_depth:
            try:
                soup = BeautifulSoup(response.text, 'html.parser')

                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(url, href)

                    parsed = urlparse(absolute_url)
                    if parsed.scheme in ('http', 'https'):
                        crawl(absolute_url, current_depth + 1, start_domain)

            except Exception:
                pass

    try:
        start_domain = get_domain(start_url)
        crawl(start_url, 1, start_domain)
    except Exception:
        return set()

    return visited
