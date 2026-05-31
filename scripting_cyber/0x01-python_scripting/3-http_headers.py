#!/usr/bin/env python3

import requests


def get_http_headers(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        return {
            'status_code': response.status_code,
            'headers': dict(response.headers)
        }

    except requests.exceptions.RequestException:
        return None
