#!/usr/bin/env python3

import socket
import requests
from bs4 import BeautifulSoup

try:
    import dns.resolver
except ImportError:
    dns = None


def dns_recon(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP Address: {ip}")
        print("\nMX Records:")
        if dns:
            for mx in dns.resolver.resolve(domain, 'MX'):
                print(f"  {mx.preference} {mx.exchange}")
    except Exception as e:
        print(f"Error: {e}")


def web_recon(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        print(f"\nStatus Code: {r.status_code}")
        print("\nImportant Headers:")
        for h in ['Server', 'Content-Type']:
            if h in r.headers:
                print(f"  {h}: {r.headers[h]}")
        links = BeautifulSoup(r.text, 'html.parser').find_all('a')
        print(f"\nTotal Links Found: {len(links)}")
    except Exception as e:
        print(f"Error: {e}")


def port_scan(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"\nScanning common ports on {domain}...")
        print("Open ports:")
        for port in [80, 443, 22, 21, 25]:
            sock = socket.socket()
            sock.settimeout(2)
            if sock.connect_ex((ip, port)) == 0:
                print(f"  Port {port}: OPEN")
            sock.close()
    except Exception as e:
        print(f"Error: {e}")
