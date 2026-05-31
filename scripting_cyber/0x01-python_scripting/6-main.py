#!/usr/bin/env python3

netrecon = __import__("6-netrecon")

print("=" * 50)
print("NETWORK RECONNAISSANCE TOOL")
print("=" * 50)

target = input("Enter target domain: ")

print("\n" + "=" * 50)
print("DNS RECONNAISSANCE")
print("=" * 50)
netrecon.dns_recon(target)

print("\n" + "=" * 50)
print("WEB RECONNAISSANCE")
print("=" * 50)
netrecon.web_recon(target)

print("\n" + "=" * 50)
print("PORT SCANNING")
print("=" * 50)
netrecon.port_scan(target)

print("\n" + "=" * 50)
print("RECONNAISSANCE COMPLETE")
print("=" * 50)
