#!/bin/bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 "$1"  & john --show --format=raw-md5 "$1" | awk -F: '/^\?:/ {print $2}' > 4-password.txt
