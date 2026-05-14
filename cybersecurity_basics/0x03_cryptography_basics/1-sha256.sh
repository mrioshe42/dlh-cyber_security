#!/bin/bash
sha256sum <(echo -n "$1") | awk '{print $1}' > 1_hash.txt
