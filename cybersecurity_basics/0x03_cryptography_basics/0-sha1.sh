#!/bin/bash
sha1sum <(echo -n "$1") | awk '{print $1}' > 0_hash.txt
