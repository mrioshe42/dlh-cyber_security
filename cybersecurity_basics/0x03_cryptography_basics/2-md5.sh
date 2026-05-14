#!/bin/bash
md5sum <(echo -n "$1") | awk '{print $1}' > 2_hash.txt
