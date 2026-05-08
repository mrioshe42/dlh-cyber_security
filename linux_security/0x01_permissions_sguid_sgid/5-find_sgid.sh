#!/bin/bash
find "$1" -type f -perm -2000 -ls 2>/dev/null
