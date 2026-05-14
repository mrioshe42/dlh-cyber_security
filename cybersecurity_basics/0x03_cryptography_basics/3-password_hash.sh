#!/bin/bash
openssl sha512 <<< "$(echo -n "$1$(openssl rand -hex 16)")" > 3_hash.txt
