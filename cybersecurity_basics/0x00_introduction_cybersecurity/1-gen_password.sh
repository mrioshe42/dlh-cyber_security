#!/bin/bash
tr -dc '[:alnum:]' < /dev/random | fold -w "$1" | head -n 1
