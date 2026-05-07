#!/bin/bash
addgroup "$1"
chown :"$1" "$2"
chmod 750 "$2"
