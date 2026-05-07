#!/bin/bash
echo "$1 ALL=(ALL) NOPASSWD: ALL" | tee -a /etc/sudoers
