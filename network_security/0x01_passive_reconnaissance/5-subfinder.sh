#!/bin/bash
subfinder -silent -d "$1" -nW -oI | awk -F',' '{print $1","$2}' | tee "$1.txt"
