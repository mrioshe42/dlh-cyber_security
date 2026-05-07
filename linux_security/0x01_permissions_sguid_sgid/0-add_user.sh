#!/bin/bash
useradd -m "$1"
chpasswd <<< "$1:$2"
