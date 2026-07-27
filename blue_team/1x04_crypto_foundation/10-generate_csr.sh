#!/bin/bash
set -euo pipefail

openssl ecparam -name prime256v1 -genkey -noout -out portal_key.pem
chmod 600 portal_key.pem

openssl req -new -key portal_key.pem -out portal.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=MedDefense Health Systems/OU=Information Technology/CN=portal.meddefense.local" \
  -addext "subjectAltName=DNS:portal.meddefense.local,DNS:www.portal.meddefense.local,DNS:patient.meddefense.internal"

echo "[SUCCESS] CSR generated successfully:"
openssl req -text -noout -in portal.csr
