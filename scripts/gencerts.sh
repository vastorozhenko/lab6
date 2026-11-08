#!/usr/bin/env bash
set -euo pipefail
mkdir -p certs
cd certs
# CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -subj "/CN=DemoCA" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
# Server
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=localhost" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")
# Client (for mTLS, опц.)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/CN=demo-client" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 825 -sha256
echo "Certificates in ./certs"
