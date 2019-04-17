#!/bin/bash

set -eufx

#The following is for DESTDIR-installations of openssl
export OPENSSL_CONF=$(find $(dirname $(which openssl))/../../ -name openssl.cnf | head -n 1)

if openssl version | grep "OpenSSL 1.0.2" >/dev/null; then
    echo "OpenSSL 1.0.2 does not load the certificate; private key mismatch ???"
    exit 77
fi

echo -n "WORKING !!!">index.html

function cleanup()
{
    kill -term $SERVER
}

tpm2tss-genkey -a ecdsa mykey

echo -e "\n\n\n\n\n\n\n" | openssl req -new -x509 -engine tpm2tss -key mykey  -keyform engine -out mykey.crt

openssl s_server -www -cert mykey.crt -key mykey -keyform engine -engine tpm2tss -accept 127.0.0.1:8444 &
SERVER=$!
trap "cleanup" EXIT

sleep 1

echo "GET index.html" | openssl s_client -connect localhost:8444
