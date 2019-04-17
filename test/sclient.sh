#!/bin/bash

set -eufx

#The following is for DESTDIR-installations of openssl
export OPENSSL_CONF=$(find $(dirname $(which openssl))/../../ -name openssl.cnf | head -n 1)

if openssl version | grep "OpenSSL 1.0.2" >/dev/null; then
    echo "OpenSSL 1.0.2 does not load the certificate; private key mismatch ???"
    exit 77
fi

echo -en "SSL CONNECTION WORKING\n">test.html

function cleanup()
{
    kill -term $SERVER || true
}

openssl ecparam -genkey -name prime256v1 -noout -out ca.key

echo -e "\n\n\n\n\n\n\n" | openssl req -new -x509 -batch -extensions v3_ca -key ca.key -out ca.crt

echo -e "\n\n\n\n\n\n\n\n\n" | openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

tpm2tss-genkey -a rsa client.tpm.key

echo -e "\n\n\n\n\n\n\n\n\n" | openssl req -new -key client.tpm.key -keyform engine -engine tpm2tss -out client.csr

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

openssl s_server -cert server.crt -key server.key -accept 8443 -verify 1 -CAfile ca.crt -WWW &
SERVER=$!

sleep 1

kill -0 $!

trap "cleanup" EXIT

# We have to sleep, such that the pipe stays open until the command is finished.
(echo -e "GET /test.html HTTP/1.1\r\n\r\n" && sleep 1) | openssl s_client -connect 127.0.0.1:8443 -cert client.crt -key client.tpm.key -engine tpm2tss -keyform engine -CAfile ca.crt

echo "SUCCESS"
