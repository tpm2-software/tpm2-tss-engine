#!/bin/bash

set -eufx

export LANG=C
if [ -z "${OPENSSL_ENGINES-}" ]; then export OPENSSL_ENGINES=${PWD}/.libs; fi
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}
#The following is for DESTDIR-installations of openssl
export OPENSSL_CONF=$(find $(dirname $(which openssl))/../../ -name openssl.cnf | head -n 1)

if openssl version | grep "OpenSSL 1.0.2" >/dev/null; then
    echo "OpenSSL 1.0.2 does not load the certificate; private key mismatch ???"
    exit 77
fi

DIR=$(mktemp -d)

echo -n "WORKING !!!">${DIR}/index.html

function cleanup()
{
    kill -term $SERVER
}

tpm2tss-genkey -a ecdsa ${DIR}/mykey

echo -e "\n\n\n\n\n\n\n" | openssl req -new -x509 -engine tpm2tss -key ${DIR}/mykey  -keyform engine -out ${DIR}/mykey.crt

openssl s_server -www -cert ${DIR}/mykey.crt -key ${DIR}/mykey -keyform engine -engine tpm2tss -accept 127.0.0.1:8443 &
SERVER=$!
trap "cleanup" EXIT

sleep 1

echo "GET index.html" | openssl s_client -connect localhost:8443
