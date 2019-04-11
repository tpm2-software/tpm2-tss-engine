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

echo -en "SSL CONNECTION WORKING\n">${DIR}/test.html

function cleanup()
{
    kill -term $SERVER || true
}

openssl ecparam -genkey -name prime256v1 -noout -out ${DIR}/ca.key

echo -e "\n\n\n\n\n\n\n" | openssl req -new -x509 -batch -extensions v3_ca -key ${DIR}/ca.key -out ${DIR}/ca.crt

echo -e "\n\n\n\n\n\n\n\n\n" | openssl req -new -newkey rsa:2048 -nodes -keyout ${DIR}/server.key -out ${DIR}/server.csr

openssl x509 -req -in ${DIR}/server.csr -CA ${DIR}/ca.crt -CAkey ${DIR}/ca.key -CAcreateserial -out ${DIR}/server.crt

tpm2tss-genkey -a rsa ${DIR}/client.tpm.key

echo -e "\n\n\n\n\n\n\n\n\n" | openssl req -new -key ${DIR}/client.tpm.key -keyform engine -engine tpm2tss -out ${DIR}/client.csr

openssl x509 -req -in ${DIR}/client.csr -CA ${DIR}/ca.crt -CAkey ${DIR}/ca.key -CAcreateserial -out ${DIR}/client.crt

pushd ${DIR}
openssl s_server -cert ${DIR}/server.crt -key ${DIR}/server.key -accept 8443 -verify 1 -CAfile ${DIR}/ca.crt -WWW &
SERVER=$!
popd

sleep 1

kill -0 $!

trap "cleanup" EXIT

# We have to sleep, such that the pipe stays open until the command is finished.
(echo -e "GET /test.html HTTP/1.1\r\n\r\n" && sleep 1) | openssl s_client -connect 127.0.0.1:8443 -cert ${DIR}/client.crt -key ${DIR}/client.tpm.key -engine tpm2tss -keyform engine -CAfile ${DIR}/ca.crt

echo "SUCCESS"
