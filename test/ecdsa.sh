#!/bin/bash

set -eufx

export LANG=C
export OPENSSL_ENGINES=${PWD}/.libs
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mydata
tpm2tss-genkey -a ecdsa -c nist_p256 -p abc ${DIR}/mykey

echo "abc" | openssl pkeyutl -keyform engine -engine tpm2tss -inkey ${DIR}/mykey -sign -in ${DIR}/mydata -out ${DIR}/mysig -passin stdin

R="$(echo "abc" | openssl pkeyutl -keyform engine -engine tpm2tss -inkey ${DIR}/mykey -verify -in ${DIR}/mydata -sigfile ${DIR}/mysig -passin stdin || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
