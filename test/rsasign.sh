#!/bin/bash

set -eufx

if [ -z "${OPENSSL_ENGINES-}" ]; then export OPENSSL_ENGINES=${PWD}/.libs; fi
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mydata

tpm2_startup --clear || true

tpm2tss-genkey -a rsa -s 2048 -p abc ${DIR}/mykey

echo "abc" | openssl rsa -engine tpm2tss -inform engine -in ${DIR}/mykey -pubout -outform pem -out ${DIR}/mykey.pub -passin stdin

echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${DIR}/mykey -sign -in ${DIR}/mydata -out ${DIR}/mysig -passin stdin

#this is a workaround because -verify allways exits 1
R="$(openssl pkeyutl -pubin -inkey ${DIR}/mykey.pub -verify -in ${DIR}/mydata -sigfile ${DIR}/mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
