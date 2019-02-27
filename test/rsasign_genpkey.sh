#!/bin/bash

set -eufx

export OPENSSL_ENGINES=${PWD}/.libs
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mydata

openssl genpkey -engine tpm2tss -outform PEM -out ${DIR}/mykey -algorithm rsa

openssl rsa -engine tpm2tss -inform PEM -in ${DIR}/mykey -pubout -outform pem -out ${DIR}/mykey.pub

openssl pkeyutl -engine tpm2tss -keyform PEM -inkey ${DIR}/mykey -sign -in ${DIR}/mydata -out ${DIR}/mysig

#this is a workaround because -verify allways exits 1
R="$(openssl pkeyutl -pubin -inkey ${DIR}/mykey.pub -verify -in ${DIR}/mydata -sigfile ${DIR}/mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
