#!/bin/bash

set -eufx

export LANG=C
if [ -z "${OPENSSL_ENGINES-}" ]; then export OPENSSL_ENGINES=${PWD}/.libs; fi
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mydata

tpm2_startup --clear || true

tpm2tss-genkey -a ecdsa -c nist_p256 ${DIR}/mykey

openssl pkeyutl -keyform engine -engine tpm2tss -inkey ${DIR}/mykey -sign -in ${DIR}/mydata -out ${DIR}/mysig

R="$(openssl pkeyutl -keyform engine -engine tpm2tss -inkey ${DIR}/mykey -verify -in ${DIR}/mydata -sigfile ${DIR}/mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
