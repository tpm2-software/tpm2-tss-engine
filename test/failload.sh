#!/bin/bash

set -eufx

export LANG=C
export OPENSSL_ENGINES=${PWD}/.libs
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mykey
chmod ugo-rwx ${DIR}/mykey
R="$(openssl rsa -engine tpm2tss -inform engine -in ${DIR}/mykey -pubout -outform pem -out ${DIR}/mykey.pub 2>&1 || true)"
echo $R
if ! echo $R | grep "unable to load Private Key" >/dev/null; then
    exit 1
fi
