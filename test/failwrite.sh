#!/bin/bash

set -eufx

export LANG=C
export OPENSSL_ENGINES=${PWD}/.libs
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mykey
chmod ugo-rwx ${DIR}/mykey
R="$(tpm2tss-genkey -a ecdsa -c nist_p256 -p abc ${DIR}/mykey 2>&1 || true)"
echo $R
if ! echo $R | grep "Error writing file" >/dev/null; then
    exit 1
fi
