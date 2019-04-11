#!/bin/bash

set -eufx

export LANG=C
if [ -z "${OPENSSL_ENGINES-}" ]; then export OPENSSL_ENGINES=${PWD}/.libs; fi
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mykey
chmod ugo-rwx ${DIR}/mykey

tpm2_startup -c || true

R="$(tpm2tss-genkey -a ecdsa -c nist_p256 -p abc ${DIR}/mykey 2>&1 || true)"
echo $R
if ! echo $R | grep "Error writing file" >/dev/null; then
    exit 1
fi
