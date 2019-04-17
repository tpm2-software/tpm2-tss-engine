#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mydata

tpm2tss-genkey -a ecdsa -c nist_p256 mykey

openssl pkeyutl -keyform engine -engine tpm2tss -inkey mykey -sign -in mydata -out mysig

R="$(openssl pkeyutl -keyform engine -engine tpm2tss -inkey mykey -verify -in mydata -sigfile mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
