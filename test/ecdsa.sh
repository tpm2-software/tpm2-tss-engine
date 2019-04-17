#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mydata

tpm2tss-genkey -a ecdsa -c nist_p256 -p abc mykey

echo "abc" | openssl pkeyutl -keyform engine -engine tpm2tss -inkey mykey -sign -in mydata -out mysig -passin stdin

R="$(echo "abc" | openssl pkeyutl -keyform engine -engine tpm2tss -inkey mykey -verify -in mydata -sigfile mysig -passin stdin || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
