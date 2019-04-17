#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mykey
chmod ugo-rwx mykey

R="$(openssl rsa -engine tpm2tss -inform engine -in mykey -pubout -outform pem -out mykey.pub 2>&1 || true)"
echo $R
if ! echo $R | grep "unable to load Private Key" >/dev/null; then
    exit 1
fi
