#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mykey
chmod ugo-rwx mykey

R="$(tpm2tss-genkey -a ecdsa -c nist_p256 -p abc mykey 2>&1 || true)"
echo $R
if ! echo $R | grep "Error writing file" >/dev/null; then
    exit 1
fi
