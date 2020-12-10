#!/bin/bash

set -eufx

R="$(tpm2tss-genkey -a ecdsa -c nist_p256 -p abc /no/such/file/path 2>&1 || true)"
echo $R
if ! echo $R | grep "Error writing file" >/dev/null; then
    exit 1
fi
