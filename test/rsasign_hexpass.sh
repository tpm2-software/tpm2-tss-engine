#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mydata

tpm2tss-genkey -a rsa -s 2048 -p hex:DEADBEEF mykey

echo hex:DEADBEEF | openssl rsa -engine tpm2tss -inform engine -in mykey -pubout -outform pem -out mykey.pub -passin stdin

echo hex:DEADBEEF | openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -sign -in mydata -out mysig -passin stdin

#this is a workaround because -verify allways exits 1
R="$(openssl pkeyutl -pubin -inkey mykey.pub -verify -in mydata -sigfile mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
