#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mydata

tpm2tss-genkey -a rsa -s 2048 -p abc mykey

echo "abc" | openssl rsa -engine tpm2tss -inform engine -in mykey -pubout -outform pem -out mykey.pub -passin stdin

openssl pkeyutl -pubin -inkey mykey.pub -encrypt -in mydata -out mycipher
rm mydata

echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -decrypt -in mycipher -out mydata -passin stdin
#this is a workaround because -decrypt sometimes exits 0 falsely
test "x$(cat mydata)" = "xabcde12345abcde12345"
