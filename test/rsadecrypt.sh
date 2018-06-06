#!/bin/bash

set -eufx

export OPENSSL_ENGINES=${PWD}/.libs
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mydata
tpm2tss-genkey -a rsa -s 2048 -p abc ${DIR}/mykey

echo "abc" | openssl rsa -engine tpm2tss -inform engine -in ${DIR}/mykey -pubout -outform pem -out ${DIR}/mykey.pub -passin stdin

openssl pkeyutl -pubin -inkey ${DIR}/mykey.pub -encrypt -in ${DIR}/mydata -out ${DIR}/mycipher
rm ${DIR}/mydata

echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${DIR}/mykey -decrypt -in ${DIR}/mycipher -out ${DIR}/mydata -passin stdin
#this is a workaround because -decrypt sometimes exits 0 falsely
test "x$(cat ${DIR}/mydata)" = "xabcde12345abcde12345"
