#!/bin/bash

set -eufx

export OPENSSL_ENGINES=${PWD}/.libs
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "abcde12345abcde12345">${DIR}/mydata

openssl genpkey -engine tpm2tss -outform PEM -out ${DIR}/mykey -algorithm rsa

openssl rsa -engine tpm2tss -inform PEM -in ${DIR}/mykey -pubout -outform pem -out ${DIR}/mykey.pub

openssl pkeyutl -pubin -inkey ${DIR}/mykey.pub -encrypt -in ${DIR}/mydata -out ${DIR}/mycipher
rm ${DIR}/mydata

echo "abc" | openssl pkeyutl -engine tpm2tss -keyform PEM -inkey ${DIR}/mykey -decrypt -in ${DIR}/mycipher -out ${DIR}/mydata
#this is a workaround because -decrypt sometimes exits 0 falsely
test "x$(cat ${DIR}/mydata)" = "xabcde12345abcde12345"
