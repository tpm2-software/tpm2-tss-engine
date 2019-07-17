#!/bin/bash

set -eufx

echo -n "abcde12345abcde12345">mydata.txt

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=primary_owner_key.ctx

tpm2_createprimary --hierarchy=o --halg=sha256 --kalg=rsa \
                   --context=${PARENT_CTX} --pwdk=hex:CAFEBABE
tpm2_flushcontext --transient-object

# Load primary key to persistent handle
HANDLE=$(tpm2_evictcontrol --auth=o --context=${PARENT_CTX} --persistent=0x81010001 | cut -d ' ' -f 2 | head -n 1)
tpm2_flushcontext --transient-object

# Generating a key underneath the persistent, password protected, parent
tpm2tss-genkey -a rsa -s 2048 -p hex:DEADBEEF -P ${HANDLE} -W hex:CAFEBABE mykey

cat > engine.conf <<EOF
    openssl_conf = openssl_init

    [openssl_init]
    engines = engine_section

    [engine_section]
    tpm2tss = tpm2tss_section

    [tpm2tss_section]
    SET_PARENTAUTH = hex:CAFEBABE
EOF

export OPENSSL_CONF=engine.conf

echo hex:DEADBEEF | openssl rsa -engine tpm2tss -inform engine -in mykey -pubout -outform pem -out mykey.pub -passin stdin
cat mykey.pub

echo hex:DEADBEEF | openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -sign -in mydata.txt -out mysig -passin stdin

# Release persistent HANDLE
tpm2_evictcontrol --auth=o --handle=${HANDLE} --persistent=${HANDLE}

#this is a workaround because -verify allways exits 1
R="$(openssl pkeyutl -pubin -inkey mykey.pub -verify -in mydata.txt -sigfile mysig || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    exit 1
fi
