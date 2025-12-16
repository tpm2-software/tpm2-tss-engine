#!/bin/bash

set -eufx

# ---------- capability checks (skip gracefully) ----------
# 1) OpenSSL must have SM2 + SM3
if ! openssl list -digest-algorithms 2>/dev/null | grep -qi '\bsm3\b'; then
    echo "SKIP: OpenSSL has no SM3 digest algorithms"
    exit 77
fi

if ! (openssl list -public-key-algorithms 2>/dev/null | grep -qi 'sm2' || \
      openssl list -signature-algorithms 2>/dev/null | grep -qi 'sm2'); then
    echo "SKIP: OpenSSL has no SM2 algorithms"
    exit 77
fi

# 2) TPM must advertise SM2 curve + SM3 hash (names may vary by tpm2-tools version/vendor)
if ! tpm2_getcap ecc-curves 2>/dev/null | grep -qi 'sm2'; then
    echo "SKIP: TPM does not support SM2 curve"
    exit 77
fi
if ! tpm2_getcap algorithms 2>/dev/null | grep -qi 'sm3'; then
    echo "SKIP: TPM does not support SM3 algorithms"
    exit 77
fi

# Generate 2k + a bit of data
dd if=/dev/zero of=mydata.txt count=4 bs=512 status=none
echo -n "abcde12345abcde12345abcde12345ab">mydata.txt

# Create a Primary key pair
echo "Generating primary key"
PARENT_CTX=primary_owner_key.ctx

tpm2_createprimary --hierarchy=o --hash-algorithm=sm3_256 --key-algorithm=ecc_sm2:null:sm4128cfb \
                   --key-context=${PARENT_CTX}
tpm2_flushcontext --transient-object

# Load primary key to persistent handle
HANDLE=$(tpm2_evictcontrol --hierarchy=o --object-context=${PARENT_CTX} | cut -d ' ' -f 2 | head -n 1)
tpm2_flushcontext --transient-object

tpm2tss-genkey -a sm2 -c sm2_p256 -P ${HANDLE} mykey

# Digest & sign Data
openssl dgst -engine tpm2tss -keyform engine -sm3 -sign mykey -out mysig mydata.txt

R="$(openssl dgst -engine tpm2tss -keyform engine -sm3 -verify mykey -signature mysig mydata.txt || true)"
if ! echo $R | grep "Verified OK" >/dev/null; then
    echo $R
    tpm2_evictcontrol --hierarchy=o --object-context=${HANDLE}
    exit 1
fi

# Release persistent HANDLE
tpm2_evictcontrol --hierarchy=o --object-context=${HANDLE}
