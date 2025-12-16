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

DIR=$(mktemp -d)
TPM_SM2_PUBKEY=${DIR}/sm2key.pub
TPM_SM2_KEY=${DIR}/sm2key
PARENT_CTX=${DIR}/primary_owner_key.ctx

echo -n "abcde12345abcde12345abcde12345ab">${DIR}/mydata

# Create primary key as persistent handle
tpm2_createprimary --hierarchy=o --hash-algorithm=sm3_256 --key-algorithm=ecc_sm2:null:sm4128cfb \
                   --key-context=${PARENT_CTX}
tpm2_flushcontext --transient-object

HANDLE=$(tpm2_evictcontrol --hierarchy=o --object-context=${PARENT_CTX} | cut -d ' ' -f 2 | head -n 1)
tpm2_flushcontext --transient-object

# Create an SM2 key pair
echo "Generating SM2 key pair"
tpm2_create --key-auth=abc --parent-context=${PARENT_CTX} \
            --hash-algorithm=sm3_256 --key-algorithm=ecc_sm2:sm2-sm3_256:null \
            --public=${TPM_SM2_PUBKEY} --private=${TPM_SM2_KEY} \
            --attributes=sign\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda
tpm2_flushcontext --transient-object

tpm2tss-genkey --public ${TPM_SM2_PUBKEY} --private ${TPM_SM2_KEY} --password abc --parent ${HANDLE} ${DIR}/mykey

echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${DIR}/mykey -sign -in ${DIR}/mydata -out ${DIR}/mysig -passin stdin

R="$(echo "abc" | openssl pkeyutl -engine tpm2tss -keyform engine -inkey ${DIR}/mykey -verify -in ${DIR}/mydata -sigfile ${DIR}/mysig -passin stdin 2>&1 || true)"
if ! echo $R | grep "Signature Verified Successfully" >/dev/null; then
    echo $R
    tpm2_evictcontrol --hierarchy=o --object-context=${HANDLE}
    exit 1
fi

# Release persistent HANDLE
tpm2_evictcontrol --hierarchy=o --object-context=${HANDLE}
