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


# tpm2tss-genkey supports "-a sm2" and "-c sm2_p256"
tpm2tss-genkey -a sm2 -c sm2_p256 sm2key

openssl req -new -engine tpm2tss -keyform engine -key sm2key \
    -sm3 -subj "/C=CN/O=tpm2tss-engine/CN=sm2-test" -out test.csr

R="$(openssl req -in test.csr -noout -verify -engine tpm2tss -key sm2key -keyform engine 2>&1 || true)"
if ! echo "$R" | grep -qi "verify OK" >/dev/null; then
    echo "$R"
    exit 1
fi
