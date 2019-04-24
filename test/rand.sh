#!/bin/bash

set -eufx

if [ -z "${OPENSSL_ENGINES-}" ]; then export OPENSSL_ENGINES=${PWD}/.libs; fi
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

tpm2_startup --clear || true

openssl rand -engine tpm2tss -hex 10 >/dev/null
