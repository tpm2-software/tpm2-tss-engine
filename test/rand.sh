#!/bin/bash

set -eufx

export OPENSSL_ENGINES=${PWD}/.libs
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

tpm2_startup -c || true

openssl rand -engine tpm2tss -hex 10 >/dev/null
