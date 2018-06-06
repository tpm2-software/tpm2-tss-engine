#!/bin/bash

set -eufx

export OPENSSL_ENGINES=${PWD}/.libs
export PATH=${PWD}:${PATH}

openssl rand -engine tpm2tss -hex 10 >/dev/null
