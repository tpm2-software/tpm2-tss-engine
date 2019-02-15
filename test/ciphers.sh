#!/bin/bash

set -eufx

export OPENSSL_ENGINES=${PWD}/.libs
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "Hello World">${DIR}/data.txt

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=${DIR}/primary_owner_key.ctx

tpm2_startup -T mssim -c || true

tpm2_createprimary -T mssim -a o -g sha256 -G rsa -o ${PARENT_CTX}
tpm2_flushcontext -T mssim -t

# Create an Sym key
echo "Generating SYM key"
TPM_RSA_PUBKEY=${DIR}/rsakey.pub
TPM_RSA_KEY=${DIR}/rsakey
tpm2_create -T mssim -C ${PARENT_CTX} -g sha256 -G aes256cbc -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -A sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth
tpm2_flushcontext -T mssim -t

# Load Key to persistent handle
RSA_CTX=${DIR}/rsakey.ctx
tpm2_load -T mssim -C ${PARENT_CTX} -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -o ${RSA_CTX}
tpm2_flushcontext -T mssim -t

HANDLE=$(tpm2_evictcontrol -T mssim -a o -c ${RSA_CTX} | cut -d ' ' -f 2)
tpm2_flushcontext -T mssim -t

KEY=${HANDLE}
IV=0123456789012345

# Encrypt Data
openssl enc -aes-256-cbc -e -engine tpm2tss -in ${DIR}/data.txt -out ${DIR}/enc_data -K ${KEY} -iv ${IV}

# Decrypt Data
openssl enc -aes-256-cbc -d -engine tpm2tss -in ${DIR}/enc_data -out ${DIR}/dec_data.txt -K ${KEY} -iv ${IV}

diff ${DIR}/data.txt ${DIR}/dec_data.txt

# Release persistent HANDLE
tpm2_evictcontrol -T mssim -a o -c ${HANDLE}
