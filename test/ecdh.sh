#!/bin/bash

set -euf

# Create a primary key pair
echo "Generating primary key"
PARENT_CTX=primary_owner_key.ctx
tpm2_createprimary --hierarchy=o \
                   --key-algorithm=ecc \
                   --hash-algorithm=sha256 \
                   --key-context=${PARENT_CTX}

# Create an ECDH key pair
echo "Generating ECDH key pair"
ECDH_TPM_PUBKEY=ecdhtpm.pub
ECDH_TPM_KEY=ecdhtpm
tpm2_create --key-auth=abc \
            --parent-context=${PARENT_CTX} \
            --key-algorithm=ecc256:ecdh-sha256 \
            --public=${ECDH_TPM_PUBKEY} \
            --private=${ECDH_TPM_KEY} \
            --attributes fixedparent\|fixedtpm\|decrypt\|sensitivedataorigin\|userwithauth\|noda
tpm2_flushcontext --transient-object

# Load key to persistent handle
ECDH_CTX=ecdhkey.ctx
tpm2_load --parent-context=${PARENT_CTX} \
          --public=${ECDH_TPM_PUBKEY} \
          --private=${ECDH_TPM_KEY} \
          --key-context=${ECDH_CTX}
tpm2_flushcontext --transient-object

HANDLE=$(tpm2_evictcontrol --hierarchy=o --object-context=${ECDH_CTX} | cut -d ' ' -f 2 | head -n 1)
tpm2_flushcontext --transient-object

# Get public key of handle
ECDH_TPM_PUBKEY_PEM=ecdhtpm.pem
tpm2_readpublic --object-context=${HANDLE} --output=${ECDH_TPM_PUBKEY_PEM} --format=pem

# Generate peer key pair
ECDH_PEER_PUBKEY=echdpeer.pub
ECDH_PEER_KEY=ecdhpeer
openssl ecparam -name prime256v1 -genkey -noout -out ${ECDH_PEER_KEY}
openssl ec -in ${ECDH_PEER_KEY} -pubout -out ${ECDH_PEER_PUBKEY}

# Perform ECDH using the TPM key pair as the private key and the peer key pair as the public key
SECRET0=$(echo "abc" | openssl pkeyutl -derive -engine tpm2tss -keyform engine -inkey ${HANDLE} -peerkey ${ECDH_PEER_PUBKEY} -peerform pem -passin stdin | base64)
echo -e "TPM(prv) <-> PEER(pub): ${SECRET0}"

# Perform ECDH with the peer key pair as the private key and the TPM key pair as the public key
SECRET1=$(openssl pkeyutl -derive -inkey ${ECDH_PEER_KEY} -peerkey ${ECDH_TPM_PUBKEY_PEM} -peerform pem | base64)
echo -e "TPM(pub) <-> PEER(prv): ${SECRET1}"

# Release persistent HANDLE and remove files
tpm2_evictcontrol --object-context=${HANDLE}
rm ${ECDH_PEER_KEY} ${ECDH_PEER_PUBKEY} ${ECDH_TPM_PUBKEY} ${ECDH_TPM_KEY} ${ECDH_TPM_PUBKEY_PEM} ${ECDH_CTX}

# Ensure tpm and peer generated secrets are the same
if [ "${SECRET0}" != "${SECRET1}" ]; then
    echo "secrets don't match"
    exit 1
fi
