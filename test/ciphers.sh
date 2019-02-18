#!/bin/bash

set -eufx

DIR=$(mktemp -d)

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=${DIR}/primary_owner_key.ctx

tpm2_createprimary --hierarchy=o \
                   --halg=sha256 \
                   --kalg=rsa \
                   --context=${PARENT_CTX}
tpm2_flushcontext --transient-object

# Create a Sym key
echo "Generating SYM key"
TPM_RSA_PUBKEY=${DIR}/rsakey.pub
TPM_RSA_KEY=${DIR}/rsakey
ALGO="symcipher"
tpm2_create --context-parent=${PARENT_CTX} \
            --halg=sha256 --kalg=${ALGO} \
            --pubfile=${TPM_RSA_PUBKEY} --privfile=${TPM_RSA_KEY} \
            --object-attributes=sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth
tpm2_flushcontext --transient-object

# Load Key to persistent handle
RSA_CTX=${DIR}/rsakey.ctx
tpm2_load --context-parent=${PARENT_CTX} \
          --pubfile=${TPM_RSA_PUBKEY} --privfile=${TPM_RSA_KEY} \
          --context=${RSA_CTX}
tpm2_flushcontext --transient-object

HANDLE=$(tpm2_evictcontrol --auth=o --context=${RSA_CTX} --persistent=0x81010001 | cut -d ' ' -f 2 | head -n 1)
tpm2_flushcontext --transient-object

KEY=$(echo ${HANDLE} | cut -d 'x' -f 2)
IV="0123456789012345"
if openssl version | grep "OpenSSL 1.0.2" > /dev/null; then
    echo -n "hello" > ${DIR}/data.txt
else
    echo -n "hello world goodbye world tpm2 tss openssl" > ${DIR}/data.txt
fi

# Encrypt, Decrypt, Diff Data
openssl enc -aes-256-cfb -e -engine tpm2tss -in ${DIR}/data.txt -out ${DIR}/enc_data -K ${KEY} -iv ${IV}
openssl enc -aes-256-cfb -d -engine tpm2tss -in ${DIR}/enc_data -out ${DIR}/dec_data -K ${KEY} -iv ${IV}
diff ${DIR}/data.txt ${DIR}/dec_data
rm ${DIR}/enc_data ${DIR}/dec_data

openssl enc -aes-256-ofb -e -engine tpm2tss -in ${DIR}/data.txt -out ${DIR}/enc_data -K ${KEY} -iv ${IV}
openssl enc -aes-256-ofb -d -engine tpm2tss -in ${DIR}/enc_data -out ${DIR}/dec_data -K ${KEY} -iv ${IV}
diff ${DIR}/data.txt ${DIR}/dec_data

# Release persistent HANDLE
tpm2_evictcontrol --auth=o --handle=${HANDLE} --persistent=${HANDLE}

