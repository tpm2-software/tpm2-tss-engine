# Overview
The tpm2-tss-engine project implements a cryptographic engine for
[OpenSSL](https://www.openssl.org) for
[Trusted Platform Module (TPM 2.0)](https://trustedcomputinggroup.org/work-groups/trusted-platform-module/)
using the [tpm2-tss](https://www.github.org/tpm2-software/tpm2-tss) software stack
that follows the Trusted Computing Groups (TCG) 
[TPM Software Stack (TSS 2.0)](https://trustedcomputinggroup.org/work-groups/software-stack/).
It uses the 
[Enhanced System API (ESAPI)](https://trustedcomputinggroup.org/wp-content/uploads/TSS_ESAPI_Version-0.9_Revision-04_reviewEND030918.pdf)
interface of the TSS 2.0 for downwards communication.
It supports RSA decryption and signatures as well as ECDSA signatures.

# Operations

## Key hierarchies
The keys used by this engine are all located underneath an ECC restricted
primary storage decryption key. This key is created on each invocation (since
ECC key creation is faster than RSA's). Thus, no persistent SRK key need to be
predeployed.

The authorization value for the storage hierarchie (the owner password) is
assumed to be clear (of zero length).

## Key types
The RSA keys are created with the ability to sign as well as to decrypt.
This allows all RSA keys to be used for either operation.
Note: The TPM's RSA sign operation will enforce tagging payloads with an ASN.1
encoded identifier of the used hash algorithm. This is incompatible with
OpelSSL's RSA interface structures. Thus, the TPM2_RSA_Decrypt method is also
used for signing operations which also requires decrypt capabilities to be
activated for this key.

The ECDSA keys are created as ECDSA keys with the ability to perform signature
operations.

# Build and install instructions
Instructions to build and install tpm2-tss are available in the
[INSTALL](INSTALL.md) file.

# Usage

## Development prefixes
In order to use this engine without `make install` for testing call:
```
export LD_LIBRAY_PATH=${TPM2TSS}/src/tss2-{tcti,mu,sys,esys}/.libs
export OPENSSL_ENGINE=${PWD}/.libs
export PATH=${PWD}:${PATH}
export PKG_CONFIG_PATH=$PWD/../tpm2-tss/lib
./bootstrap
./configure \
    CFLAGS="-I$PWD/../tpm2-tss/include" \
    LDFLAGS="-L$PWD/../tpm2-tss/src/tss2-{esys,sys,mu,tcti}/.libs"
make
tpm_server
make check
```
make check will use any available TPM (including /dev/tpm0,
/dev/tpmrm0) at this moment, until ESAPI allows runtime configuration of TCTI.

PRECONDITION: The owner password of the TPM must be set to zero.

## Engine information
Engine informations can be retrieved using
```
openssl engine -t -c tpm2tss
```

## Random data
A set of 10 random bytes can be retrieved using
```
openssl rand -engine tpm2tss -hex 10'
```

## RSA operations

### RSA decrypt
The following sequence of commands creates an RSA key using the TPM, exports the
public key, encrypts a data file and decrypts it using the TPM:
```
openssl-gentpm2tss -a rsa -k 2048 mykey
openssl rsa -engine tpm2tss -inform engine -in mykey -pubout -outform pem -out mykey.pub
openssl pkeyutl -pubin -inkey mykey.pub -in mydata -encrypt -out mycipher
openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -decrypt -in mycipher -out mydata
```
Alternatively, the data can be encrypted directly with the TPM key using:
`openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -encrypt -in mydata -out mycipher`

### RSA sign
The following sequence of commands creates an RSA key using the TPM, exports the
public key, signs a data file using the TPM and validates the signature:
```
openssl rsa -engine tpm2tss -inform engine -in mykey -pubout -outform pem -out mykey.pub
openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -sign -in mydata -out mysig
openssl pkeyutl -inkey mykey.pub -verify -in mydata -sigfile mysig
```
Alternatively, the data can be validated directly using:
`openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -verify -in mydata -sigfile mysig`
Note: `mydata` must not exceed the size of the RSA key, since these operation
do not perform any hashing of the input data.

## ECDSA operations
The following sequence of commands creates an ECDSA key using the TPM, exports
the public key, signs a data file using the TPM and validates the signature:
```
openssl-gentpm2tss -a rsa -k 2048 mykey
openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -sign -in mydata -out mysig
openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -verify -in mydata -sigfile mysig
```

# Project layout
```
├── doc     : documentation and man pages
├── include : include files for system-wide installation
├── src     : the source files
└── test    : integration tests
```
