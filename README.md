[![Linux Build Status](https://travis-ci.org/tpm2-software/tpm2-tss-engine.svg?branch=master)](https://travis-ci.org/tpm2-software/tpm2-tss-engine)
[![Code Coverage](https://codecov.io/gh/tpm2-software/tpm2-tss-engine/branch/master/graph/badge.svg)](https://codecov.io/gh/tpm2-software/tpm2-tss-engine)

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
export OPENSSL_ENGINES=${PWD}/.libs
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
openssl rand -engine tpm2tss -hex 10
```

## RSA operations

### RSA decrypt
The following sequence of commands creates an RSA key using the TPM, exports the
public key, encrypts a data file and decrypts it using the TPM:
```
tpm2tss-genkey -a rsa -s 2048 mykey
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
openssl pkeyutl -pubin -inkey mykey.pub -verify -in mydata -sigfile mysig
```
Alternatively, the data can be validated directly using:
`openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -verify -in mydata -sigfile mysig`
Note: `mydata` must not exceed the size of the RSA key, since these operation
do not perform any hashing of the input data.

## ECDSA operations
The following sequence of commands creates an ECDSA key using the TPM, exports
the public key, signs a data file using the TPM and validates the signature:
```
tpm2tss-genkey -a ecdsa mykey
openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -sign -in mydata -out mysig
openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -verify -in mydata -sigfile mysig
```

## Self Signed certificate generate operation 
The following sequence of commands creates self signed certificate using TPM key. 
Openssl command mentions tpm2tss as engine and generate self signed certificate based on provided CSR 
configuration information.
```
tpm2tss-genkey -a rsa rsa.tss
Initializing
Setting owner auth to empty auth.
Generating RSA key for 2048 bits keysize.
Establishing connection with TPM.
WARNING:esys:src/tss2-esys/esys_tcti_default.c:137:tcti_from_file() Could not load TCTI file: libtss2-tcti-default.so 
WARNING:esys:src/tss2-esys/esys_tcti_default.c:137:tcti_from_file() Could not load TCTI file: libtss2-tcti-tabrmd.so 
Creating primary key under owner.
Generating the RSA key inside the TPM.
Generated the RSA key inside the TPM.

openssl req -new -x509 -engine tpm2tss -key rsa.tss  -keyform engine  -out rsa.crt
Initializing
engine "tpm2tss" set.
Loading private key rsa.tss
get_auth called for object user key with ui_method 0xffe690
Enter password for user key:
password is 
Loaded key uses alg-id 1
Creating RSA key object.
Created RSA key object.
TPM2 Key loaded
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:IN
State or Province Name (full name) [Some-State]:MAHARASHTRA
Locality Name (eg, city) []:PUNE
Organization Name (eg, company) [Internet Widgits Pty Ltd]:SecureThings
Organizational Unit Name (eg, section) []:Eng
Common Name (e.g. server FQDN or YOUR name) []:webapp.securitydemos.net
Email Address []:sachin.gole@securethings.ai
WARNING:esys:src/tss2-esys/esys_tcti_default.c:137:tcti_from_file() Could not load TCTI file: libtss2-tcti-default.so 
WARNING:esys:src/tss2-esys/esys_tcti_default.c:137:tcti_from_file() Could not load TCTI file: libtss2-tcti-tabrmd.so 
rsa_priv_enc called for scheme 1 and input data(size=51):
3031300d06096086480165030402010500042087b64a295bcf928a2d188133740fbea18b7754b5b4696e80b1a26f991130920a
Padded digest data (size=256):
0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d06096086480165030402010500042087b64a295bcf928a2d188133740fbea18b7754b5b4696e80b1a26f991130920a
Establishing connection with TPM.
WARNING:esys:src/tss2-esys/esys_tcti_default.c:137:tcti_from_file() Could not load TCTI file: libtss2-tcti-default.so 
WARNING:esys:src/tss2-esys/esys_tcti_default.c:137:tcti_from_file() Could not load TCTI file: libtss2-tcti-tabrmd.so 
Creating primary key under owner.
Loading key blob.
Signing (via decrypt operation).
Signature done (size=256):
7f26538cf7cf83d3bd69497fedc407a5c75ebf63a6145cb04d4a175eedc5e3c05db95723a42208d7cadc997d4c6325c6f7f2c6e3c71bf952d7a28ca7550439bba3a0263d1f914ffc73d5da006cc22ce6dda82bb22a1de02a30b11d0e644f94a8139c74def6ad07605d32a73a155d678797eddb5604438d74c2f9bad73c4197f350ecf4b7ae7c3b89ea6bf845de03307fb0b8b91a4207d10992361a1ab07ba32ded61311e9982fc72ab9771156c16e44cb896971afd81dfc32ecabe68a30ea69d26aabd18e52e0ef42ebfcf10dcd6af2c16d54fffda44ab6454aaa2679ff82451939f014221b489a32b35ce7988dbe84c458856fa0d0be8d10486addb699f76b7
```
# Project layout
```
├── doc     : documentation and man pages
├── include : include files for system-wide installation
├── src     : the source files
└── test    : integration tests
```
