[![Linux Build Status](https://github.com/tpm2-software/tpm2-tss-engine/workflows/Linux%20Build%20Status/badge.svg)](https://github.com/tpm2-software/tpm2-tss-engine/actions)
[![Code Coverage](https://codecov.io/gh/tpm2-software/tpm2-tss-engine/branch/master/graph/badge.svg)](https://codecov.io/gh/tpm2-software/tpm2-tss-engine)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/tpm2-software/tpm2-tss-engine.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-tss-engine/context:cpp)
[![Coverity Scan](https://img.shields.io/coverity/scan/22247.svg)](https://scan.coverity.com/projects/tpm2-tss-engine)


# Overview
The tpm2-tss-engine project implements a cryptographic engine for
[OpenSSL](https://www.openssl.org) for
[Trusted Platform Module (TPM 2.0)](https://trustedcomputinggroup.org/work-groups/trusted-platform-module/)
using the [tpm2-tss](https://www.github.com/tpm2-software/tpm2-tss) software
stack that follows the Trusted Computing Groups (TCG) 
[TPM Software Stack (TSS 2.0)](https://trustedcomputinggroup.org/work-groups/software-stack/).
It uses the 
[Enhanced System API (ESAPI)](https://trustedcomputinggroup.org/wp-content/uploads/TSS_ESAPI_Version-0.9_Revision-04_reviewEND030918.pdf)
interface of the TSS 2.0 for downwards communication. It supports RSA decryption
and signatures as well as ECDSA signatures.

If you are looking for a provider following the OpenSSL 3.0 provider API instead of the engine API, please head over to [tpm2-openssl](https://github.com/tpm2-software/tpm2-openssl)

# Operations

## Key hierarchies
The keys used by this engine are all located underneath an ECC restricted
primary storage decryption key. This key is created on each invocation (since
ECC key creation is faster than RSA's). Thus, no persistent SRK key need to be
predeployed.

The authorization value for the storage hierarchie (the owner password) is
assumed to be clear (of zero length). If this is not the case, it needs to be
set using the engine ctrl.

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

For additional usage examples, please consider the integration tests under
`tests/*.sh`.

## Engine information
Engine informations can be retrieved using
```
openssl engine -t -c tpm2tss
```

## Random data
A set of 10 random bytes can be retrieved using
```
openssl rand -engine tpm2tss -hex 10
engine "tpm2tss" set.
WARNING:esys:src/tss2-esys/esys_tcti_default.c:137:tcti_from_file() Could not load TCTI file: libtss2-tcti-default.so
WARNING:esys:src/tss2-esys/esys_tcti_default.c:137:tcti_from_file() Could not load TCTI file: libtss2-tcti-tabrmd.so
40ac9191079e490d17b7
WARNING:esys:src/tss2-esys/esys_tcti_default.c:137:tcti_from_file() Could not load TCTI file: libtss2-tcti-default.so
WARNING:esys:src/tss2-esys/esys_tcti_default.c:137:tcti_from_file() Could not load TCTI file: libtss2-tcti-tabrmd.so
```
Note: These warnings stem from the tpm2-tss libraries and are not an issue, as
long as a TPM connection is established afterwards by a different tcti.

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
```
openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -encrypt -in mydata -out mycipher
```

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
The following sequence of commands creates an ECDSA key using the TPM, signs
a data file using the TPM and validates the signature:
```
tpm2tss-genkey -a ecdsa mykey
openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -sign -in mydata -out mysig
openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -verify -in mydata -sigfile mysig
```

To export the public key use:

```
openssl ec -engine tpm2tss -inform engine -in mykey -pubout -outform pem -out mykey.pub
```

## The TPM Key
The TPM key may be provided as file name, like "mykey" in the examples above.
Additionally, the special file name "-" is supported to read the key from stdin
and write it to stdout after generation.
Providing the key itself instead of the filename is also supported for reading.

This allows engine-users to avoid the use of temporary files with all its
issues and disadvantages (cleanup on error, mktemp()).

## Self Signed certificate generate operation 
The following sequence of commands creates self signed certificate using TPM
key. Openssl command sets tpm2tss as engine and generates a self signed
certificate based on provided CSR configuration information.
```
$ tpm2tss-genkey -a rsa rsa.tss
$ openssl req -new -x509 -engine tpm2tss -key rsa.tss  -keyform engine -out rsa.crt
```

## Signing using restricted key
Signing using a restricted ECDSA key is possible with the caveat that
the TPM must be used for the digest, so higher-level digest & sign
operations must be used instead, e.g.:
```
$ openssl dgst -engine tpm2tss -keyform engine -sha256 -sign ${HANDLE} -out mysig mydata.txt
```
Where `${HANDLE}` is the TPM persistent handle ID for the restricted
key created by an external tool (since tpm2tss-genkey doesn't support
creating restricted keys).

# TLS and s_server
This engine can be used in all places where OpenSSL is used to create a TLS
secure channel connection. You have can specify the command
```
./tpm2tss-genkey -a rsa rsa.tss
openssl req -new -x509 -engine tpm2tss -key rsa.tss  -keyform engine  -out rsa.crt
openssl s_server -cert rsa.crt -key rsa.tss -keyform engine -engine tpm2tss -accept 8443
```

For ECDSA keys however, the Hash algorithm needs to be specified because the TPM
does not support SHA512. You can blacklisting SHA512 universally. That is
possible via openssl.cnf. See the "SignatureAlgorithms" configuration file
command on this page:
https://www.openssl.org/docs/man1.1.1/man3/SSL_CONF_cmd.html

Note: Usage of s_server with HSM-protected private keys is only supported on
OpenSSL 1.1.0 and newer.

## Development prefixes
In order to use this engine without `make install` for testing call:
```
export LD_LIBRAY_PATH=${TPM2TSS}/src/tss2-{tcti,mu,sys,esys}/.libs
export PKG_CONFIG_PATH=$PWD/../tpm2-tss/lib
./bootstrap
./configure \
    CFLAGS="-I$PWD/../tpm2-tss/include" \
    LDFLAGS="-L$PWD/../tpm2-tss/src/tss2-{esys,sys,mu,tcti}/.libs"
make
make check
```
