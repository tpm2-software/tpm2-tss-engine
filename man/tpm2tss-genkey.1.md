% tpm2tss-genkey(1) tpm2-tss-engine | General Commands Manual
%
% MARCH 2019

# NAME
**tpm2tss-genkey**(1) -- generate TPM keys for tpm2-tss-engine

# SYNOPSIS

**tpm2tss-genkey** [*options*] <*filename*>

# DESCRIPTION

**tpm2tss-genkey** creates a key inside a TPM 2.0 connected via the
tpm2tss software stack. Those keys may be an RSA key for decryption or signing
or an ECC key for ECDSA signatures.

# ARGUMENTS

The `tpm2tss-genkey` command expects a filename for storing the resulting TPM
key information. This file can then be loaded with OpenSSL using
`openssl pkeyutl -engine tpm2tss -keyform engine -inkey <filename>`.

# OPTIONS

  * `-a <algorithm>`, `--alg <algorithm>`:
    The public key algorithm (rsa, ecdsa) (default: rsa)

  * `-c <curve>`, `--curve <curve>`:
    If alg ecdsa is chosen, the curve for ecc (default: nist_p256)

  * `-i <file>`, `--importpub <file>`:
    Public key (TPM2B_PUBLIC) to be imported. Requires `-k`.

  * `-k <file>`, `--importtpm <file>`:
    The (encrypted) private key (TPM2B_PRIVATE) to be imported.

  * `-e <exponent>`, `--exponent <exponent>`:
    If alg rsa is chosen, the exponent for rsa (default: 65537)

  * `-h`, `--help`:
    Print help

  * `-o <password>`, `--ownerpw <password>`:
    Password for the owner hierarchy (default: none)

  * `-p <password>`, `--password <password>`:
    Password for the created key (default: none)

  * `-s <keysize>`, `--keysize <keysize>`:
    If alg rsa is chosen, the key size in bits (default: 2048)

  * `-v`, `--verbose`:
    Print verbose messages

  * `-W <password>`, `--parentpw <password>`:
    Password for the parent key (default: none)

# EXAMPLES

Engine informations can be retrieved using:
```
$ openssl engine -t -c tpm2
```
The following sequence of commands creates an RSA key using the TPM, exports the
public key, encrypts a data file and decrypts it using the TPM:
```
$ openssl-gentpm2tss -a rsa -k 2048 mykey
$ openssl rsa -engine tpm2tss -inform engine -in mykey -pubout -outform pem -out mykey.pub
$ openssl pkeyutl -pubin -inkey mykey.pub -in mydata -encrypt -out mycipher
$ openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -decrypt -in mycipher -out mydata
```
The following sequence of commands creates an RSA key using the TPM, exports the
public key, signs a data file using the TPM and validates the signature:
```
$ openssl-gentpm2tss -a rsa -k 2048 mykey
$ openssl rsa -engine tpm2 -inform engine -in mykey -pubout -outform pem -out mykey.pub
$ openssl pkeyutl -engine tpm2 -keyform engine -inkey mykey -sign -in mydata -out mysig
$ openssl pkeyutl -inkey mykey.pub -verify -in mydata -sigfile mysig
```
The following sequence of commands creates an ECDSA key using the TPM, exports
the public key, signs a data file using the TPM and validates the signature:
```
$ openssl-gentpm2tss -a rsa -k 2048 mykey
$ openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -sign -in mydata -out mysig
$ openssl pkeyutl -engine tpm2tss -keyform engine -inkey mykey -verify -in mydata -sigfile mysig
```

# RETURNS

0 on success or 1 on failure.

## AUTHOR

Written by Andreas Fuchs.

## COPYRIGHT

tpm2tss is Copyright (C) 2017-2018 Fraunhofer SIT sponsored by Infineon
Technologies AG. License BSD 3-clause.

## SEE ALSO

openssl(1)

