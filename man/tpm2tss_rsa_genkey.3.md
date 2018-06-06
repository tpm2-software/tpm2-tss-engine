% tpm2tss-tpm2data_write(1) tpm2-tss-engine | Library calls
%
% JUNE 2018

# NAME
**tpm2tss_rsa_genkey** -- Make an RSA key object

# SYNOPSIS

**#include <tpm2tss.h>**

**int tpm2tss_rsa_genkey(RSA *rsa, int bits, BIGNUM *e, char *password);**

# DESCRIPTION

**tpm2tss_rsa_genkey** issues the generation of an RSA key `rsa` using the TPM.
The keylength is determined by `bits`. The exponent is determined by `e`.
The new key will be protected by `password`.

# RETURN VALUE

Upon successful completion **tpm2tss_rsa_genkey**() returns 1. Otherwise 0.

## AUTHOR

Written by Andreas Fuchs.

## COPYRIGHT

tpm2tss is Copyright (C) 2018 Fraunhofer SIT sponsored by Infineon
Technologies AG. License BSD 3-clause.

## SEE ALSO

openssl(1), tpm2tss_genkey(1)

