% tpm2tss-tpm2data_write(1) tpm2-tss-engine | Library calls
%
% JUNE 2018

# NAME
**tpm2tss_ecc_genkey** -- Make an ECC key object

# SYNOPSIS

**#include <tpm2tss.h>**

**int tpm2tss_ecc_genkey(EC_KEY *key, TPMI_ECC_CURVE curve, const char *password);**

# DESCRIPTION

**tpm2tss_ECC_genkey** issues the generation of an ECC key `key` using the TPM.
The ECC curve is determined by `curve`. The new key will be protected by
`password`.

# RETURN VALUE

Upon successful completion **tpm2tss_ecc_genkey**() returns 1. Otherwise 0.

## AUTHOR

Written by Andreas Fuchs.

## COPYRIGHT

tpm2tss is Copyright (C) 2018 Fraunhofer SIT sponsored by Infineon
Technologies AG. License BSD 3-clause.

## SEE ALSO

openssl(1), tpm2tss_genkey(1)

