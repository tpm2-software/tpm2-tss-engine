% tpm2tss-tpm2data_write(1) tpm2-tss-engine | Library calls
%
% JUNE 2018

# NAME
**tpm2tss_ecc_getappdata**, **tpm2tss_ecc_setappdata** -- Make an ECC key object

# SYNOPSIS

**#include <tpm2tss.h>**

**TPM2_DATA * tpm2tss_ecc_getappdata(const EC_KEY *key);**

**int tpm2tss_ecc_setappdata(EC_KEY *key, TPM2_DATA *data);**

# DESCRIPTION

**tpm2tss_ecc_getappdata** 

**tpm2tss_ecc_setappdata** 

# RETURN VALUE

Upon successful completion **tpm2tss_ecc_getappdata**() and
**tpm2tss_ecc_setappdata**() return 1. Otherwise 0.

## AUTHOR

Written by Andreas Fuchs.

## COPYRIGHT

tpm2tss is Copyright (C) 2018 Fraunhofer SIT sponsored by Infineon
Technologies AG. License BSD 3-clause.

## SEE ALSO

openssl(1), tpm2tss_genkey(1)

