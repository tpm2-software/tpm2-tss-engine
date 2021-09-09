% tpm2tss-tpm2data_write(3) tpm2-tss-engine | Library calls
%
% JUNE 2018

# NAME
**tpm2tss_ecc_makekey** -- Make an ECC key object

# SYNOPSIS

**#include <tpm2tss.h>**

**EVP_PKEY * tpm2tss_ecc_makekey(TPM2_DATA *tpm2Data);**

# DESCRIPTION

**tpm2tss_ecc_makekey** takes a TPM2_DATA object as `tpm2Data` and creates a
corresponding OpenSSL EVP_PKEY object.

# RETURN VALUE

Upon successful completion **tpm2tss_ecc_makekey**() returns the created
EVP_PKEY object's pointer. Otherwise NULL.

## AUTHOR

Written by Andreas Fuchs.

## COPYRIGHT

tpm2tss is Copyright (C) 2018 Fraunhofer SIT sponsored by Infineon
Technologies AG. License BSD 3-clause.

## SEE ALSO

openssl(1)

