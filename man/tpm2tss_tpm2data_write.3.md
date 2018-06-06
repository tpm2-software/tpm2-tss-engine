% tpm2tss-tpm2data_write(1) tpm2-tss-engine | Library calls
%
% JUNE 2018

# NAME
**tpm2tss_tpm2data_write**, **tpm2tss_tpm2data_read** -- read/write TPM2_DATA

# SYNOPSIS

**#include <tpm2tss.h>**

**int tpm2tss_tpm2data_read(const char *filename, TPM2_DATA **tpm2Datap);**

**int tpm2tss_tpm2data_write(const TPM2_DATA *tpm2Data, const char *filename);**

# DESCRIPTION

**tpm2tss_tpm2data_read** reads the TPM2_DATA object from a file called
`filename`, allocates memory and stores it under the parameter `tpm2Datap`.
Must be freed using the `free()` function.

**tpm2tss_tpm2data_write** writes the TPM2_DATA object from the parameter
`tpm2Data` to a newly created file called `filename`.

# RETURN VALUE

Upon successful completion **tpm2tss_tpm2data_write**() and
**tpm2tss_tpm2data_read**() return 1. Otherwise 0.

## AUTHOR

Written by Andreas Fuchs.

## COPYRIGHT

tpm2tss is Copyright (C) 2018 Fraunhofer SIT sponsored by Infineon
Technologies AG. License BSD 3-clause.

## SEE ALSO

openssl(1)

