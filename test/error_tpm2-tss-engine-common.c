/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

#include <execinfo.h>
#include <stdio.h>
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>

TSS2_RC
__wrap_Esys_Initialize()
{
    printf("Esys_Initialize called\n");
    void* b[128];
    backtrace_symbols_fd(b, backtrace(b, sizeof(b)/sizeof(b[0])), STDOUT_FILENO);
    return -1;
}
    
void
check_tpm2tss_tpm2data_readtpm(void **state)
{
    (void)(state);
    int i;
    i = tpm2tss_tpm2data_readtpm(0, NULL);
    assert_int_equal(i, 0);
}

void
check_tpm2tss_tpm2data_read(void **state)
{
    (void)(state);
    int i;
    i = tpm2tss_tpm2data_read("", NULL);
    assert_int_equal(i, 0);
}

void
check_init_tpm_parent_via_api(void **state)
{
    (void)(state);
    int i;
    i = tpm2tss_rsa_genkey(NULL, 0, NULL, NULL, 0); 
    assert_int_equal(i, 0);
}

void
check_init_tpm_parent(void **state)
{
    (void)(state);
    TSS2_RC r;
    ESYS_AUXCONTEXT e;
    ESYS_TR t;
    r = init_tpm_parent(&e, -1, &t);
    assert_int_not_equal(r, TSS2_RC_SUCCESS);
}

void
check_init_tpm_key(void **state)
{
    (void)(state);
    int i;
    TSS2_RC r;
    i = tpm2tss_rsa_genkey(NULL, 0, NULL, NULL, 0); 
    assert_int_equal(i, 0);

    ESYS_AUXCONTEXT e;
    ESYS_TR t;
    TPM2_DATA td = { .privatetype = KEY_TYPE_HANDLE };
    r = init_tpm_key(&e, &t, &td);
    assert_int_not_equal(r, TSS2_RC_SUCCESS);
    //assert_int_equal(1, 0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(check_tpm2tss_tpm2data_readtpm),
        cmocka_unit_test(check_tpm2tss_tpm2data_read),
        cmocka_unit_test(check_init_tpm_parent_via_api),
        cmocka_unit_test(check_init_tpm_parent),
        cmocka_unit_test(check_init_tpm_key),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
