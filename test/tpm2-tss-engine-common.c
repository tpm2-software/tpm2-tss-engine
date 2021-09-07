/* SPDX-License-Identifier: BSD-2 */
/*******************************************************************************
 * Copyright 2021, Erik Larsson
 * All rights reserved.
 ******************************************************************************/

#include "tpm2-tss-engine.h"

#include <setjmp.h>
#include <cmocka.h>

void
check_tpm2tss_tpm2data_read(void **state)
{
    (void)(state);
    TPM2_DATA *tpm2Data = NULL;
    int rc;
    rc = tpm2tss_tpm2data_read(NEG_HANDLE_PEM, &tpm2Data);
    assert_int_equal(rc, 1);
    assert_int_equal(tpm2Data->parent, 0x81000001);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(check_tpm2tss_tpm2data_read),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
