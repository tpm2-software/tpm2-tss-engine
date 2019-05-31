/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of tpm2-tss-engine nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include <string.h>

#include <openssl/engine.h>
#include <openssl/rand.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

/** Genereate random values
 *
 * Use the TPM to generate a number of random values.
 * @param buf The buffer to write the random values to
 * @param num The amound of random bytes to generate
 * @retval 1 on success
 * @retval 0 on failure
 */
static int
rand_bytes(unsigned char *buf, int num)
{
    ESYS_AUXCONTEXT eactx = { NULL, NULL };
    TSS2_RC r;

    r = esys_auxctx_init(&eactx);
    ERRchktss(rand_bytes, r, goto end);

    TPM2B_DIGEST *b;
    while (num > 0) {
        r = Esys_GetRandom(eactx.ectx,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           num, &b);
        ERRchktss(rand_bytes, r, goto end);

        memcpy(buf, &b->buffer, b->size);
        num -= b->size;
        buf += b->size;
        free(b);
    }

    esys_auxctx_free(&eactx);

 end:
    return (r == TSS2_RC_SUCCESS);
}

/** Return the entropy status of the prng
 *
 * Since we provide real (TPM-based) randomness even for the pseudorand
 * function, our status is allways good.
 * @retval 1 allways good status
 */
static int
rand_status()
{
    return 1;
}

static RAND_METHOD rand_methods = {
    NULL,                       /* seed() */
    rand_bytes,
    NULL,                       /* cleanup() */
    NULL,                       /* add() */
    rand_bytes,                 /* pseudorand() */
    rand_status                 /* status() */
};

/** Initialize the tpm2tss engine's rand submodule
 *
 * Initialize the tpm2tss engine's submodule by setting function pointer.
 * @param e The engine context.
 * @retval 1 on success
 * @retval 0 on failure
 */
int
init_rand(ENGINE *e)
{
    return ENGINE_set_RAND(e, &rand_methods);
}
