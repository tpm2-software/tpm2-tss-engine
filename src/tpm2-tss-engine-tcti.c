//**********************************************************************;
// Copyright (c) 2018, General Electric Company.
// All rights reserved.
// Copyright (c) 2019, Wind River Systems.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef NO_DL
#include <dlfcn.h>
#endif /* NO_DL */

#include <tss2/tss2_tcti.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "tpm2-tss-engine-err.h"
#include "tpm2-tss-engine-common.h"

#ifndef NO_DL
#define TMP2TSS_TCTI_NAMEFORMAT "libtss2-tcti-%s.so"

static char *
tcti_expand_dlname(const char *shortname)
{
    char *expanddlname;
    /*  determine required buffer length and allocate it */
    int size = snprintf(NULL, 0, TMP2TSS_TCTI_NAMEFORMAT, shortname);
    if (size <= 0) {
        ERR(tcti_expand_dlname, TPM2TSS_R_GENERAL_FAILURE);
        expanddlname = NULL;
    } else {
        expanddlname = (char *)OPENSSL_malloc((size_t) (size + 1));
        if (!expanddlname) {
            ERR(tcti_expand_dlname, ERR_R_MALLOC_FAILURE);
        } else {
            int print_size = snprintf(expanddlname, (size + 1),
                                      TMP2TSS_TCTI_NAMEFORMAT, shortname);
            if (print_size != size) {
                ERR(tcti_expand_dlname, TPM2TSS_R_GENERAL_FAILURE);
                OPENSSL_free(expanddlname);
                expanddlname = NULL;
            }
        }
    }
    return expanddlname;
}

static TSS2_RC
tcti_dlopen(const char *dl_path, dl_handle_t *dlhandle_p)
{
    TSS2_RC r;
    dl_handle_t dlhandle = dlopen(dl_path, RTLD_LAZY);
    if (dlhandle) {
        *dlhandle_p = dlhandle;
        r = TSS2_RC_SUCCESS;
    } else {
        char *expanddlname = tcti_expand_dlname(dl_path);
        if (!expanddlname) {
            ERR(tcti_dlopen, TPM2TSS_R_GENERAL_FAILURE);
            r = TSS2_BASE_RC_GENERAL_FAILURE;
        } else {
            dlhandle = dlopen(expanddlname, RTLD_LAZY);
            if (dlhandle) {
                *dlhandle_p = dlhandle;
                r = TSS2_RC_SUCCESS;
            } else {
                ERR(tcti_dlopen, TPM2TSS_R_DL_OPEN_FAILED);
                r = TSS2_BASE_RC_BAD_REFERENCE;
            }
            OPENSSL_free(expanddlname);
        }
    }
    return r;
}
#endif /* NO_DL */

/*  Given the handle of a loaded TCTI library, get the pointer to the
    TCTI-initialization function. */
static TSS2_RC
tcti_get_init(dl_handle_t dlhandle, TSS2_TCTI_INIT_FUNC *init_p)
{
    TSS2_RC r;
#ifndef NO_DL
    TSS2_TCTI_INFO_FUNC getinfo =
        (TSS2_TCTI_INFO_FUNC) dlsym(dlhandle, TSS2_TCTI_INFO_SYMBOL);
#else
    extern const TSS2_TCTI_INFO* Tss2_Tcti_Info (void);
    TSS2_TCTI_INFO_FUNC getinfo = (TSS2_TCTI_INFO_FUNC) Tss2_Tcti_Info;
#endif /* NO_DL */
    if (!getinfo) {
        ERR(tcti_get_init, TPM2TSS_R_DL_INVALID);
        r = TSS2_BASE_RC_BAD_REFERENCE;
    } else {
        const TSS2_TCTI_INFO *info_p = getinfo();
        *init_p = info_p->init;
        r = TSS2_RC_SUCCESS;
    }
    return r;
}

static void
tcti_dlclose(dl_handle_t *dlhandle_p)
{
    if (dlhandle_p && *dlhandle_p) {
#ifndef NO_DL
#ifndef DISABLE_DLCLOSE
        dlclose(*dlhandle_p);
#endif /* DISABLE_DLCLOSE */
#endif /* NO_DL */
        *dlhandle_p = NULL;
    }
}

/*
    Given the TCTI library handle and TCTI configuration string, return the
    initialized TCTI context.

    NOTE: cfg may be NULL. ctx_p must be non-NULL. dlhandle must be a valid
    handle that can be passed to dlsym.
*/
static TSS2_RC
__tcti_get_ctx(dl_handle_t dlhandle, const char *cfg,
               TSS2_TCTI_CONTEXT ** ctx_p)
{
    TSS2_RC r;
    TSS2_TCTI_INIT_FUNC init;
    /*  get the TCTI-initialization function using the library */
    r = tcti_get_init(dlhandle, &init);
    if (TPM2_RC_SUCCESS != r) {
        ERR(__tcti_get_ctx, TPM2TSS_R_GENERAL_FAILURE);
    } else {
        /* get the TCTI-context size */
        TSS2_TCTI_CONTEXT *ctx = NULL;
        size_t ctx_size = 0;
        r = init(ctx, &ctx_size, cfg);
        if (TPM2_RC_SUCCESS != r) {
            ERR(__tcti_get_ctx, TPM2TSS_R_GENERAL_FAILURE);
        } else {
            ctx = OPENSSL_malloc(ctx_size);
            if (NULL == ctx) {
                ERR(__tcti_get_ctx, ERR_R_MALLOC_FAILURE);
                r = TSS2_BASE_RC_GENERAL_FAILURE;
            } else {
                memset(ctx, 0, ctx_size);
                r = init(ctx, &ctx_size, cfg);
                if (TPM2_RC_SUCCESS != r) {
                    /*  Initialization failed: free the buffer */
                    OPENSSL_free(ctx);
                    ERR(__tcti_get_ctx, TPM2TSS_R_GENERAL_FAILURE);
                } else {
                    *ctx_p = ctx;
                }
            }
        }
    }
    return r;
}

static const char *tcti_path = NULL;
static const char *tcti_cfg = NULL;

void
tcti_clear_opts(void)
{
    OPENSSL_free((void *)tcti_path);
    tcti_path = NULL;
    tcti_cfg = NULL;
}

/*
    Copy and parse the opts string into the TCTI library path and TCTI
    configuration.

    NOTE: opts may be NULL.
*/
TSS2_RC
tcti_set_opts(const char *opts)
{
    /* Valid opts may be one of the following:
       case A: NULL         --> path=NULL,      cfg=NULL
       case B: \0           --> path=\0,        cfg=NULL
       case C: path\0       --> path=path\0,    cfg=NULL
       case D: path:\0      --> path=path\0,    cfg=\0
       case E: path:cfg\0   --> path=path\0,    cfg=cfg\0

       Following opts are invalid if NO_DL is not defined (cfg without path.
       must be explicitly handled, because dlopen("") returns handle of main
       program):
       case F: :\0          --> path=\0,        cfg=\0
       case G: :cfg\0       --> path=\0,        cfg=cfg\0
     */
    TSS2_RC r;
    char *path, *cfg;

    if (!opts) {
        /* case A */
        path = NULL;
        cfg = NULL;
        r = TSS2_RC_SUCCESS;
    } else {
        path = (char *)OPENSSL_strdup(opts);
        if (!path) {
            ERR(tcti_set_opts, ERR_R_MALLOC_FAILURE);
            r = TSS2_BASE_RC_MEMORY;
        } else {
            char *split = strchr(path, (int)':');
            if (!split) {
                /* case  B and case C */
                cfg = NULL;
                r = TSS2_RC_SUCCESS;
            } else {
                if (split == path) {
                    /* case F and case G */
#ifndef NO_DL
                    ERR(tcti_set_opts, TPM2TSS_R_GENERAL_FAILURE);
                    /* Invalid opts: free the buffer */
                    OPENSSL_free(path);
                    r = TSS2_BASE_RC_BAD_REFERENCE;
#else
                    split[0] = '\0';
                    cfg = split + 1;
                    r = TSS2_RC_SUCCESS;
#endif
                } else {
                    /* case D and case E */
                    split[0] = '\0';
                    cfg = split + 1;
                    r = TSS2_RC_SUCCESS;
                }
            }
        }
    }
    /*  set output variables on success */
    if (TSS2_RC_SUCCESS == r) {
        tcti_path = path;
        tcti_cfg = cfg;
    }
    return r;
}

/** get a TCTI context
 *
 * Allocate and initialize a TCTI context and associated DL handle.
 * @param opts          The TCTI option string.
 * @param ctx_p         The TCTI context output variable
 * @param dlhandle_p    The DL handle output variable
 * @retval TSS2_RC_SUCCESS on success or an appropriate TSS2_BASE_RC_ error
 * code on failure.
 */
TSS2_RC
tcti_get_ctx(TSS2_TCTI_CONTEXT **ctx_p, dl_handle_t *dlhandle_p)
{
    TSS2_RC r;
    if (!ctx_p || !dlhandle_p) {
        ERR(tcti_get_ctx, ERR_R_PASSED_NULL_PARAMETER);
        r = TSS2_TCTI_RC_BAD_REFERENCE;
    } else {
        if (!tcti_path) {
            *ctx_p = NULL;
            *dlhandle_p = NULL;
            r = TPM2_RC_SUCCESS;
        } else {
#ifndef NO_DL
            /*  open the shared library at path */
            dl_handle_t dlhandle;
            r = tcti_dlopen(tcti_path, &dlhandle);
            if (TPM2_RC_SUCCESS != r) {
                ERR(tcti_get_ctx, TPM2TSS_R_GENERAL_FAILURE);
            } else {
                /*  allocate and initialize the TCTI context */
                r = __tcti_get_ctx(dlhandle, tcti_cfg, ctx_p);
                if (TPM2_RC_SUCCESS == r) {
                    *dlhandle_p = dlhandle;
                } else {
                    /*  Initialize failed: close the TCTI library */
                    tcti_dlclose(&dlhandle);
                    ERR(tcti_get_ctx, TPM2TSS_R_GENERAL_FAILURE);
                }
            }
#else
            /*  allocate and initialize the TCTI context */
            r = __tcti_get_ctx(NULL, tcti_cfg, ctx_p);
            if (TPM2_RC_SUCCESS != r) {
                ERR(tcti_get_ctx, TPM2TSS_R_GENERAL_FAILURE);
            }
#endif /* NO_DL */
        }
    }
    return r;
}

/** free the TCTI context
 *
 * If a TCTI context is initialized, free the allocated memory and set it to
 * zero. Close the dynamic library for the TCTI module.
 * @param ctx_p The TCTI context in/out variable.
 * @retval TSS2_RC_SUCCESS on success or an appropriate TSS2_BASE_RC_ error
 * code on failure.
 */
TSS2_RC
tcti_free_ctx(TSS2_TCTI_CONTEXT **ctx_p, dl_handle_t *dlhandle_p)
{
    TSS2_RC r;
#ifndef NO_DL
    if (!ctx_p || !dlhandle_p) {
#else
    if (!ctx_p) {
#endif /* NO_DL */
        ERR(tcti_free_ctx, ERR_R_PASSED_NULL_PARAMETER);
        r = TSS2_BASE_RC_BAD_REFERENCE;
    } else {
        if (*ctx_p) {
            Tss2_Tcti_Finalize(*ctx_p);
            OPENSSL_free(*ctx_p);
            *ctx_p = NULL;
            tcti_dlclose(dlhandle_p);
        }
        r = TSS2_RC_SUCCESS;
    }
    return r;
}
