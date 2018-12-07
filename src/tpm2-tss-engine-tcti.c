//**********************************************************************;
// Copyright (c) 2018, General Electric Company.
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
#include <dlfcn.h>

#include <tss2/tss2_tcti.h>
#include <openssl/err.h>

#include "tpm2-tss-engine-err.h"

#define TMP2TSS_TCTI_NAMEFORMAT "libtss2-tcti-%s.so"
#define TPM2TSS_TCTI_ENVVAR "TPM2TSSENGINE_TCTI"

/*  Define an explicit dl_handle type to reduce confusion */
typedef void* dl_handle_t;

static char*
tcti_expand_dlname (const char *shortname)
{
    char *expanddlname;
    /*  determine required buffer length and allocate it*/
    int size = snprintf (NULL,
                         0,
                         TMP2TSS_TCTI_NAMEFORMAT,
                         shortname);
    if (size <= 0) {
        ERR(tcti_expand_dlname, TPM2TSS_R_GENERAL_FAILURE);
        expanddlname = NULL;
    } else {
        expanddlname = (char*)malloc((size_t)(size+1));
        if (!expanddlname) {
            ERR(tcti_expand_dlname, ERR_R_MALLOC_FAILURE);
        } else {
            int print_size = snprintf (expanddlname,
                                       (size+1),
                                       TMP2TSS_TCTI_NAMEFORMAT,
                                       shortname);
            if (print_size != size) {
                ERR(tcti_expand_dlname, TPM2TSS_R_GENERAL_FAILURE);
                free(expanddlname);
                expanddlname = NULL;
            }
        }
    }
    return expanddlname;
}

static TSS2_RC
tcti_dlopen (const char     *dl_path,
             dl_handle_t    *dl_handle_p)
{
    TSS2_RC r;
    dl_handle_t dl_handle = dlopen(dl_path, RTLD_LAZY);
    if (dl_handle) {
        *dl_handle_p = dl_handle;
        r = TSS2_RC_SUCCESS;
    } else {
        char *expanddlname = tcti_expand_dlname(dl_path);
        if (!expanddlname) {
            ERR(tcti_dlopen, TPM2TSS_R_GENERAL_FAILURE);
            r = TSS2_BASE_RC_GENERAL_FAILURE;
        } else {
            dl_handle = dlopen(expanddlname, RTLD_LAZY);
            if (dl_handle) {
                *dl_handle_p = dl_handle;
                r = TSS2_RC_SUCCESS;
            } else {
                ERR(tcti_dlopen, TPM2TSS_R_DL_OPEN_FAILED);
                r = TSS2_BASE_RC_BAD_REFERENCE;
            }
            free(expanddlname);
        }
    }
    return r;
}

/*  Given the handle of a loaded TCTI library, get the pointer to the
    TCTI-initialization function. */
static TSS2_RC
tcti_get_init (dl_handle_t          dl_handle,
               TSS2_TCTI_INIT_FUNC  *init_p)
{
    TSS2_RC r;
    TSS2_TCTI_INFO_FUNC getinfo =
        (TSS2_TCTI_INFO_FUNC)dlsym(dl_handle, TSS2_TCTI_INFO_SYMBOL);
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
tcti_dlclose (dl_handle_t *dl_handle_p)
{
    if (dl_handle_p && *dl_handle_p) {
#ifndef DISABLE_DLCLOSE
        dlclose(*dl_handle_p);
#endif
        *dl_handle_p = NULL;
    }
}


/*  Alignment macros used by tcti_buf_alloc */
#define ALIGNMENT_GET_MASK(alignment)   (~((alignment)-1))
#define ALIGN_DOWN(ptr, alignment)  ((ptr) & ALIGNMENT_GET_MASK(alignment))
#define ALIGN_UP(ptr, alignment)    ALIGN_DOWN(((ptr)+(alignment)-1), alignment)
#define TCTI_ALIGNMENT              (sizeof(UINT64))

/*
    Allocate a buffer to store the TCTI context as well as any auxiliary data
    that must be stored with it. Buffer for the TCTI context will be aligned to
    TCTI_ALIGNMENT.

    Allocate a single contiguous buffer. Store the auxiliary data at the start
    of the buffer (AUX region). Store the TCTI context (appropriately aligned)
    at the end of the buffer. Store the offset from the AUX region to the TCTI
    context buffer just above the TCTI context buffer. See layout below:

    --------------------------
    |    AUX buffer     |   ^
    ---------------------   |
    | alignment padding |   | AUX offset
    ---------------------   |
    |  AUX offset value |   v
    --------------------------
    |                   |
    |   TSS2_TCTI_CTX   |
    |                   |
    ---------------------
*/
static TSS2_RC
tcti_buf_alloc (size_t              aux_size,
                size_t              ctx_size,
                void                **aux_buf_p,
                TSS2_TCTI_CONTEXT   **ctx_p)
{
    TSS2_RC r;
    void *aux_buf;
    size_t total_size, offset_offset, aux_offset;
    /*  add space for the AUX region */
    total_size = aux_size;
    /*  add space for the offset (size_t)*/
    total_size += sizeof(size_t);
    /*  add space for padding to TSS2_TCTI_CONTEXT alignment */
    total_size = ALIGN_UP(total_size, TCTI_ALIGNMENT);
    /*  current value of total_size is the offset from the AUX buffer to the
        TSS2_TCTI_CONTEXT buffer */
    aux_offset = total_size;
    /*  AUX offset value is stored right above the TSS2_TCTI_CONTEXT */
    offset_offset = aux_offset - sizeof(size_t);
    /*  add space for the TSS2_TCTI_CONTEXT */
    total_size += ctx_size;
    aux_buf = calloc(1, total_size);
    if (!aux_buf) {
        ERR(tcti_buf_alloc, ERR_R_MALLOC_FAILURE);
        r = TSS2_BASE_RC_MEMORY;
    } else {
        /*  store the AUX offset value right above the TSS2_TCTI_CONTEXT */
        *(size_t*)(aux_buf + offset_offset) = aux_offset;
        *aux_buf_p = aux_buf;
        *ctx_p = (TSS2_TCTI_CONTEXT*)(aux_buf + aux_offset);
        r = TSS2_RC_SUCCESS;
    }
    return r;
}

/*  Given the address of a TCTI context allocated by tcti_buf_alloc, return the
    start address of the AUX rgeion. */
static void*
tcti_buf_get_aux (TSS2_TCTI_CONTEXT *ctx_p)
{
    /*  Dereference the AUX offset value stored right above the
        TSS2_TCTI_CONTEXT. Use the offset to calculate the start address. */
    size_t aux_offset = ((size_t*)ctx_p)[-1];
    return (((void*)ctx_p) - aux_offset);
}

/*
    Given the TCTI library handle and TCTI configuration string, return the
    initialized TCTI context.

    NOTE: cfg may be NULL. ctx_p must be non-NULL. dl_handle must be a valid
    handle that can be passed to dlsym.
*/
static TSS2_RC
__tcti_get_ctx (dl_handle_t         dl_handle,
                const char          *cfg,
                TSS2_TCTI_CONTEXT   **ctx_p)
{
    TSS2_RC r;
    TSS2_TCTI_INIT_FUNC init;
    /*  get the TCTI-initialization function using the library */
    r = tcti_get_init(dl_handle, &init);
    if (TPM2_RC_SUCCESS != r) {
        ERR(__tcti_get_ctx,TPM2TSS_R_GENERAL_FAILURE);
    } else {
        /* get the TCTI-context size */
        TSS2_TCTI_CONTEXT *ctx = NULL;
        size_t ctx_size = 0;
        r = init (ctx,
                  &ctx_size,
                  cfg);
        if (TPM2_RC_SUCCESS != r) {
            ERR(__tcti_get_ctx,TPM2TSS_R_GENERAL_FAILURE);
        } else {
            /*  allocate the buffer to store the TCTI context and AUX data
                (the AUX data is just the dl_handle)*/
            void *aux_buf;
            r = tcti_buf_alloc (sizeof(dl_handle_t),
                                ctx_size,
                                &aux_buf,
                                &ctx);
            if (TPM2_RC_SUCCESS != r) {
                ERR(__tcti_get_ctx,ERR_R_MALLOC_FAILURE);
            } else {
                r = init (ctx,
                          &ctx_size,
                          cfg);
                if (TPM2_RC_SUCCESS != r) {
                    /*  Initialization failed: free the buffer */
                    free(aux_buf);
                    ERR(__tcti_get_ctx,TPM2TSS_R_GENERAL_FAILURE);
                } else {
                    /* populate the dl_handle in the AUX region */
                    dl_handle_t *aux_dl_handle_p = (dl_handle_t*)aux_buf;
                    *aux_dl_handle_p = dl_handle;
                    *ctx_p = ctx;
                }
            }
        }
    }
    return r;
}

/*
    Get opts from environment variables if necessary and parse into
    the TCTI library path and TCTI configuration.

    NOTE: opts may be NULL. path_p and cfg_p are assumed non-NULL.
*/
static TSS2_RC
tcti_get_pathcfg (const char    *opts,
                  char          **path_p,
                  char          **cfg_p)
{
    /*  Valid opts may be one of the following:
        case A: NULL         --> path=NULL,      cfg=NULL
        case B: \0           --> path=\0,        cfg=NULL
        case C: path\0       --> path=path\0,    cfg=NULL
        case D: path:\0      --> path=path\0,    cfg=\0
        case E: path:cfg\0   --> path=path\0,    cfg=cfg\0

        Following opts are invalid (cfg without path. must be explicitly
        handled, because dlopen("") returns handle of main program):
        case F: :\0          --> path=\0,        cfg=\0
        case G: :cfg\0       --> path=\0,        cfg=\0
     */
    TSS2_RC r;
    char *path, *cfg;
    /*  if opts argument is NULL, querry environment*/
    if (!opts) {
        opts = getenv(TPM2TSS_TCTI_ENVVAR);
    }

    if (!opts) {
        /* case A */
        path = NULL;
        cfg = NULL;
        r = TSS2_RC_SUCCESS;
    } else {
        size_t opts_size = strlen(opts) + 1;
        path = (char*)malloc(opts_size);
        if (!path) {
            ERR(tcti_get_pathcfg, ERR_R_MALLOC_FAILURE);
            r = TSS2_BASE_RC_MEMORY;
        } else {
            char *split;
            strncpy (path,
                     opts,
                     opts_size);
            split = strchr(path, (int)':');
            if (!split) {
                /* case  B and case C */
                cfg = NULL;
                r = TSS2_RC_SUCCESS;
            } else {
                if (split==path) {
                    /* case F and case G */
                    ERR(tcti_get_pathcfg, TPM2TSS_R_GENERAL_FAILURE);
                    /* Invalid opts: free the buffer */
                    free(path);
                    r = TSS2_BASE_RC_BAD_REFERENCE;
                } else {
                    /* case D and case E */
                    split[0] = '\0';
                    cfg = split+1;
                    r = TSS2_RC_SUCCESS;
                }
            }
        }
    }
    /*  set output variables on success */
    if (TSS2_RC_SUCCESS == r) {
        *path_p = path;
        *cfg_p = cfg;
    }
    return r;
}

/** get a TCTI context
 *
 * Allocate and initialize a TCTI context based on 'opts' parameter. If opts is
 * NULL, opts is set using an environment variable.
 * @param opts  The TCTI option string.
 * @param ctx_p The TCTI context output variable
 * @retval TSS2_RC_SUCCESS on success or an appropriate TSS2_BASE_RC_ error
 * code on failure.
 */
TSS2_RC
tcti_get_ctx (const char        *opts,
              TSS2_TCTI_CONTEXT **ctx_p)
{
    TSS2_RC r;
    char *path, *cfg;
    if (!ctx_p) {
        ERR(tcti_get_ctx, ERR_R_PASSED_NULL_PARAMETER);
        r = TSS2_TCTI_RC_BAD_REFERENCE;
    } else {
        /*  parse the opts string into path:cfg */
        r = tcti_get_pathcfg (opts,
                              &path,
                              &cfg);
        if (TPM2_RC_SUCCESS != r) {
            ERR(tcti_get_ctx, TPM2TSS_R_GENERAL_FAILURE);
        } else {
            if (!path) {
                *ctx_p = NULL;
            } else {
                /*  open the shared library at path */
                dl_handle_t dl_handle;
                r = tcti_dlopen(path, &dl_handle);
                if (TPM2_RC_SUCCESS != r) {
                    ERR(tcti_get_ctx, TPM2TSS_R_GENERAL_FAILURE);
                } else {
                    /*  allocate and initialize the TCTI context */
                    r = __tcti_get_ctx (dl_handle,
                                        cfg,
                                        ctx_p);
                    if (TPM2_RC_SUCCESS != r) {
                        /*  Initialize failed: close the TCTI library */
                        tcti_dlclose(&dl_handle);
                        ERR(tcti_get_ctx, TPM2TSS_R_GENERAL_FAILURE);
                    }
                }
                /*  path is always non-null and malloced in this branch.
                    Always (success or failure) free the path/cfg strings */
                free(path);
            }
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
tcti_free_ctx (TSS2_TCTI_CONTEXT **ctx_p)
{
    TSS2_RC r;
    if (!ctx_p) {
        ERR(tcti_free_ctx, ERR_R_PASSED_NULL_PARAMETER);
        r = TSS2_BASE_RC_BAD_REFERENCE;
    } else {
        if (*ctx_p) {
            /*  Get the AUX region address */
            void *aux_buf = tcti_buf_get_aux(*ctx_p);
            /*  The dl_handle (void*) is at the start of this buffer */
            void **aux_dl_handle_p = (void**)aux_buf;
            Tss2_Tcti_Finalize(*ctx_p);
            tcti_dlclose(aux_dl_handle_p);
            free(aux_buf);
        }
        r = TSS2_RC_SUCCESS;
    }
    return r;
}

