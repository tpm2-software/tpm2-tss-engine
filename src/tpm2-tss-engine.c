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
#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

/**
 * The identifier of the engine
 */
static const char *engine_id = "tpm2tss";

/**
 * The full name of the engine
 */
static const char *engine_name = "TPM2-TSS engine for OpenSSL";

TPM2B_DIGEST ownerauth = { .size = 0 };
TPM2B_DIGEST parentauth = { .size = 0 };

char *tcti_nameconf = NULL;

/** Retrieve password
 *
 * Helper function to retreive a password from the user.
 * @param prompt_info [in] The object name to ask the user for
 * @param ui_method [in] The ui method callbacks to be used
 * @param cb_data [in] The callback data for the ui
 * @param auth [out] The user provided password
 * @retval 1 on success
 * @retval 0 on failure
 */
static int
get_auth(const char *prompt_info, UI_METHOD *ui_method, void *cb_data,
         TPM2B_AUTH *auth)
{
    DBG("get_auth called for object %s with ui_method %p\n", prompt_info,
        ui_method);
    char *ui_prompt = NULL;
    UI *ui = NULL;
    if (!ui_method) {
        ERR(get_auth, TPM2TSS_R_UI_ERROR);
        goto error;
    }
    ui = UI_new_method(ui_method);
    if (!ui) {
        ERR(get_auth, TPM2TSS_R_UI_ERROR);
        goto error;
    }
    ui_prompt = UI_construct_prompt(ui, "password", prompt_info);
    if (!ui_prompt) {
        ERR(get_auth, TPM2TSS_R_UI_ERROR);
        goto error;
    }
    if (0 > UI_add_input_string(ui, ui_prompt, UI_INPUT_FLAG_DEFAULT_PWD,
                                (char *)&auth->buffer[0], 0,
                                sizeof(auth->buffer) - 1)) {
        ERR(get_auth, TPM2TSS_R_UI_ERROR);
        goto error;
    }
    UI_add_user_data(ui, cb_data);
    if (0 > UI_process(ui)) {
        ERR(get_auth, TPM2TSS_R_UI_ERROR);
        goto error;
    }
    auth->size = strlen((char *)&auth->buffer[0]);
    OPENSSL_free(ui_prompt);
    UI_free(ui);

    DBG("password is %s\n", (char *)&auth->buffer[0]);

    return 1;
 error:
    if (ui_prompt)
        OPENSSL_free(ui_prompt);
    if (ui)
        UI_free(ui);
    return 0;
}

static const ENGINE_CMD_DEFN cmd_defns[] = {
    { TPM2TSS_SET_OWNERAUTH, "SET_OWNERAUTH",
     "Set the password for the owner hierarchy (default none)",
     ENGINE_CMD_FLAG_STRING },
    { TPM2TSS_SET_TCTI, "SET_TCTI",
     "Set the TCTI module and options (default none)",
     ENGINE_CMD_FLAG_STRING },
    { TPM2TSS_SET_PARENTAUTH, "SET_PARENTAUTH",
     "Set the password for the parent key (default none)",
     ENGINE_CMD_FLAG_STRING },
    {0, NULL, NULL, 0}
};

static int
engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) ())
{
    (void)(e);
    (void)(i);
    (void)(f);
    switch (cmd) {
    case TPM2TSS_SET_OWNERAUTH:
        if (!p) {
            DBG("Setting owner auth to empty auth.\n");
            ownerauth.size = 0;
            return 1;
        }
        DBG("Setting owner auth to password.\n");
        if (strlen((char *)p) > sizeof(ownerauth.buffer) - 1) {
            return 0;
        }
        ownerauth.size = strlen((char *)p);
        memcpy(&ownerauth.buffer[0], p, ownerauth.size);
        return 1;
    case TPM2TSS_SET_TCTI:
        OPENSSL_free(tcti_nameconf);
        if (!p) {
            DBG("Setting TCTI to the ESAPI default\n");
        } else {
            tcti_nameconf = OPENSSL_strdup(p);
            DBG("Setting TCTI option to \"%s\"\n", tcti_nameconf);
        }
        return 1;
    case TPM2TSS_SET_PARENTAUTH:
        if (!p) {
            DBG("Setting parent auth to empty auth.\n");
            parentauth.size = 0;
            return 1;
        }
        DBG("Setting parent auth to password.\n");
        if (strlen((char *)p) > sizeof(parentauth.buffer) - 1) {
            return 0;
        }
        parentauth.size = strlen((char *)p);
        memcpy(&parentauth.buffer[0], p, parentauth.size);
        return 1;
    default:
        break;
    }
    ERR(engine_ctrl, TPM2TSS_R_UNKNOWN_CTRL);
    return 0;
}

/** Load a TPM2TSS key
 *
 * This function implements the prototype for loading a key from a file.
 * @param e The engine for this callback (unused).
 * @param key_id The name of the file with the TPM key data.
 * @param ui The ui functions for querying the user.
 * @param cb_data Callback data.
 */
static EVP_PKEY *
loadkey(ENGINE *e, const char *key_id, UI_METHOD *ui, void *cb_data)
{
    (void)(e);
    (void)(ui);
    (void)(cb_data);

    TPM2_DATA *tpm2Data = NULL;
    EVP_PKEY *pkey = NULL;

    DBG("Loading private key %s\n", key_id);
    if (strncmp(key_id, "0x81", 4) == 0) {
        uint32_t handle;
        sscanf(key_id, "0x%x", &handle);
        if (!tpm2tss_tpm2data_readtpm(handle, &tpm2Data)) {
            ERR(loadkey, TPM2TSS_R_TPM2DATA_READ_FAILED);
            goto error;
        }
    } else {
        if (!tpm2tss_tpm2data_read(key_id, &tpm2Data)) {
            ERR(loadkey, TPM2TSS_R_TPM2DATA_READ_FAILED);
            goto error;
        }
    }

    if (tpm2Data->emptyAuth) {
        tpm2Data->userauth.size = 0;
    } else {
        if (!get_auth("user key", ui, cb_data, &tpm2Data->userauth)) {
            goto error;
        }
    }

    DBG("Loaded key uses alg-id %x\n", tpm2Data->pub.publicArea.type);

    switch (tpm2Data->pub.publicArea.type) {
    case TPM2_ALG_RSA:
        pkey = tpm2tss_rsa_makekey(tpm2Data);
        break;
    case TPM2_ALG_ECC:
        pkey = tpm2tss_ecc_makekey(tpm2Data);
        break;
    default:
        ERR(loadkey, TPM2TSS_R_UNKNOWN_ALG);
        goto error;
    }
    if (!pkey) {
        ERR(loadkey, TPM2TSS_R_CANNOT_MAKE_KEY);
        goto error;
    }

    DBG("TPM2 Key loaded\n");

    return pkey;
error:
    if (tpm2Data)
        OPENSSL_free(tpm2Data);
    return NULL;
}

/** Initialize the tpm2tss engine
 *
 * Initialize the tpm2tss engine by calling each of the submodules' init
 * functions for setting function pointer.
 * @param e The engine context.
 * @retval 1 on success
 * @retval 0 on failure
 */
static int
init_engine(ENGINE *e) {
    static int initialized = 0;

    DBG("Initializing\n");

    if (initialized) {
        DBG("Already initialized\n");
        return 1;
    }

    int rc;

#ifdef ENABLE_TCTIENVVAR
    /*  Set the default TCTI option from the environment */
    OPENSSL_free(tcti_nameconf);
    if (getenv("TPM2TSSENGINE_TCTI")) {
        tcti_nameconf = OPENSSL_strdup(getenv("TPM2TSSENGINE_TCTI"));
    }
#endif

    rc = init_rand(e);
    if (rc != 1) {
        ERR(init_engine, TPM2TSS_R_SUBINIT_FAILED);
        return rc;
    }

    rc = init_rsa(e);
    if (rc != 1) {
        ERR(init_engine, TPM2TSS_R_SUBINIT_FAILED);
        return rc;
    }

    rc = init_ecc(e);
    if (rc != 1) {
        ERR(init_engine, TPM2TSS_R_SUBINIT_FAILED);
        return rc;
    }

    initialized = 1;
    return 1;
}

/** Destroys the engine context
 *
 * Unloads the strings of the tpm2tss engine.
 * @param e The engine context (unused).
 * @retval 1 for success
 */
static int
destroy_engine(ENGINE *e)
{
    (void)(e);
    OPENSSL_free(tcti_nameconf);
    ERR_unload_TPM2TSS_strings();
    return 1;
}

/** OpenSSL's method to bind an engine.
 *
 * This initializes the name, id and function pointers of the engine.
 * @param e The TPM engine to initialize
 * @param id The identifier of the engine
 * @retval 0 if binding failed
 * @retval 1 on success
 */
static int
bind(ENGINE *e, const char *id)
{
    (void)(id);

    if (!ENGINE_set_id(e, engine_id)) {
        DBG("ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_name)) {
        DBG("ENGINE_set_name failed\n");
        goto end;
    }

    /* The init function is not allways called so we initialize crypto methods
       directly from bind. */
    if (!init_engine(e)) {
        DBG("tpm2tss enigne initialization failed\n");
        goto end;
    }

    if (!ENGINE_set_load_privkey_function(e, loadkey)) {
        DBG("ENGINE_set_load_privkey_function failed\n");
        goto end;
    }

    if (!ENGINE_set_destroy_function(e, destroy_engine)) {
        DBG("ENGINE_set_destroy_function failed\n");
        goto end;
    }

    if (!ENGINE_set_ctrl_function(e, engine_ctrl)) {
        DBG("ENGINE_set_ctrl_function failed\n");
        goto end;
    }

    if (!ENGINE_set_cmd_defns(e, cmd_defns)) {
        DBG("ENGINE_set_cmd_defns failed\n");
        goto end;
    }

    ERR_load_TPM2TSS_strings();
    return 1;
 end:
    return 0;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
