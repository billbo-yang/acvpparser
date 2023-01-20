// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include "backend_common.h"
#include <gnutls/crypto.h>

/************************************************
 * SHA cipher interface functions
 ************************************************/

// We're assuming that only SHA1 will be called...
static int gnutls_sha_generate(struct sha_data *data, flags_t parsed_flags)
{
    // We're can assume for now that only SHA1 will be used
    gnutls_hash_hd_t dig;
    unsigned char *buffer;
    size_t outputlen = 20;
    int err = 0;

    (void) parsed_flags;

    alloc_buf(outputlen, &data->mac);

    err = gnutls_hash_init(&dig, GNUTLS_DIG_SHA1);
    if (err) {
        return -1;
    }

    err = gnutls_hash(dig, data->msg.buf, data->msg.len);
    if (err) {
        return -1;
    }

    buffer = (unsigned char*) malloc(outputlen);
    gnutls_hash_output(dig, buffer);
    memcpy(data->mac.buf, buffer, outputlen);

    logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "mac\n");

    gnutls_hash_deinit(dig, buffer);

    return 0;
}

static struct sha_backend gnutls_sha =
{
    gnutls_sha_generate,
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(gnutls_sha_backend)
static void gnutls_sha_backend(void)
{
    register_sha_impl(&gnutls_sha);
}