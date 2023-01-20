// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include "backend_common.h"
#include "gcrypt.h"

/************************************************
 * SHA cipher interface functions
 ************************************************/

// We're assuming that only SHA1 will be called...
static int libgcrypt_sha_generate(struct sha_data *data, flags_t parsed_flags)
{
    gcry_error_t err = 0;
	gcry_md_hd_t hd;
    unsigned char *buffer;
    size_t outputlen = 20;

    (void)parsed_flags;

    alloc_buf(outputlen, &data->mac);
    
    gcry_md_open(&hd, GCRY_MD_SHA1, 0);
    if (err) {
        return -1;
    }

    gcry_md_write(hd, data->msg.buf, data->msg.len);

    // Due to the how libgcrypt and the parser each work we need to memcpy the data from the buffer into the data object or else we get invalid pointer error when freeing
    buffer = gcry_md_read(hd, GCRY_MD_SHA1);
    memcpy(data->mac.buf, buffer, outputlen);

    logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "mac\n");

    gcry_md_close(hd);

    return 0;
}

static struct sha_backend libgcrypt_sha =
{
    libgcrypt_sha_generate,
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(libgcrypt_sha_backend)
static void libgcrypt_sha_backend(void)
{
    register_sha_impl(&libgcrypt_sha);
}
