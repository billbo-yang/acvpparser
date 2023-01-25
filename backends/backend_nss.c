// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include "backend_common.h"

/* NSPR Headers */
#include <prprf.h>
#include <prtypes.h>
#include <plgetopt.h>
#include <prio.h>

/* NSS headers */
#include <secoid.h>
#include <secmodt.h>
#include <sechash.h>
#include <nss.h>

/************************************************
 * SHA cipher interface functions
 ************************************************/
static int nss_sha_generate(struct sha_data *data, flags_t parsed_flags)
{
    unsigned char *buffer;
    unsigned int len;
    size_t outputlen = 20;
    HASHContext *hashContext = NULL;

	(void)parsed_flags;

	if (data->cipher != ACVP_SHA1)
		return -EOPNOTSUPP;

    alloc_buf(outputlen, &data->mac);
    buffer = (unsigned char*) malloc(outputlen);

    NSS_NoDB_Init("/tmp");

    hashContext = HASH_Create(HASH_AlgSHA1);
    if (hashContext == NULL) {
        logger(LOGGER_DEBUG, "died, breaking\n");
        return SECFailure;
    }

    HASH_Begin(hashContext);
    HASH_Update(hashContext, data->msg.buf, data->msg.len);
    HASH_End(hashContext, buffer, &len, outputlen);
    memcpy(data->mac.buf, buffer, outputlen);

    logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "mac\n");

    HASH_Destroy(hashContext);

    NSS_Shutdown();

	return 0;
}

static struct sha_backend nss_sha =
{
	nss_sha_generate,   /* hash_generate */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(nss_sha_backend)
static void nss_sha_backend(void)
{
	register_sha_impl(&nss_sha);
}