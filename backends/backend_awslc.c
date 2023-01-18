// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "backend_awslc.h"

/************************************************
 * SHA cipher interface functions
 ************************************************/
static int awslc_get_hash(struct sha_data *data, const EVP_MD **md, int *digest_length)
{
	switch(data->cipher) {
	case ACVP_SHA1:
		*md = EVP_sha1();
		*digest_length = SHA_DIGEST_LENGTH;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

// We're assuming that only SHA1 will be called...
static int awslc_sha_generate(struct sha_data *data, flags_t parsed_flags)
{
	const EVP_MD *md = NULL;
	int mdlen;
	unsigned int maclen;
	int ret;


	(void)parsed_flags;

	CKINT(awslc_get_hash(data, &md, &mdlen));

	maclen = (unsigned int) mdlen;

	CKINT_LOG(alloc_buf((size_t)mdlen, &data->mac),
			"SHA buffer cannot be allocated\n");

	// logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg\n");
	// logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "mac\n");

	CKINT_O_LOG(EVP_Digest(data->msg.buf, data->msg.len, data->mac.buf, &maclen, md, NULL),
		"EVP_Digest() failed\n");

	ret = 0;

out:
	return ret;
}

static struct sha_backend awslc_sha =
{
        awslc_sha_generate,
		NULL
};

ACVP_DEFINE_CONSTRUCTOR(awslc_sha_backend)
static void awslc_sha_backend(void)
{
         register_sha_impl(&awslc_sha);
}
