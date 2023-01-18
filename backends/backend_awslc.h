// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#ifndef _BACKEND_AWSLC_H
#define _BACKEND_AWSLC_H

#ifdef __cplusplus
extern "C"
{
#endif

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "openssl/digest.h"
#include "openssl/sha.h"
#include "openssl/err.h"

#include "logger.h"

#include "backend_common.h"

#define CKINT_O(x) {							\
	ret = x;							\
	if (ret != 1) {							\
		ret = -EFAULT;						\
		goto out;						\
	}								\
}

#define CKINT_O0(x) {							\
	ret = x;							\
	if (ret == 0) {							\
		ret = -EFAULT;						\
		goto out;						\
	}								\
}

#define CKINT_O_LOG(x, ...) {						\
	ret = x;							\
	if (ret != 1) {							\
		ret = -EFAULT;						\
		logger(LOGGER_ERR,  __VA_ARGS__);			\
		goto out;						\
	}								\
}

#ifdef __cplusplus
}
#endif

#endif /* _BACKEND_AWSLC_H */
