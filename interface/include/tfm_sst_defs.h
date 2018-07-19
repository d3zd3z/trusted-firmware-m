/*
 * Copyright (c) 2017-2018, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __TFM_SST_DEFS_H__
#define __TFM_SST_DEFS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <limits.h>
#include "psa_sst_api.h"

/*!
 * \struct tfm_sst_token_t
 *
 * \brief Structure to store the asset's token.
 *
 */
struct tfm_sst_token_t {
    const uint8_t  *token;  /*!< Pointer to the asset's token to be used to
                             *   generate the asset key to encrypt and decrypt
                             *   the asset data. This is an optional parameter
                             *   that has to be NULL in case the token is not
                             *   provied.
                             */
    uint32_t token_size;    /*!< Token size. In case the token is not provided
                             *   the token size has to be 0.
                             */
};

/*!
 * \struct tfm_sst_buf_t
 *
 * \brief Structure to store data information to read/write from/to asset.
 *
 */
struct tfm_sst_buf_t {
    uint8_t *data;   /*!< Address of input/output data */
    uint32_t size;   /*!< Size of input/output data */
    uint32_t offset; /*!< Offset within asset */
};

struct tfm_sst_jwt_t {
    char *buffer;        /* Buffer to write result, in NS memory. */
    uint32_t out_size;  /* Function will write bytes used here. */
    uint32_t buffer_size;/* Available bytes in the buffer. */
    int32_t iat;         /* The current time. */
    int32_t exp;         /* The expiration time. */
    char *aud;     /* A string that is part of the token (audience) */
    uint32_t aud_len;    /* Length of audience string. */
};

#ifdef __cplusplus
}
#endif

#endif /* __TFM_SST_DEFS_H__ */
