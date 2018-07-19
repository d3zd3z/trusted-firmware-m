/*
 * Copyright (c) 2017-2018, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "sst_asset_management.h"

#include <stddef.h>

#include <stdio.h>
#include "platform/include/tfm_spm_hal.h"
#include "secure_fw/spm/spm_api.h"
#include "jwt.h"

#include "assets/sst_asset_defs.h"
#include "sst_object_system.h"
#include "sst_utils.h"
#include "tfm_secure_api.h"
#include "tfm_sst_defs.h"

/******************************/
/* Asset management functions */
/******************************/

/* Policy database */
extern struct sst_asset_policy_t asset_perms[];
extern struct sst_asset_perm_t asset_perms_modes[];

/**
 * \brief Looks up for policy entry for give app and uuid
 *
 * \param[in] db_entry  Asset specific entry
 * \param[in] app_id    Identify of the application calling the service
 *
 * \return Returns the perms entry on successful lookup
 */
static struct sst_asset_perm_t *sst_am_lookup_app_perms(
                                      const struct sst_asset_policy_t *db_entry,
                                      uint32_t app_id)
{
    struct sst_asset_perm_t *perm_entry;
    uint32_t i;

    for (i = 0; i < db_entry->perms_count; i++) {
        perm_entry = &asset_perms_modes[db_entry->perms_modes_start_idx+i];
        if (perm_entry->app == app_id) {
            return perm_entry;
        }
    }

    return NULL;
}

/**
 * \brief Gets pointer to policy entry for an asset
 *
 * \param[in] uuid  Unique identifier of the object being accessed
 *
 * \return Returns the pointer for entry for specified asset
 */
static struct sst_asset_policy_t *sst_am_lookup_db_entry(uint32_t uuid)
{
    uint32_t i;

    /* Lookup in db for matching entry */
    for (i = 0; i < SST_NUM_ASSETS; i++) {
        if (asset_perms[i].asset_uuid == uuid) {
            return &asset_perms[i];
        }
    }

    return NULL;
}

/**
 * \brief Checks the compile time policy for secure/non-secure separation
 *
 * \param[in] app_id        caller's application ID
 * \param[in] request_type  requested action to perform
 *
 * \return Returns the sanitized request_type
 */
static uint16_t sst_am_check_s_ns_policy(uint32_t app_id, uint16_t request_type)
{
    enum psa_sst_err_t err;
    uint16_t access;

    /* FIXME: based on level 1 tfm isolation, any entity on the secure side
     * can have full access if it uses secure app ID to make the call.
     * When the secure caller passes on the app_id of non-secure entity,
     * the code only allows read by reference. I.e. if the app_id
     * has the reference permission, the secure caller will be allowed
     * to read the entry. This needs a revisit when for higher level
     * of isolation.
     *
     * FIXME: current code allows only a referenced read, however there
     * is a case for refereced create/write/delete as well, for example
     * a NS entity may ask another secure service to derive a key and securely
     * store it, and make references for encryption/decryption and later on
     * delete it.
     * For now it is for the other secure service to create/delete/write
     * resources with the secure app ID.
     */
    err = sst_utils_validate_secure_caller();

    if (err == PSA_SST_ERR_SUCCESS) {
        if (app_id != S_APP_ID) {
            if (request_type & SST_PERM_READ) {
                access = SST_PERM_REFERENCE;
            } else {
                /* Other permissions can not be delegated */
                access = SST_PERM_FORBIDDEN;
            }
        } else {
            /* a call from secure entity on it's own behalf.
             * In level 1 isolation, any secure entity has
             * full access to storage.
             */
            access = SST_PERM_BYPASS;
        }
    } else if (app_id == S_APP_ID) {
        /* non secure caller spoofing as secure caller */
        access = SST_PERM_FORBIDDEN;
    } else {
        access = request_type;
    }
    return access;
}

/**
 * \brief Gets asset's permissions if the application is allowed
 *        based on the request_type
 *
 * \param[in] app_id        Caller's application ID
 * \param[in] uuid          Asset's unique identifier
 * \param[in] request_type  Type of requested access
 *
 * \note If request_type contains multiple permissions, this function
 *       returns the entry pointer for specified asset if at least one
 *       of those permissions match.
 *
 * \return Returns the entry pointer for specified asset
 */
static struct sst_asset_policy_t *sst_am_get_db_entry(uint32_t app_id,
                                                      uint32_t uuid,
                                                      uint8_t request_type)
{
    struct sst_asset_perm_t   *perm_entry;
    struct sst_asset_policy_t *db_entry;

    request_type = sst_am_check_s_ns_policy(app_id, request_type);

    /* security access violation */
    if (request_type == SST_PERM_FORBIDDEN) {
        /* FIXME: this is prone to timing attacks. Ideally the time
         * spent in this function should always be constant irrespective
         * of success or failure of checks. Timing attacks will be
         * addressed in later version.
         */
        return NULL;
    }

    /* Find policy db entry for the the asset */
    db_entry = sst_am_lookup_db_entry(uuid);
    if (db_entry == NULL) {
        return NULL;
    }

    if (request_type == SST_PERM_BYPASS) {
         return db_entry;
     }

    /* Find the app ID entry in the database */
    perm_entry = sst_am_lookup_app_perms(db_entry, app_id);
    if (perm_entry == NULL) {
        return NULL;
    }

     /* Check if the db permission matches with at least one of the
      * requested permissions types.
      */
    if ((perm_entry->perm & request_type) != 0) {
        return db_entry;
    }
    return NULL;
}

/**
 * \brief Validates the policy database's integrity
 *        Stub function.
 *
 * \return Returns value specified in \ref psa_sst_err_t
 */
static enum psa_sst_err_t validate_policy_db(void)
{
    /* Currently the policy database is inbuilt
     * in the code. It's sanity is assumed to be correct.
     * In the later revisions if access policy is
     * stored differently, it may require sanity check
     * as well.
     */
    return PSA_SST_ERR_SUCCESS;
}

enum psa_sst_err_t sst_am_prepare(void)
{
    enum psa_sst_err_t err;
    /* FIXME: outcome of this function should determine
     * state machine of asset manager. If this
     * step fails other APIs shouldn't entertain
     * any user calls. Not a major issue for now
     * as policy db check is a dummy function, and
     * sst core maintains it's own state machine.
     */

    /* Validate policy database */
    err = validate_policy_db();

    /* Initialize underlying storage system */
    if (err != PSA_SST_ERR_SUCCESS) {
        return PSA_SST_ERR_SYSTEM_ERROR;
    }

    err = sst_system_prepare();
#ifdef SST_RAM_FS
    /* in case of RAM based system there wouldn't be
     * any content in the boot time. Call the wipe API
     * to create a storage structure.
     */
    if (err != PSA_SST_ERR_SUCCESS) {
        sst_system_wipe_all();
        /* attempt to initialise again */
        err = sst_system_prepare();
    }
#endif /* SST_RAM_FS */

    return err;
}

/**
 * \brief Validate incoming iovec structure
 *
 * \param[in] src     Incoming iovec for the read/write request
 * \param[in] dest    Pointer to local copy of the iovec
 * \param[in] app_id  Application ID of the caller
 * \param[in] access  Access type to be permormed on the given dest->data
 *                    address
 *
 * \return Returns value specified in \ref psa_sst_err_t
 */
static enum psa_sst_err_t validate_copy_validate_iovec(
                                                const struct tfm_sst_buf_t *src,
                                                struct tfm_sst_buf_t *dest,
                                                uint32_t app_id,
                                                uint32_t access)
{
    /* iovec struct needs to be used as veneers do not allow
     * more than four params.
     * First validate the pointer for iovec itself, then copy
     * the iovec, then validate the local copy of iovec.
     */
    enum psa_sst_err_t bound_check;

    bound_check = sst_utils_bound_check_and_copy((uint8_t *) src,
                      (uint8_t *) dest, sizeof(struct tfm_sst_buf_t), app_id);
    if (bound_check == PSA_SST_ERR_SUCCESS) {
        bound_check = sst_utils_memory_bound_check(dest->data, dest->size,
                                                   app_id, access);
    }

    return bound_check;
}

enum psa_sst_err_t sst_am_get_info(uint32_t app_id, uint32_t asset_uuid,
                                   const struct tfm_sst_token_t *s_token,
                                   struct psa_sst_asset_info_t *info)
{
    enum psa_sst_err_t bound_check;
    struct sst_asset_policy_t *db_entry;
    struct psa_sst_asset_info_t tmp_info;
    enum psa_sst_err_t err;
    uint8_t all_perms = SST_PERM_REFERENCE | SST_PERM_READ | SST_PERM_WRITE;

    bound_check = sst_utils_memory_bound_check(info,
                                               PSA_SST_ASSET_INFO_SIZE,
                                               app_id, TFM_MEMORY_ACCESS_RW);
    if (bound_check != PSA_SST_ERR_SUCCESS) {
        return PSA_SST_ERR_PARAM_ERROR;
    }

    db_entry = sst_am_get_db_entry(app_id, asset_uuid, all_perms);
    if (db_entry == NULL) {
        return PSA_SST_ERR_ASSET_NOT_FOUND;
    }

    err = sst_object_get_info(asset_uuid, s_token, &tmp_info);
    if (err == PSA_SST_ERR_SUCCESS) {
        /* Use tmp_info to not leak information in case the previous function
         * returns and error. It avoids to leak information in case of error.
         * So, copy the tmp_info content into the attrs only if that tmp_info
         * data is valid.
         */
        sst_utils_memcpy(info, &tmp_info, PSA_SST_ASSET_INFO_SIZE);
    }

    return err;
}

enum psa_sst_err_t sst_am_get_attributes(uint32_t app_id, uint32_t asset_uuid,
                                         const struct tfm_sst_token_t *s_token,
                                         struct psa_sst_asset_attrs_t *attrs)
{
    uint8_t all_perms = SST_PERM_REFERENCE | SST_PERM_READ | SST_PERM_WRITE;
    enum psa_sst_err_t bound_check;
    struct sst_asset_policy_t *db_entry;
    enum psa_sst_err_t err;
    struct psa_sst_asset_attrs_t tmp_attrs;

    bound_check = sst_utils_memory_bound_check(attrs,
                                               PSA_SST_ASSET_ATTR_SIZE,
                                               app_id, TFM_MEMORY_ACCESS_RW);
    if (bound_check != PSA_SST_ERR_SUCCESS) {
        return PSA_SST_ERR_PARAM_ERROR;
    }

    db_entry = sst_am_get_db_entry(app_id, asset_uuid, all_perms);
    if (db_entry == NULL) {
        return PSA_SST_ERR_ASSET_NOT_FOUND;
    }

    err = sst_object_get_attributes(asset_uuid, s_token, &tmp_attrs);
    if (err == PSA_SST_ERR_SUCCESS) {
        /* Use tmp_attrs to not leak information incase the previous function
         * returns and error. It avoids to leak information in case of error.
         * So, copy the tmp_attrs content into the attrs only if that tmp_attrs
         * data is valid.
         */
        sst_utils_memcpy(attrs, &tmp_attrs, PSA_SST_ASSET_ATTR_SIZE);
    }

    return err;
}

enum psa_sst_err_t sst_am_set_attributes(uint32_t app_id, uint32_t asset_uuid,
                                      const struct tfm_sst_token_t *s_token,
                                      const struct psa_sst_asset_attrs_t *attrs)
{
    uint8_t all_perms = SST_PERM_REFERENCE | SST_PERM_READ | SST_PERM_WRITE;
    enum psa_sst_err_t bound_check;
    struct sst_asset_policy_t *db_entry;
    enum psa_sst_err_t err;

    bound_check = sst_utils_memory_bound_check((uint8_t *)attrs,
                                               PSA_SST_ASSET_ATTR_SIZE,
                                               app_id, TFM_MEMORY_ACCESS_RO);
    if (bound_check != PSA_SST_ERR_SUCCESS) {
        return PSA_SST_ERR_PARAM_ERROR;
    }

    db_entry = sst_am_get_db_entry(app_id, asset_uuid, all_perms);
    if (db_entry == NULL) {
        return PSA_SST_ERR_ASSET_NOT_FOUND;
    }

    /* FIXME: Validity attributes are not supported in the current service
     *        implementation. It is mandatory to set start and end subattributes
     *        to 0.
     */
    if (attrs->validity.start != 0 || attrs->validity.end != 0) {
        return PSA_SST_ERR_PARAM_ERROR;
    }

    /* FIXME: Check which bit attributes have been changed and check if those
     *        can be modified or not.
     */
    err = sst_object_set_attributes(asset_uuid, s_token, attrs);

    return err;
}

enum psa_sst_err_t sst_am_create(uint32_t app_id, uint32_t asset_uuid,
                                 const struct tfm_sst_token_t *s_token)
{
    enum psa_sst_err_t err;
    struct sst_asset_policy_t *db_entry;

    db_entry = sst_am_get_db_entry(app_id, asset_uuid, SST_PERM_WRITE);
    if (db_entry == NULL) {
        return PSA_SST_ERR_ASSET_NOT_FOUND;
    }

    err = sst_object_create(asset_uuid, s_token, db_entry->type,
                            db_entry->max_size);

    return err;
}

char jwt_test_private_der[] = {
  0x30, 0x82, 0x04, 0xbc, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
  0x04, 0xa6, 0x30, 0x82, 0x04, 0xa2, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01,
  0x01, 0x00, 0xa6, 0x52, 0x98, 0xdf, 0x0e, 0x33, 0xd0, 0x69, 0x62, 0x32,
  0xc4, 0x40, 0x7c, 0xec, 0xbf, 0x9f, 0xa3, 0x35, 0x8a, 0x51, 0xcd, 0xed,
  0x49, 0x99, 0xbe, 0xf8, 0x29, 0x3f, 0xd1, 0xd7, 0xa8, 0xfb, 0xc6, 0x36,
  0x82, 0x45, 0x64, 0xdb, 0x6d, 0x73, 0xef, 0x53, 0xca, 0x02, 0x7e, 0xb0,
  0x91, 0x06, 0xbd, 0xd5, 0x66, 0x4b, 0xea, 0x87, 0x7a, 0x6d, 0x95, 0xa5,
  0x6b, 0x64, 0xb9, 0xd6, 0xc3, 0xdd, 0xb2, 0x5c, 0x03, 0x8b, 0x00, 0x5c,
  0x46, 0x16, 0x8b, 0x86, 0xc8, 0x28, 0x0d, 0xb4, 0xb1, 0x3e, 0xb6, 0x0d,
  0x82, 0x22, 0x97, 0x5b, 0x75, 0x02, 0x00, 0x97, 0xc7, 0x57, 0x4b, 0xa0,
  0x81, 0xfb, 0x2d, 0xc8, 0xbb, 0x81, 0x37, 0xc4, 0x8e, 0xe6, 0x7c, 0x9a,
  0xf9, 0x2d, 0x0c, 0xd4, 0xb8, 0x22, 0xe5, 0x3b, 0xa0, 0xfe, 0xa8, 0x3e,
  0x5e, 0x99, 0x36, 0x57, 0x76, 0x25, 0x7e, 0xfc, 0x89, 0x17, 0x3c, 0x39,
  0xf0, 0x3c, 0x2e, 0xb3, 0x3f, 0x14, 0xf5, 0x23, 0x96, 0x92, 0x42, 0x7b,
  0x1d, 0xd0, 0x0b, 0xb1, 0x44, 0x71, 0x89, 0x3b, 0x44, 0xe5, 0xea, 0xea,
  0x2c, 0x67, 0xbb, 0xd9, 0xe3, 0x9c, 0x8a, 0x1a, 0x83, 0x1e, 0xe9, 0x13,
  0xe3, 0x3c, 0x06, 0xb0, 0xa3, 0x98, 0x9d, 0x2b, 0xa5, 0x84, 0x65, 0xdb,
  0x23, 0x77, 0x59, 0xca, 0x64, 0x76, 0x9d, 0x54, 0x05, 0x57, 0xa7, 0x10,
  0xcb, 0x62, 0xec, 0x7f, 0x39, 0xfc, 0xd7, 0x53, 0x3d, 0x46, 0x2d, 0xec,
  0x11, 0xd1, 0x42, 0x10, 0x6a, 0x73, 0x39, 0x18, 0x10, 0xa0, 0xcf, 0x9b,
  0x88, 0x6f, 0x1e, 0x88, 0x68, 0x8b, 0x3c, 0x30, 0x59, 0x3f, 0x66, 0xb5,
  0x09, 0x65, 0xfc, 0x37, 0xf7, 0x9f, 0x4e, 0xd7, 0x1a, 0xc6, 0x16, 0x64,
  0x67, 0x64, 0x41, 0xc0, 0x90, 0x51, 0xd9, 0xda, 0xf5, 0x25, 0x5c, 0xc0,
  0x62, 0x9f, 0x0d, 0xec, 0x2c, 0xd3, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02,
  0x82, 0x01, 0x00, 0x24, 0xad, 0xf0, 0x82, 0xb8, 0x8a, 0x1a, 0xbb, 0x32,
  0xe9, 0xc9, 0x38, 0x03, 0x94, 0xde, 0x89, 0xa1, 0x1f, 0xac, 0x9a, 0x6f,
  0xd4, 0x95, 0xb7, 0xaf, 0x52, 0xe1, 0x1d, 0xee, 0xf4, 0x25, 0x93, 0x28,
  0xda, 0x5a, 0x8e, 0x5d, 0x38, 0xbb, 0x01, 0xa7, 0x55, 0x0e, 0x26, 0xd0,
  0xb3, 0xb5, 0xb8, 0x0b, 0xe3, 0x65, 0x04, 0xf6, 0xfa, 0xdb, 0xb8, 0x11,
  0x19, 0x82, 0xfe, 0x9a, 0xb1, 0x4f, 0x4e, 0xb4, 0x07, 0xf0, 0xcc, 0x15,
  0xcf, 0x43, 0xb1, 0xb3, 0x21, 0x8d, 0x40, 0xb0, 0x0d, 0x1a, 0x4d, 0x9f,
  0x2e, 0x89, 0x75, 0x81, 0x75, 0xac, 0xef, 0x3d, 0x1c, 0x3b, 0xdc, 0xf7,
  0x93, 0xb5, 0x36, 0xa4, 0x99, 0x31, 0x28, 0xc5, 0x18, 0xb6, 0xff, 0x03,
  0x99, 0xd5, 0xbb, 0xe6, 0xa9, 0x7e, 0xd6, 0x4b, 0x41, 0x84, 0x36, 0xc4,
  0xf9, 0xc4, 0x38, 0xfb, 0xaf, 0xfc, 0x21, 0x36, 0xc9, 0x10, 0x9e, 0x51,
  0x1f, 0xc6, 0xc7, 0x52, 0xee, 0x77, 0x97, 0x64, 0x62, 0x6c, 0xc5, 0x04,
  0x80, 0x50, 0xb6, 0x5a, 0x21, 0x4e, 0x51, 0xb2, 0x91, 0x42, 0xd1, 0xe7,
  0xa1, 0x8e, 0xb6, 0x43, 0x40, 0xff, 0xb2, 0x6f, 0x42, 0x05, 0xd0, 0xdf,
  0x9c, 0xf4, 0x5d, 0x52, 0x6b, 0x02, 0xfb, 0x8e, 0x7e, 0x1b, 0xf3, 0x4c,
  0xe4, 0x64, 0x2b, 0x2c, 0x54, 0x2c, 0x93, 0x77, 0x04, 0x30, 0xa6, 0x5a,
  0x60, 0x7a, 0x40, 0x68, 0x95, 0xf7, 0x69, 0x2e, 0x3a, 0x27, 0xb5, 0x3c,
  0x84, 0x8c, 0xa9, 0xfe, 0x5f, 0xa6, 0x5a, 0x02, 0x8c, 0x01, 0x3d, 0x50,
  0x07, 0x98, 0x21, 0xd0, 0x7c, 0x45, 0xf4, 0x84, 0x13, 0x80, 0x17, 0x93,
  0x8a, 0xcd, 0xfd, 0x00, 0x97, 0xef, 0x85, 0x6f, 0xd9, 0x34, 0x58, 0x61,
  0x9c, 0xfe, 0x5b, 0x0e, 0x81, 0xf2, 0xf5, 0x26, 0xec, 0xd7, 0x73, 0xfd,
  0x46, 0x04, 0xb2, 0xdc, 0xe5, 0xff, 0x29, 0x02, 0x81, 0x81, 0x00, 0xd4,
  0x67, 0xe7, 0x55, 0xea, 0xc1, 0xf6, 0xeb, 0xb8, 0xf4, 0x95, 0x54, 0x58,
  0xc8, 0xa1, 0xbb, 0x87, 0xa1, 0xf5, 0xde, 0x2e, 0x21, 0x84, 0x98, 0xe5,
  0xd6, 0xde, 0x5f, 0xc4, 0x58, 0x6f, 0x32, 0x77, 0x7b, 0x18, 0x22, 0xac,
  0x6b, 0xaa, 0xf5, 0x36, 0xb7, 0xa0, 0x77, 0xd4, 0xa7, 0xad, 0x7c, 0xf4,
  0x1b, 0x3c, 0x0f, 0x58, 0x98, 0xc3, 0xce, 0x8a, 0x58, 0x8d, 0xae, 0x53,
  0xe9, 0xdd, 0xf9, 0x59, 0x3b, 0x1f, 0x92, 0x77, 0x2a, 0xbf, 0xf9, 0x26,
  0xb6, 0xeb, 0x8e, 0x2d, 0x09, 0x4e, 0x40, 0x05, 0xb6, 0xa0, 0x80, 0x32,
  0x1c, 0x33, 0x20, 0xd8, 0xe8, 0xcf, 0xa2, 0x9f, 0x36, 0xe4, 0xdf, 0x19,
  0xf5, 0x9c, 0xbf, 0x72, 0x61, 0x67, 0xc6, 0x89, 0xe9, 0x31, 0x32, 0xaa,
  0x45, 0xed, 0xb9, 0x2d, 0xc4, 0xa9, 0xb4, 0xc2, 0x80, 0x8f, 0xbb, 0xb2,
  0x23, 0x85, 0x2d, 0x2e, 0x50, 0x40, 0x5d, 0x02, 0x81, 0x81, 0x00, 0xc8,
  0x75, 0x6a, 0xd9, 0x29, 0xc8, 0xe3, 0x4e, 0xdf, 0xf0, 0x90, 0xb4, 0xb9,
  0x5f, 0x12, 0x84, 0xde, 0x9c, 0xd2, 0x91, 0xda, 0x30, 0x6a, 0x9a, 0xbc,
  0x12, 0xdb, 0x1d, 0x73, 0xea, 0x0c, 0x65, 0xfb, 0x60, 0x2e, 0xc3, 0xac,
  0x4d, 0x76, 0x00, 0x04, 0xdf, 0xd1, 0x5d, 0x03, 0xed, 0xef, 0x77, 0x76,
  0x25, 0xd6, 0xba, 0x8d, 0xe0, 0xf7, 0x54, 0xa3, 0x2b, 0x39, 0xfa, 0x01,
  0x52, 0xaa, 0x95, 0xb7, 0xc8, 0x61, 0x7e, 0x58, 0x17, 0xce, 0x2b, 0x6c,
  0x62, 0xbd, 0x0a, 0x27, 0x39, 0x94, 0x03, 0x92, 0xc7, 0xc4, 0x73, 0x8e,
  0xf9, 0x87, 0x8c, 0x92, 0xeb, 0x6a, 0xc5, 0x66, 0x66, 0xd3, 0xab, 0x24,
  0x56, 0xae, 0x35, 0x4f, 0x2c, 0xd6, 0x7e, 0xe3, 0x98, 0x9f, 0x74, 0xbe,
  0xb0, 0x40, 0x19, 0xfa, 0x9e, 0x95, 0x2b, 0x5c, 0x5c, 0x88, 0x5c, 0xd8,
  0xee, 0x57, 0xe9, 0x67, 0xb7, 0x0e, 0xef, 0x02, 0x81, 0x80, 0x24, 0xdb,
  0x52, 0xbd, 0x09, 0xdb, 0x56, 0x69, 0x58, 0xd2, 0xb8, 0x06, 0xc6, 0xd1,
  0x29, 0x9f, 0x4c, 0xcd, 0xc1, 0xc8, 0x27, 0xe1, 0x11, 0x0d, 0x26, 0xf4,
  0xbd, 0xe9, 0x88, 0x3c, 0x80, 0x2f, 0x15, 0xa4, 0x7a, 0x6f, 0xa9, 0xd3,
  0x94, 0xfa, 0xaf, 0xdf, 0xf5, 0x2c, 0x55, 0xee, 0x32, 0xa0, 0x78, 0x0b,
  0x31, 0xc4, 0xc7, 0xee, 0xda, 0x2b, 0x40, 0xbe, 0x54, 0xf7, 0x67, 0x00,
  0x31, 0xd0, 0x4e, 0xb7, 0x7f, 0xa6, 0xfe, 0x9e, 0xa0, 0x69, 0x2f, 0x5a,
  0x96, 0x4d, 0x39, 0x6b, 0x5f, 0xf4, 0xa4, 0x09, 0x28, 0x98, 0x96, 0x19,
  0x66, 0x95, 0xd0, 0x8d, 0xb5, 0x59, 0xd6, 0x9e, 0xc3, 0xe0, 0x22, 0xb5,
  0x07, 0xda, 0x00, 0x92, 0xfe, 0x5a, 0xe9, 0x1b, 0x59, 0xba, 0x1c, 0xe9,
  0xbd, 0x72, 0x60, 0x8a, 0xbb, 0x97, 0xee, 0x18, 0x38, 0xd8, 0xac, 0xf4,
  0x94, 0xeb, 0x5e, 0x19, 0xf6, 0xd1, 0x02, 0x81, 0x80, 0x5c, 0xcd, 0xe7,
  0x72, 0xb4, 0xa2, 0x99, 0x81, 0xd9, 0xb1, 0x60, 0xfd, 0x1a, 0x59, 0x06,
  0x94, 0xd7, 0x0f, 0x19, 0x79, 0x86, 0xdf, 0x25, 0x6b, 0x8f, 0xa8, 0xd7,
  0x22, 0x92, 0x98, 0x87, 0xb6, 0xeb, 0x23, 0x03, 0x63, 0x79, 0xb0, 0xbe,
  0xf1, 0x91, 0x50, 0x21, 0x78, 0x83, 0xaa, 0x33, 0x54, 0x46, 0x31, 0x8c,
  0x70, 0xff, 0xe0, 0x68, 0x01, 0x1a, 0x2d, 0x98, 0x00, 0xc3, 0x7e, 0x07,
  0x15, 0x9b, 0x69, 0x3c, 0xa1, 0xa6, 0x9d, 0x16, 0xc9, 0x09, 0xbb, 0xc8,
  0xb3, 0x1b, 0xa7, 0xcf, 0x7b, 0xbc, 0x07, 0x9a, 0x4e, 0xb9, 0xa1, 0x92,
  0x7c, 0xa5, 0x44, 0x32, 0x41, 0x43, 0x80, 0x55, 0x7c, 0x85, 0x2d, 0x50,
  0x27, 0xc4, 0x09, 0x09, 0x20, 0xe3, 0xb3, 0xb4, 0x16, 0xf3, 0x75, 0x5b,
  0xa7, 0xeb, 0x5c, 0x61, 0xc9, 0x1a, 0x50, 0x88, 0x9d, 0x1b, 0x9d, 0x74,
  0xbb, 0xcd, 0x55, 0x75, 0xa7, 0x02, 0x81, 0x80, 0x68, 0xd9, 0xc8, 0xa8,
  0x90, 0x90, 0xfe, 0x45, 0x8c, 0x5f, 0xb9, 0x4d, 0x1d, 0x86, 0x02, 0x21,
  0xe9, 0x23, 0x07, 0xf6, 0xaa, 0xab, 0x6c, 0xb6, 0x79, 0xf2, 0xf6, 0x53,
  0xa5, 0xee, 0x88, 0x4f, 0x48, 0x6e, 0xf4, 0x64, 0x50, 0x60, 0xe1, 0x8c,
  0x3b, 0x7d, 0xa0, 0x2b, 0x57, 0x72, 0x1a, 0xb7, 0x54, 0xd7, 0x9b, 0x0d,
  0x14, 0xa4, 0x11, 0x01, 0xfa, 0x16, 0xbd, 0x7b, 0x3b, 0xb0, 0xad, 0x66,
  0x82, 0x81, 0xef, 0x4d, 0xed, 0x28, 0x38, 0xeb, 0x19, 0x58, 0xf2, 0xc1,
  0x50, 0x12, 0x9c, 0x62, 0x36, 0x0a, 0x47, 0x4b, 0x45, 0x48, 0x2f, 0x22,
  0xf4, 0xb4, 0x32, 0xab, 0x0f, 0x64, 0x39, 0x32, 0xb4, 0x5a, 0x73, 0x99,
  0xd5, 0x53, 0x28, 0x77, 0x8b, 0x3f, 0x10, 0xdf, 0x51, 0x29, 0x15, 0xb1,
  0x49, 0x04, 0x64, 0xb3, 0xad, 0xe5, 0x6e, 0xc9, 0x29, 0xdd, 0x84, 0x3c,
  0x47, 0x41, 0x92, 0xb0
};
unsigned int jwt_test_private_der_len = 1216;

enum psa_sst_err_t sst_jwt_sign(uint32_t app_id, uint32_t asset_uuid,
                                const struct tfm_sst_token_t *s_token,
                               struct tfm_sst_jwt_t *data)
{
    enum psa_sst_err_t err = PSA_SST_ERR_SUCCESS;

	char buf[460];
	struct jwt_builder build;

    printf("fun %s() from secure \r\n", __func__);
    printf("Param Buffer %s, Size %x\r\n", data->buffer, data->buffer_size);
	int res = jwt_init_builder(&build, buf, sizeof(buf));
//	zassert_equal(res, 0, "Setting up jwt");

	res = jwt_add_payload(&build, 1530312026, 1530308426, "iot-work-199419");
//	zassert_equal(res, 0, "Adding payload");

	res = jwt_sign(&build, jwt_test_private_der, jwt_test_private_der_len);
//	zassert_equal(res, 0, "Signing payload");

//	zassert_equal(build.overflowed, false, "Not overflow");

    #endif

    return err;
}
enum psa_sst_err_t sst_am_read(uint32_t app_id, uint32_t asset_uuid,
                               const struct tfm_sst_token_t *s_token,
                               struct tfm_sst_buf_t *data)
{
    struct tfm_sst_buf_t local_data;
    enum psa_sst_err_t err;
    struct sst_asset_policy_t *db_entry;

    /* Check application ID permissions */
    db_entry = sst_am_get_db_entry(app_id, asset_uuid, SST_PERM_READ);
    if (db_entry == NULL) {
        return PSA_SST_ERR_ASSET_NOT_FOUND;
    }

    /* Make a local copy of the iovec data structure */
    err = validate_copy_validate_iovec(data, &local_data,
                                       app_id, TFM_MEMORY_ACCESS_RW);
    if (err != PSA_SST_ERR_SUCCESS) {
        return PSA_SST_ERR_ASSET_NOT_FOUND;
    }

#ifndef SST_ENABLE_PARTIAL_ASSET_RW
    if (data->offset != 0) {
        return PSA_SST_ERR_PARAM_ERROR;
    }
#endif

    err = sst_object_read(asset_uuid, s_token, local_data.data,
                          local_data.offset, local_data.size);

    return err;
}

enum psa_sst_err_t sst_am_write(uint32_t app_id, uint32_t asset_uuid,
                                const struct tfm_sst_token_t *s_token,
                                const struct tfm_sst_buf_t *data)
{
    struct tfm_sst_buf_t local_data;
    enum psa_sst_err_t err;
    struct sst_asset_policy_t *db_entry;

    /* Check application ID permissions */
    db_entry = sst_am_get_db_entry(app_id, asset_uuid, SST_PERM_WRITE);
    if (db_entry == NULL) {
        return PSA_SST_ERR_ASSET_NOT_FOUND;
    }

    /* Make a local copy of the iovec data structure */
    err = validate_copy_validate_iovec(data, &local_data,
                                       app_id, TFM_MEMORY_ACCESS_RO);
    if (err != PSA_SST_ERR_SUCCESS) {
        return PSA_SST_ERR_ASSET_NOT_FOUND;
    }

    /* Boundary check the incoming request */
    err = sst_utils_check_contained_in(0, db_entry->max_size,
                                       local_data.offset, local_data.size);

    if (err != PSA_SST_ERR_SUCCESS) {
        return err;
    }

#ifndef SST_ENABLE_PARTIAL_ASSET_RW
    if (data->offset != 0) {
        return PSA_SST_ERR_PARAM_ERROR;
    }
#endif

    err = sst_object_write(asset_uuid, s_token, local_data.data,
                           local_data.offset, local_data.size);

    return err;
}

enum psa_sst_err_t sst_am_delete(uint32_t app_id, uint32_t asset_uuid,
                                 const struct tfm_sst_token_t *s_token)
{
    enum psa_sst_err_t err;
    struct sst_asset_policy_t *db_entry;

    db_entry = sst_am_get_db_entry(app_id, asset_uuid, SST_PERM_WRITE);
    if (db_entry == NULL) {
        return PSA_SST_ERR_ASSET_NOT_FOUND;
    }

    err = sst_object_delete(asset_uuid, s_token);

    return err;
}
