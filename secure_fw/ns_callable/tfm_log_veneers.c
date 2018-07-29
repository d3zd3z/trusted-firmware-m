/*
 * Copyright (c) 2018, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "tfm_log_veneers.h"
#include "secure_fw/services/audit_logging/log_core.h"
#include "tfm_secure_api.h"
#include "tfm_api.h"
#include "spm_partition_defs.h"

__tfm_secure_gateway_attributes__
enum tfm_log_err tfm_log_veneer_retrieve(uint32_t size,
                                         int32_t start,
                                         uint8_t *buffer,
                                         struct tfm_log_info *info)
{
    return TFM_LOG_ERR_SUCCESS;
}

__tfm_secure_gateway_attributes__
enum tfm_log_err tfm_log_veneer_add_line(struct tfm_log_line *line)
{
    return TFM_LOG_ERR_SUCCESS;
}

__tfm_secure_gateway_attributes__
enum tfm_log_err tfm_log_veneer_get_info(struct tfm_log_info *info)
{
    return TFM_LOG_ERR_SUCCESS;
}

__tfm_secure_gateway_attributes__
enum tfm_log_err tfm_log_veneer_delete_items(uint32_t num_items,
                                             uint32_t *rem_items)
{
    return TFM_LOG_ERR_SUCCESS;
}
