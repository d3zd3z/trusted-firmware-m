/*
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __SECURE_UTILITIES_H__
#define __SECURE_UTILITIES_H__

#include "cmsis_compiler.h"
#include "tfm_svc.h"

#define EXC_RETURN_INDICATOR                    (0xF << 28)
#define EXC_RETURN_SECURITY_STACK_STATUS_MASK   (0x3 << 5)
#define EXC_RETURN_SECURE_STACK                 (1 << 6)
#define EXC_RETURN_FPU_FRAME_BASIC              (1 << 4)
#define EXC_RETURN_MODE_THREAD                  (1 << 3)
#define EXC_RETURN_STACK_PROCESS                (1 << 2)
#define EXC_RETURN_EXC_SECURE                   (1)

#define EXC_NUM_THREAD_MODE     (0)
#define EXC_NUM_SVCALL          (11)
#define EXC_NUM_PENDSV          (14)
#define EXC_NUM_SYSTICK         (15)

#ifdef TFM_CORE_DEBUG
#define LOG_MSG_HDLR(MSG) printf("[Sec Handler] %s\r\n", MSG)
#else
/* FixMe: redirect to secure log area */
#define LOG_MSG_HDLR(MSG) printf("[Sec Handler] %s\r\n", MSG)
#endif

#define LOG_MSG_THR(MSG) \
            __ASM("MOV r0, %0\n" \
                  "SVC %1\n" \
                  : : "r" (MSG), "I" (TFM_SVC_PRINT))

#define LOG_MSG(MSG) \
            do { \
                if (__get_active_exc_num()) { \
                    LOG_MSG_HDLR(MSG); \
                } else { \
                    LOG_MSG_THR(MSG); \
                } \
            } while (0)

#ifdef TFM_CORE_DEBUG
#define ERROR_MSG(MSG) printf("[Sec Error] %s\r\n", MSG)
#else
/* FixMe: redirect to secure log area */
#define ERROR_MSG(MSG) printf("[Sec Error] %s\r\n", MSG)
#endif

/**
 * \brief Get Link Register
 * \details Returns the value of the Link Register (LR)
 * \return LR value
 */

__attribute__ ((always_inline)) __STATIC_INLINE uint32_t __get_LR(void)
{
    register uint32_t result;

    __ASM volatile ("MOV %0, LR\n" : "=r" (result));
    return result;
}

__attribute__ ((always_inline))
__STATIC_INLINE uint32_t __get_active_exc_num(void)
{
    IPSR_Type IPSR;

    /* if non-zero, exception is active. NOT banked S/NS */
    IPSR.w = __get_IPSR();
    return IPSR.b.ISR;
}

__attribute__ ((always_inline))
__STATIC_INLINE void __set_CONTROL_SPSEL(int32_t SPSEL)
{
    CONTROL_Type ctrl;

    ctrl.w = __get_CONTROL();
    ctrl.b.SPSEL = SPSEL;
    __set_CONTROL(ctrl.w);
    __asm("ISB");
}

#endif /* __SECURE_UTILITIES_H__ */
