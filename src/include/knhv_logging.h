#pragma once

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif
extern volatile LONG g_HvVerboseLogging;
#ifdef __cplusplus
}
#endif

#ifndef KNHV_PASSIVE_PRINT
#define KNHV_PASSIVE_PRINT(...)                                                   \
    do {                                                                        \
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {                              \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__);   \
        }                                                                       \
    } while (0)
#endif

#ifndef KNHV_VERBOSE_PRINT
#define KNHV_VERBOSE_PRINT(...)                                                   \
    do {                                                                        \
        if (g_HvVerboseLogging != 0) {                                          \
            KNHV_PASSIVE_PRINT(__VA_ARGS__);                                   \
        }                                                                       \
    } while (0)
#endif
