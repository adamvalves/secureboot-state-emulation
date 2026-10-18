#ifndef SECUREBOOT_COMMON_H
#define SECUREBOOT_COMMON_H

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <stdint.h>

#define SECUREBOOT_TAG 'tBcS'

#define LOG_PREFIX "[SecureBoot] "
#define LOG_INFO(fmt, ...)  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, LOG_PREFIX fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, LOG_PREFIX "[ERROR] " fmt "\n", ##__VA_ARGS__)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#endif // SECUREBOOT_COMMON_H
