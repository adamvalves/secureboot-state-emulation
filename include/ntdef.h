#ifndef SECUREBOOT_NTDEF_H
#define SECUREBOOT_NTDEF_H

#include "common.h"

#define KUSER_SHARED_DATA_KERNEL_ADDRESS 0xFFFFF78000000000ULL
#define KUSER_SHARED_DATA_USER_ADDRESS   0x000000007FFE0000ULL
#define KUSER_SHARED_DATA_SECUREBOOT_OFFSET 0x2EC

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation                = 0,
    SystemModuleInformation               = 11,
    SystemCodeIntegrityInformation        = 103,
    SystemSecureBootInformation           = 145
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

#endif // SECUREBOOT_NTDEF_H
