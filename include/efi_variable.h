#ifndef SECUREBOOT_EFI_VARIABLE_H
#define SECUREBOOT_EFI_VARIABLE_H

#include "common.h"

#define EFI_VARIABLE_NON_VOLATILE                          0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                    0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS                        0x00000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD                 0x00000008
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS            0x00000010
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x00000020
#define EFI_VARIABLE_APPEND_WRITE                          0x00000040

#define EFI_SECUREBOOT_STANDARD_ATTRIBUTES \
    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS)

// {8BE4DF61-93CA-11d2-AA0D-00E098032B8C}
static const GUID EFI_GLOBAL_VARIABLE_GUID = {
    0x8BE4DF61, 0x93CA, 0x11d2,
    { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C }
};

// {F04EE0D0-689C-49E5-8021-968B7D4197D9}
static const GUID EFI_CUSTOM_SECURE_BOOT_GUID = {
    0xF04EE0D0, 0x689C, 0x49E5,
    { 0x80, 0x21, 0x96, 0x8B, 0x7D, 0x41, 0x97, 0xD9 }
};

typedef NTSTATUS(NTAPI* PFN_NtQuerySystemEnvironmentValueEx)(
    _In_ PUNICODE_STRING VariableName,
    _In_ LPGUID VendorGuid,
    _Out_writes_bytes_to_opt_(*ValueLength, *ValueLength) PVOID Value,
    _Inout_ PULONG ValueLength,
    _Out_opt_ PULONG Attributes
);

typedef struct _EFI_VARIABLE_ENTRY {
    const WCHAR* VariableName;
    const GUID*  VendorGuid;
    UINT8        EmulatedValue;
    ULONG        Attributes;
} EFI_VARIABLE_ENTRY, *PEFI_VARIABLE_ENTRY;

NTSTATUS EfiHookInitialize(VOID);
VOID EfiHookRemove(VOID);
BOOLEAN EfiHookIsAlreadyInstalled(PVOID TargetRoutine);

#endif // SECUREBOOT_EFI_VARIABLE_H
