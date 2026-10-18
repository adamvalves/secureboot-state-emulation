#include "../include/registry.h"

NTSTATUS RegistryPatchSecureBootState(VOID) {
    UNICODE_STRING keyPath;
    RtlInitUnicodeString(&keyPath, SECUREBOOT_REGISTRY_KEY);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(
        &objAttr,
        &keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    HANDLE hKey = NULL;
    ULONG disposition = 0;
    NTSTATUS status = ZwCreateKey(
        &hKey,
        KEY_SET_VALUE | KEY_QUERY_VALUE,
        &objAttr,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        &disposition
    );

    if (!NT_SUCCESS(status)) {
        LOG_ERROR("ZwCreateKey / ZwOpenKey failed for SecureBoot state key (0x%08X)", status);
        return status;
    }

    ULONG enabledValue = 1;
    UNICODE_STRING valEnabledName;
    RtlInitUnicodeString(&valEnabledName, SECUREBOOT_REG_VALUE_ENABLED);

    status = ZwSetValueKey(
        hKey,
        &valEnabledName,
        0,
        REG_DWORD,
        &enabledValue,
        sizeof(enabledValue)
    );

    if (!NT_SUCCESS(status)) {
        LOG_ERROR("ZwSetValueKey failed for %wZ (0x%08X)", &valEnabledName, status);
        ZwClose(hKey);
        return status;
    }

    ULONG capableValue = 1;
    UNICODE_STRING valCapableName;
    RtlInitUnicodeString(&valCapableName, SECUREBOOT_REG_VALUE_CAPABLE);

    status = ZwSetValueKey(
        hKey,
        &valCapableName,
        0,
        REG_DWORD,
        &capableValue,
        sizeof(capableValue)
    );

    if (!NT_SUCCESS(status)) {
        LOG_ERROR("ZwSetValueKey failed for %wZ (0x%08X)", &valCapableName, status);
    } else {
        LOG_INFO("Registry SecureBoot\\State synchronized successfully (UEFISecureBootEnabled=1, SecureBootCapable=1)");
    }

    ZwClose(hKey);
    return status;
}
