#ifndef SECUREBOOT_REGISTRY_H
#define SECUREBOOT_REGISTRY_H

#include "common.h"

#define SECUREBOOT_REGISTRY_KEY \
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"

#define SECUREBOOT_REG_VALUE_ENABLED L"UEFISecureBootEnabled"
#define SECUREBOOT_REG_VALUE_CAPABLE L"SecureBootCapable"

NTSTATUS RegistryPatchSecureBootState(VOID);

#endif // SECUREBOOT_REGISTRY_H
