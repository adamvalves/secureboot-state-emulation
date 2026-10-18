#ifndef SECUREBOOT_EMULATION_H
#define SECUREBOOT_EMULATION_H

#include "common.h"
#include "ntdef.h"
#include "registry.h"
#include "sysinfo.h"
#include "efi_variable.h"
#include "memory.h"

NTSTATUS SecureBootEmulationInitialize(VOID);
NTSTATUS SharedUserDataPatch(VOID);

#endif // SECUREBOOT_EMULATION_H
