#include "../include/memory.h"
#include "../include/ntdef.h"

PVOID MemoryGetKernelBase(OUT PULONG ImageSize OPTIONAL) {
    ULONG neededSize = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &neededSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH || neededSize == 0) {
        LOG_ERROR("Failed to query system module information size (0x%08X)", status);
        return NULL;
    }

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePool2(
        POOL_FLAG_PAGED,
        neededSize,
        SECUREBOOT_TAG
    );
    if (!modules) {
        LOG_ERROR("Failed to allocate pool for system module information");
        return NULL;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, modules, neededSize, &neededSize);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("Failed to query system module information (0x%08X)", status);
        ExFreePoolWithTag(modules, SECUREBOOT_TAG);
        return NULL;
    }

    PVOID kernelBase = NULL;
    if (modules->NumberOfModules > 0) {
        kernelBase = modules->Modules[0].ImageBase;
        if (ImageSize) {
            *ImageSize = modules->Modules[0].ImageSize;
        }
    }

    ExFreePoolWithTag(modules, SECUREBOOT_TAG);
    return kernelBase;
}

PVOID MemoryFindPattern(
    _In_ PVOID BaseAddress,
    _In_ ULONG Size,
    _In_ PCUCHAR Pattern,
    _In_ PCSTR Mask
) {
    if (!BaseAddress || !Pattern || !Mask || Size == 0) {
        return NULL;
    }

    SIZE_T maskLength = strlen(Mask);
    if (maskLength == 0 || Size < maskLength) {
        return NULL;
    }

    PUCHAR current = (PUCHAR)BaseAddress;
    PUCHAR end = current + (Size - maskLength);

    for (; current <= end; ++current) {
        BOOLEAN found = TRUE;
        for (SIZE_T i = 0; i < maskLength; ++i) {
            if (Mask[i] != '?' && Pattern[i] != current[i]) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            return (PVOID)current;
        }
    }

    return NULL;
}

PVOID MemoryResolveRelativeAddress(
    _In_ PVOID InstructionAddress,
    _In_ ULONG OffsetToDisplacement,
    _In_ ULONG InstructionLength
) {
    if (!InstructionAddress) {
        return NULL;
    }

    PUCHAR displacementAddr = (PUCHAR)InstructionAddress + OffsetToDisplacement;
    INT32 displacement = *(INT32*)displacementAddr;

    return (PVOID)((PUCHAR)InstructionAddress + InstructionLength + displacement);
}

NTSTATUS MemoryWriteProtectedBytes(
    _In_ PVOID Destination,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length
) {
    if (!Destination || !Source || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PMDL mdl = IoAllocateMdl(Destination, (ULONG)Length, FALSE, FALSE, NULL);
    if (!mdl) {
        LOG_ERROR("IoAllocateMdl failed for target %p", Destination);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("MmProbeAndLockPages raised exception for target %p", Destination);
        IoFreeMdl(mdl);
        return GetExceptionCode();
    }

    PVOID mappedAddress = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmCached,
        NULL,
        FALSE,
        NormalPagePriority
    );

    if (!mappedAddress) {
        LOG_ERROR("MmMapLockedPagesSpecifyCache failed");
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_NONE_MAPPED;
    }

    NTSTATUS protectStatus = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(protectStatus)) {
        LOG_ERROR("MmProtectMdlSystemAddress failed (0x%08X)", protectStatus);
        MmUnmapLockedPages(mappedAddress, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return protectStatus;
    }

    RtlCopyMemory(mappedAddress, Source, Length);

    MmUnmapLockedPages(mappedAddress, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    return STATUS_SUCCESS;
}
