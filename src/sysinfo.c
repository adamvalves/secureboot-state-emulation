#include "../include/sysinfo.h"
#include "../include/memory.h"

// Global pointer to the internal ntoskrnl variable controlling SystemSecureBootInformation (class 145)
// Typically resolved as dword_140C5467C or equivalent across Windows 10/11 builds 19041-22631
static volatile ULONG* g_pSecureBootGlobal = NULL;

BOOLEAN SysInfoIsAlreadyPatched(VOID) {
    if (!g_pSecureBootGlobal) {
        return FALSE;
    }

    ULONG currentValue = *g_pSecureBootGlobal;
    return ((currentValue & SECUREBOOT_FLAG_MASK) == SECUREBOOT_FLAG_MASK);
}

NTSTATUS SysInfoPatchInitialize(VOID) {
    ULONG kernelSize = 0;
    PVOID kernelBase = MemoryGetKernelBase(&kernelSize);
    if (!kernelBase || kernelSize == 0) {
        LOG_ERROR("Failed to acquire ntoskrnl base address");
        return STATUS_NOT_FOUND;
    }

    // Pattern 1: Windows 10 / 11 SeSecureBootQueryInformation signature
    // mov ecx, cs:dword_xxx ; test cl, 1 ; ...
    // 8B 0D ?? ?? ?? ?? F6 C1 01
    UCHAR pattern1[] = { 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xF6, 0xC1, 0x01 };
    CHAR mask1[] = "xx????xxx";

    // Pattern 2: Direct bit test against global
    // F6 05 ?? ?? ?? ?? 01 74 ??
    UCHAR pattern2[] = { 0xF6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x74 };
    CHAR mask2[] = "xx????xx";

    // Pattern 3: mov eax, cs:dword_xxx ; a8 01 (test al, 1)
    // 8B 05 ?? ?? ?? ?? A8 01
    UCHAR pattern3[] = { 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x01 };
    CHAR mask3[] = "xx????xx";

    PVOID match = MemoryFindPattern(kernelBase, kernelSize, pattern1, mask1);
    ULONG dispOffset = 2;
    ULONG instrLength = 6;

    if (!match) {
        match = MemoryFindPattern(kernelBase, kernelSize, pattern2, mask2);
        dispOffset = 2;
        instrLength = 7; // F6 05 [disp32] 01
    }

    if (!match) {
        match = MemoryFindPattern(kernelBase, kernelSize, pattern3, mask3);
        dispOffset = 2;
        instrLength = 6; // 8B 05 [disp32]
    }

    if (!match) {
        LOG_ERROR("Failed to locate SeSecureBootQueryInformation global variable signature");
        return STATUS_NOT_FOUND;
    }

    g_pSecureBootGlobal = (volatile ULONG*)MemoryResolveRelativeAddress(match, dispOffset, instrLength);
    if (!g_pSecureBootGlobal) {
        LOG_ERROR("Failed to resolve RIP-relative target for class 145 global");
        return STATUS_UNSUCCESSFUL;
    }

    LOG_INFO("Located SystemSecureBootInformation global variable at %p (current: 0x%08X)",
        g_pSecureBootGlobal, *g_pSecureBootGlobal);

    // Double-load guard: check if bits 0 & 3 are already active
    if (SysInfoIsAlreadyPatched()) {
        LOG_INFO("SystemSecureBootInformation global already contains flags 0x%02X. Skipping re-patch.",
            SECUREBOOT_FLAG_MASK);
        return STATUS_IMAGE_ALREADY_LOADED;
    }

    // Atomic bitwise OR to set bit 0 (SecureBootEnabled) and bit 3 (SecureBootCapable)
    LONG previousValue = InterlockedOr((volatile LONG*)g_pSecureBootGlobal, (LONG)SECUREBOOT_FLAG_MASK);

    LOG_INFO("Patched SystemSecureBootInformation global: previous=0x%08X, updated=0x%08X",
        previousValue, *g_pSecureBootGlobal);

    return STATUS_SUCCESS;
}
