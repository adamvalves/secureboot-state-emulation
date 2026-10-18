#include "../include/efi_variable.h"
#include "../include/memory.h"

#define DETOUR_SIZE sizeof(JMP_ABSOLUTE_RAX) // 12 bytes

static PFN_NtQuerySystemEnvironmentValueEx g_OriginalNtQuerySystemEnvironmentValueEx = NULL;
static PVOID g_TargetFunction = NULL;
static PUCHAR g_TrampolineBuffer = NULL;

static const EFI_VARIABLE_ENTRY g_EfiVariableTable[] = {
    { L"SecureBoot",       &EFI_GLOBAL_VARIABLE_GUID,    1, EFI_SECUREBOOT_STANDARD_ATTRIBUTES },
    { L"SetupMode",        &EFI_GLOBAL_VARIABLE_GUID,    0, EFI_SECUREBOOT_STANDARD_ATTRIBUTES },
    { L"AuditMode",        &EFI_GLOBAL_VARIABLE_GUID,    0, EFI_SECUREBOOT_STANDARD_ATTRIBUTES },
    { L"DeployedMode",     &EFI_GLOBAL_VARIABLE_GUID,    1, EFI_SECUREBOOT_STANDARD_ATTRIBUTES },
    { L"SecureBootEnable", &EFI_CUSTOM_SECURE_BOOT_GUID, 1, EFI_SECUREBOOT_STANDARD_ATTRIBUTES },
};

BOOLEAN EfiHookIsAlreadyInstalled(PVOID TargetRoutine) {
    if (!TargetRoutine) {
        return FALSE;
    }

    PUCHAR bytes = (PUCHAR)TargetRoutine;
    // Detour starts with 0x48 0xB8 (mov rax, <64-bit target>)
    return (bytes[0] == 0x48 && bytes[1] == 0xB8);
}

static BOOLEAN GuidEquals(const GUID* g1, const GUID* g2) {
    if (!g1 || !g2) {
        return FALSE;
    }
    return (RtlCompareMemory(g1, g2, sizeof(GUID)) == sizeof(GUID));
}

NTSTATUS NTAPI HookedNtQuerySystemEnvironmentValueEx(
    _In_ PUNICODE_STRING VariableName,
    _In_ LPGUID VendorGuid,
    _Out_writes_bytes_to_opt_(*ValueLength, *ValueLength) PVOID Value,
    _Inout_ PULONG ValueLength,
    _Out_opt_ PULONG Attributes
) {
    if (VariableName && VariableName->Buffer && VendorGuid && ValueLength) {
        for (SIZE_T i = 0; i < sizeof(g_EfiVariableTable) / sizeof(g_EfiVariableTable[0]); ++i) {
            const EFI_VARIABLE_ENTRY* entry = &g_EfiVariableTable[i];

            UNICODE_STRING entryName;
            RtlInitUnicodeString(&entryName, entry->VariableName);

            if (RtlEqualUnicodeString(VariableName, &entryName, TRUE) &&
                GuidEquals(VendorGuid, entry->VendorGuid)) {

                if (*ValueLength < sizeof(UINT8)) {
                    *ValueLength = sizeof(UINT8);
                    return STATUS_BUFFER_TOO_SMALL;
                }

                if (Value) {
                    *(PUCHAR)Value = entry->EmulatedValue;
                }

                *ValueLength = sizeof(UINT8);

                if (Attributes) {
                    *Attributes = entry->Attributes;
                }

                LOG_INFO("Intercepted EFI variable query for %wZ -> returning emulated value %u",
                    VariableName, entry->EmulatedValue);

                return STATUS_SUCCESS;
            }
        }
    }

    // Forward unhandled queries to original firmware implementation via trampoline
    if (g_OriginalNtQuerySystemEnvironmentValueEx) {
        return g_OriginalNtQuerySystemEnvironmentValueEx(
            VariableName,
            VendorGuid,
            Value,
            ValueLength,
            Attributes
        );
    }

    return STATUS_NOT_IMPLEMENTED;
}

static PVOID FindNtQuerySystemEnvironmentValueEx(PVOID KernelBase, ULONG KernelSize) {
    // 46-byte prologue signature for unexported NtQuerySystemEnvironmentValueEx across Win10/11
    // 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30
    UCHAR pattern1[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18,
        0x57,
        0x48, 0x83, 0xEC, 0x30
    };
    CHAR mask1[] = "xxxxxxxxxxxxxxxxxxxx";

    // Secondary variant with differing stack allocation
    // 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC
    UCHAR pattern2[] = {
        0x48, 0x8B, 0xC4,
        0x48, 0x89, 0x58, 0x08,
        0x48, 0x89, 0x68, 0x10,
        0x48, 0x89, 0x70, 0x18,
        0x48, 0x89, 0x78, 0x20,
        0x41, 0x56,
        0x48, 0x83, 0xEC
    };
    CHAR mask2[] = "xxxxxxxxxxxxxxxxxxxxxxx";

    PVOID match = MemoryFindPattern(KernelBase, KernelSize, pattern1, mask1);
    if (!match) {
        match = MemoryFindPattern(KernelBase, KernelSize, pattern2, mask2);
    }

    return match;
}

NTSTATUS EfiHookInitialize(VOID) {
    ULONG kernelSize = 0;
    PVOID kernelBase = MemoryGetKernelBase(&kernelSize);
    if (!kernelBase || kernelSize == 0) {
        LOG_ERROR("Failed to acquire kernel base for EFI hook installation");
        return STATUS_NOT_FOUND;
    }

    PVOID target = FindNtQuerySystemEnvironmentValueEx(kernelBase, kernelSize);
    if (!target) {
        LOG_ERROR("Failed to locate NtQuerySystemEnvironmentValueEx signature in ntoskrnl");
        return STATUS_NOT_FOUND;
    }

    g_TargetFunction = target;
    LOG_INFO("NtQuerySystemEnvironmentValueEx resolved at %p", target);

    // Double-load guard: Verify if already hooked
    if (EfiHookIsAlreadyInstalled(target)) {
        LOG_INFO("NtQuerySystemEnvironmentValueEx prologue is already patched (0x48 0xB8). Skipping hook.");
        return STATUS_IMAGE_ALREADY_LOADED;
    }

    // Allocate executable memory for the trampoline:
    // 12 bytes for saved original instructions + 12 bytes for absolute jmp back
    SIZE_T trampolineSize = DETOUR_SIZE + sizeof(JMP_ABSOLUTE_RAX);
    g_TrampolineBuffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED_EXECUTE,
        trampolineSize,
        SECUREBOOT_TAG
    );

    if (!g_TrampolineBuffer) {
        LOG_ERROR("Failed to allocate executable pool for trampoline");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Copy original instructions into trampoline
    RtlCopyMemory(g_TrampolineBuffer, target, DETOUR_SIZE);

    // Build return jump in trampoline (jumping back to target + 12)
    PJMP_ABSOLUTE_RAX returnJmp = (PJMP_ABSOLUTE_RAX)(g_TrampolineBuffer + DETOUR_SIZE);
    returnJmp->MovRaxOpcode[0] = 0x48;
    returnJmp->MovRaxOpcode[1] = 0xB8;
    returnJmp->TargetAddress = (UINT64)((PUCHAR)target + DETOUR_SIZE);
    returnJmp->JmpRaxOpcode[0] = 0xFF;
    returnJmp->JmpRaxOpcode[1] = 0xE0;

    g_OriginalNtQuerySystemEnvironmentValueEx = (PFN_NtQuerySystemEnvironmentValueEx)g_TrampolineBuffer;

    // Build detour jump targeting HookedNtQuerySystemEnvironmentValueEx
    JMP_ABSOLUTE_RAX detour;
    detour.MovRaxOpcode[0] = 0x48;
    detour.MovRaxOpcode[1] = 0xB8;
    detour.TargetAddress = (UINT64)&HookedNtQuerySystemEnvironmentValueEx;
    detour.JmpRaxOpcode[0] = 0xFF;
    detour.JmpRaxOpcode[1] = 0xE0;

    // Apply inline hook with MDL-backed write
    NTSTATUS status = MemoryWriteProtectedBytes(target, &detour, sizeof(detour));
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("Failed to write inline hook detour to target function (0x%08X)", status);
        ExFreePoolWithTag(g_TrampolineBuffer, SECUREBOOT_TAG);
        g_TrampolineBuffer = NULL;
        g_OriginalNtQuerySystemEnvironmentValueEx = NULL;
        return status;
    }

    LOG_INFO("NtQuerySystemEnvironmentValueEx inline detour installed successfully via MDL mapping");
    return STATUS_SUCCESS;
}

VOID EfiHookRemove(VOID) {
    if (g_TargetFunction && g_TrampolineBuffer) {
        // Restore original 12 bytes from trampoline back into target function
        MemoryWriteProtectedBytes(g_TargetFunction, g_TrampolineBuffer, DETOUR_SIZE);
        ExFreePoolWithTag(g_TrampolineBuffer, SECUREBOOT_TAG);
        g_TrampolineBuffer = NULL;
        g_OriginalNtQuerySystemEnvironmentValueEx = NULL;
        g_TargetFunction = NULL;
        LOG_INFO("NtQuerySystemEnvironmentValueEx inline hook removed");
    }
}
