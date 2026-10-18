#include "../include/secureboot_emulation.h"

NTSTATUS SecureBootEmulationInitialize(VOID) {
    LOG_INFO("Initializing multi-surface UEFI Secure Boot state emulation framework");

    // Surface 1: Registry synchronization (UEFISecureBootEnabled and SecureBootCapable)
    NTSTATUS regStatus = RegistryPatchSecureBootState();
    if (!NT_SUCCESS(regStatus)) {
        LOG_ERROR("Registry state synchronization encountered failure (0x%08X)", regStatus);
    }

    // Surface 2: KUSER_SHARED_DATA DbgSecureBootEnabled kernel alias
    NTSTATUS sharedDataStatus = SharedUserDataPatch();
    if (!NT_SUCCESS(sharedDataStatus)) {
        LOG_ERROR("KUSER_SHARED_DATA modification encountered failure (0x%08X)", sharedDataStatus);
    }

    // Surface 3: NtQuerySystemInformation class 145 (SystemSecureBootInformation)
    NTSTATUS sysInfoStatus = SysInfoPatchInitialize();
    if (sysInfoStatus == STATUS_IMAGE_ALREADY_LOADED) {
        LOG_INFO("Guard 1 triggered: Class 145 global flags already active");
    } else if (!NT_SUCCESS(sysInfoStatus)) {
        LOG_ERROR("Class 145 kernel global patch failed (0x%08X)", sysInfoStatus);
    }

    // Surface 4: Unexported NtQuerySystemEnvironmentValueEx inline detour & table emulation
    NTSTATUS efiStatus = EfiHookInitialize();
    if (efiStatus == STATUS_IMAGE_ALREADY_LOADED) {
        LOG_INFO("Guard 2 triggered: NtQuerySystemEnvironmentValueEx prologue already contains detour");
    } else if (!NT_SUCCESS(efiStatus)) {
        LOG_ERROR("EFI environment variable inline hook failed (0x%08X)", efiStatus);
    }

    LOG_INFO("Multi-surface emulation sequence completed");
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    LOG_INFO("Driver entry invoked (manual map / system load)");

    NTSTATUS status = SecureBootEmulationInitialize();

    // When loaded via manual mapper (e.g. kdmapper), returning STATUS_SUCCESS or
    // custom status allows caller to unload entry point while persistent patches remain active
    return status;
}
