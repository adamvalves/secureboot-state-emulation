#include "../include/secureboot_emulation.h"

NTSTATUS SharedUserDataPatch(VOID) {
    // KUSER_SHARED_DATA is permanently mapped read/write in kernel mode at 0xFFFFF78000000000
    // Offset 0x2EC corresponds to BOOLEAN DbgSecureBootEnabled (read-only in user-mode at 0x7FFE02EC)
    volatile UCHAR* pDbgSecureBootEnabled = (volatile UCHAR*)(KUSER_SHARED_DATA_KERNEL_ADDRESS + KUSER_SHARED_DATA_SECUREBOOT_OFFSET);

    __try {
        *pDbgSecureBootEnabled = (UCHAR)1;
        LOG_INFO("KUSER_SHARED_DATA->DbgSecureBootEnabled patched at %p (value=1)", pDbgSecureBootEnabled);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS status = GetExceptionCode();
        LOG_ERROR("Exception occurred while accessing KUSER_SHARED_DATA at %p (0x%08X)", pDbgSecureBootEnabled, status);
        return status;
    }

    return STATUS_SUCCESS;
}
