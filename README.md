# UEFI Secure Boot State Emulation Framework

Kernel-mode multi-surface state introspection and emulation architecture for Windows x64 platforms.

## Overview

Hardware and operating system integrity validation mechanisms verify UEFI Secure Boot state across multiple disconnected kernel and user-accessible boundaries. Simplistic emulation approaches that modify solely the system registry succeed under cursory inspections but fail when subjected to cross-validation via Windows Management Instrumentation (WMI), PowerShell hardware cmdlets (`Confirm-SecureBootUEFI`), or direct runtime EFI environment variable queries. Discrepancies between these layers immediately expose state inconsistencies.

This framework implements an atomic four-surface state synchronization model within the Windows kernel (`ntoskrnl.exe`), aligning all independent query interfaces without triggering Kernel Patch Protection (PatchGuard) or leaving persistent driver objects in system telemetry tables.

## Technical Specifications

- **Target Architecture**: x86_64
- **Operating Systems**: Windows 10 / 11 (NT Kernel builds 10.0.19041 through 10.0.22631+)
- **Execution Context**: Kernel Ring 0 (Designed for manual mapping via signed vulnerable driver loaders, e.g., `kdmapper`)
- **Key Subsystems**:
  - Configuration Manager Registry Subsystem (`ZwSetValueKey`)
  - Shared User Data Aperture (`KUSER_SHARED_DATA` at `0xFFFFF78000000000`)
  - System Information Dispatcher (`ExpQuerySystemInformation` / `SeSecureBootQueryInformation`)
  - Firmware Environment Variable Service (`NtQuerySystemEnvironmentValueEx`)

## Architectural Surfaces & Memory Layout

```text
+-----------------------+--------------------------+-----------------------+------------------------------------------+
| Subsystem Surface     | Memory Location / Path   | Type / Size           | Emulated Value / Target State            |
+-----------------------+--------------------------+-----------------------+------------------------------------------+
| Registry State        | HKLM\...\SecureBoot\State| REG_DWORD (4 Bytes)   | UEFISecureBootEnabled = 1                |
|                       |                          | REG_DWORD (4 Bytes)   | SecureBootCapable = 1                    |
| KUSER_SHARED_DATA     | 0xFFFFF780000002EC       | BOOLEAN (1 Byte)      | DbgSecureBootEnabled = 1                 |
| System Information    | RIP-relative .data ptr   | UINT32 (4 Bytes)      | Bit 0 (Enabled) = 1, Bit 3 (Capable) = 1 |
| EFI Variable: SecureBoot| NtQuerySysEnvValEx Detour| UINT8 (1 Byte)        | 0x01 (EFI_GLOBAL_VARIABLE_GUID)          |
| EFI Variable: SetupMode | NtQuerySysEnvValEx Detour| UINT8 (1 Byte)        | 0x00 (User Mode / PK Enrolled)           |
| EFI Variable: AuditMode | NtQuerySysEnvValEx Detour| UINT8 (1 Byte)        | 0x00 (Audit Mode Inactive)               |
| EFI Variable: DeployedMode| NtQuerySysEnvValEx Detour| UINT8 (1 Byte)      | 0x01 (Deployed State Active)             |
| EFI Variable: CustomEnable| NtQuerySysEnvValEx Detour| UINT8 (1 Byte)      | 0x01 (Vendor-Specific Enable Active)     |
+-----------------------+--------------------------+-----------------------+------------------------------------------+
```

## Detailed Surface Implementation

### 1. Registry State Synchronization

Registry validation is enforced under:
`\Registry\Machine\SYSTEM\CurrentControlSet\Control\SecureBoot\State`

Values written:
- `UEFISecureBootEnabled` (`REG_DWORD` = 1)
- `SecureBootCapable` (`REG_DWORD` = 1)

Modifications are executed directly via `ZwCreateKey` and `ZwSetValueKey` during driver initialization. The implementation avoids registering registry callback routines (`CmRegisterCallbackEx`), preventing forensic enumeration of filter driver tracking structures.

### 2. KUSER_SHARED_DATA Memory Aperture

User-mode processes can inspect the Secure Boot debugging flag without executing a system call by directly reading `0x7FFE02EC` (`PKUSER_SHARED_DATA->DbgSecureBootEnabled`). 

Because user-mode access to this page is marked read-only, write access is performed via the permanent kernel-mode read/write alias mapped by the memory manager at:
`0xFFFFF780000002EC`

Writing directly to this kernel virtual address synchronizes the state across all process contexts with zero overhead.

### 3. NtQuerySystemInformation Class 145 (SystemSecureBootInformation)

Administrative query utilities, including the PowerShell `Confirm-SecureBootUEFI` cmdlet and WMI providers (`Win32_SecureBoot`), query `NtQuerySystemInformation` with information class 145 (`SystemSecureBootInformation`).

Execution flow:
1. `ExpQuerySystemInformation` dispatches class 145 to `SeSecureBootQueryInformation`.
2. `SeSecureBootQueryInformation` accesses an unexported kernel global variable (e.g., `dword_140C5467C` in representative 22H2 builds).
3. Bit 0 controls `SecureBootEnabled`; Bit 3 controls `SecureBootCapable`.
4. The memory address of this global is resolved at runtime via a RIP-relative pattern scan of `SeSecureBootQueryInformation`.
5. An atomic bitwise OR (`InterlockedOr`) sets bits 0 and 3 (`0x09`). Because this variable resides in the `.data` section of `ntoskrnl.exe`, modifications do not trigger Kernel Patch Protection (PatchGuard).

### 4. EFI Environment Variable Runtime Interception

Low-level anti-cheat engines and hardware profiling utilities circumvent high-level system APIs by issuing direct queries against UEFI runtime variables.

`NtQuerySystemEnvironmentValueEx` is unexported in the `ntoskrnl.exe` export table (`MmGetSystemRoutineAddress` returns `NULL`). The routine is located using a multi-version prologue signature and hooked using an MDL-backed 12-byte absolute detour:

```text
mov rax, TargetHookAddress   ; 48 B8 [64-bit absolute address]
jmp rax                      ; FF E0
```

The hook handles five critical variables via table-driven matching:

1. **`SecureBoot`** (`EFI_GLOBAL_VARIABLE_GUID`): Returns `1`.
2. **`SetupMode`** (`EFI_GLOBAL_VARIABLE_GUID`): Returns `0`. When Secure Boot is disabled in physical firmware, UEFI defaults to Setup Mode (Platform Key not enrolled) where `SetupMode` returns `1`. Anti-cheat engines query `SetupMode` immediately after `SecureBoot`; returning `1` for both creates an immediate logical contradiction. Emulating `SetupMode = 0` guarantees consistency.
3. **`AuditMode`** (`EFI_GLOBAL_VARIABLE_GUID`): Returns `0`.
4. **`DeployedMode`** (`EFI_GLOBAL_VARIABLE_GUID`): Returns `1`.
5. **`SecureBootEnable`** (`EFI_CUSTOM_SECURE_BOOT_GUID`): Returns `1`.

All unhandled variable queries are redirected to an allocated executable trampoline preserving the original prologue instructions and jumping back to the target function offset.

## Double-Load Guard Mechanism

Repeated driver injection without an intermediate system reboot risks corrupting the inline hook chain. If mapped a second time:
1. The signature scanner locates the target function.
2. The prologue already contains bytes `0x48 0xB8` from the previous detour.
3. The newly generated trampoline saves the previous detour bytes instead of original kernel instructions, causing cyclic branch faults or `KMODE_EXCEPTION_NOT_HANDLED` bugchecks.

To eliminate this condition, the initialization sequence incorporates a dual-phase guard:
- **Guard 1**: Checks if bits 0 and 3 are already active in the Class 145 global variable.
- **Guard 2**: Checks whether bytes 0-1 of `NtQuerySystemEnvironmentValueEx` equal `0x48 0xB8`.

If either guard detects previous instrumentation, the driver gracefully bypasses detour installation and exits safely.

## Scope & Code Integrity Analysis

Queries for `SystemCodeIntegrityInformation` (information class 103) resolve to internal code integrity flags inside `ci.dll` via a Control Flow Guard (CFG) protected dispatch routine. Under standard manual mapping environments where the operating system has not enabled test-signing (`bcdedit /set testsigning on`) or connected a kernel debugger, Code Integrity flags already reflect fully validated production status (`CODEINTEGRITY_OPTION_ENABLED`). Consequently, patching class 103 is non-essential and deliberately omitted to minimize memory footprint.

## Project Structure

```text
.
├── include/
│   ├── common.h                  # Logging macros, status helpers, and driver tag
│   ├── efi_variable.h            # EFI GUIDs, variable attributes, and hook definitions
│   ├── memory.h                  # MDL page remapping, relative resolution, and scanning
│   ├── ntdef.h                   # Undocumented NT structures and system information classes
│   ├── registry.h                # Kernel registry manipulation interfaces
│   ├── secureboot_emulation.h    # High-level orchestrator interface
│   └── sysinfo.h                 # SystemSecureBootInformation class 145 contracts
├── src/
│   ├── driver_entry.c            # DriverEntry and orchestration dispatch
│   ├── efi_variable.c            # Signature lookup, MDL detour, and table emulation
│   ├── memory.c                  # Pattern search and MDL-backed safe memory write
│   ├── registry.c                # ZwSetValueKey state synchronization
│   ├── shared_data.c             # KUSER_SHARED_DATA kernel alias manipulation
│   └── sysinfo.c                 # Class 145 signature resolution and atomic bitwise patch
├── .gitignore                    # WDK / Visual Studio build artifact exclusions
├── LICENSE                       # MIT License (Adam 2026)
├── README.md                     # Technical specifications and architecture documentation
├── SecureBoot.sln                # Visual Studio 2022 solution
├── SecureBoot.vcxproj            # WDK driver project definition
└── SecureBoot.vcxproj.filters    # Solution filter hierarchy
```

## Build & Toolchain

- **Compiler**: Visual Studio 2022 (MSVC v143) with Windows Driver Kit (WDK) 10.0.22621+
- **Platform**: x64 (Native 64-bit)
- **Configuration**: Release (`/O2` optimization, `/GS-` buffer security checks disabled where appropriate for manual mapping)

```powershell
# Build driver via MSBuild
msbuild SecureBoot.sln /p:Configuration=Release /p:Platform=x64
```

## Research & Educational Disclaimer

This repository is published strictly for educational, security research, and operating system reverse-engineering purposes. It demonstrates kernel-mode memory manipulation, MDL-backed instruction modification, and system integrity verification architecture on the Windows operating system.
