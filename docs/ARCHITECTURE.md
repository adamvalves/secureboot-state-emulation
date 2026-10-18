# Architecture & Deep Internals

## System Call & Kernel Dispatch Flow

Windows operating systems validate UEFI Secure Boot status through distinct query channels. The following diagram illustrates the dispatch hierarchy intercepted by this framework:

```text
[ Usermode Caller ]
       │
       ├─► Direct Read (0x7FFE02EC) ─────────────────────────► [ KUSER_SHARED_DATA ] (Read-only user page)
       │                                                               ▲
       │                                                               │ (Direct kernel write)
       │                                                       [ 0xFFFFF780000002EC ]
       │
       ├─► WMI / Confirm-SecureBootUEFI
       │         │
       │         ▼
       │   NtQuerySystemInformation(Class 145)
       │         │
       │         ▼
       │   ExpQuerySystemInformation
       │         │
       │         ▼
       │   SeSecureBootQueryInformation ─────────────────────► [ dword_140C5467C (.data) ]
       │                                                               ▲
       │                                                               │ (InterlockedOr 0x09)
       │                                                       [ SysInfo Module ]
       │
       └─► Direct EFI Runtime Query
                 │
                 ▼
           NtQuerySystemEnvironmentValueEx (ntoskrnl)
                 │
                 ▼ (MDL 12-byte Detour: 48 B8 [addr] FF E0)
           [ HookedNtQuerySystemEnvironmentValueEx ]
                 │
                 ├─► Variable match (SecureBoot, SetupMode, etc.) ──► Return Emulated Value
                 │
                 └─► Unmatched Variable ─────────────────────────────► [ Trampoline Buffer ] ──► Original Handler
```

## Inline Detour & Trampoline Mechanics

### 1. Detour Layout (12-Byte Absolute Jump)

To avoid relative jump range limitations (+/- 2GB) across the kernel virtual address space, the hook employs an absolute 64-bit indirect jump via register RAX:

```text
+--------+--------+------------------------------------+--------+--------+
| Byte 0 | Byte 1 | Bytes 2 .. 9                       | Byte 10| Byte 11|
+--------+--------+------------------------------------+--------+--------+
| 0x48   | 0xB8   | 64-bit Absolute Hook Target Address| 0xFF   | 0xE0   |
| (mov rax, TargetHookAddress)                         | (jmp rax)       |
+--------+--------+------------------------------------+--------+--------+
```

### 2. Trampoline Construction

The trampoline buffer is allocated from `NonPagedPoolExecute` with tag `'tBcS'`:

```text
+------------------------------------+------------------------------------+
| Offset 0x00 .. 0x0B (12 Bytes)     | Offset 0x0C .. 0x17 (12 Bytes)     |
+------------------------------------+------------------------------------+
| Original Stolen Instructions       | JMP_ABSOLUTE_RAX                   |
| (Saved from target function header)| (mov rax, Target + 12; jmp rax)    |
+------------------------------------+------------------------------------+
```

### 3. MDL Memory Remapping Procedure

Modifying executable code pages in `ntoskrnl.exe` directly via pointer write triggers an immediate Bugcheck due to page-level write protection. Rather than toggling the global `CR0.WP` bit (which introduces race conditions across concurrent CPU cores), the framework utilizes Memory Descriptor Lists (MDL):

1. Allocate MDL via `IoAllocateMdl(TargetFunction, 12, FALSE, FALSE, NULL)`.
2. Lock physical pages in RAM via `MmProbeAndLockPages(mdl, KernelMode, IoReadAccess)`.
3. Map virtual pages with write permissions via `MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority)`.
4. Grant execution and write rights using `MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE)`.
5. Execute memory copy (`RtlCopyMemory`) onto the remapped virtual address.
6. Cleanly unmap and free the MDL (`MmUnmapLockedPages`, `MmUnlockPages`, `IoFreeMdl`).

## Double-Load Detection State Machine

```text
[ Driver Entry ]
       │
       ▼
[ Guard 1: SysInfo Class 145 ] ─── (Flags & 0x09) == 0x09? ──► TRUE  ──► [ Skip Hook / Return Safe ]
       │ FALSE
       ▼
[ Guard 2: Prologue Inspection] ── Target[0..1] == 0x48 0xB8? ─► TRUE  ──► [ Skip Hook / Return Safe ]
       │ FALSE
       ▼
[ Execute Full 4-Surface Patch Sequence ]
```
