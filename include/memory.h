#ifndef SECUREBOOT_MEMORY_H
#define SECUREBOOT_MEMORY_H

#include "common.h"

#pragma pack(push, 1)
typedef struct _JMP_ABSOLUTE_RAX {
    UINT8  MovRaxOpcode[2]; // 0x48, 0xB8
    UINT64 TargetAddress;   // 64-bit target address
    UINT8  JmpRaxOpcode[2]; // 0xFF, 0xE0
} JMP_ABSOLUTE_RAX, *PJMP_ABSOLUTE_RAX;
#pragma pack(pop)

PVOID MemoryGetKernelBase(OUT PULONG ImageSize OPTIONAL);

PVOID MemoryFindPattern(
    _In_ PVOID BaseAddress,
    _In_ ULONG Size,
    _In_ PCUCHAR Pattern,
    _In_ PCSTR Mask
);

PVOID MemoryResolveRelativeAddress(
    _In_ PVOID InstructionAddress,
    _In_ ULONG OffsetToDisplacement,
    _In_ ULONG InstructionLength
);

NTSTATUS MemoryWriteProtectedBytes(
    _In_ PVOID Destination,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length
);

#endif // SECUREBOOT_MEMORY_H
