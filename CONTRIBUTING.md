# Contributing Guidelines

Contributions to this repository must meet senior systems programming and kernel engineering standards.

## Code Standards & Style

1. **Language & Dialect**: Standard C11 for kernel driver implementations.
2. **Naming Conventions**: PascalCase for exported/driver functions and types; camelCase or snake_case for local variables; uppercase for macros and constants.
3. **Paging & IRQL Awareness**:
   - Ensure proper IRQL assertions (`PAGED_CODE()` for IRQL < DISPATCH_LEVEL).
   - Use `ExAllocatePool2` with explicit flags (`POOL_FLAG_PAGED` or `POOL_FLAG_NON_PAGED_EXECUTE`).
4. **Defensive Error Handling**:
   - Every system call, pool allocation, and pointer dereference must validate bounds and return codes.
   - Use structured exception handling (`__try` / `__except`) around user-mode or variable memory accesses.
5. **Aesthetics & Cleanliness**:
   - Zero emojis in commit messages, pull requests, comments, or documentation.
   - All documentation in formal technical English.

## Verification Workflow

Before submitting a Pull Request:
1. Compile under Visual Studio 2022 (MSVC v143) with `/O2` and `/W4`.
2. Confirm zero warnings treated as errors (`TreatWarningAsError=true`).
3. Verify on both Windows 10 (19041+) and Windows 11 (22621+) VMs.
