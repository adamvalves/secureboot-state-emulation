# Security Policy

## Supported Versions

This project focuses on research and demonstration within low-level Windows kernel environments. The following operating system targets are actively analyzed:

| Target Build | Architecture | Supported |
| :--- | :--- | :--- |
| Windows 11 (23H2 / 22631) | x86_64 | Yes |
| Windows 11 (22H2 / 22621) | x86_64 | Yes |
| Windows 10 (22H2 / 19045) | x86_64 | Yes |
| Windows 10 (21H2 / 19044) | x86_64 | Yes |
| Older builds (< 19041) | x86_64 | Best effort |

## Reporting Security Issues

To report potential memory corruption vectors, uncontrolled pool allocations, or unhandled bugcheck conditions, please direct a detailed technical report to:

- **Contact**: `adam@networkconnect.org`
- **PGP**: Available upon request.

Please provide:
1. Target Windows kernel build number and revision.
2. Reproduction steps and memory dump analysis (`!analyze -v`).
3. Callstack and register state at fault.
