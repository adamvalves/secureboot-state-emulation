---
name: Defect Report / Bug Report
about: Report unexpected bugchecks, signature mismatch, or execution faults
title: "[DEFECT] "
labels: ["bug", "kernel"]
assignees: adamvalves
---

### Defect Description
[Detailed description of the observed defect, bugcheck, or unexpected behavior.]

### Reproduction Environment
- Windows Build: [e.g., 10.0.19045.3803]
- Kernel Debugger Attached: [Yes / No]
- Testsigning Enabled: [Yes / No]
- Bugcheck Code (if applicable): [e.g., KMODE_EXCEPTION_NOT_HANDLED (0x1E)]

### Expected Behavior
[Detailed explanation of the expected state according to specifications.]

### Crash Dump / WinDbg Triage
```text
kd> !analyze -v
[Paste relevant WinDbg triage output here]
```
