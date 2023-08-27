# RetSpill
RetSpill is a powerful exploitation technique that threats Linux kernel security.
Given a control flow hijacking primitive (CFHP, also known as PC control), it can break the security boundary between user space and kernel space.

This repository contains a few demonstrations of the technique.
More specifically,
1. this repo use CVE-2022-1786 to shows RetSpill can break the security boundary between user space and kernel space
2. this repo demonstrates RetSpill's capability to perform privilege escalation in kernels compiled with KCFI given PC-control
3. this repo demonstrates RetSpill's capability to perform privilege escalation in kernels compiled with IBT given PC-control
