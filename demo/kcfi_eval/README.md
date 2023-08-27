## KCFI Evaluation
This folder uses a contrived vulnerable kernel module to demonstrate that RetSpill is able to perform privilege escalation in kernels compiled with KCFI given PC-Control.
In this evaluation, we simulate a control-flow hijacking vulnerability that is not protected by KCFI. This is a reasonable setting because
1. KCFI currently does not protect all call targets because of compatibility issues between some subsystems and KCFI
2. KCFI only protects forward-edge control flow, attackers can still obtain CFHP through backward-edge control flow hijacking.

In this evaluation, we simulate such a unchecked control-flow hijacking vulnerability by calling `__x86_indirect_thunk_rdi` directly.

# Setup
Run the following command to build a disk image so that you can boot the kernel first:
`cd img/ && ./create-image.sh && cd ..`
The command should finish in 5-10 minutes.

Due to the size of disk image (2G), we do not include the built disk image in this repo.

# How to Run
1. Launch the virtual machine by `./startvm` and wait for it to reach `pwn login: `
2. In another terminal in the host machine, run `./copy2vm vuln_module/vuln.ko && ./copy2vm poc/poc` to upload the vulnerable kernel module and the exploit
3. Inside the VM, login as `root` without password and run `insmod vuln.ko && chmod 666 /dev/vuln` and then `mv poc /tmp/poc && chown user:user /tmp/poc`
4. Inside the VM, logout `root` and login as `user` without password
5. Run `/tmp/poc` and a root shell should be poped
