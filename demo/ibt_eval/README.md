## IBT Evaluation
This folder uses a contrived vulnerable kernel module to demonstrate that RetSpill is able to perform privilege escalation in kernels compiled with IBT given PC-Control.
In this evaluation, we simulate a control-flow hijacking vulnerability that is not protected by IBT. This is a reasonable setting because
1. IBT currently does not protect all call targets because of compatibility issues between some subsystems and IBT.
2. IBT only protects forward-edge control flow, attackers can still obtain CFHP through backward-edge control flow hijacking.

In this evaluation, we simulate such a unchecked control-flow hijacking vulnerability by calling `__x86_indirect_thunk_rdi` directly.

# Note
This description is exactly the same as KCFI because IBT and KCFI are both forward-edge control flow protection schemes and suffer from the same issues at the moment.

# Setup
Run the following command to build a disk image so that you can boot the kernel first:
`cd img/ && ./create-image.sh && cd ..`
The command should finish in 5-10 minutes.

Due to the size of disk image (2G), we do not include the built disk image in this repo.

# How to Run
1. Add the vulnerable kernel module and the exploit to the disk image by `./add_file.sh vuln_module/vuln.ko && ./add_file.sh poc/poc`
2. Launch the virtual machine by `./startvm` and wait for it to reach `pwn login: `
3. Inside the VM, login as `root` without password and run `insmod vuln.ko && chmod 666 /dev/vuln`
4. Inside the VM, logout `root` and login as `user` without password
5. Run `/home/user/poc` and a root shell should be poped
