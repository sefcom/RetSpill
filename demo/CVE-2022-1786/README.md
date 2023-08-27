## CVE-2022-1786
This folder use CVE-2022-1786 to shows RetSpill can perform the following tasks from user space:
1. perform arbitrary read in kernel space
2. perform arbitrary write in kernel space
3. call arbitrary kernel function in kernel space and obtain its return value

More importantly, all the three experiments are done without triggering or exploiting the vulnerability again.
In other words, once CFHP is obtained, RetSpill is 100% reliable.

## Caveats
The exploit for CVE-2022-1786 is not reliable (about 50% success rate), thus you might need to rerun the exploit a few times to obtain CFHP.
The moment `CFHP is obtained!` is printed, the exploit becomes reliable.

# Setup
Run the following command to build a disk image so that you can boot the kernel first:
`cd img/ && ./create-image.sh && cd ..`
The command should finish in 5-10 minutes.

Due to the size of disk image (2G), we do not include the built disk image in this repo.

# How to Run
1. Launch the virtual machine by `./startvm`
2. Inside the VM, login as user `user` without password, then run `/home/user/poc`
3. Once `CFHP is obtained!` is printed, press enter to start the demo of RetSpill. If the kernel crashes or `Fail to obtain CFHP, plz try it again!`, that means the poc fails to obtain CFHP. You may want to rerun the step 1-3 again and ensure the exploit can obtain CFHP.
4. Then the demo will start RetSpill attack and perform arbitrary read/write/function call inside kernel space without escalating privilege
