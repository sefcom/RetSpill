from pwn import *
context.log_level = "WARNING"
#context.log_level = "DEBUG"

def evaluate_once():
    print("trial @", time.time())
    r = process("./startvm")
    r.sendlineafter(b"pwn login: ", b"root")

    # for some reason, there is a chance that the network fails, in that case, we return None and restart the eval
    ret = os.system("./copy2vm vuln_module/vuln.ko")
    print("ret:", ret)
    if ret != 0:
        return None

    # now we know the network is fine, proceed with the experiment
    os.system("./copy2vm poc")
    r.sendlineafter(b"root@pwn:~# ", b"echo 0 > /proc/sys/kernel/printk")
    r.sendlineafter(b"root@pwn:~# ", b"insmod vuln.ko")
    r.sendlineafter(b"root@pwn:~# ", b"chmod 666 /dev/vuln; mv poc /tmp/poc")
    r.sendlineafter(b"root@pwn:~# ", b"su user")
    r.sendlineafter(b"user@pwn", b"cd /tmp")
    #time.sleep(2)
    r.sendlineafter(b"user@pwn", b"timeout 2 ./poc")
    
    output = r.recvall(timeout=3)
    print(output)
    #if b'root@pwn' in output:
    #    print("good!!!")
    #    r.close()
    #    return 1
    #else:
    #    print("bad!!!")
    #    print(output)
    #    return 0

cnt = 0
for i in range(10):
    tmp = evaluate_once()
    while tmp is None:
        tmp = evaluate_once()
    cnt += tmp
    print(f"success: {cnt}/{i+1}")
    
