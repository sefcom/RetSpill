import gdb
import sys

# init
port = int(gdb.parse_and_eval("$port"))
rsp = int(gdb.parse_and_eval("$krsp"))
size = 0x1000 - (rsp & 0xfff)
# print(hex(port))
#print(hex(rsp))

# read memory
gdb.execute("target remote :%d" % port)
inferior = gdb.inferiors()[0]
mem = inferior.read_memory(rsp, size).tobytes()
print("MEMORY:", mem.hex())

# exit
gdb.execute("detach")
gdb.execute("quit")
