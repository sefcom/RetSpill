import os

cnt = 0
for i in range(5000):
    os.system("./poc")
    if os.path.exists("/tmp/output"):
        os.system("rm /tmp/output")
        cnt += 1
        print("cnt: %d, i: %d" % (cnt, i))
    
