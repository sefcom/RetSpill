import re
from elftools.elf.elffile import ELFFile

from pwn import *

KERNEL_ELF = None
elf = None
gadgets = []
functions = []
holes = []

class Gadget:
    def __init__(self, addr, assembly, raw_bytes):
        self.addr = addr
        self.assembly = assembly
        self.raw_bytes = raw_bytes
        self.start_addr = addr
        self.end_addr = addr + len(raw_bytes)

    def is_overlap(self, hole):
        if self.end_addr <= hole[0]:
            return False
        if self.start_addr >= hole[1]:
            return False
        return True

class Function:
    def __init__(self, name, addr, size):
        self.name = name
        self.addr = addr
        self.size = size
        self.start_addr = addr
        self.end_addr = addr + size

def get_func_info():
    log.info("Trying to collect position-variant function information...")
    for x in elf.sections:
        if not x.name.startswith(".text."):
            continue
        func = Function(x.name[6:], x.header.sh_addr, len(x.data()))
        functions.append(func)
    log.success("%d position-variant functions collected!", len(functions))

def get_all_gadgets():
    """
    search for all gadgets in the kernel .text section
    translate virtual address and file offset back and forth so that fking ROPgadget won't eat up all the memory
    """
    log.info("Collecting all gadgets...")
    #MIN_ADDR = 0xffffffff81000000
    #MAX_ADDR = 0xffffffff81c00000
    with open(KERNEL_ELF, "rb") as f:
        elffile = ELFFile(f)
        text = elffile.get_section_by_name(".text")
        TEXT_START = text.header['sh_addr']
        TEXT_END = TEXT_START + text.header['sh_size']
    print("start: %#x" % TEXT_START)
    print("end  : %#x" % TEXT_END)
    min_phys_off = elf.vaddr_to_offset(TEXT_START)
    max_phys_off = elf.vaddr_to_offset(TEXT_END)

    cmd = "ROPgadget --binary %s --rawArch=x86 --rawMode=64 --range %#x-%#x --dump --all" % (KERNEL_ELF, min_phys_off, max_phys_off)
    output = subprocess.getoutput(cmd)

    log.info("Parsing all gadgets...")
    for line in output.splitlines():
        if not line.startswith("0x"):
            continue

        # parse each gadget entry
        res = re.match('(0x[0-f]+) : (.+) // (.*)', line)
        assert res is not None

        addr = elf.offset_to_vaddr(int(res.group(1), 16))
        assembly = res.group(2)
        raw_bytes = bytes.fromhex(res.group(3))

        # create each gadget object
        gadget = Gadget(addr, assembly, raw_bytes)
        gadgets.append(gadget)
    log.success("%d gadgets collected!", len(gadgets))

def filter_gadgets():
    global gadgets
    log.info("Filtering gadgets that overlap with position-variant functions...")
    raw_gadgets = gadgets
    gadgets = []
    for idx, gadget in enumerate(raw_gadgets):
        for hole in holes:
            if gadget.is_overlap(hole):
                break
        else:
            gadgets.append(gadget)
    log.success("%d position-invariant gadgets collected!", len(gadgets))

def clean_gadgets():
    # de-duplicate gadgets
    seen = set()
    new_gadgets = []
    for gadget in gadgets:
        if gadget.assembly in seen:
            continue
        new_gadgets.append(gadget)
        seen.add(gadget.assembly)

    # sort gadgets
    new_gadgets.sort(key = lambda x: x.assembly)
    log.success("%d unique position-invariant gadgets collected!", len(new_gadgets))
    return new_gadgets

def show_gadgets():
    for gadget in gadgets:
        line = "%#x : %s" % (gadget.addr, gadget.assembly)
        print(line)

def merge_holes():
    log.info("Trying to reduce search complexity by merging holes...")
    global holes
    tmp_holes = []
    for idx, func in enumerate(functions):

        # determine the start of next function
        if idx != len(functions) - 1:
            next_start_addr = functions[idx+1].start_addr
        else:
            next_start_addr = func.end_addr

        # check whether the function padding is interesting, if not, we include the padding
        # in the hole to reduce search complexity
        hole_start = func.start_addr
        func_pad_len = next_start_addr-func.end_addr
        func_padding = elf.read(func.end_addr, func_pad_len)
        if func_padding == b'\x00' * func_pad_len:
            hole_end = next_start_addr
        else:
            hole_end = func.end_addr

        tmp_holes.append((hole_start, hole_end))

    # merge holes to reduce search complexity
    while True:
        for idx in range(len(tmp_holes)-1):
            hole = tmp_holes[idx]
            next_hole = tmp_holes[idx+1]
            if hole[1] != next_hole[0]:
                continue
            new_hole = (hole[0], next_hole[1])
            tmp_holes[idx+1] = new_hole
            tmp_holes.remove(hole)
            break
        else:
            break

    holes = tmp_holes
    print(holes)
    log.success("%d holes detected!", len(holes))

if __name__ == "__main__":
    import argparse

    import monkeyhex
    parser = argparse.ArgumentParser(description='Script to find position-invariant gadgets in Linux kernels compiled with FG-KASLR',
                                     usage="%(prog)s [options] <vmlinux_path>")
    parser.add_argument('vmlinux_path',  type=str,
                        help="path to vmlinux")
    args = parser.parse_args()

    KERNEL_ELF = args.vmlinux_path
    elf = ELF(args.vmlinux_path)

    get_func_info()
    merge_holes()
    get_all_gadgets()
    filter_gadgets()
    gadgets = clean_gadgets()
    show_gadgets()
