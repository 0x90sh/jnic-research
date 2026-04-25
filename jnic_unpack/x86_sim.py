from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterable

import capstone

_PARENT = {
    "rax": "rax", "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
    "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
    "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
    "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
    "rsp": "rsp", "esp": "rsp",
    "rbp": "rbp", "ebp": "rbp",
    "r8": "r8", "r8d": "r8", "r8w": "r8", "r8b": "r8",
    "r9": "r9", "r9d": "r9", "r9w": "r9", "r9b": "r9",
    "r10": "r10", "r10d": "r10", "r10w": "r10", "r10b": "r10",
    "r11": "r11", "r11d": "r11", "r11w": "r11", "r11b": "r11",
    "r12": "r12", "r12d": "r12", "r12w": "r12", "r12b": "r12",
    "r13": "r13", "r13d": "r13", "r13w": "r13", "r13b": "r13",
    "r14": "r14", "r14d": "r14", "r14w": "r14", "r14b": "r14",
    "r15": "r15", "r15d": "r15", "r15w": "r15", "r15b": "r15",
    "xmm0": "xmm0", "xmm1": "xmm1",
}

_REG_SIZE = {
    "rax": 8, "rbx": 8, "rcx": 8, "rdx": 8, "rdi": 8, "rsi": 8,
    "rsp": 8, "rbp": 8, "r8": 8, "r9": 8, "r10": 8, "r11": 8,
    "r12": 8, "r13": 8, "r14": 8, "r15": 8,
    "eax": 4, "ebx": 4, "ecx": 4, "edx": 4, "edi": 4, "esi": 4,
    "esp": 4, "ebp": 4, "r8d": 4, "r9d": 4, "r10d": 4, "r11d": 4,
    "r12d": 4, "r13d": 4, "r14d": 4, "r15d": 4,
    "ax": 2, "bx": 2, "cx": 2, "dx": 2, "di": 2, "si": 2,
    "r8w": 2, "r9w": 2, "r10w": 2, "r11w": 2, "r12w": 2, "r13w": 2,
    "r14w": 2, "r15w": 2,
    "al": 1, "bl": 1, "cl": 1, "dl": 1, "dil": 1, "sil": 1,
    "r8b": 1, "r9b": 1, "r10b": 1, "r11b": 1, "r12b": 1, "r13b": 1,
    "r14b": 1, "r15b": 1,
    "xmm0": 16, "xmm1": 16,
}


@dataclass
class JNICall:
    insn_addr: int
    vtable_offset: int
    args: list[object]


@dataclass
class State:
    binary: bytes
    section_lookup: callable
    regs: dict[str, object] = field(default_factory=dict)
    stack_bytes: dict[int, int] = field(default_factory=dict)
    stack_ptrs: dict[int, object] = field(default_factory=dict)
    rsp_delta: int = 0
    calls: list[JNICall] = field(default_factory=list)
    mem_writes: dict[int, object] = field(default_factory=dict)
    text_range: tuple[int, int] | None = None
    visited_helpers: set[int] = field(default_factory=set)
    helper_depth: int = 0
    saw_real_branch: bool = False
    saw_indirect_jump: bool = False

    def reg_get(self, name: str) -> object:
        parent = _PARENT.get(name)
        if parent is None:
            return None
        return self.regs.get(parent)

    def reg_set(self, name: str, value: object) -> None:
        parent = _PARENT.get(name)
        if parent is None:
            return
        self.regs[parent] = value

    def read_section_bytes(self, vaddr: int, length: int) -> bytes | None:
        result = self.section_lookup(vaddr)
        if result is None:
            return None
        file_off, max_len = result
        actual = min(length, max_len)
        return self.binary[file_off:file_off + actual]

    def read_section_cstring(self, vaddr: int, max_len: int = 256) -> str | None:
        b = self.read_section_bytes(vaddr, max_len)
        if b is None:
            return None
        try:
            end = b.index(0)
            return b[:end].decode("utf-8", errors="replace")
        except ValueError:
            return b.decode("utf-8", errors="replace")

    def stack_read_cstring(self, offset: int, max_len: int = 256) -> str:
        out = bytearray()
        for i in range(max_len):
            v = self.stack_bytes.get(offset + i)
            if v is None or v == 0:
                break
            out.append(v)
        return out.decode("utf-8", errors="replace")

    def stack_read_qword_ptr(self, offset: int) -> object:
        if offset in self.stack_ptrs:
            return self.stack_ptrs[offset]
        v = 0
        for i in range(8):
            b = self.stack_bytes.get(offset + i, 0)
            v |= b << (i * 8)
        return v

    def stack_write_bytes(self, offset: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.stack_bytes[offset + i] = b
        for off in list(self.stack_ptrs):
            if offset <= off < offset + len(data):
                del self.stack_ptrs[off]

    def stack_write_ptr(self, offset: int, ptr: object) -> None:
        for i in range(8):
            self.stack_bytes.pop(offset + i, None)
        self.stack_ptrs[offset] = ptr


def _imm_bytes(value: int, size: int) -> bytes:
    return (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")


def _is_ptr(v: object) -> bool:
    return isinstance(v, tuple) and len(v) > 0 and v[0] in ("rsp", "rip", "jni_env", "jni_vtable", "jni_fn", "jni_result", "mem")


def _inline_helper(parent: "State", target_vaddr: int) -> bool:
    if parent.helper_depth >= 3:
        return False
    sec = parent.section_lookup(target_vaddr)
    if sec is None:
        return False
    file_off, max_len = sec
    if parent.text_range is not None:
        text_start, text_end = parent.text_range
        if not (text_start <= target_vaddr < text_end):
            return False
    bound = min(max_len, 0x4000)
    helper_bytes = parent.binary[file_off:file_off + bound]
    helper_state = State(
        binary=parent.binary,
        section_lookup=parent.section_lookup,
        text_range=parent.text_range,
        helper_depth=parent.helper_depth + 1,
        mem_writes=dict(parent.mem_writes),
    )
    helper_state.reg_set("rdi", parent.reg_get("rdi"))
    helper_state.reg_set("rsi", parent.reg_get("rsi"))
    helper_state.reg_set("rdx", parent.reg_get("rdx"))
    helper_state.reg_set("rcx", parent.reg_get("rcx"))
    helper_state.reg_set("r8", parent.reg_get("r8"))
    helper_state.reg_set("r9", parent.reg_get("r9"))
    simulate(parent.binary, parent.section_lookup, target_vaddr,
             helper_bytes, text_range=parent.text_range,
             initial_state=helper_state)
    base_call_count = len(parent.calls)
    for c in helper_state.calls:
        new_args = []
        for a in c.args:
            if isinstance(a, tuple) and a[0] == "jni_result":
                new_args.append(("jni_result", base_call_count + a[1]))
            elif isinstance(a, tuple) and a[0] == "rsp":
                resolved = helper_state.stack_read_cstring(a[1])
                new_args.append(("frozen_string", resolved))
            else:
                new_args.append(a)
        parent.calls.append(JNICall(insn_addr=c.insn_addr, vtable_offset=c.vtable_offset, args=new_args))
    for vaddr, val in helper_state.mem_writes.items():
        if isinstance(val, tuple) and val[0] == "jni_result":
            parent.mem_writes[vaddr] = ("jni_result", base_call_count + val[1])
        else:
            parent.mem_writes[vaddr] = val
    rax_val = helper_state.reg_get("rax")
    if isinstance(rax_val, tuple) and rax_val[0] == "jni_result":
        parent.reg_set("rax", ("jni_result", base_call_count + rax_val[1]))
    else:
        parent.reg_set("rax", rax_val)
    return True


def simulate(binary: bytes, section_lookup, start_vaddr: int, code: bytes,
             max_insns: int = 4096,
             text_range: tuple[int, int] | None = None,
             initial_state: State | None = None,
             java_arg_types: list[str] | None = None,
             is_static: bool = False) -> State:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    if initial_state is not None:
        state = initial_state
    else:
        state = State(binary=binary, section_lookup=section_lookup, text_range=text_range)
        state.reg_set("rdi", ("jni_env",))
        arg_regs = ["rdx", "rcx", "r8", "r9"]
        if is_static:
            state.reg_set("rsi", ("java_class",))
            local_idx = 0
        else:
            state.reg_set("rsi", ("java_local", 0))
            local_idx = 1
        for i, t in enumerate(java_arg_types or []):
            if i < len(arg_regs):
                state.reg_set(arg_regs[i], ("java_local", local_idx, t))
            local_idx += 2 if t in ("J", "D") else 1

    insns = list(md.disasm(code, start_vaddr))
    addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}
    skip_until = None
    last_was_test_al = False
    for n, ins in enumerate(insns):
        if n >= max_insns:
            break
        if skip_until is not None:
            if ins.address < skip_until:
                last_was_test_al = False
                continue
            skip_until = None
        m = ins.mnemonic
        ops = ins.operands

        if last_was_test_al and m in ("je", "jz") and len(ops) == 1 \
                and ops[0].type == capstone.x86.X86_OP_IMM:
            target = ops[0].imm
            if target in addr_to_idx and target > ins.address:
                skip_until = target
                last_was_test_al = False
                continue

        if m == "test" and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_REG \
                and ops[1].type == capstone.x86.X86_OP_REG \
                and ops[0].reg == ops[1].reg \
                and ins.reg_name(ops[0].reg) in ("al", "eax", "rax"):
            last_was_test_al = True
            continue
        last_was_test_al = False

        if m in ("jne", "jnz", "jl", "jle", "jg", "jge", "jb", "jbe", "ja", "jae",
                 "js", "jns", "jo", "jno", "jp", "jnp", "jcxz", "jecxz", "jrcxz"):
            state.saw_real_branch = True

        if m == "jmp" and len(ops) == 1 and ops[0].type == capstone.x86.X86_OP_REG:
            state.saw_indirect_jump = True
        if m == "push":
            state.rsp_delta -= 8
            continue
        if m == "pop":
            state.rsp_delta += 8
            continue
        if m == "sub" and len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_REG \
                and ins.reg_name(ops[0].reg) == "rsp" and ops[1].type == capstone.x86.X86_OP_IMM:
            state.rsp_delta -= ops[1].imm
            continue
        if m == "add" and len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_REG \
                and ins.reg_name(ops[0].reg) == "rsp" and ops[1].type == capstone.x86.X86_OP_IMM:
            state.rsp_delta += ops[1].imm
            continue

        if m == "ret":
            break

        if m == "jmp" and len(ops) == 1 and ops[0].type == capstone.x86.X86_OP_MEM:
            mem = ops[0].mem
            base = ins.reg_name(mem.base) if mem.base != 0 else None
            if base in ("rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp",
                        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"):
                base_val = state.reg_get(base)
                if base_val == ("jni_vtable",):
                    args = [state.reg_get(r) for r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")]
                    state.calls.append(JNICall(insn_addr=ins.address,
                                                vtable_offset=mem.disp, args=args))
            break


        if m == "xor" and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_REG and ops[1].type == capstone.x86.X86_OP_REG \
                and ops[0].reg == ops[1].reg:
            state.reg_set(ins.reg_name(ops[0].reg), 0)
            continue

        if m in ("xor", "xorps", "pxor") and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_REG and ops[1].type == capstone.x86.X86_OP_MEM:
            dst = ins.reg_name(ops[0].reg)
            mem = ops[1].mem
            base = ins.reg_name(mem.base) if mem.base != 0 else None
            disp = mem.disp
            cur = state.reg_get(dst)
            other_bytes = None
            if base == "rip":
                vaddr = ins.address + ins.size + disp
                other_bytes = state.read_section_bytes(vaddr, 16)
            elif base == "rsp":
                rsp_off = disp - state.rsp_delta
                buf = bytearray()
                for i in range(16):
                    buf.append(state.stack_bytes.get(rsp_off + i, 0))
                other_bytes = bytes(buf)
            if isinstance(cur, bytes) and other_bytes:
                state.reg_set(dst, bytes(a ^ b for a, b in zip(cur, other_bytes)))
                continue
            state.reg_set(dst, None)
            continue

        if m == "xor" and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_MEM and ops[1].type == capstone.x86.X86_OP_REG:
            mem = ops[0].mem
            base = ins.reg_name(mem.base) if mem.base != 0 else None
            disp = mem.disp
            src_name = ins.reg_name(ops[1].reg)
            src_val = state.reg_get(src_name)
            size = _REG_SIZE.get(src_name, 8)
            if base == "rsp" and isinstance(src_val, int):
                rsp_off = disp - state.rsp_delta
                key = _imm_bytes(src_val, size)
                for i in range(size):
                    cur = state.stack_bytes.get(rsp_off + i, 0)
                    state.stack_bytes[rsp_off + i] = cur ^ key[i]
            continue

        if m == "xor" and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_MEM and ops[1].type == capstone.x86.X86_OP_IMM:
            mem = ops[0].mem
            base = ins.reg_name(mem.base) if mem.base != 0 else None
            disp = mem.disp
            size = ops[0].size
            imm = ops[1].imm
            if base == "rsp":
                rsp_off = disp - state.rsp_delta
                key = _imm_bytes(imm, size)
                for i in range(size):
                    cur = state.stack_bytes.get(rsp_off + i, 0)
                    state.stack_bytes[rsp_off + i] = cur ^ key[i]
            continue

        if m == "lea" and len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_REG \
                and ops[1].type == capstone.x86.X86_OP_MEM:
            dst = ins.reg_name(ops[0].reg)
            mem = ops[1].mem
            base = ins.reg_name(mem.base) if mem.base != 0 else None
            idx_name = ins.reg_name(mem.index) if mem.index != 0 else None
            disp = mem.disp
            if base == "rsp" and idx_name is None:
                state.reg_set(dst, ("rsp", disp - state.rsp_delta))
            elif base == "rip" and idx_name is None:
                state.reg_set(dst, ("rip", ins.address + ins.size + disp))
            else:
                state.reg_set(dst, None)
            continue

        if m == "movabs" and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_REG and ops[1].type == capstone.x86.X86_OP_IMM:
            state.reg_set(ins.reg_name(ops[0].reg), ops[1].imm)
            continue

        if m == "mov" and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_REG and ops[1].type == capstone.x86.X86_OP_IMM:
            state.reg_set(ins.reg_name(ops[0].reg), ops[1].imm)
            continue

        if m == "mov" and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_REG and ops[1].type == capstone.x86.X86_OP_REG:
            dst = ins.reg_name(ops[0].reg)
            src = ins.reg_name(ops[1].reg)
            if src == "rsp":
                state.reg_set(dst, ("rsp", -state.rsp_delta))
            else:
                state.reg_set(dst, state.reg_get(src))
            continue

        if m == "mov" and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_REG and ops[1].type == capstone.x86.X86_OP_MEM:
            dst = ins.reg_name(ops[0].reg)
            mem = ops[1].mem
            base = ins.reg_name(mem.base) if mem.base != 0 else None
            disp = mem.disp
            if base == "rip":
                vaddr = ins.address + ins.size + disp
                if vaddr in state.mem_writes:
                    state.reg_set(dst, state.mem_writes[vaddr])
                else:
                    state.reg_set(dst, ("mem", vaddr))
                continue
            if base in ("rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax", "rbx", "rbp",
                        "r10", "r11", "r12", "r13", "r14", "r15"):
                src = state.reg_get(base)
                if src == ("jni_env",) and disp == 0:
                    state.reg_set(dst, ("jni_vtable",))
                    continue
                if src == ("jni_vtable",):
                    state.reg_set(dst, ("jni_fn", disp))
                    continue
                if base == "rsp":
                    val = state.stack_read_qword_ptr(disp - state.rsp_delta)
                    state.reg_set(dst, val)
                    continue
            state.reg_set(dst, None)
            continue

        if m in ("mov", "movups", "movaps") and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_MEM and ops[1].type == capstone.x86.X86_OP_REG:
            mem = ops[0].mem
            base = ins.reg_name(mem.base) if mem.base != 0 else None
            disp = mem.disp
            src_name = ins.reg_name(ops[1].reg)
            src_val = state.reg_get(src_name)
            size = _REG_SIZE.get(src_name, 8)
            if base == "rsp":
                rsp_off = disp - state.rsp_delta
                if size == 8 and _is_ptr(src_val):
                    state.stack_write_ptr(rsp_off, src_val)
                elif isinstance(src_val, int):
                    state.stack_write_bytes(rsp_off, _imm_bytes(src_val, size))
                elif isinstance(src_val, bytes):
                    state.stack_write_bytes(rsp_off, src_val[:size])
                else:
                    for i in range(size):
                        state.stack_bytes.pop(rsp_off + i, None)
                    state.stack_ptrs.pop(rsp_off, None)
                continue
            if base == "rip" and size == 8:
                vaddr = ins.address + ins.size + disp
                state.mem_writes[vaddr] = src_val
                continue
            continue

        if m == "mov" and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_MEM and ops[1].type == capstone.x86.X86_OP_IMM:
            mem = ops[0].mem
            base = ins.reg_name(mem.base) if mem.base != 0 else None
            disp = mem.disp
            size = ops[0].size
            imm = ops[1].imm
            if base == "rsp":
                state.stack_write_bytes(disp - state.rsp_delta, _imm_bytes(imm, size))
            continue

        if m in ("movups", "movaps") and len(ops) == 2 \
                and ops[0].type == capstone.x86.X86_OP_REG and ops[1].type == capstone.x86.X86_OP_MEM:
            dst = ins.reg_name(ops[0].reg)
            mem = ops[1].mem
            base = ins.reg_name(mem.base) if mem.base != 0 else None
            disp = mem.disp
            if base == "rip":
                vaddr = ins.address + ins.size + disp
                data = state.read_section_bytes(vaddr, 16) or b""
                state.reg_set(dst, data)
                continue
            if base == "rsp":
                rsp_off = disp - state.rsp_delta
                buf = bytearray()
                for i in range(16):
                    buf.append(state.stack_bytes.get(rsp_off + i, 0))
                state.reg_set(dst, bytes(buf))
                continue
            state.reg_set(dst, None)
            continue

        if m == "call" and len(ops) == 1 and ops[0].type == capstone.x86.X86_OP_MEM:
            mem = ops[0].mem
            base = ins.reg_name(mem.base) if mem.base != 0 else None
            disp = mem.disp
            if base in ("rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp",
                        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"):
                base_val = state.reg_get(base)
                if base_val == ("jni_vtable",):
                    args = [state.reg_get(r) for r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")]
                    call = JNICall(insn_addr=ins.address, vtable_offset=disp, args=args)
                    state.calls.append(call)
                    state.reg_set("rax", ("jni_result", len(state.calls) - 1))
                    continue
            state.reg_set("rax", None)
            continue

        if m == "call" and len(ops) == 1 and ops[0].type == capstone.x86.X86_OP_REG:
            reg_name = ins.reg_name(ops[0].reg)
            base_val = state.reg_get(reg_name)
            if isinstance(base_val, tuple) and base_val[0] == "jni_fn":
                vt_off = base_val[1]
                args = [state.reg_get(r) for r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")]
                call = JNICall(insn_addr=ins.address, vtable_offset=vt_off, args=args)
                state.calls.append(call)
                state.reg_set("rax", ("jni_result", len(state.calls) - 1))
                continue
            state.reg_set("rax", None)
            continue

        if m == "call" and len(ops) == 1 and ops[0].type == capstone.x86.X86_OP_IMM:
            target = ops[0].imm
            inlined = _inline_helper(state, target)
            if not inlined:
                state.calls.append(JNICall(insn_addr=ins.address, vtable_offset=-1, args=[target]))
                state.reg_set("rax", ("jni_result", len(state.calls) - 1))
            for caller_saved in ("rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"):
                if caller_saved not in ("rdi",):
                    pass
            continue

        if m == "xchg":
            continue

        if len(ops) >= 1 and ops[0].type == capstone.x86.X86_OP_REG:
            dst_name = ins.reg_name(ops[0].reg)
            if dst_name in _PARENT:
                state.reg_set(dst_name, None)

    return state
