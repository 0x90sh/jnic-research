from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterable

from . import elf, jni_table, x86_sim


@dataclass
class RegisteredNative:
    method_name: str
    signature: str
    fn_vaddr: int


@dataclass
class JNITrace:
    fn_vaddr: int
    method_name: str
    signature: str
    calls: list[dict] = field(default_factory=list)
    has_branches: bool = False
    has_indirect_jump: bool = False


def analyze_elf_x64(binary: bytes, class_internal: str, bootstrap_symbol: str) -> tuple[list[RegisteredNative], list[JNITrace]]:
    e = elf.parse(binary)

    boot_sym = e.find_export(bootstrap_symbol)
    if boot_sym is None:
        raise ValueError(f"bootstrap symbol {bootstrap_symbol!r} not found")

    section_lookup = _make_section_lookup(e)

    text = e.section(".text")
    text_range = (text.addr, text.addr + text.size) if text else None

    boot_off = e.vaddr_to_off(boot_sym.value)
    boot_code = binary[boot_off:boot_off + boot_sym.size]
    state = x86_sim.simulate(binary, section_lookup, boot_sym.value, boot_code,
                              text_range=text_range)

    natives = _extract_register_natives(state)

    traces: list[JNITrace] = []
    for n in natives:
        fn_off = e.vaddr_to_off(n.fn_vaddr)
        if fn_off is None:
            continue
        text = e.section(".text")
        if text and text.offset <= fn_off < text.offset + text.size:
            max_len = text.offset + text.size - fn_off
        else:
            max_len = 0x4000
        fn_bytes = binary[fn_off:fn_off + max_len]
        arg_types = _parse_args_for_sig(n.signature)
        fn_state = x86_sim.simulate(binary, section_lookup, n.fn_vaddr, fn_bytes,
                                     text_range=text_range,
                                     java_arg_types=arg_types,
                                     is_static=False)
        trace = _build_trace(fn_state, n, e)
        traces.append(trace)

    return natives, traces


def _parse_args_for_sig(sig: str) -> list[str]:
    if not sig.startswith("("):
        return []
    end = sig.index(")")
    inner = sig[1:end]
    out: list[str] = []
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch == "L":
            j = inner.index(";", i)
            out.append(inner[i:j + 1])
            i = j + 1
        elif ch == "[":
            j = i
            while inner[j] == "[":
                j += 1
            if inner[j] == "L":
                j = inner.index(";", j)
            out.append(inner[i:j + 1])
            i = j + 1
        else:
            out.append(ch)
            i += 1
    return out


def _make_section_lookup(e: elf.ELF):
    def lookup(vaddr: int) -> tuple[int, int] | None:
        for s in e.sections:
            if s.size > 0 and s.addr <= vaddr < s.addr + s.size:
                return (s.offset + (vaddr - s.addr), s.size - (vaddr - s.addr))
        return None
    return lookup


def _resolve_arg(state: x86_sim.State, arg, depth: int = 0) -> object:
    if depth > 6:
        return arg
    if isinstance(arg, tuple):
        if arg[0] == "rsp":
            return ("string", state.stack_read_cstring(arg[1]))
        if arg[0] == "frozen_string":
            return ("string", arg[1])
        if arg[0] == "rip":
            s = state.read_section_cstring(arg[1])
            return ("string", s) if s is not None else ("rip", arg[1])
        if arg[0] == "mem":
            vaddr = arg[1]
            cached = state.mem_writes.get(vaddr)
            if cached is not None:
                return ("cached", _describe_cached(state, cached, depth + 1))
            return arg
        if arg[0] == "jni_result":
            return ("cached", _describe_cached(state, arg, depth + 1))
        return arg
    return arg


def _describe_cached(state: x86_sim.State, val, depth: int = 0) -> dict:
    if isinstance(val, tuple) and val[0] == "jni_result":
        idx = val[1]
        if 0 <= idx < len(state.calls):
            c = state.calls[idx]
            from . import jni_table
            jname = jni_table.name_for_offset(c.vtable_offset)
            args = [_resolve_arg(state, a, depth + 1) for a in c.args]
            out = {"from": jname, "args": args}
            if jname == "NewString":
                ns = _extract_newstring(state, c)
                if ns is not None:
                    out["newstring"] = ns
            return out
    return {"from": "unknown", "args": []}


def _extract_newstring(state, c) -> str | None:
    ptr_arg = c.args[1] if len(c.args) > 1 else None
    len_arg = c.args[2] if len(c.args) > 2 else None
    if isinstance(ptr_arg, tuple) and ptr_arg[0] == "rsp" and isinstance(len_arg, int):
        rsp_off = ptr_arg[1]
        chars = []
        for i in range(len_arg):
            lo = state.stack_bytes.get(rsp_off + i * 2, 0)
            hi = state.stack_bytes.get(rsp_off + i * 2 + 1, 0)
            chars.append(lo | (hi << 8))
        return "".join(chr(c) for c in chars)
    return None


def _extract_register_natives(state: x86_sim.State) -> list[RegisteredNative]:
    register_natives_offset = next(
        (off for off, name in jni_table.OFFSET_TO_NAME.items() if name == "RegisterNatives"),
        0x6B8,
    )

    out: list[RegisteredNative] = []
    for call in state.calls:
        if call.vtable_offset != register_natives_offset:
            continue
        methods_arg = call.args[2]
        count_arg = call.args[3]
        if not isinstance(count_arg, int):
            continue
        if not (isinstance(methods_arg, tuple) and methods_arg[0] == "rsp"):
            continue
        base = methods_arg[1]
        for i in range(count_arg):
            entry_off = base + i * 24
            name_ptr = state.stack_ptrs.get(entry_off)
            sig_ptr = state.stack_ptrs.get(entry_off + 8)
            fn_ptr = state.stack_ptrs.get(entry_off + 16)
            if not (isinstance(name_ptr, tuple) and isinstance(sig_ptr, tuple) and isinstance(fn_ptr, tuple)):
                continue
            name = _resolve_pointer_string(state, name_ptr)
            sig = _resolve_pointer_string(state, sig_ptr)
            fn_vaddr = _resolve_pointer_address(fn_ptr)
            if name is None or sig is None or fn_vaddr is None:
                continue
            out.append(RegisteredNative(method_name=name, signature=sig, fn_vaddr=fn_vaddr))
    return out


def _resolve_pointer_string(state: x86_sim.State, ptr: tuple) -> str | None:
    if ptr[0] == "rsp":
        return state.stack_read_cstring(ptr[1])
    if ptr[0] == "rip":
        return state.read_section_cstring(ptr[1])
    return None


def _resolve_pointer_address(ptr: tuple) -> int | None:
    if ptr[0] == "rip":
        return ptr[1]
    return None


def _build_trace(fn_state: x86_sim.State, n: RegisteredNative, e=None) -> JNITrace:
    trace = JNITrace(fn_vaddr=n.fn_vaddr, method_name=n.method_name, signature=n.signature,
                      has_branches=fn_state.saw_real_branch,
                      has_indirect_jump=fn_state.saw_indirect_jump)
    for call in fn_state.calls:
        if call.vtable_offset == -1:
            trace.calls.append({"call": "helper", "target": call.args[0]})
            continue
        jni_name = jni_table.name_for_offset(call.vtable_offset)
        resolved = [_resolve_arg(fn_state, a) for a in call.args]
        if jni_name == "NewString":
            ptr_arg = call.args[1]
            len_arg = call.args[2]
            wide_str = None
            if isinstance(ptr_arg, tuple) and ptr_arg[0] == "rsp" and isinstance(len_arg, int):
                rsp_off = ptr_arg[1]
                jchars = []
                for i in range(len_arg):
                    lo = fn_state.stack_bytes.get(rsp_off + i * 2, 0)
                    hi = fn_state.stack_bytes.get(rsp_off + i * 2 + 1, 0)
                    jchars.append(lo | (hi << 8))
                wide_str = "".join(chr(c) for c in jchars)
            trace.calls.append({"call": jni_name, "args": resolved, "newstring": wide_str})
            continue
        trace.calls.append({"call": jni_name, "args": resolved})
    return trace
