from __future__ import annotations

import struct
from dataclasses import dataclass

from . import classfile


@dataclass
class PlatformSlice:
    os_substr: str
    arch: str
    start: int
    end: int

    def label(self) -> str:
        os_map = {"win": "windows", "mac": "macos", "lin": "linux"}
        arch_map = {"amd64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64"}
        return f"{os_map.get(self.os_substr, self.os_substr)}_{arch_map.get(self.arch, self.arch)}"


@dataclass
class LoaderInfo:
    dat_resource_path: str
    slices: list[PlatformSlice]
    loader_class_internal: str
    runtime_classes_internal: list[str]


def parse_loader(cf: classfile.ClassFile) -> LoaderInfo:
    clinit = _find_clinit(cf)
    if clinit is None:
        raise ValueError("class has no <clinit>")
    code_attr = cf.find_attribute(clinit.attributes, "Code")
    if code_attr is None:
        raise ValueError("<clinit> has no Code attribute")
    code = classfile.parse_code(code_attr.info)

    dat_path = _find_resource_string(cf, code.bytecode)
    slices = _scan_platform_slices(cf, code.bytecode)
    return LoaderInfo(
        dat_resource_path=dat_path,
        slices=slices,
        loader_class_internal=cf.class_name(cf.this_class),
        runtime_classes_internal=[],
    )


def _find_clinit(cf: classfile.ClassFile) -> classfile.Member | None:
    for m in cf.methods:
        if cf.method_name(m) == "<clinit>" and cf.method_descriptor(m) == "()V":
            return m
    return None


def _find_resource_string(cf: classfile.ClassFile, bc: bytes) -> str:
    for op, idx in _walk_ldc_string(cf, bc):
        s = _resolve_string(cf, idx)
        if s and "/dev/jnic/lib/" in s:
            return s
    raise ValueError("no /dev/jnic/lib/*.dat ldc found in <clinit>")


def _walk_ldc_string(cf: classfile.ClassFile, bc: bytes):
    i = 0
    while i < len(bc):
        op = bc[i]
        if op == 0x12:
            yield op, bc[i + 1]
            i += 2
            continue
        if op == 0x13:
            yield op, struct.unpack_from(">H", bc, i + 1)[0]
            i += 3
            continue
        i += _opsize(bc, i)


def _resolve_string(cf: classfile.ClassFile, cp_idx: int) -> str | None:
    e = cf.cp[cp_idx]
    if e is None or e.tag != classfile.CONSTANT_String:
        return None
    (utf8_idx,) = struct.unpack(">H", e.raw)
    return cf.utf8(utf8_idx)


def _scan_platform_slices(cf: classfile.ClassFile, bc: bytes) -> list[PlatformSlice]:
    slices: list[PlatformSlice] = []
    last_os: str | None = None
    last_arch: str | None = None
    pending_long: int | None = None
    pending_start: int | None = None

    i = 0
    while i < len(bc):
        op = bc[i]
        if op in (0x12, 0x13):
            if op == 0x12:
                idx = bc[i + 1]
                step = 2
            else:
                idx = struct.unpack_from(">H", bc, i + 1)[0]
                step = 3
            s = _resolve_string(cf, idx)
            if s is not None:
                if s in ("win", "mac", "lin"):
                    last_os = s
                elif s in ("x86_64", "amd64", "aarch64", "arm64"):
                    last_arch = s
            i += step
            continue
        if op == 0x14:
            idx = struct.unpack_from(">H", bc, i + 1)[0]
            e = cf.cp[idx]
            if e is not None and e.tag == classfile.CONSTANT_Long:
                hi, lo = struct.unpack(">II", e.raw)
                val = (hi << 32) | lo
                if val >= (1 << 63):
                    val -= (1 << 64)
                pending_long = val
            i += 3
            continue
        if op == 0x41:
            if pending_long is not None:
                pending_start = pending_long
                pending_long = None
            i += 1
            continue
        if op == 0x37:
            local = bc[i + 1]
            if pending_long is not None and local == 4:
                if pending_start is not None and last_os and last_arch:
                    slices.append(PlatformSlice(
                        os_substr=last_os,
                        arch=last_arch,
                        start=pending_start,
                        end=pending_long,
                    ))
                pending_start = None
                pending_long = None
            elif pending_long is not None:
                pending_long = None
            i += 2
            continue

        i += _opsize(bc, i)

    seen = set()
    deduped = []
    for sl in slices:
        key = (sl.os_substr, sl.arch, sl.start, sl.end)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(sl)
    return deduped


_FIXED_SIZE = {
    **{op: 1 for op in (
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22,
        0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
        0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
        0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71,
        0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C,
        0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83,
        0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
        0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xBE, 0xBF, 0xC2, 0xC3,
    )},
    0x10: 2,
    0x11: 3,
    0x12: 2,
    0x13: 3,
    0x14: 3,
    0x15: 2, 0x16: 2, 0x17: 2,
    0x36: 2, 0x37: 2, 0x38: 2, 0x39: 2, 0x3A: 2,
    0x84: 3,
    0x99: 3, 0x9A: 3, 0x9B: 3, 0x9C: 3, 0x9D: 3, 0x9E: 3,
    0x9F: 3, 0xA0: 3, 0xA1: 3, 0xA2: 3, 0xA3: 3, 0xA4: 3,
    0xA5: 3, 0xA6: 3, 0xA7: 3, 0xA8: 3,
    0xB2: 3, 0xB3: 3, 0xB4: 3, 0xB5: 3,
    0xB6: 3, 0xB7: 3, 0xB8: 3,
    0xBB: 3,
    0xBC: 2,
    0xBD: 3,
    0xC0: 3, 0xC1: 3,
    0xC5: 4,
    0xC6: 3, 0xC7: 3,
    0xB9: 5,
    0xBA: 5,
    0xC8: 5,
    0xC9: 5,
}


def _opsize(bc: bytes, pos: int) -> int:
    op = bc[pos]
    if op == 0xAA:
        p = pos + 1
        while (p % 4) != 0:
            p += 1
        low = struct.unpack_from(">i", bc, p + 4)[0]
        high = struct.unpack_from(">i", bc, p + 8)[0]
        n = high - low + 1
        return (p + 12 + n * 4) - pos
    if op == 0xAB:
        p = pos + 1
        while (p % 4) != 0:
            p += 1
        npairs = struct.unpack_from(">I", bc, p + 4)[0]
        return (p + 8 + npairs * 8) - pos
    if op == 0xC4:
        next_op = bc[pos + 1]
        if next_op == 0x84:
            return 6
        return 4
    return _FIXED_SIZE.get(op, 1)
