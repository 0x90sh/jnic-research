from __future__ import annotations

import io
import struct
from dataclasses import dataclass, field
from typing import Optional

CONSTANT_Utf8 = 1
CONSTANT_Integer = 3
CONSTANT_Float = 4
CONSTANT_Long = 5
CONSTANT_Double = 6
CONSTANT_Class = 7
CONSTANT_String = 8
CONSTANT_Fieldref = 9
CONSTANT_Methodref = 10
CONSTANT_InterfaceMethodref = 11
CONSTANT_NameAndType = 12
CONSTANT_MethodHandle = 15
CONSTANT_MethodType = 16
CONSTANT_Dynamic = 17
CONSTANT_InvokeDynamic = 18
CONSTANT_Module = 19
CONSTANT_Package = 20

ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_SUPER = 0x0020
ACC_SYNCHRONIZED = 0x0020
ACC_VOLATILE = 0x0040
ACC_TRANSIENT = 0x0080
ACC_NATIVE = 0x0100
ACC_INTERFACE = 0x0200
ACC_ABSTRACT = 0x0400
ACC_STRICT = 0x0800
ACC_SYNTHETIC = 0x1000


@dataclass
class CPEntry:
    tag: int
    raw: bytes


@dataclass
class Attribute:
    name_index: int
    info: bytes


@dataclass
class Member:
    access_flags: int
    name_index: int
    descriptor_index: int
    attributes: list[Attribute] = field(default_factory=list)


@dataclass
class ClassFile:
    magic: int
    minor: int
    major: int
    cp: list[Optional[CPEntry]]
    access_flags: int
    this_class: int
    super_class: int
    interfaces: list[int]
    fields: list[Member]
    methods: list[Member]
    attributes: list[Attribute]

    def utf8(self, idx: int) -> str:
        e = self.cp[idx]
        assert e is not None and e.tag == CONSTANT_Utf8, f"cp#{idx} not utf8"
        return _decode_modified_utf8(e.raw)

    def class_name(self, idx: int) -> str:
        e = self.cp[idx]
        assert e is not None and e.tag == CONSTANT_Class
        (name_idx,) = struct.unpack(">H", e.raw)
        return self.utf8(name_idx)

    def method_name(self, m: Member) -> str:
        return self.utf8(m.name_index)

    def method_descriptor(self, m: Member) -> str:
        return self.utf8(m.descriptor_index)

    def find_attribute(self, attrs: list[Attribute], name: str) -> Optional[Attribute]:
        for a in attrs:
            if self.utf8(a.name_index) == name:
                return a
        return None

    def add_utf8(self, value: str) -> int:
        encoded = _encode_modified_utf8(value)
        for i, e in enumerate(self.cp):
            if e is not None and e.tag == CONSTANT_Utf8 and e.raw == encoded:
                return i
        self.cp.append(CPEntry(CONSTANT_Utf8, encoded))
        return len(self.cp) - 1

    def add_class(self, internal_name: str) -> int:
        name_idx = self.add_utf8(internal_name)
        for i, e in enumerate(self.cp):
            if e is not None and e.tag == CONSTANT_Class and struct.unpack(">H", e.raw)[0] == name_idx:
                return i
        self.cp.append(CPEntry(CONSTANT_Class, struct.pack(">H", name_idx)))
        return len(self.cp) - 1

    def add_string(self, value: str) -> int:
        utf8_idx = self.add_utf8(value)
        for i, e in enumerate(self.cp):
            if e is not None and e.tag == CONSTANT_String and struct.unpack(">H", e.raw)[0] == utf8_idx:
                return i
        self.cp.append(CPEntry(CONSTANT_String, struct.pack(">H", utf8_idx)))
        return len(self.cp) - 1

    def add_name_and_type(self, name: str, descriptor: str) -> int:
        name_idx = self.add_utf8(name)
        desc_idx = self.add_utf8(descriptor)
        target = struct.pack(">HH", name_idx, desc_idx)
        for i, e in enumerate(self.cp):
            if e is not None and e.tag == CONSTANT_NameAndType and e.raw == target:
                return i
        self.cp.append(CPEntry(CONSTANT_NameAndType, target))
        return len(self.cp) - 1

    def add_methodref(self, owner: str, name: str, descriptor: str) -> int:
        cls_idx = self.add_class(owner)
        nt_idx = self.add_name_and_type(name, descriptor)
        target = struct.pack(">HH", cls_idx, nt_idx)
        for i, e in enumerate(self.cp):
            if e is not None and e.tag == CONSTANT_Methodref and e.raw == target:
                return i
        self.cp.append(CPEntry(CONSTANT_Methodref, target))
        return len(self.cp) - 1

    def add_fieldref(self, owner: str, name: str, descriptor: str) -> int:
        cls_idx = self.add_class(owner)
        nt_idx = self.add_name_and_type(name, descriptor)
        target = struct.pack(">HH", cls_idx, nt_idx)
        for i, e in enumerate(self.cp):
            if e is not None and e.tag == CONSTANT_Fieldref and e.raw == target:
                return i
        self.cp.append(CPEntry(CONSTANT_Fieldref, target))
        return len(self.cp) - 1


def parse(data: bytes) -> ClassFile:
    r = _Reader(data)
    magic = r.u4()
    if magic != 0xCAFEBABE:
        raise ValueError(f"not a class file (bad magic 0x{magic:08x})")
    minor = r.u2()
    major = r.u2()
    cp_count = r.u2()
    cp: list[Optional[CPEntry]] = [None]
    i = 1
    while i < cp_count:
        tag = r.u1()
        size = _cp_payload_size(tag, r)
        raw = r.bytes(size)
        cp.append(CPEntry(tag, raw))
        if tag in (CONSTANT_Long, CONSTANT_Double):
            cp.append(None)
            i += 2
        else:
            i += 1
    access_flags = r.u2()
    this_class = r.u2()
    super_class = r.u2()
    interfaces = [r.u2() for _ in range(r.u2())]
    fields = [_read_member(r) for _ in range(r.u2())]
    methods = [_read_member(r) for _ in range(r.u2())]
    attributes = [_read_attribute(r) for _ in range(r.u2())]
    return ClassFile(magic, minor, major, cp, access_flags, this_class, super_class,
                     interfaces, fields, methods, attributes)


def _cp_payload_size(tag: int, r: "_Reader") -> int:
    if tag == CONSTANT_Utf8:
        length = struct.unpack(">H", r.peek(2))[0]
        return 2 + length
    return {
        CONSTANT_Integer: 4,
        CONSTANT_Float: 4,
        CONSTANT_Long: 8,
        CONSTANT_Double: 8,
        CONSTANT_Class: 2,
        CONSTANT_String: 2,
        CONSTANT_Fieldref: 4,
        CONSTANT_Methodref: 4,
        CONSTANT_InterfaceMethodref: 4,
        CONSTANT_NameAndType: 4,
        CONSTANT_MethodHandle: 3,
        CONSTANT_MethodType: 2,
        CONSTANT_Dynamic: 4,
        CONSTANT_InvokeDynamic: 4,
        CONSTANT_Module: 2,
        CONSTANT_Package: 2,
    }[tag]


def _read_member(r: "_Reader") -> Member:
    access_flags = r.u2()
    name_index = r.u2()
    descriptor_index = r.u2()
    attributes = [_read_attribute(r) for _ in range(r.u2())]
    return Member(access_flags, name_index, descriptor_index, attributes)


def _read_attribute(r: "_Reader") -> Attribute:
    name_index = r.u2()
    length = r.u4()
    info = r.bytes(length)
    return Attribute(name_index, info)


def serialize(cf: ClassFile) -> bytes:
    w = io.BytesIO()
    w.write(struct.pack(">IHH", cf.magic, cf.minor, cf.major))
    w.write(struct.pack(">H", len(cf.cp)))
    i = 1
    while i < len(cf.cp):
        e = cf.cp[i]
        assert e is not None
        w.write(struct.pack(">B", e.tag))
        w.write(e.raw)
        if e.tag in (CONSTANT_Long, CONSTANT_Double):
            i += 2
        else:
            i += 1
    w.write(struct.pack(">HHH", cf.access_flags, cf.this_class, cf.super_class))
    w.write(struct.pack(">H", len(cf.interfaces)))
    for iface in cf.interfaces:
        w.write(struct.pack(">H", iface))
    _write_members(w, cf.fields)
    _write_members(w, cf.methods)
    _write_attrs(w, cf.attributes)
    return w.getvalue()


def _write_members(w: io.BytesIO, members: list[Member]) -> None:
    w.write(struct.pack(">H", len(members)))
    for m in members:
        w.write(struct.pack(">HHH", m.access_flags, m.name_index, m.descriptor_index))
        _write_attrs(w, m.attributes)


def _write_attrs(w: io.BytesIO, attrs: list[Attribute]) -> None:
    w.write(struct.pack(">H", len(attrs)))
    for a in attrs:
        w.write(struct.pack(">HI", a.name_index, len(a.info)))
        w.write(a.info)


@dataclass
class Code:
    max_stack: int
    max_locals: int
    bytecode: bytes
    exceptions: bytes
    attributes: list[Attribute]

    def serialize(self) -> bytes:
        w = io.BytesIO()
        w.write(struct.pack(">HH", self.max_stack, self.max_locals))
        w.write(struct.pack(">I", len(self.bytecode)))
        w.write(self.bytecode)
        w.write(self.exceptions)
        _write_attrs(w, self.attributes)
        return w.getvalue()


def parse_code(info: bytes) -> Code:
    r = _Reader(info)
    max_stack = r.u2()
    max_locals = r.u2()
    code_length = r.u4()
    bytecode = r.bytes(code_length)
    et_count = r.u2()
    exceptions = struct.pack(">H", et_count) + r.bytes(et_count * 8)
    attrs = [_read_attribute(r) for _ in range(r.u2())]
    return Code(max_stack, max_locals, bytecode, exceptions, attrs)


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def u1(self) -> int:
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u2(self) -> int:
        v = struct.unpack_from(">H", self.data, self.pos)[0]
        self.pos += 2
        return v

    def u4(self) -> int:
        v = struct.unpack_from(">I", self.data, self.pos)[0]
        self.pos += 4
        return v

    def bytes(self, n: int) -> bytes:
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v

    def peek(self, n: int) -> bytes:
        return self.data[self.pos:self.pos + n]


def _decode_modified_utf8(b: bytes) -> str:
    (length,) = struct.unpack_from(">H", b, 0)
    payload = b[2:2 + length]
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload.decode("latin-1")


def _encode_modified_utf8(s: str) -> bytes:
    encoded = s.encode("utf-8")
    if len(encoded) > 0xFFFF:
        raise ValueError("utf8 too long for cp entry")
    return struct.pack(">H", len(encoded)) + encoded
