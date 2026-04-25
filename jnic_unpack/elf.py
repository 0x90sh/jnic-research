from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class Section:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    bind: int
    type_: int
    shndx: int


@dataclass
class ELF:
    data: bytes
    sections: list[Section]
    sym_dyn: list[Symbol]

    def vaddr_to_off(self, vaddr: int) -> int | None:
        for s in self.sections:
            if s.size > 0 and s.addr <= vaddr < s.addr + s.size:
                return s.offset + (vaddr - s.addr)
        return None

    def section(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def find_export(self, name: str) -> Symbol | None:
        for sym in self.sym_dyn:
            if sym.name == name:
                return sym
        return None


def parse(data: bytes) -> ELF:
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF")
    if data[4] != 2:
        raise ValueError("only 64-bit ELFs supported")
    if data[5] != 1:
        raise ValueError("only little-endian ELFs supported")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3a)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3c)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3e)[0]
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
    sections: list[Section] = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_info = \
            struct.unpack_from("<IIQQQQII", data, base)
        name_end = data.index(b"\x00", shstr_off + sh_name)
        name = data[shstr_off + sh_name:name_end].decode("ascii", errors="replace")
        sections.append(Section(name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_info))
    sym_dyn: list[Symbol] = []
    dynsym = next((s for s in sections if s.sh_type == 11), None)
    dynstr = sections[dynsym.link] if dynsym else None
    if dynsym and dynstr:
        n = dynsym.size // 24
        for i in range(n):
            base = dynsym.offset + i * 24
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", data, base)
            bind = st_info >> 4
            type_ = st_info & 0xF
            ne = data.index(b"\x00", dynstr.offset + st_name)
            name = data[dynstr.offset + st_name:ne].decode("ascii", errors="replace")
            sym_dyn.append(Symbol(name, st_value, st_size, bind, type_, st_shndx))
    return ELF(data=data, sections=sections, sym_dyn=sym_dyn)
