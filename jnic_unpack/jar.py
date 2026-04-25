from __future__ import annotations

import zipfile
from dataclasses import dataclass


@dataclass
class JarEntry:
    name: str
    data: bytes


def read_jar(path: str) -> list[JarEntry]:
    out: list[JarEntry] = []
    with zipfile.ZipFile(path, "r") as zf:
        for info in zf.infolist():
            out.append(JarEntry(name=info.filename, data=zf.read(info.filename)))
    return out


def write_jar(path: str, entries: list[JarEntry]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for e in entries:
            zf.writestr(e.name, e.data)
