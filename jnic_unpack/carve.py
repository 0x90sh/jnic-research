from __future__ import annotations

import lzma
from dataclasses import dataclass

from .loader_parse import LoaderInfo, PlatformSlice


@dataclass
class CarvedBinary:
    slice_: PlatformSlice
    data: bytes

    @property
    def kind(self) -> str:
        if self.data.startswith(b"\x7fELF"):
            return "elf"
        if self.data.startswith(b"MZ"):
            return "pe"
        if self.data.startswith(b"\xcf\xfa\xed\xfe") or self.data.startswith(b"\xfe\xed\xfa\xcf"):
            return "macho"
        return "unknown"


def decompress_blob(dat: bytes, max_dict_size: int = 1 << 26) -> bytes:
    last_error: Exception | None = None
    for ds in (1 << 20, 1 << 22, 1 << 24, 1 << 26, 1 << 30):
        if ds > max_dict_size and ds != (1 << 20):
            continue
        try:
            d = lzma.LZMADecompressor(
                format=lzma.FORMAT_RAW,
                filters=[{"id": lzma.FILTER_LZMA2, "dict_size": ds}],
            )
            out = d.decompress(dat)
            if d.eof:
                return out
        except lzma.LZMAError as exc:
            last_error = exc
    raise RuntimeError(f"LZMA2 decompression failed (last error: {last_error})")


def carve(decompressed: bytes, info: LoaderInfo) -> list[CarvedBinary]:
    out: list[CarvedBinary] = []
    for sl in info.slices:
        if sl.end > len(decompressed):
            continue
        chunk = decompressed[sl.start:sl.end]
        out.append(CarvedBinary(slice_=sl, data=chunk))
    return out
