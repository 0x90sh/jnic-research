from __future__ import annotations

import json
import os
from dataclasses import dataclass

from . import carve, classfile, elf, jar, jni_mangle, loader_parse, native_analyze


@dataclass
class JarContext:
    entries: list[jar.JarEntry]
    loader_class: str
    loader_info: loader_parse.LoaderInfo
    blob: bytes
    binaries: list[carve.CarvedBinary]
    protected_classes: list[tuple[str, classfile.ClassFile]]


def load_jar_context(input_jar: str) -> JarContext:
    entries = jar.read_jar(input_jar)
    by_name = {e.name: e for e in entries}
    loader_class, loader_cf = _find_loader(entries)
    if loader_class is None:
        raise RuntimeError("input jar doesn't look JNIC-protected")
    info = loader_parse.parse_loader(loader_cf)
    dat_path = info.dat_resource_path.lstrip("/")
    dat_entry = by_name.get(dat_path)
    if dat_entry is None:
        raise RuntimeError(f"loader points to {dat_path!r} but the jar doesn't contain it")
    blob = carve.decompress_blob(dat_entry.data)
    binaries = carve.carve(blob, info)
    protected: list[tuple[str, classfile.ClassFile]] = []
    for e in entries:
        if not e.name.endswith(".class"):
            continue
        if e.name.startswith(os.path.dirname("dev/jnic/" + info.loader_class_internal.split("/")[-2]) + "/"):
            continue
        if e.name.endswith("JNICLoader.class"):
            continue
        cf = classfile.parse(e.data)
        if any(cf.method_name(m) == "$jnicLoader" and (m.access_flags & classfile.ACC_NATIVE) for m in cf.methods):
            protected.append((e.name, cf))
    return JarContext(entries=entries, loader_class=loader_class, loader_info=info,
                      blob=blob, binaries=binaries, protected_classes=protected)


def _find_loader(entries):
    for e in entries:
        if not e.name.endswith("JNICLoader.class"):
            continue
        try:
            cf = classfile.parse(e.data)
            loader_parse.parse_loader(cf)
        except Exception:
            continue
        return cf.class_name(cf.this_class), cf
    return None, None


def dump_strings(ctx: JarContext) -> dict:
    out: dict = {"per_class": {}, "all_strings": []}
    lin_x64 = next((b for b in ctx.binaries if b.slice_.label() == "linux_x86_64" and b.kind == "elf"), None)
    if not lin_x64:
        return out
    seen: set[str] = set()
    for jar_name, cf in ctx.protected_classes:
        class_internal = cf.class_name(cf.this_class)
        symbol = jni_mangle.mangle(class_internal, "$jnicLoader")
        try:
            natives, traces = native_analyze.analyze_elf_x64(lin_x64.data, class_internal, symbol)
        except ValueError:
            continue
        cls_strings: list[str] = []
        for t in traces:
            for c in t.calls:
                ns = c.get("newstring")
                if ns is not None:
                    cls_strings.append(ns)
                    seen.add(ns)
                for arg in c.get("args", []) or []:
                    if isinstance(arg, tuple) and arg[0] == "string" and arg[1]:
                        cls_strings.append(arg[1])
                        seen.add(arg[1])
        out["per_class"][class_internal] = sorted(set(cls_strings))
    out["all_strings"] = sorted(seen)
    return out


def dump_traces(ctx: JarContext) -> dict:
    out: dict = {"per_class": {}}
    lin_x64 = next((b for b in ctx.binaries if b.slice_.label() == "linux_x86_64" and b.kind == "elf"), None)
    if not lin_x64:
        return out
    for jar_name, cf in ctx.protected_classes:
        class_internal = cf.class_name(cf.this_class)
        symbol = jni_mangle.mangle(class_internal, "$jnicLoader")
        try:
            natives, traces = native_analyze.analyze_elf_x64(lin_x64.data, class_internal, symbol)
        except ValueError:
            continue
        cls_data = {"natives": [], "methods": {}}
        for n in natives:
            cls_data["natives"].append({
                "method": n.method_name,
                "signature": n.signature,
                "fn_vaddr": f"0x{n.fn_vaddr:x}",
            })
        for t in traces:
            cls_data["methods"][f"{t.method_name}{t.signature}"] = {
                "fn_vaddr": f"0x{t.fn_vaddr:x}",
                "calls": [_serialize_call(c) for c in t.calls],
            }
        out["per_class"][class_internal] = cls_data
    return out


def _serialize_call(c: dict) -> dict:
    return {
        "call": c.get("call"),
        "args": [_arg_repr(a) for a in c.get("args", []) or []],
        "newstring": c.get("newstring"),
    }


def _arg_repr(a) -> object:
    if isinstance(a, tuple):
        if a[0] == "string":
            return {"string": a[1]}
        if a[0] == "cached":
            inner = a[1]
            return {"from": inner.get("from"),
                    "args": [_arg_repr(x) for x in inner.get("args", [])]}
        if a[0] == "frozen_string":
            return {"string": a[1]}
        return {"tag": a[0], "value": a[1] if len(a) > 1 else None}
    return a


def write_natives(ctx: JarContext, natives_dir: str) -> list[dict]:
    os.makedirs(natives_dir, exist_ok=True)
    out: list[dict] = []
    for b in ctx.binaries:
        ext = {"elf": ".so", "macho": ".dylib", "pe": ".dll"}.get(b.kind, ".bin")
        path = os.path.join(natives_dir, b.slice_.label() + ext)
        with open(path, "wb") as f:
            f.write(b.data)
        out.append({"path": path, "kind": b.kind, "size": len(b.data),
                    "platform": b.slice_.label()})
    return out
