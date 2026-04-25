from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from typing import Iterable

from . import classfile, carve, jar, jni_mangle, loader_parse, native_analyze, strip


@dataclass
class Report:
    input_jar: str
    output_jar: str
    loader_class: str | None
    dat_resource: str | None
    runtime_classes_dropped: list[str]
    natives_carved: list[dict]
    classes_modified: list[dict]
    summary: dict


def deobfuscate(input_jar: str, output_jar: str,
                natives_dir: str | None = None,
                stub_unlifted: bool = False) -> Report:
    entries = jar.read_jar(input_jar)
    by_name = {e.name: e for e in entries}

    loader_class_internal, loader_cf = _find_loader(entries)
    if loader_class_internal is None:
        raise RuntimeError("input jar doesn't look JNIC-protected (no JNICLoader class found)")

    loader_info = loader_parse.parse_loader(loader_cf)

    dat_path = loader_info.dat_resource_path.lstrip("/")
    dat_entry = by_name.get(dat_path)
    if dat_entry is None:
        raise RuntimeError(f"loader points to {dat_path!r} but the jar doesn't contain it")
    blob = carve.decompress_blob(dat_entry.data)
    binaries = carve.carve(blob, loader_info)

    lin_x64 = next((b for b in binaries if b.slice_.label() == "linux_x86_64" and b.kind == "elf"), None)

    natives_report: list[dict] = []
    traces_by_class_method: dict[str, dict[tuple[str, str], native_analyze.JNITrace]] = {}

    if natives_dir is not None:
        os.makedirs(natives_dir, exist_ok=True)
        for b in binaries:
            ext = {"elf": ".so", "macho": ".dylib", "pe": ".dll"}.get(b.kind, ".bin")
            out_path = os.path.join(natives_dir, b.slice_.label() + ext)
            with open(out_path, "wb") as f:
                f.write(b.data)
            natives_report.append({"path": out_path, "kind": b.kind, "size": len(b.data),
                                    "platform": b.slice_.label()})

    protected_classes: list[tuple[str, classfile.ClassFile]] = []
    for e in entries:
        if not e.name.endswith(".class"):
            continue
        if e.name.startswith("dev/jnic/JmEMUM/") or e.name == "dev/jnic/JmEMUM/JNICLoader.class":
            continue
        cf = classfile.parse(e.data)
        if not _has_jnic_loader_marker(cf):
            continue
        protected_classes.append((e.name, cf))

    if lin_x64 is not None:
        for jar_name, cf in protected_classes:
            class_internal = cf.class_name(cf.this_class)
            symbol = jni_mangle.mangle(class_internal, "$jnicLoader")
            try:
                natives, traces = native_analyze.analyze_elf_x64(
                    lin_x64.data, class_internal, symbol)
            except ValueError:
                continue
            tm: dict[tuple[str, str], native_analyze.JNITrace] = {}
            for t in traces:
                tm[(t.method_name, t.signature)] = t
            traces_by_class_method[class_internal] = tm

    classes_modified: list[dict] = []
    new_entries: list[jar.JarEntry] = []
    for e in entries:
        if e.name.startswith("dev/jnic/JmEMUM/"):
            continue
        if e.name == dat_path:
            continue
        if not e.name.endswith(".class"):
            new_entries.append(e)
            continue
        cf = classfile.parse(e.data)
        if not _has_jnic_loader_marker(cf):
            new_entries.append(e)
            continue
        class_internal = cf.class_name(cf.this_class)
        traces = traces_by_class_method.get(class_internal, {})
        report = strip.strip_class(cf, traces_by_method=traces,
                                   loader_class_internal=loader_class_internal,
                                   stub_unlifted=stub_unlifted)
        new_data = classfile.serialize(cf)
        new_entries.append(jar.JarEntry(name=e.name, data=new_data))
        classes_modified.append({"class": class_internal, "report": report})

    jar.write_jar(output_jar, new_entries)

    summary = {
        "classes_modified_count": len(classes_modified),
        "lifted_count": sum(len(c["report"]["lifted_methods"]) for c in classes_modified),
        "unlifted_count": sum(len(c["report"]["unlifted_methods"]) for c in classes_modified),
        "stubbed_count": sum(len(c["report"].get("stubbed_methods", [])) for c in classes_modified),
        "platform_binaries_carved": [b.slice_.label() for b in binaries],
    }

    return Report(
        input_jar=input_jar,
        output_jar=output_jar,
        loader_class=loader_class_internal,
        dat_resource=loader_info.dat_resource_path,
        runtime_classes_dropped=[e.name for e in entries
                                 if e.name.startswith("dev/jnic/JmEMUM/")] + [dat_path],
        natives_carved=natives_report,
        classes_modified=classes_modified,
        summary=summary,
    )


def report_json(report: Report) -> str:
    return json.dumps(asdict(report), indent=2)


def _find_loader(entries: list[jar.JarEntry]) -> tuple[str | None, classfile.ClassFile | None]:
    for e in entries:
        if not e.name.endswith("JNICLoader.class"):
            continue
        try:
            cf = classfile.parse(e.data)
        except Exception:
            continue
        try:
            loader_parse.parse_loader(cf)
        except Exception:
            continue
        return cf.class_name(cf.this_class), cf
    return None, None


def _has_jnic_loader_marker(cf: classfile.ClassFile) -> bool:
    for m in cf.methods:
        if cf.method_name(m) == "$jnicLoader" and (m.access_flags & classfile.ACC_NATIVE):
            return True
    return False
