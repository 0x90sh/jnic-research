from __future__ import annotations

import io
import struct

from . import classfile, lift
from .native_analyze import JNITrace


def strip_class(cf: classfile.ClassFile,
                traces_by_method: dict[tuple[str, str], JNITrace] | None = None,
                loader_class_internal: str | None = None,
                stub_unlifted: bool = False) -> dict:
    report: dict = {
        "removed_methods": [],
        "rewrote_clinit": False,
        "removed_clinit": False,
        "lifted_methods": [],
        "unlifted_methods": [],
        "stubbed_methods": [],
    }
    traces_by_method = traces_by_method or {}

    new_methods: list[classfile.Member] = []
    jnic_clinit_lifted: bytes | None = None
    jnic_clinit_max_stack = 0
    for m in cf.methods:
        name = cf.method_name(m)
        if name == "$jnicLoader" and (m.access_flags & classfile.ACC_NATIVE):
            report["removed_methods"].append(name + cf.method_descriptor(m))
            continue
        if name == "$jnicClinit" and (m.access_flags & classfile.ACC_NATIVE):
            trace = traces_by_method.get(("$jnicClinit", "()V"))
            if trace is not None:
                lifted = lift.lift(trace, cf, m)
                if lifted.success:
                    jnic_clinit_lifted = lifted.bytecode
                    jnic_clinit_max_stack = lifted.max_stack
                    report["lifted_methods"].append({
                        "method": ("<clinit>", "()V"),
                        "pattern": lifted.pattern,
                        "reason": f"$jnicClinit body restored: {lifted.reason}",
                    })
                else:
                    report["unlifted_methods"].append({
                        "method": ("$jnicClinit", "()V"),
                        "reason": f"could not lift original <clinit> body: {lifted.reason}",
                    })
            report["removed_methods"].append(name + cf.method_descriptor(m))
            continue
        new_methods.append(m)
    cf.methods = new_methods

    for i, m in enumerate(cf.methods):
        if cf.method_name(m) != "<clinit>":
            continue
        code_attr = cf.find_attribute(m.attributes, "Code")
        if code_attr is None:
            continue
        code = classfile.parse_code(code_attr.info)
        new_bc = _strip_clinit(cf, code.bytecode, loader_class_internal)
        if jnic_clinit_lifted is not None:
            code.bytecode = jnic_clinit_lifted
            code.max_stack = max(code.max_stack, jnic_clinit_max_stack)
            code_attr.info = code.serialize()
            report["rewrote_clinit"] = True
            jnic_clinit_lifted = None
        elif new_bc != code.bytecode:
            if _is_only_return(new_bc):
                report["removed_clinit"] = True
                cf.methods.pop(i)
            else:
                code.bytecode = new_bc
                code_attr.info = code.serialize()
                report["rewrote_clinit"] = True
        break

    if jnic_clinit_lifted is not None:
        clinit_name_idx = cf.add_utf8("<clinit>")
        sig_idx = cf.add_utf8("()V")
        code = classfile.Code(
            max_stack=jnic_clinit_max_stack,
            max_locals=0,
            bytecode=jnic_clinit_lifted,
            exceptions=struct.pack(">H", 0),
            attributes=[],
        )
        code_name_idx = cf.add_utf8("Code")
        new_clinit = classfile.Member(
            access_flags=classfile.ACC_STATIC,
            name_index=clinit_name_idx,
            descriptor_index=sig_idx,
            attributes=[classfile.Attribute(name_index=code_name_idx, info=code.serialize())],
        )
        cf.methods.append(new_clinit)
        report["rewrote_clinit"] = True

    for m in cf.methods:
        if not (m.access_flags & classfile.ACC_NATIVE):
            continue
        key = (cf.method_name(m), cf.method_descriptor(m))
        trace = traces_by_method.get(key)
        if trace is None:
            report["unlifted_methods"].append({"method": key, "reason": "no trace available"})
            if stub_unlifted:
                _attach_stub(cf, m)
                report["stubbed_methods"].append({"method": key})
            continue
        result = lift.lift(trace, cf, m)
        if not result.success:
            report["unlifted_methods"].append({"method": key, "reason": result.reason})
            if stub_unlifted:
                _attach_stub(cf, m)
                report["stubbed_methods"].append({"method": key})
            continue
        m.access_flags &= ~classfile.ACC_NATIVE
        code = classfile.Code(
            max_stack=result.max_stack,
            max_locals=result.max_locals,
            bytecode=result.bytecode,
            exceptions=struct.pack(">H", 0),
            attributes=[],
        )
        code_name_idx = cf.add_utf8("Code")
        m.attributes.append(classfile.Attribute(name_index=code_name_idx, info=code.serialize()))
        report["lifted_methods"].append({"method": key, "pattern": result.pattern, "reason": result.reason})

    return report


def _attach_stub(cf: classfile.ClassFile, m: classfile.Member) -> None:
    desc = cf.method_descriptor(m)
    return_type = desc[desc.index(")") + 1:]
    bc = bytearray()
    cls_ref = cf.add_class("java/lang/UnsupportedOperationException")
    msg_ref = cf.add_string("JNIC method body not lifted")
    ctor_ref = cf.add_methodref("java/lang/UnsupportedOperationException", "<init>", "(Ljava/lang/String;)V")
    bc += b"\xbb" + struct.pack(">H", cls_ref)
    bc += b"\x59"
    if msg_ref <= 0xFF:
        bc += b"\x12" + bytes([msg_ref])
    else:
        bc += b"\x13" + struct.pack(">H", msg_ref)
    bc += b"\xb7" + struct.pack(">H", ctor_ref)
    bc += b"\xbf"
    m.access_flags &= ~classfile.ACC_NATIVE
    n_locals = _stub_locals(m, cf)
    code = classfile.Code(
        max_stack=3,
        max_locals=n_locals,
        bytecode=bytes(bc),
        exceptions=struct.pack(">H", 0),
        attributes=[],
    )
    code_name_idx = cf.add_utf8("Code")
    m.attributes.append(classfile.Attribute(name_index=code_name_idx, info=code.serialize()))


def _stub_locals(m: classfile.Member, cf: classfile.ClassFile) -> int:
    desc = cf.method_descriptor(m)
    is_static = bool(m.access_flags & classfile.ACC_STATIC)
    n = 0 if is_static else 1
    end = desc.index(")")
    inner = desc[1:end]
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch == "L":
            j = inner.index(";", i)
            n += 1
            i = j + 1
        elif ch == "[":
            j = i
            while inner[j] == "[":
                j += 1
            if inner[j] == "L":
                j = inner.index(";", j)
            n += 1
            i = j + 1
        elif ch in ("J", "D"):
            n += 2
            i += 1
        else:
            n += 1
            i += 1
    return n


def _is_only_return(bc: bytes) -> bool:
    return bc == b"\xb1"


def _strip_clinit(cf: classfile.ClassFile, bc: bytes, loader_class_internal: str | None) -> bytes:
    out = bytearray()
    i = 0
    while i < len(bc):
        op = bc[i]
        if op == 0xB8:
            cp_idx = struct.unpack_from(">H", bc, i + 1)[0]
            target = _resolve_method_ref(cf, cp_idx)
            if target is not None:
                owner, name, _desc = target
                if loader_class_internal and owner == loader_class_internal and name == "init":
                    i += 3
                    continue
                if owner.endswith("/JNICLoader") and name == "init":
                    i += 3
                    continue
                if name in ("$jnicLoader", "$jnicClinit"):
                    i += 3
                    continue
            out.append(op)
            out += bc[i + 1:i + 3]
            i += 3
            continue
        out.append(op)
        sz = _opsize_short(bc, i)
        out += bc[i + 1:i + sz]
        i += sz
    return bytes(out)


def _resolve_method_ref(cf: classfile.ClassFile, cp_idx: int) -> tuple[str, str, str] | None:
    e = cf.cp[cp_idx]
    if e is None or e.tag not in (classfile.CONSTANT_Methodref, classfile.CONSTANT_InterfaceMethodref):
        return None
    cls_idx, nt_idx = struct.unpack(">HH", e.raw)
    cls_name = cf.class_name(cls_idx)
    nt = cf.cp[nt_idx]
    if nt is None or nt.tag != classfile.CONSTANT_NameAndType:
        return None
    name_idx, desc_idx = struct.unpack(">HH", nt.raw)
    return (cls_name, cf.utf8(name_idx), cf.utf8(desc_idx))


_FIXED_SIZE = {
    0xB1: 1,
    0xB2: 3,
    0xB3: 3,
    0xB6: 3,
    0xB7: 3,
    0xB8: 3,
    0xB9: 5,
    0xBA: 5,
    0x12: 2,
    0x13: 3,
    0x14: 3,
    0x59: 1,
    0x57: 1,
    0x58: 1,
    0xBB: 3,
    0xBF: 1,
}


def _opsize_short(bc: bytes, pos: int) -> int:
    return _FIXED_SIZE.get(bc[pos], 1)
