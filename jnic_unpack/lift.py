from __future__ import annotations

import struct
from dataclasses import dataclass

from . import classfile
from .native_analyze import JNITrace


@dataclass
class LiftResult:
    success: bool
    pattern: str
    bytecode: bytes | None = None
    max_stack: int = 0
    max_locals: int = 0
    reason: str = ""


_NOISE_CALLS = (
    "ExceptionCheck", "NewGlobalRef", "FindClass",
    "GetFieldID", "GetMethodID", "GetStaticMethodID", "GetStaticFieldID",
    "DeleteLocalRef", "DeleteGlobalRef", "EnsureLocalCapacity",
    "PushLocalFrame", "PopLocalFrame", "helper",
)


_GET_FIELD_OPS = {
    "GetIntField": "I", "GetBooleanField": "Z", "GetByteField": "B",
    "GetCharField": "C", "GetShortField": "S", "GetLongField": "J",
    "GetFloatField": "F", "GetDoubleField": "D", "GetObjectField": "L",
}

_SET_FIELD_OPS = {
    "SetIntField": "I", "SetBooleanField": "Z", "SetByteField": "B",
    "SetCharField": "C", "SetShortField": "S", "SetLongField": "J",
    "SetFloatField": "F", "SetDoubleField": "D", "SetObjectField": "L",
}

_GET_STATIC_OPS = {
    "GetStaticIntField": "I", "GetStaticBooleanField": "Z", "GetStaticByteField": "B",
    "GetStaticCharField": "C", "GetStaticShortField": "S", "GetStaticLongField": "J",
    "GetStaticFloatField": "F", "GetStaticDoubleField": "D", "GetStaticObjectField": "L",
}

_SET_STATIC_OPS = {
    "SetStaticIntField": "I", "SetStaticBooleanField": "Z", "SetStaticByteField": "B",
    "SetStaticCharField": "C", "SetStaticShortField": "S", "SetStaticLongField": "J",
    "SetStaticFloatField": "F", "SetStaticDoubleField": "D", "SetStaticObjectField": "L",
}

_CALL_VIRTUAL_OPS = {
    "CallVoidMethod": "V", "CallObjectMethod": "L", "CallIntMethod": "I",
    "CallBooleanMethod": "Z", "CallByteMethod": "B", "CallCharMethod": "C",
    "CallShortMethod": "S", "CallLongMethod": "J", "CallFloatMethod": "F",
    "CallDoubleMethod": "D",
}

_CALL_STATIC_OPS = {
    "CallStaticVoidMethod": "V", "CallStaticObjectMethod": "L",
    "CallStaticIntMethod": "I", "CallStaticBooleanMethod": "Z",
    "CallStaticByteMethod": "B", "CallStaticCharMethod": "C",
    "CallStaticShortMethod": "S", "CallStaticLongMethod": "J",
    "CallStaticFloatMethod": "F", "CallStaticDoubleMethod": "D",
}


def _filtered(trace: JNITrace) -> list[dict]:
    return [c for c in trace.calls if c.get("call") not in _NOISE_CALLS]


def lift(trace: JNITrace, cf: classfile.ClassFile, method: classfile.Member) -> LiftResult:
    calls = _filtered(trace)
    class_internal = cf.class_name(cf.this_class)

    for fn in (_try_empty, _try_println, _try_getter, _try_setter, _try_return_const,
               _try_linear):
        result = fn(trace, calls, cf, method, class_internal)
        if result.success:
            return result
    return LiftResult(success=False, pattern="unknown", reason="no matching pattern")


def _string_arg(arg) -> str | None:
    if isinstance(arg, tuple) and len(arg) == 2 and arg[0] == "string":
        return arg[1]
    return None


def _cached(arg) -> dict | None:
    if isinstance(arg, tuple) and len(arg) == 2 and arg[0] == "cached":
        return arg[1]
    return None


def _resolve_field_from_cached(cached: dict) -> tuple[str, str, str] | None:
    """A GetFieldID cached call returns (owner_class, name, sig)."""
    if cached.get("from") not in ("GetFieldID", "GetStaticFieldID"):
        return None
    args = cached.get("args", [])
    if len(args) < 4:
        return None
    name = _string_arg(args[2])
    sig = _string_arg(args[3])
    cls_arg = args[1]
    if isinstance(cls_arg, tuple) and cls_arg[0] == "cached":
        cls = _resolve_class_from_cached(cls_arg[1])
    else:
        cls = None
    if not name or not sig or not cls:
        return None
    return (cls, name, sig)


def _resolve_method_from_cached(cached: dict) -> tuple[str, str, str] | None:
    if cached.get("from") not in ("GetMethodID", "GetStaticMethodID"):
        return None
    args = cached.get("args", [])
    if len(args) < 4:
        return None
    name = _string_arg(args[2])
    sig = _string_arg(args[3])
    cls_arg = args[1]
    if isinstance(cls_arg, tuple) and cls_arg[0] == "cached":
        cls = _resolve_class_from_cached(cls_arg[1])
    else:
        cls = None
    if not name or not sig or not cls:
        return None
    return (cls, name, sig)


def _resolve_class_from_cached(cached: dict) -> str | None:
    f = cached.get("from")
    if f == "FindClass":
        args = cached.get("args", [])
        if len(args) >= 2:
            return _string_arg(args[1])
    if f == "NewGlobalRef":
        args = cached.get("args", [])
        if len(args) >= 2 and isinstance(args[1], tuple) and args[1][0] == "cached":
            return _resolve_class_from_cached(args[1][1])
    return None


def _split_sig_args(sig: str) -> tuple[list[str], str]:
    if not sig.startswith("("):
        return ([], "V")
    end = sig.index(")")
    inner = sig[1:end]
    ret = sig[end + 1:]
    args: list[str] = []
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch == "L":
            j = inner.index(";", i)
            args.append(inner[i:j + 1])
            i = j + 1
        elif ch == "[":
            j = i
            while inner[j] == "[":
                j += 1
            if inner[j] == "L":
                j = inner.index(";", j)
            args.append(inner[i:j + 1])
            i = j + 1
        else:
            args.append(ch)
            i += 1
    return (args, ret)


def _count_locals(m: classfile.Member, cf: classfile.ClassFile) -> int:
    desc = cf.method_descriptor(m)
    is_static = bool(m.access_flags & classfile.ACC_STATIC)
    n = 0 if is_static else 1
    args, _ = _split_sig_args(desc)
    for a in args:
        n += 2 if a in ("J", "D") else 1
    return n


def _load_op(t: str) -> int:
    if t in ("L", "[") or t.startswith("L") or t.startswith("["):
        return 0x19
    if t == "J":
        return 0x16
    if t == "D":
        return 0x18
    if t == "F":
        return 0x17
    return 0x15


def _store_op(t: str) -> int:
    if t in ("L", "[") or t.startswith("L") or t.startswith("["):
        return 0x3a
    if t == "J":
        return 0x37
    if t == "D":
        return 0x39
    if t == "F":
        return 0x38
    return 0x36


def _return_op(t: str) -> int:
    if t == "V":
        return 0xb1
    if t in ("L",) or t.startswith("L") or t.startswith("["):
        return 0xb0
    if t == "J":
        return 0xad
    if t == "D":
        return 0xaf
    if t == "F":
        return 0xae
    return 0xac


def _slot_size(t: str) -> int:
    return 2 if t in ("J", "D") else 1


def _emit_load_local(idx: int, t: str) -> bytes:
    return bytes([_load_op(t), idx])


def _emit_iconst(n: int) -> bytes:
    if -1 <= n <= 5:
        return bytes([0x03 + n])
    if -128 <= n <= 127:
        return bytes([0x10, n & 0xff])
    if -32768 <= n <= 32767:
        return b"\x11" + struct.pack(">h", n)
    return b""


def _try_empty(trace, calls, cf, method, class_internal) -> LiftResult:
    if calls:
        return LiftResult(False, "empty", reason="trace not empty")
    desc = cf.method_descriptor(method)
    _, ret = _split_sig_args(desc)
    if ret == "V":
        return LiftResult(True, "empty", bytecode=b"\xb1",
                          max_stack=0, max_locals=_count_locals(method, cf),
                          reason="empty body, void return")
    return LiftResult(False, "empty", reason="non void return needs a value")


def _try_println(trace, calls, cf, method, class_internal) -> LiftResult:
    new_strings = [c for c in trace.calls
                   if c.get("call") == "NewString" and c.get("newstring") is not None]
    if len(new_strings) != 1:
        return LiftResult(False, "println", reason=f"expected 1 NewString, got {len(new_strings)}")
    relevant = [c for c in calls if c.get("call") not in ("NewString", "GetStaticObjectField",
                                                           "IsInstanceOf", "ThrowNew")]
    if len(relevant) != 1 or relevant[0].get("call") != "CallVoidMethod":
        return LiftResult(False, "println", reason="trace has more than just println")
    call_void = relevant[0]
    args = call_void.get("args", [])
    if len(args) < 3:
        return LiftResult(False, "println", reason="CallVoidMethod has too few args")
    method_id = args[2]
    cinfo = _cached(method_id)
    if not cinfo or cinfo.get("from") != "GetMethodID":
        return LiftResult(False, "println", reason="method id not from GetMethodID")
    cargs = cinfo.get("args", [])
    if len(cargs) < 4 or _string_arg(cargs[2]) != "println" \
            or _string_arg(cargs[3]) != "(Ljava/lang/String;)V":
        return LiftResult(False, "println", reason="cached method id is not println(String)V")
    literal = new_strings[0]["newstring"]
    bc = _emit_println(cf, literal)
    return LiftResult(True, "println", bytecode=bc,
                      max_stack=2, max_locals=_count_locals(method, cf),
                      reason=f'System.out.println("{literal}")')


def _try_getter(trace, calls, cf, method, class_internal) -> LiftResult:
    if not calls:
        return LiftResult(False, "getter", reason="empty trace")
    last = calls[-1]
    name = last.get("call")
    if name not in _GET_FIELD_OPS:
        return LiftResult(False, "getter", reason="not a Get*Field op")
    args = last.get("args", [])
    if len(args) < 3:
        return LiftResult(False, "getter", reason="too few args")
    cinfo = _cached(args[2])
    if not cinfo:
        return LiftResult(False, "getter", reason="field id not cached")
    field = _resolve_field_from_cached(cinfo)
    if field is None:
        return LiftResult(False, "getter", reason="cannot resolve field")
    cls_owner, fname, fsig = field
    desc = cf.method_descriptor(method)
    _, ret_sig = _split_sig_args(desc)
    if ret_sig != fsig and not (ret_sig.startswith("L") and fsig.startswith("L")):
        return LiftResult(False, "getter", reason=f"return {ret_sig} mismatches field {fsig}")
    fieldref = cf.add_fieldref(cls_owner, fname, fsig)
    bc = bytearray()
    bc += b"\x2a"
    bc += b"\xb4" + struct.pack(">H", fieldref)
    bc += bytes([_return_op(fsig)])
    max_stack = 2 if fsig in ("J", "D") else 1
    return LiftResult(True, "getter", bytecode=bytes(bc),
                      max_stack=max_stack, max_locals=_count_locals(method, cf),
                      reason=f"return this.{fname}")


def _try_setter(trace, calls, cf, method, class_internal) -> LiftResult:
    set_calls = [c for c in calls if c.get("call") in _SET_FIELD_OPS]
    if len(set_calls) != 1:
        return LiftResult(False, "setter", reason=f"need exactly 1 Set*Field, got {len(set_calls)}")
    sc = set_calls[0]
    args = sc.get("args", [])
    if len(args) < 4:
        return LiftResult(False, "setter", reason="too few args")
    cinfo = _cached(args[2])
    if not cinfo:
        return LiftResult(False, "setter", reason="field id not cached")
    field = _resolve_field_from_cached(cinfo)
    if field is None:
        return LiftResult(False, "setter", reason="cannot resolve field")
    cls_owner, fname, fsig = field
    desc = cf.method_descriptor(method)
    arg_types, ret = _split_sig_args(desc)
    if ret != "V" or len(arg_types) != 1:
        return LiftResult(False, "setter", reason="not a single arg void method")
    val = args[3]
    if not (isinstance(val, tuple) and val[0] == "java_local"):
        return LiftResult(False, "setter", reason="value not a local")
    if val[1] == 0:
        return LiftResult(False, "setter", reason="value cannot be this")
    val_type = val[2] if len(val) >= 3 else fsig
    if val_type != fsig and not (val_type.startswith("L") and fsig.startswith("L")):
        return LiftResult(False, "setter", reason="value type mismatches field")
    fieldref = cf.add_fieldref(cls_owner, fname, fsig)
    bc = bytearray()
    bc += b"\x2a"
    bc += _emit_load_local(val[1], fsig)
    bc += b"\xb5" + struct.pack(">H", fieldref)
    bc += b"\xb1"
    max_stack = 3 if fsig in ("J", "D") else 2
    return LiftResult(True, "setter", bytecode=bytes(bc),
                      max_stack=max_stack, max_locals=_count_locals(method, cf),
                      reason=f"this.{fname} = arg")


def _try_return_const(trace, calls, cf, method, class_internal) -> LiftResult:
    if calls:
        return LiftResult(False, "return_const", reason="trace not empty")
    desc = cf.method_descriptor(method)
    _, ret = _split_sig_args(desc)
    if ret == "V":
        return LiftResult(True, "return_void", bytecode=b"\xb1",
                          max_stack=0, max_locals=_count_locals(method, cf),
                          reason="empty body")
    if ret in ("I", "Z", "B", "C", "S"):
        return LiftResult(True, "return_zero", bytecode=b"\x03\xac",
                          max_stack=1, max_locals=_count_locals(method, cf),
                          reason="return 0")
    return LiftResult(False, "return_const", reason=f"return type {ret} not handled")


def _try_linear(trace, calls, cf, method, class_internal) -> LiftResult:
    if trace.has_branches or trace.has_indirect_jump:
        return LiftResult(False, "linear",
                          reason="method has control flow; linear lifter refuses")
    desc = cf.method_descriptor(method)
    _, ret = _split_sig_args(desc)
    is_static = bool(method.access_flags & classfile.ACC_STATIC)
    if not calls:
        return LiftResult(False, "linear", reason="no recognizable calls")
    relevant = calls

    bc = bytearray()
    max_stack = 0
    last_pushed_type: str | None = None

    for c in relevant:
        name = c.get("call")
        args = c.get("args", [])

        if name == "NewString":
            literal = c.get("newstring")
            if literal is None:
                return LiftResult(False, "linear", reason="NewString without literal")
            if last_pushed_type is not None:
                return LiftResult(False, "linear",
                                  reason="NewString result chained without consumer")
            str_ref = cf.add_string(literal)
            if str_ref <= 0xff:
                bc += b"\x12" + bytes([str_ref])
            else:
                bc += b"\x13" + struct.pack(">H", str_ref)
            last_pushed_type = "Ljava/lang/String;"
            max_stack = max(max_stack, 1)
            continue

        if name in _GET_FIELD_OPS:
            if len(args) < 3:
                return LiftResult(False, "linear", reason="GetField args")
            recv = _resolve_value_to_bytecode(args[1], cf)
            if recv is None:
                return LiftResult(False, "linear", reason="cannot push recv")
            field = _resolve_field_from_cached(_cached(args[2]) or {})
            if field is None:
                return LiftResult(False, "linear", reason="cannot resolve field id")
            cls, fname, fsig = field
            fieldref = cf.add_fieldref(cls, fname, fsig)
            bc += recv[0]
            bc += b"\xb4" + struct.pack(">H", fieldref)
            last_pushed_type = fsig
            max_stack = max(max_stack, 2)
            continue

        if name in _GET_STATIC_OPS:
            if len(args) < 3:
                return LiftResult(False, "linear", reason="GetStaticField args")
            field = _resolve_field_from_cached(_cached(args[2]) or {})
            if field is None:
                return LiftResult(False, "linear", reason="cannot resolve static field id")
            cls, fname, fsig = field
            fieldref = cf.add_fieldref(cls, fname, fsig)
            bc += b"\xb2" + struct.pack(">H", fieldref)
            last_pushed_type = fsig
            max_stack = max(max_stack, 1)
            continue

        if name in _SET_FIELD_OPS:
            if len(args) < 4:
                return LiftResult(False, "linear", reason="SetField args")
            recv = _resolve_value_to_bytecode(args[1], cf)
            field = _resolve_field_from_cached(_cached(args[2]) or {})
            if recv is None or field is None:
                return LiftResult(False, "linear", reason="cannot resolve setfield")
            cls, fname, fsig = field
            val = _resolve_value_to_bytecode(args[3], cf)
            if val is None:
                return LiftResult(False, "linear", reason="cannot push setfield value")
            fieldref = cf.add_fieldref(cls, fname, fsig)
            bc += recv[0]
            bc += val[0]
            bc += b"\xb5" + struct.pack(">H", fieldref)
            last_pushed_type = None
            max_stack = max(max_stack, 3 if fsig in ("J", "D") else 2)
            continue

        if name in _SET_STATIC_OPS:
            if len(args) < 4:
                return LiftResult(False, "linear", reason="SetStaticField args")
            field = _resolve_field_from_cached(_cached(args[2]) or {})
            if field is None:
                return LiftResult(False, "linear", reason="cannot resolve static field id")
            cls, fname, fsig = field
            val = _resolve_value_to_bytecode(args[3], cf)
            if val is None:
                return LiftResult(False, "linear", reason="cannot push setstatic value")
            fieldref = cf.add_fieldref(cls, fname, fsig)
            bc += val[0]
            bc += b"\xb3" + struct.pack(">H", fieldref)
            last_pushed_type = None
            max_stack = max(max_stack, 2 if fsig in ("J", "D") else 1)
            continue

        if name in _CALL_VIRTUAL_OPS:
            if len(args) < 3:
                return LiftResult(False, "linear", reason="CallMethod args")
            recv = _resolve_value_to_bytecode(args[1], cf)
            mref = _resolve_method_from_cached(_cached(args[2]) or {})
            if recv is None or mref is None:
                return LiftResult(False, "linear", reason="cannot resolve invokevirtual")
            cls, mname, msig = mref
            arg_types, ret_type = _split_sig_args(msig)
            if len(args) < 3 + len(arg_types):
                return LiftResult(False, "linear", reason="not enough args for invoke")
            bc += recv[0]
            stack_used = 1
            for i, t in enumerate(arg_types):
                argv = _resolve_value_to_bytecode(args[3 + i], cf)
                if argv is None:
                    return LiftResult(False, "linear", reason=f"cannot push arg {i}")
                bc += argv[0]
                stack_used += _slot_size(t)
            mref_idx = cf.add_methodref(cls, mname, msig)
            bc += b"\xb6" + struct.pack(">H", mref_idx)
            last_pushed_type = ret_type if ret_type != "V" else None
            max_stack = max(max_stack, stack_used)
            continue

        if name in _CALL_STATIC_OPS:
            if len(args) < 3:
                return LiftResult(False, "linear", reason="CallStaticMethod args")
            mref = _resolve_method_from_cached(_cached(args[2]) or {})
            if mref is None:
                return LiftResult(False, "linear", reason="cannot resolve invokestatic")
            cls, mname, msig = mref
            arg_types, ret_type = _split_sig_args(msig)
            if len(args) < 3 + len(arg_types):
                return LiftResult(False, "linear", reason="not enough args for invokestatic")
            stack_used = 0
            for i, t in enumerate(arg_types):
                argv = _resolve_value_to_bytecode(args[3 + i], cf)
                if argv is None:
                    return LiftResult(False, "linear", reason=f"cannot push static arg {i}")
                bc += argv[0]
                stack_used += _slot_size(t)
            mref_idx = cf.add_methodref(cls, mname, msig)
            bc += b"\xb8" + struct.pack(">H", mref_idx)
            last_pushed_type = ret_type if ret_type != "V" else None
            max_stack = max(max_stack, max(stack_used, 1))
            continue

        return LiftResult(False, "linear", reason=f"unhandled call {name}")

    if ret == "V":
        if last_pushed_type is not None:
            t = last_pushed_type
            bc += b"\x57" if t not in ("J", "D") else b"\x58"
        bc += b"\xb1"
    else:
        if last_pushed_type is None:
            return LiftResult(False, "linear", reason=f"need value of {ret} but stack empty")
        if last_pushed_type != ret and not (ret.startswith("L") and last_pushed_type.startswith("L")):
            return LiftResult(False, "linear",
                              reason=f"return type {ret} mismatches stacked {last_pushed_type}")
        bc += bytes([_return_op(ret)])

    return LiftResult(True, "linear", bytecode=bytes(bc),
                      max_stack=max(max_stack, 1),
                      max_locals=_count_locals(method, cf),
                      reason=f"{len(relevant)} ops emitted")


def _resolve_value_to_bytecode(arg, cf: classfile.ClassFile) -> tuple[bytes, str] | None:
    if isinstance(arg, tuple):
        if arg[0] == "java_local":
            idx = arg[1]
            t = arg[2] if len(arg) >= 3 else "L"
            return (_emit_load_local(idx, t), t)
        if arg[0] == "cached":
            cinfo = arg[1]
            f = cinfo.get("from")
            if f in _GET_FIELD_OPS:
                cargs = cinfo.get("args", [])
                if len(cargs) < 3:
                    return None
                recv_bc = _resolve_value_to_bytecode(cargs[1], cf)
                field_cached = _cached(cargs[2])
                if recv_bc is None or field_cached is None:
                    return None
                fld = _resolve_field_from_cached(field_cached)
                if fld is None:
                    return None
                cls, name, sig = fld
                fref = cf.add_fieldref(cls, name, sig)
                return (recv_bc[0] + b"\xb4" + struct.pack(">H", fref), sig)
            if f in _GET_STATIC_OPS:
                cargs = cinfo.get("args", [])
                if len(cargs) < 3:
                    return None
                field_cached = _cached(cargs[2])
                if field_cached is None:
                    return None
                fld = _resolve_field_from_cached(field_cached)
                if fld is None:
                    return None
                cls, name, sig = fld
                fref = cf.add_fieldref(cls, name, sig)
                return (b"\xb2" + struct.pack(">H", fref), sig)
            if f == "NewString" and "newstring" in cinfo:
                literal = cinfo["newstring"]
                str_ref = cf.add_string(literal)
                if str_ref <= 0xff:
                    return (b"\x12" + bytes([str_ref]), "Ljava/lang/String;")
                return (b"\x13" + struct.pack(">H", str_ref), "Ljava/lang/String;")
            return None
        return None
    if isinstance(arg, int):
        c = _emit_iconst(arg)
        if c:
            return (c, "I")
        return None
    return None


def _emit_println(cf: classfile.ClassFile, literal: str) -> bytes:
    sysout_ref = cf.add_fieldref("java/lang/System", "out", "Ljava/io/PrintStream;")
    str_ref = cf.add_string(literal)
    println_ref = cf.add_methodref("java/io/PrintStream", "println", "(Ljava/lang/String;)V")
    out = bytearray()
    out += b"\xb2" + struct.pack(">H", sysout_ref)
    if str_ref <= 0xff:
        out += b"\x12" + bytes([str_ref])
    else:
        out += b"\x13" + struct.pack(">H", str_ref)
    out += b"\xb6" + struct.pack(">H", println_ref)
    out += b"\xb1"
    return bytes(out)
