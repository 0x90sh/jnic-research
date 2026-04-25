def mangle(class_internal: str, method_name: str) -> str:
    parts = class_internal.replace(".", "/").split("/")
    out = "Java_" + "_".join(_mangle_segment(p) for p in parts)
    out += "_" + _mangle_segment(method_name)
    return out


def _mangle_segment(s: str) -> str:
    out = []
    for ch in s:
        if ch.isalnum() and ord(ch) < 128:
            out.append(ch)
        elif ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        else:
            out.append(f"_0{ord(ch):04x}")
    return "".join(out)


def demangle_to_class_method(symbol: str) -> tuple[str, str] | None:
    if not symbol.startswith("Java_"):
        return None
    body = symbol[5:]
    segments = _split_unescaped_underscores(body)
    if len(segments) < 2:
        return None
    method = _demangle_segment(segments[-1])
    cls_parts = [_demangle_segment(p) for p in segments[:-1]]
    return ("/".join(cls_parts), method)


def _split_unescaped_underscores(s: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "_":
            nxt = s[i + 1] if i + 1 < len(s) else ""
            if nxt in ("0", "1", "2", "3"):
                cur.append(ch)
                cur.append(nxt)
                i += 2
                continue
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def _demangle_segment(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "_" and i + 1 < len(s):
            esc = s[i + 1]
            if esc == "0" and i + 5 < len(s):
                code = int(s[i + 2:i + 6], 16)
                out.append(chr(code))
                i += 6
                continue
            if esc == "1":
                out.append("_")
                i += 2
                continue
            if esc == "2":
                out.append(";")
                i += 2
                continue
            if esc == "3":
                out.append("[")
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)
