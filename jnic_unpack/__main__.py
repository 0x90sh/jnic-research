from __future__ import annotations

import argparse
import json
import os
import sys

from . import dumps, orchestrator


BANNER = r"""
   _   _  _ ___ ___   _   _ _ _ ___  __ _   __
  ( ) ( )( |_ _/   \ ( ) ( | | ) _ \/ _` | / _|
  | |_| | || | | (_) || |_| | | |  _/ (_| || (__
  | (___)|_||_|\___/ |_____|_|_|_|  \____| \____|
   reverse JNIC protected jars in seconds
"""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="jnic-unpack",
        description="Reverse engineering toolkit for JNIC protected jars.",
    )
    sub = p.add_subparsers(dest="command")

    up = sub.add_parser("unpack", help="strip + carve + lift -> clean jar")
    up.add_argument("input")
    up.add_argument("-o", "--output", required=True)
    up.add_argument("--natives-dir", default=None)
    up.add_argument("--report", default=None)
    up.add_argument("--stub-unlifted", action="store_true",
                    help="replace unlifted native methods with throwing stubs so the jar loads")
    up.add_argument("-q", "--quiet", action="store_true")

    cv = sub.add_parser("carve", help="only extract per platform native binaries")
    cv.add_argument("input")
    cv.add_argument("-d", "--dir", required=True)

    sd = sub.add_parser("strings", help="dump every string referenced by every protected method")
    sd.add_argument("input")
    sd.add_argument("--json", action="store_true", help="emit JSON instead of human format")

    tr = sub.add_parser("trace", help="dump JNI call traces (the IR) per method")
    tr.add_argument("input")
    tr.add_argument("--json", action="store_true")
    tr.add_argument("--class", dest="cls", default=None,
                    help="filter to a single class")

    info = sub.add_parser("info", help="quick summary of what's in the jar")
    info.add_argument("input")

    args = p.parse_args(argv)

    if args.command is None:
        return _interactive_menu()

    if args.command == "unpack":
        return _cmd_unpack(args)
    if args.command == "carve":
        return _cmd_carve(args)
    if args.command == "strings":
        return _cmd_strings(args)
    if args.command == "trace":
        return _cmd_trace(args)
    if args.command == "info":
        return _cmd_info(args)
    p.print_help()
    return 1


def _cmd_unpack(args) -> int:
    natives_dir = args.natives_dir or (args.output + ".natives")
    report_path = args.report or (args.output + ".report.json")
    report = orchestrator.deobfuscate(args.input, args.output,
                                       natives_dir=natives_dir,
                                       stub_unlifted=args.stub_unlifted)
    with open(report_path, "w") as f:
        f.write(orchestrator.report_json(report))
    if not args.quiet:
        _print_unpack_summary(report)
        print(f"\noutput jar:   {args.output}")
        print(f"native dumps: {natives_dir}/")
        print(f"json report:  {report_path}")
    return 0


def _cmd_carve(args) -> int:
    ctx = dumps.load_jar_context(args.input)
    natives = dumps.write_natives(ctx, args.dir)
    print(f"loader: {ctx.loader_class}")
    print(f".dat:   {ctx.loader_info.dat_resource_path}")
    print(f"decompressed blob: {len(ctx.blob)} bytes")
    print(f"binaries:")
    for n in natives:
        print(f"  {n['platform']:18s} {n['kind']:5s} {n['size']:>7d} bytes  {n['path']}")
    return 0


def _cmd_strings(args) -> int:
    ctx = dumps.load_jar_context(args.input)
    data = dumps.dump_strings(ctx)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    print(f"Strings recovered from {len(data['per_class'])} protected classes:\n")
    for cls, strs in sorted(data["per_class"].items()):
        print(f"== {cls} ==")
        for s in strs:
            print(f"  {s!r}")
        print()
    return 0


def _cmd_trace(args) -> int:
    ctx = dumps.load_jar_context(args.input)
    data = dumps.dump_traces(ctx)
    if args.cls:
        data["per_class"] = {k: v for k, v in data["per_class"].items() if k == args.cls}
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    for cls, info in sorted(data["per_class"].items()):
        print(f"== {cls} ==")
        for sig, mdata in sorted(info["methods"].items()):
            print(f"  {sig}  @ {mdata['fn_vaddr']}")
            for c in mdata["calls"]:
                args_repr = _format_args_short(c.get("args", []))
                ns = c.get("newstring")
                if ns is not None:
                    print(f"    {c['call']}({args_repr}) -> jstring \"{ns}\"")
                else:
                    print(f"    {c['call']}({args_repr})")
            print()
    return 0


def _format_args_short(args, depth=0) -> str:
    if depth > 2:
        return "..."
    parts = []
    for a in args:
        if a is None:
            parts.append("_")
        elif isinstance(a, dict):
            if "string" in a:
                parts.append(f'"{a["string"]}"')
            elif "from" in a:
                inner_args = a.get("args", [])
                if a["from"] == "FindClass" and len(inner_args) >= 2:
                    arg1 = inner_args[1]
                    if isinstance(arg1, dict) and "string" in arg1:
                        parts.append(f"<class:{arg1['string']}>")
                        continue
                if a["from"] == "GetFieldID" and len(inner_args) >= 4:
                    name = inner_args[2]
                    if isinstance(name, dict) and "string" in name:
                        parts.append(f"<field:{name['string']}>")
                        continue
                if a["from"] == "GetMethodID" and len(inner_args) >= 4:
                    name = inner_args[2]
                    sig = inner_args[3]
                    if isinstance(name, dict) and "string" in name:
                        sig_s = sig.get("string", "?") if isinstance(sig, dict) else "?"
                        parts.append(f"<method:{name['string']}{sig_s}>")
                        continue
                if a["from"] == "NewGlobalRef" and len(inner_args) >= 2:
                    inner = _format_args_short([inner_args[1]], depth + 1)
                    parts.append(f"global({inner})")
                    continue
                inner = _format_args_short(inner_args, depth + 1)
                parts.append(f"{a['from']}({inner})")
            elif "tag" in a:
                tag = a["tag"]
                if tag == "jni_env":
                    parts.append("env")
                elif tag == "jni_arg_class":
                    parts.append("self")
                elif tag == "jni_vtable":
                    parts.append("vtable")
                elif tag == "rsp":
                    parts.append(f"stack+{a.get('value')}")
                elif tag == "rip":
                    parts.append(f"data@{a.get('value'):#x}")
                elif tag == "mem":
                    parts.append(f"mem@{a.get('value'):#x}")
                elif tag == "jni_result":
                    parts.append(f"%{a.get('value')}")
                else:
                    parts.append(f"{tag}({a.get('value')})")
            else:
                parts.append(str(a))
        elif isinstance(a, int):
            parts.append(str(a))
        else:
            parts.append(repr(a))
    return ", ".join(parts)


def _cmd_info(args) -> int:
    ctx = dumps.load_jar_context(args.input)
    print(f"input:        {args.input}")
    print(f"loader class: {ctx.loader_class}")
    print(f".dat resource: {ctx.loader_info.dat_resource_path}")
    print(f"decompressed blob size: {len(ctx.blob)} bytes")
    print(f"protected classes ({len(ctx.protected_classes)}):")
    for jar_name, cf in ctx.protected_classes:
        ci = cf.class_name(cf.this_class)
        natives_in_cls = sum(1 for m in cf.methods if m.access_flags & 0x100)
        print(f"  {ci}  ({natives_in_cls} native methods)")
    print(f"platform binaries ({len(ctx.binaries)}):")
    for b in ctx.binaries:
        print(f"  {b.slice_.label():18s} {b.kind:5s} {len(b.data):>7d} bytes")
    return 0


def _print_unpack_summary(report) -> None:
    print(f"loader class:   {report.loader_class}")
    print(f".dat resource:  {report.dat_resource}")
    print(f"carved natives:")
    for n in report.natives_carved:
        print(f"  {n['platform']:18s} {n['kind']:5s} {n['size']:>7d}b  {n['path']}")
    print(f"classes modified: {report.summary['classes_modified_count']}  "
          f"(lifted: {report.summary['lifted_count']}, "
          f"unlifted: {report.summary['unlifted_count']}, "
          f"stubbed: {report.summary['stubbed_count']})")
    for c in report.classes_modified:
        r = c["report"]
        print(f"  {c['class']}")
        for m in r["lifted_methods"]:
            print(f"    + lifted   {m['method'][0]}{m['method'][1]}  ({m['pattern']})")
        for m in r["unlifted_methods"]:
            print(f"    - unlifted {m['method'][0]}{m['method'][1]}  ({m['reason']})")
        for m in r.get("stubbed_methods", []):
            print(f"    * stubbed  {m['method'][0]}{m['method'][1]}")
        if r["removed_clinit"]:
            print(f"    - dropped <clinit>")
        elif r["rewrote_clinit"]:
            print(f"    + rewrote <clinit>")
        for n in r["removed_methods"]:
            print(f"    - removed {n}")


def _interactive_menu() -> int:
    print(BANNER)
    print("no command given, entering interactive mode\n")
    jar_path = input("path to JNIC protected jar: ").strip()
    if not jar_path or not os.path.exists(jar_path):
        print(f"file not found: {jar_path!r}")
        return 1
    while True:
        print()
        print("  1) info       quick summary")
        print("  2) carve      extract per platform native binaries")
        print("  3) strings    dump all recovered strings")
        print("  4) trace      print JNI call traces")
        print("  5) unpack     full deobfuscation to a clean jar")
        print("  q) quit")
        choice = input("> ").strip().lower()
        if choice in ("q", "quit", "exit"):
            return 0
        if choice == "1":
            _cmd_info(argparse.Namespace(input=jar_path))
        elif choice == "2":
            d = input("output dir: ").strip()
            _cmd_carve(argparse.Namespace(input=jar_path, dir=d))
        elif choice == "3":
            _cmd_strings(argparse.Namespace(input=jar_path, json=False))
        elif choice == "4":
            cls = input("class filter (blank for all): ").strip() or None
            _cmd_trace(argparse.Namespace(input=jar_path, json=False, cls=cls))
        elif choice == "5":
            o = input("output jar path: ").strip()
            stub = input("stub unlifted methods so the jar loads? (y/N) ").strip().lower() == "y"
            _cmd_unpack(argparse.Namespace(input=jar_path, output=o,
                                            natives_dir=None, report=None,
                                            stub_unlifted=stub, quiet=False))
        else:
            print("unknown choice")


if __name__ == "__main__":
    sys.exit(main())
