# jnic-research

JNIC is a Java protector. It strips your method bodies into native code and ships six platform binaries packed inside the jar. This is the toolkit that unwinds it.

This repository is **research tooling** for understanding and partially unwinding that process. It is a **proof of concept**, not a complete deprotector, not production-grade software, and not a fully fleshed-out reverse-engineering framework.

Point it at a JNIC jar and it gives you back:

* the original jar with JNIC scaffolding removed where possible
* embedded native binaries as real `.so`, `.dylib`, and `.dll` files
* per-method JSON dumps of recovered JNI call traces
* bundled strings, including strings XOR-encrypted by JNIC at load time
* lifted JVM bytecode for methods whose native call trace is simple enough to map back safely

Methods that are too tangled to lift safely stay as `native` shells. The report says which ones and why. Pass `--stub-unlifted` if you want the jar to load anyway.

## Quick start

```bash
pip install -e .
jnic-unpack info input.jar
jnic-unpack unpack input.jar -o clean.jar
```

Run with no arguments for an interactive menu.

## Commands

```
jnic-unpack info <jar>                     summary of what's inside
jnic-unpack carve <jar> -d <dir>           extract the per platform native binaries
jnic-unpack strings <jar>                  recovered strings per class
jnic-unpack trace <jar> [--class X]        JNI call trace per method
jnic-unpack unpack <jar> -o <out>          full deobfuscation (poc implementation)
jnic-unpack unpack <jar> -o <out> --stub-unlifted   stub the unlifted methods
```

`--json` works on the dump commands.

## What the lifter handles

`System.out.println("literal")`, getters, single field setters, multi field setters, method chains on a receiver, static field reads and writes, `NewString` literals flowing into method args, and the original `<clinit>` body that JNIC stashes in `$jnicClinit`.

What it doesn't: anything with a real branch. Loops, switches, `if`/`else` bodies, `try`/`catch`. The simulator detects branches and bails so it never produces wrong bytecode. That refusal is a feature. A linear walk through a switch statement would lift one branch's calls and call it the whole method.

`new X(...)` plus constructor, `instanceof`, `checkcast`, integer arithmetic between locals: the trace shows them, the lifter doesn't recombine them yet.

## Two samples ship with the repo

`HelloWorld-jnic.jar` is the easy case. One method, prints `Hello, world!`. After unpack: one class, runs, prints the right thing. Bytecode equivalent to what `javac` would produce.

`SnakeGame-jnic.jar` is the real one. Seven classes, nineteen protected methods, plus JNIC's XOR string encryption layer over the top. The simulator handles `xorps` and stack XOR ops so class and field names come back as plaintext.

Seven of nineteen methods lift on SnakeGame. The lifted ones decompile to Java that matches the original source. The other twelve all have the kind of control flow we don't fake: the snake's main loop, a switch on key codes, list iteration with a cast, that sort of thing. Their JNI traces are in the report so an analyst can read them anyway.

## Layout

```
jnic_unpack/
  __main__.py          CLI plus interactive menu
  jar.py               zip wrapper
  classfile.py         JVM class file read, edit, write
  jni_mangle.py        JNI symbol name mangling
  loader_parse.py      pulls the dat path and platform offsets out of JNICLoader.<clinit>
  carve.py             LZMA2 decompress and slice
  elf.py               ELF reader
  jni_table.py         JNI vtable offsets
  x86_sim.py           x86-64 abstract interpreter
  native_analyze.py    bootstrap walk, RegisterNatives recovery, JNI traces
  lift.py              pattern matchers and the linear lifter
  strip.py             class file surgery
  dumps.py             string and trace dumps
  orchestrator.py      wires the phases together
tests/                 18 tests across both samples
docs/jnic-architecture.md
samples/               HelloWorld and SnakeGame
```

## Legal

JNIC is commercial software. This toolkit exists for malware analysis, incident response, and security research, which are protected research activities. Don't run it against jars you aren't authorized to analyze.

MIT license, see [`LICENSE`](LICENSE).
