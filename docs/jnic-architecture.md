# How JNIC works

Notes from reverse engineering two protected jars: `HelloWorld-jnic.jar` (one method, no string encryption) and `SnakeGame-jnic.jar` (seven classes, XOR encrypted strings, the more recent build).

## What JNIC does to your jar

You compile this:

```java
package dev.jnic;
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, world!");
    }
}
```

JNIC turns the 987 byte jar into 23,516 bytes:

```
dev/jnic/HelloWorld.class
dev/jnic/JmEMUM/JNICLoader.class
dev/jnic/JmEMUM/{B,D,L,T,b,h,k,o,t,u,x,y}.class
dev/jnic/lib/40db034e-902c-4d1b-a58d-b847a6cc845a.dat
META-INF/MANIFEST.MF
```

The package name `JmEMUM` is randomized per build. So is the `.dat` UUID. Everything else is structurally identical across builds.

Inside the protected `HelloWorld.class`, `main` becomes:

```
public static native void main(java.lang.String[]);
  flags: ACC_PUBLIC, ACC_STATIC, ACC_NATIVE
```

No body. The string `"Hello, world!"` is gone from the constant pool. JNIC adds a synthetic `$jnicLoader()` method and rewrites `<clinit>` to call `JNICLoader.init()` and then `$jnicLoader()`. When the class loads, the static initializer wakes up the loader, which extracts a native library and binds the real `main` implementation through `RegisterNatives`.

If the class already had its own `<clinit>` (Window in SnakeGame is the example), JNIC moves the original body into another synthetic native called `$jnicClinit`. The new `<clinit>` becomes `JNICLoader.init() + $jnicLoader() + $jnicClinit()`.

## The .dat blob

It's a raw LZMA2 stream. No magic, no header, no XZ container. JNIC's loader is a renamed copy of XZ for Java by Tukaani:

* `JNICLoader` is `XZInputStream`
* `T` is `LZDecoder`
* `L` is `RangeDecoder`
* `u` is `LZMADecoder`. The `(pb*5 + lp)*9 + lc` properties decode is the giveaway.

Decompress the 12,024 byte HelloWorld blob and you get exactly 93,252 bytes. That's the concatenation of six platform binaries:

| Platform | Range | Size |
|---|---|---|
| Windows x86\_64 | 0..11776 | 11,776 |
| Windows aarch64 | 11776..23552 | 11,776 |
| macOS x86\_64 | 23552..36332 | 12,780 |
| macOS aarch64 | 36332..86268 | 49,936 |
| Linux x86\_64 | 86268..89508 | 3,240 |
| Linux aarch64 | 89508..93252 | 3,744 |

The macOS aarch64 size is misleading. Its actual `__text` is similar to the others. The bloat is `__LINKEDIT` and dyld info.

`JNICLoader.<clinit>` reads `os.name` and `os.arch`, picks the matching `[start, end)` range, calls `skip(start)` on the decompression stream, reads `end - start` bytes into a temp file, and `System.load`s it. No keys, no checksum, no integrity gate.

## The native binaries

All twelve binaries across both samples were built with clang 13.0.1 from the `ziglang/zig-bootstrap` toolchain. That's how JNIC ships six platforms from one host: `zig cc` does the cross compile. The build host path leaks on macOS as `o/<md5>/jnic.jnilib` in `LC_ID_DYLIB`.

Each binary exports exactly one symbol per protected class:

```
Java_dev_jnic_HelloWorld__00024jnicLoader
Java_DataOfSquare__00024jnicLoader
Java_KeyboardListener__00024jnicLoader
...
```

That's it. No other exports. The actual `main` implementation has no public name. It sits at a private address inside `.text` and gets bound at runtime when the bootstrap calls `RegisterNatives`.

## The bootstrap, line by line

For HelloWorld on Linux x86\_64:

```
sub  rsp, 0x48
mov  byte ptr [rsp+0xf], 0x0
mov  dword ptr [rsp+0xb], 0x6e69616d  ; "main"
lea  rax, [rsp+0xb]
mov  qword ptr [rsp+0x30], rax        ; methods[0].name = &"main"

movups xmm0, [rip+0x36c]              ; load 16 byte head from .rodata
movaps [rsp+0x10], xmm0               ; place at rsp+0x10
movabs rax, 0x19f0a5fdcdbfbc          ; junk magic
mov  [rsp+0x1f], rax                  ; junk store, overwritten next
movaps xmm0, [rip+0x320]              ; "([Ljava/lang/Stri" (the real head)
movaps [rsp+0x10], xmm0               ; overwrite
mov  dword ptr [rsp+0x20], 0x3b676e69 ; "ing;"
mov  word ptr  [rsp+0x24], 0x5629     ; ")V"
lea  rax, [rsp+0x10]
mov  qword ptr [rsp+0x38], rax        ; methods[0].sig = &"([Ljava/lang/String;)V"

lea  rax, [rip+0xfffffffffffffcee]    ; -> 0x13b0, the real main
mov  qword ptr [rsp+0x40], rax        ; methods[0].fnPtr = main impl

mov  rax, [rdi]                       ; vtable
lea  rdx, [rsp+0x30]                  ; arg3 = &methods[0]
mov  ecx, 0x1                         ; arg4 = nMethods
call [rax+0x6b8]                      ; RegisterNatives
add  rsp, 0x48
ret
```

A few things to notice. `"main"` is built from a 32 bit immediate, not stored in `.rodata`. The signature is half in `.rodata` and half emitted as immediate stores. There's a dead 8 byte store with a junk value before the real signature head gets loaded over it. RegisterNatives sits at vtable offset `0x6b8`, which is index 215 in OpenJDK's struct.

The newer SnakeGame build adds an XOR layer on top:

```
movups xmm0, [rip+0x...]              ; encrypted 16 bytes from .rodata
movaps [rsp+0x10], xmm0
movups xmm0, [rip+0x...]              ; encrypted 16 bytes
movups [rsp+0x1d], xmm0
mov byte ptr [rsp+0x10], 0x28         ; '(' written plaintext
movups xmm0, [rsp+0x11]
xorps xmm0, [rip+0x480]               ; XOR decrypt 16 bytes
movups [rsp+0x11], xmm0
movabs rax, 0xf2e9a9899acdc1d4        ; second key
xor qword ptr [rsp+0x21], rax         ; XOR decrypt 8 bytes
xor byte ptr [rsp+0x29], 0xf9         ; per byte XOR
xor byte ptr [rsp+0x2a], 0xdf
xor byte ptr [rsp+0x2b], 0x66
```

The signature `(Ljava/awt/event/KeyEvent;)V` lives in `.rodata` as ciphertext plus an XOR key. To get plaintext you have to simulate the loader. `strings` on the binary gives you nothing useful from the encrypted regions.

## What a method body looks like

Tuple's `getX` on SnakeGame:

1. Calls a helper at `0x3f10`. The helper has a cache check at the top: if a `.bss` slot is non null, return cached. Otherwise it does `FindClass("Tuple")`, `NewGlobalRef`, four `GetFieldID`s for `x`, `xf`, `y`, `yf`, four `GetMethodID`s for the public methods, and stores each result in a `.bss` slot.
2. Loads the cached field id for `x`.
3. `GetIntField(env, this, fieldID)`.
4. `ExceptionCheck`, return the int.

That's `return this.x;` translated to JNI calls. The lifter recognizes the pattern and emits `aload_0; getfield Tuple.x:I; ireturn`. Same for `getY`, `getXf`, `getYf`.

For HelloWorld's `main`:

1. Helper resolves `java/lang/System` and the field id for `out`.
2. `GetStaticObjectField(env, sysClass, outFieldID)` to fetch `System.out`.
3. The literal `"Hello, world!"` is built as a UTF 16 jchar array on the stack, then `NewString(env, jchars, 13)`.
4. Helper resolves `java/io/PrintStream`. `GetMethodID` for `println(String)V` with a byte spinlock for thread safety.
5. `CallVoidMethod(env, systemOut, printlnId, jstring)`.

Lifted bytecode: `getstatic System.out; ldc "Hello, world!"; invokevirtual println; return`. Decompile and you get the original four lines back.

## What JNIC actually obfuscates

In rough order of how much trouble each one is:

* **Bytecode stripping with `RegisterNatives` binding.** This is the only meaningful piece. If you don't read the binary you don't know what the method does.
* **JNI string chunking.** Strings longer than 16 bytes get split into a 16 byte head in `.rodata` plus tail bytes as immediate stores. Defeats `strings`. Reassembled by any disassembler that walks one function.
* **XOR string encryption** (we assume newer builds only). Class names and method signatures stored as ciphertext with XOR keys. Decrypted inline at the bootstrap and at every helper. To recover plaintext statically, simulate the loader.
* **Dead store junk.** Write 16 random bytes to a stack slot, immediately overwrite. Adds noise, folded by data flow.
* **Cached lookups with byte spinlocks.** First call fills the cache, subsequent calls hit it. Adds branch density, no real difficulty.
* **Single bootstrap export.** Only `Java_<class>__00024jnicLoader` is exported. Real functions are bound by `RegisterNatives` and have no public names. Walk the call graph from the bootstrap.
* **One LZMA2 blob containing every platform.** Mild logistical hassle. Four lines of Python with `lzma.LZMADecompressor`.
* **Windows TLS callback patching.** Windows binaries only. Two TLS callbacks at DLL load walk a patch table and use `VirtualProtect` to write 4 byte fixups into specific call sites in `.text`. Static disassembly sees the pre patch bytes; the running process sees the patched bytes. Linux and macOS don't have this layer.

## What JNIC does not have

No VMProtect, no Themida, no commercial protector wrapping. No anti debug. No code encryption. No control flow flattening, no opaque predicates. No anti tamper. No checksum on the blob. No per build polymorphism in the binary: the bootstrap symbol name is identical across builds, the build host path leaks, the same source produces a fingerprint identical native output.

YARA rule for any JNIC binary: any DLL or `.so` exporting `Java_*__00024jnicLoader`.

## How far the lifter gets

The toolkit ships a real bytecode lifter. Every emitted op is provably equivalent to the JNI calls in the trace.

For HelloWorld, every method lifts. The output jar is one class file that runs and prints `Hello, world!`.

For SnakeGame, seven of nineteen methods lift:

* The four `Tuple` getters.
* `Tuple.ChangeData(int, int)` to two `putfield`s.
* `SquarePanel.ChangeColor` to `setBackground` then `repaint`.
* `Window.<clinit>` restored from `$jnicClinit`. JNIC moved the original body into a synthetic native; we lift it and reinstall the real `<clinit>` that does `Window.width = 20; Window.height = 20`.

The other twelve don't lift. They have control flow we don't fake. The simulator detects branches (`jne`, `jl`, computed `jmp reg`) and refuses. That refusal is the design: a linear walk through a switch statement would emit one branch's calls and call it the whole method.

What it would take to lift more, in order of effort:

* Linear sequence of method calls. Roughly 35 percent on typical jars. Shipped.
* Integer arithmetic between locals. Roughly 45 percent. Easy to add when you have a sample that needs it.
* Single `if` / `else`. Roughly 60 percent. Needs CFG analysis.
* Loops. Roughly 75 percent. Real CFG work.
* Exception handling. Roughly 85 percent. The remaining 15 is research territory.

For the methods that don't lift, the JNI call trace is preserved and viewable through `jnic-unpack trace`. Same information a decompiler would synthesize, just rendered as JNI calls instead of pseudocode.

## Defeat time

Without the toolkit, an analyst with `cfr`, `lzma`, and `objdump` can do the whole pipeline in well under an hour. With the toolkit:

```
jnic-unpack unpack input.jar -o clean.jar
```
