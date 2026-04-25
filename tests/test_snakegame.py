from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile

import pytest

from jnic_unpack import classfile, dumps, orchestrator


SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "SnakeGame-jnic.jar")


@pytest.fixture
def out_dir():
    d = tempfile.mkdtemp(prefix="jnic_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_loader_with_randomized_package(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    report = orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    assert report.loader_class is not None
    assert report.loader_class.startswith("dev/jnic/")
    assert report.loader_class.endswith("/JNICLoader")
    assert "JmEMUM" not in report.loader_class


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_seven_classes_modified(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    report = orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    classes = {c["class"] for c in report.classes_modified}
    assert classes == {"DataOfSquare", "KeyboardListener", "Main", "SquarePanel",
                       "ThreadsController", "Tuple", "Window"}


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_tuple_getters_lifted(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    report = orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    tuple_report = next(c for c in report.classes_modified if c["class"] == "Tuple")
    lifted = {tuple(m["method"]) for m in tuple_report["report"]["lifted_methods"]}
    assert ("getX", "()I") in lifted
    assert ("getY", "()I") in lifted
    assert ("getXf", "()I") in lifted
    assert ("getYf", "()I") in lifted


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_lifted_getter_bytecode(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    with zipfile.ZipFile(out_jar) as zf:
        cls_data = zf.read("Tuple.class")
    cf = classfile.parse(cls_data)
    get_x = next(m for m in cf.methods if cf.method_name(m) == "getX")
    assert not (get_x.access_flags & classfile.ACC_NATIVE)
    code_attr = cf.find_attribute(get_x.attributes, "Code")
    code = classfile.parse_code(code_attr.info)
    assert code.bytecode == b"\x2a\xb4" + code.bytecode[2:4] + b"\xac"


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_window_jnicclinit_removed(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    with zipfile.ZipFile(out_jar) as zf:
        cls_data = zf.read("Window.class")
    cf = classfile.parse(cls_data)
    method_names = {cf.method_name(m) for m in cf.methods}
    assert "$jnicLoader" not in method_names
    assert "$jnicClinit" not in method_names


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_window_clinit_restored(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    with zipfile.ZipFile(out_jar) as zf:
        cls_data = zf.read("Window.class")
    cf = classfile.parse(cls_data)
    clinit = next((m for m in cf.methods if cf.method_name(m) == "<clinit>"), None)
    assert clinit is not None
    code = classfile.parse_code(cf.find_attribute(clinit.attributes, "Code").info)
    assert b"\xb3" in code.bytecode, "expected putstatic in restored <clinit>"


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_changedata_multi_setter(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    with zipfile.ZipFile(out_jar) as zf:
        cls_data = zf.read("Tuple.class")
    cf = classfile.parse(cls_data)
    cd = next(m for m in cf.methods if cf.method_name(m) == "ChangeData")
    assert not (cd.access_flags & classfile.ACC_NATIVE)
    code = classfile.parse_code(cf.find_attribute(cd.attributes, "Code").info)
    assert code.bytecode.count(b"\xb5") == 2, "expected two putfields"
    assert code.bytecode.endswith(b"\xb1")


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_changecolor_method_chain(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    with zipfile.ZipFile(out_jar) as zf:
        cls_data = zf.read("SquarePanel.class")
    cf = classfile.parse(cls_data)
    cc = next(m for m in cf.methods if cf.method_name(m) == "ChangeColor")
    assert not (cc.access_flags & classfile.ACC_NATIVE)
    code = classfile.parse_code(cf.find_attribute(cc.attributes, "Code").info)
    assert code.bytecode.count(b"\xb6") == 2, "expected two invokevirtuals"


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_branchy_methods_refused(out_dir):
    """Methods with control flow get correctly flagged as unlifted, not bogus-lifted."""
    out_jar = os.path.join(out_dir, "out.jar")
    report = orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    branchy = {("KeyboardListener", "keyPressed"), ("ThreadsController", "run"),
               ("Main", "main"), ("ThreadsController", "checkCollision")}
    seen_unlifted: set = set()
    for c in report.classes_modified:
        for m in c["report"]["unlifted_methods"]:
            seen_unlifted.add((c["class"], m["method"][0]))
    assert branchy.issubset(seen_unlifted), \
        f"expected all branchy methods unlifted, missing: {branchy - seen_unlifted}"


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_xor_string_decryption(out_dir):
    """SnakeGame uses XOR string encryption. Check that signatures are recovered."""
    ctx = dumps.load_jar_context(SAMPLE)
    data = dumps.dump_strings(ctx)
    kbd_strings = data["per_class"].get("KeyboardListener", [])
    assert any("KeyEvent" in s for s in kbd_strings), \
        f"expected KeyEvent reference recovered via XOR decrypt, got {kbd_strings!r}"


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_stub_unlifted_makes_jar_loadable(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"),
                              stub_unlifted=True)
    java = shutil.which("java")
    if java is None:
        pytest.skip("no java on PATH")
    result = subprocess.run([java, "-jar", out_jar], capture_output=True, text=True, timeout=10)
    assert "UnsupportedOperationException" in result.stderr or result.returncode == 0


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_dump_traces_includes_all_classes(out_dir):
    ctx = dumps.load_jar_context(SAMPLE)
    data = dumps.dump_traces(ctx)
    assert set(data["per_class"].keys()) == {
        "DataOfSquare", "KeyboardListener", "Main", "SquarePanel",
        "ThreadsController", "Tuple", "Window",
    }


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample SnakeGame-jnic.jar not available")
def test_six_platform_binaries(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    report = orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    platforms = {n["platform"] for n in report.natives_carved}
    assert platforms == {
        "linux_x86_64", "linux_aarch64",
        "windows_x86_64", "windows_aarch64",
        "macos_x86_64", "macos_aarch64",
    }
