from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile

import pytest

from jnic_unpack import classfile, orchestrator


SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "HelloWorld-jnic.jar")


@pytest.fixture
def out_dir():
    d = tempfile.mkdtemp(prefix="jnic_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample HelloWorld-jnic.jar not available")
def test_strip_phase(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    report = orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    with zipfile.ZipFile(out_jar) as zf:
        names = zf.namelist()
    assert not any(n.startswith("dev/jnic/JmEMUM/") for n in names)
    assert not any(n.endswith(".dat") for n in names)
    assert report.loader_class == "dev/jnic/JmEMUM/JNICLoader"


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample HelloWorld-jnic.jar not available")
def test_carve_phase(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    report = orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    platforms = {n["platform"] for n in report.natives_carved}
    assert platforms == {
        "linux_x86_64", "linux_aarch64",
        "windows_x86_64", "windows_aarch64",
        "macos_x86_64", "macos_aarch64",
    }
    by_platform = {n["platform"]: n for n in report.natives_carved}
    assert by_platform["linux_x86_64"]["kind"] == "elf"
    assert by_platform["windows_x86_64"]["kind"] == "pe"
    assert by_platform["macos_aarch64"]["kind"] == "macho"


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample HelloWorld-jnic.jar not available")
def test_lift_phase(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    report = orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    cls = next((c for c in report.classes_modified if c["class"] == "dev/jnic/HelloWorld"), None)
    assert cls is not None
    lifted_methods = cls["report"]["lifted_methods"]
    assert any(m["method"] == ["main", "([Ljava/lang/String;)V"] or
               tuple(m["method"]) == ("main", "([Ljava/lang/String;)V")
               for m in lifted_methods)


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample HelloWorld-jnic.jar not available")
def test_output_jar_runs(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    java = shutil.which("java")
    if java is None:
        pytest.skip("no java on PATH")
    result = subprocess.run([java, "-jar", out_jar], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert "Hello, world!" in result.stdout


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample HelloWorld-jnic.jar not available")
def test_lifted_main_matches_javac_pattern(out_dir):
    out_jar = os.path.join(out_dir, "out.jar")
    orchestrator.deobfuscate(SAMPLE, out_jar, natives_dir=os.path.join(out_dir, "natives"))
    with zipfile.ZipFile(out_jar) as zf:
        cls_data = zf.read("dev/jnic/HelloWorld.class")
    cf = classfile.parse(cls_data)
    main = next(m for m in cf.methods if cf.method_name(m) == "main")
    assert not (main.access_flags & classfile.ACC_NATIVE)
    code_attr = cf.find_attribute(main.attributes, "Code")
    assert code_attr is not None
    code = classfile.parse_code(code_attr.info)
    bc = code.bytecode
    assert bc[0] == 0xB2
    assert bc[3] in (0x12, 0x13)
    if bc[3] == 0x12:
        assert bc[5] == 0xB6
        assert bc[8] == 0xB1
    else:
        assert bc[6] == 0xB6
        assert bc[9] == 0xB1
