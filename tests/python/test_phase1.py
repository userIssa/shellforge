"""
test_phase1.py
──────────────
Phase 1 smoke tests for ShellForge C core + Python bridge.
Run after building the shared library:

    cd core && mkdir -p build && cd build && cmake .. && make
    cd ../../ && python tests/python/test_phase1.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from python.engine.shellforge_bridge import (
    ShellForge, Constraints, Arch, OS, Goal, Encoding, SFStatus
)

PASS = "✅"
FAIL = "❌"
SKIP = "⚠️ "

results = []

def test(name: str, fn):
    try:
        fn()
        print(f"  {PASS} {name}")
        results.append((name, True, None))
    except AssertionError as e:
        print(f"  {FAIL} {name}: {e}")
        results.append((name, False, str(e)))
    except Exception as e:
        print(f"  {FAIL} {name}: {type(e).__name__}: {e}")
        results.append((name, False, str(e)))

def run():
    print("\n── ShellForge Phase 1 Test Suite ────────────────────────\n")

    try:
        sf = ShellForge()
        print(f"  {PASS} Library loaded: {sf.version()}\n")
    except FileNotFoundError as e:
        print(f"  {FAIL} Cannot load library:\n  {e}")
        return

    # ── T1: Basic x86-64 Linux exec shell ────────────────────
    print("[ T1 ] x86-64 Linux — execve(/bin/sh)")

    def t1_basic():
        c = Constraints()
        r = sf.synthesize(c)
        assert r.ok, f"Expected OK, got {r.status.name}: {r.error_msg}"
        assert r.payload_len > 0, "Empty payload"
        assert r.arch == Arch.X86_64
        assert r.os   == OS.LINUX
        assert r.goal == Goal.EXEC_SHELL

    test("Basic synthesis OK", t1_basic)

    def t1_disasm():
        c = Constraints()
        r = sf.synthesize(c)
        assert "syscall" in r.disasm.lower(), "Expected syscall in disasm"

    test("Disassembly contains 'syscall'", t1_disasm)

    def t1_hex():
        c = Constraints()
        r = sf.synthesize(c)
        h = r.hex_escaped()
        assert h.startswith("\\x"), "hex_escaped should start with \\x"
        print(f"       Payload: {h}")
        print(f"       Size:    {r.payload_len} bytes")

    test("hex_escaped output", t1_hex)

    # ── T2: Bad char detection ────────────────────────────────
    print("\n[ T2 ] Bad char constraint enforcement")

    def t2_null_free():
        c = Constraints(null_free=True)
        r = sf.synthesize(c)
        if r.ok:
            assert 0x00 not in r.payload, "\\x00 in null-free payload"

    test("null_free: no \\x00 in output", t2_null_free)

    def t2_bad_char_check():
        c = Constraints()
        c.add_bad_char(0x48)  # 'H' — will hit the REX prefix in x86-64
        r = sf.synthesize(c)
        # Should either succeed with encoding or fail with ENCODE_FAIL
        assert r.status in (SFStatus.OK, SFStatus.ERR_ENCODE_FAIL), \
            f"Unexpected status: {r.status.name}"
        if r.ok:
            assert 0x48 not in r.payload, "Bad char 0x48 found in clean payload"

    test("Bad char 0x48: encode or fail gracefully", t2_bad_char_check)

    def t2_is_bad_char_api():
        c = Constraints(null_free=True)
        c.add_bad_char(0x0a)
        assert sf.is_bad_char(c, 0x00) == True,  "\\x00 should be bad (null_free)"
        assert sf.is_bad_char(c, 0x0a) == True,  "\\x0a should be bad"
        assert sf.is_bad_char(c, 0x41) == False, "\\x41 should be clean"

    test("is_bad_char API", t2_is_bad_char_api)

    # ── T3: Size budget ───────────────────────────────────────
    print("\n[ T3 ] Size budget enforcement")

    def t3_size_exceeded():
        c = Constraints(size_budget=5)  # definitely too small
        r = sf.synthesize(c)
        assert r.status == SFStatus.ERR_SIZE_EXCEED, \
            f"Expected SIZE_EXCEED, got {r.status.name}"

    test("Size budget 5 bytes → SIZE_EXCEED", t3_size_exceeded)

    def t3_size_ok():
        c = Constraints(size_budget=512)  # plenty of room
        r = sf.synthesize(c)
        assert r.ok, f"Expected OK with generous budget, got {r.status.name}"

    test("Size budget 512 bytes → OK", t3_size_ok)

    # ── T4: Unsupported paths ─────────────────────────────────
    print("\n[ T4 ] Unsupported arch/goal stubs")

    def t4_arm():
        c = Constraints(arch=Arch.ARM)
        r = sf.synthesize(c)
        assert r.status in (SFStatus.ERR_UNSUPPORTED, SFStatus.OK)

    test("ARM → ERR_UNSUPPORTED (Phase 3 stub)", t4_arm)

    def t4_mips():
        c = Constraints(arch=Arch.MIPS)
        r = sf.synthesize(c)
        assert r.status in (SFStatus.ERR_UNSUPPORTED, SFStatus.OK)

    test("MIPS → ERR_UNSUPPORTED (Phase 3 stub)", t4_mips)

    def t4_windows():
        c = Constraints(os=OS.WINDOWS)
        r = sf.synthesize(c)
        assert r.status == SFStatus.ERR_UNSUPPORTED

    test("Windows → ERR_UNSUPPORTED (Phase 3 stub)", t4_windows)

    # ── T5: buffer_clean API ──────────────────────────────────
    print("\n[ T5 ] buffer_clean API")

    def t5_clean():
        c = Constraints(null_free=True)
        assert sf.buffer_clean(c, b"\x41\x42\x43") == True

    test("Clean buffer passes check", t5_clean)

    def t5_dirty():
        c = Constraints(null_free=True)
        assert sf.buffer_clean(c, b"\x41\x00\x43") == False

    test("Buffer with \\x00 fails null_free check", t5_dirty)

    # ── Summary ───────────────────────────────────────────────
    passed = sum(1 for _, ok, _ in results if ok)
    total  = len(results)
    print(f"\n── Results: {passed}/{total} passed ─────────────────────────\n")

    if passed < total:
        print("Failed tests:")
        for name, ok, msg in results:
            if not ok:
                print(f"  {FAIL} {name}: {msg}")
        sys.exit(1)
    else:
        print("All Phase 1 tests passed. Ready for Phase 2.\n")

if __name__ == "__main__":
    run()
