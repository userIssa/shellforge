"""
test_phase5.py
──────────────
Phase 5: Windows x86-64 synthesis tests.
Covers PEB-walk WinExec shellcode, arb write,
encoder constraints, and unsupported path handling.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from python.engine.shellforge_bridge import (
    ShellForge, Constraints, Arch, OS, Goal, Encoding, SFStatus
)

PASS="✅"; FAIL="❌"
results=[]

def test(name, fn):
    try:
        fn()
        print(f"  {PASS} {name}")
        results.append((name,True,None))
    except Exception as e:
        print(f"  {FAIL} {name}: {e}")
        results.append((name,False,str(e)))

def run():
    print("\n── ShellForge Phase 5 Test Suite (Windows) ─────────────\n")
    try:
        sf = ShellForge()
        print(f"  {PASS} Library loaded: {sf.version()}\n")
    except FileNotFoundError as e:
        print(f"  {FAIL} {e}"); return

    # ── T1: WinExec via PEB walk ──────────────────────────────
    print("[ T1 ] Windows x86-64 WinExec (PEB walk)")

    def t1_basic():
        c = Constraints(os=OS.WINDOWS)
        r = sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.payload_len > 0
        assert r.os == OS.WINDOWS
        assert r.arch == Arch.X86_64
        print(f"       size: {r.payload_len} bytes")
        print(f"       {r.hex_escaped()[:80]}...")
    test("Windows exec_shell synthesis OK", t1_basic)

    def t1_peb_bytes():
        c = Constraints(os=OS.WINDOWS)
        r = sf.synthesize(c)
        assert r.ok
        # GS:[0x60] = 0x65 0x48 0x8b 0x04 0x25 0x60
        assert bytes([0x65,0x48,0x8b,0x04,0x25,0x60]) in r.payload
    test("PEB access bytes present (gs:[0x60])", t1_peb_bytes)

    def t1_ror13_hash():
        c = Constraints(os=OS.WINDOWS)
        r = sf.synthesize(c)
        assert r.ok
        # WinExec ROR13 hash = 0x98FE8A0E (little-endian: 0e 8a fe 98)
        assert bytes([0x0e,0x8a,0xfe,0x98]) in r.payload
    test("WinExec ROR13 hash present (0x98FE8A0E)", t1_ror13_hash)

    def t1_disasm():
        c = Constraints(os=OS.WINDOWS)
        r = sf.synthesize(c)
        assert r.ok
        assert "peb" in r.disasm.lower()
        assert "winexec" in r.disasm.lower()
    test("Disasm documents PEB walk + WinExec", t1_disasm)

    # ── T2: Constraints ───────────────────────────────────────
    print("\n[ T2 ] Constraint enforcement")

    def t2_null_free():
        c = Constraints(os=OS.WINDOWS, null_free=True)
        r = sf.synthesize(c)
        # May encode or fail — either is valid
        if r.ok:
            assert 0x00 not in r.payload
        print(f"       null_free: {r.status.name} enc={r.encoding_used.name}")
    test("null_free constraint", t2_null_free)

    def t2_size_exceed():
        c = Constraints(os=OS.WINDOWS, size_budget=10)
        r = sf.synthesize(c)
        assert r.status == SFStatus.ERR_SIZE_EXCEED
    test("Size budget exceeded → ERR_SIZE_EXCEED", t2_size_exceed)

    def t2_bad_chars():
        c = Constraints(os=OS.WINDOWS)
        bad = [0x2f,0x62,0x69,0x6e,0x73,0x68]
        for b in bad: c.add_bad_char(b)
        r = sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        hits = [b for b in r.payload if b in bad]
        assert not hits, f"banned bytes in output: {[hex(b) for b in hits]}"
        print(f"       encoded clean: {r.payload_len} bytes enc={r.encoding_used.name}")
    test("Bad chars avoided via encoder", t2_bad_chars)

    # ── T3: Arbitrary write ───────────────────────────────────
    print("\n[ T3 ] Windows arbitrary write")

    def t3_arb():
        c = Constraints(os=OS.WINDOWS, goal=Goal.ARBITRARY_WRITE)
        c.goal_args = ["0x7fffffffe000","0x4141414141414141"]
        r = sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.payload[-1] == 0xc3
        print(f"       size: {r.payload_len} bytes")
    test("Windows arbitrary write", t3_arb)

    def t3_missing_args():
        c = Constraints(os=OS.WINDOWS, goal=Goal.ARBITRARY_WRITE)
        r = sf.synthesize(c)
        assert r.status == SFStatus.ERR_INVALID_ARG
    test("Missing args → ERR_INVALID_ARG", t3_missing_args)

    # ── T4: Unsupported paths ─────────────────────────────────
    print("\n[ T4 ] Unsupported paths")

    def t4_revshell():
        c = Constraints(os=OS.WINDOWS, goal=Goal.REVERSE_SHELL)
        c.goal_args = ["192.168.1.1:4444"]
        r = sf.synthesize(c)
        assert r.status == SFStatus.ERR_UNSUPPORTED
    test("Windows reverse shell → ERR_UNSUPPORTED (next phase)", t4_revshell)

    def t4_arm_windows():
        c = Constraints(os=OS.WINDOWS, arch=Arch.ARM)
        r = sf.synthesize(c)
        assert r.status == SFStatus.ERR_UNSUPPORTED
    test("Windows ARM → ERR_UNSUPPORTED", t4_arm_windows)

    # ── T5: Regression ───────────────────────────────────────
    print("\n[ T5 ] Cross-platform regression")

    def t5_linux_unaffected():
        c = Constraints()
        r = sf.synthesize(c)
        assert r.ok and r.payload_len == 26 and r.os == OS.LINUX
    test("Linux x86-64 execve unaffected", t5_linux_unaffected)

    def t5_all_linux_archs():
        for arch in [Arch.X86_64, Arch.X86_32, Arch.ARM, Arch.MIPS]:
            c = Constraints(arch=arch)
            r = sf.synthesize(c)
            assert r.ok, f"{arch.name} failed: {r.error_msg}"
    test("All Linux archs still synthesise", t5_all_linux_archs)

    # ── Summary ──────────────────────────────────────────────
    passed = sum(1 for _,ok,_ in results if ok)
    total  = len(results)
    print(f"\n── Results: {passed}/{total} passed ─────────────────────────\n")
    if passed < total:
        for name,ok,msg in results:
            if not ok: print(f"  {FAIL} {name}: {msg}")
        sys.exit(1)
    else:
        print("All Phase 5 tests passed.\n")

if __name__ == "__main__":
    run()
