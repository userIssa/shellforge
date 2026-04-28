#!/usr/bin/env python3
"""
benchmark.py — ShellForge Phase 6
──────────────────────────────────
Benchmarks ShellForge against msfvenom and pwntools across
constraint profiles. Produces a results table and JSON report.

Metrics:
  - synthesis_ok     : did the tool produce a payload?
  - payload_size     : bytes in output
  - clean            : no forbidden bytes in output?
  - time_ms          : synthesis time in milliseconds

Usage:
    cd ~/shellforge
    python tools/benchmark.py
    python tools/benchmark.py --json results.json
    python tools/benchmark.py --no-msf   (skip msfvenom)
"""

import sys, os, json, time, subprocess, argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from python.engine.shellforge_bridge import (
    ShellForge, Constraints, Arch, OS, Goal, Encoding, SFStatus
)

# ── Constraint profiles ──────────────────────────────────────
# Each profile is what we test across all three tools.
# Profiles escalate in difficulty.

PROFILES = [
    {
        "id":    "P01",
        "label": "x86-64 Linux execve — no constraints",
        "arch":  "x86_64", "os": "linux", "goal": "exec_shell",
        "bad_chars": [], "null_free": False,
        "msf_payload":  "linux/x64/exec",
        "msf_opts":     "CMD=/bin/sh",
        "pwn_arch":     "amd64", "pwn_os": "linux",
        "pwn_shellcode": "shellcraft.amd64.linux.sh()",
    },
    {
        "id":    "P02",
        "label": "x86-64 Linux execve — null-free",
        "arch":  "x86_64", "os": "linux", "goal": "exec_shell",
        "bad_chars": ["00"], "null_free": True,
        "msf_payload":  "linux/x64/exec",
        "msf_opts":     "CMD=/bin/sh",
        "msf_bad":      "\\x00",
        "pwn_arch":     "amd64", "pwn_os": "linux",
        "pwn_shellcode": "shellcraft.amd64.linux.sh()",
    },
    {
        "id":    "P03",
        "label": "x86-64 Linux execve — bad chars 00,0a,0d",
        "arch":  "x86_64", "os": "linux", "goal": "exec_shell",
        "bad_chars": ["00","0a","0d"], "null_free": True,
        "msf_payload":  "linux/x64/exec",
        "msf_opts":     "CMD=/bin/sh",
        "msf_bad":      "\\x00\\x0a\\x0d",
        "pwn_arch":     "amd64", "pwn_os": "linux",
        "pwn_shellcode": "shellcraft.amd64.linux.sh()",
    },
    {
        "id":    "P04",
        "label": "x86-64 Linux execve — bad chars 00,0a,0d,20,2f",
        "arch":  "x86_64", "os": "linux", "goal": "exec_shell",
        "bad_chars": ["00","0a","0d","20","2f"], "null_free": True,
        "msf_payload":  "linux/x64/exec",
        "msf_opts":     "CMD=/bin/sh",
        "msf_bad":      "\\x00\\x0a\\x0d\\x20\\x2f",
        "pwn_arch":     "amd64", "pwn_os": "linux",
        "pwn_shellcode": "shellcraft.amd64.linux.sh()",
    },
    {
        "id":    "P05",
        "label": "x86-64 Linux reverse shell — null-free",
        "arch":  "x86_64", "os": "linux", "goal": "reverse_shell",
        "bad_chars": ["00"], "null_free": True,
        "goal_args": ["127.0.0.1:4444"],
        "msf_payload":  "linux/x64/shell_reverse_tcp",
        "msf_opts":     "LHOST=127.0.0.1 LPORT=4444",
        "msf_bad":      "\\x00",
        "pwn_arch":     "amd64", "pwn_os": "linux",
        "pwn_shellcode": "shellcraft.amd64.linux.connect('127.0.0.1',4444)+shellcraft.amd64.linux.dupsh()",
    },
    {
        "id":    "P06",
        "label": "x86-32 Linux execve — null-free",
        "arch":  "x86_32", "os": "linux", "goal": "exec_shell",
        "bad_chars": ["00"], "null_free": True,
        "msf_payload":  "linux/x86/exec",
        "msf_opts":     "CMD=/bin/sh",
        "msf_bad":      "\\x00",
        "pwn_arch":     "i386", "pwn_os": "linux",
        "pwn_shellcode": "shellcraft.i386.linux.sh()",
    },
    {
        "id":    "P07",
        "label": "x86-32 Linux execve — bad chars 00,0a,0d,ff",
        "arch":  "x86_32", "os": "linux", "goal": "exec_shell",
        "bad_chars": ["00","0a","0d","ff"], "null_free": True,
        "msf_payload":  "linux/x86/exec",
        "msf_opts":     "CMD=/bin/sh",
        "msf_bad":      "\\x00\\x0a\\x0d\\xff",
        "pwn_arch":     "i386", "pwn_os": "linux",
        "pwn_shellcode": "shellcraft.i386.linux.sh()",
    },
    {
        "id":    "P08",
        "label": "ARM Linux execve — null-free",
        "arch":  "arm", "os": "linux", "goal": "exec_shell",
        "bad_chars": ["00"], "null_free": True,
        "msf_payload":  "linux/armle/exec",
        "msf_opts":     "CMD=/bin/sh",
        "msf_bad":      "\\x00",
        "pwn_arch":     "arm", "pwn_os": "linux",
        "pwn_shellcode": "shellcraft.arm.linux.sh()",
    },
    {
        "id":    "P09",
        "label": "MIPS Linux execve — null-free",
        "arch":  "mips", "os": "linux", "goal": "exec_shell",
        "bad_chars": ["00"], "null_free": True,
        "msf_payload":  "linux/mipsbe/exec",
        "msf_opts":     "CMD=/bin/sh",
        "msf_bad":      "\\x00",
        "pwn_arch":     "mips", "pwn_os": "linux",
        "pwn_shellcode": "shellcraft.mips.linux.sh()",
    },
    {
        "id":    "P10",
        "label": "x86-64 Linux execve — size budget 60 bytes",
        "arch":  "x86_64", "os": "linux", "goal": "exec_shell",
        "bad_chars": [], "null_free": False, "size_budget": 60,
        "msf_payload":  "linux/x64/exec",
        "msf_opts":     "CMD=/bin/sh",
        "pwn_arch":     "amd64", "pwn_os": "linux",
        "pwn_shellcode": "shellcraft.amd64.linux.sh()",
    },
]

ARCH_MAP = {"x86_64": Arch.X86_64, "x86_32": Arch.X86_32,
            "arm": Arch.ARM, "mips": Arch.MIPS}
OS_MAP   = {"linux": OS.LINUX, "windows": OS.WINDOWS}
GOAL_MAP = {"exec_shell": Goal.EXEC_SHELL, "reverse_shell": Goal.REVERSE_SHELL,
            "bind_shell": Goal.BIND_SHELL}

# ── Tool runners ─────────────────────────────────────────────

def run_shellforge(sf, profile):
    c = Constraints(
        arch        = ARCH_MAP[profile["arch"]],
        os          = OS_MAP[profile["os"]],
        goal        = GOAL_MAP[profile["goal"]],
        null_free   = profile.get("null_free", False),
        size_budget = profile.get("size_budget", 0),
        goal_args   = profile.get("goal_args", []),
    )
    for b in profile.get("bad_chars", []):
        c.add_bad_char(int(b, 16))

    t0 = time.perf_counter()
    r  = sf.synthesize(c)
    ms = (time.perf_counter() - t0) * 1000

    bad = [int(b,16) for b in profile.get("bad_chars",[])]
    if profile.get("null_free"): bad.append(0x00)
    clean = all(b not in r.payload for b in bad) if r.ok else False

    size_ok = True
    if profile.get("size_budget") and r.ok:
        size_ok = r.payload_len <= profile["size_budget"]

    return {
        "tool":         "ShellForge",
        "ok":           r.ok and size_ok,
        "size":         r.payload_len if r.ok else 0,
        "clean":        clean,
        "time_ms":      round(ms, 2),
        "encoding":     r.encoding_used.name if r.ok else "—",
        "error":        r.error_msg if not r.ok else "",
    }


def run_msfvenom(profile):
    payload = profile.get("msf_payload")
    if not payload:
        return {"tool": "msfvenom", "ok": False, "size": 0,
                "clean": False, "time_ms": 0, "error": "no payload defined"}

    cmd = ["msfvenom", "-p", payload]
    if profile.get("msf_opts"):
        cmd += profile["msf_opts"].split()
    if profile.get("msf_bad"):
        cmd += ["-b", profile["msf_bad"]]
    if profile.get("size_budget"):
        pass  # msfvenom doesn't have a direct size limit flag
    cmd += ["-f", "raw", "--platform", "linux", "-a",
            {"x86_64":"x64","x86_32":"x86","arm":"arm","mips":"mips"}.get(profile["arch"],"x64")]

    t0 = time.perf_counter()
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        ms = (time.perf_counter() - t0) * 1000
        if result.returncode != 0:
            return {"tool": "msfvenom", "ok": False, "size": 0,
                    "clean": False, "time_ms": round(ms,2),
                    "error": result.stderr.decode(errors="replace")[:100]}

        payload_bytes = result.stdout
        bad = [int(b,16) for b in profile.get("bad_chars",[])]
        if profile.get("null_free"): bad.append(0x00)
        clean = all(b not in payload_bytes for b in bad)
        size_ok = True
        if profile.get("size_budget"):
            size_ok = len(payload_bytes) <= profile["size_budget"]

        return {"tool": "msfvenom", "ok": True and size_ok,
                "size": len(payload_bytes), "clean": clean,
                "time_ms": round(ms,2), "error": ""}
    except FileNotFoundError:
        return {"tool": "msfvenom", "ok": False, "size": 0,
                "clean": False, "time_ms": 0, "error": "msfvenom not found"}
    except subprocess.TimeoutExpired:
        return {"tool": "msfvenom", "ok": False, "size": 0,
                "clean": False, "time_ms": 30000, "error": "timeout"}


def run_pwntools(profile):
    sc_expr = profile.get("pwn_shellcode")
    if not sc_expr:
        return {"tool": "pwntools", "ok": False, "size": 0,
                "clean": False, "time_ms": 0, "error": "no shellcode defined"}

    script = f"""
import sys
os.environ['PWNLIB_NOTERM'] = '1'
import warnings
warnings.filterwarnings('ignore')
from pwn import *
context.arch = '{profile["pwn_arch"]}'
context.os   = '{profile["pwn_os"]}'
context.log_level = 'error'
import time
t0 = time.perf_counter()
try:
    sc = asm({sc_expr})
    ms = (time.perf_counter()-t0)*1000
    sys.stdout.buffer.write(sc)
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
"""
    t0 = time.perf_counter()
    try:
        result = subprocess.run(
            ["python3", "-c",
             f"import os\n{script}"],
            capture_output=True, timeout=30
        )
        ms = (time.perf_counter() - t0) * 1000
        if result.returncode != 0:
            return {"tool": "pwntools", "ok": False, "size": 0,
                    "clean": False, "time_ms": round(ms,2),
                    "error": result.stderr.decode(errors="replace")[:100]}

        payload_bytes = result.stdout
        if not payload_bytes:
            return {"tool": "pwntools", "ok": False, "size": 0,
                    "clean": False, "time_ms": round(ms,2),
                    "error": "empty output"}

        bad = [int(b,16) for b in profile.get("bad_chars",[])]
        if profile.get("null_free"): bad.append(0x00)
        clean = all(b not in payload_bytes for b in bad)
        size_ok = True
        if profile.get("size_budget"):
            size_ok = len(payload_bytes) <= profile["size_budget"]

        return {"tool": "pwntools", "ok": True and size_ok,
                "size": len(payload_bytes), "clean": clean,
                "time_ms": round(ms,2), "error": ""}
    except FileNotFoundError:
        return {"tool": "pwntools", "ok": False, "size": 0,
                "clean": False, "time_ms": 0, "error": "python3 not found"}
    except subprocess.TimeoutExpired:
        return {"tool": "pwntools", "ok": False, "size": 0,
                "clean": False, "time_ms": 30000, "error": "timeout"}


# ── Result formatting ─────────────────────────────────────────

def fmt_ok(v):    return "✅" if v else "❌"
def fmt_clean(v): return "✅" if v else "❌"

def print_table(all_results):
    col_w = 14
    print("\n" + "═"*90)
    print("  ShellForge Benchmark Results")
    print("═"*90)

    for profile, results in all_results:
        print(f"\n  [{profile['id']}] {profile['label']}")
        print(f"  {'─'*86}")
        hdr = f"  {'Tool':<14} {'OK':<6} {'Size':>8} {'Clean':<8} {'Time(ms)':>10} {'Encoding':<12} Note"
        print(hdr)
        print(f"  {'─'*86}")
        for r in results:
            note = r.get("error","")[:30] if not r["ok"] else r.get("encoding","")
            print(f"  {r['tool']:<14} {fmt_ok(r['ok']):<6} {r['size']:>7}B "
                  f"{fmt_clean(r['clean']):<8} {r['time_ms']:>9.1f}ms "
                  f"{r.get('encoding','—'):<12} {note}")

    # Summary stats
    print(f"\n{'═'*90}")
    print("  Summary")
    print(f"{'─'*90}")

    tools = ["ShellForge", "msfvenom", "pwntools"]
    for tool in tools:
        tool_results = [r for _,results in all_results for r in results if r["tool"]==tool]
        if not tool_results: continue
        total    = len(tool_results)
        ok       = sum(1 for r in tool_results if r["ok"])
        clean    = sum(1 for r in tool_results if r["clean"])
        avg_size = sum(r["size"] for r in tool_results if r["ok"]) / max(ok,1)
        avg_time = sum(r["time_ms"] for r in tool_results) / total
        print(f"  {tool:<14} success={ok}/{total}  clean={clean}/{total}  "
              f"avg_size={avg_size:.0f}B  avg_time={avg_time:.1f}ms")
    print(f"{'═'*90}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-msf",  action="store_true", help="skip msfvenom")
    parser.add_argument("--no-pwn",  action="store_true", help="skip pwntools")
    parser.add_argument("--json",    default="", help="save JSON report to file")
    parser.add_argument("--profile", default="", help="run single profile by ID e.g. P01")
    args = parser.parse_args()

    print("\n── ShellForge Phase 6 Benchmark ─────────────────────────\n")

    sf = ShellForge()
    print(f"[+] {sf.version()}")

    msf_avail = not args.no_msf and (
        subprocess.run(["which","msfvenom"], capture_output=True).returncode == 0
    )
    pwn_avail = not args.no_pwn
    print(f"[+] msfvenom : {'available' if msf_avail else 'skipped'}")
    print(f"[+] pwntools : {'available' if pwn_avail else 'skipped'}")

    profiles = PROFILES
    if args.profile:
        profiles = [p for p in PROFILES if p["id"] == args.profile]
        if not profiles:
            print(f"[!] Profile {args.profile} not found")
            return

    all_results = []
    for i, profile in enumerate(profiles):
        print(f"\n[{i+1}/{len(profiles)}] {profile['id']}: {profile['label']}")

        results = []

        # ShellForge
        r = run_shellforge(sf, profile)
        results.append(r)
        status = "✅" if r["ok"] else "❌"
        print(f"  ShellForge : {status} {r['size']}B  {r['time_ms']:.1f}ms  enc={r['encoding']}")

        # msfvenom
        if msf_avail:
            r = run_msfvenom(profile)
            results.append(r)
            status = "✅" if r["ok"] else "❌"
            print(f"  msfvenom   : {status} {r['size']}B  {r['time_ms']:.1f}ms")

        # pwntools
        if pwn_avail:
            r = run_pwntools(profile)
            results.append(r)
            status = "✅" if r["ok"] else "❌"
            print(f"  pwntools   : {status} {r['size']}B  {r['time_ms']:.1f}ms")

        all_results.append((profile, results))

    print_table(all_results)

    if args.json:
        report = []
        for profile, results in all_results:
            report.append({
                "profile": profile,
                "results": results,
            })
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] JSON report saved to: {args.json}")

if __name__ == "__main__":
    main()
