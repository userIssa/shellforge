# ShellForge

**Constraint-Aware Shellcode Generator**

ShellForge synthesises shellcode dynamically based on environmental constraints — bad characters, size limits, target architecture, OS, and goal. Not templates. Not encoding wrappers. Actual instruction-level construction driven by a constraint solver.

## Architecture

```
Frontend (React + Vite)
        │ REST API
Python Orchestration Layer  ←→  GPT-4o-mini (annotation)
        │ ctypes
C Core Engine (.so / .dll)
```

## Supported Targets (Phase roadmap)

| Phase | Arch    | OS      | Goals                                |
|-------|---------|---------|--------------------------------------|
| 1     | x86-64  | Linux   | execve(/bin/sh)                      |
| 2     | x86-64  | Linux   | + reverse shell, bind shell, arb write |
| 3     | x86-32, ARM, MIPS | Linux | All goals               |
| 4     | All     | Windows | All goals                            |

## Build

### C Core (shared library)

```bash
cd core
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make
```

Output: `core/build/libshellforge.so`

### CLI smoke test

```bash
./build/sf_cli
./build/sf_cli --null-free
./build/sf_cli --bad-chars 00,0a,0d
./build/sf_cli --bad-chars 48 --size 64
```

### Python tests

```bash
# From project root
python tests/python/test_phase1.py
```

### Python bridge (REPL)

```python
from python.engine.shellforge_bridge import ShellForge, Constraints, Arch, OS

sf = ShellForge()
c  = Constraints(null_free=True)
r  = sf.synthesize(c)
print(r.hex_escaped())
print(r.disasm)
```

## Project Structure

```
shellforge/
├── core/
│   ├── include/
│   │   └── shellforge.h        # Constraint model + public API
│   ├── src/
│   │   ├── shellforge.c        # Core implementation
│   │   └── cli.c               # CLI test binary
│   └── CMakeLists.txt
├── python/
│   └── engine/
│       └── shellforge_bridge.py  # ctypes bridge
├── frontend/                     # React dashboard (Phase 5)
├── tests/
│   └── python/
│       └── test_phase1.py
└── README.md
```

## Phase Status

- [x] Phase 1 — C core scaffold, constraint model, x86-64 Linux execve, Python bridge
- [ ] Phase 2 — Constraint solver engine, encoding, multi-goal
- [ ] Phase 3 — Architecture expansion (x86-32, ARM, MIPS)
- [ ] Phase 4 — Python orchestration + Flask API + GPT-4o-mini
- [ ] Phase 5 — React dashboard
- [ ] Phase 6 — Evaluation + benchmarking
