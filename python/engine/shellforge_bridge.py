import ctypes
import ctypes.util
import os
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional

class Arch(IntEnum):
    X86_64  = 0
    X86_32  = 1
    ARM     = 2
    MIPS    = 3
    UNKNOWN = -1

class OS(IntEnum):
    LINUX   = 0
    WINDOWS = 1
    UNKNOWN = -1

class Goal(IntEnum):
    EXEC_SHELL      = 0
    REVERSE_SHELL   = 1
    BIND_SHELL      = 2
    ARBITRARY_WRITE = 3
    CUSTOM          = 4

class Encoding(IntEnum):
    NONE    = 0
    XOR     = 1
    ADD_SUB = 2
    AUTO    = 3

class SFStatus(IntEnum):
    OK              =  0
    ERR_BAD_CHAR    = -1
    ERR_SIZE_EXCEED = -2
    ERR_UNSUPPORTED = -3
    ERR_ENCODE_FAIL = -4
    ERR_INVALID_ARG = -5

SF_MAX_BAD_CHARS = 256
SF_MAX_PAYLOAD   = 4096
SF_MAX_GOAL_ARGS = 8
SF_MAX_ARG_LEN   = 128

class _GoalArgs(ctypes.Structure):
    _fields_ = [
        ("args", (ctypes.c_char * SF_MAX_ARG_LEN) * SF_MAX_GOAL_ARGS),
        ("argc", ctypes.c_int),
    ]

class _Constraints(ctypes.Structure):
    _fields_ = [
        ("arch",           ctypes.c_int),
        ("os",             ctypes.c_int),
        ("goal",           ctypes.c_int),
        ("goal_args",      _GoalArgs),
        ("encoding",       ctypes.c_int),
        ("bad_chars",      ctypes.c_uint8 * SF_MAX_BAD_CHARS),
        ("bad_char_count", ctypes.c_size_t),
        ("size_budget",    ctypes.c_size_t),
        ("null_free",      ctypes.c_int),
        ("newline_free",   ctypes.c_int),
    ]

class _Result(ctypes.Structure):
    _fields_ = [
        ("status",        ctypes.c_int),
        ("payload",       ctypes.c_uint8 * SF_MAX_PAYLOAD),
        ("payload_len",   ctypes.c_size_t),
        ("disasm",        ctypes.c_char * (SF_MAX_PAYLOAD * 8)),
        ("error_msg",     ctypes.c_char * 256),
        ("arch",          ctypes.c_int),
        ("os",            ctypes.c_int),
        ("goal",          ctypes.c_int),
        ("encoding_used", ctypes.c_int),
    ]

@dataclass
class SynthesisResult:
    status:        SFStatus
    payload:       bytes
    payload_len:   int
    disasm:        str
    error_msg:     str
    arch:          Arch
    os:            OS
    goal:          Goal
    encoding_used: Encoding

    @property
    def ok(self) -> bool:
        return self.status == SFStatus.OK

    def hex_escaped(self) -> str:
        return "".join(f"\\x{b:02x}" for b in self.payload)

    def hex_dump(self, width: int = 16) -> str:
        lines = []
        for i in range(0, self.payload_len, width):
            chunk = self.payload[i:i + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            lines.append(f"  {i:04x}  {hex_part}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"SynthesisResult(status={self.status.name}, "
            f"arch={self.arch.name}, os={self.os.name}, "
            f"goal={self.goal.name}, size={self.payload_len}B, "
            f"encoding={self.encoding_used.name})"
        )

@dataclass
class Constraints:
    arch:         Arch      = Arch.X86_64
    os:           OS        = OS.LINUX
    goal:         Goal      = Goal.EXEC_SHELL
    encoding:     Encoding  = Encoding.AUTO
    bad_chars:    list      = field(default_factory=list)
    size_budget:  int       = 0
    null_free:    bool      = False
    newline_free: bool      = False
    goal_args:    list      = field(default_factory=list)

    def add_bad_char(self, byte: int) -> "Constraints":
        if byte not in self.bad_chars:
            self.bad_chars.append(byte)
        return self

    def _to_c_struct(self) -> _Constraints:
        c = _Constraints()
        c.arch         = int(self.arch)
        c.os           = int(self.os)
        c.goal         = int(self.goal)
        c.encoding     = int(self.encoding)
        c.size_budget  = self.size_budget
        c.null_free    = 1 if self.null_free else 0
        c.newline_free = 1 if self.newline_free else 0
        for i, b in enumerate(self.bad_chars[:SF_MAX_BAD_CHARS]):
            c.bad_chars[i] = b
        c.bad_char_count = min(len(self.bad_chars), SF_MAX_BAD_CHARS)
        for i, arg in enumerate(self.goal_args[:SF_MAX_GOAL_ARGS]):
            encoded = arg.encode()[:SF_MAX_ARG_LEN - 1]
            c.goal_args.args[i][:len(encoded)] = encoded
        c.goal_args.argc = min(len(self.goal_args), SF_MAX_GOAL_ARGS)
        return c

class ShellForge:
    def __init__(self, lib_path=None):
        self._lib = self._load_library(lib_path)
        self._setup_signatures()

    def _load_library(self, lib_path):
        candidates = []
        if lib_path:
            candidates.append(lib_path)

        # Walk up from this file to project root
        this_file = Path(__file__).resolve()
        root = this_file.parent.parent.parent  # engine/ -> python/ -> shellforge/
        candidates += [
            str(root / "core" / "build" / "libshellforge.so"),
            str(root / "core" / "build" / "libshellforge.dylib"),
            str(root / "core" / "build" / "shellforge.dll"),
        ]

        sys_lib = ctypes.util.find_library("shellforge")
        if sys_lib:
            candidates.append(sys_lib)

        for path in candidates:
            if os.path.exists(path):
                try:
                    return ctypes.CDLL(path)
                except OSError:
                    continue

        raise FileNotFoundError(
            f"ShellForge shared library not found.\nSearched: {candidates}"
        )

    def _setup_signatures(self):
        lib = self._lib
        lib.sf_constraints_init.argtypes = [ctypes.POINTER(_Constraints)]
        lib.sf_constraints_init.restype  = None
        lib.sf_add_bad_char.argtypes = [ctypes.POINTER(_Constraints), ctypes.c_uint8]
        lib.sf_add_bad_char.restype  = ctypes.c_int
        lib.sf_is_bad_char.argtypes  = [ctypes.POINTER(_Constraints), ctypes.c_uint8]
        lib.sf_is_bad_char.restype   = ctypes.c_int
        lib.sf_buffer_clean.argtypes = [ctypes.POINTER(_Constraints), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
        lib.sf_buffer_clean.restype  = ctypes.c_int
        lib.sf_synthesize.argtypes   = [ctypes.POINTER(_Constraints)]
        lib.sf_synthesize.restype    = _Result
        lib.sf_validate_constraints.argtypes = [ctypes.POINTER(_Constraints)]
        lib.sf_validate_constraints.restype  = ctypes.c_int
        lib.sf_status_str.argtypes   = [ctypes.c_int]
        lib.sf_status_str.restype    = ctypes.c_char_p
        lib.sf_version.argtypes      = []
        lib.sf_version.restype       = ctypes.c_char_p

    def version(self) -> str:
        return self._lib.sf_version().decode()

    def synthesize(self, constraints: Constraints) -> SynthesisResult:
        c_struct = constraints._to_c_struct()
        raw = self._lib.sf_synthesize(ctypes.byref(c_struct))
        payload_bytes = bytes(raw.payload[:raw.payload_len])
        return SynthesisResult(
            status        = SFStatus(raw.status),
            payload       = payload_bytes,
            payload_len   = raw.payload_len,
            disasm        = raw.disasm.decode(errors="replace"),
            error_msg     = raw.error_msg.decode(errors="replace"),
            arch          = Arch(raw.arch),
            os            = OS(raw.os),
            goal          = Goal(raw.goal),
            encoding_used = Encoding(raw.encoding_used),
        )

    def is_bad_char(self, constraints: Constraints, byte: int) -> bool:
        c_struct = constraints._to_c_struct()
        return bool(self._lib.sf_is_bad_char(ctypes.byref(c_struct), byte))

    def buffer_clean(self, constraints: Constraints, buf: bytes) -> bool:
        c_struct = constraints._to_c_struct()
        arr = (ctypes.c_uint8 * len(buf))(*buf)
        return bool(self._lib.sf_buffer_clean(ctypes.byref(c_struct), arr, len(buf)))
