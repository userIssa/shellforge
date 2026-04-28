"""
ShellForge Flask REST API — Phase 4
Endpoints:
    GET  /health
    GET  /arches
    POST /synthesize
    POST /annotate
"""

import os
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS
from openai import OpenAI

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from python.engine.shellforge_bridge import (
    ShellForge, Constraints, Arch, OS, Goal, Encoding, SFStatus
)

app = Flask(__name__)
CORS(app)

# ── Initialise ShellForge ────────────────────
try:
    sf = ShellForge()
    print(f"[+] {sf.version()} loaded")
except FileNotFoundError as e:
    print(f"[!] Failed to load ShellForge library: {e}")
    sf = None

# ── OpenAI client ────────────────────────────
openai_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

# ── Enum maps ────────────────────────────────
ARCH_MAP = {
    "x86_64": Arch.X86_64,
    "x86_32": Arch.X86_32,
    "arm":    Arch.ARM,
    "mips":   Arch.MIPS,
}
OS_MAP = {
    "linux":   OS.LINUX,
    "windows": OS.WINDOWS,
}
GOAL_MAP = {
    "exec_shell":      Goal.EXEC_SHELL,
    "reverse_shell":   Goal.REVERSE_SHELL,
    "bind_shell":      Goal.BIND_SHELL,
    "arbitrary_write": Goal.ARBITRARY_WRITE,
}
ENCODING_MAP = {
    "none":    Encoding.NONE,
    "xor":     Encoding.XOR,
    "add_sub": Encoding.ADD_SUB,
    "auto":    Encoding.AUTO,
}

# ── Helpers ──────────────────────────────────

def parse_constraints(data: dict) -> Constraints:
    c = Constraints(
        arch         = ARCH_MAP.get(data.get("arch", "x86_64"), Arch.X86_64),
        os           = OS_MAP.get(data.get("os", "linux"), OS.LINUX),
        goal         = GOAL_MAP.get(data.get("goal", "exec_shell"), Goal.EXEC_SHELL),
        encoding     = ENCODING_MAP.get(data.get("encoding", "auto"), Encoding.AUTO),
        size_budget  = int(data.get("size_budget", 0)),
        null_free    = bool(data.get("null_free", False)),
        newline_free = bool(data.get("newline_free", False)),
        goal_args    = data.get("goal_args", []),
    )
    for b in data.get("bad_chars", []):
        c.add_bad_char(int(b, 16) if isinstance(b, str) else int(b))
    return c

def result_to_dict(r) -> dict:
    return {
        "status":        r.status.name,
        "ok":            r.ok,
        "arch":          r.arch.name,
        "os":            r.os.name,
        "goal":          r.goal.name,
        "encoding_used": r.encoding_used.name,
        "payload_len":   r.payload_len,
        "payload_hex":   r.hex_escaped(),
        "payload_bytes": list(r.payload),
        "hex_dump":      r.hex_dump(),
        "disasm":        r.disasm,
        "error_msg":     r.error_msg,
    }

# ── Routes ───────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":  "ok",
        "version": sf.version() if sf else "unavailable",
        "library": sf is not None,
    })


@app.route("/arches", methods=["GET"])
def list_arches():
    return jsonify({
        "architectures":    list(ARCH_MAP.keys()),
        "operating_systems": list(OS_MAP.keys()),
        "goals":            list(GOAL_MAP.keys()),
        "encodings":        list(ENCODING_MAP.keys()),
    })


@app.route("/synthesize", methods=["POST"])
def synthesize():
    if not sf:
        return jsonify({"error": "ShellForge library not loaded"}), 503

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    try:
        c = parse_constraints(data)
    except Exception as e:
        return jsonify({"error": f"Constraint parse error: {e}"}), 400

    result = sf.synthesize(c)
    return jsonify(result_to_dict(result)), 200


@app.route("/annotate", methods=["POST"])
def annotate():
    """
    Pass a synthesis result to GPT-4o-mini for plain-English explanation.
    Body: { "disasm": str, "arch": str, "goal": str, "encoding_used": str }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    disasm   = data.get("disasm", "").strip()
    arch     = data.get("arch", "x86_64")
    goal     = data.get("goal", "exec_shell")
    encoding = data.get("encoding_used", "NONE")

    if not disasm:
        return jsonify({"error": "disasm field required"}), 400

    if not openai_client.api_key:
        return jsonify({"error": "OPENAI_API_KEY not set"}), 503

    prompt = f"""You are a shellcode analysis assistant helping a security researcher.

ShellForge synthesised the following shellcode:
- Architecture : {arch}
- Goal         : {goal}
- Encoding     : {encoding}

Disassembly:
{disasm}

Provide a concise technical explanation covering:
1. What this shellcode does step by step
2. Key techniques used (syscall numbers, register usage, encoding)
3. Any constraint-avoidance techniques visible in the code
4. Potential detection signatures

Be technical and precise. Max 300 words."""

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            temperature=0.2,
        )
        return jsonify({
            "annotation": response.choices[0].message.content.strip(),
            "model": "gpt-4o-mini",
        }), 200

    except Exception as e:
        return jsonify({"error": f"OpenAI API error: {e}"}), 500


if __name__ == "__main__":
    port  = int(os.environ.get("SF_PORT", 5000))
    debug = os.environ.get("SF_DEBUG", "1") == "1"
    print(f"[*] ShellForge API starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
