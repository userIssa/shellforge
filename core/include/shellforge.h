#ifndef SHELLFORGE_H
#define SHELLFORGE_H

#include <stdint.h>
#include <stddef.h>

/* ─────────────────────────────────────────────
   ShellForge Core — Constraint Data Model
   Phase 1: x86-64 Linux foundation
   ───────────────────────────────────────────── */

#define SF_VERSION_MAJOR 0
#define SF_VERSION_MINOR 1
#define SF_VERSION_PATCH 0

#define SF_MAX_BAD_CHARS   256
#define SF_MAX_PAYLOAD     4096
#define SF_MAX_GOAL_ARGS   8
#define SF_MAX_ARG_LEN     128

/* ── Architecture ── */
typedef enum {
    ARCH_X86_64 = 0,
    ARCH_X86_32 = 1,
    ARCH_ARM    = 2,
    ARCH_MIPS   = 3,
    ARCH_UNKNOWN = -1
} sf_arch_t;

/* ── Target OS ── */
typedef enum {
    OS_LINUX   = 0,
    OS_WINDOWS = 1,
    OS_UNKNOWN = -1
} sf_os_t;

/* ── Shellcode Goal ── */
typedef enum {
    GOAL_EXEC_SHELL     = 0,   /* execve(/bin/sh) or cmd.exe */
    GOAL_REVERSE_SHELL  = 1,   /* connect back to host:port  */
    GOAL_BIND_SHELL     = 2,   /* listen on port             */
    GOAL_ARBITRARY_WRITE= 3,   /* write value to address     */
    GOAL_CUSTOM         = 4    /* raw instruction spec       */
} sf_goal_t;

/* ── Encoding Strategy ── */
typedef enum {
    ENC_NONE    = 0,   /* raw bytes, no encoding    */
    ENC_XOR     = 1,   /* XOR encoder with key      */
    ENC_ADD_SUB = 2,   /* ADD/SUB chain encoding    */
    ENC_AUTO    = 3    /* solver picks best strategy */
} sf_encoding_t;

/* ── Goal Arguments ── */
typedef struct {
    char args[SF_MAX_GOAL_ARGS][SF_MAX_ARG_LEN];
    int  argc;
} sf_goal_args_t;

/* ── Core Constraint Structure ── */
typedef struct {
    sf_arch_t       arch;
    sf_os_t         os;
    sf_goal_t       goal;
    sf_goal_args_t  goal_args;       /* e.g. host, port for reverse shell */
    sf_encoding_t   encoding;

    uint8_t         bad_chars[SF_MAX_BAD_CHARS];
    size_t          bad_char_count;

    size_t          size_budget;     /* max bytes, 0 = unlimited          */
    int             null_free;       /* 1 = treat \x00 as bad char        */
    int             newline_free;    /* 1 = treat \x0a\x0d as bad chars   */
} sf_constraints_t;

/* ── Synthesis Result ── */
typedef enum {
    SF_OK               =  0,
    SF_ERR_BAD_CHAR     = -1,   /* bad char in output, re-encode needed  */
    SF_ERR_SIZE_EXCEED  = -2,   /* payload exceeds size_budget           */
    SF_ERR_UNSUPPORTED  = -3,   /* arch/goal combo not yet implemented   */
    SF_ERR_ENCODE_FAIL  = -4,   /* encoding could not avoid bad chars    */
    SF_ERR_INVALID_ARG  = -5    /* bad constraint input                  */
} sf_status_t;

typedef struct {
    sf_status_t status;
    uint8_t     payload[SF_MAX_PAYLOAD];
    size_t      payload_len;
    char        disasm[SF_MAX_PAYLOAD * 8]; /* human-readable disassembly */
    char        error_msg[256];
    sf_arch_t   arch;
    sf_os_t     os;
    sf_goal_t   goal;
    sf_encoding_t encoding_used;
} sf_result_t;

/* ─────────────────────────────────────────────
   Public API — called via Python ctypes
   ───────────────────────────────────────────── */

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise a constraints struct with safe defaults */
void sf_constraints_init(sf_constraints_t *c);

/* Add a bad char to the constraint set */
int  sf_add_bad_char(sf_constraints_t *c, uint8_t byte);

/* Check if a byte is forbidden under current constraints */
int  sf_is_bad_char(const sf_constraints_t *c, uint8_t byte);

/* Check if a buffer is clean (no bad chars) */
int  sf_buffer_clean(const sf_constraints_t *c,
                     const uint8_t *buf, size_t len);

/* Core synthesis entry point */
sf_result_t sf_synthesize(const sf_constraints_t *c);

/* Validate constraints struct before synthesis */
sf_status_t sf_validate_constraints(const sf_constraints_t *c);

/* Return a human-readable status string */
const char *sf_status_str(sf_status_t status);

/* Return version string */
const char *sf_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SHELLFORGE_H */

/* ─────────────────────────────────────────────
   Phase 3: Architecture Profile System
   ───────────────────────────────────────────── */

/* ARM sub-mode */
typedef enum {
    ARM_MODE_ARM   = 0,   /* 32-bit ARM instructions  */
    ARM_MODE_THUMB = 1,   /* 16-bit Thumb instructions */
} sf_arm_mode_t;

/* MIPS endianness */
typedef enum {
    MIPS_BE = 0,   /* big-endian (default)    */
    MIPS_LE = 1,   /* little-endian (mipsel)  */
} sf_mips_endian_t;

/* Per-architecture syscall table */
typedef struct {
    sf_arch_t arch;
    int       nr_execve;
    int       nr_socket;
    int       nr_connect;
    int       nr_bind;
    int       nr_listen;
    int       nr_accept;
    int       nr_dup2;
    int       uses_socketcall;  /* 1 = x86-32 style multiplexed */
    int       is_bigendian;
    sf_arm_mode_t  arm_mode;    /* ARM only  */
    sf_mips_endian_t mips_end;  /* MIPS only */
} sf_arch_profile_t;

/* Retrieve arch profile for a given arch */
const sf_arch_profile_t *sf_get_arch_profile(sf_arch_t arch);
