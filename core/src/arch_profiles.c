#include "shellforge.h"

/* ─────────────────────────────────────────────
   Architecture Profile Table
   Single source of truth for all syscall
   numbers and arch-specific flags.
   ───────────────────────────────────────────── */

static const sf_arch_profile_t ARCH_PROFILES[] = {

    /* ── x86-64 Linux ── */
    {
        .arch             = ARCH_X86_64,
        .nr_execve        = 59,
        .nr_socket        = 41,
        .nr_connect       = 42,
        .nr_bind          = 49,
        .nr_listen        = 50,
        .nr_accept        = 43,
        .nr_dup2          = 33,
        .uses_socketcall  = 0,
        .is_bigendian     = 0,
        .arm_mode         = ARM_MODE_ARM,
        .mips_end         = MIPS_BE,
    },

    /* ── x86-32 Linux ── */
    /* socket ops are multiplexed through socketcall(nr=102)
       SYS_SOCKET=1, SYS_BIND=2, SYS_CONNECT=3,
       SYS_LISTEN=4, SYS_ACCEPT=5                          */
    {
        .arch             = ARCH_X86_32,
        .nr_execve        = 11,
        .nr_socket        = 102,   /* socketcall */
        .nr_connect       = 102,
        .nr_bind          = 102,
        .nr_listen        = 102,
        .nr_accept        = 102,
        .nr_dup2          = 63,
        .uses_socketcall  = 1,
        .is_bigendian     = 0,
        .arm_mode         = ARM_MODE_ARM,
        .mips_end         = MIPS_BE,
    },

    /* ── ARM Linux (Thumb mode) ── */
    {
        .arch             = ARCH_ARM,
        .nr_execve        = 11,
        .nr_socket        = 281,
        .nr_connect       = 283,
        .nr_bind          = 282,
        .nr_listen        = 284,
        .nr_accept        = 285,
        .nr_dup2          = 63,
        .uses_socketcall  = 0,
        .is_bigendian     = 0,
        .arm_mode         = ARM_MODE_THUMB,
        .mips_end         = MIPS_BE,
    },

    /* ── MIPS Linux (big-endian) ── */
    /* MIPS O32 ABI: syscall NR in $v0, args in $a0-$a3
       All NR = 4000 + linux_nr                           */
    {
        .arch             = ARCH_MIPS,
        .nr_execve        = 4011,
        .nr_socket        = 4183,
        .nr_connect       = 4170,
        .nr_bind          = 4169,
        .nr_listen        = 4174,
        .nr_accept        = 4168,
        .nr_dup2          = 4063,
        .uses_socketcall  = 0,
        .is_bigendian     = 1,
        .arm_mode         = ARM_MODE_ARM,
        .mips_end         = MIPS_BE,
    },
};

#define N_PROFILES (sizeof(ARCH_PROFILES) / sizeof(ARCH_PROFILES[0]))

const sf_arch_profile_t *sf_get_arch_profile(sf_arch_t arch) {
    for (size_t i = 0; i < N_PROFILES; i++)
        if (ARCH_PROFILES[i].arch == arch)
            return &ARCH_PROFILES[i];
    return NULL;
}
