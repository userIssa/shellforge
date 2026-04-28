#include "shellforge.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ─────────────────────────────────────────────
   ShellForge CLI — Phase 1 smoke tester
   Usage: sf_cli [--bad-chars XX,XX,...] [--null-free] [--goal exec]
   ───────────────────────────────────────────── */

static void print_hex(const uint8_t *buf, size_t len) {
    printf("\\x");
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
        if (i < len - 1) printf("\\x");
    }
    printf("\n");
}

static void print_hex_dump(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n  %04zx  ", i);
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("╔══════════════════════════════════╗\n");
    printf("║   ShellForge v%s           ║\n", sf_version() + 11); /* skip prefix */
    printf("║   Constraint-Aware Shellcode Gen ║\n");
    printf("╚══════════════════════════════════╝\n\n");

    sf_constraints_t c;
    sf_constraints_init(&c);

    /* Parse CLI args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--null-free") == 0) {
            c.null_free = 1;
            printf("[*] null-free mode ON (\\x00 is bad char)\n");
        }
        else if (strcmp(argv[i], "--newline-free") == 0) {
            c.newline_free = 1;
            printf("[*] newline-free mode ON\n");
        }
        else if (strcmp(argv[i], "--bad-chars") == 0 && i + 1 < argc) {
            char *token = strtok(argv[++i], ",");
            while (token) {
                uint8_t byte = (uint8_t)strtoul(token, NULL, 16);
                sf_add_bad_char(&c, byte);
                printf("[*] Bad char added: 0x%02x\n", byte);
                token = strtok(NULL, ",");
            }
        }
        else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
            c.size_budget = (size_t)atoi(argv[++i]);
            printf("[*] Size budget: %zu bytes\n", c.size_budget);
        }
        else if (strcmp(argv[i], "--arch") == 0 && i + 1 < argc) {
            i++;
            if      (strcmp(argv[i], "x86_64") == 0) c.arch = ARCH_X86_64;
            else if (strcmp(argv[i], "x86")    == 0) c.arch = ARCH_X86_32;
            else if (strcmp(argv[i], "arm")    == 0) c.arch = ARCH_ARM;
            else if (strcmp(argv[i], "mips")   == 0) c.arch = ARCH_MIPS;
            printf("[*] Architecture: %s\n", argv[i]);
        }
        else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: sf_cli [options]\n");
            printf("  --arch x86_64|x86|arm|mips\n");
            printf("  --bad-chars XX,XX,...    hex bytes (e.g. 00,0a,0d)\n");
            printf("  --null-free              shorthand for bad char \\x00\n");
            printf("  --newline-free           shorthand for \\x0a \\x0d\n");
            printf("  --size N                 max payload bytes\n");
            return 0;
        }
    }

    printf("\n[*] Synthesising...\n\n");

    sf_result_t result = sf_synthesize(&c);

    if (result.status != SF_OK) {
        printf("[!] Synthesis failed: %s\n", result.error_msg);
        return 1;
    }

    printf("[+] Status      : %s\n",    sf_status_str(result.status));
    printf("[+] Payload size: %zu bytes\n", result.payload_len);
    printf("[+] Encoding    : %s\n",
           result.encoding_used == ENC_NONE    ? "none (raw)" :
           result.encoding_used == ENC_XOR     ? "XOR" :
           result.encoding_used == ENC_ADD_SUB ? "ADD/SUB" : "unknown");

    printf("\n── Disassembly ──────────────────────\n%s", result.disasm);
    printf("\n── Escaped Bytes ────────────────────\n");
    print_hex(result.payload, result.payload_len);
    printf("\n── Hex Dump ─────────────────────────\n");
    print_hex_dump(result.payload, result.payload_len);
    printf("\n");

    return 0;
}
