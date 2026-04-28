/*
 * shellforge_loader.c
 * ───────────────────
 * Windows x64 shellcode loader for testing ShellForge payloads.
 *
 * Usage:
 *   shellforge_loader.exe <hex_payload>
 *   shellforge_loader.exe --file payload.bin
 *
 * Build on Windows (MSVC):
 *   cl shellforge_loader.c /Fe:shellforge_loader.exe
 *
 * Build on Windows (MinGW/cross-compile from Kali):
 *   x86_64-w64-mingw32-gcc shellforge_loader.c -o shellforge_loader.exe
 *
 * Example:
 *   shellforge_loader.exe \x48\x31\xff\x57...
 *
 * WARNING: Only run in a VM. This executes arbitrary shellcode.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PAYLOAD 4096

/* ── Hex string parser ───────────────────────────────────────
 * Accepts: \x48\x31\xff or 4831ff or 48 31 ff
 */
static int parse_hex(const char *input, unsigned char *out, size_t *out_len) {
    size_t len = 0;
    const char *p = input;

    while (*p && len < MAX_PAYLOAD) {
        /* skip \x prefix, spaces, commas */
        if (*p == '\\' && *(p+1) == 'x') { p += 2; continue; }
        if (*p == ' ' || *p == ',' || *p == '\n' || *p == '\r') { p++; continue; }

        /* need two hex chars */
        if (!isxdigit((unsigned char)*p)) { p++; continue; }
        if (!isxdigit((unsigned char)*(p+1))) { p++; continue; }

        char byte_str[3] = { p[0], p[1], 0 };
        out[len++] = (unsigned char)strtoul(byte_str, NULL, 16);
        p += 2;
    }

    *out_len = len;
    return len > 0 ? 0 : -1;
}

/* ── File loader ─────────────────────────────────────────────*/
static int load_bin_file(const char *path, unsigned char *out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[!] Cannot open file: %s\n", path); return -1; }
    *out_len = fread(out, 1, MAX_PAYLOAD, f);
    fclose(f);
    return *out_len > 0 ? 0 : -1;
}

/* ── Execute shellcode ───────────────────────────────────────*/
static int execute(unsigned char *payload, size_t len) {
    printf("[*] Allocating RWX memory (%zu bytes)...\n", len);

    /* VirtualAlloc with PAGE_EXECUTE_READWRITE */
    LPVOID mem = VirtualAlloc(NULL, len,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!mem) {
        fprintf(stderr, "[!] VirtualAlloc failed: %lu\n", GetLastError());
        return -1;
    }
    printf("[+] Allocated at: %p\n", mem);

    /* Copy payload */
    memcpy(mem, payload, len);
    printf("[+] Payload copied\n");

    /* Hex dump first 32 bytes */
    printf("[*] First 32 bytes:\n    ");
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x ", ((unsigned char*)mem)[i]);
        if ((i+1) % 16 == 0) printf("\n    ");
    }
    printf("\n");

    printf("[*] Executing shellcode...\n");
    fflush(stdout);

    /* Cast and call */
    void (*shellcode)() = (void(*)())mem;
    shellcode();

    /* If we return (e.g. arb write payloads end with ret) */
    printf("[+] Shellcode returned cleanly\n");
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

/* ── Main ────────────────────────────────────────────────────*/
int main(int argc, char *argv[]) {
    printf("╔══════════════════════════════════════╗\n");
    printf("║   ShellForge Loader  (x64 Windows)  ║\n");
    printf("║   FOR TESTING IN VM ONLY             ║\n");
    printf("╚══════════════════════════════════════╝\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s <hex_payload>          e.g. \\x48\\x31\\xff...\n", argv[0]);
        printf("  %s --file payload.bin     binary file\n", argv[0]);
        return 1;
    }

    unsigned char payload[MAX_PAYLOAD];
    size_t payload_len = 0;

    if (strcmp(argv[1], "--file") == 0) {
        if (argc < 3) { fprintf(stderr, "[!] --file requires a path\n"); return 1; }
        if (load_bin_file(argv[2], payload, &payload_len) != 0) return 1;
        printf("[+] Loaded %zu bytes from %s\n", payload_len, argv[2]);
    } else {
        /* Concatenate all args as one hex string */
        char hexbuf[MAX_PAYLOAD * 4] = {0};
        for (int i = 1; i < argc; i++) {
            strncat(hexbuf, argv[i], sizeof(hexbuf) - strlen(hexbuf) - 1);
        }
        if (parse_hex(hexbuf, payload, &payload_len) != 0) {
            fprintf(stderr, "[!] Failed to parse hex payload\n");
            return 1;
        }
        printf("[+] Parsed %zu bytes from hex input\n", payload_len);
    }

    return execute(payload, payload_len);
}
