/* arm.c - ARM Disassembler/Emulator
 *
 * Copyright (c) 2015-17 Jordan Hargrave<jordan_hargrave@hotmail.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "tinydis.h"
#include "arm.h"

#define _LBIT 20
#define _WBIT 21
#define _NBIT 22

#define _P (1 << 24)
#define _U (1 << 23)
#define _B (1 << 22)
#define _S (1 << 22)
#define _N (1 << _NBIT)
#define _W (1 << _WBIT)
#define _L (1 << _LBIT)

/*=================================================*
 * ARM
 *=================================================*/
#define moff(x) ((x) << 8)
#define __(m,a...)     { .mnem=#m, .args = { a } }
#define _b(m,a...)     { .mnem=#m, .args = { a }, .flag='b'|moff(3) } /* BYTE size */
#define _t(t,s,m,a...) { .mnem=#t, .args = { a }, .tbl=t, .flag=mkTBL(s, m), .args = { a } }

/* MNEM
 *  STC{cond}{L:N=1}
 *  LDC{cond}{L:N=1}
 *  LDM{cond]{xxx}
 *  STM{cond}{xxx}
 *  LDR{cond}{H|SH|SB}
 *  STR{cond}{H|SH|SB}
 *  LDR{cond}{B:B=1|T:W=1}
 */
const char *aregs[] = {
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
  "r8", "r9","r10","fp",  "ip", "sp", "lr", "pc"
};

enum {
  stLSL,
  stLSR,
  stASR,
  stROR,
  stRRX
};

static const char *st[] = {
  "lsl", "lsr", "asr", "ror", "rrx"
};

static const char *ccsfx[] = {
  "eq",
  "ne",
  "cs",
  "cc",
  "mi",
  "pl",
  "vs",
  "vc",
  "hi",
  "ls",
  "ge",
  "lt",
  "gt",
  "le",
  "",
  "uc"
};

/*==============================================*/
/* cccc.0000.00as.dddd.nnnn.ssss.1001.mmmm mul  */
/* cccc.0000.1uas.hhhh.llll.ssss.1001.mmmm mull */
/*==============================================*/
static struct opcode multab[] = {
  __(mul,    MRd, Rm, Rs),
  __(muls,   MRd, Rm, Rs),
  __(mla,    MRd, Rm, Rs, Rn),
  __(mlas,   MRd, Rm, Rs, Rn),
  __(0),
  __(0),
  __(0),
  __(0),
  __(umull,  MRdp, Rm, Rs),
  __(umulls, MRdp, Rm, Rs),
  __(umlal,  MRdp, Rm, Rs),
  __(umlals, MRdp, Rm, Rs),
  __(smull,  MRdp, Rm, Rs),
  __(smulls, MRdp, Rm, Rs),
  __(smlal,  MRdp, Rm, Rs),
  __(smlals, MRdp, Rm, Rs),
};

/*=========================================*/
/* cccc.0000.ooos.nnnn.dddd.iiii.itt0.mmmm *
/*  Rn = Rd op (Rm shiftop iiiii)           */
/*=========================================*/
static struct opcode data0mi[] = {
  __(and,   Rd, Rn, Rmi),
  __(ands,  Rd, Rn, Rmi),
  __(eor,   Rd, Rn, Rmi),
  __(eors,  Rd, Rn, Rmi),
  __(sub,   Rd, Rn, Rmi),
  __(subs,  Rd, Rn, Rmi),
  __(rsb,   Rd, Rn, Rmi),
  __(rsbs,  Rd, Rn, Rmi),
  __(add,   Rd, Rn, Rmi),
  __(adds,  Rd, Rn, Rmi),
  __(adc,   Rd, Rn, Rmi),
  __(adcs,  Rd, Rn, Rmi),
  __(sbc,   Rd, Rn, Rmi),
  __(sbcs,  Rd, Rn, Rmi),
  __(rsc,   Rd, Rn, Rmi),
  __(rscs,  Rd, Rn, Rmi),
};

/*=========================================*/
/* cccc.0000.ooos.nnnn.dddd.ssss.0tt1.mmmm */
/*  Rn = Rd op (Rm shiftop Rs)              */
/*=========================================*/
static struct opcode data0ms[] = {
  __(and,   Rd, Rn, Rms),
  __(ands,  Rd, Rn, Rms),
  __(eor,   Rd, Rn, Rms),
  __(eors,  Rd, Rn, Rms),
  __(sub,   Rd, Rn, Rms),
  __(subs,  Rd, Rn, Rms),
  __(rsb,   Rd, Rn, Rms),
  __(rsbs,  Rd, Rn, Rms),
  __(add,   Rd, Rn, Rms),
  __(adds,  Rd, Rn, Rms),
  __(adc,   Rd, Rn, Rms),
  __(adcs,  Rd, Rn, Rms),
  __(sbc,   Rd, Rn, Rms),
  __(sbcs,  Rd, Rn, Rms),
  __(rsc,   Rd, Rn, Rms),
  __(rscs,  Rd, Rn, Rms),
};

/* 0tt1 = Rms
 * itt0 = Rmi
 * 1001 = mul/swp
 * 1011 = h  [ldr,str]
 * 1101 = sb [ldr]
 * 1111 = sh [ldr]
 */
static struct opcode data0tt[] = {
  _t(data0mi, 20, 0xF),
  _t(data0ms, 20, 0xF),
  _t(data0mi, 20, 0xF),
  _t(data0ms, 20, 0xF),
  _t(data0mi, 20, 0xF),
  _t(data0ms, 20, 0xF),
  _t(data0mi, 20, 0xF),
  _t(data0ms, 20, 0xF),
  _t(data0mi, 20, 0xF),
  _t(multab,  20, 0xF),
  _t(data0mi, 20, 0xF),
  __(0),
  _t(data0mi, 20, 0xF),
  __(0),
  _t(data0mi, 20, 0xF),
  __(0),
};

/*=====================================================*/
/* 0001.0p00.1111.dddd.0000.0000.0000 = mrs      [0,4] */
/* 0001.0d10.1001.1111.0000.0000.mmmm = msr      [2,6] */
/* 0001.0d10.1000.1111.0000.0000.0000 = msr      [2,6] */
/* 0001.0010.1111.1111.1111.0001.nnnn = bx       [2]   */
/* 0001.0b00.nnnn.dddd.0000.1001.mmmm = swp/swpb [0,4] */
/* 0001.ooos.nnnn.dddd.iiii.itt0.mmmm = dataop         */
/* 0001.ooos.nnnn.dddd.ssss.0tt1.mmmm = dataop         */
/*=====================================================*/
static struct opcode data1tt[16] = {
  __(mrs,   Rd, Rn, ROp2), //0:mrsa[00] ,swp[9]
  __(teq,   Rd, Rn, ROp2),
  __(msrx,  Rd, Rn, ROp2), //2:msrab[00],bx[01]
  __(tst,   Rd, Rn, ROp2),
  __(mrs,   Rd, Rn, ROp2), //4:mrsa[0],swpb[9]
  __(cmn,   Rd, Rn, ROp2),
  __(msry,  Rd, Rn, ROp2), //6:msrab[00]
  __(cmp,   Rd, Rn, ROp2),
  __(orr,   Rd, Rn, ROp2),
  __(orrs,  Rd, Rn, ROp2),
  __(mov,   Rd, ROp2),     // Rd = Op2
  __(movs,  Rd, ROp2),
  __(bic,   Rd, Rn, ROp2), // Rn = Rd & ~Op2
  __(bics,  Rd, Rn, ROp2),
  __(mvn,   Rd, ROp2),     // Rd = ~Op2
  __(mvns,  Rd, ROp2),
};

/*=========================================*/
/* cccc.001o.ooos.nnnn.dddd.rrrr.iiii.iiii */
/*   Rn = Rd op (iiiiiiii rol rrrr)        */
/*=========================================*/
static struct opcode data2[] = {
  __(and,   Rd, Rn, Rii),
  __(ands,  Rd, Rn, Rii),
  __(eor,   Rd, Rn, Rii),
  __(eors,  Rd, Rn, Rii),
  __(sub,   Rd, Rn, Rii),
  __(subs,  Rd, Rn, Rii),
  __(rsb,   Rd, Rn, Rii),
  __(rsbs,  Rd, Rn, Rii),
  __(add,   Rd, Rn, Rii),
  __(adds,  Rd, Rn, Rii),
  __(adc,   Rd, Rn, Rii),
  __(adcs,  Rd, Rn, Rii),
  __(sbc,   Rd, Rn, Rii),
  __(sbcs,  Rd, Rn, Rii),
  __(rsc,   Rd, Rn, Rii),
  __(rscs,  Rd, Rn, Rii),
};

/*==========================================*/
/* 0011.0d10.1000.1111.rrrr.iiii.iiii = msr */
/*==========================================*/
static struct opcode data3[16] = {
  __(mrs,   Rd, Rn, Rii),
  __(teq,   Rd, Rn, Rii),
  __(msrx,  Rd, Rn, Rii), //2:
  __(tst,   Rd, Rn, Rii),
  __(mrs,   Rd, Rn, Rii),
  __(cmn,   Rd, Rn, Rii),
  __(msry,  Rd, Rn, Rii), //6:
  __(cmp,   Rd, Rn, Rii),
  __(orr,   Rd, Rn, Rii),
  __(orrs,  Rd, Rn, Rii),
  __(mov,   Rd, Rii),  // Rd = Op2
  __(movs,  Rd, Rii),
  __(bic,   Rd, Rn, Rii),
  __(bics,  Rd, Rn, Rii),
  __(mvn,   Rd, Rii),  // Rd = ~Op2
  __(mvns,  Rd, Rii),
};

/*====================================*/
/* 0x4: LSPostI */
/* 010p.ubwl.nnnn.dddd.iiii.iiii.iiii */
/*====================================*/
static struct opcode ldst4[] = {
  __(str,   Rd, LSPostI),
  __(ldr,   Rd, LSPostI),
  __(strt,  Rd, LSPostI),
  __(ldrt,  Rd, LSPostI),
  _b(strb,  Rd, LSPostI),
  _b(ldrb,  Rd, LSPostI),
  _b(strbt, Rd, LSPostI),
  _b(ldrbt, Rd, LSPostI),
};

/*====================================*/
/* 0x5: Rd, LSPreI                    */
/* 010p.ubwl.nnnn.dddd.iiii.iiii.iiii */
/*====================================*/
static struct opcode ldst5[] = {
  __(str,  Rd, LSPreI),
  __(ldr,  Rd, LSPreI),
  __(str,  Rd, LSPreI),
  __(ldr,  Rd, LSPreI),
  _b(strb, Rd, LSPreI),
  _b(ldrb, Rd, LSPreI),
  _b(strb, Rd, LSPreI),
  _b(ldrb, Rd, LSPreI),
};

/* 0x8,0x9 */
static struct opcode ldmstm89[] = {
  __(stm, Rn, Rl),
  __(ldm, Rn, Rl),
};

/*====================================*/
/* Single Transfer                    */
/* 011p.ubwl.nnnn.dddd.ssss.ssss.mmmm */
/* 011p.ubwl.nnnn.dddd.ssss.ssss.mmmm */
/*====================================*/
static struct opcode ldst[] = {
  __(str),
  __(ldr),
};

/*=========================================*/
/* Conditional branch                      */
/*=========================================*/
static struct opcode brcc[] = {
  __(b, Br24), // zf=1  hliEQ
  __(b, Br24), // zf=0  hliNEQ
  __(b, Br24), // cf=1  hliGTE
  __(b, Br24), // cf=0  hliLT
  __(b, Br24), // nf=1  <0
  __(b, Br24), // nf=0  >=0
  __(b, Br24), // vf=1  Overflow
  __(b, Br24), // vf=0  No Overflow
  __(b, Br24), // cf=1 && zf=0 hliGT
  __(b, Br24), // cf=0 || zf=1 hliLTE
  __(b, Br24), // nf==vf hliGTEs
  __(b, Br24), // nf!=vf hliLTs
  __(b, Br24), // zf=0 && (nf==vf) hliGTs
  __(b, Br24), // zf=1 || (nf!=vf) hliLTEs
  __(br,Br24), // always
  __(b, Br24), // always
};

/*========================================*/
/* 110p.unw0.nnnn.DDDD.####.oooo.oooo stc */
/* 110p.unw1.nnnn.DDDD.####.oooo.oooo ldc */
/*   _W = Writeback                       */
/*   _N = Long                            */
/*   _U = Down/Up                         */
/*========================================*/
static struct opcode stc[] = {
  __(stc,  CPl),
  __(stcl, CPl),
};
static struct opcode ldc[] = {
  __(ldc,  CPl),
  __(ldcl, CPl),
};
static struct opcode stc_ldc[] = {
  _t(stc, _NBIT, 0x1),
  _t(ldc, _NBIT, 0x1),
};

/*==========================================*/
/* 1110.OOOO.NNNN.DDDD.####.PPP0.MMMM cdp   */
/* 1110.OOO0.NNNN.dddd.####.PPP1.MMMM mcr   */
/* 1110.OOO1.NNNN.dddd.####.PPP1.MMMM mrc   */
/*==========================================*/
static struct opcode mcr_mrc[] = {
  __(mcr, MCr),
  __(mrc, MCr),
};
static struct opcode cdp_mcr[] = {
  __(cdp, CDp),               /* Coprocessor Data Operation    */
  _t(mcr_mrc, _LBIT, 0x1),    /* Coprocessor Register Transfer */
};

/*===============================================*/
/* Top-level opcode table. Key off bits 24..27   */
/*===============================================*/
struct opcode armmap[] = {
  _t(data0tt,4,0xF),
  _t(data1tt,20,0xF),
  _t(data2,20,0xF),
  _t(data3,20,0xF),
  _t(ldst4,20,0x7),        // 0.ubwl PostI
  _t(ldst5,20,0x7),        // 1.ubwl PreI
  _t(ldst, _LBIT,0x1),     // 0.ubwl PostM
  _t(ldst, _LBIT,0x1),     // 1.ubwl PreM
  _t(ldmstm89, _LBIT,0x1), // p.ublock xfer
  _t(ldmstm89, _LBIT,0x1), // block xfer
  _t(brcc,28,0xF),         // conditional/unconditional jump
  __(bl,  Br24),           // call
  _t(stc_ldc, _LBIT, 0x1), // coprocessor
  _t(stc_ldc, _LBIT, 0x1), // coprocessor
  _t(cdp_mcr, 4, 0x1),     // coprocessor
  __(svci),
};

extern uint64_t _vbase;

#define mkreg(sz,vv) (TYPE_REG+(sz)+(vv))

uint32_t _rol(uint32_t v, int n)
{
  return (v << n) | (v >> (32-n));
}

uint32_t _ror(uint32_t v, int n)
{
  return (v >> n) | (v << (32-n));
}

int imm12(uint32_t cb)
{
  if (cb & _U) {
    return (cb & 0xFFF);
  }
  else {
    return -(cb & 0xFFF);
  }
}

/* LSL:0 = LSL:0
 * LSR:0 = LSR:32
 * ASR:0 = LSL:0
 * ROR:0 = LSL:0
 * ROR:0 = RRX
 */
const char *shifty(int type, int val)
{
  static char sop[32];

  if (!val) {
    if (type == stLSL)
      return "";
    if (type == stLSR)
      val = 32;
    if (type == stROR)
      return "rrx";
  }
  snprintf(sop, sizeof(sop), "%s #%d", st[type], val);
  return sop;
}


/* MEMORY: xxxx.xxxx.xxxx.xxxx
 *         PW             rrrr
 */
int armop(struct cpu *cpu, int arg, int sz)
{
  uint32_t op = cpu->op;
  int rn = (op >> 16) & 0xF;
  int rd = (op >> 12) & 0xF;
  int rs = (op >> 8) & 0xF;
  int rm = (op >> 0) & 0xF;
  int tt = (op >> 5) & 0x3;
  int rr = (op >> 8) & 0xF;
  int ii = (op & 0xFF);
  int rl = (op & 0xFFFF);
  char *pfx;
  int i;
  
  if (arg == ROp2) {
    if (op & 0x10) {
      /* ssss.0tt1.mmmm = Rms */
      arg = Rms;
    }
    else {
      /* iiii.itt0.mmmm = Rmi */
      arg = Rmi;
    }
  }
  switch (arg) {
  case MRn:
  case Rd:
    printf("%s ", aregs[rd]);
    return mkreg(sz, rd);
  case MRd:
  case Rn:
    printf("%s ", aregs[rn]);
    return mkreg(sz, rn);
  case Rm:
    printf("%s ", aregs[rm]);
    return mkreg(sz, rm);
  case Rs:
    printf("%s ", aregs[rs]);
    return mkreg(sz, rs);
  case Rms:    // cccc.000o.ooos.nnnn.dddd.ssss.0tt1.mmmm
    printf("%s %s %s ", aregs[rm], st[tt], aregs[rs]);
    break;
  case Rmi:    // cccc.000o.ooos.nnnn.dddd.iiii.itt0.mmmm
    printf("%s %s ", aregs[rm], shifty(tt, (op >> 7) & 0x1F));
    break;
  case Rii:    // cccc.001o.ooos.nnnn.dddd.rrrr.iiii.iiii
    cpu->immv = _ror(ii, rr<<1);
    printf("#%d ", cpu->immv);
    return TYPE_IMM|SIZE_DWORD;
  case Rl:
    /* Register List (Block Xfer) */
    pfx = "";
    printf("{");
    for (i = 0; i < 16; i++) {
      if (rl & (1L << i)) {
	printf("%s%s", pfx, aregs[i]);
	pfx = ", ";
      }
    }
    printf("} ");
    break;
  case LSPostI: // cccc.0100.ubwl.nnnn.dddd.iiii.iiii.iiii
    cpu->offv = imm12(op);
    printf("[%s], #%d ", aregs[rn], (int)cpu->offv);
    return TYPE_MEMORY|sz|rn;
  case LSPreI:  // cccc.0101.ubwl.nnnn.dddd.iiii.iiii.iiii
    cpu->offv = imm12(op);
    printf("[%s, #%d]%s ", aregs[rn], (int)cpu->offv, op & _W ? "!" : "");
    return TYPE_MEMORY|sz|rn;
  case Br24:    // ccc.101x.iiii.iiii.iiii.iiii.iiii.iiii
    cpu->immv = (signex32(op & 0xFFFFFF, 24) << 2);
    cpu->immv += getpc(cpu) + 4;
    printf("0x%llx <%s> ", cpu->immv + _vbase, getSymName(NULL, cpu->immv + _vbase));
    return TYPE_JMP|SIZE_DWORD;
  case CPl:
  case CDp:
  case MCr:
    break;
  }
  return arg;
}

/* Get Next Table index */
struct opcode *nxtIb(struct cpu *cpu, struct opcode *opc)
{
  int flag = opc->flag;
  int ib;

  ib = (cpu->op >> tSHIFT(flag)) & tMASK(flag);
  return &opc->tbl[ib];
}

struct opcode *_disarm(stack_t *stk, struct cpu *cpu)
{
  struct opcode *opc, *noc;
  char sm[32];
  int off, ib, sz;

  /* All ARM opcodes are 32-bits */
  off = getpc(cpu);
  cpu->op = _get32(cpu->pc);
  cpu->nb = 4;

  /* initial key off bits 27:24 */
  ib = (cpu->op >> 24) & 0xF;
  opc = &armmap[ib];
  while (opc->tbl) {
    opc->flag |= FLAG_USED;
    opc = nxtIb(cpu, opc);
  }

  /* Allocate new opcode with translated args */
  noc = calloc(1, sizeof(*noc));
  noc->mnem = opc->mnem;
  noc->flag = opc->flag;
  noc->llop = opc->llop;
  noc->data = opc;

  /* Get suffix for conditional */
  snprintf(sm, sizeof(sm), "%s%s",
	   opc->mnem, ccsfx[(cpu->op >> 28) & 0xF]);
  printf("%.8llx: %.8x %-8s ", stk->vbase+off, cpu->op, sm);
  sz = SIZE_DWORD;
  if ((opc->flag & 0xFF) == 'b')
    sz = SIZE_BYTE;
  noc->args[0] = armop(cpu, opc->args[0], sz);
  noc->args[1] = armop(cpu, opc->args[1], sz);
  noc->args[2] = armop(cpu, opc->args[2], sz);
  noc->args[3] = armop(cpu, opc->args[3], sz);
  printf("\n");

  if ((noc->args[0] & TYPE_MASK) == TYPE_JMP) {
    _push(stk, cpu->immv, "jump");
  }
  cpu->pc += cpu->nb;
  return noc;
}

