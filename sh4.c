/* sh4.c - SH4 Disassembler/Emulator
 *
 * Copyright (c) 2015-17 Jordan Hargrave<jordan_hargrave@hotmail.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include "tinydis.h"

enum {
  SH4_BASE = 0x4000,
  Rm,
  Rn,
  FRm,
  FRn,
  i8,
  i20,
  Dm,   // [--Rm]
  Dn,   // [--Rn]
  Dr15, // [R15++]
  d4n,  // [Rn+d4]
  d4m,  // [Rm+d4]
  dn0,  // [Rn+R0]
  dm0,  // [Rm+R0]
  dn,   // [Rm]
  dm,   // [Rn]
  Pn,   // [Rn++]
  Pm,   // [Rm++]
  d8g,  // [GBR+d8]
  dr0g, //[GBR+R0]
  d8p,  // [Rm+PC]
  dmp,  // 
  d12n, // [Rn+d12]
  d12m, // [Rm+d12]
  j8,
  j12,

  _fT,
  _fS,
  _fM,
  _fQ,

  SIZE_FLOAT = 'f' << SIZE_SHIFT,

  R0  = TYPE_REG+SIZE_DWORD,
  R15 = TYPE_REG+SIZE_DWORD+15,
  PC  = TYPE_REG+SIZE_DWORD+16,

  rMACH,
  rMACL,
  rPR,
  rSGR,
  rDSR,
  rFPUL,
  rA0,
  rX0,
  rX1,
  rY0,
  rY1,
  rDBR,
  rGBR,
  rVBR,
  rTBR,
  rSSR,
  rSR,
  rSPC,
  rMOD,
  rRS,
  rRE,
};

#define _0 { 0 }
#define _f(f,m,a...)   { .mnem=#m, .args={ a }, .flag=f }
#define __(m,a...)     _f(0,m,a)
#define _b(m,a...)     _f('b',m,a)
#define _w(m,a...)     _f('w',m,a)
#define _d(m,a...)     _f('l',m,a)
#define _s(m,a...)     _f(0,m,a)
#define _t(t,s,m,a...) { .mnem=#m, .args={ a }, .tbl=t, .flag=mkTBL(s,m) }

extern uint64_t _vbase;
static uint32_t mkmem(int base, int index, int off)
{
}

static int getarg(struct cpu *cpu, int arg, int sz)
{
  int op, nb0, nb1, v, _Rn, _Rm, off;
  uint8_t *pc;

  pc = cpu->pc;
  op = cpu->op;
  nb0 = (op >> 4) & 0xF;
  nb1 = (op >> 8) & 0xF;
  _Rn  = mkreg(SIZE_DWORD, nb1, 0);
  _Rm  = mkreg(SIZE_DWORD, nb0, 0);
  if ((arg & TYPE_MASK) == TYPE_REG) {
    printf(" {reg}r%d", arg & VAL_MASK);
    return arg;
  }
  switch (arg) {
  case Rm:
    printf(" r%d", nb0);
    return _Rm;
  case Rn:
    printf(" r%d", nb1);
    return _Rn;
  case FRm:
    printf(" {FRm}Fr%d", nb0);
    return mkreg(SIZE_FLOAT, nb0, 0);
  case FRn:
    printf(" {FRn}Fr%d", nb1);
    return mkreg(SIZE_FLOAT, nb1, 0);
  case i8:
    printf(" {i8}0x%x", op & 0xFF);
    return mkimm(cpu, SIZE_DWORD, op & 0xFF);
  case i20:
    v = (nb0 << 16) + _get16(pc+2);
    return mkimm(cpu, SIZE_DWORD, v);
  case Dr15:
    printf(" {Dr15}@R15");
    return mkmem(R15, 0, 0);
  case d8g:
    printf(" {d8g}");
    break;
  case dr0g:
    printf(" {dr0g)");
    break;

  case Dn:  // [--Rn]
    printf(" {Dn}@r%d", nb1);
    return mkmem(_Rn, 0, 0);
  case dn:  // [Rn]
    printf(" {dn}@r%d", nb1);
    return mkmem(_Rn, 0, 0);
  case d4n: // [Rn+disp4]
    v = (op & 0xF) * 4;
    printf(" {d4n}@(%d,r%d)", v, nb1);
    return mkmem(_Rn, 0, v);
  case d12n: // [Rn+disp12]
    v = _get16(pc+2) & 0xFFFFFF;
    printf(" {d12n}@(r%d,0x%x)", nb1, v);
    return mkmem(_Rn, 0, v<<2);
  case dn0: // [R0+Rn]
    printf(" {dn0}@(r0,r%d)", nb1);
    return mkmem(R0, _Rn, 0);

  case Dm:  // [--Rm]
    printf(" {Dm}[r%d]", nb0);
    return mkmem(_Rm, 0, 0);
  case dm:  // [Rm]
    printf(" {dm}[r%d]", nb0);
    return mkmem(_Rm, 0, 0);
  case d4m: // [Rm+disp4]
    v = (op & 0xF) * 4;
    printf(" {d4n}(%d,r%d)", v, nb0);
    return mkmem(_Rn, 0, v);
  case d12m: // [Rm+disp12]
    v = _get16(pc+2) & 0xFFFFFF;
    printf(" {d12m}[r%d+0x%x]", nb0, v);
    return mkmem(_Rm, 0, v<<2);
  case dm0: // [R0+Rn]
    printf(" {dm0}[r0+r%d]", nb0);
    return mkmem(R0, _Rm, 0);

  case d8p:
    if (sz == 'w') {
      v = ((op & 0xFF) * 2) + getoff(cpu);
    }
    else {
      v = ((op & 0xFF) * 4) + (getoff(cpu) & ~0x3);
    }
    v += _vbase + 4;
    printf(" {d8p.%c}%.8x <%s>", sz, v, getSymName(NULL, v));
    return mkmem(-1, 0, v);
  case dmp: // [Rm+PC]
    printf(" {dmp}");
    return mkmem(Rm, PC, 0);

  case j8:  // signed
    v = signex32(op & 0xFF, 8) * 2;
    v += getoff(cpu) + 4;
    cpu->immv = v;
    printf(" {j8}0x%x", v + _vbase);
    break;
  case j12: // signed
    v = signex32(op & 0xFFF, 12) * 2;
    v += getoff(cpu) + 4;
    cpu->immv = v;
    printf(" {j12}0x%x", v + _vbase);
    break;
  default:
    if (arg) {
      printf("  Unknown: %x", arg);
    }
    break;
  }
  return 0;
}

struct opcode sh0000_2[16] = {
  /* 0000 */ __(stc, rSR,   Rn),
  /* 0001 */ __(stc, rGBR,  Rn),
  /* 0010 */ __(stc, rVBR,  Rn),
  /* 0011 */ __(stc, rSSR,  Rn),
  /* 0100 */ __(stc, rSPC,  Rn),
  /* 0101 */ __(stc, rMOD,  Rn),
  /* 0110 */ __(stc, rRS,   Rn),
  /* 0111 */ __(stc, rRE,   Rn),
  /* 1000 */ __(stcbank, Rm,   Rn),
  /* 1001 */ __(stcbank, Rm,   Rn),
  /* 1010 */ __(stcbank, Rm,   Rn),
  /* 1011 */ __(stcbank, Rm,   Rn),
  /* 1100 */ __(stcbank, Rm,   Rn),
  /* 1101 */ __(stcbank, Rm,   Rn),
  /* 1110 */ __(stcbank, Rm,   Rn),
  /* 1111 */ __(stcbank, Rm,   Rn),
};

struct opcode sh0000_3[16] = { 
  [0] = __(bsrf, Rn),
  [2] = __(braf, Rn),
  [6] = __(movli, dn, R0),
  [7] = __(movco, R0, dn),
  [8] = __(pref, dn),
  [9] = __(ocbi, dn),
  [10]= __(ocbp, dn),
  [11]= __(ocbwb, dn),
  [12]= __(movca, R0, dn),
  [13]= __(prefi, dn),
  [14]= __(icbi, dn),
};

struct opcode sh0000_8[16] = {
  [0] = __(clrt),
  [1] = __(sets),
  [2] = __(clrmac),
  [3] = __(ldtbl),
  [4] = __(clrs),
  [6] = __(nott),
};

struct opcode sh0000_9[16] = {
  [0] = __(nop),
  [1] = __(div0u),
  [2] = __(movt, Rn),
  [3] = __(movrt, Rn),
};

struct opcode sh0000_a[16] = {
  [0] = __(sts, rMACH, Rn),
  [1] = __(sts, rMACL, Rn),
  [2] = __(sts, rPR,   Rn),
  [3] = __(stc, rSGR,  Rn),
  [4] = __(stc, rTBR,  Rn),
  [5] = __(sts, rFPUL, Rn),
  [7] = __(sts, rA0,   Rn),
  [8] = __(sts, rX0,   Rn),
  [9] = __(sts, rX1,   Rn),
  [10]= __(sts, rY0,   Rn),
  [11]= __(sts, rY1,   Rn),
  [15]= __(stc, rDBR,  Rn),
};

struct opcode sh0000_b[16] = {
  [0] = __(rts),
  [1] = __(sleep),
  [2] = __(rte),
  [5] = __(resbank),
  [6] = __(rtsn),
  [7] = __(rtvn, Rn),
  [10] = __(synco),
};

/* 0000.xxxx.xxxx.oooo */
struct opcode sh0000[16] = {
  /* 0000 */ __(movi20, i20, Rn), // 0000nnnniiii0000 iiiiiiiiiiiiiiii
  /* 0001 */ __(movi20s,i20, Rn), // 0000nnnniiii0001 iiiiiiiiiiiiiiii
  /* 0010 */ _t(sh0000_2, 4, 0xF),
  /* 0011 */ _t(sh0000_3, 4, 0xF),
  /* 0100 */ _b(mov, Rm, dn0), // Rm, [Rn+R0]
  /* 0101 */ _w(mov, Rm, dn0), // Rm, [Rn+R0]
  /* 0110 */ _d(mov, Rm, dn0), // Rm, [Rn+R0]
  /* 0111 */ _d(mul, Rm, Rn),
  /* 1000 */ _t(sh0000_8, 4, 0xF),
  /* 1001 */ _t(sh0000_9, 4, 0xF),
  /* 1010 */ _t(sh0000_a, 4, 0xF),
  /* 1011 */ _t(sh0000_b, 4, 0xF),
  /* 1100 */ _b(mov, dm0, Rn),  // [Rm+R0], Rn
  /* 1101 */ _w(mov, dm0, Rn),  // [Rm+R0], Rn
  /* 1110 */ _d(mov, dm0, Rn),  // [Rm+R0], Rn
  /* 1111 */ __(mac, dm0, dn0), // [Rm++], [Rn++]
};

/* 0010.xxxx.xxxx.xxxx */
struct opcode sh0010[16] = {
  /* 0000 */ _b(mov,    Rm, dn), // [Rn]
  /* 0001 */ _w(mov,    Rm, dn), // [Rn]
  /* 0010 */ _d(mov,    Rm, dn), // [Rn]
  /* 0011 */ _0,
  /* 0100 */ _b(mov,    Rm, Dn), // [--Rn]
  /* 0101 */ _w(mov,    Rm, Dn), // [--Rn]
  /* 0110 */ _d(mov,    Rm, Dn), // [--Rn]
  /* 0111 */ __(div0s,  Rm, Rn),
  /* 1000 */ __(tst,    Rm, Rn),
  /* 1001 */ __(and,    Rm, Rn),
  /* 1010 */ __(xor,    Rm, Rn),
  /* 1011 */ __(or,     Rm, Rn),
  /* 1100 */ __(cmp.str,Rm, Rn),
  /* 1101 */ __(xtrct,  Rm, Rn), // (Rm.L<<16)|(Rn.H>>16)
  /* 1110 */ _w(mulu,   Rm, Rn),
  /* 1111 */ _w(muls,   Rm, Rn),
};

/* 0011.xxxx.xxxx.0001 oooodddddddddddd */
struct opcode sh0011_1[16] = {
  /* 0000 */ _b(mov, Rm,   d12n),
  /* 0001 */ _w(mov, Rm,   d12n),
  /* 0010 */ _d(mov, Rm,   d12n),
  /* 0011 */ _s(fmov,FRm,  d12n),
  /* 0100 */ _b(mov, d12m, Rn),
  /* 0101 */ _w(mov, d12m, Rn),
  /* 0110 */ _d(mov, d12m, Rn),
  /* 0111 */ _s(fmov,d12m, FRn),
  /* 1000 */ _b(movu,d12m, Rn),
  /* 1001 */ _w(movu,d12m, Rn),
};

/* 0011.xxxx.xxxx.1001 oooodddddddddddd */
struct opcode sh0011_9[16] = {
  /* 0000 */ _b(bclr, i3, d12n),
  /* 0001 */ _b(bset, i3, d12n),
  /* 0010 */ _b(bst,  i3, d12n),
  /* 0011 */ _b(bld,  i3, d12n),
  /* 0100 */ _b(band, i3, d12n),
  /* 0101 */ _b(bor,  i3, d12n),
  /* 0110 */ _b(bxor, i3, d12n),
  /* 0111 */ _0,
  /* 1000 */ _0,
  /* 1001 */ _0,
  /* 1010 */ _0,
  /* 1011 */ _b(bldnot, i3,d12n),
  /* 1100 */ _b(bandnot,i3,d12n),
  /* 1101 */ _b(bornot, i3,d12n),
};

/* 0011.xxxx.xxxx.xxxx */
struct opcode sh0011[16] = {
  /* 0000 */ __(cmp/eq, Rm, Rn),
  /* 0001 */ _t(sh0011_1, 28, 0xF),
  /* 0010 */ __(cmp.hs, Rm, Rn),
  /* 0011 */ __(cmp.ge, Rm, Rn),
  /* 0100 */ __(div1,  Rm, Rn),
  /* 0101 */ _d(dmulu, Rm, Rn),
  /* 0110 */ __(cmp/hi, Rm, Rn),
  /* 0111 */ __(cmp/gt, Rm, Rn),
  /* 1000 */ __(sub,   Rm, Rn),
  /* 1001 */ _t(sh0011_9, 28, 0xF),
  /* 1010 */ __(subc,  Rm, Rn),
  /* 1011 */ __(subv,  Rm, Rn),
  /* 1100 */ __(add,   Rm, Rn),
  /* 1101 */ _d(dmuls, Rm, Rn),
  /* 1110 */ __(addc,  Rm, Rn),
  /* 1111 */ __(addv,  Rm, Rn),
};

struct opcode sh0100_0[16] = {
  [0] = __(shll, Rn),
  [1] = __(dt,   Rn),
  [2] = __(shal, Rn),
  [8] = __(mul,  R0, Rn),
  [15]= _d(movmu,Rm, Dr15),
};
struct opcode sh0100_1[16] = {
  [0] = __(shlr,   Rn),
  [1] = __(cmp.pz, Rn),
  [2] = __(shar,   Rn),
  [8] = _b(clipu,  Rn),
  [9] = _b(clips,  Rn),
  [15]= _d(movml,  Rm, Dr15),
};
struct opcode sh0100_2[16] = {
  [0] = _d(sts, rMACH, Dn),  // [--Rn]
  [1] = _d(sts, rMACL, Dn),  // [--Rn]
  [2] = _d(sts, rPR,   Dn),  // [--Rn]
  [3] = _d(stc, rSGR,  Dn),  // [--Rn]
  [5] = _d(sts, rFPUL, Dn),  // [--Rn]
  [6] = _d(sts, rA0,   Dn),  // [--Rn]
  [8] = _d(sts, rX0,   Dn),  // [--Rn]
  [9] = _d(sts, rX1,   Dn),  // [--Rn]
  [10]= _d(sts, rY0,   Dn),  // [--Rn]
  [11]= _d(sts, rY1,   Dn),  // [--Rn]
  [15]= _d(stc, rDBR,  Dn),  // [--Rn]
};
struct opcode sh0100_3[16] = {
  [0] = _d(stc, rSR,  Dn),   // [--Rn]
  [1] = _d(stc, rGBR, Dn),   // [--Rn]
  [2] = _d(stc, rVBR, Dn),   // [--Rn]
  [3] = _d(stc, rSSR, Dn),   // [--Rn]
  [4] = _d(stc, rSPC, Dn),   // [--Rn]
  [5] = _d(stc, rMOD, Dn),   // [--Rn]
  [6] = _d(stc, rRS,  Dn),   // [--Rn]
  [7] = _d(stc, rRE,  Dn),   // [--Rn]
};
struct opcode sh0100_4[16] = {
  [0] = __(rotl, Rn),
  [1] = __(setrc, Rn),
  [2] = __(rotcl, Rn),
  [8] = __(divu,  R0, Rn),
  [9] = __(divs,  R0, Rn),
  [15]= _d(movmu, Dr15, Rn),
};
struct opcode sh0100_5[16] = {
  [0] = __(rotr, Rn),
  [1] = __(cmp.pl, Rn),
  [2] = __(rotcr, Rn),
  [8] = _w(clipu, Rn),
  [9] = _w(clips, Rn),
  [14]= __(ldbank, dn, R0),
  [15]= _d(movml, Dr15, Rn),
};
struct opcode sh0100_6[16] = {
  [0] = __(lds, Dn, rMACH),
  [1] = __(lds, Dn, rMACL),
  [2] = __(lds, Dn, rPR), 
  [3] = __(lds, Dn, rSGR),
  [5] = __(lds, Dn, rFPUL),
  [6] = __(lds, Dn, rDSR), 
  [7] = __(lds, Dn, rA0),
  [8] = __(lds, Dn, rX0),
  [9] = __(lds, Dn, rX1),
  [10] = __(lds, Dn, rY0),
  [11] = __(lds, Dn, rY1),
  [15] = __(ldc, Dn, rDBR),
};
struct opcode sh0100_7[16] = {
  [0] = __(ldc, Dn, rSR),
  [1] = __(ldc, Dn, rGBR),
  [2] = __(ldc, Dn, rVBR),
  [3] = __(ldc, Dn, rSSR),
  [4] = __(ldc, Dn, rSPC), 
  [5] = __(ldc, Dn, rMOD), 
  [6] = __(ldc, Dn, rRS), 
  [7] = __(ldc, Dn, rRE),
};
struct opcode sh0100_8[16] = {
  [0] = __(shll2, Rn),
  [1] = __(shll8, Rn),
  [2] = __(shll16, Rn),
};
struct opcode sh0100_9[16] = {
  [0] = __(shlr2, Rn),
  [1] = __(shlr8, Rn),
  [2] = __(shlr16, Rn),
  [10]= __(movua,  dn, R0), // [Rm]
  [14]= __(movua,  Dn, R0), // [Rm++]
};
struct opcode sh0100_a[16] = {
  [0] = __(lds, Rn, rMACH),
  [1] = __(lds, Rn, rMACL),
  [2] = __(lds, Rn, rPR), 
  [3] = __(lds, Rn, rSGR),
  [5] = __(lds, Rn, rFPUL),
  [6] = __(lds, Rn, rDSR), 
  [8] = __(lds, Rn, rX0),
  [9] = __(lds, Rn, rX1),
  [10] = __(lds, Rn, rY0),
  [11] = __(lds, Rn, rY1),
};
struct opcode sh0100_b[16] = {
  [0] = __(jsr, dn),     // 0100nnnn00001011
  [1] = _b(tas, dn),
  [2] = __(jmp, dn),     // 0100nnnn00101011
  [4] = __(jsrn, dn),    // 0100nnnn01001011
  [8] = _b(mov, R0, Dn), // [Rn++]
  [9] = _w(mov, R0, Dn), // [Rn++]
  [10]= _d(mov, R0, Dn), // [Rn++]
  [12]= _b(mov, Dn, R0), // [--Rm]
  [13]= _w(mov, Dn, R0), // [--Rm]
  [14]= _d(mov, Dn, R0), // [--Rm]
};
struct opcode sh0100_e[16] = {
  __(ldc, Rm, rSR),
  __(ldc, Rm, rGBR),
  __(ldc, Rm, rVBR),
  __(ldc, Rm, rSSR),
  __(ldc, Rm, rSPC),
  __(ldc, Rm, rMOD),
  __(ldc, Rm, rRS),
  __(ldc, Rm, rRE),
};

/* 0110.xxxx.xxxx.oooo */
struct opcode sh0100[16] = {
  /* 0000 */ _t(sh0100_0, 4, 0xF),
  /* 0001 */ _t(sh0100_1, 4, 0xF),
  /* 0010 */ _t(sh0100_2, 4, 0xF),
  /* 0011 */ _t(sh0100_3, 4, 0xF),
  /* 0100 */ _t(sh0100_4, 4, 0xF),
  /* 0101 */ _t(sh0100_5, 4, 0xF),
  /* 0110 */ _t(sh0100_6, 4, 0xF),
  /* 0111 */ _t(sh0100_7, 4, 0xF),
  /* 1000 */ _t(sh0100_8, 4, 0xF),
  /* 1001 */ _t(sh0100_9, 4, 0xF),
  /* 1010 */ _t(sh0100_a, 4, 0xF),
  /* 1011 */ _t(sh0100_b, 4, 0xF),
  /* 1100 */ __(shad, Rm, Rn),
  /* 1101 */ __(shld, Rm, Rn),
  /* 1110 */ _t(sh0100_e, 0, 0xF),
  /* 1111 */ _w(mac,  Dm, Dn),
};

/* 0110.xxxx.xxxx.xxxx */
struct opcode sh0110[16] = {
  /* 0000 */ _b(mov,   dm, Rn),
  /* 0001 */ _w(mov,   dm, Rn),
  /* 0010 */ _d(mov,   dm, Rn),
  /* 0011 */ __(mov,   Rm, Rn),
  /* 0100 */ _b(mov,   Dm, Rn), // Rn=[Rm++]
  /* 0101 */ _w(mov,   Dm, Rn), // Rn=[Rm++]
  /* 0110 */ _d(mov,   Dm, Rn), // Rn=[Rm++]
  /* 0111 */ __(not,   Rm, Rn),
  /* 1000 */ _b(swap,  Rm, Rn),
  /* 1001 */ _w(swap,  Rm, Rn),
  /* 1010 */ __(negc,  Rm, Rn),
  /* 1011 */ __(neg,   Rm, Rn),
  /* 1100 */ _b(extu,  Rm, Rn),
  /* 1101 */ _w(extu,  Rm, Rn),
  /* 1110 */ _b(exts,  Rm, Rn),
  /* 1111 */ _w(exts,  Rm, Rn),
};

struct opcode sh1000_6[2] = {
  __(bclr, i3, Rn),
  __(bset, i3, Rn),
};
struct opcode sh1000_7[2] = {
  __(bst, i3, Rn),
  __(bld, i3, Rn),
};

/* 1000.oooo.xxxx.xxxx */
struct opcode sh1000[16] = {
  /* 0000 */ _b(mov,  R0, d4n), 
  /* 0001 */ _w(mov,  R0, d4n),
  /* 0010 */ __(setrc, i8),
  /* 0011 */ __(jsr,   i8),
  /* 0100 */ _b(mov,   d4m, R0),
  /* 0101 */ _w(mov,   d4m, R0),
  /* 0110 */ _t(sh1000_6, 4, 1),
  /* 0111 */ _t(sh1000_7, 4, 1),
  /* 1000 */ __(cmp.eq, i8, R0),
  /* 1001 */ __(bt,   j8),
  /* 1010 */ _0,
  /* 1011 */ __(bf,   j8),
  /* 1100 */ __(ldrs, d8p),
  /* 1101 */ __(bt.s, j8),     // 1000.1101.dddd.dddd
  /* 1110 */ __(ldre, d8p),
  /* 1111 */ __(bf.s, j8),     // 1000.1111.dddd.dddd
};

/* 1100.oooo.xxxx.xxxx */
struct opcode sh1100[16] = {
  /* 0000 */ _b(mov, R0, d8g),
  /* 0001 */ _w(mov, R0, d8g),
  /* 0010 */ _d(mov, R0, d8g), 
  /* 0011 */ __(trapa, i8),
  /* 0100 */ _b(mov,  d8g, R0),
  /* 0101 */ _w(mov,  d8g, R0),
  /* 0110 */ _d(mov,  d8g, R0),
  /* 0111 */ __(mova, d8p, R0),
  /* 1000 */ __(tst, i8, R0),
  /* 1001 */ __(and, i8, R0),
  /* 1010 */ __(xor, i8, R0),
  /* 1011 */ __(or,  i8, R0),
  /* 1100 */ _b(tst, i8, dr0g),
  /* 1101 */ _b(and, i8, dr0g),
  /* 1110 */ _b(xor, i8, dr0g),
  /* 1111 */ _b(or,  i8, dr0g),
};

/* 1111.xxxx.xxxx.xxxx */
struct opcode sh1111[16] = {
  /* 0000 */ __(fadd, FRm, FRn),
  /* 0001 */ __(fsub, FRm, FRn),
  /* 0010 */ __(fmul, FRm, FRn),
  /* 0011 */ __(fdiv, FRm, FRn),
  /* 0100 */ __(fcmp.eq,FRm,FRn),
  /* 0101 */ __(fcmp.gt,FRm,FRn),
  /* 0110 */ _s(fmov, dm0, FRn),
  /* 0111 */ _s(fmov, FRm, dn0),
  /* 1000 */ _s(fmov, dm,  FRn),
  /* 1001 */ _s(fmov, dm,  FRn),
  /* 1010 */ _s(fmov, FRm, dn),
  /* 1011 */ _s(fmov, FRm, dn),
  /* 1100 */ __(fmov, FRm, FRn),
  /* 1101 */ _0,
  /* 1110 */ __(fmac, FRm, FRm, FRn),
  /* 1111 */ _0,
};

struct opcode shtab[16] = {
  /* 0000 */ _t(sh0000, 0, 0xF),  // 0000........oooo
  /* 0001 */ _d(mov,   Rm, d4n),  // 0001nnnnmmmmdddd
  /* 0010 */ _t(sh0010, 0, 0xF),  // 0010........oooo
  /* 0011 */ _t(sh0011, 0, 0xF),  // 0011........oooo
  /* 0100 */ _t(sh0100, 0, 0xF),  // 0100........oooo
  /* 0101 */ _d(mov, d4m, Rn),    // 0101nnnnmmmmdddd
  /* 0110 */ _t(sh0110, 0, 0xF),  // 0110........oooo
  /* 0111 */ __(add, i8, Rn),     // 0111nnnniiiiiiii
  /* 1000 */ _t(sh1000, 8, 0xF),  // 1000oooo........
  /* 1001 */ _w(mov, d8p, Rn),    // 1001nnnndddddddd
  /* 1010 */ __(bra, j12),        // 1010dddddddddddd
  /* 1011 */ __(bsr, j12),        // 1011dddddddddddd
  /* 1100 */ _t(sh1100, 8, 0xF),  // 1100oooo........
  /* 1101 */ _d(mov, d8p, Rn),    // 1101nnnndddddddd
  /* 1110 */ __(mov, i8, Rn),     // 1110nnnniiiiiiii
  /* 1111 */ _t(sh1111, 0, 0xF),
};

struct emutab shetab[] = {
  { "nop" },

  { "add",    _a1, hliADD,    _a1, _a0 },
  { "addc",   _a1, hliADD,    _a1, _a0, _fT },
  { "neg",    _a1, hliSUB,    _mkimm(0), _a0 },
  { "sub",    _a1, hliSUB,    _a1, _a0 },
  { "subc",   _a1, hliSUB,    _a1, _a0, _fT },
  
  { "mov",    _a1, hliASSIGN, _a0 },
  { "movi20", _a1, hliASSIGN, _a0 },
  { "movi20s",_a1, hliASSIGN, _a0 },
  { "mov.b",  _a1, hliASSIGN, _a0 },
  { "mov.l",  _a1, hliASSIGN, _a0 },
  { "mov.w",  _a1, hliASSIGN, _a0 },
  { "movt",   _a0, hliASSIGN, _fT },

  { "ldc",    _a1, hliASSIGN, _a0 },
  { "ldc.l",  _a1, hliASSIGN, _a0 },
  { "lds",    _a1, hliASSIGN, _a0 },
  { "lds.l",  _a1, hliASSIGN, _a0 },
  { "stc",    _a1, hliASSIGN, _a0 },
  { "stc.l",  _a1, hliASSIGN, _a0 },
  { "sts",    _a1, hliASSIGN, _a0 },
  { "sts.l",  _a1, hliASSIGN, _a0 },

  { "not",    _a1, hliNOT,    _a1, _a0 },
  { "or",     _a1, hliOR,     _a1, _a0 },
  { "or.b",   _a1, hliOR,     _a1, _a0 },
  { "and",    _a1, hliAND,    _a1, _a0 },
  { "and.b",  _a1, hliAND,    _a1, _a0 },
  { "xor",    _a1, hliXOR,    _a1, _a0 },
  { "xor.b",  _a1, hliXOR,    _a1, _a0 },
  { "tst",      0, hliAND,    _a1, _a0 },
  { "tst.b",    0, hliAND,    _a1, _a0 },
  
  { "rotcl",  _a0, hliRCL,    _a0,  _mkimm(1) },
  { "rotcr",  _a0, hliRCR,    _a0,  _mkimm(1) },
  { "rotl",   _a0, hliROL,    _a0,  _mkimm(1) },
  { "rotr",   _a0, hliROR,    _a0,  _mkimm(1) },
  { "shal",   _a0, hliSHL,    _a0,  _mkimm(1) },
  { "shar",   _a0, hliSHR,    _a0,  _mkimm(1) },
  { "shll",   _a0, hliSHL,    _a0,  _mkimm(1) },
  { "shll2",  _a0, hliSHL,    _a0,  _mkimm(2) },
  { "shll8",  _a0, hliSHL,    _a0,  _mkimm(8) },
  { "shll16", _a0, hliSHL,    _a0,  _mkimm(16) },
  { "shlr",   _a0, hliSHR,    _a0,  _mkimm(1) },
  { "shrl2",  _a0, hliSHR,    _a0,  _mkimm(2) },
  { "shrl8",  _a0, hliSHR,    _a0,  _mkimm(8) },
  { "shrl16", _a0, hliSHR,    _a0,  _mkimm(16) },

  { "bf",       0, hliJCC,    _fT,  rvIP, _a0 }, // T==1, nothing, T==0, jump
  { "bt",       0, hliJCC,    _fT,  _a0, rvIP }, // T==1, jump, T==0, nothing
  { "dt",     _a0, hliSUB,    _a0,  _mkimm(1) },
  { "sets",   _fS, hliASSIGN, _mkimm(1) },
  { "sett",   _fT, hliASSIGN, _mkimm(1) },
  { "clrs",   _fS, hliASSIGN, _mkimm(0) },
  { "clrt",   _fT, hliASSIGN, _mkimm(0) },
  { },
};

#if 0
void shemu(struct imap *i)
{
  if (runemu(i, shetab))
    return;
  a0 = i->opc->args[0];
  a1 = i->opc->args[1];
  a2 = i->opc->args[2];

  if (isemu(i, 1, "addv")) {
    v0 = getval(i, a0);
    v1 = getval(i, a1);
    dv = v0 + v1;
    setval(i, a1,  (uint32_t)dv);
    setval(i, _fT, !!(dv & ~0xFFFFFFFFLL));
  }
  else if (isemu(i, 1, "subv")) {
    v0 = getval(i, a0);
    v1 = getval(i, a1);
    dv = v0 - v1;
    setval(i, a1,  (uint32_t)dv);
    setval(i, _fT, !!(dv & ~0xFFFFFFFFLL));
  }
  else if (isemu(i, 2, "shad", "shld")) {
    v0 = getval(i, a0);
    v1 = getval(i, a1);
    if (v0 >= 0)
      dv = v1 << v0;
    else
      dv = v1 >> (32 - v0);
    setval(i, _a1, dv);
  }
  else if (isemu(i, 1, "cmp/eq")) {
    v0 = getval(i, a0);
    v1 = getval(i, a1);
    setval(i, _fT, !!(v0 == v1));
  }
  else if (isemu(i, 2, "cmp/ge", "cmp/hs")) {
    v0 = getval(i, a0);
    v1 = getval(i, a1);
    setval(i, _fT, !!(v0 >= v1));
  }    
  else if (isemu(i, 2, "cmp/gt", "cmp/hi")) {
    v0 = getval(i, a0);
    v1 = getval(i, a1);
    setval(i, _fT, !!(v0 > v1));
  }
  else if (isemu(i, 1, "cmp/pl")) {
    v0 = getval(i, a0);
    setval(i, _fT, !!(v0 > 0));
  }
  else if (isemu(i, 1, "cmp/pz")) {
    v0 = getval(i, a0);
    setval(i, _fT, !!(v0 >= 0));
  }
  else if (isemu(i, 1, "div0u")) {
    setval(i, _fT, 0);
    setval(i, _fQ, 0);
    setval(i, _fM, 0);
  }
  else if (isemu(i, 2, "dmuls.l", "dmulu.l")) {
    v0 = getval(i, a0);
    v1 = getval(i, a1);
    dv = v0 * v1;
    setval(i, fMACL, (uint32_t)dv);
    setval(i, fMACH, dv >> 32);
  }
  else if (isemu(i, 1, "exts.b")) {
    v0 = (int8_t)getval(i, (a0 & ~SIZE-MASK) | SIZE_BYTE);
    setval(i, a1, v0);
  }
  else if (isemu(i, 1, "exts.w")) {
    v0 = (int16_t)getval(i, (a0 & ~SIZE-MASK) | SIZE_WORD);
    setval(i, a1, v0);
  }
  else if (isemu(i, 1, "extu.b")) {
    v0 = getval(i, (a0 & ~SIZE-MASK) | SIZE_BYTE);
    setval(i, a1, v0);
  }
  else if (isemu(i, 1, "extu.w")) {
    v0 = getval(i, (a0 & ~SIZE-MASK) | SIZE_WORD);
    setval(i, a1, v0);
  }
}
#endif

static struct opcode *nxtSh(struct cpu *cpu, struct opcode *opc)
{
  int flag = opc->flag;
  int ib;

  ib = (cpu->op >> tSHIFT(flag)) & tMASK(flag);
  return &opc->tbl[ib];
}

void showit(struct opcode *tbl, int n, int lvl)
{
  int i, j;

  for (j=0; j<n; j++) {
    if (tbl[j].tbl)
      showit(tbl[j].tbl, tMASK(tbl[j].flag)+1, lvl+1);
    else {
      printf("@%s\n", tbl[j].mnem);
    }
  }
}

struct opcode *_dissh4(stack_t *stk, struct cpu *cpu)
{
  struct opcode *opc, *noc;
  char sm[32];
  int off, ib, sz;
  static int i1;

  if (!i1) {
    showit(shtab, 16, 0);
    i1++;
  }
  exit(0);
  
  off = getpc(cpu);
  cpu->op = _get16(cpu->pc);
  cpu->nb = 2;

  ib = (cpu->op >> 12) & 0xF;
  opc = &shtab[ib];
  while (opc->tbl) {
    opc->flag |= FLAG_USED;
    opc = nxtSh(cpu, opc);
  }
  sm[0] = 0;
  if (opc->flag & 0xFF) {
    snprintf(sm, sizeof(sm), "%s.%c", opc->mnem, opc->flag & 0xFF);
  }
  else if (opc->mnem) {
    strcpy(sm, opc->mnem);
  }
  noc = calloc(1, sizeof(*noc));
  noc->mnem = opc->mnem;
  noc->flag = opc->flag;
  noc->llop = opc->llop;
  noc->data = opc;
  
  printf("%.8lx %.4x %-8s ", stk->vbase+off, cpu->op, sm);
  sz = opc->flag & 0xFF;
  if (!sz)
    sz = 'd';
  noc->args[0] = getarg(cpu, opc->args[0], sz);
  noc->args[1] = getarg(cpu, opc->args[1], sz);
  noc->args[2] = getarg(cpu, opc->args[2], sz);
  printf("\n");
  return noc;
}
