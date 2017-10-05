/* cr16.c - Cr16 Disassembler/Emulator
 *
 * Copyright (c) 2015-17 Jordan Hargrave<jordan_hargrave@hotmail.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "tinydis.h"
#include "cr16.h"

extern uint64_t _vbase;
extern const char *crarg(int);
extern int _cpuflag;

extern struct regval _regs[];

/*=========================================================================*
 * CR16 disassembly 
 *=========================================================================*/

#define _(m,a...)      { .mnem=#m, .args = { a } }
#define b(m,a...)       { .flag=SIZE_BYTE,  .mnem=#m "b", .args = { a } }
#define w(m,a...)       { .flag=SIZE_WORD,  .mnem=#m "w", .args = { a } }
#define d(m,a...)       { .flag=SIZE_HWORD, .mnem=#m "d", .args = { a } }
#define jd(m,a...)      { .flag=SIZE_HWORD, .mnem=#m, .args = { a } }
#define t(t,s,m,a...)   { .mnem=#t, .tbl=t, .args = { a }, .flag = mkTBL(s,m) }

// 0110.1010.0iii.BBBB
// 0110.1010.10dd.BBBB dddd.dddd.-iii.dddd
// 0110.1010.11dd.BBBB dddd.dddd.iiii.dddd
struct opcode t6A[] = {
  b(cbit,n3,d0),
  b(cbit,n3,d0),
  b(cbit,n3,d14,1),
  w(cbit,n4,d14,1),
};
// 0110.1000.0iii.BBBB dddd.dddd.dddd.dddd
// 0110.1000.Biii.dddd dddd.dddd.dddd.dddd
struct opcode t6B[] = {
  b(cbit,n3,d16,1),
  b(cbit,n3,a20r3,1),
};
struct opcode t72[] = {
  b(sbit,n3,d0),
  b(sbit,n3,d0),
  b(sbit,n3,d14,1),
  w(sbit,n4,d14,1),
};
struct opcode t73[] = {
  b(sbit,n3,d16,1),
  b(sbit,n3,a20r3,1),
};
struct opcode t7A[] = {
  b(tbit,n3,d0),
  b(tbit,n3,d0),
  b(tbit,n3,d14,1),
  w(tbit,n4,d14,1),
};
struct opcode t7B[] = {
  b(tbit,n3,d16,1),
  b(tbit,n3,a20r3,1),
};
struct opcode t86[] = {
  b(stor,n4,d14,1),
  b(load,d14,r1,1),
  d(load,d14,r1,1),
  w(load,d14,r1,1),
};
struct opcode tC6[] = {
  w(stor,n4,d14,1),
  b(stor,r1,d14,1),
  d(stor,r1,d14,1),
  w(stor,r1,d14,1),
};

// 0000.0010.cccc.rrrr
struct opcode jccr[16] = {
  jd(jmpeq,r0),
  jd(jmpne,r0),
  jd(jmpcs,r0),
  jd(jmpcc,r0),
  jd(jmphi,r0),
  jd(jmpls,r0),
  jd(jmpgt,r0),
  jd(jmple,r0),
  jd(jmpfs,r0),
  jd(jmpfc,r0),
  jd(jmplo,r0),
  jd(jmphs,r0),
  jd(jmplt,r0),
  jd(jmpge,r0),
  jd(jmpa, r0),
  jd(jmpuc,r0),
};

/* C = Carry
 * L = Low
 * F = Flag
 * Z = Zero
 */
// 0001.jjjj.cccc.jjjj
// 0001.1000.cccc.0000 jjjj.jjjj.jjjj.jjjj
struct opcode jcc8[16] = {
  _(beq,j8), // ==   (Z=1)
  _(bne,j8), // !=   (Z=0)
  _(bcs,j8), //      (C=1)
  _(bcc,j8), //      (C=0)
  _(bhi,j8), // >.u  (L=1)
  _(bls,j8), // <=.u (L=0)
  _(bgt,j8), // >.s  (N=1)
  _(ble,j8), // <=.s (N=0)
  _(bfs,j8), //      (F=1)
  _(bfc,j8), //      (F=0)
  _(blo,j8), // <.u  (Z|L=0)
  _(bhs,j8), // >=.u (Z|L=1)
  _(blt,j8), // <.s  (Z|N=0)
  _(bge,j8), // >=.s (Z|L=1)
  _(br, j8),
  _(buc,j8),
};

// 0000.0000.0001.0000 0000.jjjj.cccc.jjjj jjjj.jjjj.jjjj.jjjj
struct opcode jcc24[16] = {
  _(beq,jx24,0,1),
  _(bne,jx24,0,1),
  _(bcs,jx24,0,1),
  _(bcc,jx24,0,1),
  _(bhi,jx24,0,1),
  _(bls,jx24,0,1),
  _(bgt,jx24,0,1),
  _(ble,jx24,0,1),
  _(bfs,jx24,0,1),
  _(bfc,jx24,0,1),
  _(blo,jx24,0,1),
  _(bhs,jx24,0,1),
  _(blt,jx24,0,1),
  _(bge,jx24,0,1),
  _(br, jx24,0,1),
  _(buc,jx24,0,1),
};

/* nw=1 */
struct opcode cr000x[16] = {
  [0]  = _(res,0),
  [1]  = _(res,0),
  [2]  = _(res,0),
  [3]  = _(retx,0),
  [4]  = _(di,0),
  [5]  = _(ei,0),
  [6]  = _(wait,0),
  [7]  = _(eiwait,0),
  [8]  = _(res,0),
  [9]  = _(res,0),
  [10] = _(cinv_i,0),
  [11] = _(cinv_iu,0),
  [12] = _(cinv_d,0),
  [13] = _(cinv_du,0),
  [14] = _(cinv_di,0),
  [15] = _(cinv_diu,0),
};
/* nw=3 */
struct opcode cr0010[16] = {
  t(jcc24,20,0xF),  // 0000.0000.0001.0000 0000.jjjj.cccc.jjjj jjjj.jjjj.jjjj.jjjj
  _(res,0),
  _(bal,jx24,0,2),  // 0000.0000.0001.0000 0010.jjjj.cccc.jjjj jjjj.jjjj.jjjj.jjjj
  _(res,0),

  b(cbit,n3,d20,2), // 0000.0000.0001.0000 oooo.dddd.-iii.BBBB dddd.dddd.dddd.dddd
  b(cbit,n3,d20,2), // 0000.0000.0001.0000 oooo.dddd.-iii.BBBB dddd.dddd.dddd.dddd
  b(cbit,n3,d20,2), // 0000.0000.0001.0000 oooo.dddd.-iii.BBBB dddd.dddd.dddd.dddd
  b(cbit,n3,a24,2), // 0000.0000.0001.0000 oooo.dddd.-iii.dddd dddd.dddd.dddd.dddd

  b(sbit,n3,d20,2), // 0000.0000.0001.0000 oooo.dddd.-iii.BBBB dddd.dddd.dddd.dddd
  b(sbit,n3,d20,2), // 0000.0000.0001.0000 oooo.dddd.-iii.BBBB dddd.dddd.dddd.dddd
  b(sbit,n3,d20,2), // 0000.0000.0001.0000 oooo.dddd.-iii.BBBB dddd.dddd.dddd.dddd
  b(sbit,n3,a24,2), // 0000.0000.0001.0000 oooo.dddd.-iii.dddd dddd.dddd.dddd.dddd
  
  b(tbit,n3,d20,2), // 0000.0000.0001.0000 oooo.dddd.-iii.BBBB dddd.dddd.dddd.dddd
  b(tbit,n3,d20,2), // 0000.0000.0001.0000 oooo.dddd.-iii.BBBB dddd.dddd.dddd.dddd
  b(tbit,n3,d20,2), // 0000.0000.0001.0000 oooo.dddd.-iii.BBBB dddd.dddd.dddd.dddd
  b(tbit,n3,a24,2), // 0000.0000.0001.0000 oooo.dddd.-iii.dddd dddd.dddd.dddd.dddd
};
/* nw=3 */
struct opcode cr0011[16] = {
  [0]  = _(res,0),
  [1]  = _(res,0),
  [2]  = _(res,0),
  [3]  = _(res,0),

  [4] =
  w(cbit,n4,d20,2), // 0000.0000.0001.0001 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(cbit,n4,d20,2), // 0000.0000.0001.0001 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(cbit,n4,d20,2), // 0000.0000.0001.0001 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(cbit,n4,a24,2), // 0000.0000.0001.0001 oooo.dddd.iiii.dddd dddd.dddd.dddd.dddd

  w(sbit,n4,d20,2), // 0000.0000.0001.0001 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(sbit,n4,d20,2), // 0000.0000.0001.0001 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(sbit,n4,d20,2), // 0000.0000.0001.0001 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(sbit,n4,a24,2), // 0000.0000.0001.0001 oooo.dddd.iiii.dddd dddd.dddd.dddd.dddd
  
  w(tbit,n4,d20,2), // 0000.0000.0001.0001 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(tbit,n4,d20,2), // 0000.0000.0001.0001 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(tbit,n4,d20,2), // 0000.0000.0001.0001 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(tbit,n4,a24,2), // 0000.0000.0001.0001 oooo.dddd.iiii.dddd dddd.dddd.dddd.dddd
};

/* nw=3 */
struct opcode cr0012[16] = {
  b(stor,n4,d20,2), // 0000.0000.0001.0010 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  b(stor,n4,d20,2), // 0000.0000.0001.0010 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  b(stor,n4,d20,2), // 0000.0000.0001.0010 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  b(stor,n4,a24,2), // 0000.0000.0001.0010 oooo.dddd.iiii.dddd dddd.dddd.dddd.dddd

  b(load,d20,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  b(load,d20,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  b(load,d20,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  b(load,a24,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.dddd dddd.dddd.dddd.dddd

  d(load,d20,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  d(load,d20,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  d(load,d20,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  d(load,a24,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.dddd dddd.dddd.dddd.dddd

  w(load,d20,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  w(load,d20,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  w(load,d20,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  w(load,a24,r1,2), // 0000.0000.0001.0010 oooo.dddd.rrrr.dddd dddd.dddd.dddd.dddd
};

struct opcode cr0013[16] = {
  w(stor,n4,d20,2), // 0000.0000.0001.0011 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(stor,n4,d20,2), // 0000.0000.0001.0011 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(stor,n4,d20,2), // 0000.0000.0001.0011 oooo.dddd.iiii.BBBB dddd.dddd.dddd.dddd
  w(stor,n4,a24,2), // 0000.0000.0001.0011 oooo.dddd.iiii.dddd dddd.dddd.dddd.dddd

  b(stor,r1,d20,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  b(stor,r1,d20,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  b(stor,r1,d20,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  b(stor,r1,a24,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.dddd dddd.dddd.dddd.dddd

  d(stor,r1,d20,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  d(stor,r1,d20,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  d(stor,r1,d20,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  d(stor,r1,a24,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.dddd dddd.dddd.dddd.dddd

  w(stor,r1,d20,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  w(stor,r1,d20,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  w(stor,r1,d20,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  w(stor,r1,a24,2), // 0000.0000.0001.0011 oooo.dddd.rrrr.dddd dddd.dddd.dddd.dddd
};
struct opcode cr0014[16] = {
  _(lpr,0,0,1),
  _(lprd,0,0,1),
  _(spr,0,0,1),
  _(sprd,0,0,1),
  _(res,0),
  _(res,0),
  _(res,0),
  _(res,0),
  [9] =
  d(ord, r1, r0,1),   // 0000.0000.0001.0100 oooo.____.rrrr.rrrr
  d(xor, r1, r0,1),   // 0000.0000.0001.0100 oooo.____.rrrr.rrrr
  d(and, r1, r0,1),   // 0000.0000.0001.0100 oooo.____.rrrr.rrrr
  d(sub, r1, r0,1),   // 0000.0000.0001.0100 oooo.____.rrrr.rrrr
};
struct opcode cr0018[16] = {
  [0x4] =
  b(load,md20,r1,2), // 0000.0000.0001.1000 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  b(load,md20,r1,2), // 0000.0000.0001.1000 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  [0x8] =
  d(load,md20,r1,2), // 0000.0000.0001.1000 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  d(load,md20,r1,2), // 0000.0000.0001.1000 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  [0xa] =
  w(load,md20,r1,2), // 0000.0000.0001.1000 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  w(load,md20,r1,2)  // 0000.0000.0001.1000 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
};
struct opcode cr0019[16] = {
  [0x4] =
  b(stor,r1,md20,2), // 0000.0000.0001.1001 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  b(stor,r1,md20,2), // 0000.0000.0001.1001 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  [0x8] =
  d(stor,r1,md20,2), // 0000.0000.0001.1001 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  d(stor,r1,md20,2), // 0000.0000.0001.1001 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  [0xa] =
  w(stor,r1,md20,2), // 0000.0000.0001.1001 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
  w(stor,r1,md20,2)  // 0000.0000.0001.1001 oooo.dddd.rrrr.BBBB dddd.dddd.dddd.dddd
};
struct opcode cr001x[16] = {
  [0x0] = t(cr0010,28,0xf),
  [0x1] = t(cr0011,28,0xf),
  [0x2] = t(cr0012,28,0xf),
  [0x3] = t(cr0013,28,0xf),
  [0x4] = t(cr0014,28,0xf),
  [0x8] = t(cr0018,28,0xf),
  [0x9] = t(cr0019,28,0xf),
};

/* 0000.0000.oooo.xxxx */
struct opcode cr00[16] = {
  t(cr000x,0,0xF),
  t(cr001x,0,0xF),
  d(add,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(sub,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(and,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(or, i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(xor,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(mov,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(0),
  d(cmp,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  _(loadmp),
  _(stormp),
  _(excp),
  jd(jal,r0),
};

/* arg2 = #word-1 */
struct opcode crmap[] = {
  /* 0x00 */
  t(cr00,4,0xF), _(push,n3,r0),   _(pop,r0),     _(popret,0),
  d(add,i20,r1,1), d(mov,i20,r1,1), w(tbit,n4,r0), w(tbit,r1,r0),
  _(a08),          _(a09),          t(jccr,4,0xF), b(muls,r1,r0),
  _(beq0b,j4,r0),  _(bne0b,j4,r0), _(beq0w,j4,r0), _(beq0w,j4,r0),
  /* 0x10 */
  t(jcc8,4,0xF), t(jcc8,4,0xF), t(jcc8,4,0xF), t(jcc8,4,0xF),
  t(jcc8,4,0xF), t(jcc8,4,0xF), t(jcc8,4,0xF), t(jcc8,4,0xF),
  t(jcc8,4,0xF), t(jcc8,4,0xF), t(jcc8,4,0xF), t(jcc8,4,0xF),
  t(jcc8,4,0xF), t(jcc8,4,0xF), t(jcc8,4,0xF), t(jcc8,4,0xF),
  /* 0x20 */
  b(and, i4,r0), b(and, r1,r0), w(and, i4,r0), w(and, r1,r0),
  b(or,  i4,r0), b(or,  r1,r0), w(or,  i4,r0), w(or,  r1,r0),
  b(xor, i4,r0), b(xor, r1,r0), w(xor, i4,r0), w(xor, r1,r0),
  b(addu,i4,r0), b(addu,r1,r0), w(addu,i4,r0), w(addu,r1,r0),
  /* 0x30 */
  b(add, i4,r0), b(add, r1,r0), w(add, i4,r0), w(add, r1,r0),
  b(addc,i4,r0), b(addc,r1,r0), w(addc,i4,r0), w(addc,r1,r0),
  b(sub, i4,r0), b(sub, r1,r0), w(sub, i4,r0), w(sub, r1,r0),
  b(subc,i4,r0), b(subc,r1,r0), w(subc,i4,r0), w(subc,r1,r0),
  /* 0x40 */
  b(ashu,i4,r0), b(ashu,r1,r0), w(ashu,n5,r0), w(ashu,n5,r0), // s3,r,s5:L,s5:R
  b(lsh,r1,r0),  w(ashu,r1,r0), w(lsh,r1,r0),  d(lshd,r1,r0), // r,r,r,r
  d(ashu,r1,r0), w(lsh, n4,r0), d(lsh,n5,r0),  d(lsh, n5,r0), // r,n4:R,n5:R,n5:R
  d(ashu,n5,r0), d(ashu,n5,r0), d(ashu,n5,r0), d(ashu,n5,r0), // n5:L,n5:L,n5:R,n5:R
  /* 0x50 */
  b(cmp, i4,r0), b(cmp, r1,r0), w(cmp, i4,r0), w(cmp, r1,r0),
  d(mov, i4,r0), d(mov, r1,r0), d(cmp, i4,r0), d(cmp, r1,r0),
  b(mov, i4,r0), b(mov, r1,r0), w(mov, i4,r0), w(mov, r1,r0),
  b(movx,r1,r0), b(movz,r1,r0), w(movx,r1,r0), w(movz,r1,r0),
  /* 0x60 */
  d(add,i4,r0),     d(add,r1,r0),     w(muls, r1,r0), w(mulu,r1,r0),
  b(mul,i4,r0),     b(mul,r1,r0),     w(mul,i4,r0),   w(mul, r1,r0),
  b(cbit,n3,a20r3,2),w(cbit,n4,d16,2), t(t6A,6,0x3),   t(t6B,7,0x1),
  w(cbit,n4,a20r4,2),w(cbit,n4,a20r4,2),w(cbit,n4,d0),  w(cbit,n4,a20,2),
  /* 0x70 */
  b(sbit,n3,a20r3,2),w(sbit,n4,d16,2), t(t72,6,0x3), t(t73,7,0x1),
  w(sbit,n4,a20r4,2),w(sbit,n4,a20r4,2),w(sbit,n4,d0),w(sbit,n4,a20,2),
  b(tbit,n3,a20r3,2),w(tbit,n4,d16,2), t(t7A,6,0x3), t(t7B,7,0x1),
  w(tbit,n4,a20r4,2),w(tbit,n4,a20r4,2),w(tbit,n4,d0),w(tbit,n4,a20,2),
  /* 0x80 */
  b(NULL),          b(stor,n4,a20,1), b(stor,n4,d0),    b(stor,n4,d16,1),
  b(stor,n4,a20r4,1),b(stor,n4,a20r4,1),t(t86,6,0x3),     d(load,a20,r1,1),
  b(load,a20, r1,1),w(load,a20,r1,1), b(load,a20r4,r1,1),b(load,a20r4,r1,1),
  d(load,a20r4,r1,1),d(load,a20r4,r1,1),w(load,a20r4,r1,1),w(load,a20r4,r1,1),
  /* 0x90 */
  w(load,d4,r1),w(load,d4,r1),w(load,d4,r1),w(load,d4,r1),
  w(load,d4,r1),w(load,d4,r1),w(load,d4,r1),w(load,d4,r1),
  w(load,d4,r1),w(load,d4,r1),w(load,d4,r1),w(load,d4,r1),
  w(load,d4,r1),w(load,d4,r1),w(load,d0,r1),w(load,d16,r1,1),
  /* 0xa0 */
  d(load,d4,r1),d(load,d4,r1),d(load,d4,r1),d(load,d4,r1),
  d(load,d4,r1),d(load,d4,r1),d(load,d4,r1),d(load,d4,r1),
  d(load,d4,r1),d(load,d4,r1),d(load,d4,r1),d(load,d4,r1),
  d(load,d4,r1),d(load,d4,r1),d(load,d0,r1),d(load,d16,r1,1),
  /* 0xb0 */
  b(load,d4,r1),b(load,d4,r1),b(load,d4,r1),b(load,d4,r1),
  b(load,d4,r1),b(load,d4,r1),b(load,d4,r1),b(load,d4,r1),
  b(load,d4,r1),b(load,d4,r1),b(load,d4,r1),b(load,d4,r1),
  b(load,d4,r1),b(load,d4,r1),b(load,d0,r1),b(load,d16,r1,1),
  /* 0xc0 */
  _(bal,j24,0,1),    w(stor,n4,a20,1),  w(stor,n4,d0),     w(stor,n4,d16,1),
  w(stor,n4,a20r4,1),w(stor,n4,a20r4,1),t(tC6,6,0x3),      d(stor,r1,a20,1),
  b(stor,r1,a20,1),  w(stor,r1,a20,1),  b(stor,r1,a20r4,1),b(stor,r1,a20r4,1),
  d(stor,r1,a20r4,1),d(stor,r1,a20r4,1),w(stor,r1,a20r4,1),w(stor,r1,a20r4,1),
  /* 0xd0 */
  w(stor,r1,d4),w(stor,r1,d4),w(stor,r1,d4),w(stor,r1,d4),
  w(stor,r1,d4),w(stor,r1,d4),w(stor,r1,d4),w(stor,r1,d4),
  w(stor,r1,d4),w(stor,r1,d4),w(stor,r1,d4),w(stor,r1,d4),
  w(stor,r1,d4),w(stor,r1,d4),w(stor,r1,d0),w(stor,r1,d16,1),
  /* 0xe0 */
  d(stor,r1,d4),d(stor,r1,d4),d(stor,r1,d4),d(stor,r1,d4),
  d(stor,r1,d4),d(stor,r1,d4),d(stor,r1,d4),d(stor,r1,d4),
  d(stor,r1,d4),d(stor,r1,d4),d(stor,r1,d4),d(stor,r1,d4),
  d(stor,r1,d4),d(stor,r1,d4),d(stor,r1,d0),d(stor,r1,d16,1),
  /* 0xf0 */
  b(stor,r1,d4),b(stor,r1,d4),b(stor,r1,d4),b(stor,r1,d4),
  b(stor,r1,d4),b(stor,r1,d4),b(stor,r1,d4),b(stor,r1,d4),
  b(stor,r1,d4),b(stor,r1,d4),b(stor,r1,d4),b(stor,r1,d4),
  b(stor,r1,d4),b(stor,r1,d4),b(stor,r1,d0),b(stor,r1,d16,1),
};

const char *crregw[] = { "r0", "r1", "r2", "r3",
			 "r4", "r5", "r6", "r7",
			 "r8", "r9", "r10", "r11",
			 "r12", "r13", "ra", "sp" };
const char *crregd[] = { "(r1,r0)","(r2,r1)","(r3,r2)","(r4,r3)",
			 "(r5,r4)","(r6,r5)","(r7,r6)",
			 "(r8,r7)","(r9,r8)","(r10,r9)",
			 "(r11,r10)","(r12,r11)",
			 "(r12)","(r13)", "(ra)", "(sp)" };

const char *crregname(int reg, int sz)
{
  if (sz == SIZE_HWORD) {
    return crregd[reg];
  }
  return crregw[reg];
}

int mkcrmem(struct cpu *cpu, int sz, int base, uint32_t off)
{
  cpu->offv = off;
  return TYPE_OFFSET|sz;
}

const char *crargv(struct cpu *cpu, int arg, int sz, int off)
{
  static char argstr[128];
  
  if (!arg)
    return "";
  switch (tt(arg)) {
  case TYPE_REG:
    return crregname(arg & 0xF, sz);
  case TYPE_IMM:
    snprintf(argstr, sizeof(argstr), "0x%x", cpu->immv);
    break;
  case TYPE_IMMV:
    snprintf(argstr, sizeof(argstr), "0x%x", (arg & VAL_MASK));
    break;
  case TYPE_OFFSET:
    snprintf(argstr, sizeof(argstr), "0x%x <%s>",
	     cpu->offv, getSymName(NULL, cpu->offv));
    break;
  case TYPE_JMP:
    snprintf(argstr, sizeof(argstr), "0x%x <%s>",
	     _vbase+cpu->immv, getSymName(NULL, _vbase+cpu->immv));
    break;
  default:
    printf("foo: %x\n", arg);
    exit(0);
  }
  return argstr;
}

/* Convert opcode arguments to common */
int crop(struct cpu *cpu, int *arg, int sz)
{
  uint32_t op = cpu->op;
  uint32_t v;
  int a0, a1;

  if (!*arg)
    return 0;
  
  a0 = (op & 0xF);
  a1 = (op >> 4) & 0xF;
  sz &= SIZE_MASK;
  switch (*arg) {
  case r0:
    return mkreg(sz, a0, 0);
  case r1:
    return mkreg(sz, a1, 0);
  case i3:
  case n3:
    return mkimm(cpu, SIZE_BYTE, (op >> 4) & 0x7);
  case n4:
    return mkimm(cpu, SIZE_BYTE, a1);
  case n5:
    return mkimm(cpu, SIZE_BYTE, (op >> 4) & 0x1F);
  case i4:
    v = a1;
    if (v == 0xB) {
      /* Special case i16 */
      *arg = i16;
      cpu->nb |= 2;
      v = _get16(cpu->pc+2);
      return mkimm(cpu, SIZE_WORD, v);
    }
    else if (v == 0x9) {
      /* Special case -1 */
      v = 0xFFFF;
    }
    return mkimm(cpu, SIZE_BYTE, v);
  case i20:
    v =  (a0 << 16) | _get16(cpu->pc+2);
    return mkimm(cpu, SIZE_DWORD, v);
  case i32:
    v = _get16(cpu->pc+2) << 16;
    v |= _get16(cpu->pc+4);
    return mkimm(cpu, SIZE_DWORD, v);
  case d0: // rp,prp(rp if CFG.SR, else rrp)
    return mkcrmem(cpu, sz, a0, 0);
  case d4: // 0..13 = positive displacement, 14=prp, 15=disp16
    v = (op >> 8) & 0xF;
    if (sz == SIZE_HWORD)
      v <<= 1;
    return mkcrmem(cpu, sz, a0, v);
  case d14:
    /* base = prp */
    v = _get16(cpu->pc+2);
    return mkcrmem(cpu, SIZE_WORD, a0,
		   ((op & 0x0030) << 8) |
		   ((v & 0xFF00) >> 4) |
		   (v & 0x000F));
  case d16:
    return mkcrmem(cpu, SIZE_WORD, a0, _get16(cpu->pc+2));
  case a24:
    return mkcrmem(cpu, SIZE_DWORD, -1,
		   (a0 << 20) |
		   ((op & 0xF00) << 8) |
		   _get16(cpu->pc+4));
  case a20:
    return mkcrmem(cpu, SIZE_DWORD, -1,
		   (a0 << 16) | _get16(cpu->pc+2));
  case a20r3:
    return mkcrmem(cpu, SIZE_DWORD, (op & 0x80) ? _r13 : _r12,
		   (a0 << 16) | _get16(cpu->pc+2));
  case a20r4:
    return mkcrmem(cpu, SIZE_DWORD, (op & 0x100) ? _r13 : _r12,
		   (a0 << 16) | _get16(cpu->pc+2));
  case j8:
    v =  a0;
    v |= (op & 0xF00) >> 4;
    if (v == 0x80) {
      /* j16:format 22 */
      *arg = j16;
      v = _get16(cpu->pc+2);
      v = (int16_t)((v >> 1) | (v << 15)) << 1;
      cpu->immv = v + getpc(cpu);
      cpu->nb |= 2;
      return TYPE_JMP|SIZE_WORD;
    }
    else {
      /* j8 */
      v = ((int8_t)v) << 1;
      cpu->immv = v + getpc(cpu);
      return TYPE_JMP|SIZE_BYTE;
    }
    break;
  case j24:
    cpu->immv = (op & 0xFF) << 16;
    cpu->immv |= _get16(cpu->pc+2);
    if (op & 0x80)
      cpu->immv = (cpu->immv | ~0xFFFFFF) - 1;
    cpu->immv += getpc(cpu);
    addSym(cpu->immv+_vbase, 1, NULL, "func_%.8x", cpu->immv+_vbase);
    return TYPE_JMP|SIZE_DWORD;
  default:
    printf("Foo: %x\n", arg);
    exit(0);
    break;
  }
  return *arg;
}

/* get next opcode */ 
struct opcode *nxtCr(struct cpu *cpu, struct opcode *opc)
{
  uint32_t ib;

  ib = (_get32(cpu->pc) >> tSHIFT(opc->flag)) & tMASK(opc->flag);
  return &opc->tbl[ib];
}

struct opcode *_discr16(stack_t *stk, struct cpu *cpu)
{
  struct opcode *opc, *noc;
  int off;
  uint32_t civ;
  int a0, a1, ta0, ta1;
  char *i0, *i1;

  cpu->nb = 0;
  off = cpu->pc - stk->base;
  printf("%.8lx ", stk->vbase + off);
  cpu->op = _get16(cpu->pc);
  opc = &crmap[cpu->op >> 8];
  while (opc->tbl) {
    opc->flag |= FLAG_USED;
    opc = nxtCr(cpu, opc);
  }

  /* Decode opcode operands */
  ta0 = opc->args[0];
  ta1 = opc->args[1];
  a0 = crop(cpu, &ta0, opc->flag);
  a1 = crop(cpu, &ta1, opc->flag);
  i0 = strdup(crargv(cpu, a0, opc->flag & SIZE_MASK, off));
  i1 = strdup(crargv(cpu, a1, opc->flag & SIZE_MASK, off));

  /* Calculate #of bytes used by this instruction */
  cpu->nb += (opc->args[2] + 1) * 2;

  printf("%.5x[%x] %-8s {%s}%s,{%s}%s\n",
	 cpu->op, cpu->nb, opc->mnem,
	 crarg(ta0), i0,
	 crarg(ta1), i1);
  free(i0);
  free(i1);
  
  if (opc->mnem && !strcmp(opc->mnem, "jmpa") &&
      _get16(cpu->pc - 6) == 0x0020) {
    civ  = _get16(cpu->pc - 4) << 16;
    civ |= _get16(cpu->pc - 2);
    civ <<= 1;
    civ &= 0xFFFF;
    printf("Jump Table @ %x\n", civ);
    _push(stk, civ, "civ");
  }
  noc = calloc(1, sizeof(*noc));
  noc->mnem = opc->mnem;
  noc->flag = opc->flag;
  noc->data = opc;
  noc->llop = opc->llop;
  noc->args[0] = a0;
  noc->args[1] = a1;
  cpu->pc += cpu->nb;
  return noc;
}

/*=====================================================*
 * Cr16 emutab
 *=====================================================*/
struct emutab cremutab[] = {
  { "andb", hliAND, _a1, _a0, _a1, 0 },
  { "andw", hliAND, _a1, _a0, _a1, 0 },
  { "andd", hliAND, _a1, _a0, _a1, 0 },

  { "orb",  hliOR,  _a1, _a0, _a1, 0 },
  { "orw",  hliOR,  _a1, _a0, _a1, 0 },
  { "ord",  hliOR,  _a1, _a0, _a1, 0 },

  { "xorb", hliXOR, _a1, _a0, _a1, 0 },
  { "xorw", hliXOR, _a1, _a0, _a1, 0 },
  { "xord", hliXOR, _a1, _a0, _a1, 0 },

  { "addub",hliADD, _a1, _a0, _a1, 0 },
  { "adduw",hliADD, _a1, _a0, _a1, 0 },
  { "addud",hliADD, _a1, _a0, _a1, 0 },
  
  { "addb", hliADD, _a1, _a0, _a1, 0 },
  { "addw", hliADD, _a1, _a0, _a1, 0 },
  { "addd", hliADD, _a1, _a0, _a1, 0 },
  
  { "addcb",hliADD, _a1, _a0, _a1, rCF },
  { "addcw",hliADD, _a1, _a0, _a1, rCF },
  { "addcd",hliADD, _a1, _a0, _a1, rCF },

  { "subb", hliSUB, _a1, _a0, _a1, 0 },
  { "subw", hliSUB, _a1, _a0, _a1, 0 },
  { "subd", hliSUB, _a1, _a0, _a1, 0 },

  { "subcb",hliSUB, _a1, _a0, _a1, rCF },
  { "subcw",hliSUB, _a1, _a0, _a1, rCF },
  { "subcd",hliSUB, _a1, _a0, _a1, rCF },

  { "movb", hliASSIGN,_a1,_a0, 0, 0 },
  { "movw", hliASSIGN,_a1,_a0, 0, 0 },
  { "movd", hliASSIGN,_a1,_a0, 0, 0 },

  { "cmpb", hliSUB,   0, _a0, _a1, 0 },
  { "cmpw", hliSUB,   0, _a0, _a1, 0 },
  { "cmpd", hliSUB,   0, _a0, _a1, 0 },

  { "storb",hliASSIGN,_a1,_a0, 0, 0  },
  { "storw",hliASSIGN,_a1,_a0, 0, 0  },
  { "stord",hliASSIGN,_a1,_a0, 0, 0  },

  { "loadb",hliASSIGN,_a1,_a0, 0, 0  },
  { "loadw",hliASSIGN,_a1,_a0, 0, 0  },
  { "loadd",hliASSIGN,_a1,_a0, 0, 0  },
  { },
};

#define fb(a,v) ((_cpuflag & (a)) ? v : '-')
void _showregscr(struct imap *ci)
{
  int i;

  printf("===================================================\n");
  for (i = 0; i < 16; i++) {
    printf("%4s: %.8x  %s", crregw[i], _regs[i].w,
	   i == 7 ? "\n" : "");
  }
  printf("\n  IP: %.8x  ", _regs[16].w);
  printf("%c%c%c%c\n", fb(fCF,'c'), fb(fZF,'z'), fb(fOF,'o'), fb(fSF,'s'));
}

void cremu(struct imap *i)
{
  val_t a, b;

  if (runemu(i, cremutab))
    return;
  if (isemu(i, 2, "sbitb", "sbitw")) {
    a = _getval(i, i->opc->args[0]);
    b = _getval(i, i->opc->args[1]);
    _setval(i, i->opc->args[1], b | (1L << a));
  }
  if (isemu(i, 2, "cbitb", "cbitw")) {
    a = _getval(i, i->opc->args[0]);
    b = _getval(i, i->opc->args[1]);
    _setval(i, i->opc->args[1], b & ~(1L << a));
  }
}
