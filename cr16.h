#ifndef __cr16_h__
#define __cr16_h__

enum {
  CRBASE = 0x200,

  /* Register arg */
  r0,   // ? oooo.oooo.----.rrrr
  r1,   // ? oooo.oooo.rrrr.----

  /* Relative Memory Address */
  d0,   // 1 oooo.oooo.----.BBBB
  d4,   // 1 oooo.dddd.----.BBBB
  d14,  // 2 oooo.oooo.oodd.BBBB dddd.dddd.----.dddd
  d16,  // 2 oooo.oooo.----.BBBB dddd.dddd.dddd.dddd
  d20,  // 3 0000.0000.0001.oooo oooo.dddd.----.BBBB dddd.dddd.dddd.dddd
  md20, // 3 0000.0000.0001.oooo oooo.dddd.----.BBBB dddd.dddd.dddd.dddd

  /* Absolute Memory Address */
  a20,  // 2 oooo.oooo.----.dddd dddd.dddd.dddd.dddd
  a20r4,// 2 oooo.oooB.----.dddd.dddd.dddd.dddd.dddd
  a20r3,// 2 oooo.oooo.B---.dddd.dddd.dddd.dddd.dddd
  a24,  // 3 0000.0000.oooo.oooo.oooo dddd.----.dddd dddd.dddd.dddd.dddd

  /* Integer */
  n3,   // 1 oooo.oooo.-iii.----
  n4,   // 1 oooo.oooo.iiii.----
  n5,   // 1 oooo.oooi.iiii.----
  i4,   // 1 oooo.oooo.iiii.----
  i16,  // 2 oooo.oooo.1101.---- iiii.iiii.iiii.iiii
  i20,  // 2 oooo.oooo.----.iiii iiii.iiii.iiii.iiii
  i32,  // 3 oooo.oooo.oooo.---- iiii.iiii.iiii.iiii iiii,iiii.iiii.iiii

  /* j4  bxx disp4       
   * j8  bxx disp8       
   * j16 bxx disp16      
   * jx24 
   * jx24 bal rp,disp24  3a 3 0000.0000.0001.0000 0010.jjjj.rrrr.jjjj jjjj.jjjj.jjjj.jjjj
   * j24 
   */
  j4,   // bxx disp4  15 1 oooo.oooo.jjjj.rrrr
  j8,   // bxx disp8  21 1 0001.jjjj.cccc.jjjj
  j16,  // bxx disp16 22 2 0001.1000.cccc.0000 jjjj.jjjj.jjjj.jjjj
  jx24, // bxx disp24 3a 3 0000.0000.0001.0000 0000.jjjj.cccc.jjjj jjjj.jjjj.jjjj.jjjj
  j24,  // bal ra,disp24   5  2 1100.0000.jjjj.jjjj jjjj.jjjj.jjjj,jjjj

  _r12 = TYPE_REG+12,
  _r13 = TYPE_REG+13,
  _rPC = TYPE_REG+16,

  _N = TYPE_CPUFLAG|0x1,
  _L = TYPE_CPUFLAG|0x2,
  _C = TYPE_CPUFLAG|0x4,
  _F = TYPE_CPUFLAG|0x8,
  _Z = TYPE_CPUFLAG|0x10,
  
  _ZL = _Z|_L,
  _ZN = _Z|_N,
};

#endif
