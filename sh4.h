#ifndef __sh4_h__
#define __sh4_h__

enum {
  SH4_BASE = 0x4000,
  Rm,
  Rn,
  FRm,
  FRn,
  i3,
  i8,
  i20,
  Pr15, // [R15++]

  Dn,   // [--Rn]
  Pn,   // [Rn++]
  dn,   // [Rn]
  dn0,  // [Rn+R0]
  d4n,  // [Rn+d4]
  d12n, // [Rn+d12]

  Dm,   // [--Rm]
  Pm,   // [Rm++]
  dm,   // [Rm]
  dm0,  // [Rm+R0]
  d4m,  // [Rm+d4]
  d12m, // [Rm+d12]
  dmp,  // [Rm+PC]

  d8g,  // [GBR+d8]
  dr0g, // [GBR+R0]
  d8p,  // [PC+d8]

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


#endif
