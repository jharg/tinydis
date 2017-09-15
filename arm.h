#ifndef __arm_h__
#define __arm_h__

enum {
  ARMBASE = 0x2000,
  Rd,
  Rn,
  Rm,
  Rs,
  Rmi,
  Rms,
  Rii,
  ROp2,
  MRd,
  MRdp, // Rd pair Hi/Lo
  MRn,
  Rl,
  Br24,
  
  LSPreI,
  LSPostI,
  CPl,
  CDp,
  MCr,

  _r0 = TYPE_REG+SIZE_DWORD,
  _r1,
  _r2,
  _r3,
  _r4,
  _r5,
  _r6,
  _r7,
  _r8,
  _r9,
  _r10,
  _fp,
  _ip,
  _sp,
  _lr,
  _pc,
};

#endif
