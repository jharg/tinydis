#ifndef __tinydis_h__
#define __tinydis_h__

#define _get8(x)    *(uint8_t *)(x)
#define _get16(x)   *(uint16_t *)(x)
#define _get32(x)   *(uint32_t *)(x)
#define _get64(x)   *(uint64_t *)(x)

#define _put8(x,v)  *(uint8_t *)(x) = (v)
#define _put16(x,v) *(uint16_t *)(x) = (v)
#define _put32(x,v) *(uint32_t *)(x) = (v)
#define _put64(x,v) *(uint64_t *)(x) = (v)

static inline uint16_t _get16be(void *p)
{
  uint8_t *b = p;
  return (b[0] << 8) | b[1];
}

#define mrr_mm(x)  (((x) >> 6) & 3)
#define mrr_ggg(x) (((x) >> 3) & 7)
#define mrr_rrr(x) (((x) >> 0) & 7)

#define sib_ss(x)  (((x) >> 6) & 3)
#define sib_iii(x) (((x) >> 3) & 7)
#define sib_bbb(x) (((x) >> 0) & 7)

#define REX_B    0x1
#define REX_X    0x2
#define REX_R    0x4
#define REX_W    0x8
#define REX_MASK 0xFF

#define VEX_RR   0x100 // vex_rr|rex_r,mrr_ggg
#define VEX_VV   0x200 // vex_vv,      vex_vvvv
#define VEX_XX   0x400 // vex_xx|rex_b,mrr_rrr
#define VEX_MASK 0xF00

/* CPU Flags bits */
#define fCF (1L << 0)
#define fPF (1L << 2)
#define fAF (1L << 4)
#define fZF (1L << 6)
#define fSF (1L << 7)
#define fTF (1L << 8)
#define fIF (1L << 9)
#define fDF (1L << 10)
#define fOF (1L << 11)

enum {
  TYPE_SHIFT  = 24,
  TYPE_MASK   = (0xFF << TYPE_SHIFT),
  TYPE_REG    = ('r'  << TYPE_SHIFT),  /* CPU Register */
  TYPE_OFFSET = ('O'  << TYPE_SHIFT),  /* Direct Memory Offset */
  TYPE_EA     = ('E'  << TYPE_SHIFT),  /* Effective address: Mem/Reg */
  TYPE_EAMEM  = ('M'  << TYPE_SHIFT),  /* Effective address: Memory */
  TYPE_EAREG  = ('G'  << TYPE_SHIFT),  /* Effective address: Register */
  TYPE_EMBREG = ('g'  << TYPE_SHIFT),  /* Embedded reg, part of opcode: oooorrr */
  TYPE_IMM    = ('I'  << TYPE_SHIFT),  /* Immediate */
  TYPE_IMMV   = ('i'  << TYPE_SHIFT),  /* Implied immediate */
  TYPE_JMP    = ('J'  << TYPE_SHIFT),  /* PC-relative offset */
  TYPE_DXAX   = ('d'  << TYPE_SHIFT),  /* DX:AX for div/mul */
  TYPE_DSSI   = ('X'  << TYPE_SHIFT),  /* DS:SI for strop */
  TYPE_ESDI   = ('Y'  << TYPE_SHIFT),  /* ES:DI for strop */
  TYPE_ABSPTR = ('A'  << TYPE_SHIFT),  /* Iw:Iw or Iw:Id */
  TYPE_CPUFLAG= ('F'  << TYPE_SHIFT),
  TYPE_MEMORY = ('$'  << TYPE_SHIFT),  /* Memory: uses basev, offv */

  SIZE_SHIFT  = 16,
  SIZE_MASK   = (0xFF << SIZE_SHIFT),
  SIZE_BYTE   = ('b'  << SIZE_SHIFT),
  SIZE_WORD   = ('w'  << SIZE_SHIFT),
  SIZE_DWORD  = ('d'  << SIZE_SHIFT),
  SIZE_QWORD  = ('q'  << SIZE_SHIFT),
  SIZE_VWORD  = ('v'  << SIZE_SHIFT),
  SIZE_ZWORD  = ('z'  << SIZE_SHIFT),
  SIZE_HWORD  = ('h'  << SIZE_SHIFT),  /* CR16 split register */
  SIZE_SEGREG = ('s'  << SIZE_SHIFT),  /* Segment register */
  SIZE_PTR    = ('p'  << SIZE_SHIFT),  /* PTR16:16 or PTR16:32 */
  SIZE_CREG   = ('C'  << SIZE_SHIFT),
  SIZE_DREG   = ('D'  << SIZE_SHIFT),
  SIZE_XMM    = ('X'  << SIZE_SHIFT),
  SIZE_YMM    = ('Y'  << SIZE_SHIFT),
  SIZE_ZMM    = ('Z'  << SIZE_SHIFT),
  
  VAL_MASK = 0xFFFF,

  Vx = TYPE_EA+SIZE_XMM,
  
  Eb = TYPE_EA+SIZE_BYTE,
  Ew = TYPE_EA+SIZE_WORD,
  Ev = TYPE_EA+SIZE_VWORD,

  Cv = TYPE_EA+SIZE_CREG,
  Dv = TYPE_EA+SIZE_DREG,

  Mw = TYPE_EAMEM+SIZE_WORD,
  Mp = TYPE_EAMEM+SIZE_PTR,
  
  Gb = TYPE_EAREG+SIZE_BYTE,
  Gw = TYPE_EAREG+SIZE_WORD,
  Gv = TYPE_EAREG+SIZE_VWORD,
  Sw = TYPE_EAREG+SIZE_SEGREG,

  Ob = TYPE_OFFSET+SIZE_BYTE,
  Ov = TYPE_OFFSET+SIZE_VWORD,

  Ap = TYPE_ABSPTR+SIZE_VWORD,
  
  Xb = TYPE_DSSI+SIZE_BYTE,
  Xv = TYPE_DSSI+SIZE_VWORD,
  Xz = TYPE_DSSI+SIZE_ZWORD,

  Yb = TYPE_ESDI+SIZE_BYTE,
  Yv = TYPE_ESDI+SIZE_VWORD,
  Yz = TYPE_ESDI+SIZE_ZWORD,
  
  Ib = TYPE_IMM+SIZE_BYTE,
  Iw = TYPE_IMM+SIZE_WORD,
  Id = TYPE_IMM+SIZE_DWORD,
  Iv = TYPE_IMM+SIZE_VWORD,
  Iz = TYPE_IMM+SIZE_ZWORD,

  i0 = TYPE_IMMV+SIZE_BYTE+0,
  i1 = TYPE_IMMV+SIZE_BYTE+1,
  i3 = TYPE_IMMV+SIZE_BYTE+3,

  gb = TYPE_EMBREG+SIZE_BYTE,
  gv = TYPE_EMBREG+SIZE_VWORD,
  
  Jb = TYPE_JMP+SIZE_BYTE,
  Jw = TYPE_JMP+SIZE_WORD,
  Jz = TYPE_JMP+SIZE_ZWORD,

  /* CPU Flags register */
  rCF = TYPE_CPUFLAG+SIZE_BYTE+fCF,
  rPF = TYPE_CPUFLAG+SIZE_BYTE+fPF,
  rAF = TYPE_CPUFLAG+SIZE_BYTE+fAF,
  rZF = TYPE_CPUFLAG+SIZE_BYTE+fZF,
  rSF = TYPE_CPUFLAG+SIZE_BYTE+fSF,
  rIF = TYPE_CPUFLAG+SIZE_BYTE+fIF,
  rDF = TYPE_CPUFLAG+SIZE_BYTE+fDF,
  rOF = TYPE_CPUFLAG+SIZE_BYTE+fOF,
  rbFLAGS = TYPE_CPUFLAG+SIZE_BYTE+0xFF,

  rAL = TYPE_REG+SIZE_BYTE,
  rCL,
  rDL,
  rBL,
  rAH,
  rCH,
  rDH,
  rBH,

  rAX = TYPE_REG+SIZE_WORD,
  rCX,
  rDX,
  rBX,
  rSP,
  rBP,
  rSI,
  rDI,

  rIP = TYPE_REG+SIZE_WORD+16,
  rRIP = TYPE_REG+SIZE_QWORD+16,
  rvIP = TYPE_REG+SIZE_VWORD+16,

  rDAX = TYPE_DXAX+SIZE_WORD,
  rEDAX = TYPE_DXAX+SIZE_DWORD,
  rRDAX = TYPE_DXAX+SIZE_QWORD,
  rvDAX = TYPE_DXAX+SIZE_VWORD,
  
  rEAX = TYPE_REG+SIZE_DWORD,
  rECX,
  rEDX,
  rEBX,
  rESP,
  rEBP,
  rESI,
  rEDI,

  rRAX = TYPE_REG+SIZE_QWORD,
  rRCX,
  rRDX,
  rRBX,
  rRSP,
  rRBP,
  rRSI,
  rRDI,
  rR8,
  rR9,
  rR10,
  rR11,
  rR12,
  rR13,
  rR14,
  rR15,
  
  rzAX = TYPE_REG+SIZE_ZWORD,

  rvAX = TYPE_REG+SIZE_VWORD,
  rvCX,
  rvDX,
  rvBX,
  rvSP,
  rvBP,
  rvSI,
  rvDI,
  
  rES = TYPE_REG+SIZE_SEGREG,
  rCS,
  rSS,
  rDS,
  rFS,
  rGS,
};

struct sym
{
  uint32_t addr;
  const char *name;
  void *data;
  int flag;
};

#define sCODE    0x01
#define sCODEGEN 0x07
#define sSTRING  0x08
#define sCOMMENT 0x10

#define MACH_CR16    0x10067
#define MACH_X86_64  0x2003e
#define MACH_X86_32  0x10003
#define MACH_X86_16  0x00003
#define MACH_ARM     0x10028
#define MACH_SH4     0x1002a

typedef struct
{
  uint64_t vbase;
  uint32_t len;
  uint8_t *map;
  uint8_t *base;
} stack_t;

typedef struct
{
  int         idx;
  uint32_t    vaddr;
  size_t      size;
  void       *data;
  void       *opaque;
  const char *name;
  stack_t     stk;
} section_t;

section_t *addSection(int idx, uint32_t vaddr, size_t sz, void *data, const char *name, void *opaque);
struct sym *findSym(uint32_t addr);
const char *getSymName(section_t *,uint32_t addr);
struct sym *addSym(uint32_t addr, int flag, void *data, const char *name, ...);

extern void parsebb(void *, int, int, uint64_t, int);

struct opcode {
  struct opcode *tbl;
  const char    *mnem;
  uint32_t       args[4];
  uint32_t       flag;
  int            llop;
  void          *data;
};

struct imap {
  struct opcode *opc;
  struct expr   *expr;
  int32_t  offv;
  uint64_t immv;
  int      basev;
  int      hli;
  int      nb;
  int      seg;
  int      sz;
  int      flag;
};

enum {
  bbNONE,
  bbJUMP,
  bbCOND,
  bbCALL,
  bbFALL,
  bbTERM,

  /* Convert to other type */
  bbSPLIT,
  bbIF,
  bbIFRET,
  bbWHILE,
  bbDOWHILE,
  bbFOR,
};

struct cpu {
  uint64_t vbase;
  uint8_t *start;
  uint8_t *pc;
  
  int      op;
  int      flag;
  int      seg;
  int      mode;
  int      osz;
  int      asz;
  int      rex;
  int      mrr;
  int      sib;
  int      nb;
  
  int      base;
  int      index;
  int      scale;
  int32_t  offv;
  uint64_t immv;
};


/* Store bits in opcode flag:  ssss.sssm.mmmm.mmmm.----.----.----.---- */
#define tBYTE(x)   (((x) >> 27) & 0x1F)
#define tBIT(x)    (((x) >> 25) & 0x07)
#define tSHIFT(x)  (((x) >> 25) & 0x1F)
#define tMASK(x)   (((x) >> 16) & 0x1FF)
#define mkTBL(s,m) (((s) << 25) | ((m) << 16))
#define FLAG_USED  0x1000

uint32_t getoff(struct cpu *cpu);
uint32_t getpc(struct cpu *cpu);
void _push(stack_t *stk, int off, const char *lbl);
int32_t signex32(uint32_t v, int bit);

#define tt(x) ((x) & TYPE_MASK)

const char *regname(int arg);

void addtype(int rtype, const char *name, int narg, ...);

enum {
  NOTYPE,

  VOID,
  CHAR,
  SHORT,
  INT,
  LONG,
  STRUCT,
  
  FARPTR    = 0x080,
  PTR       = 0x100,
  VOIDPTR   = VOID|PTR,
  CHARPTR   = CHAR|PTR,
  SHORTPTR  = SHORT|PTR,
  INTPTR    = INT|PTR,
  LONGPTR   = LONG|PTR,
  STRUCTPTR = STRUCT|PTR,
  
  ARRAY      = 0x200,
  CHARARR    = CHAR|ARRAY,
  SHORTARR   = SHORT|ARRAY,
  INTARR     = INT|ARRAY,
  LONGARR    = LONG|ARRAY,
  STRUCTARR  = STRUCT|ARRAY,
  
  PRINTFSTR  = 0x0300 | CHAR | PTR,
  VARARG     = 0x400,
};

int mkreg(int size, int reg, int rex);
int mkimm(struct cpu *cpu, int size, uint64_t immv);

struct emutab {
  const char *mnem;
  int hli;
  int dst;
  int arg0;
  int arg1;
  int arg2;
};

enum {
  _a0 = 0xf0f0,
  _a1 = 0xf0f1,
  _a2 = 0xf0f2,
};

#define _mkreg(sz,vv) (TYPE_REG+(sz)+(vv))
#define _mkimm(x)     (TYPE_IMMV+SIZE_BYTE+(x))

#define uno(a,x)     (((a) << 24) + (x))
#define duo(a,x,y)   ((((y) << 8) | uno(a,x)))
#define tri(a,x,y,z) ((((z) << 6) | duo(a, x, y)))

enum {
  hliASSIGN = uno(0x9,'='),

  hliADD  = uno(0xa,'+'),
  hliSUB  = uno(0xa,'-'),
  hliOR   = uno(0xa,'|'),
  hliAND  = uno(0xa,'&'),
  hliMUL  = uno(0xa,'*'),
  hliDIV  = uno(0xa,'/'),
  hliMOD  = uno(0xa,'%'),
  hliXOR  = uno(0xa,'^'),
  hliLNOT = uno(0xa,'!'),
  hliNOT  = uno(0xa,'~'),
  hliSHL  = duo(0xa,'<','<'),
  hliSHR  = duo(0xb,'>','>'),
  hliNEG  = duo(0xa,' ','-'),
  
  hliTRI   = duo(0xb,'?',':'),
  hliARRAY = duo(0xb,'[',']'),

  hliPREDEC = duo(0xa, '-','-'),
  hliPREINC = duo(0xa, '+','+'),
  hliPOSTDEC= duo(0xb, '-','-'),
  hliPOSTINC= duo(0xb, '+','+'),

  /* comparison operator */
  hliLT    = uno(0xc,'<'),
  hliLTE   = duo(0xc,'<','='),
  hliEQ    = duo(0xc,'=','='),
  hliNEQ   = duo(0xc,'!','='),
  hliGTE   = duo(0xc,'>','='),
  hliGT    = uno(0xc,'>'),

  /* Signed comparison */
  hliLTs   = duo(0xc,'<','s'),
  hliLTEs  = tri(0xc,'<','=','s'),
  hliGTEs  = tri(0xc,'>','=','s'),
  hliGTs   = duo(0xc,'>','s'),
  
  /* Non-standard HLI ops */
  hliXCHG  = uno(0xF,0),
  hliJCC,   // jcc a1 if a0 true, else jcc a2
  hliSIGNEX,
  hliINVAL,
  hliJMP,
  hliIGNORE,

  hliROR,
  hliRCR,
  hliROL,
  hliRCL,
};

typedef int64_t val_t;

val_t _getval(struct imap *ci, int arg);
void  _setval(struct imap *ci, int arg, val_t v);
val_t _memread(struct imap *ci, int seg, int base, int index, val_t off, int arg);
void  _memwrite(struct imap *ci, int seg, int base, int index, val_t off, int arg, val_t val);
val_t _popv(struct imap *ci, int arg);
void  _pushv(struct imap *ci, int arg, val_t v);
int   emul(struct imap *ci, const char *m, int op, int dst, int a0, int a1, int a2);
int isemu(struct imap *i, int n, ...);
int runemu(struct imap *i, struct emutab *etab);

struct regval
{
  union {
    uint8_t  b[2];
    uint16_t w;
    uint32_t d;
    uint64_t q;
  };
};

#endif
