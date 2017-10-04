/* tinydis.c - Disassembler/Emulator
 *
 * Copyright (c) 2015-17 Jordan Hargrave<jordan_hargrave@hotmail.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/queue.h>
#include <unistd.h>
#include <endian.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include "tinydis.h"
#include "x86.h"
#include "arm.h"

const char *crarg(int arg);

#define cv(x) ((x) ? (x) : ' ')
#define ot(x) cv(((x) & TYPE_MASK) >> TYPE_SHIFT), cv(((x) & SIZE_MASK) >> SIZE_SHIFT)

uint64_t _vbase;

int isImm(int arg);
int isMem(int arg);
struct imap *prv(struct imap *i);
struct imap *nxt(struct imap *i, int n);

struct emutab;

int getsz(int arg, int *osz);
int dfsz(int arg, int flg);

struct type
{
  const char *name;
  int   conv;
  int   rtype;
  int   narg;
  int  *arg;
  int   nloc;
};

const char *ota1(struct imap *);
const char *ota2(struct imap *);
const char *enumToType(int type);
struct type *findType(const char *name);

struct machine
{
  int size;
  struct opcode * (*dis)(stack_t *, struct cpu *);
  void (*scan)(stack_t *);
  void (*showregs)(struct imap *);
  void (*chkhli)(struct imap *);
  void (*emu)(struct imap *);
};

int opeq(struct imap *i, const char *op, int arg0, int arg1, int arg2);

void dump(void *buf, int len, const char *sfx, int flag)
{
  uint8_t *b = buf;
  int i, j;

  printf("------------ dump : %s\n", sfx);
  for (i = 0; i < len; i += 16) {
    if (flag & 1)
      printf("  %.5x ", i);
    for (j=0; j<16; j++)
      printf("%.2x ", i+j < len ? b[i+j] : 0xFF);
    if (flag & 2) {
      printf("  ");
      for (j=0; j<16; j++)
	printf("%c", isprint(b[i+j]) && i+j < len ? b[i+j] : '-');
    }
    printf("\n");
  }
}

const char *hlit(int hli)
{
  static char s[32];

  switch (hli) {
  case 0:        return "   ";
  case hliINVAL: return "---";
  case hliADD: return "+  ";
  case hliSUB: return "-  ";
  case hliOR:  return "|  ";
  case hliAND: return "&  ";
  case hliMOD: return "%  ";
  case hliXOR: return "^  ";
  case hliMUL: return "*  ";
  case hliDIV: return "/  ";
  case hliNOT: return "!  ";
  case hliNEG: return "-()";
  case hliTRI: return "?: ";
  case hliSHL: return "<< ";
  case hliSHR: return ">> ";
  case hliLT:  return "<  ";
  case hliLTE: return "<= ";
  case hliLTs: return "<s ";
  case hliLTEs:return "<=s";
  case hliEQ:  return "== ";
  case hliNEQ: return "!= ";
  case hliGTE: return ">= ";
  case hliGTs: return ">s ";
  case hliGTEs:return ">=s";
  case hliGT:  return ">  ";
  case hliASSIGN: return "=  ";
  case hliPREDEC: return "-- ";
  case hliPOSTDEC: return "-- ";
  case hliPREINC: return "++ ";
  case hliPOSTINC: return "++ ";
  default:     return "???";
  }
}

struct expr
{
  int   type;
  union {
    int   imm;
    char *str;
    struct {
      int   op;
      struct expr *lhs;
      struct expr *rhs;
      struct expr *cond;
    };
  };
  TAILQ_ENTRY(expr) link;
};

enum {
  eNONE,
  eEXPR,
  eINT,
  eSTR,
  eSTACK,
};

void showexpr(struct expr *e, int lvl)
{
  if (!e) {
    printf("<null>");
    return;
  }
  switch (e->type) {
  case eINT:
    printf("int:0x%x", e->imm);
    break;
  case eSTR:
    printf("str:\"%s\"", e->str);
    break;
  case eSTACK:
    if (e->imm < 0)
      printf("Local_%x", -e->imm);
    else
      printf("Arg_%x", e->imm);
    break;
  case eEXPR:
    if (lvl)
      printf("(");
    if (e->cond) {
      printf("(");
      showexpr(e->cond, lvl+1);
      printf(") ? ");
      showexpr(e->lhs, lvl+1);
      printf(" : ");
      showexpr(e->rhs, lvl+1);
    }
    else {
      showexpr(e->lhs, lvl+1);
      printf(" %s ", hlit(e->op));
      showexpr(e->rhs, lvl+1);
    }
    if (lvl)
      printf(")");
    break;
  }
}

struct expr *_mkexpr(int type)
{
  struct expr *e = calloc(1,sizeof(*e));
  e->type = type;
  return e;
}

struct expr *mkint(int v)
{
  struct expr *e;
  
  e = _mkexpr(eINT);
  e->imm = v;
  return e;
}

struct expr *mkstack(int v)
{
  struct expr *e;
  
  e = _mkexpr(eSTACK);
  e->imm = v;
  return e;
}

struct expr *mkstr(const char *str, ...)
{
  struct expr *e;
  char tstr[1024];
  va_list ap;

  va_start(ap, str);
  vsnprintf(tstr, sizeof(tstr), str, ap);
  
  e = _mkexpr(eSTR);
  e->str = strdup(tstr);
  return e;
}

struct expr *mkexpr(int op, struct expr *l, struct expr *r)
{
  struct expr *e;
  int nv;

  e = _mkexpr(eEXPR);
  if (r && r->type == eINT) {
    if (!r->imm && (op == hliADD || op == hliSUB || op == hliOR || op == hliXOR)) {
      printf("Shortcut: (op lhs 0) => lhs\n");
      return l;
    }
  }
  if (op == hliOR && l == r) {
    printf("Shortcut OR\n");
    return l;
  }
  e->op = op;
  e->lhs = l;
  e->rhs = r;
}

struct expr *mktri(struct expr *cond, struct expr *e1, struct expr *e2)
{
  struct expr *e;

  e = _mkexpr(eEXPR);
  e->op = hliTRI;
  e->cond = cond;
  e->lhs = e1;
  e->rhs = e2;
  showexpr(e, 0);
  printf("\n");
  return e;
}

struct expr *regvals[32];

void resetexpr()
{
  memset(regvals, 0, sizeof(regvals));
}

struct expr *getexpr(struct imap *i, int arg)
{
  int vv = arg & 0x1F;
  
  switch (tt(arg)) {
  case TYPE_REG:
    return regvals[arg & VAL_MASK];
  case TYPE_IMM:
    return mkint(i->immv);
  case TYPE_IMMV:
    return mkint(arg & VAL_MASK);
  case TYPE_OFFSET:
    return mkstr("data_%x", i->offv);
    break;
  case TYPE_MEMORY:
    if (vv == 6) {
      return mkstack(i->offv);
    }
    break;
  }
  return NULL;
}

void setexpr(struct imap *i, int dst, struct expr *e)
{
  switch (tt(dst)) {
  case TYPE_REG:
    printf("Setting '%s' = ", regname(dst));
    break;
  default:
    printf("Setting: %c%c = ", ot(dst));
    break;
  }
  showexpr(e, 0);
  printf("\n");

  switch (tt(dst)) {
  case TYPE_REG:
    if ((dst & SIZE_MASK) != SIZE_SEGREG)
      regvals[dst & 0xF] = e;
    break;
  }
}

int evalemul(struct imap *ci, const char *m, int op,
	     int dst, int a0, int a1, int a2)
{
  if (strcmp(m, ci->opc->mnem))
    return 0;
  switch (op) {
  case hliASSIGN:
  case hliSIGNEX:
    setexpr(ci, dst, getexpr(ci, a0));
    break;
  case hliADD:
  case hliSUB:
  case hliAND:
  case hliXOR:
  case hliSHL:
  case hliSHR:
  case hliOR:
    setexpr(ci, dst, mkexpr(op, getexpr(ci, a0), getexpr(ci, a1)));
    break;
  case hliDIV:
    setexpr(ci, dst, mkexpr(hliDIV, getexpr(ci, a1), getexpr(ci, a2)));
    setexpr(ci, dst, mkexpr(hliMOD, getexpr(ci, a1), getexpr(ci, a2)));
    break;
  default:
    return 0;
  }
  return 1;
}


int32_t signex32(uint32_t v, int bit)
{
  int32_t m = 1U << (bit - 1);
  return (v ^ m) - m;
}

static FILE *vcg;

void writevcg(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vfprintf(vcg, fmt, ap);
}

void openvcg(const char *file)
{
  char vcgf[128];

  snprintf(vcgf, sizeof(vcgf), "%s.vcg", file);
  vcg = fopen(vcgf, "w+");
  writevcg("graph: {\norientation:top_to_bottom\nsplines:yes\n");
}

void closevcg(void)
{
  writevcg("}\n");
  fclose(vcg);
}

int nsects;
section_t *sectTbl;
section_t *dseg;

int prstrlen(const char *s)
{
  int l;

  l = 0;
  while (s[l] >= ' ' && s[l] <= 'z')
    l++;
  if (s[l] == 0) {
    return l;
  }
  return -1;
}

void scanString(stack_t *stk)
{
  int i, len;
  
  i = 0;
  while (i < stk->len) {
    len = prstrlen(stk->base + i);
    if (len >= 4) {
      printf("Potential string @ %lx ; '%s'\n",
	     stk->vbase+i, stk->base+i);
      addSym(stk->vbase+i, sSTRING, stk->base+i,
	     "str_%x", stk->vbase+i);
      i += len+1;
    }
    else {
      i++;
    }
  }
}

section_t *addSection(int idx, uint32_t vaddr, size_t sz, void *data,
		      const char *name, void *opaque)
{
  section_t *s;
  int i, l;

  if (sz < 65536)
    sz = 65536;
  sectTbl = realloc(sectTbl, ++nsects * sizeof(section_t));
  s = &sectTbl[nsects-1];
  s->idx = idx;
  s->vaddr = vaddr;
  s->size = sz;
  if (data == NULL) {
    /* BSS section  */
    data = calloc(1, sz);
  }
  s->data = data;
  s->name = strdup(name);
  s->opaque = opaque;
  if (!strcmp(name, ".data")) {
    dseg = s;
  }

  /* Initialize code coverage stack */
  s->stk.vbase = vaddr;
  s->stk.base  = data;
  s->stk.len   = sz;
  s->stk.map   = calloc(1, sz);

  return s;
}

void *findmem(off_t off)
{
  int i;

  for (i = 0; i < nsects; i++) {
    if (off >= sectTbl[i].vaddr && off <= (sectTbl[i].vaddr+sectTbl[i].size)) {
      return sectTbl[i].data + (off - sectTbl[i].vaddr);
    }
  }
  return NULL;
}

/*========================================================================================*
 * Code Stack
 *========================================================================================*/
#define PENDING   0x01
#define VISITED   0x03

/* Mark stack usage */
void _setstk(stack_t *stk, int off, int v, int n)
{
  if (off + n < stk->len)
    memset(stk->map + off, v, n);
}

/* Push address onto istack */
void _push(stack_t *stk, int off, const char *lbl)
{
  if (off >= stk->len) {
    printf("Stack out of range @ %x/%x [%s]\n", off, stk->len, lbl);
    return;
  }
#if 1
  printf("======== push: %.8llx %.8x %.2x [%s]\n",
	 stk->vbase+off, off, stk->map[off], lbl);
#endif
  if (!stk->map[off])
    stk->map[off] = PENDING;
}

/* Pop address off of istack. Default to last address if pending */
int _pop(stack_t *stk, int *off, int *rst)
{
  /* Check if we can continue consecutive address */
  if (*off >= 0 && *off < stk->len && stk->map[*off] == PENDING) {
    //printf("======== popcont : %.8llx %.8x\n", stk->vbase+*off, *off);
    stk->map[*off] |= VISITED;
    *rst = 0;
    return 0;
  }
  /* Current address not pushed.. get a new one */
  for (*off = 0; *off < stk->len; (*off)++) {
    if (stk->map[*off] == PENDING) {
      //printf("======== pop : %.8llx %.8x\n", stk->vbase+*off, *off);
      stk->map[*off] |= VISITED;
      *rst = 1;
      return 0;
    }
  }
  return -1;
}

void useStk(section_t *seg, int off, int v, int len)
{
  if (seg)
    _setstk(&seg->stk, off, v, len);
}

/*========================================================================================*
 * Symbols code
 *========================================================================================*/
int nsym;
struct sym *symTbl;

struct sym *findSym(uint32_t addr)
{
  int i;

  for (i=0; i<nsym; i++) {
    if (symTbl[i].addr == addr)
      return &symTbl[i];
  }
  return NULL;
}

struct sym *addSym(uint32_t addr, int flag, void *data, const char *name, ...)
{
  va_list ap;
  char sname[128];
  struct sym *sym;

  if ((sym = findSym(addr)) != NULL) {
    if (!sym->data && data) {
      sym->data = data;
    }
    return sym;
  }
  
  va_start(ap, name);
  vsnprintf(sname, sizeof(sname), name, ap);
  //printf("addsym: %.8lx %s\n", addr, sname);

  symTbl = realloc(symTbl, ++nsym * sizeof(struct sym));
  sym = &symTbl[nsym-1];
  sym->addr = addr;
  sym->data = data;
  sym->flag = flag;
  sym->name = strdup(sname);
  return sym;
}

void rstrip(char *s)
{
  int i;

  i = strlen(s);
  while (--i > 0 && isspace(s[i])) {
    s[i] = 0;
  }
}

void readsym(const char *sname)
{
  char line[128], name[128], *c;
  int addr, flag;
  FILE *fp;
  
  snprintf(line, sizeof(line), "%s.dat", sname);
  if ((fp = fopen(line, "r")) == NULL)
    return;
  while (fgets(line, sizeof(line), fp) != NULL) {
    if ((c = strchr(line, ';')) != NULL) {
      *c = 0;
    }
    rstrip(line);
    if (sscanf(line,"%x:%x:%s", &addr, &flag, name) == 3) {
      addSym(addr, flag, NULL, name);
    }
  }
  fclose(fp);
}

const char *getSymName(section_t *dseg, uint32_t addr)
{
  static char sn[128];
  struct sym *s;
  struct type *t;
  int i;
  
  if (dseg)
    addr += dseg->vaddr;
  s = findSym(addr);
  if (s != NULL) {
    t = findType(s->name);
    if (!t)
      return s->name;
    snprintf(sn, sizeof(sn), "%s %s(",
	     enumToType(t->rtype),
	     s->name);
    for (i = 0; i < t->narg; i++) {
      strcat(sn, i ? ", " : "");
      strcat(sn, enumToType(t->arg[i]));
    }
    strcat(sn, ")");
    return sn;
  }
  return "";
}

static int symcmp(const void *a, const void *b)
{
  const struct sym *sa = a;
  const struct sym *sb = b;

  return (sa->addr - sb->addr);
}

void dumpsym()
{
  int i;
  
  printf("================= Symtab\n");
  qsort(symTbl, nsym, sizeof(struct sym), symcmp);
  for (i = 0; i < nsym; i++) {
    printf("%.8x:%d:%s", symTbl[i].addr, symTbl[i].flag, symTbl[i].name);
    if ((symTbl[i].flag == sSTRING) && symTbl[i].data) {
      printf(" ; %s", symTbl[i].data);
    }
    printf("\n");
  }
}

/*==============================================================*
 * Types code
 *==============================================================*/
#define ARRAYOF(len,type) ((len << 16) | type | ARRAY)
#define STRUCT(len)       ((len << 16) | STRUCT)

struct typemap {
  int id;
  const char *val;
};

static int ntype;
static struct type *types;

static struct typemap tmap[] = {
  { VOID, 	"void" },
  { CHAR, 	"char" },
  { SHORT,	"short" },
  { INT, 	"int" },
  { LONG,	"long" },
  { STRUCT,	"struct" },

  { VOIDPTR,	"void*" },
  { CHARPTR,	"char*" },
  { SHORTPTR,	"short*" },
  { INTPTR,	"int*" },
  { LONGPTR,	"long*" },
  { STRUCTPTR,	"struct*" },

  { CHARARR,	"char[]" },
  { SHORTARR,	"short[]" },
  { INTARR,	"int[]" },
  { LONGARR,	"long[]" },
  { STRUCTARR,	"struct[]" },

  { PRINTFSTR,	"printstr*" },
  { VARARG,     "..." },
  { 0, 0 }
};

int typeToEnum(const char *v)
{
  struct typemap *tm = tmap;

  while (tm->id) {
    if (!strcmp(tm->val, v))
      return tm->id;
    tm++;
  }
  return 0;
}

const char *enumToType(int type)
{
  struct typemap *tm = tmap;

  while (tm->id) {
    if (tm->id == type)
      return tm->val;
    tm++;
  }
  return "none";
}
  
struct type *findType(const char *name)
{
  int i;

  for (i=0; i<ntype; i++) {
    if (!strcmp(name, types[i].name))
      return &types[i];
  }
  return NULL;
}

static void _addtype(int rtype, const char *name, int narg, int *arg)
{
  int tmparg[narg];
  struct type *tt;
  int i;

  memset(tmparg, 0, sizeof(tmparg));
  if (!arg)
    arg = tmparg;
  types = (struct type *)realloc(types, ++ntype * sizeof(struct type));
  tt = &types[ntype-1];

  tt->name = strdup(name);
  tt->rtype = rtype;
  tt->narg = narg;
  tt->arg = (int *)calloc(narg, sizeof(int));
  for (i=0; i<narg; i++) {
    tt->arg[i] = arg[i];
  }
  if (narg == 1 && arg[0] == VOID)
    tt->narg = 0;
}

void addtype(int rtype, const char *name, int narg, ...)
{
  int i, arg[narg];
  struct type *tt;
  va_list ap;

  tt = findType(name);
  if (tt) {
    printf("duplicate: %s\n", name);
    return;
  }
  va_start(ap, narg);
  for (i=0; i<narg; i++) {
    arg[i] = va_arg(ap, int);
  }
  _addtype(rtype, name, narg, arg);
}

void showtype(struct type *tt)
{
  int i;

  if (!tt)
    return;
  printf("%s %s(", enumToType(tt->rtype), tt->name);
  for (i = 0; i < tt->narg; i++) {
    printf("%s%s", i ? ", " : "", enumToType(tt->arg[i]));
  }
  printf(")\n");
}

/*========================================================================================*
 * Basic Block code
 *========================================================================================*/
const char *bbt[] = { "none", "jump", "cond", "call", "fall", "term", "split", "if", "ifret", "while", "dowhile", "for" };

enum {
  WHITE,
  GREY,
  BLACK
};

enum {
  etNONE,
  etTREE = 't',     /* Tree edge: jump */
  etBACK = 'b',     /* Back edge: while/for/do */
  etCROSS = 'x',    /* Cross edge: if-else */
  etFORWARD = 'f',  /* Forward edge: if */
  etNEXT = 'n',     /* Consecutive edge. Fall/Call/JCC */
};

struct bb
{
  int   ifv;
  int   type;
  int   start;
  int   end;
  int   sub;
  int   nInst;
  int   nIn;
  int   nOut;
  int   nifIn;
  int  *edge;
  int  *etype;
  void *data;
  char *lbl;
  int   flags;
  
  /* DFS Visit variable */
  int   color;
  int   p;  /* parent */
  int   u;  /* start time */
  int   v;  /* exit time */

  TAILQ_ENTRY(bb) link;
};

struct ebb
{
  struct ebb *parent;
  struct bb  *bb;
  TAILQ_HEAD(,ebb) child;
  TAILQ_ENTRY(ebb) link;
};

TAILQ_HEAD(,ebb) ebbHead;

struct ebb *addEbb(struct ebb *parent, struct bb *bb)
{
  struct ebb *ne;

  ne = calloc(1, sizeof(*ne));
  ne->bb = bb;
  ne->parent = parent;
  TAILQ_INIT(&ne->child);
  if (parent) {
    TAILQ_INSERT_TAIL(&parent->child, ne, link);
  }
  return ne;
}

void _showbb(struct bb *bb);

int nbb;
struct bb *bbTbl;
TAILQ_HEAD(,bb) bbHead = TAILQ_HEAD_INITIALIZER(bbHead);

struct bb *findbb(int start)
{
  int i;

  for (i = 0; i < nbb; i++) {
    if (start >= bbTbl[i].start && start < bbTbl[i].end && bbTbl[i].type != bbNONE)
      return &bbTbl[i];
  }
  return NULL;
}

void _showbb(struct bb *bb)
{
  struct sym *sym;
  int i;

  if (!bb)
    return;
  printf("%2d:%-6s ninst:%-4d %.8x %.8x sub:%.8x p:%.8x in:%-2d out:%-2d { ",
	 bb->type, bbt[bb->type], bb->nInst, bb->start, bb->end, bb->sub, bb->p,
	 bb->nIn, bb->nOut);
  for (i = 0; i < bb->nOut; i++) {
    printf("%.4x ", bb->edge[i]);
  }
  printf("}\n");
}

void showbb()
{
  int i;

  printf("=================================== showbb\n");
  for (i = 0; i < nbb; i++) {
    _showbb(&bbTbl[i]);
  }
}

void rmBB(struct bb *bb)
{
  bb->type  = bbNONE;
  bb->nOut  = 0;
  bb->nIn   = 0;
  bb->start = 0x7FFFFFFF;
  bb->end   = 0x7FFFFFFF;
}

int _addBB(stack_t *stk, int type, int start, int end, int ninst, void *data, int nOut, int *edge)
{
  struct bb *bb;
  int i;
  
  bbTbl = realloc(bbTbl, ++nbb * sizeof(struct bb));
  bb = &bbTbl[nbb-1];
  bb->type = type;
  bb->start = start;
  bb->end = end;
  bb->nInst = ninst;
  bb->data = data;
  bb->nOut = nOut;
  bb->nIn  = 0;
  bb->nifIn = 0;
  bb->sub  = -1;
  bb->p = -1;
  bb->ifv  = 0;
  bb->flags = 0;
  bb->lbl = NULL;
  bb->edge = calloc(nOut, sizeof(int));
  bb->etype = calloc(nOut, sizeof(int));
  for (i = 0; i < nOut; i++) {
    bb->etype[i] = etNONE;
    bb->edge[i] = edge[i];
    _push(stk, edge[i], "_addBB");
  }
  printf(">>>> ADDBB: %s", ninst == -1 ? "<split>" : "");
  _showbb(bb);
  return type;
}

int addBB(stack_t *stk, int type, int start, int end, int ninst, void *data, int nOut, ...)
{
  struct bb *bb;
  int edge[nOut];
  va_list ap;
  int i, olds;
  
  memset(edge, 0, sizeof(edge));
  va_start(ap, nOut);
  for (i = 0; i < nOut; i++) {
    edge[i] = va_arg(ap, int);
    if (start < edge[i] && edge[i] < end) {
      /* Self-split BB */
      _addBB(stk, bbFALL, start, edge[i], -1, NULL, 1, &edge[i]);
      start = edge[i];
      ninst = -1;
    }
    else if ((bb = findbb(edge[i])) != NULL && bb->start < edge[i]) {
      /* Split existing BB */
      olds = bb->start;
      bb->start = edge[i];
      bb->nInst = -1;
      _addBB(stk, bbFALL, olds, edge[i], -1, NULL, 1, &edge[i]);
      ninst = -1;
    }
  }
  return _addBB(stk, type, start, end, ninst, data, nOut, edge);
}

int NumIN(struct bb *bb, int match)
{
  return (bb && ((bb->nIn-bb->nifIn) == match));
}

int EQ(struct bb *a, struct bb *b)
{
  return (a && a == b);
}

struct bb *NEXT(struct bb *bb)
{
  if (!bb)
    return NULL;
  if (bb->sub != bb->start)
    return findbb(bb->sub);
  return findbb(bb->edge[0]);
}

struct bb *THEN(struct bb *bb)
{
  if (bb && bb->type == bbCOND)
    return findbb(bb->edge[0]);
  return NULL;
}

struct bb *ELSE(struct bb *bb)
{
  if (bb && bb->type == bbCOND)
    return findbb(bb->edge[1]);
  return NULL;
}

int IsTerm(struct bb *bb)
{
  while (bb) {
    switch (bb->type) {
    case bbTERM:
      return 1;
    case bbFALL:
    case bbJUMP:
      bb = findbb(bb->edge[0]);
      break;
    default:
      return 0;
    }
  }
  return 0;
}

int isIf(struct bb *t, struct bb *e, int nt)
{
  return EQ(e, NEXT(t)) && NumIN(t, nt);
}

int isIfElse(struct bb *t, struct bb *e, int nt, int ne)
{
  return EQ(NEXT(t), NEXT(e)) && NumIN(t, nt) && NumIN(e, ne);
}

int ifv;

void mkif(struct bb *bb, struct bb *sub, int nin, char *lbl)
{
  printf("mkif   : %.8x -> %.8x [%s]\n", bb->start, sub->start, lbl);
  bb->type = bbIF;
  bb->lbl = lbl;
  bb->ifv = ifv;
  if (sub) {
    sub->nifIn += nin;
    printf("  mkif:%d %d\n", sub->nifIn, sub->nIn);
    _showbb(sub);
    bb->sub = sub->start;
  }
}

void mkifret(struct bb *bb, struct bb *sub, char *lbl)
{
  printf("mkifret: %.8x -> %.8x [%s]\n", bb->start, sub, lbl);
  bb->type = bbIFRET;
  bb->lbl = lbl;
  bb->sub = sub->start;
  bb->ifv = ifv;
}

void mkwhile(struct bb *bb, struct bb *sub, char *lbl)
{
  bb->type = bbWHILE;
  bb->lbl = lbl;
  bb->ifv = ifv;
  if (sub) {
    bb->sub = sub->start;
  }
}

int IsLoop(struct bb *bb)
{
  struct bb *nxt;
  
  /* Cases:
   *  fall -> xxx... -> cmp -> nxt  do-while
   *           ^---b-----v
   *
   *   v-----b-------^
   *  cmp -> ... -> jump  nxt    while
   *   v-------------------^
   *
   *   ^--f-----d-----------v
   *  cmp -> ... -> cmp -> nxt  for..
   *          ^--b---v
   *
   *   v--b---------------^
   *  fall -> ... -> fall -> cmp -> ... -> cmp -> nxt   
   *              ^-------------------------v
   *
   *  fall -> ... -> cmp -> ... -> cmp -> nxt -> ... -> zzz
   *                
   */
  if (!bb->nOut || bb->type == bbTERM)
    return 0;
  nxt = findbb(bb->edge[0]);
  if (bb->type == bbFALL && (nxt->flags & 0x1000)) {
    printf("A:possible do-while: %.8x\n", nxt->start);
  }
  if (bb->type == bbCOND) {
    if ((bb->flags & 0x1000) && bb->etype[1] == etTREE) {
      printf("B:possible while: %.8x\n", bb->start);
    }
    else if ((nxt->flags & 0x1000) && bb->etype[1] == etFORWARD) {
      printf("C:possible for: %.8x\n", bb->start);
    }
  }
  return 0;
}

/* Check basic blocks for:
 *  if (x)      { a }
 *  if (x)      { a } else { b }
 *  if (x)      { return; }
 *  if (x && y) { a }
 *  if (x || y) { a }
 */
int checkLoop(struct bb *bb, int verb)
{
  if (!(bb->flags & 0x1000))
    return 0;
}

int checkIf(struct bb *bb, int verb)
{
  struct bb *t, *e, *tt, *te, *et, *ee, *ne, *nt;

  //IsLoop(bb);
  if (bb->flags & 0x1000) {
    /* Target of Back-edge */
    if (bb->edge[1] == bb->start) {
      /* Self-loop */
    }
  }
  if (bb->type != bbCOND) {
    return 0;
  }
  t = THEN(bb);
  nt = NEXT(t);
  tt = THEN(t); /* if then-block is a conditional */
  te = ELSE(t);

  e = ELSE(bb);
  ne = NEXT(e);
  et = THEN(e); /* if else-block is a conditional */
  ee = ELSE(e);

  if (!t || !e) {
    printf("missing edge from: %.8x\n", bb->start);
    return 0;
  }
  printf("--------------- ckif : %.8x\n", bb->start);
  _showbb(bb);
  _showbb(t);
  _showbb(e);
  _showbb(nt);
  _showbb(ne);
  if (bb->start == 0x163f ||bb->start == 0x28da || bb->start == 0x312e) {
    printf("aha\n");
  }

  /*While Loops */
  if (EQ(e, bb)) {
    bb->flags |= 0x1000;
    mkwhile(bb, t, "do-while");
    return 1;
  }

  if (isIf(e, t, 1)) {
    printf("%.8x if(c) {a}\n", bb->start);
    mkif(bb, t, 2, "if:X");
    return 1;
  }
  if (isIf(t, e, 1)) {
    printf("%.8x if(!c) {a}\n", bb->start);
    mkif(bb, e, 2, "if:!X");
    return 1;
  }
  if (isIfElse(t, e, 1, 1)) {
    printf("%.8x if(c) {b} else {a}:\n", bb->start);
    mkif(bb, nt, 2, "if-else");
    return 1;
  }
  if (isIfElse(tt, te, 1, 2) && EQ(te, e) && NumIN(t, 1)) {
    printf("%.8x if (c||d) {b} else {a}\n");
    mkif(bb, ne, 2, "if-else:c||d");
    t->flags |= 0x2000;
    return 1;
  }
#if 0
  if (EQ(t,et) && EQ(nt, ee) && NumIN(t, 2) && NumIN(e, 1)) {
    mkif(bb, nt, "ifgrp:!X||!Y");
    return 1;
  }
  if (EQ(t,ee) && EQ(nt, et) && NumIN(t, 2) && NumIN(e, 1)) {
    mkif(bb, nt, "ifgrp:!X||Y");
    return 1;
  }
  if (EQ(e,tt) && EQ(ne,te) && NumIN(t, 1) && NumIN(e, 2)) {
    /* HAZ */
    t->flags |= 0x2000;
    mkif(bb, ne, "ifgrp:X||!Y");
    return 1;
  }
  if (EQ(e,te) && EQ(ne,tt) && NumIN(t,1) && NumIN(e,2)) {
    mkif(bb, ne, "ifgrp:X||Y");
    return 1;
  }
  if (EQ(t, et) && EQ(et, NEXT(ee)) && NumIN(e, 1) && NumIN(ee, 1)) {
    mkif(bb, t, "ifgrp:X&&Y");
    return 1;
  }
  if (EQ(t, ee) && EQ(ee, NEXT(et)) && NumIN(e, 1) && NumIN(et, 1)) {
    mkif(bb, t, "ifgrp:X&&!Y");
    return 1;
  }
  if (EQ(e, tt) && EQ(tt, NEXT(te)) && NumIN(t, 1) && NumIN(te, 1)) {
    mkif(bb, e, "ifgrp:!X&&Y");
    return 1;
  }
  if (EQ(e, te) && EQ(te, NEXT(tt)) && NumIN(t, 1) && NumIN(tt, 1)) {
    /* HAZ */
    mkif(bb, e, "ifgrp:!X&&!Y");
    return 1;
  }
  if (NumIN(t, 1) && NumIN(e, 1) && EQ(nt, ne)) {
    mkif(bb, nt, "if-else");
    return 1;
  }
  if (EQ(nt, e) && NumIN(t, 1)) {
    mkif(bb, e, "if:!X");
    return 1;
  }
  if (EQ(ne, t) && NumIN(e, 1) && !EQ(t, bb)) {
    mkif(bb, t, "if:X");
    return 1;
  }
  if (isIf(t, e, 1)) {
    mkif(bb, e, "if:!X");
    return 1;
  }
  if (isIf(e, t, 1)) {
    mkif(bb, t, "if:X");
    return 1;
  }
  if (isIfElse(t, e, 1, 1)) {
    mkif(bb, nt, "if-else");
    return 1;
  }
#endif
  if (IsTerm(t)) {
    mkifret(bb, e, "ifret:X"); 
    return 1;
  }
  if (IsTerm(e)) {
    mkifret(bb, t, "ifret:!X");
    return 1;
  }
  return 0;
}

int checkIfs(int verb)
{
  int nif, i;

  nif = 0;
  for (i = 0; i < nbb; i++) {
    if (checkIf(&bbTbl[i], verb))
      nif++;
  }
  printf("mkif:reduced %d\n", nif);
  return nif;
}

void dfsInit()
{
  int i;
  
  for (i = 0; i < nbb; i++)
    bbTbl[i].color = WHITE;
}

int walkback(struct bb *s, struct bb *e)
{
  printf("Walkback: %.8x[%s:%s] -> %.8x\n",
	 s->start, bbt[s->type], bbt[e->type],
	 e->start);
  while (s != e) {
    _showbb(s);
    s = findbb(s->p);
  }
  printf("--- done\n");
  return 1;
}

void dfsVisit(struct bb *bb)
{
  static int dfsTime;
  struct bb *e;
  int i;

  if (!bb || bb->color != WHITE)
    return;
  bb->u = ++dfsTime;
  bb->color = GREY;
  bb->sub = bb->start;
  for (i = 0; i < bb->nOut; i++) {
    e = findbb(bb->edge[i]);
    if (!e) {
      /* No edge! */
      printf("NOBB %.8x %.8x\n", bb->start, bb->edge[i]);
    } else {
      if (e->color == GREY) {
	/* back edge */
	e->flags |= 0x1000;
	bb->etype[i] = etBACK;
	//walkback(bb, e);
      }
      else if (e->color == BLACK) {
	/* cross or forward */
	bb->etype[i]= (bb->u < e->u) ? etFORWARD : etCROSS;
      }
      else {
	/* unvisited.. call recursively */
	bb->etype[i] = (e->start == bb->end) ?
	  etNEXT : etTREE;
	e->p = bb->start;
	dfsVisit(e);
      }
      e->nIn++;
    }
  }
  bb->v = ++dfsTime;
  bb->color = BLACK;
}

/* Compare operator for qsort */
int bbcmp(const void *a, const void *b)
{
  const struct bb *bba = a;
  const struct bb *bbb = b;

  return (bba->start - bbb->start);
}

void mergejmp(struct bb *bb, int *oe, int *ot)
{
  struct bb *e, *f;

  while ((e = findbb(*oe)) != NULL) {
    if (e->type != bbJUMP || e->nInst != 1 || e->nOut != 1)
      break;
    f = findbb(e->edge[0]);
    printf("merge jmp: %.8x[%s] %c:-> %.8x[%s] %c:-> %.8x[%s]\n",
	   bb->start, bbt[bb->type], bb->etype[0],
	   e->start, bbt[e->type], e->etype[0],
	   e->edge[0], f ? bbt[f->type] : "<bad>");
    *oe = e->edge[0];
    *ot = e->etype[0];
    if (*ot == etNEXT)
      *ot = etTREE;
    if (--e->nIn == 0) {
      /* Remove this BB */
      rmBB(e);
    }
  }
}

/* Merge consecutive blocks with single entry/exit
 *   call
 *   call
 *   ...
 *   cond
 */
void mergenxt(struct bb *bb)
{
  struct bb *e;

  while (bb->nOut == 1) {
    e = findbb(bb->edge[0]);
    if (e == bb) {
      printf("%.8x Self-loop!\n", bb->start);
      bb->flags |= 0x1000;
    }
    if (!e || e->nIn != 1 || bb->end != e->start || e->type == bbJUMP)
      return;
    printf("merge nxt: %.8x[%s.%d.%d] -> %.8x[%s.%d.%d]\n",
	   bb->start, bbt[bb->type], bb->nIn, bb->nOut,
	   e->start, bbt[e->type], e->nIn, e->nOut);
    e->nIn = bb->nIn;
    e->start = bb->start;
    e->sub = bb->start;
    rmBB(bb);
    bb = e;
  }
}

/*==========================*
 *  s...e|s...e|s..e => bb0=none,bb1=none,bb2=s0..e2
 *=========================*/

/* Set number of instructions for a basic block (for split blocks) */
void setInst(struct bb *bb, struct imap *imap)
{
  struct imap *ci, *end;
  
  if (bb->nInst != -1)
    return;
  bb->nInst = 0;
  ci  = &imap[bb->start];
  end = &imap[bb->end];
  printf("Enter Ninst: %.8x ", bb->start);
  while (ci < end) {
    ci = nxt(ci, 1);
    bb->nInst++;
  }
  printf("%.8x [%s] Set Ninst: %d\n", bb->start, bbt[bb->type], bb->nInst);
}

void mergebb(struct imap *imap)
{
  struct bb *bb, *e;
  struct imap *ci;
  int i, j, nif;

  /* Sort basic blocks by start address */
  qsort(bbTbl, nbb, sizeof(struct bb), bbcmp);

  /* DFS visit blocks to create control flow graph */
  printf("============== Analyze CFG\n");
  dfsInit();
  for (i = 0;  i < nbb; i++) {
    //setInst(&bbTbl[i], imap);
    dfsVisit(&bbTbl[i]);
  }
  showbb();
  printf("-- pre merge\n");
  for (i = 0; i < nbb; i++) {
    /* Merge redundant jmp -> jmp -> x statements */
    bb = &bbTbl[i];
    for (j = 0; j < bb->nOut; j++) {
      mergejmp(bb, &bb->edge[j], &bb->etype[j]);
    }
    /* Merge consecutive simple blocks */
    mergenxt(bb);
  }
  printf("------ Post merge\n");
  qsort(bbTbl, nbb, sizeof(struct bb), bbcmp);
  showbb();
#if 1
  ifv = 1;
  while (checkIfs(0))
    ifv++;
#endif
}

int invalbb(struct bb *bb)
{
  //return (!bb || bb->type == bbNONE || bb->start < 0x1c02 || bb->start > 0x2b0a);
  //return (!bb || bb->type == bbNONE || bb->start < 0x1430);
  return (!bb || bb->type == bbNONE);
}

const char *hlistr(struct imap *ci)
{
  static char hli[1024];
  struct imap *ni;
  
  if (!ci->opc || ci->hli)
    return NULL;
  ni = nxt(ci,1);
  if (opeq(ci, "mov", 0, 0, 0) && isMem(ci->opc->args[0]) && isImm(ci->opc->args[1])) {
    snprintf(hli, sizeof(hli), "%s = %s;", ota1(ci), ota2(ci));
    return hli;
  }
  if (opeq(ci, "mov", rAX, 0, 0) && opeq(ni, "mov", 0, rAX, 0)) {
    snprintf(hli, sizeof(hli), "%s = %s;", ota1(ni), ota2(ci));
    ni->hli = 1;
    return hli;
  }
  if (opeq(ci, "mov", rEAX, 0, 0) && opeq(ni, "mov", 0, rEAX, 0)) {
    snprintf(hli, sizeof(hli), "%s = %s;", ota1(ni), ota2(ci));
    ni->hli = 1;
    return hli;
  }
  return NULL;
}

void genvcg(struct imap *imap)
{
  struct sym *sym;
  struct bb *bb, *t, *e;
  const char *shp, *clr, *hs;
  char line[40000], l2[1024];
  int i, j;

  for (i = 0; i < nbb; i++) {
    bb = &bbTbl[i];
    if (invalbb(bb))
      continue;
    sym = findSym(bb->start + _vbase);
    if (sym != NULL) {
      writevcg("node: { title:\"fn%x\" label:\"%s\" color:blue }\n",
	       bb->start, sym->name);
      writevcg("edge: { sourcename:\"fn%x\" targetname:\"%x\" }\n",
	       bb->start, bb->start);
    }
    shp = "";
    clr = "";
    switch (bb->type) {
    case bbTERM:
      clr = "color:lightblue";
      break;
    case bbCOND:
      clr = "color:yellow";
      if (bb->etype[1] == etBACK)
	clr = "color:lightred";
      break;
    case bbCALL:
      clr = "color:orange";
      break;
    case bbFALL:
      clr = "color:lightgrey";
      break;
    case bbJUMP:
      clr = "color:magenta";
      break;
    case bbIF:
      clr = "color:green";
      break;
    case bbIFRET:
      clr = "color:yellowgreen";
      break;
    }
    /* Back edge target */
    if (bb->flags & 0x1000) {
      clr = "color:khaki";
      //bb->lbl = "while";
    }
    if (bb->flags & 0x2000) {
      clr = "color:lightgreen";
    }
    if (!bb->lbl)
      bb->lbl = bbt[bb->type];
    snprintf(line, sizeof(line), "%.8x [%d] sub:%.8x p:%.8x ifin:%d %s",
	     bb->start, bb->ifv, bb->sub, bb->p, bb->nIn - bb->nifIn,
	     bb->lbl);
    for (j = bb->start; j < bb->end; j++) {
      hs = hlistr(&imap[j]);
      if (hs != NULL) {
	snprintf(l2, sizeof(l2), "\n%s", hs);
	strcat(line, l2);
      }
#if 1
      if (imap[j].opc) {
	snprintf(l2, sizeof(l2), "\n%s %s %s ",
		 imap[j].opc->mnem,
		 ota1(&imap[j]),
		 ota2(&imap[j]));
	strcat(line, l2);
      }
#endif
    }
    writevcg("node: { title:\"%x\" label:\"%s\" %s %s }\n",
	     bb->start, line, clr, shp);
  }
  for (i = 0; i < nbb; i++) {
    bb = &bbTbl[i];
    if (invalbb(bb))
      continue;
    for (j = 0; j < bb->nOut; j++) {
      writevcg("edge: { sourcename:\"%x\" targetname:\"%x\" label:\"%d:%c\" }\n",
	       bb->start, bb->edge[j], j, bb->etype[j]);
    }
  }
}

void cpuinit(struct cpu *cpu, uint8_t *pc, int mode)
{
  cpu->pc   = pc;
  cpu->mode = mode;
  cpu->nb   = 0;
  cpu->flag = 0;
  cpu->rex  = 0;
  cpu->mrr  = 0;
  cpu->sib  = 0;
  cpu->immv = 0;
  cpu->offv = 0;
  cpu->seg  = 0;
}

int tblIdx(uint8_t *pc, int flag)
{
  int mask  = tMASK(flag);
  int shift = tBIT(flag);

  assert(mask <= 0xFF);
  return (_get8(pc + tBYTE(flag)) >> shift) & mask;
}

/*================================================================*
 * X86
 *================================================================*/

#define FLAG_EMU   0x2000

#define FLAG_MRR   0x01
#define FLAG_PFX   0x02
#define FLAG_VSZ   0x04

#define f00    0x00
#define f66    0x01
#define fOSZ   0x01  /* f66 */
#define fF2    0x02
#define fF3    0x04

#define fASZ   0x10
#define fLOCK  0x20

/* mm.ggg = 32 fpu
 * 00 xxx iii
 * 01 xxx iii
 * 10 xxx iii
 * 11 xxx yyy
 */
#define __(op, Args...)   { .mnem=#op, .args = { Args } }
#define _x(op, Args...)   { .mnem=#op, .llop=x86_##op, .args = { Args } }
#define _p(Args...)       { .flag=FLAG_PFX, .mnem="PFX", .args = { Args } }
#define _m(op, Args...)   { .flag=FLAG_MRR, .mnem=#op, .llop=x86_##op, .args = { Args } }
#define _v(op, Args...)   { .flag=FLAG_VSZ, .mnem=#op, .llop=x86_##op, .args = { Args }  }
#define TM(op, Args...)   { .flag=mkTBL(3,0x7)|FLAG_MRR, .tbl=op, .mnem=#op, .args = { Args } } /* opcode=ggg */
#define t0(op, Args...)   { .flag=mkTBL(6,0x3)|FLAG_MRR, .tbl=op, .mnem=#op }
#define t1(op, Args...)   { .flag=mkTBL(3,0x7), .tbl=op, .mnem=#op } /* opcode=ggg */
#define hi(op)            { .flag=mkTBL(8,0xFF), .tbl=op, .mnem=#op}

/* SSE TABLE:
 * 00 = 000
 * 66 = 001
 * F2 = 010
 * F3 = 100
 */
struct opcode pF29[8] = {
  [f00] = _m(movaps, Vx, Vx),
  [f66] = _m(movapd, Vx, Vx),
};
struct opcode pF50[8] = {
  [f00] = _m(movmskps, Vx),
  [f66] = _m(movmskpd, Vx),
};
struct opcode pF51[8] = {
  [f00] = _m(sqrtps, Vx),
  [fF3] = _m(sqrtss, Vx),
  [f66] = _m(sqrtpd, Vx),
  [fF2] = _m(sqrtsd, Vx),
};
struct opcode pF61[8] = {
  [f00] = _m(punpcklwd, Vx),
  [f66] = _m(punpcklwd, Vx),
};

struct opcode GRP1[8] = {
  _x(add), _x(or), _x(adc), _x(sbb), _x(and), _x(sub), _x(xor), _x(cmp)
};

struct opcode GRP2[8] = {
  _x(rol), _x(ror), _x(rcl), _x(rcr), _x(shl), _x(shr), _x(sal), _x(sar),
};

struct opcode GRP3b[8] = {
  _x(test,Eb,Ib), _x(test,Eb,Ib), _x(not,Eb), _x(neg,Eb), _x(mul,Eb),_x(imul,Eb),_x(div,Eb),_x(idiv,Eb)
};
struct opcode GRP3v[8] = {
  _x(test,Ev,Iv), _x(test,Ev,Iv), _x(not,Ev), _x(neg,Ev), _x(mul,Ev),_x(imul,Ev),_x(div,Ev),_x(idiv,Ev)
};
struct opcode GRP4[8] = {
  _x(inc,Eb),_x(dec,Eb)
};
struct opcode GRP5[8] = {
  _x(inc,Ev),_x(dec,Ev),_x(call,Ev),_x(call,Mp),_v(jmp,Ev),_x(jmp,Mp),_x(push,Ev),
};
struct opcode GRP7[8] = {
  __(sgdt,Mp),__(sidt,Mp),__(lgdt,Mp),__(lidt,Mp),__(smsw,Mw),__(f015),__(lmsw,Mw),
};

/*====================
 * FPU instructions
 *====================*/
struct opcode fpuD8_012[8] = {
  __(fadd), __(fmul), __(fcom), __(fcomp), __(fsub), __(fsubr), __(fdiv), __(fdivr),
};
struct opcode fpuD9_012[8] = {
  __(fld), [2]= __(fst), [3]=__(fstp), [4]=__(fldenv), [5]=__(fldcw), [6]=__(fstenv), [7]=__(fstcw),
};
struct opcode fpuDA_012[8] = {
  __(fiadd), __(fimul), __(ficom), __(ficomp), __(fisub), __(fisubr), __(fidiv), __(fidivr)
};
struct opcode fpuDB_012[8] = {
  __(fild), [2]=__(fist), [3]=__(fistp), [5]=__(fld), [7]=__(fstp),
};
struct opcode fpuDC_012[8] = {
  __(fadd), __(fmul), __(fcom), __(fcomp), __(fsub), __(fsubr), __(fdiv), __(fdivr),
};
struct opcode fpuDD_012[8] = {
  __(fld), [2]= __(fst), [3]=__(fstp), [4]=__(frstor), [6]=__(fsave), [7]=__(fstsw),
};
struct opcode fpuDE_012[8] = {
  __(fiadd), __(fimul), __(ficom), __(ficomp), __(fisub), __(fisubr), __(fidiv), __(fidivr),
};
struct opcode fpuDF_012[8] = {
  __(fild), [2]=__(fist), [3]=__(fistp), [4]=__(fbld),[5]=__(fild), [6]=__(fbstp),[7]=__(fstp),
};

#define fpuD8_3 fpuD8_012
#define fpuD9_3 fpuD8_012
#define fpuDA_3 fpuD8_012
#define fpuDB_3 fpuD8_012
#define fpuDC_3 fpuD8_012
#define fpuDD_3 fpuD8_012
#define fpuDE_3 fpuD8_012
#define fpuDF_3 fpuD8_012

struct opcode fpuD8[4] = {
  t1(fpuD8_012),
  t1(fpuD8_012),
  t1(fpuD8_012),
  t1(fpuD8_3), /* c0,c8,d0,d8,e0,e8,f0,f8 */
};
struct opcode fpuD9[4] = {
  t1(fpuD9_012),
  t1(fpuD9_012),
  t1(fpuD9_012),
  t1(fpuD9_3),
};
struct opcode fpuDA[4] = {
  t1(fpuDA_012),
  t1(fpuDA_012),
  t1(fpuDA_012),
  t1(fpuDA_3),
};
struct opcode fpuDB[4] = {
  t1(fpuDB_012),
  t1(fpuDB_012),
  t1(fpuDB_012),
  t1(fpuDB_3),
};
struct opcode fpuDC[4] = {
  t1(fpuDC_012),
  t1(fpuDC_012),
  t1(fpuDC_012),
  t1(fpuDC_3),
};
struct opcode fpuDD[4] = {
  t1(fpuDD_012),
  t1(fpuDD_012),
  t1(fpuDD_012),
  t1(fpuDD_3),
};
struct opcode fpuDE[4] = {
  t1(fpuDE_012),
  t1(fpuDE_012),
  t1(fpuDE_012),
  t1(fpuDE_3),
};
struct opcode fpuDF[4] = {
  t1(fpuDF_012),
  t1(fpuDF_012),
  t1(fpuDF_012),
  t1(fpuDF_3),
};

struct opcode himap[256] = {
  __(f00), TM(GRP7), _m(lar,Gw,Ew), _m(lsl,Gv,Ew), __(f04), __(f05), __(clts), __(f07),
  __(invd), __(wbinvd), __(f0a), __(ud1), __(f0c), __(f0d), __(f0e), __(f0f),
  __(f10), __(f11), __(f12), __(f13), __(f14), __(f15), __(f16), __(f17),
  __(f18), __(f19), __(f1a), __(f1b), __(f1c), __(f1d), __(f1e), _m(nop, Ev),

  [0x20] =
  _m(mov, Gv, Cv), _m(mov, Gv, Dv), _m(mov, Cv, Gv), _m(mov, Dv, Gv),

  [0x28] =
  _m(movaps,Vx,Vx),_m(movaps,Vx,Vx),

  [0x40] =
  _m(cmovo, Gv,Ev),_m(cmovno,Gv,Ev),_m(cmovb, Gv,Ev),_m(cmovae,Gv,Ev),_m(cmove,Gv,Ev),_m(cmovne,Gv,Ev),_m(cmovbe,Gv,Ev),_m(cmova, Gv,Ev), 
  _m(cmovs, Gv,Ev),_m(cmovns,Gv,Ev),_m(cmovpe,Gv,Ev),_m(cmovpo,Gv,Ev),_m(cmovl,Gv,Ev),_m(cmovge,Gv,Ev),_m(cmovle,Gv,Ev),_m(cmovg, Gv,Ev), 

  [0x61] =
  _m(punpcklwd),
  
  [0x80] =
  _x(jo,  Jz), _x(jno, Jz), _x(jb,  Jz), _x(jae, Jz), _x(je, Jz), _x(jne, Jz), _x(jbe, Jz), _x(ja, Jz), 
  _x(js,  Jz), _x(jns, Jz), _x(jpe, Jz), _x(jpo, Jz), _x(jl, Jz), _x(jge, Jz), _x(jle, Jz), _x(jg, Jz), 

  [0x90] =
  _m(seto, Eb), _m(setno,Eb), _m(setb, Eb), _m(setae,Eb), _m(sete,Eb), _m(setne,Eb), _m(setbe,Eb), _m(seta, Eb), 
  _m(sets, Eb), _m(setns,Eb), _m(setpe,Eb), _m(setpo,Eb), _m(setl,Eb), _m(setge,Eb), _m(setle,Eb), _m(setg, Eb), 

  [0xa0] =
  _x(push,rFS),_x(pop,rFS),__(0),__(0),__(0),__(0),__(0),__(0),
  _x(push,rGS),_x(pop,rGS),__(0),__(0),__(0),__(0),__(0),__(0),
  
  [0xb0] =
  _m(cmpxchg, Eb, rAL), _m(cmpxchg, Ev, rvAX), _m(lss, Gv, Mp), _m(btr, Ev, Gv), _m(lfs, Gv, Mp), _m(lgs, Gv, Mp), _m(movzx, Gv, Eb), _m(movzx, Gv,Ew),
  __(0),__(0),__(0),__(0),__(0),__(0),_m(movsx,Gv,Eb), _m(movsx,Gv,Ew),

  /* D0: sse 
   * E0: see
   * F0: sse
   */
};

struct opcode opmap[] = {
  _m(add, Eb,Gb),  _m(add, Ev,Gv),  _m(add, Gb,Eb),  _m(add, Gv,Ev),  _x(add, rAL,Ib),  _x(add, rvAX,Iz),  _x(push, rES),  _x(pop, rES),
  _m(or,  Eb,Gb),  _m(or,  Ev,Gv),  _m(or,  Gb,Eb),  _m(or,  Gv,Ev),  _x(or,  rAL,Ib),  _x(or,  rvAX,Iz),  _x(push, rCS),  hi(himap),
  _m(adc, Eb,Gb),  _m(adc, Ev,Gv),  _m(adc, Gb,Eb),  _m(adc, Gv,Ev),  _x(adc, rAL,Ib),  _x(adc, rvAX,Iz),  _x(push, rSS),  _x(pop, rSS),
  _m(sbb, Eb,Gb),  _m(sbb, Ev,Gv),  _m(sbb, Gb,Eb),  _m(sbb, Gv,Ev),  _x(sbb, rAL,Ib),  _x(sbb, rvAX,Iz),  _x(push, rDS),  _x(pop, rDS),

  /* 0x20 */
  _m(and, Eb,Gb),  _m(and, Ev,Gv),  _m(and, Gb,Eb),  _m(and, Gv,Ev),  _x(and, rAL,Ib),  _x(and, rvAX,Iz),  _p(rES),        _x(daa),
  _m(sub, Eb,Gb),  _m(sub, Ev,Gv),  _m(sub, Gb,Eb),  _m(sub, Gv,Ev),  _x(sub, rAL,Ib),  _x(sub, rvAX,Iz),  _p(rCS),        _x(das),
  _m(xor, Eb,Gb),  _m(xor, Ev,Gv),  _m(xor, Gb,Eb),  _m(xor, Gv,Ev),  _x(xor, rAL,Ib),  _x(xor, rvAX,Iz),  _p(rDS),        _x(aaa),
  _m(cmp, Eb,Gb),  _m(cmp, Ev,Gv),  _m(cmp, Gb,Eb),  _m(cmp, Gv,Ev),  _x(cmp, rAL,Ib),  _x(cmp, rvAX,Iz),  _p(rSS),        _x(aas),

  /* 0x40 */
  _x(inc,  gv),    _x(inc,  gv),    _x(inc,  gv),    _x(inc,  gv),    _x(inc,  gv),     _x(inc,  gv),      _x(inc,  gv),   _x(inc,  gv),
  _x(dec,  gv),    _x(dec,  gv),    _x(dec,  gv),    _x(dec,  gv),    _x(dec,  gv),     _x(dec,  gv),      _x(dec,  gv),   _x(dec,  gv),
  _v(push, gv),    _v(push, gv),    _v(push, gv),    _v(push, gv),    _v(push, gv),     _v(push, gv),      _v(push, gv),   _v(push, gv),
  _v(pop,  gv),    _v(pop,  gv),    _v(pop,  gv),    _v(pop,  gv),    _v(pop,  gv),     _v(pop,  gv),      _v(pop,  gv),   _v(pop,  gv),

  /* 0x60 */
  _x(pusha),       _x(popa),        __(0),           _m(movsq,Ev,Gv),     _p(rFS),        _p(rGS),        _p(fOSZ),        _p(fASZ),
  _x(push, Iz),    _m(imul, Gv,Ev,Iz),_x(push,Ib),   _m(imul, Gb,Eb,Ib),  _x(insb,Yb,rDX),_x(insv,Yz,rDX),_x(outsb,rDX,Xb),_x(outsv,rDX,Xz),
  _x(jo,  Jb),     _x(jno, Jb),     _x(jb,  Jb),     _x(jae, Jb),         _x(je, Jb),     _x(jne, Jb),    _x(jbe, Jb),     _x(ja,  Jb),
  _x(js,  Jb),     _x(jns, Jb),     _x(jpe, Jb),     _x(jpo, Jb),         _x(jl, Jb),     _x(jge, Jb),    _x(jle, Jb),     _x(jg,  Jb),

  /* 0x80 */
  TM(GRP1, Eb,Ib), TM(GRP1, Ev,Iz),   TM(GRP1, Eb,Ib),   TM(GRP1, Ev,Ib),   _m(test, Eb,Gb),  _m(test, Ev,Gv),  _m(xchg, Eb,Gb),  _m(xchg, Ev,Gv),
  _m(mov,  Eb,Gb), _m(mov,  Ev,Gv),   _m(mov,  Gb,Eb),   _m(mov,  Gv,Ev),   _m(mov,  Ew,Sw),  _m(lea,  Gv,Ev),  _m(mov,  Sw,Ew),  _m(pop,  Ev),
  _x(nop),         _x(xchg, rvAX,gv), _x(xchg, rvAX,gv), _x(xchg, rvAX,gv), _x(xchg, rvAX,gv),_x(xchg, rvAX,gv),_x(xchg, rvAX,gv),_x(xchg, rvAX,gv),
  _x(cbw),         _x(cwd),           _x(call, Ap),      _x(wait),          _x(pushf),        _x(popf),         _x(sahf),         _x(lahf),

  /* 0xa0 */
  _x(mov,  rAL,Ob),  _x(mov,  rvAX,Ov),  _x(mov,  Ob,rAL),  _x(mov, Ov,rvAX),  _x(movsb,Yb,Xb), _x(movsv,Yv,Xv),  _x(cmpsb,Yb,Xb), _x(cmpsv,Yb,Xb),
  _x(test, rAL,Ib),  _x(test, rvAX,Iz),  _x(stosb,Yb,rAL),  _x(stosv,Yv,rvAX), _x(lodsb,rAL,Xb),_x(lodsv,rvAX,Xv),_x(scasb,Yb,rAL),_x(scasv,Yv,rvAX),
  _x(mov,  gb,Ib),   _x(mov,  gb,Ib),    _x(mov,  gb,Ib),   _x(mov,  gb,Ib),   _x(mov,  gb,Ib), _x(mov,  gb,Ib),  _x(mov,  gb,Ib), _x(mov,  gb,Ib),
  _x(mov,  gv,Iv),   _x(mov,  gv,Iv),    _x(mov,  gv,Iv),   _x(mov,  gv,Iv),   _x(mov,  gv,Iv), _x(mov,  gv,Iv),  _x(mov,  gv,Iv), _x(mov,  gv,Iv),

  /* 0xc0 */
  TM(GRP2, Eb,Ib),  TM(GRP2, Ev,Ib),   _v(ret,Iw),        _v(ret),           _m(les, Gv, Mp),  _m(lds, Gv, Mp), _m(mov, Eb,Ib),   _m(mov,  Ev,Iz),
  _v(enter,Iw,Ib),  _v(leave),         _v(retf,Iw),       _v(retf),          _x(int, i3),      _x(int,Ib),      _x(into),         _x(iret),
  TM(GRP2, Eb,i1),  TM(GRP2, Ev,i1),   TM(GRP2,Eb,rCL),   TM(GRP2,Ev,rCL),   _x(aam, Ib),      _x(aad,Ib),      _x(salc),         _x(xlat),
  t0(fpuD8),        t0(fpuD9),         t0(fpuDA),         t0(fpuDB),         t0(fpuDC),        t0(fpuDD),       t0(fpuDE),        t0(fpuDF),

  /* 0xe0 */
  _v(loopnz, Jb),    _v(loopz,Jb),       _v(loop,Jb),       _v(jcxz,Jb),       _x(in, rAL,Ib),    _x(in,rzAX,Ib),   _x(out,Ib,rAL),  _x(out,Ib, rzAX),
  _v(call,Jz),       _v(jmp,  Jz),       _x(jmp, Ap),       _x(jmp,Jb),        _x(in, rAL,rDX),   _x(in,rzAX,rDX),  _x(out,rDX,rAL), _x(out,rDX,rzAX),
  _p(fLOCK),         __(0),              _p(fF2),           _p(fF3),           _x(hlt),           _x(cmc),          TM(GRP3b),       TM(GRP3v),
  _x(clc),           _x(stc),            _x(cli),           _x(sti),           _x(cld),           _x(std),          TM(GRP4),        TM(GRP5),
};

/*=========================================================================*
 * CR16 disassembly 
 *=========================================================================*/
enum {
  CRBASE = 0x200,
  
  r0,   // ? oooo.oooo.----.rrrr
  r1,   // ? oooo.oooo.rrrr.----

  d0,   // 1 oooo.oooo.----.BBBB
  d4,   // 1 oooo.dddd.----.BBBB
  d14,  // 2 oooo.oooo.oodd.BBBB dddd.dddd.----.dddd
  d16,  // 2 oooo.oooo.----.BBBB dddd.dddd.dddd.dddd
  d20,  // 3 0000.0000.0001.oooo oooo.dddd.----.BBBB dddd.dddd.dddd.dddd
  md20, // 3 0000.0000.0001.oooo oooo.dddd.----.BBBB dddd.dddd.dddd.dddd
  
  a20,  // 2 oooo.oooo.----.dddd dddd.dddd.dddd.dddd
  a20r4,// 2 oooo.oooB.----.dddd.dddd.dddd.dddd.dddd
  a20r3,// 2 oooo.oooo.B---.dddd.dddd.dddd.dddd.dddd
  a24,  // 3 0000.0000.oooo.oooo.oooo dddd.----.dddd dddd.dddd.dddd.dddd
  
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

  r12 = TYPE_REG+12,
  r13 = TYPE_REG+13,
};

#undef t
#define xx(m,a...)      { .mnem=#m, .args = { a } }
#define b(m,a...)       { .flag=SIZE_BYTE,  .mnem=#m "b", .args = { a } }
#define w(m,a...)       { .flag=SIZE_WORD,  .mnem=#m "w", .args = { a } }
#define d(m,a...)       { .flag=SIZE_HWORD, .mnem=#m "d", .args = { a } }
#define jd(m,a...)      { .flag=SIZE_HWORD, .mnem=#m, .args = { a } }
#define t(t,s,m,a...)   { .mnem=#t, .tbl=t, .args = { a }, .flag = mkTBL(s,m) }

/* Special F flag */
#define fFF (1L << 1)
#define rFF TYPE_CPUFLAG+SIZE_BYTE+fFF

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
  xx(beq,j8), // ==   (Z=1)
  xx(bne,j8), // !=   (Z=0)
  xx(bcs,j8), //      (C=1)
  xx(bcc,j8), //      (C=0)
  xx(bhi,j8), // >.u  (L=1)
  xx(bls,j8), // <=.u (L=0)
  xx(bgt,j8), // >.s  (N=1)
  xx(ble,j8), // <=.s (N=0)
  xx(bfs,j8), //      (F=1)
  xx(bfc,j8), //      (F=0)
  xx(blo,j8), // <.u  (Z|L=0)
  xx(bhs,j8), // >=.u (Z|L=1)
  xx(blt,j8), // <.s  (Z|N=0)
  xx(bge,j8), // >=.s (Z|L=1)
  xx(br, j8),
  xx(buc,j8),
};

// 0000.0000.0001.0000 0000.jjjj.cccc.jjjj jjjj.jjjj.jjjj.jjjj
struct opcode jcc24[16] = {
  xx(beq,jx24,0,1),
  xx(bne,jx24,0,1),
  xx(bcs,jx24,0,1),
  xx(bcc,jx24,0,1),
  xx(bhi,jx24,0,1),
  xx(bls,jx24,0,1),
  xx(bgt,jx24,0,1),
  xx(ble,jx24,0,1),
  xx(bfs,jx24,0,1),
  xx(bfc,jx24,0,1),
  xx(blo,jx24,0,1),
  xx(bhs,jx24,0,1),
  xx(blt,jx24,0,1),
  xx(bge,jx24,0,1),
  xx(br, jx24,0,1),
  xx(buc,jx24,0,1),
};

/* nw=1 */
struct opcode z000x[16] = {
  [0]  = xx(res,0),
  [1]  = xx(res,0),
  [2]  = xx(res,0),
  [3]  = xx(retx,0),
  [4]  = xx(di,0),
  [5]  = xx(ei,0),
  [6]  = xx(wait,0),
  [7]  = xx(eiwait,0),
  [8]  = xx(res,0),
  [9]  = xx(res,0),
  [10] = xx(cinv_i,0),
  [11] = xx(cinv_iu,0),
  [12] = xx(cinv_d,0),
  [13] = xx(cinv_du,0),
  [14] = xx(cinv_di,0),
  [15] = xx(cinv_diu,0),
};
/* nw=3 */
struct opcode z0010[16] = {
  t(jcc24,20,0xF),  // 0000.0000.0001.0000 0000.jjjj.cccc.jjjj jjjj.jjjj.jjjj.jjjj
  xx(res,0),
  xx(bal,jx24,0,2), // 0000.0000.0001.0000 0010.jjjj.cccc.jjjj jjjj.jjjj.jjjj.jjjj
  xx(res,0),

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
struct opcode z0011[16] = {
  [0]  = xx(res,0),
  [1]  = xx(res,0),
  [2]  = xx(res,0),
  [3]  = xx(res,0),

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
struct opcode z0012[16] = {
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
/* nw=3 */
struct opcode z0013[16] = {
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
/* nw=2 */
struct opcode z0014[16] = {
  xx(lpr,0,0,1),
  xx(lprd,0,0,1),
  xx(spr,0,0,1),
  xx(sprd,0,0,1),
  xx(res,0),
  xx(res,0),
  xx(res,0),
  xx(res,0),
  [9] =
  d(ord, r1, r0,1),   // 0000.0000.0001.0100 oooo.xxxx.rrrr.rrrr
  d(xor, r1, r0,1),   // 0000.0000.0001.0100 oooo.xxxx.rrrr.rrrr
  d(and, r1, r0,1),   // 0000.0000.0001.0100 oooo.xxxx.rrrr.rrrr
  d(sub, r1, r0,1),   // 0000.0000.0001.0100 oooo.xxxx.rrrr.rrrr
};
struct opcode z0018[16] = {
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
struct opcode z0019[16] = {
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
struct opcode z001x[16] = {
  [0x0] = t(z0010,28,0xf),
  [0x1] = t(z0011,28,0xf),
  [0x2] = t(z0012,28,0xf),
  [0x3] = t(z0013,28,0xf),
  [0x4] = t(z0014,28,0xf),
  [0x8] = t(z0018,28,0xf),
  [0x9] = t(z0019,28,0xf),
};

/* 0000.0000.xxxx.???? */
struct opcode zero[16] = {
  t(z000x,0,0xF),
  t(z001x,0,0xF),
  d(add,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(sub,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(and,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(or, i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(xor,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(mov,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  d(0),
  d(cmp,i32,r0,2), // 0000.0000.0010.rrrr iiii.iiii.iiii.iiii iiii.iiii.iiii.iiii
  xx(loadmp),
  xx(stormp),
  xx(excp),
  jd(jal,r0),
};

/* arg2 = #word-1 */
struct opcode crmap[] = {
  /* 0x00 */
  t(zero,4,0xF),   xx(push,n3,r0),  xx(pop,r0),     xx(popret,0),
  d(add,i20,r1,1), d(mov,i20,r1,1), w(tbit,n4,r0),  w(tbit,r1,r0),
  xx(a08),         xx(a09),         t(jccr,4,0xF),  b(muls,r1,r0),
  xx(beq0b,j4,r0), xx(bne0b,j4,r0), xx(beq0w,j4,r0),xx(beq0w,j4,r0),
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
  xx(bal,j24,0,1),  w(stor,n4,a20,1), w(stor,n4,d0),    w(stor,n4,d16,1),
  w(stor,n4,a20r4,1),w(stor,n4,a20r4,1),t(tC6,6,0x3),     d(stor,r1,a20,1),
  b(stor,r1,a20,1), w(stor,r1,a20,1), b(stor,r1,a20r4,1),b(stor,r1,a20r4,1),
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

const char *bregs[] = { "al",  "cl",  "dl",   "bl",  "ah",   "ch",   "dh",   "bh",
			"r8b", "r9b", "r10b", "r11b","r12b", "r13b", "r14b", "r15b" };
const char *wregs[] = { "ax",  "cx",  "dx",   "bx",  "sp",   "bp",   "si",   "di",
			"r8w", "r9w", "r10w","r11w", "r12w", "r13w", "r14w", "r15w",
			"ip" };
const char *dregs[] = { "eax", "ecx", "edx", "ebx",  "esp",  "ebp",  "esi",  "edi",
			"r8d", "r9d", "r10d","r11d", "r12d", "r13d", "r14d", "r15d",
			"eip" };
const char *qregs[] = { "rax", "rcx", "rdx", "rbx",  "rsp",  "rbp",  "rsi",  "rdi",
			"r8",  "r9",  "r10", "r11",  "r12",  "r13",  "r14",  "r15",
			"rip" };
const char *sregs[] = { "es", "cs", "ss", "ds", "fs", "gs" };
const char *xmmregs[] = { "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
			  "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15" };
const char *ymmregs[] = { "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8",
			  "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15" };
const char *zmmregs[] = { "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8",
			  "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15" };

int isMem(int arg)
{
  return (tt(arg) == TYPE_OFFSET || tt(arg) == TYPE_MEMORY);
}

int isImm(int arg)
{
  return (tt(arg) == TYPE_IMM || tt(arg) == TYPE_IMMV);
}

int mkimm(struct cpu *cpu, int sz, uint64_t immv)
{
  if (immv <= VAL_MASK)
    return TYPE_IMMV|sz|immv;
  cpu->immv = immv;
  return TYPE_IMM|sz;
}

/* Create register from size and index */
int mkreg(int sz, int vv, int rex)
{
  vv &= VAL_MASK;
  if (rex & REX_MASK)
    vv += 8;
  if (rex & VEX_MASK)
    vv += 16;
  return TYPE_REG+sz+vv;
}

/* Map size of vword/zword */
int getsz(int arg, int *osz)
{
  int sz = arg & SIZE_MASK;

  if (!osz)
    return arg;
  arg &= ~SIZE_MASK;
  if (sz == SIZE_VWORD)
    sz = *osz;
  else if (sz == SIZE_ZWORD)
    sz = (*osz == SIZE_WORD) ? SIZE_WORD : SIZE_DWORD;
  return arg|sz;
}

uint32_t getpc(struct cpu *cpu)
{
  return (cpu->pc - cpu->start) + cpu->nb;
}

uint32_t getoff(struct cpu *cpu)
{
  return (cpu->pc - cpu->start);
}

/* Extract N bytes */
uint64_t getn(struct cpu *cpu, int sz)
{
  uint8_t *pos = &cpu->pc[cpu->nb];
  
  if (sz == SIZE_BYTE) {
    cpu->nb += 1;
    return _get8(pos);
  }
  else if (sz == SIZE_WORD) {
    cpu->nb += 2;
    return _get16(pos);
  }
  else if (sz == SIZE_DWORD) {
    cpu->nb += 4;
    return _get32(pos);
  }
  else if (sz == SIZE_QWORD) {
    cpu->nb += 8;
    return _get64(pos);
  }
  return 0;
}

/* Get PC-relative Jump */
uint32_t getjmp(struct cpu *cpu, int sz)
{
  uintptr_t immv = 0;

  if (sz == SIZE_BYTE) {
    immv = (int8_t)getn(cpu, SIZE_BYTE);
  } else if (sz == SIZE_WORD) {
    immv = (int16_t)getn(cpu, SIZE_WORD);
  } else if (sz == SIZE_DWORD) {
    immv = (int32_t)getn(cpu, SIZE_DWORD);
  }
  immv += getpc(cpu);
  return immv;
}

/* Get jump table */
int getjmptab(stack_t *stk, int off, int n, int sz)
{
  int nj, so, immv;

  so = off;
  if (sz == SIZE_VWORD)
    sz = SIZE_WORD;
  for (nj = 0; off < stk->len && !stk->map[off]; nj++) {
    if (n > 0 && nj >= n)
      break;
    immv = 0;
    if (sz == SIZE_WORD) {
      immv = _get16(stk->base + off);
      off += 2;
    }
    else if (sz == SIZE_DWORD) {
      immv = _get32(stk->base + off);
      off += 4;
    }
    printf("jmpv: %.8x %.2x\n", off, stk->map[off]);
    if (immv > stk->len)
      break;
    _push(stk, immv, "jmptab");
  }
  _setstk(stk, so, 0xc, off-so);
  return nj;
}

const char *regname(int arg)
{
  int vv = arg & VAL_MASK;
  
  switch (arg & SIZE_MASK) {
  case SIZE_BYTE:  return bregs[vv];
  case SIZE_WORD:  return wregs[vv];
  case SIZE_DWORD: return dregs[vv];
  case SIZE_QWORD: return qregs[vv];
  case SIZE_SEGREG:return sregs[vv];
  case SIZE_XMM:   return xmmregs[vv];
  case SIZE_YMM:   return ymmregs[vv];
  case SIZE_ZMM:   return zmmregs[vv];
  case SIZE_VWORD: return wregs[vv];
  }
  return "xx";
}

/*================================================================
 * Display args
 *================================================================*/
const char *eastr(struct cpu *cpu, int arg)
{
  if (cpu->asz == SIZE_WORD) {
    switch (arg) {
    case 0: return "bx+si";
    case 1: return "bx+di";
    case 2: return "bp+si";
    case 3: return "bp+di";
    case 4: return "si";
    case 5: return "di";
    case 6: return "bp";
    case 7: return "bx";
    }
    return "";
  }
  if (cpu->asz == SIZE_QWORD) {
    return qregs[arg & 0x3F];
  }
  if (cpu->asz == SIZE_DWORD) {
    return dregs[arg & 0x3F];
  }
  return "ea32";
}

const char *ota(struct imap *i, int arg, char *as)
{
  int vv = arg & 0xFFF;
  
  switch (tt(arg)) {
  case TYPE_REG:
    return regname(arg);
  case TYPE_IMM:
  case TYPE_IMMV:
    snprintf(as, 32, "0x%llx", i->immv);
    return as;
  case TYPE_OFFSET:
    snprintf(as, 32, "data_0x%x", i->offv);
    return as;
  case TYPE_MEMORY:
    if (vv == 6) {
      snprintf(as, 32, "%s_0x%x",
	       i->offv < 0 ? "Local" : "Arg",
	       i->offv < 0 ? -i->offv : i->offv);
    }
    else {
      snprintf(as, 32, "data_index_0x%x", i->offv);
    }
    return as;
  case TYPE_JMP:
  case TYPE_ABSPTR:
    if (i->immv) {
      snprintf(as, 32, "@0x%llx <%s>", i->immv + _vbase,
	       getSymName(NULL, i->immv));
      return as;
    }
    break;
  case TYPE_EAMEM:
  case TYPE_EAREG:
    printf("ERROR: Shouldn't be here\n");
    exit(0);
  }
  as[0] = arg >> TYPE_SHIFT;
  as[1] = arg >> SIZE_SHIFT;
  as[2] = 0;
  return as;
}

const char *ota1(struct imap *i)
{
  static char oa[32];
  return ota(i, i->opc->args[0], oa);
}

const char *ota2(struct imap *i)
{
  static char oa[32];
  return ota(i, i->opc->args[1], oa);
}

const char *at(struct cpu *cpu, int arg, char *argstr)
{
  argstr[0] = 0;
  switch (tt(arg)) {
  case TYPE_REG:
    return regname(arg);
  case TYPE_IMMV:
  case TYPE_IMM:
  case TYPE_JMP:
    snprintf(argstr, 30, "0x%llx", cpu->immv);
    break;
  case TYPE_OFFSET:
    useStk(dseg, cpu->offv, 0x3, dfsz(arg, 0));
    snprintf(argstr, 30, "[0x%x] <%s>", cpu->offv, getSymName(dseg, cpu->offv));
    break;
  case TYPE_MEMORY:
    if (cpu->asz == SIZE_WORD && (arg & 0xFFF) == 6) {
      if ((int)cpu->offv < 0) {
	snprintf(argstr, 30, "Local_%x", -cpu->offv);
      }
      else {
	snprintf(argstr, 30, "Arg_%x", cpu->offv);
      }
    }
    else {
      snprintf(argstr, 30, "[%s+0x%x]",
	       eastr(cpu, arg & 0xFFF),
	       cpu->offv);
    }
    break;
  default:
    if (arg != 0) {
      argstr[0] = (arg >> TYPE_SHIFT) & 0xFF;
      argstr[1] = (arg >> SIZE_SHIFT) & 0xFF;
      argstr[2] = 0;
    }
    break;
  }
  return argstr;
}

const char *szof(int sz)
{
  switch (sz & SIZE_MASK) {
  case 0: return "none";
  case SIZE_BYTE: return "byte";
  case SIZE_WORD: return "word";
  case SIZE_DWORD: return "dword";
  case SIZE_VWORD: return "vword";
  }
  return "unk";
}

/* EA Byte: OSss.iiii.iibb.bbbb
 * O=offset present
 * S=seg present
 * ss=Index Scale
 * ii=Index
 * bb=Base
 */
int mkea(struct cpu *cpu, int base, int offsz, int sz)
{
  int vv = 0;
  int sbase;
  
  if (cpu->seg)
    vv |= 0x4000;
  if (offsz) {
    /* Get offset */
    cpu->offv = getn(cpu, offsz);
    if (offsz == SIZE_BYTE) {
      /* signed offset */
      cpu->offv = (int8_t)cpu->offv;
    }
    else {
      /* No base register. Direct offset */
      if (cpu->seg == rCS)
	sbase = 0;
      else if (cpu->seg == rES)
	sbase = 0x10000;
      else
	sbase = dseg;
      addSym(sbase + cpu->offv, 0, NULL, "data_%s%.5x",
	     cpu->seg ? regname(cpu->seg) : "",
	     cpu->offv);
    }
    vv |= 0x8000;
  }
  if (base == -1) {
    if (cpu->seg == 0) {
      cpu->seg = rDS;
    }
    return TYPE_OFFSET|sz;
  }
  if (base == rESP || base == rRSP) {
    vv |= ((cpu->sib & 0xC0) << 6);

    /* Check SIB Byte */
    base = mkreg(sz, sib_bbb(cpu->sib), cpu->rex & REX_B);
    vv |= (base & 0x1F);

    base = mkreg(sz, sib_iii(cpu->sib), cpu->rex & REX_X);
    vv |= (base & 0x1F) << 6;
    printf("mkea: seg:%x base:%x off:%s sz:%s sib:%.2x ",
	   cpu->seg, base, szof(offsz), szof(sz), cpu->sib);
  }
  else {
    vv |= base & 0xFFF;
  }
  return TYPE_MEMORY|sz|vv;
}

/*=============================================*
 * Decode effective address
 *=============================================*/
int getea(struct cpu *cpu, int sz)
{
  int rrr = mrr_rrr(cpu->mrr);
  int mm = mrr_mm(cpu->mrr);
  int base;
  
  if (mm == 3) {
    /* MM = 3 => register */
    return mkreg(sz, rrr, cpu->rex & (REX_B|VEX_XX));
  }
  base = mkreg(sz, rrr, cpu->rex & REX_B);
  switch (cpu->asz) {
  case SIZE_WORD:
    /* 16-bit EA */
    if (mm == 2)
      return mkea(cpu, base, SIZE_WORD, sz);
    else if (mm == 1)
      return mkea(cpu, base, SIZE_BYTE, sz);
    else if (rrr == 6)
      /* Special case [Ow] */
      return mkea(cpu, -1, SIZE_WORD, sz);
    break;
  case SIZE_DWORD:
    /* 32-bit EA */
    if (mm == 2)
      return mkea(cpu, base, SIZE_DWORD, sz);
    else if (mm == 1)
      return mkea(cpu, base, SIZE_BYTE, sz);
    else if (rrr == 5)
      /* Special Case [Od] */
      return mkea(cpu, -1, SIZE_DWORD, sz);
    break;
  case SIZE_QWORD:
    /* 64-bit EA */
    if (mm == 2)
      return mkea(cpu, base, SIZE_DWORD, sz);
    else if (mm == 1)
      return mkea(cpu, base, SIZE_BYTE, sz);
    else if (rrr == 5)
      /* Special Case [rip+Id] */
      return mkea(cpu, rRIP, SIZE_DWORD, sz);
    break;
  }
  /* Default */
  return mkea(cpu, base, 0, sz);
}

/*=======================================================*
 * Decode operand argument
 *  TYPE_IMM   : Ib, Iz 
 *  TYPE_REG   : rAL, rRSI
 *  TYPE_EMBREG: gb, gv
 *  TYPE_EAREG : Gb, Gv
 *=======================================================*/
int getarg(struct cpu *cpu, int arg)
{
  int sz, vv = arg & VAL_MASK;
  int s,o,base;

  arg = getsz(arg, &cpu->osz);
  sz  = arg & SIZE_MASK;
  
  switch (tt(arg)) {
  case TYPE_IMM:
    /* Immediate value */
    cpu->immv = getn(cpu, sz);
    return TYPE_IMM|sz;
  case TYPE_IMMV:
    /* Embedded immediate */
    return TYPE_IMMV|sz|vv;
  case TYPE_REG:
    /* Explicit register */
    return mkreg(sz, vv, 0);
  case TYPE_EMBREG:
    /* Embedded register, part of opcode */
    return mkreg(sz, mrr_rrr(cpu->op),  cpu->rex & (REX_B|VEX_XX));
  case TYPE_EAREG:
    /* Register, MRR.ggg */
    return mkreg(sz, mrr_ggg(cpu->mrr), cpu->rex & (REX_R|VEX_RR));
  case TYPE_EA:
  case TYPE_EAMEM:
    return getea(cpu, sz);
  case TYPE_OFFSET:
    /* Direct memory offset */
    return mkea(cpu, -1, cpu->asz, sz);
  case TYPE_ABSPTR:
    /* Absolute far call/jump */
    o = getn(cpu, sz);
    s = getn(cpu, SIZE_WORD);
    cpu->immv = (s << 4) + o;
    printf("AbsCall: %.4x:%.4x <%s> %x ", s, o, getSymName(NULL, cpu->immv));
    break;
  case TYPE_JMP:
    /* PC-relative jump */
    cpu->immv = getjmp(cpu, sz);
    break;
  default:
    break;
  }
  return arg;
}

/* mm rrr 
 * 00 000 --- --- eax        bx+si
 * 00 001 --- --- ecx        bx+di
 * 00 010 --- --- edx        bp+si
 * 00 011 --- --- ebx        bp+di
 * 00 100 sib                si
 * 00 101 --- --- disp32     di
 * 00 110 --- --- esi        disp16
 * 00 111 --- --- edi        bx
 *
 * 01 000 --- --- eax+disp8  bx+si+disp8
 * 01 001 --- --- ecx+disp8  bx+di+disp8
 * 01 010 --- --- edx+disp8  bp+si+disp8
 * 01 011 --- --- ebx+disp8  bp+di+disp8
 * 01 100 sib                si+disp8
 * 01 101 --- --- ebp+disp8  di+disp8
 * 01 110 --- --- esi+disp8  bp+disp8
 * 01 111 --- --- edi+disp8  bx+disp8
 *
 * 10 000 --- --- eax+disp32 bx+si+disp16
 * 10 001 --- --- ecx+disp32 bx+di+disp16
 * 10 010 --- --- edx+disp32 bp+si+disp16
 * 10 011 --- --- ebx+disp32 bp+di+disp16
 * 10 100 sib                si+disp16
 * 10 101 --- --- ebp+disp32 di+disp16
 * 10 110 --- --- esi+disp32 bp+disp16
 * 10 111 --- --- edi+disp32 bx+disp16

             0     1      2
 * sib iii.x bbb.b bbb.b  bbb.b
 * 000 eax   eax   eax+b  eax+d
 * 001 ecx   ecx   ecx+b  ecx+d
 * 010 edx   edx   edx+b  edx+d
 * 011 ebx   ebx   ebx+b  ebx+d
 * 100 ---   esp   esp+b  esp+d
 * 101 ebp   d32   ebp+b  ebp+d
 * 110 esi   esi   esi+b  esi+d
 * 111 edi   edi   edi+b  edi+d
 */
struct opcode *getop(struct cpu *cpu)
{
  struct opcode *opc;
  int ib, flag = 0;
  char pfx[10];

  snprintf(pfx, sizeof(pfx), "   ");
  do {
    cpu->op = getn(cpu, SIZE_BYTE);
    if (cpu->op == 0x0f) {
      opc = &himap[getn(cpu, SIZE_BYTE)];
    }
    else
      opc = &opmap[cpu->op];
    opc->flag |= FLAG_USED;
    flag = opc->flag;
    if (flag & FLAG_PFX) {
      snprintf(pfx, sizeof(pfx), "%.2x:", cpu->op);
      if (tt(opc->args[0]) == TYPE_REG) {
	cpu->seg = opc->args[0];
      }
      else
	cpu->flag |= opc->args[0];
    }
    if ((cpu->mode == SIZE_QWORD) && ((cpu->op & 0xF0) == 0x40)) {
      cpu->rex = cpu->op;
      flag |= FLAG_PFX;
    }
  } while (flag & FLAG_PFX);
  if (opc->flag & FLAG_MRR) {
    cpu->mrr = getn(cpu, SIZE_BYTE);
    if (mrr_mm(cpu->mrr) != 3 && mrr_rrr(cpu->mrr) == 4 && cpu->asz != SIZE_WORD) {
      cpu->sib = getn(cpu, SIZE_BYTE);
      printf("sib.%d/%d/%d ", sib_ss(cpu->sib), sib_iii(cpu->sib), sib_bbb(cpu->sib));
    }
#if 1
    printf("%s%.2x %.2x ", pfx, cpu->op, cpu->mrr);
    printf("[%d/%d/%d] %.2x ", mrr_mm(cpu->mrr),
	   mrr_ggg(cpu->mrr), mrr_rrr(cpu->mrr), cpu->sib);
#endif
  }
  else {
    printf("%s%.2x      %9s", pfx, cpu->op, " ");
  }
  return opc;
}

const char *segpfx(int arg)
{
  static char sp[32];
  if (!arg)
    return "";
  snprintf(sp, sizeof(sp), "!%s:", regname(arg));
  return sp;
}

struct opcode *_dis86(stack_t *stk, struct cpu *cpu)
{
  struct opcode *opc, *noc;
  int ta0, ta1, ta2;
  char as0[32];
  char as1[32];
  char as2[32];
  uint64_t pc;
  struct sym *cmt;

  cmt = findSym(getpc(cpu));
  pc = cpu->pc - stk->base;
  printf("%.8llx ", stk->vbase + pc);
  cpu->osz = (cpu->mode == SIZE_WORD) ? SIZE_WORD : SIZE_DWORD;
  cpu->asz = cpu->mode;
  ta0 = 0;
  ta1 = 0;
  ta2 = 0;
  opc = getop(cpu);
  for(;;) {
    opc->flag |= FLAG_USED;
    ta0 |= opc->args[0];
    ta1 |= opc->args[1];
    ta2 |= opc->args[2];
    if (!opc->tbl)
      break;
    opc = &opc->tbl[mrr_ggg(cpu->mrr)];
  }
  if (cpu->mode == SIZE_WORD && (cpu->flag & fOSZ))
    cpu->osz = SIZE_DWORD;
  if (cpu->mode == SIZE_QWORD && ((cpu->rex & REX_W) || (opc->flag & FLAG_VSZ))) {
    /* REX specified or default to 64-bit */
    cpu->osz = SIZE_QWORD;
  }
  /* Return copy of opcode with translated args */
  noc = calloc(1, sizeof(*noc));
  noc->mnem = opc->mnem;
  if (noc->mnem == NULL) {
    snprintf(as0, sizeof(as0), "noop_%x", cpu->op);
    noc->mnem = strdup(as0);
  }
  noc->flag = opc->flag;
  noc->llop = opc->llop;
  noc->args[0] = getarg(cpu, ta0);
  noc->args[1] = getarg(cpu, ta1);
  noc->args[2] = getarg(cpu, ta2);
  noc->data    = opc;
#if 1
  printf("%-8s {%2s %2s %2s} %s%s,%s,%s",
	 opc->mnem, crarg(ta0),crarg(ta1),crarg(ta2),
	 segpfx(cpu->seg),
	 at(cpu, noc->args[0], as0),
	 at(cpu, noc->args[1], as1),
	 at(cpu, noc->args[2], as2));
  if (cmt && cmt->flag == sCOMMENT) {
    printf(" ; %s", cmt->name);
  }
  printf("\n");
#endif
  //_setstk(stk, pc, 0x3, cpu->nb);
  cpu->pc += cpu->nb;

  return noc;
}

const char *crarg(int arg)
{
  switch(arg) {
  case 0:  return "";
  case r0: return "r0";
  case r1: return "r1";
  case d0: return "d0";
  case d4: return "d4";
  case d14: return "d14";
  case d16: return "d16";
  case d20: return "d20";
  case a20: return "a20";
  case a20r3:return "a20r3";
  case a20r4:return "a20r4";
  case md20: return "md20";
  case a24: return "a24";
  case i20: return "i20";
  case i32: return "i32";
  case i4:  return "i4";
  case i16: return "i16";
  case n4:  return "i4";
  case n3:  return "i3";
  case n5:  return "i5";
  case j4: return  "j4";
  case j8: return  "j8";
  case j16: return "j16";
  case jx24: return "jx24";
  case j24: return "j24";

  case Eb:  return "Eb";
  case Ev:  return "Ev";
  case Gb:  return "Gb";
  case Gv:  return "Gv";
  case gb:  return "gb";
  case gv:  return "gv";
  case Ib:  return "Ib";
  case Iv:  return "Iv";
  case Iz:  return "Iz";
  case Jb:  return "Jb";
  case Jz:  return "Jz";
  case Ap:  return "Ap";
  case Mp:  return "Mp";
  case Xb:  return "Xb";
  case Xv:  return "Xv";
  case Yb:  return "Yb";
  case Yv:  return "Yv";
  }
  if (tt(arg) == TYPE_REG) {
    return regname(arg);
  }
  return "zk";
}

const char *crregw[] = { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
			 "r8", "r9", "r10", "r11", "r12", "r13", "ra", "sp" };
const char *crregd[] = { "(r1,r0)","(r2,r1)","(r3,r2)","(r4,r3)","(r5,r4)","(r6,r5)","(r7,r6)",
			 "(r8,r7)","(r9,r8)","(r10,r9)","(r11,r10)","(r12,r11)",
			 "(r12)","(r13)", "(ra)", "(sp)" };

const char *crregname(int reg, int sz)
{
  static char regname[32];

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
    return mkcrmem(cpu, SIZE_DWORD, (op & 0x80) ? r13 : r12,
		   (a0 << 16) | _get16(cpu->pc+2));
  case a20r4:
    return mkcrmem(cpu, SIZE_DWORD, (op & 0x100) ? r13 : r12,
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
  return arg;
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

void scancr16fn(stack_t *stk)
{
  int i;

  uint8_t *start = stk->base;
  for (i = 0; i < stk->len; i+=2) {
    if (_get16(stk->base + i) == 0x1200)
      ;
#if 0
  for (i = 2; i < stk->len; i+=2) {
    if ((_get16(start + i - 2) & 0xFF00) == 0x0300 &&
	(_get16(start + i)     & 0xFF00) == 0x0100)
      _push(&stk, i, "poppush");
    if ((_get16(start + i - 2) & 0xFFFF) == 0x0aee &&
	(_get16(start + i)     & 0xFF00) == 0x0100)
      _push(&stk, i, "jmppush");
  }
#endif
  }
}

/* get next opcode */ 
struct opcode *nxtCr(struct cpu *cpu, struct opcode *opc)
{
  uint32_t ib;

  ib = (_get32(cpu->pc) >> tSHIFT(opc->flag)) & tMASK(opc->flag);
  return &opc->tbl[ib];
}

#if 0
struct opcode osz_cbw[] = {
  __(cbw),
  __(cwde),
  __(cdqe), // rex.w
};
struct opcode osz_cwd[] = {
  __(cwd),
  __(cdq),
  __(cqo),
};
/*
  ssss.sssm.mmmm.mmmm.----.----.----.----
  xxxx.xxxx.xxxx.xxxx                     TBLMASK
  ----.----.----.----.O---.----.----.---- TBLOSZ
  ----.----.----.----.-S--.----.----.---- TBLSSE
  ----.----.----.----.--R-.----.----.---- REX
  ----.----.----.----.---P.----.----.---- PFX
  ----.----.----.----.----.6723.----.---- 66/67/F2/F3 flag
  ----.----.----.----.----.----.Ssss.---- SEG flag
  ----.----.----.----.----.----.----.Q--- QSZ flag (default osize=64)
*/
x86cr(struct cpu *cpu, struct opcode *opc)
{
  if (opc->flag & TBLMASK) {
    return &opc->tbl[tblIdx(cpu->pc, opc->flag)];
  }
  else if (opc->flag & TBLOSZ) {
    if (cpu->osz == SIZE_WORD)  return &opc->tbl[0];
    if (cpu->osz == SIZE_DWORD) return &opc->tbl[1];
    if (cpu->osz == SIZE_QWORD) return &opc->tbl[2];
  }
  else if (opc->flag & TBLSSE) {
    /* default to idx 0 */
    if (cpu->flag & f66) return &opc->tbl[1];
    if (cpu->flag & fF2) return &opc->tbl[2];
    if (cpu->flag & fF3) return &opc->tbl[3];
    return &opc->tbl[0];
  }
  if ((cpu->mode == SIZE_QWORD) && (opc->flag & FLAG_REX)) {
    cpu->rex = op;
  }
  else {
    return;
  }
  cpu->op = getn(cpu, SIZE_BYTE);
  return &locodes[cpu->op];
}
#endif

struct opcode *_discr16(stack_t *stk, struct cpu *cpu)
{
  struct opcode *opc, *noc;
  int off;
  uint32_t civ, i;
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
  
  if (opc->mnem && !strcmp(opc->mnem, "jmpa") && _get16(cpu->pc - 6) == 0x0020) {
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

extern struct opcode *_disarm(stack_t *stk, struct cpu *cpu);
extern struct opcode *_dissh4(stack_t *stk, struct cpu *cpu);

void showinst(struct opcode *opc, int n, const char *lbl)
{
  int i;

  printf("showinst: %d\n", n);
  for (i = 0; i < n; i++) {
    printf("%-6s: %.4x %-8s %6s,%6s,%6s %s %s\n",
	   lbl, i,
	   opc[i].mnem ? opc[i].mnem : "<none>",
	   crarg(opc[i].args[0]),
	   crarg(opc[i].args[1]),
	   crarg(opc[i].args[2]),
	   opc[i].flag & FLAG_USED ? "used" : "unused",
	   opc[i].flag & FLAG_EMU  ? "emu" : "noemu");
    if (opc[i].tbl) {
      showinst(opc[i].tbl, tMASK(opc[i].flag)+1, opc[i].mnem);
    }
  }
}

int isExit(uint32_t pos)
{
  struct sym *s;

  if ((s = getSymName(NULL, pos)) != NULL) {
    if (!strcmp(s, "abort"))
      return 1;
    if (!strcmp(s, "exit"))
      return 1;
  }
  return 0;
}

/* Check if we need to end this basic block... */
int getbb(stack_t *stk, struct cpu *cpu, struct opcode *opc, int start,
	  int pos, int ninst, int mach)
{
  int *jtab, nj;

  switch (mach) {
  case MACH_SH4:
    if (!opc->mnem)
      break;
    if (!strcmp(opc->mnem, "rts")) {
      return addBB(stk, bbTERM, start, pos, ninst, opc, 0);
    }
    if (!strcmp(opc->mnem, "bt") || !strcmp(opc->mnem, "bf")) {
      return addBB(stk, bbCOND, start, pos, ninst, opc, 2, pos, cpu->immv);
    }
    break;
  case MACH_X86_16:
  case MACH_X86_32:
  case MACH_X86_64:
    if (!strcmp(opc->mnem, "jmp")) {
      if (tt(opc->args[0]) == TYPE_JMP) {
	/* Unconditional jump:Jx */
	return addBB(stk, bbJUMP, start, pos, ninst, opc, 1, cpu->immv);
      }
      if (tt(opc->args[0]) == TYPE_OFFSET) {
	/* Unconditional jump: Ov */
	printf("Jump indirect!!\n");
	getjmptab(stk, cpu->offv, 1, SIZE_WORD);
      }
      else if (tt(opc->args[0]) == TYPE_ABSPTR) {
	/* Unconditional jump: seg:off */
	printf("Jump Ap : %x\n", cpu->immv);
      }
      else if (cpu->offv) {
	/* Unconditional jump: [bx+offset] */
	getjmptab(stk, cpu->offv, -1, SIZE_WORD);
      }
      printf("Jump table/register: %x %x\n", cpu->offv, opc->args[0]);
      /* Get Jump Table */
      return addBB(stk, bbJUMP, start, pos, ninst, opc, 0);
    }
    else if (!strcmp(opc->mnem, "call")) {
      if (tt(opc->args[0]) == TYPE_JMP) {
	addSym(cpu->immv - stk->vbase, 1, NULL, "func_%x", cpu->immv - stk->vbase); 
	_push(stk, cpu->immv - stk->vbase, "call");
	return addBB(stk, bbCALL, start, pos, ninst, opc, 1, pos);
      }
      else if (tt(opc->args[0]) == TYPE_ABSPTR) {
	//printf("AbsCall: %lx\n", cpu->immv);
      }
      else {
	printf("Call table/register: %c%c: %x\n", ot(opc->args[0]), cpu->offv);
      }
      /* Get Call Table' */
      return addBB(stk, bbCALL, start, pos, ninst, opc, 1, pos);
    }
    else if (!strcmp(opc->mnem, "int") || !strcmp(opc->mnem, "into")) {
      /* Interrupt */
      return addBB(stk, bbCALL, start, pos, ninst, opc, 1, pos);
    }
    else if (tt(opc->args[0]) == TYPE_JMP) {
      /* Conditional jump */
      return addBB(stk, bbCOND, start, pos, ninst, opc, 2, pos, cpu->immv);
    }
    else if (!strcmp(opc->mnem, "ret") || !strcmp(opc->mnem, "retf") || !strcmp(opc->mnem, "iret") || !strcmp(opc->mnem, "hlt")) {
      /* Return/Terminate */
      return addBB(stk, bbTERM, start, pos, ninst, opc, 0);
    }
    break;
  case MACH_CR16:
    if (!opc->mnem)
      return addBB(stk, bbTERM, start, pos, ninst, opc, 0);
    if (!strcmp(opc->mnem, "br")) {
      /* Unconditional jump */
      printf("UncondJmp: %.8x\n", cpu->immv + _vbase);
      return addBB(stk, bbJUMP, start, pos, ninst, opc, 1, cpu->immv);
    }
    else if (!strcmp(opc->mnem, "bal")) {
      printf("j24: %.8x\n", cpu->immv + _vbase);
      return addBB(stk, bbCALL, start, pos, ninst, opc, 1, pos);
    }
    else if (opc->mnem[0] == 'b') {
      /* Conditional jump */
      printf("CondJmp: %.8x\n", cpu->immv + _vbase);
      return addBB(stk, bbCOND, start, pos, ninst, opc, 2, pos, cpu->immv);
    }
    else if (!strcmp(opc->mnem, "popret") || !strcmp(opc->mnem, "jmpa") || !strcmp(opc->mnem, "retx")) {
      return addBB(stk, bbTERM, start, pos, ninst, opc, 0);
    }
    break;
  case MACH_ARM:
    if (!strcmp(opc->mnem, "bl")) {
      if (isExit(cpu->immv + _vbase)) {
	return addBB(stk, bbTERM,start, pos, ninst, opc, 0);
      }
      return addBB(stk, bbCALL,start, pos, ninst, opc, 1, pos);
    }
    if (!strcmp(opc->mnem, "br"))
      return addBB(stk, bbJUMP,start, pos, ninst, opc, 1, cpu->immv);
    if (tt(opc->args[0]) == TYPE_JMP)
      return addBB(stk, bbCOND,start, pos, ninst, opc, 2, pos, cpu->immv);
    if (!strcmp(opc->mnem, "ldm") && opc->args[0] == _sp &&
	(cpu->op & 0x8000)) {
      /* ldm sp, { .. pc } -> return */
      printf("ldm:%s %.8x %.8x\n", opc->mnem, opc->args[0], opc->args[1]);
      return addBB(stk, bbTERM, start, pos, ninst, opc, 0);
    }
    break;
  }
  /* next address already visited: Fall Node */
  if (stk->map[pos] & 0x3) {
    printf("FALLNODE: %.2x %.8llx\n", stk->map[pos], stk->vbase + pos);
    return addBB(stk, bbFALL, start, pos, ninst, opc, 1, pos);
  }
  return 0;
}

void scan86fn(stack_t *stk)
{
  uint8_t *pc = stk->base;
  int i;

  for (i = 0; i < stk->len; i++) {
#if 1
    if (pc[i] == 0x55 && pc[i+1] == 0x8b && pc[i+2] == 0xec) {
      _push(stk, i, "_func");
    }
    if (pc[i] == 0xc8 && pc[i+2] == 0x00 && pc[i+3] == 0x00) {
      _push(stk, i, "_enter");
    }
#endif
  }
}

void scanarmfn(stack_t *stk)
{
  uint8_t *pc = stk->base;
  int i;

  for (i = 0; i < stk->len; i+=4) {
    if (_get32(pc + i) == 0xe1a0c00d)
      _push(stk, i, "_func");
  }
}

#define MLEN 16

void dumpstk(stack_t *stk)
{
  struct sym *s;
  int i, j, c;

  printf("======================= stkdone\n");
  for (i = 0; i < stk->len; i+=MLEN) {
    printf("%.8x ", i + stk->vbase);
    for (j = 0; j < MLEN; j++) {
      c = stk->map[i+j];
      if (c & 0xC) {
	printf("jj");
      } else if (c) {
	printf("__");
      }
      else {
	printf("%.2X", stk->base[i+j]);
      }
    }
    for (j = 0; j < MLEN; j++) {
      s = findSym(stk->vbase + i + j);
      if (s)
	printf(" %s", s->name);
    }
    printf("\n");
  }
}

/* Compare instruction match */
int opeq(struct imap *i, const char *op, int arg0, int arg1, int arg2)
{
  if (!i || i->hli)
    return 0;
  if (op && strcmp(i->opc->mnem, op))
    return 0;
  if (arg0 && (arg0 != i->opc->args[0]))
    return 0;
  if (arg1 && (arg1 != i->opc->args[1]))
    return 0;
  if (arg2 && (arg2 != i->opc->args[2]))
    return 0;
  return 1;
}

/* Return next instruction in imap */
struct imap *nxt(struct imap *i, int n)
{
  while (n--)
    i = &i[i->nb];
  return i;
}

struct imap *prv(struct imap *i)
{
  while (i && !i->flag) {
    --i;
    if (i->opc)
      return i;
  }
  return NULL;
}

void sethli(struct imap *i, int hli, int n)
{
  printf("  sethli: '%s' %d\n", hlit(hli), n);
  i->hli = hli;
  while (n--) {
    i = &i[i->nb];
    i->hli = hliINVAL;
  }
}

/* Check for integer propagation commands */
void chklong(struct imap *ci, const char *op1, const char *op2, int hli)
{
  struct imap *ni = nxt(ci, 1);

  if (opeq(ci, op1, 0, 0, 0) && opeq(ni, op2, 0, 0, 0)) {
    printf("Chklong: %s:%s\n", op1, op2);
    sethli(ci, hli, 1);
  }
}

int chkcmpjmp(struct imap *ci, const char *op2, int hli)
{
  if (opeq(ci, "cmp", 0, 0, 0) ||
      opeq(ci, "or",  0, 0, 0) ||
      opeq(ci, "test",0, 0, 0)) {
    if (opeq(nxt(ci, 1), op2, 0, 0, 0)) {
      sethli(ci, hli, 1);
      return 1;
    }
  }
  return 0;
}

void chkone(struct imap *ci, const char *op, int hli)
{
  if (opeq(ci, op, 0, 0, 0)) {
    hli = hliASSIGN;
    sethli(ci, hli, 0);
  }
}

int isdword(struct imap *ci, struct imap *ni)
{
  return ci->offv+2 == ni->offv;
}
	    
void checkhli_x86(struct imap *ci)
{
  uint16_t i1, i2;
  struct imap *ni, *nni;
  const char *sym = "";
  
  /* Check some idioms here: 
   *  xor ax, ax => mov ax, 0
   *  sub ax, ax => mov ax, 0
   */
  ni = nxt(ci, 1);
  nni = nxt(ni, 1);
#if 0
  if (opeq(ci, "xor", ci->opc->args[1], 0, 0) ||
      opeq(ci, "sub", ci->opc->args[1], 0, 0)) {
    printf(" => assign zero : %s\n", ci->opc->mnem);
    ci->opc->mnem = "mov";
    ci->opc->args[1] = TYPE_IMM|SIZE_BYTE;
    ci->immv = 0;
  }
#endif
  chklong(ci, "add", "adc",  hliADD);
  chklong(ci, "sub", "sbb",  hliSUB);
  chklong(ci, "shl", "rcl",  hliSHL);
  chklong(ci, "shr", "rcr",  hliSHR);
  chklong(ci, "sar", "rcr",  hliSHR);
  chklong(ci, "cwd", "idiv", hliDIV);

  if (opeq(ci, "push", rBP, 0, 0) &&
      opeq(ci, "mov",  rBP, rSP, 0)) {
    ci->hli = hliIGNORE;
    ni->hli = hliIGNORE;
  }

  if (opeq(ci, "mov", rAX, 0, 0) &&
      opeq(ni, "mov", 0, rAX, 0)) {
    sethli(ci, hliASSIGN, 1);
  }
  
  /* mov [mem], dx:ax */
  if (opeq(ci, "mov", 0, rAX, 0) &&
      opeq(ni, "mov", 0, rDX, 0) &&
      isdword(ci, ni)) {
    sethli(ci, hliASSIGN, 1);
  }
  if (opeq(ci, "mov", 0, rDX, 0) &&
      opeq(ni, "mov", 0, rAX, 0) &&
      isdword(ni, ci)) {
    sethli(ci, hliASSIGN, 1);
  }

  /* mov dx:ax, [mem] */
  if (opeq(ci, "mov", rAX, 0, 0) &&
      opeq(ni, "mov", rDX, 0, 0) &&
      isdword(ci, ni)) {
    sethli(ci, hliASSIGN, 1);
  }
  if (opeq(ci, "mov", rDX, 0, 0) &&
      opeq(ni, "mov", rAX, 0, 0) &&
      isdword(ni, ci)) {
    sethli(ci, hliASSIGN, 1);
  }

  if (opeq(ci, "neg", 0, 0, 0) &&
      opeq(ni, "neg", 0, 0, 0) &&
      opeq(nni,"sbb", 0, 0, 0)) {
    sethli(ci, hliNEG, 2);
  }
  if (opeq(ci, "neg", 0, 0, 0) &&
      opeq(ni, "adc", ni->opc->args[0], i0, 0) &&
      opeq(ni, "neg", ni->opc->args[0], 0, 0)) {
    sethli(ci, hliNEG, 2);
  }

  /* Compare */
  chkcmpjmp(ci, "je", hliEQ);
  chkcmpjmp(ci, "jne",hliNEQ);

  /* Signed */
  chkcmpjmp(ci, "jl",  hliLTs);
  chkcmpjmp(ci, "jle", hliLTEs);
  chkcmpjmp(ci, "jge", hliGTEs);
  chkcmpjmp(ci, "jg",  hliGTs);

  /* Unsigned */
  chkcmpjmp(ci, "jb",  hliLT);
  chkcmpjmp(ci, "jbe", hliLTE);
  chkcmpjmp(ci, "jae", hliGTE);
  chkcmpjmp(ci, "ja",  hliGT);

  // call xxx
  // add  sp, nnn
  if (opeq(ci, "call", 0, 0, 0) &&
      opeq(ni,"add", rSP, Ib, 0)) {
    ni->hli = hliIGNORE;
  }

  // mov al, ah; mov ah, dl ; mov dl, dh => dx:ax >>= 8 */
  if (opeq(ci, "mov", rAL, rAH, 0) &&
      opeq(ni, "mov",rAH,rDL,0) &&
      opeq(nni,"mov",rDL,rDH,0)) {
    printf("dx:ax>>=8");
    sethli(ci, hliSHR, 2);
  }
  if (opeq(ci, "mov", rDH, rDL, 0) &&
      opeq(ni, "mov",rDL,rAH,0) &&
      opeq(nni,"mov",rAH,rAL,0) &&
      opeq(nxt(ci,3),"sub",rAL,rAL,0)) {
    printf("dx:ax<<=8");
    sethli(ci, hliSHL, 3);
  }
  
  /* Generic functions */
  chkone(ci, "add", hliADD);
  chkone(ci, "sub", hliSUB);
  chkone(ci, "xor", hliXOR);
  chkone(ci, "and", hliAND);
  chkone(ci, "or",  hliOR);
  if (opeq(ci, "mov", 0, Ib, 0) ||
      opeq(ci, "mov", 0, Iw, 0) ||
      opeq(ci, "mov", 0, Iv, 0))
    sethli(ci, hliASSIGN, 0);

  if (opeq(ci, "call", 0, 0, 0))
    sym = getSymName(NULL, ci->immv);
    
  printf("%-8x %-6s %s,%s %s\n",
	 ci->hli, ci->opc->mnem,
	 ota1(ci),
	 ota2(ci),
	 sym);
}

/*======================================================
 * CR16
 *======================================================*/
void chkcmpjmpcr(struct imap *ci, const char *op2, int hli)
{
  if (opeq(ci, "cmpb",  0, 0, 0) ||
      opeq(ci, "cmpw",  0, 0, 0) ||
      opeq(ci, "cmpd",  0, 0, 0)) {
    if (opeq(nxt(ci,1), op2, 0, 0, 0)) {
      sethli(ci, hli, 1);
    }
  }
}

void chkonecr(struct imap *ci, const char *op, int hli)
{
  char tmpop[32];

  snprintf(tmpop, sizeof(tmpop), "%sb", op);
  chkone(ci, tmpop, hli);
  snprintf(tmpop, sizeof(tmpop), "%sw", op);
  chkone(ci, tmpop, hli);
  snprintf(tmpop, sizeof(tmpop), "%sd", op);
  chkone(ci, tmpop, hli);
}

void checkhli_cr16(struct imap *ci)
{
  chkonecr(ci, "add", hliADD);
  chkonecr(ci, "sub", hliSUB);
  chkonecr(ci, "xor", hliXOR);
  chkonecr(ci, "and", hliAND);
  chkonecr(ci, "or",  hliOR);
  chkonecr(ci, "mov", hliASSIGN);

  /* Compare */
  chkcmpjmpcr(ci, "beq", hliEQ);
  chkcmpjmpcr(ci, "bne",hliNEQ);

  /* Signed */
  chkcmpjmpcr(ci, "blt", hliLTs);
  chkcmpjmpcr(ci, "ble", hliLTEs);
  chkcmpjmpcr(ci, "bge", hliGTEs);
  chkcmpjmpcr(ci, "bgt", hliGTs);

  /* Unsigned */
  chkcmpjmpcr(ci, "blo", hliLT);
  chkcmpjmpcr(ci, "bls", hliLTE);
  chkcmpjmpcr(ci, "bhs", hliGTE);
  chkcmpjmpcr(ci, "bhi", hliGT);

  printf("%-8x %-6s %s,%s\n", ci->hli, ci->opc->mnem,
	 crarg(ci->opc->args[0]),
	 crarg(ci->opc->args[1]));
}

/*=====================================================================*
 * Emulator section
 *=====================================================================*/
typedef int64_t val_t;

val_t _getval(struct imap *ci, int arg);
void  _setval(struct imap *ci, int arg, val_t v);
val_t _memread(struct imap *ci, int seg, int base, int index, val_t off, int arg);
void  _memwrite(struct imap *ci, int seg, int base, int index, val_t off, int arg, val_t val);
val_t _popv(struct imap *ci, int arg);
void  _pushv(struct imap *ci, int arg, val_t v);
int   emul(struct imap *ci, const char *m, int op, int dst, int a0, int a1, int a2);

struct regval
{
  union {
    uint8_t  b[2];
    uint16_t w;
    uint32_t d;
    uint64_t q;
  };
};

struct regval   _regs[17];
uint16_t        _sregs[6];
int             _cpuflag;

int _setflag(int flag, int v)
{
  if (v)
    _cpuflag |= flag;
  else
    _cpuflag &= ~flag;
}

int _getflag(int flag)
{
  return !!(_cpuflag & flag);
}

/* Get String direction and size */
int dfsz(int arg, int flg)
{
  int delta = 0;

  arg &= SIZE_MASK;
  if (arg == SIZE_BYTE)
    delta = 1;
  else if (arg == SIZE_WORD || arg == SIZE_SEGREG)
    delta = 2;
  else if (arg == SIZE_DWORD)
    delta = 4;
  else if (arg == SIZE_QWORD)
    delta = 8;
  return (_getflag(flg) ? -delta : delta); 
}

void *memaddr(struct imap *ci, int seg, int base, int index, val_t off)
{
  if (seg)
    off += _getval(ci, seg) * 0x10000;
  if (base)
    off += _getval(ci, base);
  printf("memaddr: %lx\n", off);
  return findmem(off);
}

val_t _memread(struct imap *ci, int seg, int base, int index, val_t off, int sz)
{
  void *ptr;
  
  printf("Read from: %.4x %.4x %.4x %.8llx %c\n",
	 seg, base, index, off, (sz >>16) & 0xFF);
  if ((ptr = memaddr(ci, seg, base, index, off)) != NULL) {
    switch (sz & SIZE_MASK) {
    case SIZE_BYTE:
      return _get8(ptr);
    case SIZE_SEGREG:
    case SIZE_WORD:
      return _get16(ptr);
    case SIZE_DWORD:
      return _get32(ptr);
    case SIZE_QWORD:
      return _get64(ptr);
    }
  }
  printf("nomem\n");
  return 0xCAFEDEADBEEF;
}

void _memwrite(struct imap *ci, int seg, int base, int index, val_t off, int sz, val_t val)
{
  void *ptr;
  
  printf("Write to: %s:[%s %s %.8llx] %c <= %.8llx\n",
	 regname(seg),
	 regname(base),
	 regname(index),
	 off, (sz >> 16) & 0xFF, val);
  if ((ptr = memaddr(ci, seg, base, index, off)) != NULL) {
    switch (sz & SIZE_MASK) {
    case SIZE_BYTE:
      _put8(ptr, val);
      break;
    case SIZE_SEGREG:
    case SIZE_WORD:
      _put16(ptr, val);
      break;
    case SIZE_DWORD:
      _put32(ptr, val);
      break;
    case SIZE_QWORD:
      _put64(ptr, val);
      break;
    default:
      printf("nomem\n");
    }
    dump(ptr, 16, "write", 3);
  }
}

void readptr(struct imap *ci, int seg, int a0, int a1)
{
  _setval(ci, a0, _memread(ci, 0, 0, 0, 0, a0));
  _setval(ci, seg,_memread(ci, 0, 0, 0, 0, dfsz(a0,0)));
}

void _pushv(struct imap *ci, int arg, val_t v)
{
  val_t off;

  off = _getval(ci, rvSP);
  printf("dfsz: %c = %d\n", arg >> 16, dfsz(arg, 0));
  _setval(ci, rvSP, off - dfsz(arg, 0));
  _memwrite(ci, rSS, 0, 0, off, arg, v);
}

void push(struct imap *ci, int arg)
{
  _pushv(ci, arg, _getval(ci, arg));
}

val_t _popv(struct imap *ci, int arg)
{
  val_t off;

  off = _getval(ci, rvSP);
  _setval(ci, rvSP, off + dfsz(arg, 0));
  return _memread(ci, rSS, 0, 0, off, arg);
}

void pop(struct imap *ci, int arg)
{
  _setval(ci, arg, _popv(ci, arg));
}

/*================================================================*
 * SET/GET
 *================================================================*/
void _setval(struct imap *ci, int arg, val_t v)
{
  int vv,sz,ty;
  val_t dx,ax;

  if (arg == rvIP)
    arg = rIP;
  ty = arg & TYPE_MASK;
  vv = arg & VAL_MASK;
  sz = getsz(arg & SIZE_MASK, &ci->sz);
  switch (ty) {
  case TYPE_REG:
    if (sz == SIZE_BYTE)
      _regs[vv & 3].b[vv >> 2] = v;
    else if (sz == SIZE_WORD)
      _regs[vv].w = v;
    else if (sz == SIZE_DWORD)
      _regs[vv].d = v;
    else if (sz == SIZE_QWORD)
      _regs[vv].q = v;
    else if (sz == SIZE_HWORD) {
      _regs[vv].w   = v;
      _regs[vv+1].w = v >> 16;
    }
    else if (sz == SIZE_SEGREG)
      _sregs[vv] = v;
    break;
  case TYPE_DXAX:
    /* Special case DX:AX for muldiv */
    if (sz == SIZE_WORD) {
      _setval(ci, rvAX, (uint16_t)v);
      _setval(ci, rvDX, v >> 16);
    } else if (sz == SIZE_DWORD) {
      _setval(ci, rvAX, (uint32_t)v);
      _setval(ci, rvDX, v >> 32);
    }
    break;
  case TYPE_ESDI:
    _memwrite(ci, rES, rvDI, 0, 0, sz, v);
    _setval(ci, rvDI, _getval(ci, rvDI) + dfsz(sz, fDF));
    break;
  case TYPE_DSSI:
    _memwrite(ci, rDS, rvSI, 0, 0, sz, v);
    _setval(ci, rvSI, _getval(ci, rvSI) + dfsz(sz, fDF));
    break;
  case TYPE_CPUFLAG:
    _setflag(vv, v);
    break;
  case TYPE_EAMEM:
  case TYPE_OFFSET:
    _memwrite(ci, ci->seg, 0, 0, ci->offv, sz, v);
    break;
  default:
    printf("unk setval : %.8x %c%c\n", arg, ot(arg));
    break;
  }
}

val_t _getval(struct imap *ci, int arg)
{
  int vv,sz,ty,rb;
  val_t off;
  
  if (arg == rvIP)
    arg = rIP;
  ty = arg & TYPE_MASK;
  sz = getsz(arg & SIZE_MASK, &ci->sz);
  vv = arg & VAL_MASK;
  switch (ty) {
  case TYPE_REG:
    if (sz == SIZE_BYTE) 
      return _regs[vv & 3].b[vv >> 2];
    else if (sz == SIZE_WORD)
      return _regs[vv].w;
    else if (sz == SIZE_DWORD)
      return _regs[vv].d;
    else if (sz == SIZE_QWORD)
      return _regs[vv].q;
    else if (sz == SIZE_HWORD) {
      return (_regs[vv].w |
	      _regs[vv+1].w << 16);
    }
    else if (sz == SIZE_SEGREG)
      return _sregs[vv];
    break;
  case TYPE_DXAX:
    if (sz == SIZE_WORD) {
      return (_getval(ci, rvAX) |
	      _getval(ci, rvDX) << 16L);
    } else if (sz == SIZE_DWORD) {
      return (_getval(ci, rvAX) |
	      _getval(ci, rvDX) << 32L);
    }
    break;
  case TYPE_IMMV:
    return vv;
  case TYPE_IMM:
  case TYPE_JMP:
    return ci->immv;
  case TYPE_ESDI:
    /* Get DI value, inc/dec, read memory */
    off = _getval(ci, rvDI);
    _setval(ci, rvDI, off + dfsz(sz, fDF));
    return _memread(ci, rES, 0, 0, off, arg);
  case TYPE_DSSI:
    /* Get SI value, inc/dec, read memory */
    off = _getval(ci, rvSI);
    _setval(ci, rvSI, off + dfsz(sz, fDF));
    return _memread(ci, rDS, 0, 0, off, arg);
  case TYPE_MEMORY:
    arg = mkreg(SIZE_WORD, vv, 0);
    return _memread(ci, ci->seg, arg, 0, ci->offv, sz);
  case TYPE_OFFSET:
    return _memread(ci, ci->seg, 0, 0, ci->offv, sz);
  case TYPE_CPUFLAG:
    if (vv == 0xFFFF)
      vv = -1;
    return _getflag(vv);
  }
  printf("unk getval : %.8x %c%c\n", arg, ot(arg));
  return 0;
}

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

void showregs_x86(struct imap *ci)
{
  int i;
  void *ptr;

  printf("============== regs\n");
  for (i = rRAX; i <= rRDI; i++) {
    printf("%3s: %.16llx ", regname(i), _getval(ci, i));
  }
  printf("\n");
  for (i = rR8; i <= rR15; i++) {
    printf("%3s: %.16llx ", regname(i), _getval(ci, i));
  }
  printf("\n");
  for (i = rES; i <= rGS; i++)
    printf("%3s: %.8lx ", regname(i), _getval(ci, i));
  printf("\n");
  printf("Flags: ----oditsz-a-p-c  EIP: %.8lx\n",
	 _getval(ci, rvIP));
  printf("       ----%d%d%d%d%d%d-%d-%d-%d\n",
	 !!(_cpuflag& fOF),
	 !!(_cpuflag& fDF),
	 !!(_cpuflag& fIF),
	 !!(_cpuflag& fTF),
	 !!(_cpuflag& fSF),
	 !!(_cpuflag& fZF),
	 !!(_cpuflag& fAF),
	 !!(_cpuflag& fPF),
	 !!(_cpuflag& fCF));
}

int _parity(val_t v)
{
  val_t y;

  y = v ^ (v >> 1);
  y = y ^ (y >> 2);
  y = y ^ (y >> 4);
  return y & 1;
}

void _emumath(struct imap *ci, int dst, val_t a, val_t b, val_t v)
{
  val_t mask = 0;

  switch (dst & SIZE_MASK) {
  case SIZE_BYTE:
    mask = 0x80;
    break;
  case SIZE_WORD:
    mask = 0x8000;
    break;
  case SIZE_DWORD:
    mask = 0x80000000;
    break;
  case SIZE_QWORD:
    mask = 0x8000000000000000LL;
    break;
  }
  printf("'mask: %llx  v:%llx v:%llx\n", mask, v, v & mask);
  _setflag(fSF, (v & mask));
  mask <<= 1;
  /* note: what about 64-bit: add, shift, sub, mul */
  _setflag(fCF, (v & mask));
  mask--;
  _setflag(fZF, !(v & mask));
  _setflag(fPF, _parity(v));
  _setval(ci, dst, v);
}

int isemu(struct imap *i, int n, ...)
{
  va_list ap;

  va_start(ap, n);
  while(n--) {
    if (!strcmp(i->opc->mnem, va_arg(ap, char *))) {
      ((struct opcode *)i->opc->data)->flag |= FLAG_EMU;
      return 1;
    }
  }
  return 0;
}

int emul(struct imap *ci, const char *m, int op, int dst, int a0, int a1, int a2)
{
  val_t a, b, c;
  int sz;

  if (strcmp(ci->opc->mnem, m))
    return 0;
  switch (op) {
  case hliMUL:
    a = _getval(ci, a0);
    b = _getval(ci, a1);
    c = _getval(ci, a2);
    printf("@MUL : %c\n", (a0 & SIZE_MASK) >> SIZE_SHIFT);
    /* Special MUL+ADD */
    _emumath(ci, dst, a, b, a*b+c);
    break;
  case hliDIV:
    /* Special case: dst = a1/a2. a0 = a1%a2; */
    printf("@DIV : %c\n", (a0 & SIZE_MASK) >> SIZE_SHIFT);
    a = _getval(ci, a1);
    b = _getval(ci, a2);
    if (b) {
      _emumath(ci, dst, a, b, a/b);
      _setval(ci, a0, a%b);
    }
    break;
  case hliADD:
    /* coszap */
    a = _getval(ci, a0);
    b = _getval(ci, a1);
    c = _getval(ci, a2);
    if (c)
      printf("ADC: %.8llx %.8llx %.8llx\n", a, b, c);
    _emumath(ci, dst, a, b, a+b+c);
    break;
  case hliSUB:
    /* coszap */
    a = _getval(ci, a0);
    b = _getval(ci, a1);
    c = _getval(ci, a2);
    if (c)
      printf("SBB: %.8llx %.8llx %.8llx\n", a, b, c);
    _emumath(ci, dst, a, b, a-b-c);
    break;
  case hliNEG:
    a = _getval(ci, a0);
    _emumath(ci, dst, a, 0, -a);
    break;
  case hliAND:
    /* oc=0,a=?,szp */
    a = _getval(ci, a0);
    b = _getval(ci, a1);
    _emumath(ci, dst, a, b, a&b);
    break;
  case hliOR:
    /* oc=0,a=?,szp */
    a = _getval(ci, a0);
    b = _getval(ci, a1);
    _emumath(ci, dst, a, b, a|b);
    break;
  case hliXOR:
    /* oc=0,a=?,szp */
    a = _getval(ci, a0);
    b = _getval(ci, a1);
    _emumath(ci, dst, a, b, a^b);
    break;
  case hliSHR:
    /* coszap */
    a = _getval(ci, a0);
    b = _getval(ci, a1);
    _emumath(ci, dst, a, b, a>>b);
    break;
  case hliSHL:
    /* coszap */
    a = _getval(ci, a0);
    b = _getval(ci, a1);
    _emumath(ci, dst, a, b, a<<b);
    break;
  case hliNOT:
    /* no flags */
    a = _getval(ci, a0);
    _setval(ci, dst, ~a);
    break;
  case hliASSIGN:
    /* no flags */
    a = _getval(ci, a0);
    _setval(ci, dst, a);
    break;
  case hliSIGNEX:
    /* Sign extend value */
    printf("@@@ SIGNEX\n");
    switch (getsz(a0, &ci->sz) & SIZE_MASK) {
    case SIZE_BYTE:
      a = (int8_t)_getval(ci, a0);
      break;
    case SIZE_WORD:
      a = (int16_t)_getval(ci, a0);
      break;
    case SIZE_DWORD:
      a = (int32_t)_getval(ci, a0);
      break;
    }
    _setval(ci, dst, a);
    break;
  case hliXCHG:
    /* no flags */
    a = _getval(ci, a0);
    b = _getval(ci, a1);
    _setval(ci, a0, b);
    _setval(ci, a1, a);
    break;
  case hliJCC: /* a0 = cond, a1 = true addr, a2 = false addr */
    a = _getval(ci, a0);
    b = _getval(ci, a1);
    c = _getval(ci, a2);
    printf("jcc: %x %x %x\n", a, b, c);
    _setval(ci, rvIP, a ? b : c);
    printf("new jcc: %x\n", _getval(ci, rvIP));
    break;
  }
  return 1;
}

void _emucc(struct imap *i, const char *op, int cond)
{
  if (!strcmp(i->opc->mnem, op) && cond) {
    ((struct opcode *)i->opc->data)->flag |= FLAG_EMU;
    printf("emucc:%s\n", op);
    _setval(i, rvIP, i->immv);
  }
}

int emuarg(struct imap *i, int arg)
{
  if (arg >= _a0 && arg <= _a2)
    return i->opc->args[arg - _a0];
  return arg;
}

int runemu(struct imap *i, struct emutab *etab)
{
  while (etab->mnem) {
    if (emul(i, etab->mnem, etab->hli, emuarg(i, etab->dst),
	     emuarg(i, etab->arg0), emuarg(i, etab->arg1),
	     emuarg(i, etab->arg2))) {
      ((struct opcode *)i->opc->data)->flag |= FLAG_EMU;
      return 1;
    }
    etab++;
  }
  return 0;
}

/*=====================================================*
 * CR16 emutab
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

/*============================================================
 * ARM emulator
 *   mul: Rd = Rm * Rs
 *   mla: Rd = Rm * Rs + Rn
 *  mull: Hi:Lo = Rm * Rs
 *  mlal: Hi:Lo = Rm * Rs + Hi:Lo
 *============================================================*/
struct emutab armetab[] = {
  { "and", hliAND,   _a0, _a1, _a2, 0 },
  { "eor", hliXOR,   _a0, _a1, _a2, 0 },
  { "sub", hliSUB,   _a0, _a1, _a2, 0 },
  { "rsb", hliSUB,   _a0, _a2, _a1, 0 },
  { "add", hliADD,   _a0, _a1, _a2, 0 },
  { "adc", hliADD,   _a0, _a1, _a2, rCF },
  { "sbc", hliSUB,   _a0, _a1, _a2, rCF },
  { "rsc", hliSUB,   _a0, _a2, _a1, rCF },
  { "orr", hliOR,    _a0, _a1, _a2, 0 },
  { "mov", hliASSIGN,_a0, _a1,   0, 0 },
  { "mvn", hliNOT,   _a0, _a1,   0, 0 },
  { "teq", hliXOR,    0,  _a1, _a2, 0 },
  { "tst", hliAND,    0,  _a1, _a2, 0 },
  { "cmn", hliADD,    0,  _a1, _a2, 0 },
  { "cmp", hliSUB,    0,  _a1, _a2, 0 },
  { "mul", hliMUL,   _a0, _a1, _a2, 0 },  /* Rd = Rm * Rs */
  { "ldr", hliASSIGN,_a0, _a1, 0, 0 },
  { "ldrb",hliASSIGN,_a0, _a1, 0, 0 },
  { "str", hliASSIGN,_a1, _a0, 0, 0 },
  { "strb",hliASSIGN,_a1, _a0, 0, 0 },
  { },
};

extern const char *aregs[];

/* GEN: Rn, Rd, Op2 */
void armemu(struct imap *i)
{
  val_t a, b;
  int a0 = i->opc->args[0];
  int a1 = i->opc->args[1];
  int a2 = i->opc->args[2];
  int k;

  for (k = 0; k<16; k++) {
    printf("%3s: %.8x ", aregs[k], _regs[k].d);
    if ((k & 0x7) == 7)
      printf("\n");
  }
  if (runemu(i, armetab))
    return;
  /* Special case for BIC */
  if (isemu(i, 1, "bic")) {
    a = _getval(i, a1);
    b = _getval(i, a2);
    _setval(i, a0, a & ~b);
  }
  if (isemu(i, 1, "mla")) {
    a = _getval(i, a1);
    b = _getval(i, a2);
  }
}
/*============================================================
 * X86 emulator
 *============================================================*/
struct emutab x86emutab[] = {
  { "nop" },
  { "add", hliADD,   _a0, _a0, _a1, _a2 },
  { "or",  hliOR,    _a0, _a0, _a1, _a2 },
  { "adc", hliADD,   _a0, _a0, _a1, rCF },
  { "sbb", hliSUB,   _a0, _a0, _a1, rCF },
  { "and", hliAND,   _a0, _a0, _a1, _a2 },
  { "sub", hliSUB,   _a0, _a0, _a1, _a2 },
  { "xor", hliXOR,   _a0, _a0, _a1, _a2 },
  { "cmp", hliSUB,     0, _a0, _a1, _a2 },

  { "test",hliAND,     0, _a0, _a1, _a2 },
  { "xchg",hliXCHG,    0, _a0, _a1, _a2 },
  { "not", hliNOT,   _a0, _a0, _a1, _a2 },
  { "neg", hliNEG,   _a0, _a0, _a1, _a2 },
  { "shl", hliSHL,   _a0, _a0, _a1, _a2 },
  { "shr", hliSHR,   _a0, _a0, _a1, _a2 },
  { "sar", hliSHR,   _a0, _a0, _a1, _a2 },
  { "inc", hliADD,   _a0, _a0,  i1,  0 },
  { "dec", hliSUB,   _a0, _a0,  i1,  0 },
  { "mov", hliASSIGN,_a0, _a1,  0,   0 },

  { "movsb",hliASSIGN, _a0, _a1, 0, 0 },
  { "movsv",hliASSIGN, _a0, _a1, 0, 0 },
  { "stosb",hliASSIGN, _a0, _a1, 0, 0 },
  { "stosv",hliASSIGN, _a0, _a1, 0, 0 },
  { "lodsb",hliASSIGN, _a0, _a1, 0, 0 },
  { "lodsv",hliASSIGN, _a0, _a1, 0, 0 },
  { "cmpsb",hliSUB,    0,  _a0, _a1, _a2 },
  { "cmpsv",hliSUB,    0,  _a0, _a1, _a2 },
  { "scasb",hliSUB,    0,  _a0, _a1, _a2 },
  { "scasv",hliSUB,    0,  _a0, _a1, _a2 },

  { "clc",  hliASSIGN, rCF, i0, 0, 1 },
  { "stc",  hliASSIGN, rCF, i1, 0, 1 },
  { "cmc",  hliXOR,    rCF, i1, 0, 1 },
  { "cld",  hliASSIGN, rDF, i0, 0, 1 },
  { "std",  hliASSIGN, rDF, i1, 0, 1 },
  { "cli",  hliASSIGN, rIF, i0, 0, 1 },
  { "sti",  hliASSIGN, rIF, i1, 0, 1 },

  /* JCC: Arg0 = cond, Arg0 = True, Arg1 = False */
  { "jcxz", hliJCC,    0, rCX,     rvIP, _a0 },
  { "jo",   hliJCC,    0, rOF,     _a0, rvIP },
  { "jno",  hliJCC,    0, rOF,     rvIP, _a0 },
  { "js",   hliJCC,    0, rSF,     _a0, rvIP },
  { "jns",  hliJCC,    0, rSF,     rvIP, _a0 },
  { "je",   hliJCC,    0, rZF,     _a0, rvIP },
  { "jne",  hliJCC,    0, rZF,     rvIP, _a0 },
  { "jb",   hliJCC,    0, rCF,     _a0, rvIP },
  { "jae",  hliJCC,    0, rCF,     rvIP, _a0 },
  { "jpo",  hliJCC,    0, rPF,     _a0, rvIP },
  { "jpe",  hliJCC,    0, rPF,     rvIP, _a0 },
  { "jbe",  hliJCC,    0, rCF|rZF, _a0, rvIP },
  { "ja",   hliJCC,    0, rCF|rZF, rvIP, _a0 },

  { "lahf", hliASSIGN, rAL, rbFLAGS, 0, 0 },
  { "cwd",  hliSIGNEX, rvDAX, rvAX,  0, 0 },
  { "movzx",hliASSIGN, _a0, _a1, 0, 0 },
  { "movsx",hliSIGNEX, _a0, _a1, 0, 0 },
  { },
};

void x86emu(struct imap *i)
{
  int a0, a1, a2, dst, sz;
  val_t v, r, ax;
  const char *mnem;
  struct sym *sym;
  
  /* Run basic emulator table */
  //showregs_x86(i);
  if (runemu(i, x86emutab)) {
    return;
  }
  printf("@@@@@@@@@@@ NOT EMU\n");
  mnem = i->opc->mnem;
  a0 = i->opc->args[0];
  a1 = i->opc->args[1];
  a2 = i->opc->args[2];

  sz = a0 & SIZE_MASK;
  if (isemu(i, 1, "rcl")) {
    v = _getval(i, a0);
    r = _getval(i, a1);
  }
  if (isemu(i, 1, "lea")) {
    _setval(i, a0, i->offv);
  }
  if (isemu(i, 1, "lds")) {
    readptr(i, rDS, a0, a1);
  }
  if (isemu(i, 1, "les")) {
    readptr(i, rES, a0, a1);
  }
  if (isemu(i, 1, "lfs")) {
    readptr(i, rFS, a0, a1);
  }
  if (isemu(i, 1, "lgs")) {
    readptr(i, rGS, a0, a1);
  }
  if (isemu(i, 1, "lss")) {
    readptr(i, rSS, a0, a1);
  }
  if (isemu(i, 1, "xlat")) {
    _setval(i, rAL, _memread(i, 0, rBX, rAL, 0, SIZE_BYTE));
  }
  if (isemu(i, 1, "loop")) {
    v = _getval(i, rvCX);
    _setval(i, rvCX, --v);
    if (v)
      _setval(i, rvIP, _getval(i, a0));
  }
  if (isemu(i, 1, "loopz")) {
    v = _getval(i, rvCX);
    _setval(i, rvCX, --v);
    if (v && _getflag(fZF))
      _setval(i, rvIP, _getval(i, a0));
  }
  if (isemu(i, 1, "loopnz")) {
    v = _getval(i, rvCX);
    _setval(i, rvCX, --v);
    if (v && !_getflag(fZF))
      _setval(i, rvIP, _getval(i, a0));
  }
  if (isemu(i, 1, "cbw")) {
    /* AX <- AL
     * EAX <- AX
     * RAX <- EAX
     */
    if (i->sz == SIZE_WORD)
      _setval(i, rvAX, (int8_t)_getval(i, rAL));
    else if (i->sz == SIZE_DWORD)
      _setval(i, rvAX, (int16_t)_getval(i, rAX));
    else if (i->sz == SIZE_QWORD)
      _setval(i, rvAX, (int32_t)_getval(i, rEAX));
  }
  if (isemu(i, 1, "pusha")) {
    v = _getval(i, rvSP);
    push(i, rvAX);
    push(i, rvCX);
    push(i, rvDX);
    push(i, rvBX);
    _pushv(i, rvSP, v);
    push(i, rvBP);
    push(i, rvSI);
    push(i, rvDI);
  }
  if (isemu(i, 1, "popa")) {
    pop(i, rvDI);
    pop(i, rvSI);
    pop(i, rvBP);
    _popv(i, rvSP); // don't store anywhere
    pop(i, rvBX);
    pop(i, rvDX);
    pop(i, rvCX);
    pop(i, rvAX);
  }
  if (isemu(i, 1, "mul")) {
    if (sz == SIZE_BYTE) {
      // F6.4 mul: AX = AL * Eb
      emul(i, mnem, hliMUL, rAX, rAL, a0, 0);
    } else {
      // F7.4 mul: DX:AX = AX * Ew
      // F7.4 mul: EDX:EAX = EAX * Ed
      // F7.4 mul: RDX:RAX = RAX * Eq
      emul(i, mnem, hliMUL, rvDAX, rvAX, a0, 0);
    }
    return;
  }
  if (isemu(i, 1, "imul")) {
    if (a2) {
      // 69/6B Ev = Gv * Ib/Iz
      emul(i, mnem, hliMUL, a0, a1, a2, 0);
    } else if (sz == SIZE_BYTE) {
      // F6.5 mul: AX = AL * Eb
      emul(i, mnem, hliMUL, rAX, rAL, a0, 0);
    } else {
      // F7.5 imul: DX:AX = AX * Ew
      // F7.5 imul: EDX:EAX = EAX * Ed
      // F7.5 imul: RDX:RAX = RAX * Eq
      emul(i, mnem, hliMUL, rvDAX, rvAX, a0, 0);
    }
    return;
  }
  if (isemu(i, 1, "div")) {
    if (sz == SIZE_BYTE)
      emul(i, mnem, hliDIV, rAL, rAH, rAX, a0); /* rAL=AX/a0; rAH=AX%a0 */
    else
      emul(i, mnem, hliDIV, rvAX, rvDX, rvDAX, a0); /* rAL=AX/a0; rAH=AX%a0 */
    return;
  }
  if (isemu(i, 1, "idiv")) {
    if (sz == SIZE_BYTE) {
      // F6.7 idiv: AL = AX / rm8 ; AH = AX % Eb
      emul(i, mnem, hliDIV, rAL, rAH, rAX, a0);
    }
    else {
      // F7.7 idiv: AX = DX:AX / rm16 ; DX = DX:AX % Ew
      // F7.7 idiv: EAX = EDX:EAX / rm32 ; EDX = EDX:EAX % Ed
      // F7.7 idiv: RAX = RDX:RAX / rm64 ; RDX = RDX:RAX % Eq
      emul(i, mnem, hliDIV, rvAX, rvDX, rvDAX, a0);
    }
    return;
  }
  _emucc(i, "jl",  _getflag(fSF) != _getflag(fOF));
  _emucc(i, "jge", _getflag(fSF) == _getflag(fOF));
  _emucc(i, "jle", _getflag(fZF) || (_getflag(fSF) != _getflag(fOF)));
  _emucc(i, "jg",  !_getflag(fZF) && (_getflag(fSF) == _getflag(fOF)));

  if (isemu(i, 1, "sahf")) {
    _cpuflag &= ~0xFF;
    _cpuflag |= _getval(i, rAH);
  }
  if (isemu(i, 1, "push"))
    push(i, a0);
  if (isemu(i, 1, "pop"))
    pop(i, a0);
  if (isemu(i, 1, "pushf"))
    _pushv(i, 0, _cpuflag);
  if (isemu(i, 1, "popf"))
    _cpuflag = _popv(i, 0);
  if (isemu(i, 1, "iret")) {
    pop(i, rvIP);
    pop(i, rCS);
    _cpuflag = _popv(i, i->sz);
    return;
  }
  if (isemu(i, 1,"retf")) {
    pop(i, rvIP);
    pop(i, rCS);
    return;
  }
  if (isemu(i, 1,"ret")) {
    pop(i, rvIP);
    return;
  }
  if (isemu(i, 1, "call")) {
    int jt = tt(i->opc->args[0]);
    
    // Jv
    // Ap
    // Ev near
    // Mp far
    if (jt == TYPE_JMP) {
      push(i, rvIP);
      _setval(i, rvIP, i->immv);
    }
    if (jt == TYPE_ABSPTR) {
      sym = findSym(i->immv);
      if (sym && (sym->flag & 0x1000)) {
	printf("Calling import: '%s'\n", sym->name);
      }
      else {
	push(i, rCS);
	push(i, rvIP);
	_setval(i, rvIP, i->immv & 0xFFFF);
	_setval(i, rCS, i->immv / 0x10000);
      }
    }
  }
  if (isemu(i, 1, "jmp")) {
    int jt = tt(i->opc->args[0]);
    
    // Jb
    // Jv
    // Ap
    // Ev near
    // Mp far
    if (jt == TYPE_JMP) {
      _setval(i, rvIP, i->immv);
    }
  }
  if (isemu(i, 1, "rcl")) {
    v = _getval(i, a0);
    r = _getval(i, a1);
    if (sz == SIZE_BYTE) {
    }
  }
  /* BCD operations */
  if (isemu(i, 1, "daa")) {
  }
  if (isemu(i, 1, "das")) {
  }
  if (isemu(i, 1, "aaa")) {
    v = _getval(i, rAL);
    if ((v & 0xF) > 9 || _getflag(fAF)) {
      v += 6;
      _setval(i, rAH, _getval(i, rAH) + 1);
      _setflag(fCF, 1);
      _setflag(fAF, 1);
    } else {
      _setflag(fCF, 0);
      _setflag(fAF, 0);
    }
    _setval(i, rAL, v & 0xF);
    return;
  }
  if (isemu(i, 1, "aas")) {
    v = _getval(i, rAL);
    if ((v & 0xF) > 9 || _getflag(fAF)) {
      v = v-6;
      _setval(i, rAH, _getval(i, rAH) - 1);
      _setflag(fCF, 1);
      _setflag(fAF, 1);
    }
    else {
      _setflag(fCF, 0);
      _setflag(fAF, 0);
    }
    _setval(i, rAL, v & 0xF);
    return;
  }
  if (isemu(i, 1, "aam")) {
    emul(i, mnem, hliDIV, rAH, rAL, a0, 0);
  }
  if (isemu(i, 1, "aad")) {
    v = _getval(i, rAL) + _getval(i, rAH) * _getval(i, a0);
    _setval(i, rAX, v & 0xFF);
  }
}

#define fntype(x) "void"
#define fnargs(x) "void"

int getcc(const char *str)
{
  if (!strcmp(str, "e"))
    return hliEQ;
  if (!strcmp(str, "ne"))
    return hliNEQ;
  if (!strcmp(str, "l"))
    return hliLTs;
  if (!strcmp(str, "le"))
    return hliLTEs;
  if (!strcmp(str, "ge"))
    return hliGTEs;
  if (!strcmp(str, "g"))
    return hliGTs;
  if (!strcmp(str, "b"))
    return hliLT;
  if (!strcmp(str, "be"))
    return hliLTE;
  if (!strcmp(str, "ae"))
    return hliGTE;
  if (!strcmp(str, "a"))
    return hliGT;
  return 0;
}

const char *getfnret(struct imap *ci)
{
  struct sym  *sym;
  struct type *tt;
  
  sym = findSym(ci->immv);
  if (sym == NULL)
    return "";
  if ((tt = findType(sym->name)) != NULL) {
    if ((tt->rtype & PTR) || (tt->rtype == LONG)) {
      setexpr(ci, rvDAX, mkstr(sym->name));
      return "P_dxax = ";
    }
    else if (tt->rtype != VOID) {
      setexpr(ci, rvAX, mkstr(sym->name));
      return "P_ax = ";
    }
  }
  return "";
}

const char *getfnargs(struct imap *ci, int npush, char *stack[])
{
  static char strargs[128];
  struct type *tt;
  int i;

  strargs[0] = 0;
  if ((tt = findType(getSymName(NULL, ci->immv))) != NULL) {
    for (i = 0; i < tt->narg; i++) {
      if (i) strcat(strargs, ", ");
      if (npush >= tt->narg+i)
	strcat(strargs, stack[npush-tt->narg+i]);
      else
	strcat(strargs, "blah");
    }
    return strargs;
  }
  return strargs;
}

void setign(struct imap *ci, int n)
{
  while (n--) {
    ci->hli = hliIGNORE;
    ci = nxt(ci, 1);
  }
}

const char *ifOp(struct imap *ci)
{
  static char str[128];
  struct imap *ni;
  int hli;

  str[0] = 0;
  ni = nxt(ci, 1);
  hli = getcc(ni->opc->mnem+1);
  if (opeq(ci, "cmp", 0, 0, 0)) {
    snprintf(str, sizeof(str), "%s %s %s", ota1(ci), hlit(hli), ota2(ci));
  }
  else if (opeq(ci, "or", ci->opc->args[1], 0, 0)) {
    snprintf(str, sizeof(str), "%s %s 0", ota1(ci), hlit(hli));
  }
  else if (opeq(ci, "test", 0, 0, 0)) {
    snprintf(str, sizeof(str), "(%s & %s) %s 0", ota1(ci), ota2(ci), hlit(hli));
  }
  return str;
}

int _chklong(struct imap *ci, const char *op1, const char *op2, int hli)
{
  struct imap *ni;

  ni = nxt(ci, 1);
  if (opeq(ci, op1, 0, 0, 0) && opeq(ni, op2, 0, 0, 0)) {
    printf("mklong(%s,", ota1(ni));
    printf("%s) %s= mklong(%s,", ota1(ci), hlit(hli), ota2(ni));
    printf(",%s)\n", ota2(ci));
    return 1;
  }
  return 0;
}

int _chkhliarm(struct imap *ci)
{
  struct imap *ni, *nni;
  
  ni = nxt(ci, 1);
  nni = nxt(ni, 1);
  if (opeq(ci, "ldrb", ci->opc->args[0], 0, 0) &&
      opeq(ni, "ldrb", ni->opc->args[0], 0, 0) &&
      opeq(nni,"orr",  0, ci->opc->args[0], ci->opc->args[1])) {
    /* MovW rx, [mem] */
    return 3;
  }
  if (opeq(ci, "mov", ci->opc->args[0], TYPE_IMM, 0) &&
      opeq(ni, "str", ci->opc->args[0], 0, 0)) {
    /* MovD [mem], Imm */
  }
  if (opeq(ci, "mov",  ci->opc->args[0], TYPE_IMM, 0) &&
      opeq(ni, "strb", ci->opc->args[0], 0, 0) &&
      opeq(nni,"strb", ci->opc->args[0], 0, 0)) {
    /* MovW [mem], Imm */
  }
}

int _chkhli(struct imap *ci)
{
  struct imap *ni, *nni;
  const char *o1 = strdup(ota1(ci));
  const char *o2 = strdup(ota2(ci));
  int i1, i2;
  int a0, a1, a2;
  struct expr *e;
  
  ni = nxt(ci, 1);
  nni = nxt(ni, 1);
  if (ci->hli == hliIGNORE)
    return 1;
  if (opeq(ci, "enter", 0, 0, 0)) {
    return 1;
  }
  if (opeq(ci, "leave", 0, 0, 0) &&
      opeq(ni, "ret", 0, 0, 0)) {
    return 2;
  }
  if (opeq(ci, "jmp", 0, 0, 0)) {
    return 1;
  }

  a0 = ci->opc->args[0];
  a1 = ci->opc->args[1];
  a2 = ci->opc->args[2];
  
  /* Check long operations */
  if (_chklong(ci, "add", "adc", hliADD))
    return 2;
  if (_chklong(ci, "sub", "sbb", hliSUB))
    return 2;
  if (_chklong(ci, "shl", "rcl", hliSHL))
    return 2;
  if (_chklong(ci, "shr", "rcr", hliSHR))
    return 2;
  if (_chklong(ci, "sar", "rcr", hliSHR))
    return 2;
  if (opeq(ci, "call", 0, 0, 0) &&
      opeq(ni, "add", rSP, Ib, 0)) {
    setign(ni, 1);
    return 0;
  }

  /* Tristate */
  if (opeq(ci,  "cmp", 0, 0, 0) &&
      opeq(ni,  "sbb", ni->opc->args[1], 0, 0) &&
      opeq(nni, "neg", ni->opc->args[1], 0, 0)) {
    ci->expr = mktri(mkexpr(hliEQ, getexpr(ci, a0), getexpr(ci, a1)),
		     mkint(0), mkint(1));
    setexpr(ci, nni->opc->args[0], ci->expr);
    printf("%s = ((%s == %s) ? 0 : 1); // tria\n",
	   ota1(ni), o1, o2);
    return 3;
  }
  /* tristate-integer: ? a : a+1 */
  if (opeq(ci, "cmp", 0, 0, 0) &&
      opeq(ni, "sbb", ni->opc->args[1], 0, 0) &&
      opeq(nni,"add", ni->opc->args[1], 0, 0)) {
    i1 = nni->immv;
    ci->expr = mktri(mkexpr(hliEQ, getexpr(ci, a0), getexpr(ci, a1)),
		     mkint(i1), mkint(i1-1));
    setexpr(ci, nni->opc->args[0], ci->expr);
    printf("%s = ((%s == %s) ? %d : %d); // trib\n",
	   ota1(ni), o1, o2, i1, i1-1);
    return 3;
  }
  /* tristate-integer: ? a : b */
  if (opeq(ci, "cmp", 0, 0, 0) &&
      opeq(ni, "sbb", ni->opc->args[1], 0, 0) &&
      opeq(nni,"and", ni->opc->args[1], 0, 0) &&
      opeq(nxt(ci, 3), "add", ni->opc->args[1], 0, 0)) {
    i1 = nni->immv;
    i2 = nxt(ci, 3)->immv;
    ci->expr = mktri(mkexpr(hliEQ, getexpr(ci, a0), getexpr(ci, a1)),
		     mkint(i1), mkint(i2 + i1));
    setexpr(ci, nni->opc->args[0], ci->expr);
    printf("%s = ((%s == %s) ? %d : %x); // tric\n",
	   ota1(ni), o1, o2, i1, i2 + i1);
    return 4;
  }
  /* Check assign to zero */
  if (opeq(ci, "xor", ci->opc->args[1], 0, 0)) {
    setexpr(ci, ci->opc->args[0], mkint(0));
    printf("%s = 0;\n", ota1(ci));
    return 1;
  }
  if (opeq(ci, "test", 0, 0, 0) && tt(ni->opc->args[0]) == TYPE_JMP) {
    ci->expr = mkexpr(getcc(ni->opc->mnem+1), mkexpr(hliAND, getexpr(ci, a0), getexpr(ci, a1)), mkint(0));
    return 2;
  }
  if (opeq(ci, "or", a1, 0, 0) && tt(ni->opc->args[0]) == TYPE_JMP) {
    ci->expr = mkexpr(getcc(ni->opc->mnem+1), getexpr(ci, a0), mkint(0));
    return 2;
  }
  if (opeq(ci, "cmp", 0, 0, 0) && tt(ni->opc->args[0]) == TYPE_JMP) {
    ci->expr = mkexpr(getcc(ni->opc->mnem+1), getexpr(ci, a0), getexpr(ci, a1));
    return 2;
  }
  if (evalemul(ci, "add", hliADD, a0, a0, a1, 0) ||
      evalemul(ci, "sub", hliSUB, a0, a0, a1, 0) ||
      evalemul(ci, "xor", hliXOR, a0, a0, a1, 0) ||
      evalemul(ci, "and", hliAND, a0, a0, a1, 0) ||
      evalemul(ci, "or",  hliOR,  a0, a0, a1, 0))
    return 0;
  if (opeq(ci, "dec", 0, 0, 0)) {
    ci->expr = mkexpr(hliPREDEC, NULL, getexpr(ci, a0));
    setexpr(ci, a0, ci->expr);
  }
  if (evalemul(ci, "mov", hliASSIGN, a0, a1, 0, 0))
    return 1;
  return 0;
}

void _gencode(struct bb *bb, struct imap *imap, int lvl, int sub)
{
  int i1, i2, i, npush = 0, pc, ng;
  char *pushstk[0x32];
  struct imap *ci, *ni, *nni, *pi;

  while (bb) {
    if (bb->start == sub)
      break;
    printf("//-- start: %.8x\n", bb->start);
    for (i = bb->start; i < bb->end; ) {
      const char *oa1 = ota1(&imap[i]);
      const char *oa2 = ota2(&imap[i]);

      pc = i;
      ci = &imap[i];
      ni = nxt(ci, 1);
      nni = nxt(ci, 2);
      i += ci->nb;
#if 0
      /* Check HLI generator */
      ng = _chkhli(ci);
      if (ng > 0) {
	setign(ci, ng);
      }
      if (!strcmp(ci->opc->mnem, "push")) {
	pushstk[npush++] = strdup(oa1);
	//printf("push: %d = %c%c %s\n", npush, ot(ci->opc->args[0]), oa1);
      }
      else if (!strcmp(ci->opc->mnem, "call")) {
	printf("%s%s(%s);\n",
	       getfnret(ci), getSymName(NULL, ci->immv),
	       getfnargs(ci, npush, pushstk));
	npush = 0;
      }
      else {
	printf("@@%.8x %s %s %s;\n", pc, ci->opc->mnem, oa1, oa2);
      }
#else
      printf("@@%.8x %s %s %s;\n", pc, ci->opc->mnem, oa1, oa2);
#endif
    }
    printf("//--- end: %.8x\n", bb->start);
    if (bb->type == bbIF) {
      pi = prv(ci);
      printf("if (");
      showexpr(pi->expr, 0);
      printf(") {\n");
      if (bb->lbl && !strcmp(bb->lbl,"ifret:!X")) {
	_gencode(findbb(bb->edge[1]), imap, lvl+1, -1);
      } else {
	_gencode(findbb(bb->edge[0]), imap, lvl+1, bb->sub);
      }
      printf("}\n");
      if (bb->lbl && !strcmp(bb->lbl, "if-else")) {
	printf("else {\n");
	_gencode(findbb(bb->edge[1]), imap, lvl+1, bb->sub);
	printf("}\n");
      }
      if (lvl)
	return;
      bb = findbb(bb->sub);
    }
    else {
      bb = findbb(bb->edge[0]);
    }
  }
}

void gencode(struct imap *imap)
{
  int i;
  struct bb *bb;
  struct sym *_sym;

  printf("======================= gencode\n");
  addtype(VOID, "__abc", 2, INT, INT);
  addtype(VOID, "CODE21", 2, INT, INT, INT);
  addtype(VOID, "CODE11", 3, INT, INT, INT);
  addtype(VOID, "CODE12", 1, INT);
  addtype(VOID, "CODE13", 1, INT);
  addtype(VOID, "CODE15", 3, INT, INT, INT);
  addtype(VOID, "CODE31", 1, INT);
  for (i = 0; i < nsym; i++) {
    _sym = &symTbl[i];
    if (_sym->flag != 7)
      continue;
    printf("/*==============================================\n");
    printf(" * %s\n", _sym->name);
    printf(" *==============================================*/\n");
    printf("\n%s %s(%s)\n{\n",
	   fntype(_sym->addr),
	   _sym->name,
	   fnargs(_sym->start));
    bb = findbb(_sym->addr);
    _gencode(bb, imap, 0, -1);
    printf("}\n");
  }    
}

void chkfn(struct imap *ci)
{
  struct expr **stk;
  struct imap *pi;
  struct sym *s = NULL;
  int narg, sp = 0;

  pi = prv(ci);
  if (opeq(pi, "call", 0, 0, 0) &&
      opeq(ci, "add",  rSP, Ib, 0)) {
    narg = ci->immv / 2;
    s = findSym(pi->immv);
  }
  else if (opeq(ci, "call", 0, 0, 0)) {
    struct type *t;
    s = findSym(ci->immv);
    if (!s)
      return;
    t = findType(s->name);
    if (!t)
      return;
    narg = t->narg;
  }
  if (!s)
    return;
  
  printf("Function : %s uses %d args\n",
	 s->name, narg);
  stk  = alloca(sizeof(*stk) * narg);
  memset(stk, 0, sizeof(*stk) * narg);
  while (sp < narg && pi) {
    pi = prv(pi);
    if (opeq(pi, "push", Id, 0, 0)) {
      stk[sp++] = mkint(pi->immv & 0xFFFF);
      stk[sp++] = mkint(pi->immv >> 16);
    }
    else if (opeq(pi, "push", Iw, 0, 0) ||
	     opeq(pi, "push", Ib, 0, 0)) {
      stk[sp++] = mkint(pi->immv);
    }
    else if (opeq(pi, "push", 0, 0, 0)) {
      stk[sp++] = mkstr(ota1(pi));
    }
  }
  pi = prv(ci);
  printf("%s(", getSymName(NULL, pi->immv));
  while (sp-- > 0) {
    showexpr(stk[sp], 0);
    printf(", ");
  }
  printf(");\n");
}

int deltaOff(struct imap *ci, struct imap *ni, int n)
{
  if (!ci || !ni)
    return -1;
  return (ci->offv+n == ni->offv);
}

void armhli(struct imap *ci)
{
  struct imap *ppi, *pi;

  pi = prv(ci);
  ppi = prv(pi);
  if (opeq(ppi, "ldrb", 0, 0, 0) &&
      opeq(pi,  "ldrb", 0, 0, 0) && 
      opeq(ci,  "orr",  0, 0, 0) &&
      deltaOff(ppi, pi, 1)) {
    printf("loadw\n");
  }
  if (opeq(ppi, "mov",  0, 0, 0) &&
      opeq(pi,  "strb", 0, 0, 0) &&
      opeq(ci,  "strb", 0, 0, 0) &&
      deltaOff(pi, ci, 1)) {
    printf("storw.imm\n");
  }
  if (opeq(ppi, "strb", 0, 0, 0) &&
      opeq(pi,  "mov",  0, 0, 0) &&
      opeq(ci,  "strb", 0, 0, 0) &&
      deltaOff(ppi, ci, 1)) {
    printf("storw.reg\n");
  }
}

void parsebb(void *_start, int len, int off, uint64_t vbase, int mach)
{
  stack_t stk;
  struct cpu cpu;
  struct opcode *opc;
  int  sBB, ninst, i, j, bb, mode, rst;
  uint8_t *start = _start;
  struct opcode * (*dis)(stack_t *, struct cpu *) = NULL;
  void (*ckhli)(struct imap *) = NULL;
  struct imap *imap;

  _setval(NULL, rDS, 0xDEADCAFEBEEFC0DELL);
  
  _vbase = vbase;
  printf("@@@@@@@@@@@@@@ PARSEBB: %.8llx %.8x %.8x %.6x\n", vbase, len, off, mode);
  stk.vbase = vbase;
  stk.base = start;
  stk.len = len;
  stk.map = malloc(len);
  memset(stk.map, 0, len);
  memset(&cpu, 0, sizeof(cpu));

  imap = calloc(len, sizeof(struct imap));
  imap[0].flag=1;
  
  switch (mach) {
  case MACH_SH4:
    mode = SIZE_WORD;
    dis = _dissh4;
    break;
  case MACH_ARM:
    scanarmfn(&stk);
    mode = SIZE_DWORD;
    dis = _disarm;
    break;
  case MACH_X86_64:
    scan86fn(&stk);
    mode = SIZE_QWORD;
    dis = _dis86;
    ckhli = checkhli_x86;
    break;
  case MACH_X86_32:
    scan86fn(&stk);
    mode = SIZE_DWORD;
    dis = _dis86;
    ckhli = checkhli_x86;
    break;
  case MACH_X86_16:
    scan86fn(&stk);
    mode = SIZE_WORD;
    dis = _dis86;
    ckhli = checkhli_x86;
    break;
  case MACH_CR16:
    mode = SIZE_WORD;
    dis = _discr16;
    ckhli = checkhli_cr16;
#if 0
    for (i = 0; i < 16; i++)
      _setval(NULL, TYPE_REG|SIZE_WORD|i, rand());
#endif
    break;
  default:
    dis = NULL;
    printf("Unknown arch: %x\n", mach);
    exit(0);
    break;
  }
#if 0
  _setval(NULL, rvIP, off);
  _setval(NULL, rDI, 0x1234);
  _setval(NULL, rCX, 32768);
  _setval(NULL, rDS, 0x2);
  _setval(NULL, rSP, 0xFFFE);
  for(;;) {
    off = _getval(NULL, rvIP);
    cpuinit(&cpu, start + off, mode);
    showregs_x86(&imap[off]);
    opc = dis(&stk, &cpu);
    imap[off].opc = opc;
    imap[off].nb  = cpu.nb;
    imap[off].immv = cpu.immv;
    imap[off].offv = cpu.offv;
    imap[off].seg  = cpu.seg;
    imap[off].sz = cpu.osz;
    opc->flag |= FLAG_USED;
    _setval(NULL, rvIP, off + imap[off].nb);
    x86emu(&imap[off]);
  }
  exit(0);
#endif
  _push(&stk, 0x1bbd, "FUNC_BBD");
  for (i = 0; i<nsym; i++) {
    if (symTbl[i].flag & 1)
      _push(&stk, symTbl[i].addr - vbase, symTbl[i].name);
  }
  while (!_pop(&stk, &off, &rst)) {
    printf("\n=================================================== %.8llx[%.8x] <%s>\n",
	   vbase+off, off, getSymName(NULL, vbase+off));
    cpu.start = start;
    sBB = off;
    ninst = 0;
    if (rst)
      resetexpr();
    do {
      cpuinit(&cpu, start + off, mode);
      opc = dis(&stk, &cpu);
      imap[off].opc = opc;
      imap[off].nb  = cpu.nb;
      imap[off].immv = cpu.immv;
      imap[off].offv = cpu.offv;
      imap[off].seg  = cpu.seg;
      imap[off].sz = cpu.osz;
      opc->flag |= FLAG_USED;
      //armhli(&imap[off]);
      //chkfn(&imap[off]);
      //armemu(&imap[off]);
      //x86emu(&imap[off]);
      _setstk(&stk, off, 0x3, cpu.nb);
      off += cpu.nb;
      bb = getbb(&stk, &cpu, opc, sBB, off, ++ninst, mach);
    } while(!bb);
  }
  mergebb(imap);
  showbb();
  dumpstk(&stk);
  dumpstk(&sectTbl[2].stk);
  
#if 0
  if (!ckhli)
    return;
  for (i = 0; i < nbb; i++) {
    struct bb *bb;
    int i1, i2;
    
    bb = &bbTbl[i];
    if (bb->type == bbNONE)
      continue;
    printf("\n@@@@@@@@@@@@@@@@ hligen: %6s %.8lx %d:%d %d %s\n",
	   bbt[bb->type], (uint32_t)(vbase + bb->start),
	   bb->nIn, bb->nOut, bb->nInst,
	   getSymName(NULL, bb->start));
    for (off = bb->start; off < bb->end; ) {
      ckhli(&imap[off]);
      off += imap[off].nb;
    }
  }
#endif

  genvcg(imap);
  gencode(imap);
  dumpsym();
}

extern int readelf(void *, int);
extern int readne(void *, int);
extern int readpe(void *, int);

int main(int argc, char *argv[])
{
  void *buf;
  int fd;
  int sz;
  int off;

  setbuf(stdout, NULL);
  if (argc > 1) {
    openvcg("tdout");
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
      perror("open file");
      exit(0);
    }
    readsym(argv[1]);

    sz = lseek(fd, 0, SEEK_END);
    buf = malloc(sz);
    pread(fd, buf, sz, 0);
    close(fd);

    if (readpe(buf, sz))
      if (readne(buf, sz))
	readelf(buf, sz);

    //showinst(opmap, 256, "x86");
    closevcg();
    exit(0);
  }
  parsebb(getarg, 0x10000, 0x0, (uintptr_t)getarg, sizeof(long));
}

