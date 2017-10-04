/* ne.c - New Executable (Windows 3.1) Loader
 *
 * Copyright (c) 2015-17 Jordan Hargrave<jordan_hargrave@hotmail.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "tinydis.h"
#include "ne.h"

#define BIT(x) (1L << (x))

#define cc(a,b) case a##b: return #b;

void dump(void *buf, int len, const char *sfx, int flag);

static const char *getPascalStr(uint8_t *buf)
{
  static char str[258];
  int len = buf[0];

  memcpy(str, buf+1, len);
  str[len] = 0;
  return str;
}

static const char *ratype(int c)
{
  switch (c) {
    cc(ra,LOBYTE);
    cc(ra,SEL16);
    cc(ra,OFF16);
    cc(ra,PTR32);
    cc(ra,OFF32);
    cc(ra,PTR48);
  }
  return "UNK";
}

static const char *rttype(int c)
{
  switch (c) {
    cc(rt,INTREF);
    cc(rt,IMPORD);
    cc(rt,IMPNAM);
  }
  return "UNK";
}

/* Get DLL Ordinal Name (static string) */
static const char *getOrdName(const char *file, const char *dll, int ord)
{
  static char line[128];
  FILE *fp;
  char  *kd, *ko, *kf;

  if ((fp = fopen(file, "r")) != NULL) {
    while (fgets(line, sizeof(line), fp) != NULL) {
      if (line[0] == ';')
	continue;
      kd = strtok(line, " \t.\n\r");
      ko = strtok(NULL, " \t.\n\r");
      kf = strtok(NULL, " \t.\n\r");
      if (!strcmp(kd, dll) && atoi(ko) == ord)
	return kf;
    }
    snprintf(line, sizeof(line), "%s:%d", dll, ord);
    return line;
  }
}

/* Do reloc fixups */
static void nereloc(ne_reloc *nr, int n, int bseg, void *base, int len, const char *mrt[])
{
  int i;
  uint16_t nro, px;
  uint16_t seg, off;
  int dllImp = (len + 0xF) & ~0xF;
  const char *nsym;
  
  printf("-------------------- Relocs %.4x:%.4x\n", bseg, len);
  for (i = 0; i < n; i++) {
    printf("  %.4x %.2x[%-6s] %.2x[%-6s] ",
	   nr[i].nr_offset,
	   nr[i].nr_rtype, rttype(nr[i].nr_rtype),
	   nr[i].nr_atype, ratype(nr[i].nr_atype));
    nro = nr[i].nr_offset;
    switch (nr[i].nr_rtype) {
    case rtIMPORD:
      seg = bseg;
      off = ++dllImp;
      nsym = getOrdName("win31.dat", mrt[nr[i].imp_ord.mrt-1], nr[i].imp_ord.ord);
      printf("  %s:%d = %s\n", mrt[nr[i].imp_ord.mrt-1], nr[i].imp_ord.ord, nsym);
      addSym(dllImp, 0x1000, NULL, nsym);
      break;
    case rtIMPNAM:
      seg = bseg;
      off = ++dllImp;
      printf("  %.4x[%s]:%.4x\n", nr[i].imp_name.mrt, mrt[nr[i].imp_name.mrt-1], nr[i].imp_name.imp);
      addSym(dllImp, 0x1000, NULL, "impname");
      break;
    case rtINTREF:
      seg = nr[i].iref.seg-1;
      off = nr[i].iref.off;
      printf("  %.4x:%.4x\n", seg, off);
      break;
    default:
      /* Unknown */
      printf("\n");
      continue;
    }
    while (nro != 0xFFFF) {
      px = _get8(base + nro - 1);
      printf("    reloc: %.4x %.2x => %.4x:%.4x [%.4x]\n",
	     nro, px, seg, off, _get16(base + nro));
      px = _get16(base + nro);
      switch (nr[i].nr_atype) {
      case raLOBYTE:
	_put8(base + nro, off);
	break;
      case raSEL16:
	/* 9A Iv Iw
	 * 68 Iz
	 * Bx gv, Iv
	 */
	if (_get8(base + nro - 1) == 0x68) {
	  /* Push Iz */
	  addSym(bseg * 0x10000 + nro - 1, sCOMMENT, NULL, "sel_%x", seg);
	  printf("addsym: %x\n", bseg * 0x10000 + nro - 1);
	}
	_put16(base + nro, seg);
	break;
      case raOFF16:
	_put16(base + nro, off);
	break;
      case raPTR32:
	_put16(base + nro, off);
	_put16(base + nro + 2, seg);
	break;
      case raOFF32:
	_put32(base + nro, off);
	break;
      case raPTR48:
	_put32(base + nro, off);
	_put16(base + nro + 2, seg);
	break;
      }
      nro = px;
    }
  }
}

#define MKADDR(s,o) (((s) << 4) + (o))

struct mz_reloc
{
  uint16_t off;
  uint16_t seg;
};

int intcmp(const void *a, const void *b)
{
  return *(const int *)a - *(const int *)b;
}

int rscmp(const void *a, const void *b)
{
  const struct mz_reloc *ra = a;
  const struct mz_reloc *rb = b;

  return MKADDR(ra->seg,ra->off) - MKADDR(rb->seg,rb->off);
}

/* WIN31 */
#define HWND   INT
#define HANDLE INT
#define HMENU  INT
#define HDC    INT
#define HINSTANCE INT
#define HLOCAL INT
#define HGLOBAL INT
#define HBRUSH INT
#define HPEN INT
#define COLORREF LONG
#define HCURSOR INT
#define BOOL INT
#define HBITMAP INT
#define HPALETTE INT
#define HGDIOBJ INT
#define HRSRC INT
#define MMRESULT INT
#define HWAVEOUT INT
#define LPWAVEOUT INTPTR

void winAPI()
{
  addtype(INT,"MessageBeep",1,INT);
  addtype(INT,"SetSystemPaletteUse",2,HDC,INT); //x
  addtype(INT,"PeekMessage",5,STRUCTPTR,HWND,INT,INT,INT);
  addtype(VOID,"FatalExit",1,INT);
  addtype(LONG,"GetVersion",0);
  addtype(INT,"GetDOSEnvironment",0);
  addtype(INT,"LocalInit",3,INT,INT,INT);
  addtype(HLOCAL,"LocalAlloc",2,INT,INT); //x
  addtype(INT,"GetWindowsDirectory",2,CHARPTR,INT);
  addtype(HLOCAL,"LocalReAlloc",3,HLOCAL,INT,INT); //x
  addtype(HLOCAL,"LocalFree",1,HLOCAL); //x
  addtype(INT,"GetAsyncKeyState",1,SHORT);
  addtype(COLORREF,"SetBkColor",2,HDC,COLORREF); //x
  addtype(VOID,"FatalAppExit",2,INT,CHARPTR);
  addtype(INT,"SetBkMode",2,HDC,INT);
  addtype(INT,"LocalSize",1,HLOCAL);
  addtype(HGLOBAL,"GlobalAlloc",2,INT,LONG); //x
  addtype(INT,"SetTextCharacterExtra",2,HDC,SHORT);
  addtype(HGLOBAL,"GlobalReAlloc",3,HGLOBAL,INT,INT); //x
  addtype(INT,"MessageBox",4,HWND,CHARPTR,CHARPTR,INT);
  addtype(HGLOBAL,"GlobalFree",1,HGLOBAL); //x
  addtype(COLORREF,"SetTextColor",2,HDC,COLORREF); //x
  addtype(VOIDPTR,"GlobalLock",1,HGLOBAL);
  addtype(BOOL,"GlobalUnlock",1,HGLOBAL); //x
  addtype(INT,"GlobalSize",1,HGLOBAL);
  addtype(INT,"LockSegment",1,INT);
  addtype(INT,"UnlockSegment",1,INT);
  addtype(INT,"GlobalCompact",1,LONG);
  addtype(INT,"LineTo",3,HDC,INT,INT);
  addtype(INT,"MoveTo",3,HDC,INT,INT);
  addtype(INT,"GetCursorPos",1,STRUCTPTR);
  addtype(INT,"PatBlt",6,HDC,INT,INT,INT,INT,LONG);
  addtype(HCURSOR,"CreateCursor",7,HINSTANCE,INT,INT,INT,INT,VOIDPTR,VOIDPTR);
  addtype(INT,"SelectPalette",3,HDC,HPALETTE,INT);
  addtype(INT,"BitBlt",9,HDC,INT,INT,INT,INT,HDC,INT,INT,LONG);
  addtype(INT,"RealizePalette",1,HDC);
  addtype(INT,"GetModuleUsage",1,HINSTANCE);
  addtype(INT,"waveOutGetNumDevs",0); //x
  addtype(MMRESULT,"waveOutOpen",6,LPWAVEOUT,INTPTR,STRUCTPTR,LONGPTR,LONGPTR,LONG); //x
  addtype(MMRESULT,"waveOutClose",1,HWAVEOUT); //x
  addtype(MMRESULT,"waveOutPrepareHeader",3,HWAVEOUT,STRUCTPTR,INT); //x
  addtype(MMRESULT,"waveOutUnprepareHeader",3,HWAVEOUT,STRUCTPTR,INT); //x
  addtype(MMRESULT,"waveOutWrite",3,HWAVEOUT,STRUCTPTR,INT); //x
  addtype(MMRESULT,"waveOutPause",1,HWAVEOUT); //x
  addtype(MMRESULT,"waveOutRestart",1,HWAVEOUT); //
  addtype(MMRESULT,"waveOutReset",1,HWAVEOUT); //xx
  addtype(MMRESULT,"waveOutGetVolume",2,HWAVEOUT,LONGPTR);
  addtype(MMRESULT,"waveOutSetVolume",2,HWAVEOUT,LONG);
  addtype(HGDIOBJ,"SelectObject",2,HDC,HGDIOBJ);
  addtype(INT,"CreateBitmap",5,SHORT,SHORT,INT,INT,VOIDPTR);
  addtype(HWND,"CreateWindow",11,CHARPTR,CHARPTR,LONG,INT,INT,INT,INT,HWND,HMENU,HINSTANCE,VOIDPTR); // xx
  addtype(HBITMAP,"CreateCompatibleBitmap",3,HDC,INT,INT);
  addtype(HDC,"CreateCompatibleDC",1,HDC);
  addtype(HRSRC,"FindResource",3,VOIDPTR,CHARPTR,CHARPTR);
  addtype(HCURSOR,"LoadCursor",2,HINSTANCE,CHARPTR);
  addtype(HGLOBAL,"LoadResource",2,HINSTANCE,HRSRC);
  addtype(INT,"LockResource",1,HGLOBAL);
  addtype(INT,"FreeResource",1,HGLOBAL);
  addtype(INT,"SetDIBits",7,HDC,HBITMAP,INT,INT,VOIDPTR,STRUCTPTR,INT);
  addtype(INT,"DefWindowProc",4,VOIDPTR,INT,INT,LONG);
  addtype(INT,"GetSystemMetrics",1,INT);
  addtype(HBRUSH,"CreatePatternBrush",1,HBITMAP);
  addtype(HPEN,"CreatePen",3,INT,INT,LONG);
  addtype(INT,"RegisterClass",1,STRUCTPTR);
  addtype(HBRUSH,"CreateSolidBrush",1,LONG);
  addtype(INT,"__WINFLAGS",0);
  addtype(INT,"DeleteDC",1,HDC);
  addtype(INT,"DeleteObject",1,HGDIOBJ);
  addtype(VOIDPTR,"_lclose",1,INT);
  addtype(HDC,"GetDC",1,HWND);
  addtype(INT,"ReleaseDC",2,HWND,HDC);
  addtype(INT,"_llseek",0);
  addtype(HCURSOR,"SetCursor",1,HCURSOR);
  addtype(VOIDPTR,"_lopen",2,CHARPTR,INT);
  addtype(INT,"SetCursorPos",2,INT,INT);
  addtype(INT,"ShowCursor",1,INT);
  addtype(INT,"SetRect",5,STRUCTPTR,INT,INT,INT,INT);
  addtype(INT,"GetDeviceCaps",2,HDC,INT);
  addtype(INT,"DestroyCursor",1,HCURSOR);
  addtype(LONG,"_hread",3,VOIDPTR,VOIDPTR,LONG);
  addtype(HGDIOBJ,"GetStockObject",1,INT);
  addtype(INT,"FillRect",3,HDC,STRUCTPTR,HBRUSH);
  addtype(INT,"DrawText",5,HDC,CHARPTR,INT,STRUCTPTR,INT);
  addtype(INT,"DOS3CALL",0);
  addtype(LONG,"DefWindowProc",4,VOIDPTR,INT,SHORT,LONG);
  addtype(HPALETTE,"CreatePalette",1,STRUCTPTR);
  addtype(INT,"LockInput",3,HANDLE,HWND,INT);
  addtype(INT,"timeSetEvent",0);
  addtype(INT,"timeKillEvent",0);
  addtype(INT,"timeBeginPeriod",0);
  addtype(INT,"timeEndPeriod",0);
}

void readmz(void *buf, int size)
{
  mz_file_hdr *mz = buf;
  uint32_t sz, *rlc;
  int i, seg, ofs, start, rs, ra;
  int *segTab, nseg, oseg;

  sz = mz->e_cp * 512;
  if (mz->e_cblp) {
    sz -= (512 - mz->e_cblp);
  }
  start = 16 * mz->e_cparhdr;
  printf("================= DOS Header =====================\n");
  printf("Magic number          : %x (%c%c)\n", mz->e_magic, 
         mz->e_magic&0xFF, (mz->e_magic>>8)&0xFF);
  printf("Bytes on last page    : %d\n", mz->e_cblp);
  printf("Total pages           : %d (total size: %lx)\n", mz->e_cp, sz);
  printf("Relocations           : %d @ %x\n", mz->e_crlc, mz->e_lfarlc);
  printf("Size of header        : %d (0x%lx)\n",
         mz->e_cparhdr, 16L*mz->e_cparhdr);
  printf("Min/Max paragraphs    : %d/%d\n", mz->e_minalloc, mz->e_maxalloc);
  printf("Initial SS:SP         : %.04x:%.04x (%.08lx)\n",
	 mz->e_ss, mz->e_sp, MKADDR(mz->e_ss, mz->e_sp));
  printf("Initial CS:IP         : %.04x:%.04x (%.08lx)\n",
	 mz->e_cs, mz->e_ip, MKADDR(mz->e_cs, mz->e_ip));
  printf("Checksum              : %.04x\n", mz->e_csum);
  printf("Overlay number        : %d\n", mz->e_ovno);
  printf("OEM information       : %.04x:%.04x\n", mz->e_oemid,
         mz->e_oeminfo);
  printf("NE/PE Header offset   : %lx\n", mz->e_lfanew);

  nseg = 0;
  segTab = alloca(mz->e_crlc * sizeof(int));
  addSym(MKADDR(mz->e_cs, mz->e_ip), 1, NULL, "_start");

  /* Do relocs */
  oseg = -1;
  printf("======================= relocs\n");
  qsort(buf + mz->e_lfarlc, mz->e_crlc, 4, rscmp);
  for (i = 0; i < mz->e_crlc; i++) {
    ofs = _get16(buf + mz->e_lfarlc + (i * 4) + 0);
    seg = _get16(buf + mz->e_lfarlc + (i * 4) + 2);
    if (oseg != seg) {
      printf("================= seg: %.4x\n", seg);
      oseg = seg;
    }
    rs = MKADDR(seg, ofs) + start;
    if (_get8(buf + rs - 3) == 0x9a) {
      /* call Ap */
      ra = MKADDR(_get16(buf+rs), _get16(buf+rs-2));
      addSym(ra, 1, NULL, "funcra_%x", ra);
      printf("%.8x call Ap: %.4x:%.4x %.8x [%.2x]\n",
	     rs-start-3,
	     _get16(buf+rs), _get16(buf+rs-2), ra,
	     _get8(buf+ra+start));
    }
    else if (_get8(buf+rs-3) == 0xc7) {
      /* mov Ev, Iz */
      printf("%.8x mov ev,iz: %.4x\n", rs-start-3, _get16(buf+rs));
    }
    else if ((_get8(buf+rs-1) & 0xF8) == 0xb8) {
      /* mov gv, Iv */
      printf("%.8x mov gv,iv:%.4x\n", rs-start-1, _get16(buf+rs));
    }
    else {
      printf("%.8lx unk:%.2x %.2x %.2x %.2x\n", rs-start, _get8(buf+rs-4), _get8(buf+rs-3), _get8(buf+rs-2), _get8(buf+rs-1));
    }
  }
  parsebb(buf + start, sz, 0x0, 0, 0x3);
}

void dumprsrc(void *buf, int sz, uint8_t *fb)
{
  printf("================ Resources\n");
  dump(buf, sz, "test", 3);
}

int readne(void *buf, int sz)
{
  uint32_t     segoff;
  void        *nebuf;
  const char  *mt;
  mz_file_hdr *mz;
  ne_file_hdr *ne;
  ne_segment  *ns;
  ne_reloctab *nr;
  ne_bundle   *nb;
  uint16_t    *nm;
  uint8_t     *ni;  // imports table
  const char  **mrt;
  int i, mid, len, soff;

  mz = buf;
  if (memcmp(buf, "MZ", 2))
    return -1;
  if (memcmp(buf+mz->e_lfanew,"NE", 2)) {
    readmz(buf, sz);
    return -1;
  }
  winAPI();
  nebuf = buf + mz->e_lfanew;

  ne = nebuf;
  ns = nebuf + ne->ne_segtab; /* segment table */
  nb = nebuf + ne->ne_enttab; /* entry table */
  ni = nebuf + ne->ne_imptab; /* imports      : pascalstr[] */
  nm = nebuf + ne->ne_modtab; /* module table : uint16_t[] */

  printf("size       : %x\n", sz);
  printf("new offset : %x\n", mz->e_lfanew);
  printf("Linker ver : %d %d\n", ne->ne_ver, ne->ne_rev);

  printf("Segments   : %.4x/%.4x\n", ne->ne_segtab, ne->ne_cseg);
  printf("Rsrc Table : %.4x/%.4x\n", ne->ne_rsrctab, ne->ne_cres);
  printf("ResName    : %.4x\n", ne->ne_restab);
  printf("Module Ref : %.4x/%.4x\n", ne->ne_modtab, ne->ne_cmod);
  printf("ImportName : %.4x\n", ne->ne_imptab);
  printf("NonresName : %.4x/%.4x\n", ne->ne_nrestab, ne->ne_cbnrestab);
  printf("Entry Table: %.4x/%.4x\n", ne->ne_enttab, ne->ne_cbenttab);

  printf("Alignment  : %.4x\n", ne->ne_align);
  printf("Flags      : %.4x [%s %s %s %s %s %s]\n",
	 ne->ne_flags,
	 ne->ne_flags ? "" : "NOAUTODATA",
	 ne->ne_flags & BIT(0) ? "SINGLEDATA" : "",
	 ne->ne_flags & BIT(1) ? "MULTIPLEDATA" : "",
	 ne->ne_flags & BIT(11) ? "LOADER" : "",
	 ne->ne_flags & BIT(13) ? "ERROR" : "",
	 ne->ne_flags & BIT(15) ? "DLL" : "");
  printf("CS:IP      : %.4x:%.4x [%.8x]\n",
	 ne->ne_csip >> 16,
	 ne->ne_csip & 0xFFFF, ne->ne_csip);
  printf("SS:SP      : %.4x:%.4x\n",
	 ne->ne_sssp >> 16,
	 ne->ne_sssp & 0xFFFF);
  soff = ne->ne_csip & 0xFFFF;
  
  printf("----------- Import Name Table\n");
  mrt = alloca(sizeof(char *) * ne->ne_cmod);
  for (i = 0; i < ne->ne_cmod; i++) {
    mrt[i] = strdup(getPascalStr(ni + nm[i]));
    printf("  %.4x: %s\n", i, mrt[i]);
  }
  printf("------------ Resident Name Table\n");
  for (i = ne->ne_restab; i+3 < ne->ne_modtab; i+= len+3) {
    /* pascalStr, dw */
    len = _get8(nebuf + i);
    mt = getPascalStr(nebuf + i);
    mid = _get16(nebuf + i + len + 1);
    printf("  %.4x: %s\n", mid, mt);
  }

  /* Add Sections */
  printf("------------ Sections\n");
  for (i = 0; i < ne->ne_cseg; i++) {
    segoff = ns[i].ns_sector << ne->ne_align;
    printf("  %3d: file:%.6x size:%.4x flags:%.4x minalloc:%.4x [",
	   i+1, segoff, ns[i].ns_cbseg, ns[i].ns_flags, ns[i].ns_minalloc);
    printf(" %s %s %s %s %s %s %s %s %s]\n",
	   (ns[i].ns_flags & NS_DATA) ? "DATA" : "CODE",
	   (ns[i].ns_flags & NS_ALLOC) ? "ALLOC" : "",
	   (ns[i].ns_flags & NS_LOADED) ? "LOADED" : "",
	   (ns[i].ns_flags & NS_MOVABLE) ? "MOVEABLE" : "FIXED",
	   (ns[i].ns_flags & NS_PURE) ? "SHAREABLE" : "NONSHAREABLE",
	   (ns[i].ns_flags & NS_PRELOAD) ? "PRELOAD" : "LOADONCALL",
	   (ns[i].ns_flags & NS_READONLY) ? "HAZRELOC" : "",
	   (ns[i].ns_flags & NS_RELOC) ? "RELOC" : "",
	   (ns[i].ns_flags & NS_DISCARD) ? "DISCARDABLE" : "");
    addSection(i, 0x10000 * i, ns[i].ns_cbseg, buf + segoff,
	       ns[i].ns_flags & NS_DATA ? ".data" : ".text",
	       &ns[i]);
  }
  dumprsrc(nebuf + ne->ne_rsrctab, ne->ne_restab - ne->ne_rsrctab, buf);

  /* Do relocs */
  for (i = 0; i < ne->ne_cseg; i++) {
    segoff = ns[i].ns_sector << ne->ne_align;
    if (ns[i].ns_flags & NS_RELOC) {
      nr = (void *)(buf + segoff + ns[i].ns_cbseg);
      nereloc(nr->nr_reloc, nr->nr_nreloc, i, buf + segoff, ns[i].ns_cbseg, mrt);
    }
  }

  /* Show sections */
  for (i = 0; i < ne->ne_cseg; i++) {
    segoff = ns[i].ns_sector << ne->ne_align;
    if (!(ns[i].ns_flags & NS_DATA) && ns[i].ns_sector) {
      parsebb(buf + segoff, ns[i].ns_cbseg, soff, 0, 0x3);
    }
  }
  return 0;
}
