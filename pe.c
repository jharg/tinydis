/* pe.c - Portable Executable (Windows 32/64) Loader
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
#include "pe.h"

static const char *datanames[] = {
  "export",
  "import",
  "resource",
  "exception",
  "certificate",
  "basereloc",
  "debug",
  "global",
  "tls",
  "loadconfig",
  "boundimport",
  "importaddress",
  "delayimport",
  "clrruntimeheader",
  "",
};

void *getScnData(coff_scn_hdr *shdr, int n, void *buf, rva_t rva)
{
  int i;

  if (!rva)
    return NULL;
  for (i = 0; i < n; i++) {
    if (rva >= shdr[i].s_vaddr && rva < shdr[i].s_vaddr+shdr[i].s_size) {
      return buf + shdr[i].s_paddr;
    }
  }
  return NULL;
}

const char *findScnName(coff_scn_hdr *shdr, int n, rva_t rva)
{
  int i;

  if (!rva)
    return "";
  for (i = 0; i < n; i++) {
    if (rva >= shdr[i].s_vaddr && rva < shdr[i].s_vaddr+shdr[i].s_size)
      return shdr[i].s_name;
  }
  return "";
}

void doImport(void *buf, int impoff, int sz, int ibase)
{
  pe_imp_hdr *imp = buf + impoff;
  const char *name;
  int i;

  for (i = 0; imp[i].name; i++) {
    name = buf + imp[i].name;
    printf("  [inp] %.8x %.8x %.8x %.8x %.8x [%s]\n",
	   imp[i].origfirstthunk,
	   imp[i].timedate,
	   imp[i].forwardchain,
	   imp[i].name + ibase,
	   imp[i].firstthunk + ibase);
  }
}

int readcoff(void *buf, size_t sz, int off)
{
  coff_file_hdr *fhdr = buf + off;
  coff_opt_hdr  *ohdr = (void *)&fhdr[1];
  coff_scn_hdr  *shdr = (void *)&fhdr[1] + fhdr->f_opthdr;
  pe_imp_hdr    *imp;
  uint32_t ibase = 0;
  int i;

  printf("================= COFF Header =================\n");
  printf("size   : %x\n", sz - off);
  printf("offset : %x\n", off);
  printf("magic  : %.4x\n", fhdr->f_magic);
  printf("nscn   : %d\n", fhdr->f_nscns);
  printf("syms   : %d @ %.4x\n", fhdr->f_nsyms, fhdr->f_symptr);
  printf("opthdr : %.4x\n", fhdr->f_opthdr);
  printf("flags  : %.4x\n", fhdr->f_flags);

  if (fhdr->f_opthdr) {
    ibase = ohdr->image_base;
    printf("image base : %.8x\n", ohdr->image_base);
    printf("align.sect : %.8x\n", ohdr->section_align); 
    printf("align.file : %.8x\n", ohdr->file_align);
    printf("num_rva    : %d\n",   ohdr->num_rva);
    printf("text       : %.8x-%.8x\n", ohdr->text_rva, ohdr->text_rva + ohdr->text_size - 1);
    printf("entry      : %.8x\n", ohdr->entry_rva);
    printf("data       : %.8x-%.8x\n", ohdr->data_rva, ohdr->data_rva + ohdr->data_size - 1);
    addSym(ohdr->entry_rva - ohdr->text_rva, 1, NULL, "_entry");
    //parsebb(buf + shdr[0].s_scnptr, ohdr->text_size, 0, 0, MACH_X86_32);
  }
#if 0
  printf("id  paddr    vaddr    size     scnptr   relptr         lnno           flags    name\n");
  for (i = 0; i < fhdr->f_nscns; i++) {
    printf("%3d %.8x %.8x %.8x %.8x %.8x/%.5x %.8x/%.5x %.8x %-10s\n",
	   i, shdr[i].s_paddr, ibase+shdr[i].s_vaddr, shdr[i].s_size,
	   shdr[i].s_scnptr,
	   shdr[i].s_relptr, shdr[i].s_nreloc,
	   shdr[i].s_lnnoptr, shdr[i].s_nlnno,
	   shdr[i].s_flags,
	   shdr[i].s_name);
    addSection(i, ibase+shdr[i].s_vaddr, shdr[i].s_size,
	       buf + shdr[i].s_paddr, shdr[i].s_name,
	       &shdr[i]);
  }
  if (fhdr->f_opthdr >= sizeof(coff_opt_hdr)) {
    for (i = 0; i < 15; i++) {
      if (ohdr->datadir[i].rva) {
	printf(" rva:%.8x size:%.8x [%-8s] %s\n",
	       ohdr->datadir[i].rva + ibase, ohdr->datadir[i].size,
	       findScnName(shdr, fhdr->f_nscns, ohdr->datadir[i].rva),
	     datanames[i]);
	if (i == 1) {
	  imp = getScnData(shdr, fhdr->f_nscns, buf, ohdr->datadir[i].rva);
	}
      }
    }
  }
#endif
  return 0;
}

int readpe(void *buf, size_t sz)
{
  mz_file_hdr *mz;
  off_t off;
  
  mz = buf;
  if (memcmp(buf, "MZ", 2))
    return -1;
  if (memcmp(buf + mz->e_lfanew, "PE\0\0", 4))
    return -1;
  return readcoff(buf, sz, mz->e_lfanew + 4);
}

