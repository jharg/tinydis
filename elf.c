/* elf.c - Elf Loader
 *
 * Copyright (c) 2015-17 Jordan Hargrave<jordan_hargrave@hotmail.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <inttypes.h>
#include <assert.h>
#include "tinydis.h"
#include "elf.h"

#define _l(x) (unsigned long)(x)

const char *shtype[] = {
  "NULL",
  "PROGBITS",
  "SYMTAB",
  "STRTAB",
  "RELA",
  "HASH",
  "DYNAMIC",
  "NOTE",
  "NOBITS",
  "REL",
  "SHLIB",
  "DYNSYM",
  "",
  "",
  "INIT_ARRAY",
  "FINI_ARRAY",
};

#define cc(a,b) case a##b: return #b;

static int elf_stt(uint8_t info) { return info & 0xF; };
static int elf_stb(uint8_t info) { return info >> 4; };

static const char *elf_sym_type(uint8_t info)
{
  switch (info & 0xF) {
    cc(STT_,NOTYPE);
    cc(STT_,OBJECT);
    cc(STT_,FUNC);
    cc(STT_,SECTION);
    cc(STT_,FILE);
    cc(STT_,COMMON);
    cc(STT_,TLS);
    cc(STT_,LOOS);
    cc(STT_,HIOS);
    cc(STT_,LOPROC);
    cc(STT_,HIPROC);
  }
  return "UNK";
}

static const char *elf_sym_bind(uint8_t info)
{
  switch (info >> 4) {
    cc(STB_,LOCAL);
    cc(STB_,GLOBAL);
    cc(STB_,WEAK);
    cc(STB_,LOOS);
    cc(STB_,HIOS);
    cc(STB_,LOPROC);
    cc(STB_,HIPROC);
  }
  return "UNK";
}

static int symcmp(const void *a, const void *b)
{
  const elf64_sym *sa = a;
  const elf64_sym *sb = b;

  return (sa->st_value - sb->st_value);
}

void dump(void *buf, int len, const char *sfx, int flag);
#define dump(b,l) dump(b,l,"elf",1)

/*================================================
 * Get ELF File header
 * Converts ELF32->ELF64
 *================================================*/
#define COPY(x) e64->x = e32->x
static elf64_fhdr *elf_fhdr(void *buf, int *type)
{
  elf32_fhdr *e32 = buf;
  elf64_fhdr *e64 = buf;

  *type = e32->e_ident[4];
  if (*type == ELF64)
    return e64;
  printf("Conv FHDR\n");
  e64 = calloc(1, sizeof(*e64));
  memcpy(e64->e_ident, e32->e_ident, sizeof(e32->e_ident));
  COPY(e_type);
  COPY(e_machine);
  COPY(e_version);
  COPY(e_entry);
  COPY(e_phoff);
  COPY(e_shoff);
  COPY(e_flags);
  COPY(e_ehsize);
  COPY(e_phentsize);
  COPY(e_phnum);
  COPY(e_shentsize);
  COPY(e_shnum);
  COPY(e_shstrndx);
  return e64;
}
#undef COPY

/*================================================
 * Get ELF Program headers
 * Converts ELF32->ELF64
 *================================================*/
#define COPY(x) e64[i].x = e32[i].x
static elf64_phdr *elf_phdr(void *buf, int n, int type)
{
  elf32_phdr *e32 = buf;
  elf64_phdr *e64 = buf;
  int i;
  
  if (type == ELF64)
    return e64;
  printf("Conv PHDR %d\n", n);
  e64 = calloc(n, sizeof(*e64));
  for (i=0; i<n; i++) {
    COPY(p_type);
    COPY(p_flags);
    COPY(p_offset);
    COPY(p_vaddr);
    COPY(p_paddr);
    COPY(p_filesz);
    COPY(p_memsz);
    COPY(p_align);
  }
  return e64;
}

/*================================================
 * Get ELF Section headers
 * Converts ELF32->ELF64
 *================================================*/
static elf64_shdr *elf_shdr(void *buf, int n, int type)
{
  elf32_shdr *e32 = buf;
  elf64_shdr *e64 = buf;
  int i;
  
  if (type == ELF64)
    return e64;
  printf("Conv SHDR %d\n", n);
  e64 = calloc(n, sizeof(*e64));
  for (i=0; i<n; i++) {
    COPY(sh_name);
    COPY(sh_type);
    COPY(sh_flags);
    COPY(sh_addr);
    COPY(sh_offset);
    COPY(sh_size);
    COPY(sh_link);
    COPY(sh_info);
    COPY(sh_addralign);
    COPY(sh_entsize);
  }
  return e64;
}

/*================================================
 * Get ELF Symbols section
 * Converts ELF32->ELF64
 *================================================*/
static elf64_sym *elf_sym(void *buf, int n, int type)
{
  elf32_sym *e32 = buf;
  elf64_sym *e64 = buf;
  int i;
  
  if (type == ELF64)
    return e64;
  printf("Conv SYM %d\n", n);
  e64 = calloc(n, sizeof(*e64));
  for (i=0; i<n; i++) {
    COPY(st_name);
    COPY(st_value);
    COPY(st_size);
    COPY(st_info);
    COPY(st_other);
    COPY(st_shndx);
  }
  return e64;
}

uint64_t elf_rinfo(uint64_t ri)
{
  /* ELF32 r_info:                         sssssssssssssssssssssssstttttttt */
  /* ELF64 r_info: sssssssssssssssssssssssstttttttttttttttttttttttttttttttt */
  return ((ri & ~0xFF) << 24) | (ri & 0xFF);
}

/*================================================
 * Get ELF Reloc section
 * Converts ELF32->ELF64
 *================================================*/
static elf64_rel *elf_rel(void *buf, int n, int type)
{
  elf32_rel *e32 = buf;
  elf64_rel *e64 = buf;
  int i;
  
  if (type == ELF64)
    return e64;
  printf("Conv REL %d\n", n);
  e64 = calloc(n, sizeof(*e64));
  for (i=0; i<n; i++) {
    COPY(r_addr);
    e64[i].r_info = elf_rinfo(e32[i].r_info);
  }
  return e64;
}

/*================================================
 * Get ELF RelocA section
 * Converts ELF32->ELF64
 *================================================*/
static elf64_rela *elf_rela(void *buf, int n, int type)
{
  elf32_rela *e32 = buf;
  elf64_rela *e64 = buf;
  int i;
  
  if (type == ELF64)
    return e64;
  printf("Conv RELA %d\n", n);
  e64 = calloc(n, sizeof(*e64));
  for (i=0; i<n; i++) {
    COPY(r_offset);
    COPY(r_addend);
    e64[i].r_info = elf_rinfo(e32[i].r_info);
  }
  return e64;
}

void readelf(void *buf, int len)
{
  elf64_fhdr *fhdr;
  elf64_phdr *phdr;
  elf64_shdr *shdr;
  elf64_sym  *sym;
  const char *strtab, *symoff;
  int i, j, type, nsym;
  void **sdata;

  if (memcmp(buf, "\x7F" "ELF", 4))
    return;
  fhdr = elf_fhdr(buf, &type);
  phdr = elf_phdr(buf + fhdr->e_phoff, fhdr->e_phnum, type);
  shdr = elf_shdr(buf + fhdr->e_shoff, fhdr->e_shnum, type);
  assert(fhdr->e_shstrndx < fhdr->e_shnum);
  
  strtab = buf + shdr[fhdr->e_shstrndx].sh_offset;
  printf("type    : %.4lx\n", _l(fhdr->e_type));
  printf("machine : %.4lx\n", _l(fhdr->e_machine));
  printf("version : %.8lx\n", _l(fhdr->e_version));
  printf("entry   : %.8lx\n", _l(fhdr->e_entry));
  printf("phoff   : %.8lx %.8lx %.8lx\n", _l(fhdr->e_phoff), _l(fhdr->e_phentsize), _l(fhdr->e_phnum));
  printf("shoff   : %.8lx %.8lx %.8lx\n", _l(fhdr->e_shoff), _l(fhdr->e_shentsize), _l(fhdr->e_shnum));
  printf("flags   : %.8lx\n", _l(fhdr->e_flags));
  printf("ehsize  : %.8lx\n", _l(fhdr->e_ehsize));
  printf("strtab  : %.8lx\n", _l(fhdr->e_shstrndx));

  printf("======================= Prog Header\n");
  for (i = 0; i < fhdr->e_phnum; i++) {
    printf("%.8lx %.8lx %.8lx %.8lx %.8lx %.8lx %.8lx %.8lx\n",
	   _l(phdr[i].p_type),
	   _l(phdr[i].p_flags),
	   _l(phdr[i].p_offset),
	   _l(phdr[i].p_vaddr),
	   _l(phdr[i].p_paddr),
	   _l(phdr[i].p_filesz),
	   _l(phdr[i].p_memsz),
	   _l(phdr[i].p_align));
  }

  /* Allocate section data pointers */
  sdata = alloca(fhdr->e_shnum * sizeof(void *));
  memset(sdata, 0, fhdr->e_shnum * sizeof(void *));
  
  printf("======================= Sections\n");
  printf("id  name     type     flags    addr     offset   size     link info addralgn entsize\n");
  for (i = 0; i < fhdr->e_shnum; i++) {
    printf("%3ld %.8lx %.8lx %.8lx %.8lx %.8lx %.8lx %.4lx %.4lx %.8lx %.8lx %-8s [%s]\n",
	   _l(i), 
	   _l(shdr[i].sh_name),
	   _l(shdr[i].sh_type),
	   _l(shdr[i].sh_flags),
	   _l(shdr[i].sh_addr),
	   _l(shdr[i].sh_offset),
	   _l(shdr[i].sh_size),
	   _l(shdr[i].sh_link),
	   _l(shdr[i].sh_info),
	   _l(shdr[i].sh_addralign),
	   _l(shdr[i].sh_entsize),
	   shdr[i].sh_type <= SHT_FINI_ARRAY ? shtype[shdr[i].sh_type] : "",
	   strtab + shdr[i].sh_name);
    /* Convert section contents to ELF64 */
    sdata[i] = buf + shdr[i].sh_offset;
    switch (shdr[i].sh_type) {
    case SHT_SYMTAB:
    case SHT_DYNSYM:
      sdata[i] = elf_sym(sdata[i], shdr[i].sh_size / shdr[i].sh_entsize, type);
      break;
    case SHT_REL:
      sdata[i] = elf_rel(sdata[i], shdr[i].sh_size / shdr[i].sh_entsize, type);
      break;
    case SHT_RELA:
      sdata[i] = elf_rel(sdata[i], shdr[i].sh_size / shdr[i].sh_entsize, type);
      break;
    case SHT_NULL:
    case SHT_NOBITS:
      sdata[i] = NULL;
      break;
    }
    addSection(i, shdr[i].sh_addr, shdr[i].sh_size, sdata[i],
	       strtab + shdr[i].sh_name,
	       &shdr[i]);
  }

  /* Show symbols */
  printf("======================= Symbols\n");
  for (i = 0; i < fhdr->e_shnum; i++) {
    if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
      symoff = buf + shdr[shdr[i].sh_link].sh_offset;
      nsym = shdr[i].sh_size / shdr[i].sh_entsize;
      sym = sdata[i];

      printf("Symbols: %s\n", strtab + shdr[i].sh_name);
      qsort(sym, nsym, sizeof(*sym), symcmp);
      for (j = 0; j < nsym; j++) {
	printf("%.8lx %.8lx %-8s %-8s %.4lx %.8lx %s\n",
	       _l(sym[j].st_value),
	       _l(sym[j].st_size),
	       elf_sym_type(sym[j].st_info),
	       elf_sym_bind(sym[j].st_info),
	       _l(sym[j].st_other),
	       _l(sym[j].st_shndx),
	       symoff + sym[j].st_name);
	if (elf_stt(sym[j].st_info) == STT_FUNC && sym[j].st_shndx < fhdr->e_shnum) {
	  addSym(sym[j].st_value, 1, &sym[j], symoff + sym[j].st_name);
	}
      }
    }
  }

  /* Dump code */
  for (i = 0; i < fhdr->e_shnum; i++) {
    if (!strcmp(strtab + shdr[i].sh_name, ".text")) {
      dump(buf + shdr[i].sh_offset, 64);
      parsebb(buf + shdr[i].sh_offset, shdr[i].sh_size,
	      0x0, shdr[i].sh_addr, (type << 16) | fhdr->e_machine);
    }
  }
}
