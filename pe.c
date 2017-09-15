#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "tinydis.h"
#include "ne.h"

#define __packed __attribute__((packed))

typedef uint32_t rva_t;

/*============================================================================*
 * COFF/PE format
 *============================================================================*/
typedef struct
{
  uint32_t	m_magic;
  /* coff_file_hdr */
  uint16_t	m_machine;
  uint16_t	m_nscn;
  uint32_t	m_timedate;
  uint32_t	m_symtab;
  uint32_t	m_numsym;
  uint16_t	m_optsz;
  uint16_t	m_characteristics;
} __packed pe_file_hdr;

typedef struct
{
  uint16_t      hint;
  char          name[1];
} __packed pe_impname;

struct pe_opt_hdr
{
};

typedef struct
{
  char		m_name[8];
  uint32_t	m_virtsize;
  uint32_t	m_virtaddr;
  uint32_t	m_rawsize;
  uint32_t	m_rawdata;
} __packed  pe_scn_hdr;

typedef struct
{
  rva_t         origfirstthunk; /* pointer to *IMAGE_IMPORT_BY_NAME[] */
  uint32_t      timedate;
  uint32_t      forwardchain;
  rva_t         name;           /* RVA to name string */
  rva_t         firstthunk;     /* RVA to pe_impname */
} __packed  pe_imp_hdr;

typedef struct
{
  uint16_t	f_magic;
  uint16_t	f_nscns;
  uint32_t	f_timdat;
  uint32_t	f_symptr;
  uint32_t	f_nsyms;
  uint16_t	f_opthdr;
  uint16_t	f_flags;
} __packed  coff_file_hdr;

typedef struct
{
  uint16_t	magic;
  uint8_t       mjr;
  uint8_t       mnr;
  uint32_t	text_size;
  uint32_t	data_size;
  uint32_t	bss_size;
  rva_t		entry_rva;
  rva_t		text_rva;
  rva_t		data_rva;
  /* PE opt header */
  uint32_t      image_base;
  uint32_t      section_align;
  uint32_t      file_align;
  uint16_t      osmjr;
  uint16_t      osmnr;
  uint16_t      imgmjr;
  uint16_t      imgmnr;
  uint16_t      subsysmjr;
  uint16_t      subsysmnr;
  uint32_t      rsvd1;
  uint32_t      image_size;
  uint32_t      header_size;
  uint32_t      chksum;
  uint16_t      subsys;
  uint16_t      dllflags;
  uint32_t      stack_reserve_size;
  uint32_t      stack_commit_size;
  uint32_t      heap_reserve_size;
  uint32_t      heap_commit_size;
  uint32_t      loader_flags;
  uint32_t      num_rva;
  struct {
    rva_t       rva;
    uint32_t    size;
  } datadir[15];
  /* 0: Export
     1: Import
     2: Resource
     3: Exception
     4: Certificate
     5: BaseRelocation
     6: Debug
     7: GlobalPtr[size=0]
     8: TLSTable
     9: LoadConfigTable
     a: BoundImport
     b: ImportAddressTable
     c: DelayImportDescriptor
     d: CLRRuntimeHeader
  */
} __packed  coff_opt_hdr;

typedef struct
{
  char		s_name[8];
  uint32_t	s_paddr;
  rva_t		s_vaddr;     /* rva */
  uint32_t	s_size;
  uint32_t	s_scnptr;
  uint32_t	s_relptr;
  uint32_t	s_lnnoptr;
  uint16_t	s_nreloc;
  uint16_t	s_nlnno;
  uint32_t	s_flags;
}  __packed coff_scn_hdr;

typedef struct
{
  uint32_t	r_vaddr;
  uint32_t	r_symndx;
  uint16_t	r_type;
} __packed  coff_reloc;

union coff_lnno
{
  struct {
    uint32_t	l_symndx;
    uint32_t	l_paddr;
  } l_addr;
  uint16_t	l_lnno;
};

struct coff_symtab {
  char		n_name[8];
  uint32_t	n_value;
  uint16_t	n_scnnum;
  uint16_t	n_type;
  uint8_t	n_sclass;
  uint8_t	n_numaux;
};

union coff_strtab {
  char		name[8];
  struct {
    uint32_t	zeroes;
    uint32_t	offset;
  };
};

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

void *getScnData(coff_scn_hdr *shdr, void *buf, rva_t rva)
{
  int i, n;

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
#if 1
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
	  imp = getScnData(shdr, buf, ohdr->datadir[i].rva);
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

