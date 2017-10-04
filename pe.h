#ifndef __PE_H__
#define __PE_H__

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


#endif
