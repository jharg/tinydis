#ifndef __NE_H__
#define __NE_H__

/*============================================================================*
 * DOS .EXE MZ Executable format
 *============================================================================*/
#define __packed __attribute__((packed))

typedef struct
{
  uint16_t	e_magic;
  uint16_t	e_cblp;
  uint16_t	e_cp;
  uint16_t	e_crlc;
  uint16_t	e_cparhdr;
  uint16_t	e_minalloc;
  uint16_t	e_maxalloc;
  uint16_t	e_ss;
  uint16_t	e_sp;
  uint16_t	e_csum;
  uint16_t	e_ip;
  uint16_t	e_cs;
  uint16_t	e_lfarlc;
  uint16_t	e_ovno;
  uint16_t	e_res[4];
  uint16_t	e_oemid;
  uint16_t	e_oeminfo;
  uint16_t	e_res2[10];
  uint32_t	e_lfanew;
} __packed  mz_file_hdr;

/*============================================================================*
 * New Executable format
 *============================================================================*/
typedef struct
{
  uint16_t   ne_magic;                    // Magic number
  uint8_t    ne_ver;                      // Version number
  uint8_t    ne_rev;                      // Revision number
  uint16_t   ne_enttab;                   // Offset of Entry Table
  uint16_t   ne_cbenttab;                 // Number of bytes in Entry Table
  uint32_t   ne_crc;                      // Checksum of whole file
  uint16_t   ne_flags;                    // Flag word
  uint16_t   ne_autodata;                 // Automatic data segment number
  uint16_t   ne_heap;                     // Initial heap allocation
  uint16_t   ne_stack;                    // Initial stack allocation
  uint32_t   ne_csip;                     // Initial CS:IP setting
  uint32_t   ne_sssp;                     // Initial SS:SP setting
  uint16_t   ne_cseg;                     // Count of file segments
  uint16_t   ne_cmod;                     // Entries in Module Reference Table
  uint16_t   ne_cbnrestab;                // Size of non-resident name table

  uint16_t   ne_segtab;                   // Offset of Segment Table
  uint16_t   ne_rsrctab;                  // Offset of Resource Table
  uint16_t   ne_restab;                   // Offset of resident name table
  uint16_t   ne_modtab;                   // Offset of Module Reference Table
  uint16_t   ne_imptab;                   // Offset of Imported Names Table
  uint32_t   ne_nrestab;                  // Offset of Non-resident Names Table

  uint16_t   ne_cmovent;                  // Count of movable entries
  uint16_t   ne_align;                    // Segment alignment shift count
  uint16_t   ne_cres;                     // Count of resource segments
  uint8_t    ne_exetyp;                   // Target Operating system
  uint8_t    ne_flagsothers;              // Other .EXE flags
  uint16_t   ne_pretthunks;               // offset to return thunks
  uint16_t   ne_psegrefbytes;             // offset to segment ref. bytes
  uint16_t   ne_swaparea;                 // Minimum code swap area size
  uint16_t   ne_expver;                   // Expected Windows version number
} __packed  ne_file_hdr;

#define NS_DATA     (1 << 0)
#define NS_ALLOC    (1 << 1)
#define NS_LOADED   (1 << 2)
#define NS_MOVABLE  (1 << 4)
#define NS_PURE     (1 << 5)
#define NS_PRELOAD  (1 << 6)
#define NS_READONLY (1 << 7)
#define NS_RELOC    (1 << 8)
#define NS_DISCARD  (1 << 12)

typedef struct
{
  uint16_t     ns_sector;
  uint16_t     ns_cbseg;
  uint16_t     ns_flags;
  uint16_t     ns_minalloc;
} __packed  ne_segment;

typedef struct _neBundle
{
  uint8_t   count;
  uint8_t   info;
  union {
    uint8_t next;
    struct {
      uint8_t  flags;
      uint16_t offset;
    } __packed fixed[1];
    struct {
      uint8_t  flags;
      uint8_t  cd3f[2];
      uint8_t  section;
      uint16_t offset;
    } __packed movable[1];
  };
} __packed ne_bundle;

typedef struct
{
  uint8_t  type;
  uint8_t  flags;
  uint16_t offset;
  union _target {
    struct _internalref {
      uint8_t  seg;
      uint8_t  reserved;
      uint16_t offset;
    } ref;
    struct _importname {
      uint16_t  modTabIdx;
      uint16_t  procNameIdx;
    } name;
    struct _importordinal {
      uint16_t  modTabIdx;
      uint16_t  procOrdinal;
    } ord;
  } t;
} __packed  neFixupTable;

enum {
  raLOBYTE = 0,
  raSEL16  = 2,
  raPTR32  = 3,
  raOFF16  = 5,
  raPTR48  = 11,
  raOFF32  = 13
};

enum {
  rtINTREF = 0,
  rtIMPORD = 1,
  rtIMPNAM = 2,
};

typedef struct
{
  uint8_t  nr_atype;
  uint8_t  nr_rtype;
  uint16_t nr_offset;
  union {
    uint8_t xx[4];
    struct {
      uint16_t mrt;
      uint16_t ord;
    } imp_ord;
    struct {
      uint16_t mrt;
      uint16_t imp;
    } imp_name;
    struct {
      uint8_t seg;
      uint8_t x;
      uint16_t off;
    } iref;
  };
} __packed  ne_reloc;

typedef struct
{
  uint16_t nr_nreloc;
  ne_reloc nr_reloc[1];
} __packed  ne_reloctab;

#endif
