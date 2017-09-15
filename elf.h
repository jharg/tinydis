#ifndef __ELF_H__
#define __ELF_H__

#define __packed __attribute__((packed))

/* Elf32 File Header */
typedef uint32_t elf32_addr;
typedef uint16_t elf32_half;
typedef uint32_t elf32_off;
typedef uint32_t elf32_word;
typedef int32_t  elf32_sword;

typedef uint64_t elf64_off;
typedef uint64_t elf64_addr;
typedef uint16_t elf64_half;
typedef uint32_t elf64_word;
typedef int32_t  elf64_sword;
typedef uint64_t elf64_xword;
typedef int64_t  elf64_sxword;

enum {
  ELF32 = 0x01,
  ELF64 = 0x02,
};

/* secthdr.sh_type */
enum {
  SHT_NULL = 0,
  SHT_PROGBITS = 1,
  SHT_SYMTAB = 2,
  SHT_STRTAB = 3,
  SHT_RELA = 4,
  SHT_HASH = 5,
  SHT_DYNAMIC = 6,
  SHT_NOTE = 7,
  SHT_NOBITS = 8,
  SHT_REL = 9,
  SHT_SHLIB = 10,
  SHT_DYNSYM = 11,
};

enum {
  STT_NOTYPE = 0,
  STT_OBJECT = 1,
  STT_FUNC = 2,
  STT_SECTION = 3,
  STT_FILE = 4,
  STT_COMMON = 5,
  STT_TLS = 6,
  STT_LOOS = 10,
  STT_HIOS = 12,
  STT_LOPROC = 13,
  STT_HIPROC = 15
};

enum {
  STB_LOCAL = 0,
  STB_GLOBAL = 1,
  STB_WEAK = 2,
  STB_LOOS = 10,
  STB_HIOS = 12,
  STB_LOPROC = 13,
  STB_HIPROC = 15,
};

/*===============================================*
 * ELF64
 *===============================================*/
typedef struct {
  uint8_t    e_ident[16];
  elf64_half e_type;
  elf64_half e_machine;
  elf64_word e_version;
  elf64_addr e_entry;
  elf64_off  e_phoff;
  elf64_off  e_shoff;
  elf64_word e_flags;
  elf64_half e_ehsize;
  elf64_half e_phentsize;
  elf64_half e_phnum;
  elf64_half e_shentsize;
  elf64_half e_shnum;
  elf64_half e_shstrndx;
} __packed elf64_fhdr;

/* Elf Program header */
typedef struct {
  elf64_word  p_type;
  elf64_word  p_flags;
  elf64_off   p_offset;
  elf64_addr  p_vaddr;
  elf64_addr  p_paddr;
  elf64_xword p_filesz;
  elf64_xword p_memsz;
  elf64_xword p_align;
} __packed elf64_phdr;

/* Elf Section header */
typedef struct {
  elf64_word  sh_name;
  elf64_word  sh_type;
  elf64_xword sh_flags;
  elf64_addr  sh_addr;
  elf64_off   sh_offset;
  elf64_xword sh_size;
  elf64_word  sh_link;
  elf64_word  sh_info;
  elf64_xword sh_addralign;
  elf64_xword sh_entsize;
} __packed elf64_shdr;

/* Elf symbol[ */
typedef struct {
  elf64_word  st_name;
  uint8_t     st_info;
  uint8_t     st_other;
  elf64_half  st_shndx;
  elf64_addr  st_value;
  elf64_xword st_size;
} __packed elf64_sym;

/* Info: sssssssssssssssssssssssstttttttttttttttttttttttttttttttt */
#define REL64_SYM(x)  ((x) >> 32)
#define REL64_TYPE(x) ((x) & 0xFFFFFFFF)
typedef struct {
  elf64_addr  r_addr;
  elf64_xword r_info;
} __packed elf64_rel;

typedef struct {
  elf64_addr   r_offset;
  elf64_xword  r_info;
  elf64_sxword r_addend;
} __packed elf64_rela;

/*===============================================*
 * ELF32
 *===============================================*/
typedef struct {
  uint8_t    e_ident[16];
  elf32_half e_type;
  elf32_half e_machine;
  elf32_word e_version;
  elf32_addr e_entry;
  elf32_off  e_phoff;
  elf32_off  e_shoff;
  elf32_word e_flags;
  elf32_half e_ehsize;
  elf32_half e_phentsize;
  elf32_half e_phnum;
  elf32_half e_shentsize;
  elf32_half e_shnum;
  elf32_half e_shstrndx;
} __packed elf32_fhdr;

/* Elf Program header */
typedef struct {
  elf32_word  p_type;
  elf32_off   p_offset;
  elf32_addr  p_vaddr;
  elf32_addr  p_paddr;
  elf32_word  p_filesz;
  elf32_word  p_memsz;
  elf32_word  p_flags;
  elf32_word  p_align;
} __packed elf32_phdr;

/* Elf Section header */
typedef struct {
  elf32_word sh_name;
  elf32_word sh_type;
  elf32_word sh_flags;
  elf32_addr sh_addr;
  elf32_off  sh_offset;
  elf32_word sh_size;
  elf32_word sh_link;
  elf32_word sh_info;
  elf32_word sh_addralign;
  elf32_word sh_entsize;
} __packed elf32_shdr;

/* Elf symbol */
typedef struct {
  elf32_word st_name;
  elf32_addr st_value;
  elf32_word st_size;
  uint8_t    st_info;
  uint8_t    st_other;
  elf32_half st_shndx;
} __packed elf32_sym;

/* Info: sssssssssssssssssssssssstttttttt */
#define REL32_SYM(x)  ((x) >> 8)
#define REL32_TYPE(x) ((x) & 0xFF)
typedef struct {
  elf32_addr  r_addr;
  elf32_word  r_info;
} __packed elf32_rel;

typedef struct {
  elf32_addr  r_offset;
  elf32_word  r_info;
  elf32_sword r_addend;
} __packed elf32_rela;

#endif
