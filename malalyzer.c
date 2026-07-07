/*
 * malalyzer.c — Malware Analysis Toolkit
 * Reverse engineering utility for malware analysts.
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o malalyzer malalyzer.c -lcrypto -lm
 *   With YARA: gcc -O2 -Wall -Wextra -o malalyzer malalyzer.c -lcrypto -lm -lyara -DYARA_ENABLED
 *
 * Usage: malalyzer <command> [options] <target>
 *
 * Commands:
 *   pe       <file>                      Parse PE structure
 *   elf      <file>                      Parse ELF structure
 *   dump     <pid>                       Dump process memory
 *   strings  [-e <min_entropy>] <file>   Extract strings
 *   hash     <file>                      Compute MD5/SHA1/SHA256
 *   hooks    <file>                      Detect API hooks in PE
 *   yara     <rule_file> <target>        Scan with YARA
 *   decode   <file>                      Decode shellcode
 *   xorsearch [-k <keylen>] <file>       Search XOR-encoded data
 */

#define _GNU_SOURCE
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <getopt.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#ifdef YARA_ENABLED
#include <yara.h>
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */
#define MAX_STR_LEN      65536
#define HEX_DUMP_WIDTH   16
#define MIN_ASCII_STR    4
#define MIN_WIDE_STR     2
#define ENTROPY_THRESH   4.5
#define CHUNK_SIZE       (1024 * 1024)
#define MAX_SECTIONS     96
#define MAX_IMPORTS      16384
#define MAX_EXPORTS      16384
#define MAX_PE_SIZE      (512 * 1024 * 1024)
#define MAX_REGIONS      4096

/* ------------------------------------------------------------------ */
/*  PE structures (winnt.h subset)                                    */
/* ------------------------------------------------------------------ */
#pragma pack(push,1)
typedef struct { uint16_t e_magic; uint16_t e_cblp; uint16_t e_cp;
  uint16_t e_crlc; uint16_t e_cparhdr; uint16_t e_minalloc;
  uint16_t e_maxalloc; uint16_t e_ss; uint16_t e_sp; uint16_t e_csum;
  uint16_t e_ip; uint16_t e_cs; uint16_t e_lfarlc; uint16_t e_ovno;
  uint16_t e_res[4]; uint16_t e_oemid; uint16_t e_oeminfo;
  uint16_t e_res2[10]; uint32_t e_lfanew; } IMAGE_DOS_HEADER;

typedef struct { uint16_t Machine; uint16_t NumberOfSections;
  uint32_t TimeDateStamp; uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols; uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics; } IMAGE_FILE_HEADER;

typedef struct { uint16_t Magic; uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion; uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData; uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint; uint32_t BaseOfCode;
  uint32_t BaseOfData; uint32_t ImageBase; uint32_t SectionAlignment;
  uint32_t FileAlignment; uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion; uint16_t MajorImageVersion;
  uint16_t MinorImageVersion; uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion; uint32_t Win32VersionValue;
  uint32_t SizeOfImage; uint32_t SizeOfHeaders;
  uint32_t CheckSum; uint16_t Subsystem; uint16_t DllCharacteristics;
  uint32_t SizeOfStackReserve; uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve; uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags; uint32_t NumberOfRvaAndSizes;
  uint32_t DataDirectory[16][2]; } IMAGE_OPTIONAL_HEADER32;

typedef struct { uint16_t Magic; uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion; uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData; uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint; uint32_t BaseOfCode;
  uint64_t ImageBase; uint32_t SectionAlignment;
  uint32_t FileAlignment; uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion; uint16_t MajorImageVersion;
  uint16_t MinorImageVersion; uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion; uint32_t Win32VersionValue;
  uint32_t SizeOfImage; uint32_t SizeOfHeaders;
  uint32_t CheckSum; uint16_t Subsystem; uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve; uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve; uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags; uint32_t NumberOfRvaAndSizes;
  uint32_t DataDirectory[16][2]; } IMAGE_OPTIONAL_HEADER64;

typedef struct { uint8_t Name[8]; union { uint32_t PhysicalAddress;
  uint32_t VirtualSize; } Misc; uint32_t VirtualAddress;
  uint32_t SizeOfRawData; uint32_t PointerToRawData;
  uint32_t PointerToRelocations; uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations; uint16_t NumberOfLinenumbers;
  uint32_t Characteristics; } IMAGE_SECTION_HEADER;

typedef struct { uint32_t OriginalFirstThunk; uint32_t TimeDateStamp;
  uint32_t ForwarderChain; uint32_t Name;
  uint32_t FirstThunk; } IMAGE_IMPORT_DESCRIPTOR;

typedef struct { uint32_t Characteristics; uint32_t TimeDateStamp;
  uint16_t MajorVersion; uint16_t MinorVersion; uint32_t Name;
  uint32_t Base; uint32_t NumberOfFunctions;
  uint32_t NumberOfNames; uint32_t AddressOfFunctions;
  uint32_t AddressOfNames; uint32_t AddressOfNameOrdinals; } IMAGE_EXPORT_DIRECTORY;
#pragma pack(pop)

#define DOS_MAGIC     0x5A4D
#define PE_MAGIC      0x00004550
#define PE32_MAGIC    0x10B
#define PE64_MAGIC    0x20B
#define IMAGE_SNAP_BY_ORDINAL(x) ((x) & 0x80000000ULL)
#define IMAGE_ORDINAL(x)         ((x) & 0xFFFF)

/* ------------------------------------------------------------------ */
/*  Utility helpers                                                   */
/* ------------------------------------------------------------------ */
typedef struct { uint8_t key; double score; } key_score_t;
static void fatal(const char *fmt, ...) {
  va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
  fprintf(stderr, "\n"); exit(1);
}

static void *xmalloc(size_t sz) {
  void *p = calloc(1, sz); if (!p) fatal("malloc(%zu) failed", sz); return p;
}



static uint8_t *read_file(const char *path, size_t *out_len) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) fatal("Cannot open %s: %s", path, strerror(errno));
  struct stat st;
  if (fstat(fd, &st)) fatal("fstat %s: %s", path, strerror(errno));
  if (st.st_size > MAX_PE_SIZE) fatal("File too large: %s", path);
  uint8_t *buf = xmalloc(st.st_size + 1);
  ssize_t n = read(fd, buf, st.st_size);
  if (n < 0 || (size_t)n != (size_t)st.st_size)
    fatal("read %s: short read", path);
  close(fd);
  buf[st.st_size] = 0;
  *out_len = st.st_size;
  return buf;
}

static double shannon_entropy(const uint8_t *data, size_t len) {
  if (len == 0) return 0.0;
  double freq[256] = {0};
  for (size_t i = 0; i < len; i++) freq[data[i]]++;
  double e = 0.0;
  for (int i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      double p = freq[i] / (double)len;
      e -= p * log2(p);
    }
  }
  return e;
}

static void hex_dump(const uint8_t *data, size_t len, FILE *fp) {
  for (size_t i = 0; i < len; i += HEX_DUMP_WIDTH) {
    fprintf(fp, "%08zx  ", i);
    for (size_t j = 0; j < HEX_DUMP_WIDTH; j++) {
      if (i + j < len) fprintf(fp, "%02x ", data[i + j]);
      else fprintf(fp, "   ");
      if (j == 7) fputc(' ', fp);
    }
    fputc(' ', fp);
    for (size_t j = 0; j < HEX_DUMP_WIDTH && i + j < len; j++) {
      fputc(isprint(data[i + j]) ? data[i + j] : '.', fp);
    }
    fputc('\n', fp);
  }
}

static uint32_t rva_to_offset(IMAGE_SECTION_HEADER *sec, int nsec, uint32_t rva) {
  for (int i = 0; i < nsec; i++)
    if (rva >= sec[i].VirtualAddress &&
        rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
      return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
  return 0;
}

static const char *pe_subsystem_str(uint16_t s) {
  switch (s) {
    case 1:  return "NATIVE";
    case 2:  return "WINDOWS_GUI";
    case 3:  return "WINDOWS_CUI";
    case 5:  return "OS2_CUI";
    case 7:  return "POSIX_CUI";
    case 8:  return "NATIVE_WINDOWS";
    case 9:  return "WINDOWS_CE_GUI";
    case 10: return "EFI_APPLICATION";
    case 11: return "EFI_BOOT_SERVICE_DRIVER";
    case 12: return "EFI_RUNTIME_DRIVER";
    case 13: return "EFI_ROM";
    case 14: return "XBOX";
    case 16: return "WINDOWS_BOOT_APPLICATION";
    default: return "UNKNOWN";
  }
}

static const char *pe_machine_str(uint16_t m) {
  switch (m) {
    case 0x014c: return "I386";
    case 0x8664: return "AMD64";
    case 0x0200: return "IA64";
    case 0x01c4: return "ARMNT";
    case 0xaa64: return "ARM64";
    case 0x5032: return "RISC-V32";
    case 0x5064: return "RISC-V64";
    case 0x5128: return "RISC-V128";
    default:     return "OTHER";
  }
}

static const char *sec_flags_str(uint32_t c, char *buf, size_t sz) {
  snprintf(buf, sz, "%s%s%s%s%s%s%s%s",
    (c & 0x00000020) ? "CODE " : "",
    (c & 0x00000040) ? "INIT_DATA " : "",
    (c & 0x00000080) ? "UNINIT_DATA " : "",
    (c & 0x20000000) ? "EXECUTE " : "",
    (c & 0x40000000) ? "READ " : "",
    (c & 0x80000000) ? "WRITE " : "",
    (c & 0x02000000) ? "DISCARDABLE " : "",
    (c & 0x01000000) ? "SHARED " : "");
  return buf;
}

/* ------------------------------------------------------------------ */
/*  1. PE Parser                                                      */
/* ------------------------------------------------------------------ */
static int cmd_pe(int argc, char **argv) {
  if (argc < 1) fatal("Usage: malalyzer pe <file>");
  size_t len; uint8_t *buf = read_file(argv[0], &len);
  if (len < sizeof(IMAGE_DOS_HEADER)) fatal("File too small for DOS header");

  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
  if (dos->e_magic != DOS_MAGIC) fatal("Not a PE file (bad DOS magic)");
  if (dos->e_lfanew == 0 || dos->e_lfanew >= len - 4)
    fatal("Invalid e_lfanew");

  uint32_t *pe_sig = (uint32_t *)(buf + dos->e_lfanew);
  if (*pe_sig != PE_MAGIC) fatal("Not a PE file (bad PE magic)");

  IMAGE_FILE_HEADER *fh = (IMAGE_FILE_HEADER *)(buf + dos->e_lfanew + 4);
  int is_64 = 0;
  uint16_t *opt_magic = (uint16_t *)(buf + dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));

  printf("=== PE File Header ===\n");
  printf("Machine:         %s (0x%04x)\n", pe_machine_str(fh->Machine), fh->Machine);
  printf("Sections:        %d\n", fh->NumberOfSections);
  { time_t t = fh->TimeDateStamp; printf("TimeDateStamp:   %s", ctime(&t)); }
  printf("SymbolTable:     0x%x (%u entries)\n",
         fh->PointerToSymbolTable, fh->NumberOfSymbols);
  printf("OptHeaderSize:   %d bytes\n", fh->SizeOfOptionalHeader);
  printf("Characteristics: 0x%04x\n", fh->Characteristics);

  if (*opt_magic == PE64_MAGIC) {
    is_64 = 1;
    printf("\n=== PE32+ Optional Header ===\n");
  } else if (*opt_magic == PE32_MAGIC) {
    printf("\n=== PE32 Optional Header ===\n");
  } else {
    printf("\n(No optional header)\n");
    free(buf); return 0;
  }

  if (is_64) {
    IMAGE_OPTIONAL_HEADER64 *oh = (IMAGE_OPTIONAL_HEADER64 *)opt_magic;
    printf("EntryPoint:      0x%x\n", oh->AddressOfEntryPoint);
    printf("ImageBase:       0x%lx\n", oh->ImageBase);
    printf("CodeBase:        0x%x\n", oh->BaseOfCode);
    printf("SectionAlign:    0x%x\n", oh->SectionAlignment);
    printf("FileAlign:       0x%x\n", oh->FileAlignment);
    printf("Subsystem:       %s (%d)\n", pe_subsystem_str(oh->Subsystem), oh->Subsystem);
    printf("ImageSize:       0x%x\n", oh->SizeOfImage);
    printf("HeaderSize:      0x%x\n", oh->SizeOfHeaders);
    printf("CheckSum:        0x%x\n", oh->CheckSum);
    printf("DllChar:         0x%04x\n", oh->DllCharacteristics);
    printf("StackReserve:    0x%lx\n", oh->SizeOfStackReserve);
    printf("StackCommit:     0x%lx\n", oh->SizeOfStackCommit);
    printf("HeapReserve:     0x%lx\n", oh->SizeOfHeapReserve);
    printf("HeapCommit:      0x%lx\n", oh->SizeOfHeapCommit);
    printf("NumDataDir:      %d\n", oh->NumberOfRvaAndSizes);
  } else {
    IMAGE_OPTIONAL_HEADER32 *oh = (IMAGE_OPTIONAL_HEADER32 *)opt_magic;
    printf("EntryPoint:      0x%x\n", oh->AddressOfEntryPoint);
    printf("ImageBase:       0x%x\n", oh->ImageBase);
    printf("CodeBase:        0x%x\n", oh->BaseOfCode);
    printf("DataBase:        0x%x\n", oh->BaseOfData);
    printf("SectionAlign:    0x%x\n", oh->SectionAlignment);
    printf("FileAlign:       0x%x\n", oh->FileAlignment);
    printf("Subsystem:       %s (%d)\n", pe_subsystem_str(oh->Subsystem), oh->Subsystem);
    printf("ImageSize:       0x%x\n", oh->SizeOfImage);
    printf("HeaderSize:      0x%x\n", oh->SizeOfHeaders);
    printf("CheckSum:        0x%x\n", oh->CheckSum);
    printf("DllChar:         0x%04x\n", oh->DllCharacteristics);
    printf("StackReserve:    0x%x\n", oh->SizeOfStackReserve);
    printf("StackCommit:     0x%x\n", oh->SizeOfStackCommit);
    printf("HeapReserve:     0x%x\n", oh->SizeOfHeapReserve);
    printf("HeapCommit:      0x%x\n", oh->SizeOfHeapCommit);
    printf("NumDataDir:      %d\n", oh->NumberOfRvaAndSizes);
  }

  /* Sections */
  int nsec = fh->NumberOfSections;
  if (nsec > MAX_SECTIONS) nsec = MAX_SECTIONS;
  IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)((uint8_t *)opt_magic +
    fh->SizeOfOptionalHeader);

  printf("\n=== Sections (%d) ===\n", nsec);
  printf("%-10s %-10s %-10s %-10s %-10s %s\n",
         "Name", "VirtAddr", "VirtSize", "RawOff", "RawSize", "Flags");
  for (int i = 0; i < nsec; i++) {
    char fbuf[128];
    printf("%-10s 0x%08x 0x%08x 0x%08x 0x%08x %s\n",
           sec[i].Name, sec[i].VirtualAddress, sec[i].Misc.VirtualSize,
           sec[i].PointerToRawData, sec[i].SizeOfRawData,
           sec_flags_str(sec[i].Characteristics, fbuf, sizeof(fbuf)));
  }

  /* Data directories */
  int ndirs;
  uint32_t (*dirs)[2];
  if (is_64) {
    IMAGE_OPTIONAL_HEADER64 *oh = (IMAGE_OPTIONAL_HEADER64 *)opt_magic;
    ndirs = oh->NumberOfRvaAndSizes; dirs = oh->DataDirectory;
  } else {
    IMAGE_OPTIONAL_HEADER32 *oh = (IMAGE_OPTIONAL_HEADER32 *)opt_magic;
    ndirs = oh->NumberOfRvaAndSizes; dirs = oh->DataDirectory;
  }
  if (ndirs > 16) ndirs = 16;

  static const char *dir_names[16] = {
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
    "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
    "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT",
    "COM_DESCRIPTOR", "RESERVED" };

  printf("\n=== Data Directories ===\n");
  printf("%-20s %-12s %s\n", "Directory", "RVA", "Size");
  for (int i = 0; i < ndirs; i++) {
    if (dirs[i][0] == 0 && dirs[i][1] == 0) continue;
    printf("%-20s 0x%08x  0x%08x\n",
           (i < 16) ? dir_names[i] : "UNKNOWN", dirs[i][0], dirs[i][1]);
  }

  /* Imports */
  uint32_t import_rva = dirs[1][0];
  uint32_t import_sz  = dirs[1][1];
  if (import_rva && import_sz) {
    uint32_t off = rva_to_offset(sec, nsec, import_rva);
    printf("\n=== Imports (directory @ 0x%x, RVAs: 0x%x, size: 0x%x, file off: 0x%x) ===\n",
           import_rva, import_rva, import_sz, off);
    if (off && off < len) {
      IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(buf + off);
      for (int i = 0; imp[i].OriginalFirstThunk || imp[i].FirstThunk; i++) {
        if (i >= MAX_IMPORTS) { printf("(truncated at %d imports)\n", MAX_IMPORTS); break; }
        uint32_t name_off = rva_to_offset(sec, nsec, imp[i].Name);
        char *dll_name = name_off ? (char *)(buf + name_off) : "?";
        printf("  DLL: %s\n", dll_name);
        uint32_t thunk_rva = imp[i].OriginalFirstThunk ?
                             imp[i].OriginalFirstThunk : imp[i].FirstThunk;
        uint32_t thunk_off = rva_to_offset(sec, nsec, thunk_rva);
        if (thunk_off && thunk_off < len) {
          if (is_64) {
            uint64_t *thunk = (uint64_t *)(buf + thunk_off);
            for (int j = 0; thunk[j]; j++) {
              if (IMAGE_SNAP_BY_ORDINAL(thunk[j])) {
                printf("    [%d] Ordinal: %u\n", j, (unsigned)IMAGE_ORDINAL(thunk[j]));
              } else {
                uint32_t n_off = rva_to_offset(sec, nsec, (uint32_t)(thunk[j] & 0x7FFFFFFF) + 2);
                char *fn = (n_off && n_off < len) ? (char *)(buf + n_off) : "?";
                printf("    [%d] %s\n", j, fn);
              }
            }
          } else {
            uint32_t *thunk = (uint32_t *)(buf + thunk_off);
            for (int j = 0; thunk[j]; j++) {
              if (IMAGE_SNAP_BY_ORDINAL(thunk[j])) {
                printf("    [%d] Ordinal: %u\n", j, (unsigned)IMAGE_ORDINAL(thunk[j]));
              } else {
                uint32_t n_off = rva_to_offset(sec, nsec, thunk[j] + 2);
                char *fn = (n_off && n_off < len) ? (char *)(buf + n_off) : "?";
                printf("    [%d] %s\n", j, fn);
              }
            }
          }
        }
      }
    }
  }

  /* Exports */
  uint32_t export_rva = dirs[0][0];
  if (export_rva) {
    uint32_t eoff = rva_to_offset(sec, nsec, export_rva);
    if (eoff && eoff + sizeof(IMAGE_EXPORT_DIRECTORY) <= len) {
      IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(buf + eoff);
      printf("\n=== Exports ===\n");
      uint32_t name_off = rva_to_offset(sec, nsec, exp->Name);
      printf("Name:            %s\n", name_off ? (char *)(buf + name_off) : "?");
      printf("Base:            %u\n", exp->Base);
      printf("NumFunctions:    %u\n", exp->NumberOfFunctions);
      printf("NumNames:        %u\n", exp->NumberOfNames);
      uint32_t addr_off = rva_to_offset(sec, nsec, exp->AddressOfFunctions);
      uint32_t namearr_off = rva_to_offset(sec, nsec, exp->AddressOfNames);
      uint32_t ord_off = rva_to_offset(sec, nsec, exp->AddressOfNameOrdinals);
      if (addr_off && addr_off < len) {
        uint32_t *funcs = (uint32_t *)(buf + addr_off);
        uint32_t *names = namearr_off ? (uint32_t *)(buf + namearr_off) : NULL;
        uint16_t *ords  = ord_off ? (uint16_t *)(buf + ord_off) : NULL;
        int nf = exp->NumberOfFunctions;
        if (nf > MAX_EXPORTS) nf = MAX_EXPORTS;
        for (int i = 0; i < nf; i++) {
          if (funcs[i] == 0) continue;
          char *ename = NULL;
          if (names && ords)
            for (unsigned j = 0; j < exp->NumberOfNames; j++)
              if (ords[j] == (uint16_t)i) {
                uint32_t no = rva_to_offset(sec, nsec, names[j]);
                if (no) ename = (char *)(buf + no);
                break;
              }
          printf("  [%4d] %s RVA: 0x%08x\n", i + exp->Base,
                 ename ? ename : "(ordinal)", funcs[i]);
        }
      }
    }
  }

  /* Anomaly detection */
  printf("\n=== Anomaly Scan ===\n");
  int anom = 0;
  for (int i = 0; i < nsec; i++) {
    if (sec[i].SizeOfRawData > len - sec[i].PointerToRawData &&
        sec[i].PointerToRawData < len) {
      printf("[!] Section %.*s: raw data extends beyond EOF\n", 8, sec[i].Name);
      anom++;
    }
    if (sec[i].Characteristics & 0x80000000 && /* writable */
        sec[i].Characteristics & 0x20000000) { /* executable */
      printf("[!] Section %.*s: W+X (write+execute)\n", 8, sec[i].Name);
      anom++;
    }
    if (sec[i].VirtualAddress == 0) {
      printf("[!] Section %.*s: null virtual address\n", 8, sec[i].Name);
      anom++;
    }
  }
  if ((fh->Characteristics & 0x2000) && /* DLL */
      (fh->Characteristics & 0x0002))   /* EXE */
    { printf("[!] FILE is both DLL and EXE\n"); anom++; }
  if (!anom) printf("(none)\n");

  free(buf);
  return 0;
}

/* ------------------------------------------------------------------ */
/*  2. ELF Parser                                                     */
/* ------------------------------------------------------------------ */
#include <elf.h>

static const char *elf_type_str(uint16_t t) {
  switch (t) { case 0: return "NONE"; case 1: return "REL";
    case 2: return "EXEC"; case 3: return "DYN";
    case 4: return "CORE"; default: return "OTHER"; }
}

static const char *elf_machine_str(uint16_t m) {
  switch (m) {
    case 3: return "i386"; case 62: return "x86_64";
    case 40: return "ARM"; case 183: return "AARCH64";
    case 243: return "RISC-V"; default: return "OTHER";
  }
}

static const char *elf_pf_str(uint32_t f, char *buf, size_t sz) {
  snprintf(buf, sz, "%s%s%s",
    (f & 4) ? "R" : "-", (f & 2) ? "W" : "-", (f & 1) ? "X" : "-");
  return buf;
}

static const char *elf_sht_str(uint32_t t) {
  switch (t) {
    case 0: return "NULL"; case 1: return "PROGBITS"; case 2: return "SYMTAB";
    case 3: return "STRTAB"; case 4: return "RELA"; case 5: return "HASH";
    case 6: return "DYNAMIC"; case 7: return "NOTE"; case 8: return "NOBITS";
    case 9: return "REL"; case 11: return "DYNSYM";
    default: return "OTHER";
  }
}

static int cmd_elf(int argc, char **argv) {
  if (argc < 1) fatal("Usage: malalyzer elf <file>");
  size_t len; uint8_t *buf = read_file(argv[0], &len);
  if (len < EI_NIDENT + 2) fatal("File too small for ELF header");

  unsigned char *ei = buf;
  if (ei[EI_MAG0] != ELFMAG0 || ei[EI_MAG1] != ELFMAG1 ||
      ei[EI_MAG2] != ELFMAG2 || ei[EI_MAG3] != ELFMAG3)
    fatal("Not an ELF file");

  int is_64 = (ei[EI_CLASS] == ELFCLASS64);

  if (!is_64) {
    /* 32-bit */
    Elf32_Ehdr *eh = (Elf32_Ehdr *)buf;
    printf("=== ELF32 Header ===\n");
    printf("Type:            %s (%d)\n", elf_type_str(eh->e_type), eh->e_type);
    printf("Machine:         %s (0x%x)\n", elf_machine_str(eh->e_machine), eh->e_machine);
    printf("Version:         %u\n", eh->e_version);
    printf("EntryPoint:      0x%x\n", eh->e_entry);
    printf("Phoffset:        %u (phoff)\n", eh->e_phoff);
    printf("Shoffset:        %u (shoff)\n", eh->e_shoff);
    printf("Flags:           0x%x\n", eh->e_flags);
    printf("Ehsize:          %u\n", eh->e_ehsize);
    printf("Phentsize:       %u\n", eh->e_phentsize);
    printf("Phnum:           %u\n", eh->e_phnum);
    printf("Shentsize:       %u\n", eh->e_shentsize);
    printf("Shnum:           %u\n", eh->e_shnum);
    printf("Shstrndx:        %u\n", eh->e_shstrndx);

    /* Program headers */
    if (eh->e_phoff && eh->e_phnum) {
      printf("\n=== Program Headers (%u) ===\n", eh->e_phnum);
      Elf32_Phdr *ph = (Elf32_Phdr *)(buf + eh->e_phoff);
      printf("%-8s %-12s %-12s %-10s %-10s %-10s %s\n",
             "Type", "Offset", "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flags");
      for (int i = 0; i < eh->e_phnum; i++) {
        char fb[8];
        printf("%-8u 0x%08x   0x%08x   0x%08x   0x%08x 0x%08x %s\n",
               ph[i].p_type, ph[i].p_offset, ph[i].p_vaddr,
               ph[i].p_paddr, ph[i].p_filesz, ph[i].p_memsz,
               elf_pf_str(ph[i].p_flags, fb, sizeof(fb)));
      }
    }

    /* Section headers */
    if (eh->e_shoff && eh->e_shnum) {
      printf("\n=== Section Headers (%u) ===\n", eh->e_shnum);
      Elf32_Shdr *sh = (Elf32_Shdr *)(buf + eh->e_shoff);
      Elf32_Shdr *shstr = (eh->e_shstrndx < eh->e_shnum) ? &sh[eh->e_shstrndx] : NULL;
      char *shstrtab = (shstr && shstr->sh_offset) ? (char *)(buf + shstr->sh_offset) : NULL;
      printf("%-3s %-18s %-10s %-10s %-10s %-10s %s\n",
             "#", "Name", "Type", "Addr", "Offset", "Size", "Entire");
      for (int i = 0; i < eh->e_shnum; i++) {
        char *name = (shstrtab && sh[i].sh_name < len) ? shstrtab + sh[i].sh_name : "?";
        printf("%-3d %-18s %-10s 0x%08x 0x%08x 0x%08x 0x%x\n",
               i, name, elf_sht_str(sh[i].sh_type),
               sh[i].sh_addr, sh[i].sh_offset, sh[i].sh_size, sh[i].sh_entsize);
      }

      /* Symbol table */
      for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type == SHT_SYMTAB || sh[i].sh_type == SHT_DYNSYM) {
          Elf32_Sym *sym = (Elf32_Sym *)(buf + sh[i].sh_offset);
          int nsym = sh[i].sh_size / sh[i].sh_entsize;
          Elf32_Shdr *strsec = &sh[sh[i].sh_link];
          char *strtab = (char *)(buf + strsec->sh_offset);
          printf("\n=== Symbols (section %d, %d entries) ===\n", i, nsym);
          printf("%-30s %-10s %s\n", "Name", "Value", "Size");
          for (int j = 0; j < nsym && j < 500; j++) {
            char *sn = strtab + sym[j].st_name;
            if (sym[j].st_name && sym[j].st_value)
              printf("%-30s 0x%08x %u\n", sn, sym[j].st_value, sym[j].st_size);
          }
          if (nsym > 500) printf("... (truncated)\n");
        }
      }
    }
  } else {
    /* 64-bit */
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    printf("=== ELF64 Header ===\n");
    printf("Type:            %s (%d)\n", elf_type_str(eh->e_type), eh->e_type);
    printf("Machine:         %s (0x%x)\n", elf_machine_str(eh->e_machine), eh->e_machine);
    printf("Version:         %u\n", eh->e_version);
    printf("EntryPoint:      0x%lx\n", eh->e_entry);
    printf("Phoffset:        %lu (phoff)\n", eh->e_phoff);
    printf("Shoffset:        %lu (shoff)\n", eh->e_shoff);
    printf("Flags:           0x%x\n", eh->e_flags);
    printf("Ehsize:          %u\n", eh->e_ehsize);
    printf("Phentsize:       %u\n", eh->e_phentsize);
    printf("Phnum:           %u\n", eh->e_phnum);
    printf("Shentsize:       %u\n", eh->e_shentsize);
    printf("Shnum:           %u\n", eh->e_shnum);
    printf("Shstrndx:        %u\n", eh->e_shstrndx);

    if (eh->e_phoff && eh->e_phnum) {
      printf("\n=== Program Headers (%u) ===\n", eh->e_phnum);
      Elf64_Phdr *ph = (Elf64_Phdr *)(buf + eh->e_phoff);
      printf("%-8s %-12s %-18s %-10s %-10s %s\n",
             "Type", "Offset", "VirtAddr", "FileSiz", "MemSiz", "Flags");
      for (int i = 0; i < eh->e_phnum; i++) {
        char fb[8];
        printf("%-8u 0x%08lx   0x%016lx   0x%08lx 0x%08lx %s\n",
               ph[i].p_type, ph[i].p_offset, ph[i].p_vaddr,
               ph[i].p_filesz, ph[i].p_memsz,
               elf_pf_str(ph[i].p_flags, fb, sizeof(fb)));
      }
    }

    if (eh->e_shoff && eh->e_shnum) {
      printf("\n=== Section Headers (%u) ===\n", eh->e_shnum);
      Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff);
      Elf64_Shdr *shstr = (eh->e_shstrndx < eh->e_shnum) ? &sh[eh->e_shstrndx] : NULL;
      char *shstrtab = (shstr && shstr->sh_offset < len) ? (char *)(buf + shstr->sh_offset) : NULL;
      printf("%-3s %-20s %-10s %-18s %-10s %-10s %s\n",
             "#", "Name", "Type", "Addr", "Offset", "Size", "Entire");
      for (int i = 0; i < eh->e_shnum; i++) {
        char *name = (shstrtab && sh[i].sh_name < len) ? shstrtab + sh[i].sh_name : "?";
        printf("%-3d %-20s %-10s 0x%016lx 0x%08lx 0x%08lx 0x%lx\n",
               i, name, elf_sht_str(sh[i].sh_type),
               sh[i].sh_addr, sh[i].sh_offset, sh[i].sh_size, sh[i].sh_entsize);
      }

      for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type == SHT_SYMTAB || sh[i].sh_type == SHT_DYNSYM) {
          Elf64_Sym *sym = (Elf64_Sym *)(buf + sh[i].sh_offset);
          int nsym = sh[i].sh_size / sh[i].sh_entsize;
          Elf64_Shdr *strsec = &sh[sh[i].sh_link];
          char *strtab = (strsec->sh_offset < len) ? (char *)(buf + strsec->sh_offset) : NULL;
          printf("\n=== Symbols (section %d, %d entries) ===\n", i, nsym);
          printf("%-30s %-18s %s\n", "Name", "Value", "Size");
          for (int j = 0; j < nsym && j < 500; j++) {
            if (!strtab || !sym[j].st_name || !sym[j].st_value) continue;
            printf("%-30s 0x%016lx %lu\n", strtab + sym[j].st_name,
                   sym[j].st_value, sym[j].st_size);
          }
          if (nsym > 500) printf("... (truncated)\n");
        }
      }
    }
  }

  free(buf);
  return 0;
}

/* ------------------------------------------------------------------ */
/*  3. Process Memory Dumper                                          */
/* ------------------------------------------------------------------ */
static int cmd_dump(int argc, char **argv) {
  if (argc < 1) fatal("Usage: malalyzer dump <pid>");
  pid_t pid = atoi(argv[0]);
  if (pid <= 0) fatal("Invalid PID: %s", argv[0]);

  char path[256];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *fp = fopen(path, "r");
  if (!fp) fatal("Cannot open %s: %s", path, strerror(errno));

  snprintf(path, sizeof(path), "/proc/%d/mem", pid);
  int mem_fd = open(path, O_RDONLY);
  if (mem_fd < 0) { fclose(fp); fatal("Cannot open %s: %s", path, strerror(errno)); }

  char line[1024];
  char dump_dir[64];
  snprintf(dump_dir, sizeof(dump_dir), "dump_%d", pid);
  mkdir(dump_dir, 0755);

  printf("Dumping process %d memory to %s/\n", pid, dump_dir);
  printf("%-20s %-18s %-10s %s\n", "Region", "Address", "Size", "Perm");

  int region = 0;
  while (fgets(line, sizeof(line), fp)) {
    unsigned long start, end, offset, inode;
    char perms[8], dev[16], pathname[256] = "";
    int n = sscanf(line, "%lx-%lx %4s %lx %15s %lu %255s",
                   &start, &end, perms, &offset, dev, &inode, pathname);
    if (n < 6) continue;
    if (pathname[0] == 0) snprintf(pathname, sizeof(pathname), "[anonymous]");

    size_t size = end - start;
    if (size == 0 || size > (size_t)1 << 40) continue;
    region++;
    if (region > MAX_REGIONS) { printf("(truncated at %d regions)\n", MAX_REGIONS); break; }

    char fname[512];
    snprintf(fname, sizeof(fname), "%s/region_%03d_0x%lx_0x%lx_%s_%s.bin",
             dump_dir, region, start, end, perms,
             strchr(pathname, '/') ? strrchr(pathname, '/') + 1 : pathname);
    /* sanitize filename */
    for (char *p = fname; *p; p++) if (*p == '/' || *p == ' ') *p = '_';

    uint8_t *chunk = xmalloc(size > CHUNK_SIZE ? CHUNK_SIZE : size);
    size_t total = 0;
    FILE *out = fopen(fname, "wb");
    if (!out) { free(chunk); continue; }
    while (total < size) {
      size_t to_read = (size - total > CHUNK_SIZE) ? CHUNK_SIZE : (size - total);
      ssize_t r = pread(mem_fd, chunk, to_read, start + total);
      if (r <= 0) break;
      fwrite(chunk, 1, r, out);
      total += r;
    }
    fclose(out);
    double ent = shannon_entropy(chunk, total > 0 ? (total > 256 ? 256 : total) : 0);
    printf("region_%03d       0x%lx-0x%lx  %-8zu %-4s  [%.1f] ",
           region, start, end, size, perms, ent);
    if (total > 0 && total < size) printf("(partial: %zu/%zu)", total, size);
    printf("\n");
    free(chunk);
  }

  close(mem_fd);
  fclose(fp);
  printf("\nDumped %d regions to %s/\n", region, dump_dir);
  return 0;
}

/* ------------------------------------------------------------------ */
/*  4. String Extractor                                                */
/* ------------------------------------------------------------------ */
static int cmd_strings(int argc, char **argv) {
  double min_entropy = 0.0;
  char *file = NULL;

  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "-e") == 0 && i + 1 < argc)
      min_entropy = atof(argv[++i]);
    else
      file = argv[i];
  }
  if (!file) fatal("Usage: malalyzer strings [-e <min_entropy>] <file>");

  size_t len; uint8_t *buf = read_file(file, &len);
  int total = 0;

  printf("=== Strings (min_entropy=%.1f) ===\n", min_entropy);

  /* ASCII strings */
  for (size_t i = 0; i < len; i++) {
    if (isprint(buf[i]) || buf[i] == '\t' || buf[i] == '\r' || buf[i] == '\n') {
      size_t start = i;
      while (i < len && (isprint(buf[i]) || buf[i] == '\t' || buf[i] == '\r' || buf[i] == '\n')) i++;
      size_t slen = i - start;
      if (slen >= (size_t)MIN_ASCII_STR && slen < MAX_STR_LEN) {
        double e = shannon_entropy(buf + start, slen);
        if (e >= min_entropy) {
          printf("[A:%.1f] %.*s\n", e, (int)slen, buf + start);
          total++;
        }
      }
    }
  }

  /* Wide/Unicode strings */
  for (size_t i = 0; i + 1 < len; i += 2) {
    if (buf[i + 1] == 0 && isprint(buf[i])) {
      size_t start = i;
      while (i + 1 < len && buf[i + 1] == 0 && (isprint(buf[i]) || buf[i] == 0))
        i += 2;
      size_t slen = (i - start) / 2;
      if (slen >= (size_t)MIN_WIDE_STR && slen < MAX_STR_LEN / 2) {
        uint8_t *utf8 = xmalloc(slen + 1);
        for (size_t j = 0; j < slen; j++) utf8[j] = buf[start + j * 2];
        utf8[slen] = 0;
        double e = shannon_entropy(utf8, slen);
        if (e >= min_entropy) {
          printf("[W:%.1f] %s\n", e, (char *)utf8);
          total++;
        }
        free(utf8);
      }
    }
  }

  printf("Total: %d strings\n", total);
  free(buf);
  return 0;
}

/* ------------------------------------------------------------------ */
/*  5. Hash Computation                                                */
/* ------------------------------------------------------------------ */
static int cmd_hash(int argc, char **argv) {
  if (argc < 1) fatal("Usage: malalyzer hash <file>");
  size_t len; uint8_t *buf = read_file(argv[0], &len);

  unsigned char md5_out[MD5_DIGEST_LENGTH];
  MD5(buf, len, md5_out);
  printf("MD5:    ");
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", md5_out[i]);
  printf("\n");

  unsigned char sha1_out[SHA_DIGEST_LENGTH];
  SHA1(buf, len, sha1_out);
  printf("SHA1:   ");
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++) printf("%02x", sha1_out[i]);
  printf("\n");

  unsigned char sha256_out[SHA256_DIGEST_LENGTH];
  SHA256(buf, len, sha256_out);
  printf("SHA256: ");
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", sha256_out[i]);
  printf("\n");

  double ent = shannon_entropy(buf, len > 65536 ? 65536 : len);
  printf("Entropy: %.4f (first %zu bytes)\n", ent, len > 65536 ? (size_t)65536 : len);
  printf("Size:    %zu bytes\n", len);

  free(buf);
  return 0;
}

/* ------------------------------------------------------------------ */
/*  6. API Hook Detector (PE IAT + inline)                             */
/* ------------------------------------------------------------------ */

/* Suspicious IAT entries that often indicate hooking */
static const char *hooked_api_probes[] = {
  "NtOpenProcess", "NtReadVirtualMemory", "NtWriteVirtualMemory",
  "NtClose", "NtCreateFile", "NtDeviceIoControlFile",
  "NtProtectVirtualMemory", "NtAllocateVirtualMemory",
  "NtFreeVirtualMemory", "NtCreateThreadEx", "NtOpenThread",
  "NtResumeThread", "NtSuspendThread", "NtGetContextThread",
  "NtSetContextThread", "NtQueueApcThread", "NtCreateUserProcess",
  "NtOpenKey", "NtOpenKeyEx", "NtCreateKey", "NtDeleteKey",
  "NtEnumerateKey", "NtQueryKey", "NtSetValueKey",
  "NtQueryValueKey", "NtDeleteValueKey", "NtFlushKey",
  "NtLoadKey", "NtUnloadKey", "NtRenameKey",
  "NtOpenKeyedEvent", "NtCreateKeyedEvent",
  "NtQuerySystemInformation", "NtQueryInformationProcess",
  "NtSetInformationProcess", "NtQueryObject",
  "NtDuplicateObject", "NtQueryDirectoryFile",
  "LdrLoadDll", "LdrGetProcedureAddress",
  "CreateRemoteThread", "SetWindowsHookEx",
  NULL
};

static int cmd_hooks(int argc, char **argv) {
  if (argc < 1) fatal("Usage: malalyzer hooks <pe_file>");
  size_t len; uint8_t *buf = read_file(argv[0], &len);

  if (len < sizeof(IMAGE_DOS_HEADER)) fatal("File too small");
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
  if (dos->e_magic != DOS_MAGIC) fatal("Not a PE file");
  if (dos->e_lfanew == 0 || dos->e_lfanew >= len - 4) fatal("Invalid e_lfanew");

  uint32_t *pe_sig = (uint32_t *)(buf + dos->e_lfanew);
  if (*pe_sig != PE_MAGIC) fatal("Not a PE file");
  IMAGE_FILE_HEADER *fh = (IMAGE_FILE_HEADER *)(buf + dos->e_lfanew + 4);
  uint16_t *opt_magic = (uint16_t *)(buf + dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
  int is_64 = (*opt_magic == PE64_MAGIC);
  int nsec = fh->NumberOfSections;
  if (nsec > MAX_SECTIONS) nsec = MAX_SECTIONS;
  IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)((uint8_t *)opt_magic +
    fh->SizeOfOptionalHeader);

  uint32_t (*dirs)[2];
  if (is_64) dirs = ((IMAGE_OPTIONAL_HEADER64 *)opt_magic)->DataDirectory;
  else       dirs = ((IMAGE_OPTIONAL_HEADER32 *)opt_magic)->DataDirectory;
  int ndirs = (is_64 ? ((IMAGE_OPTIONAL_HEADER64 *)opt_magic)->NumberOfRvaAndSizes
                     : ((IMAGE_OPTIONAL_HEADER32 *)opt_magic)->NumberOfRvaAndSizes);
  if (ndirs > 16) ndirs = 16;

  printf("=== IAT Hook Detection ===\n");
  uint32_t iat_rva = dirs[12][0]; /* IAT directory */
  uint32_t import_rva = dirs[1][0];

  if (iat_rva == 0 && import_rva == 0) {
    printf("No IAT or import directory found.\n");
    free(buf); return 0;
  }

  /* Scan IAT entries for suspicious patterns */
  uint32_t iat_off_import = rva_to_offset(sec, nsec, import_rva);

  printf("\n[IAT Scan]\n");
  int hook_found = 0;
  if (iat_off_import && iat_off_import < len) {
    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(buf + iat_off_import);
    for (int i = 0; imp[i].OriginalFirstThunk || imp[i].FirstThunk; i++) {
      uint32_t name_off = rva_to_offset(sec, nsec, imp[i].Name);
      char *dll = name_off ? (char *)(buf + name_off) : "?";
      uint32_t thunk_rva = imp[i].OriginalFirstThunk ?
                           imp[i].OriginalFirstThunk : imp[i].FirstThunk;
      uint32_t thunk_off = rva_to_offset(sec, nsec, thunk_rva);
      if (!thunk_off || thunk_off >= len) continue;

      if (is_64) {
        uint64_t *thunk = (uint64_t *)(buf + thunk_off);
        for (int j = 0; thunk[j]; j++) {
          if (!IMAGE_SNAP_BY_ORDINAL(thunk[j])) {
            uint32_t fn_off = rva_to_offset(sec, nsec, (uint32_t)(thunk[j] & 0x7FFFFFFF) + 2);
            char *fn = (fn_off && fn_off < len) ? (char *)(buf + fn_off) : "?";
            /* Check against sensitive API list */
            for (int k = 0; hooked_api_probes[k]; k++) {
              if (strcasecmp(fn, hooked_api_probes[k]) == 0) {
                printf("[HOOK-SENSITIVE] %s!%s (IAT entry)\n", dll, fn);
                hook_found++;
              }
            }
          }
        }
      } else {
        uint32_t *thunk = (uint32_t *)(buf + thunk_off);
        for (int j = 0; thunk[j]; j++) {
          if (!IMAGE_SNAP_BY_ORDINAL(thunk[j])) {
            uint32_t fn_off = rva_to_offset(sec, nsec, thunk[j] + 2);
            char *fn = (fn_off && fn_off < len) ? (char *)(buf + fn_off) : "?";
            for (int k = 0; hooked_api_probes[k]; k++) {
              if (strcasecmp(fn, hooked_api_probes[k]) == 0) {
                printf("[HOOK-SENSITIVE] %s!%s (IAT entry)\n", dll, fn);
                hook_found++;
              }
            }
          }
        }
      }
    }
  }
  if (!hook_found) printf("No sensitive IAT entries flagged.\n");

  /* Inline hook detection: scan executable sections for JMP/CALL rel32 patterns */
  printf("\n[Inline Hook Scan]\n");
  int inline_found = 0;
  for (int i = 0; i < nsec; i++) {
    if (!(sec[i].Characteristics & 0x20000000)) continue; /* skip non-exec */

    uint32_t raw_off = sec[i].PointerToRawData;
    uint32_t raw_sz  = sec[i].SizeOfRawData;
    uint32_t virt_addr = sec[i].VirtualAddress;
    if (raw_off == 0 || raw_sz == 0 || raw_off + raw_sz > len) continue;

    uint8_t *data = buf + raw_off;
    for (uint32_t j = 0; j + 4 < raw_sz; j++) {
      /* JMP rel32: E9 xx xx xx xx */
      if (data[j] == 0xE9) {
        int32_t disp = *(int32_t *)(data + j + 1);
        uint32_t target = virt_addr + j + 5 + disp;
        printf("[INLINE] JMP rel32 at 0x%08x -> 0x%08x (%s+0x%x)\n",
               virt_addr + j, target, sec[i].Name, j);
        inline_found++;
        j += 4;
      }
      /* CALL rel32: E8 xx xx xx xx */
      else if (data[j] == 0xE8) {
        int32_t disp = *(int32_t *)(data + j + 1);
        uint32_t target = virt_addr + j + 5 + disp;
        if (target < virt_addr || target >= virt_addr + raw_sz) {
          printf("[INLINE] CALL rel32 at 0x%08x -> 0x%08x (%s+0x%x) [cross-section]\n",
                 virt_addr + j, target, sec[i].Name, j);
          inline_found++;
        }
        j += 4;
      }
      /* PUSH-RET sequence: 68 xx xx xx xx C3 (push imm32; ret) */
      else if (j + 5 < raw_sz && data[j] == 0x68 && data[j+5] == 0xC3) {
        uint32_t target = *(uint32_t *)(data + j + 1);
        printf("[INLINE] PUSH-RET at 0x%08x -> 0x%08x (%s+0x%x)\n",
               virt_addr + j, target, sec[i].Name, j);
        inline_found++;
        j += 5;
      }
      /* JMP [mem] indirect: FF 25 xx xx xx xx */
      else if (j + 5 < raw_sz && data[j] == 0xFF && data[j+1] == 0x25) {
        uint32_t target = *(uint32_t *)(data + j + 2);
        printf("[INLINE] JMP [mem] at 0x%08x -> [0x%08x] (%s+0x%x)\n",
               virt_addr + j, target, sec[i].Name, j);
        inline_found++;
        j += 5;
      }
    }
  }
  if (!inline_found) printf("No inline hooks detected.\n");
  if (inline_found) printf("\nTotal inline hook candidates: %d\n", inline_found);

  /* Section anomaly detection for hooking */
  printf("\n[Section Anomalies]\n");
  int sec_anom = 0;
  for (int i = 0; i < nsec; i++) {
    if (sec[i].Characteristics & 0x80000000 && /* writable */
        sec[i].Characteristics & 0x20000000) { /* executable */
      printf("[WARN] W+X section: %s (0x%08x)\n", sec[i].Name, sec[i].VirtualAddress);
      sec_anom++;
    }
    /* Check for modified .text section (suspicious) */
    double e = 0;
    if (sec[i].PointerToRawData && sec[i].SizeOfRawData &&
        sec[i].PointerToRawData < len) {
      size_t check_len = (sec[i].SizeOfRawData > 4096) ? 4096 : sec[i].SizeOfRawData;
      e = shannon_entropy(buf + sec[i].PointerToRawData, check_len);
    }
    if (e > 7.5) {
      printf("[WARN] High-entropy section: %s (%.2f) — possible packed/encrypted\n",
             sec[i].Name, e);
      sec_anom++;
    }
  }
  if (!sec_anom) printf("No section anomalies.\n");

  free(buf);
  return 0;
}

/* ------------------------------------------------------------------ */
/*  7. YARA Scan Wrapper                                               */
/* ------------------------------------------------------------------ */
#ifdef YARA_ENABLED
static int yara_callback(int message, void *data, void *user_data) {
  if (message == YARA_CALLBACK_MATCH_RULE) {
    YR_RULE *rule = data;
    printf("Match: %s", rule->identifier);
    YR_META *meta = NULL;
    yr_rule_metas_foreach(rule, meta) {
      if (meta->type == META_TYPE_STRING && strcmp(meta->identifier, "description") == 0)
        printf(" (%s)", meta->string);
    }
    printf("\n");
    YR_STRING *string = NULL;
    yr_rule_strings_foreach(rule, string) {
      YR_MATCH *match = NULL;
      yr_string_matches_foreach(string, match) {
        printf("  offset: 0x%x, length: %zu\n",
               match->offset, match->match_length);
      }
    }
  }
  return CALLBACK_CONTINUE;
}
#endif

static int cmd_yara(int argc, char **argv) {
#ifndef YARA_ENABLED
  (void)argc; (void)argv;
  fatal("YARA support not compiled. Rebuild with -DYARA_ENABLED -lyara");
#else
  if (argc < 2) fatal("Usage: malalyzer yara <rule_file> <target>");
  if (yr_initialize() != ERROR_SUCCESS)
    fatal("YARA initialization failed");

  YR_COMPILER *compiler = NULL;
  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
    fatal("yr_compiler_create failed");

  FILE *rfp = fopen(argv[0], "r");
  if (!rfp) fatal("Cannot open rule file: %s", argv[0]);
  fseek(rfp, 0, SEEK_END);
  long rsize = ftell(rfp);
  rewind(rfp);
  char *rules_text = xmalloc(rsize + 1);
  if (fread(rules_text, 1, rsize, rfp) != (size_t)rsize)
    fatal("Error reading rule file");
  fclose(rfp);
  rules_text[rsize] = 0;

  if (yr_compiler_add_string(compiler, rules_text, NULL) != 0)
    fatal("YARA rule compilation failed (syntax error)");
  free(rules_text);

  YR_RULES *rules = NULL;
  if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
    fatal("yr_compiler_get_rules failed");

  printf("Scanning %s with %s ...\n", argv[1], argv[0]);
  int result = yr_rules_scan_file(rules, argv[1], yara_callback, NULL, 0);
  if (result != ERROR_SUCCESS)
    printf("Scan error: %d\n", result);
  else
    printf("Scan complete.\n");

  yr_rules_destroy(rules);
  yr_compiler_destroy(compiler);
  yr_finalize();
  return 0;
#endif
  return 0;
}

/* ------------------------------------------------------------------ */
/*  8. Shellcode Decoder                                               */
/* ------------------------------------------------------------------ */

static void xor_single(const uint8_t *in, size_t len, uint8_t key) {
  for (size_t i = 0; i < len; i++) putchar(in[i] ^ key);
}

static uint8_t rol(uint8_t v, int n) { return (v << n) | (v >> (8 - n)); }
static uint8_t ror(uint8_t v, int n) { return (v >> n) | (v << (8 - n)); }

static double score_plaintext(const uint8_t *data, size_t len) {
  /* Simple scoring: count printable ASCII, common letters, whitespace */
  if (len == 0) return 0.0;
  int printable = 0, common = 0, whitespace = 0, total = 0;
  static const char *common_chars = "etaoinshrdlu";
  for (size_t i = 0; i < len && i < 1024; i++) {
    total++;
    if (isprint(data[i]) || data[i] == '\n' || data[i] == '\r' || data[i] == '\t')
      printable++;
    if (strchr(common_chars, tolower(data[i]))) common++;
    if (data[i] == ' ' || data[i] == '\n' || data[i] == '\t') whitespace++;
  }
  if (total == 0) return 0;
  return (double)(printable + common * 2 + whitespace * 3) / (double)total;
}

static int cmd_decode(int argc, char **argv) {
  if (argc < 1) fatal("Usage: malalyzer decode <shellcode_file>");
  size_t len; uint8_t *buf = read_file(argv[0], &len);
  if (len == 0 || len > 1024 * 1024) fatal("Invalid shellcode size: %zu", len);

  printf("Shellcode: %zu bytes\n", len);
  printf("\nRaw bytes:\n");
  hex_dump(buf, len > 256 ? 256 : len, stdout);
  printf("Entropy: %.2f\n\n", shannon_entropy(buf, len));

  /* 1. Single-byte XOR brute force */
  printf("=== Single-byte XOR Brute Force (top 5 by plaintext score) ===\n");
  key_score_t scores[256];
  for (int k = 0; k < 256; k++) {
    uint8_t *dec = xmalloc(len);
    for (size_t i = 0; i < len; i++) dec[i] = buf[i] ^ (uint8_t)k;
    scores[k].key = (uint8_t)k;
    scores[k].score = score_plaintext(dec, len);
    free(dec);
  }
  /* Sort by score descending */
  for (int i = 0; i < 256; i++)
    for (int j = i + 1; j < 256; j++)
      if (scores[j].score > scores[i].score) {
        key_score_t t = scores[i]; scores[i] = scores[j]; scores[j] = t;
      }
  for (int i = 0; i < 5 && i < 256; i++) {
    if (scores[i].score < 0.3) break;
    printf("Key 0x%02x ('%c') score=%.2f:\n  ",
           scores[i].key, isprint(scores[i].key) ? scores[i].key : '.', scores[i].score);
    xor_single(buf, len > 96 ? 96 : len, scores[i].key);
    printf("\n\n");
  }

  /* 2. Multi-byte XOR (try common key lengths) */
  printf("=== Multi-byte XOR (trying key lengths 2-16) ===\n");
  int keylens[] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  for (int ki = 0; ki < 15; ki++) {
    int klen = keylens[ki];
    if ((size_t)klen >= len) continue;
    uint8_t key[16] = {0};
    /* Use frequency analysis per position */
    for (int p = 0; p < klen; p++) {
      int best_k = 0;
      double best_s = 0;
      for (int k = 0; k < 256; k++) {
        size_t cnt = 0;
        double pos_score = 0;
        for (size_t i = p; i < len; i += klen) {
          uint8_t d = buf[i] ^ (uint8_t)k;
          if (isprint(d) || d == ' ' || d == '\n' || d == '\t') pos_score += 1;
          if (d == ' ' || d == 'e' || d == 't' || d == 'a') pos_score += 2;
          cnt++;
        }
        pos_score /= (double)(cnt > 0 ? cnt : 1);
        if (pos_score > best_s) { best_s = pos_score; best_k = k; }
      }
      key[p] = (uint8_t)best_k;
    }
    /* Score full decode with this key */
    uint8_t *dec = xmalloc(len);
    for (size_t i = 0; i < len; i++) dec[i] = buf[i] ^ key[i % klen];
    double final_score = score_plaintext(dec, len);
    if (final_score > 0.5) {
      printf("Key len %d, key = ", klen);
      for (int p = 0; p < klen; p++) printf("%02x", key[p]);
      printf(", score=%.2f\n  ", final_score);
      for (size_t i = 0; i < (len > 96 ? 96 : len); i++) putchar(dec[i]);
      printf("\n\n");
    }
    free(dec);
  }

  /* 3. ROL/ROR decode */
  printf("=== ROL/ROR ===\n");
  for (int n = 1; n < 8; n++) {
    uint8_t *rol_dec = xmalloc(len), *ror_dec = xmalloc(len);
    for (size_t i = 0; i < len; i++) {
      rol_dec[i] = rol(buf[i], n);
      ror_dec[i] = ror(buf[i], n);
    }
    double s_rol = score_plaintext(rol_dec, len);
    double s_ror = score_plaintext(ror_dec, len);
    if (s_rol > 0.3) {
      printf("ROL %d (score=%.2f): ", n, s_rol);
      for (size_t i = 0; i < (len > 64 ? 64 : len); i++) putchar(rol_dec[i]);
      printf("\n");
    }
    if (s_ror > 0.3) {
      printf("ROR %d (score=%.2f): ", n, s_ror);
      for (size_t i = 0; i < (len > 64 ? 64 : len); i++) putchar(ror_dec[i]);
      printf("\n");
    }
    free(rol_dec); free(ror_dec);
  }

  /* 4. ADD/SUB decode (common shift ciphers in shellcode) */
  printf("\n=== ADD/SUB ===\n");
  for (int n = 1; n < 256; n++) {
    uint8_t *add_dec = xmalloc(len), *sub_dec = xmalloc(len);
    for (size_t i = 0; i < len; i++) {
      add_dec[i] = buf[i] - (uint8_t)n;
      sub_dec[i] = buf[i] + (uint8_t)n;
    }
    double s_add = score_plaintext(add_dec, len);
    double s_sub = score_plaintext(sub_dec, len);
    if (s_add > 0.5) {
      printf("SUB 0x%02x (%d) score=%.2f: ", (uint8_t)n, n, s_add);
      for (size_t i = 0; i < (len > 64 ? 64 : len); i++) putchar(add_dec[i]);
      printf("\n");
      free(add_dec); free(sub_dec); break;
    }
    if (s_sub > 0.5) {
      printf("ADD 0x%02x (%d) score=%.2f: ", (uint8_t)n, n, s_sub);
      for (size_t i = 0; i < (len > 64 ? 64 : len); i++) putchar(sub_dec[i]);
      printf("\n");
      free(add_dec); free(sub_dec); break;
    }
    free(add_dec); free(sub_dec);
  }

  free(buf);
  return 0;
}

/* ------------------------------------------------------------------ */
/*  9. XOR / Key Search                                                */
/* ------------------------------------------------------------------ */

/* Compute Hamming distance between two byte sequences */
static int hamming_dist(const uint8_t *a, const uint8_t *b, size_t len) {
  int d = 0;
  for (size_t i = 0; i < len; i++) {
    uint8_t x = a[i] ^ b[i];
    while (x) { d += x & 1; x >>= 1; }
  }
  return d;
}

/* Try to find likely XOR key length using normalized Hamming distance */
static int find_xor_keylen(const uint8_t *data, size_t len, int *out_len) {
  double best = 999.0;
  int best_k = 1;
  for (int k = 2; k <= 40 && (size_t)k * 4 <= len; k++) {
    double dist = 0;
    int samples = 0;
    for (int i = 0; i + k * 2 <= (int)len && i < k * 8; i += k) {
      dist += (double)hamming_dist(data + i, data + i + k, k) / (double)k;
      samples++;
    }
    if (samples == 0) continue;
    dist /= (double)samples;
    /* Prefer smaller keys slightly */
    dist -= 0.01 * (40 - k) / 39.0;
    if (dist < best) { best = dist; best_k = k; }
  }
  *out_len = best_k;
  return (best < 3.5);
}

static void try_repeating_xor(const uint8_t *data, size_t len, int keylen,
                              uint8_t *out_key, int *out_klen) {
  uint8_t key[64];
  for (int p = 0; p < keylen; p++) {
    /* Count byte frequencies at this position */
    uint32_t freq[256] = {0};
    for (size_t i = p; i < len; i += keylen) freq[data[i]]++;
    /* Find the byte that, when XOR'd with space (0x20), produces the most common char */
    int best_k = 0;
    uint32_t best_n = 0;
    for (int k = 0; k < 256; k++) {
      uint32_t score = 0;
      for (size_t i = p; i < len; i += keylen) {
        uint8_t d = data[i] ^ (uint8_t)k;
        if (isprint(d) || d == '\n' || d == '\t' || d == '\r') score++;
        if (d == ' ' || d == 'e' || d == 't' || d == 'a' || d == 'o') score += 2;
      }
      if (score > best_n) { best_n = score; best_k = k; }
    }
    key[p] = (uint8_t)best_k;
  }

  memcpy(out_key, key, keylen);
  *out_klen = keylen;
}

static int cmd_xorsearch(int argc, char **argv) {
  int force_keylen = 0;
  char *file = NULL;

  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "-k") == 0 && i + 1 < argc)
      force_keylen = atoi(argv[++i]);
    else
      file = argv[i];
  }
  if (!file) fatal("Usage: malalyzer xorsearch [-k <keylen>] <file>");

  size_t len; uint8_t *buf = read_file(file, &len);
  if (len < 8) fatal("File too small for XOR analysis");

  printf("=== XOR Search ===\n");
  printf("File: %s (%zu bytes, entropy: %.2f)\n\n", file, len, shannon_entropy(buf, len));

  /* Single-byte XOR */
  printf("[Single-byte XOR]\n");
  key_score_t scores[256];
  for (int k = 0; k < 256; k++) {
    uint8_t *dec = xmalloc(len > 1024 ? 1024 : len);
    size_t sl = len > 1024 ? 1024 : len;
    for (size_t i = 0; i < sl; i++) dec[i] = buf[i] ^ (uint8_t)k;
    scores[k].key = (uint8_t)k;
    scores[k].score = score_plaintext(dec, sl);
    free(dec);
  }
  for (int i = 0; i < 256; i++)
    for (int j = i + 1; j < 256; j++)
      if (scores[j].score > scores[i].score) {
        key_score_t t = scores[i]; scores[i] = scores[j]; scores[j] = t;
      }

  for (int i = 0; i < 10 && i < 256; i++) {
    if (scores[i].score < 0.3) break;
    printf("  0x%02x ('%c') score=%.2f: ",
           scores[i].key, isprint(scores[i].key) ? scores[i].key : '.', scores[i].score);
    xor_single(buf, len > 80 ? 80 : len, scores[i].key);
    printf("\n");
  }

  /* Multi-byte XOR */
  printf("\n[Multi-byte XOR]\n");
  int keylen;
  if (force_keylen > 0) {
    keylen = force_keylen;
    printf("  Using forced key length: %d\n", keylen);
  } else {
    int found = find_xor_keylen(buf, len, &keylen);
    printf("  Detected key length: %d (confidence: %s)\n",
           keylen, found ? "high" : "low");
  }

  /* Try the detected key length and neighbors */
  int start_k = keylen - 2;
  if (start_k < 2) start_k = 2;
  for (int k = start_k; k <= keylen + 2 && k <= 64; k++) {
    uint8_t key[64];
    int actual = 0;
    try_repeating_xor(buf, len, k, key, &actual);
    uint8_t *dec = xmalloc(len);
    for (size_t i = 0; i < len; i++) dec[i] = buf[i] ^ key[i % actual];
    double sc = score_plaintext(dec, len);
    if (sc > 0.4) {
      printf("  Key len %d, key = ", k);
      for (int p = 0; p < actual; p++) printf("%02x", key[p]);
      printf(" (");
      for (int p = 0; p < actual; p++) putchar(isprint(key[p]) ? key[p] : '.');
      printf("), score=%.2f\n", sc);
      printf("    ");
      for (size_t i = 0; i < (len > 80 ? 80 : len); i++) putchar(dec[i]);
      printf("\n");
    }
    free(dec);
  }

  /* Rolling XOR detection: data[i] ^ data[i+1] constant? */
  printf("\n[Rolling XOR Pattern]\n");
  int roll_found = 0;
  for (size_t i = 1; i + 1 < len && i < 1000; i++) {
    if (buf[i] == (buf[i-1] ^ buf[i+1])) { roll_found++; }
  }
  if (roll_found > (int)len / 4 && len > 10) {
    printf("  Rolling XOR pattern detected (%d/%zu matches)\n", roll_found,
           len > 1000 ? (size_t)999 : len - 1);
    /* Try to find the base XOR constant */
    for (int k = 0; k < 256; k++) {
      uint8_t *dec = xmalloc(len);
      dec[0] = buf[0];
      int consistent = 1;
      for (size_t i = 1; i < len; i++) {
        dec[i] = buf[i] ^ dec[i-1] ^ (uint8_t)k;
        if (!isprint(dec[i]) && dec[i] != 0 && dec[i] != '\n' && dec[i] != '\t') {
          consistent = 0;
          break;
        }
      }
      if (consistent) {
        printf("  Rolling key 0x%02x: ", (uint8_t)k);
        for (size_t i = 0; i < (len > 64 ? 64 : len); i++) putchar(dec[i]);
        printf("\n");
      }
      free(dec);
    }
  } else {
    printf("  No rolling XOR pattern detected\n");
  }

  free(buf);
  return 0;
}

/* ------------------------------------------------------------------ */
/*  Main dispatcher                                                    */
/* ------------------------------------------------------------------ */
static void banner(void) {
  const char *colors[] = {"\033[1;31m", "\033[1;33m", "\033[1;32m", "\033[1;36m", "\033[1;34m", "\033[1;35m"};
  const char *bold = "\033[1;37m";
  const char *dim  = "\033[2;37m";
  const char *reset = "\033[0m";

  fprintf(stderr, "\n");
  fprintf(stderr, "%s   █   █   ███   █       ███   █      █   █  █████  █████  █████%s\n", colors[0], reset);
  fprintf(stderr, "%s   ██ ██  ██ ██  █      ██ ██  █      █   █     █   █      █   █%s\n", colors[1], reset);
  fprintf(stderr, "%s   █ █ █  █████  █      █████  █       █ █     █    █████  ████ %s\n", colors[2], reset);
  fprintf(stderr, "%s   █   █  ██ ██  █      ██ ██  █        █     █     █      █  █ %s\n", colors[3], reset);
  fprintf(stderr, "%s   █   █  ██ ██  █████  ██ ██  █████    █    █████  █████  █   █%s\n", colors[4], reset);
  fprintf(stderr, "%s\n", reset);
  fprintf(stderr, "   %sMalware Analysis Toolkit — Reverse Engineering Utility%s\n", bold, reset);
  fprintf(stderr, "   %sv1.0 • gcc -O2 malalyzer.c -lcrypto -lm%s\n\n", dim, reset);
}

static void usage(void) {
  fprintf(stderr,
    "Usage: malalyzer <command> [options] <target>\n"
    "\n"
    "File Analysis:\n"
    "  pe       <file>                      Parse PE file structure\n"
    "  elf      <file>                      Parse ELF file structure\n"
    "  strings  [-e <min_entropy>] <file>   Extract strings (ASCII/wide)\n"
    "  hash     <file>                      Compute MD5/SHA1/SHA256\n"
    "  hooks    <file>                      Detect API hooks in PE\n"
    "  decode   <file>                      Decode/deobfuscate shellcode\n"
    "  xorsearch [-k <keylen>] <file>       Search XOR-encoded content\n"
#ifdef YARA_ENABLED
    "  yara     <rule_file> <target>        Scan with YARA rules\n"
#else
    "  yara     <rule_file> <target>        (not compiled; rebuild with -DYARA_ENABLED -lyara)\n"
#endif
    "\n"
    "Process Analysis:\n"
    "  dump     <pid>                       Dump process memory regions\n"
    "\n"
    "Examples:\n"
    "  malalyzer pe sample.exe\n"
    "  malalyzer strings -e 5.5 sample.bin\n"
    "  malalyzer hash malware.exe\n"
    "  malalyzer decode shellcode.bin\n"
    "  malalyzer xorsearch -k 4 encrypted.bin\n"
    "  malalyzer dump 1337\n");
}

int main(int argc, char **argv) {
  if (argc < 2) { banner(); usage(); return 1; }

  const char *cmd = argv[1];
  int cmd_argc = argc - 2;
  char **cmd_argv = argv + 2;

  if (strcmp(cmd, "pe") == 0)
    return cmd_pe(cmd_argc, cmd_argv);
  else if (strcmp(cmd, "elf") == 0)
    return cmd_elf(cmd_argc, cmd_argv);
  else if (strcmp(cmd, "dump") == 0)
    return cmd_dump(cmd_argc, cmd_argv);
  else if (strcmp(cmd, "strings") == 0)
    return cmd_strings(cmd_argc, cmd_argv);
  else if (strcmp(cmd, "hash") == 0)
    return cmd_hash(cmd_argc, cmd_argv);
  else if (strcmp(cmd, "hooks") == 0)
    return cmd_hooks(cmd_argc, cmd_argv);
  else if (strcmp(cmd, "yara") == 0)
    return cmd_yara(cmd_argc, cmd_argv);
  else if (strcmp(cmd, "decode") == 0)
    return cmd_decode(cmd_argc, cmd_argv);
  else if (strcmp(cmd, "xorsearch") == 0)
    return cmd_xorsearch(cmd_argc, cmd_argv);
  else if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0)
    { banner(); usage(); return 0; }
  else
    fatal("Unknown command: %s\nUse 'malalyzer --help' for usage.", cmd);

  return 0;
}
