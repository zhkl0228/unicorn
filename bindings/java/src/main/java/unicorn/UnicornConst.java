// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT

package unicorn;

public interface UnicornConst {
   int UC_API_MAJOR = 1;

   int UC_API_MINOR = 0;
   int UC_VERSION_MAJOR = 1;

   int UC_VERSION_MINOR = 0;
   int UC_VERSION_EXTRA = 2;
   int UC_SECOND_SCALE = 1000000;
   int UC_MILISECOND_SCALE = 1000;
   int UC_ARCH_ARM = 1;
   int UC_ARCH_ARM64 = 2;
   int UC_ARCH_MIPS = 3;
   int UC_ARCH_X86 = 4;
   int UC_ARCH_PPC = 5;
   int UC_ARCH_SPARC = 6;
   int UC_ARCH_M68K = 7;
   int UC_ARCH_MAX = 8;

   int UC_MODE_LITTLE_ENDIAN = 0;
   int UC_MODE_BIG_ENDIAN = 1073741824;

   int UC_MODE_ARM = 0;
   int UC_MODE_THUMB = 16;
   int UC_MODE_MCLASS = 32;
   int UC_MODE_V8 = 64;
   int UC_MODE_ARM926 = 128;
   int UC_MODE_ARM946 = 256;
   int UC_MODE_ARM1176 = 512;
   int UC_MODE_MICRO = 16;
   int UC_MODE_MIPS3 = 32;
   int UC_MODE_MIPS32R6 = 64;
   int UC_MODE_MIPS32 = 4;
   int UC_MODE_MIPS64 = 8;
   int UC_MODE_16 = 2;
   int UC_MODE_32 = 4;
   int UC_MODE_64 = 8;
   int UC_MODE_PPC32 = 4;
   int UC_MODE_PPC64 = 8;
   int UC_MODE_QPX = 16;
   int UC_MODE_SPARC32 = 4;
   int UC_MODE_SPARC64 = 8;
   int UC_MODE_V9 = 16;

   int UC_ERR_OK = 0;
   int UC_ERR_NOMEM = 1;
   int UC_ERR_ARCH = 2;
   int UC_ERR_HANDLE = 3;
   int UC_ERR_MODE = 4;
   int UC_ERR_VERSION = 5;
   int UC_ERR_READ_UNMAPPED = 6;
   int UC_ERR_WRITE_UNMAPPED = 7;
   int UC_ERR_FETCH_UNMAPPED = 8;
   int UC_ERR_HOOK = 9;
   int UC_ERR_INSN_INVALID = 10;
   int UC_ERR_MAP = 11;
   int UC_ERR_WRITE_PROT = 12;
   int UC_ERR_READ_PROT = 13;
   int UC_ERR_FETCH_PROT = 14;
   int UC_ERR_ARG = 15;
   int UC_ERR_READ_UNALIGNED = 16;
   int UC_ERR_WRITE_UNALIGNED = 17;
   int UC_ERR_FETCH_UNALIGNED = 18;
   int UC_ERR_HOOK_EXIST = 19;
   int UC_ERR_RESOURCE = 20;
   int UC_ERR_EXCEPTION = 21;
   int UC_MEM_READ = 16;
   int UC_MEM_WRITE = 17;
   int UC_MEM_FETCH = 18;
   int UC_MEM_READ_UNMAPPED = 19;
   int UC_MEM_WRITE_UNMAPPED = 20;
   int UC_MEM_FETCH_UNMAPPED = 21;
   int UC_MEM_WRITE_PROT = 22;
   int UC_MEM_READ_PROT = 23;
   int UC_MEM_FETCH_PROT = 24;
   int UC_MEM_READ_AFTER = 25;
   int UC_HOOK_INTR = 1;
   int UC_HOOK_INSN = 2;
   int UC_HOOK_CODE = 4;
   int UC_HOOK_BLOCK = 8;
   int UC_HOOK_MEM_READ_UNMAPPED = 16;
   int UC_HOOK_MEM_WRITE_UNMAPPED = 32;
   int UC_HOOK_MEM_FETCH_UNMAPPED = 64;
   int UC_HOOK_MEM_READ_PROT = 128;
   int UC_HOOK_MEM_WRITE_PROT = 256;
   int UC_HOOK_MEM_FETCH_PROT = 512;
   int UC_HOOK_MEM_READ = 1024;
   int UC_HOOK_MEM_WRITE = 2048;
   int UC_HOOK_MEM_FETCH = 4096;
   int UC_HOOK_MEM_READ_AFTER = 8192;
   int UC_HOOK_INSN_INVALID = 16384;
   int UC_HOOK_MEM_UNMAPPED = 112;
   int UC_HOOK_MEM_PROT = 896;
   int UC_HOOK_MEM_READ_INVALID = 144;
   int UC_HOOK_MEM_WRITE_INVALID = 288;
   int UC_HOOK_MEM_FETCH_INVALID = 576;
   int UC_HOOK_MEM_INVALID = 1008;
   int UC_HOOK_MEM_VALID = 7168;
   int UC_QUERY_MODE = 1;
   int UC_QUERY_PAGE_SIZE = 2;
   int UC_QUERY_ARCH = 3;
   int UC_QUERY_TIMEOUT = 4;

   int UC_PROT_NONE = 0;
   int UC_PROT_READ = 1;
   int UC_PROT_WRITE = 2;
   int UC_PROT_EXEC = 4;
   int UC_PROT_ALL = 7;

}
