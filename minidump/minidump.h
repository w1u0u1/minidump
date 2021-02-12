#pragma once
#include <windows.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define STATUS_SUCCESS 0

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef DWORD   RVA;
typedef ULONG64 RVA64;

struct process
{
    struct process* next;
    HANDLE                      handle;
    const struct loader_ops* loader;
    WCHAR* search_path;
    WCHAR* environment;

    PSYMBOL_REGISTERED_CALLBACK64       reg_cb;
    PSYMBOL_REGISTERED_CALLBACK reg_cb32;
    BOOL                        reg_is_unicode;
    DWORD64                     reg_user;

    struct module* lmodules;
    ULONG_PTR                   dbg_hdr_addr;

    IMAGEHLP_STACK_FRAME        ctx_frame;

    unsigned                    buffer_size;
    void* buffer;

    BOOL                        is_64bit;
};

struct dump_context
{
    /* process & thread information */
    struct process* process;
    DWORD                               pid;
    HANDLE                              handle;
    unsigned                            flags_out;
    /* thread information */
    struct dump_thread* threads;
    unsigned                            num_threads;
    /* module information */
    struct dump_module* modules;
    unsigned                            num_modules;
    unsigned                            alloc_modules;
    /* exception information */
    /* output information */
    MINIDUMP_TYPE                       type;
    HANDLE                              hFile;
    RVA                                 rva;
    struct dump_memory* mem;
    unsigned                            num_mem;
    unsigned                            alloc_mem;
    struct dump_memory64* mem64;
    unsigned                            num_mem64;
    unsigned                            alloc_mem64;
    /* callback information */
    MINIDUMP_CALLBACK_INFORMATION* cb;
};

struct line_info
{
    ULONG_PTR                   is_first : 1,
        is_last : 1,
        is_source_file : 1,
        line_number;
    union
    {
        ULONG_PTR                   pc_offset;   /* if is_source_file isn't set */
        unsigned                    source_file; /* if is_source_file is set */
    } u;
};

struct module_pair
{
    struct process* pcs;
    struct module* requested; /* in:  to module_get_debug() */
    struct module* effective; /* out: module with debug info */
};

enum pdb_kind { PDB_JG, PDB_DS };

struct pdb_lookup
{
    const char* filename;
    enum pdb_kind               kind;
    DWORD                       age;
    DWORD                       timestamp;
    GUID                        guid;
};

struct cpu_stack_walk
{
    HANDLE                      hProcess;
    HANDLE                      hThread;
    BOOL                        is32;
    struct cpu* cpu;
    union
    {
        struct
        {
            PREAD_PROCESS_MEMORY_ROUTINE        f_read_mem;
            PTRANSLATE_ADDRESS_ROUTINE          f_xlat_adr;
            PFUNCTION_TABLE_ACCESS_ROUTINE      f_tabl_acs;
            PGET_MODULE_BASE_ROUTINE            f_modl_bas;
        } s32;
        struct
        {
            PREAD_PROCESS_MEMORY_ROUTINE64      f_read_mem;
            PTRANSLATE_ADDRESS_ROUTINE64        f_xlat_adr;
            PFUNCTION_TABLE_ACCESS_ROUTINE64    f_tabl_acs;
            PGET_MODULE_BASE_ROUTINE64          f_modl_bas;
        } s64;
    } u;
};

struct dump_memory
{
    ULONG64                             base;
    ULONG                               size;
    ULONG                               rva;
};

struct dump_memory64
{
    ULONG64                             base;
    ULONG64                             size;
};

struct dump_module
{
    unsigned                            is_elf;
    ULONG64                             base;
    ULONG                               size;
    DWORD                               timestamp;
    DWORD                               checksum;
    WCHAR                               name[MAX_PATH];
};

struct dump_thread
{
    ULONG                               tid;
    ULONG                               prio_class;
    ULONG                               curr_prio;
};
