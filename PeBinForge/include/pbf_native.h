#ifndef PBF_NATIVE_H
#define PBF_NATIVE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#include "pbf_abi.h"

#define PBF_NATIVE_ABI_VERSION 3U
#define PBF_NATIVE_ARCH_X64 IMAGE_FILE_MACHINE_AMD64
#define PBF_NATIVE_ARCH_X86 IMAGE_FILE_MACHINE_I386
#define PBF_NATIVE_MAGIC_SIZE 8U
#define PBF_NATIVE_BOOTSTRAP_SIZE_X64 12U
#define PBF_NATIVE_BOOTSTRAP_SIZE_X86 14U
#if defined(_M_IX86)
#define PBF_NATIVE_ARCH_CURRENT PBF_NATIVE_ARCH_X86
#define PBF_NATIVE_BOOTSTRAP_SIZE PBF_NATIVE_BOOTSTRAP_SIZE_X86
#else
#define PBF_NATIVE_ARCH_CURRENT PBF_NATIVE_ARCH_X64
#define PBF_NATIVE_BOOTSTRAP_SIZE PBF_NATIVE_BOOTSTRAP_SIZE_X64
#endif
#define PBF_NATIVE_HEADER_OFFSET PBF_NATIVE_BOOTSTRAP_SIZE
#define PBF_NATIVE_MAX_BUNDLE (64U * 1024U * 1024U)
#define PBF_NATIVE_MAX_EMBEDDED_MODULES 16U
#define PBF_NATIVE_MODULE_NAME_SIZE 64U
#define PBF_NATIVE_PIC_WORKSPACE_SIZE (32U * 1024U)

#define PBF_NATIVE_MODULE_PRIMARY 0x00000001U
#define PBF_NATIVE_MODULE_EXE     0x00000002U

enum pbf_native_status_t {
    PBF_NATIVE_STATUS_OK = 0,
    PBF_NATIVE_STATUS_BAD_CONTEXT = 1,
    PBF_NATIVE_STATUS_BAD_IMAGE = 2,
    PBF_NATIVE_STATUS_ALLOC_FAILED = 3,
    PBF_NATIVE_STATUS_RELOCATION_FAILED = 4,
    PBF_NATIVE_STATUS_IMPORT_FAILED = 5,
    PBF_NATIVE_STATUS_EXCEPTION_TABLE_FAILED = 6,
    PBF_NATIVE_STATUS_PROTECTION_FAILED = 7,
    PBF_NATIVE_STATUS_TLS_FAILED = 8,
    PBF_NATIVE_STATUS_DLLMAIN_FAILED = 9,
    PBF_NATIVE_STATUS_EXPORT_FAILED = 10,
    PBF_NATIVE_STATUS_ENTRY_FAILED = 11
};

typedef LPVOID (WINAPI *pbf_virtual_alloc_fn)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *pbf_virtual_free_fn)(LPVOID, SIZE_T, DWORD);
typedef BOOL (WINAPI *pbf_virtual_protect_fn)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE (WINAPI *pbf_load_library_a_fn)(LPCSTR);
typedef BOOL (WINAPI *pbf_free_library_fn)(HMODULE);
typedef FARPROC (WINAPI *pbf_get_proc_address_fn)(HMODULE, LPCSTR);
typedef BOOL (WINAPI *pbf_flush_instruction_cache_fn)(HANDLE, LPCVOID, SIZE_T);
typedef HANDLE (WINAPI *pbf_get_current_process_fn)(VOID);
#if defined(_WIN64)
typedef BOOLEAN (WINAPI *pbf_rtl_add_function_table_fn)(
    PRUNTIME_FUNCTION, DWORD, DWORD64);
typedef BOOLEAN (WINAPI *pbf_rtl_delete_function_table_fn)(PRUNTIME_FUNCTION);
#else
typedef BOOLEAN (WINAPI *pbf_rtl_add_function_table_fn)(LPVOID, DWORD, ULONGLONG);
typedef BOOLEAN (WINAPI *pbf_rtl_delete_function_table_fn)(LPVOID);
#endif
typedef LPVOID (WINAPI *pbf_swap_process_image_base_fn)(LPVOID);

typedef struct pbf_native_api_t {
    pbf_virtual_alloc_fn virtual_alloc;
    pbf_virtual_free_fn virtual_free;
    pbf_virtual_protect_fn virtual_protect;
    pbf_load_library_a_fn load_library_a;
    pbf_free_library_fn free_library;
    pbf_get_proc_address_fn get_proc_address;
    pbf_flush_instruction_cache_fn flush_instruction_cache;
    pbf_get_current_process_fn get_current_process;
    pbf_rtl_add_function_table_fn rtl_add_function_table;
    pbf_rtl_delete_function_table_fn rtl_delete_function_table;
    pbf_swap_process_image_base_fn swap_process_image_base;
} pbf_native_api;

typedef struct pbf_native_context_t {
    uint32_t size;
    uint32_t abi_version;
    BYTE *bundle_base;
    uint32_t bundle_size;
    uint32_t dll_offset;
    uint32_t dll_size;
    uint32_t module_table_offset;
    uint32_t module_count;
    uint32_t primary_module_index;
    BYTE *workspace;
    uint32_t workspace_size;
    uint32_t status;
    uint32_t mapped_at_preferred_base;
    uint32_t allow_host_image_reuse;
    pbf_context payload;
    pbf_native_api api;
} pbf_native_context;

#pragma pack(push, 1)
typedef struct pbf_native_module_record_t {
    char name[PBF_NATIVE_MODULE_NAME_SIZE];
    uint32_t offset;
    uint32_t size;
    uint32_t flags;
    uint32_t reserved;
} pbf_native_module_record;

typedef struct pbf_native_footer_t {
    uint8_t magic[PBF_NATIVE_MAGIC_SIZE];
    uint32_t version;
    uint32_t architecture;
    uint32_t entry_offset;
    uint32_t code_size;
    uint32_t dll_offset;
    uint32_t dll_size;
    uint32_t module_table_offset;
    uint32_t module_count;
    uint32_t primary_module_index;
    uint32_t total_size;
    uint32_t standalone_entry_offset;
} pbf_native_footer;
#pragma pack(pop)

typedef uint64_t (__fastcall *pbf_native_entry_fn)(pbf_native_context *context);

#endif
