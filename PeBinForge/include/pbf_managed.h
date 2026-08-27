#ifndef PBF_MANAGED_H
#define PBF_MANAGED_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#include "pbf_abi.h"

#define PBF_MANAGED_ABI_VERSION 2U
#define PBF_MANAGED_ARCH_X86 IMAGE_FILE_MACHINE_I386
#define PBF_MANAGED_ARCH_X64 IMAGE_FILE_MACHINE_AMD64
#define PBF_MANAGED_BOOTSTRAP_SIZE_X64 12U
#define PBF_MANAGED_BOOTSTRAP_SIZE_X86 14U
#if defined(_M_IX86)
#define PBF_MANAGED_ARCH_CURRENT PBF_MANAGED_ARCH_X86
#define PBF_MANAGED_BOOTSTRAP_SIZE PBF_MANAGED_BOOTSTRAP_SIZE_X86
#else
#define PBF_MANAGED_ARCH_CURRENT PBF_MANAGED_ARCH_X64
#define PBF_MANAGED_BOOTSTRAP_SIZE PBF_MANAGED_BOOTSTRAP_SIZE_X64
#endif
#define PBF_MANAGED_HEADER_OFFSET PBF_MANAGED_BOOTSTRAP_SIZE
#define PBF_MANAGED_MAGIC_SIZE 8U
#define PBF_MANAGED_MAX_BUNDLE (64U * 1024U * 1024U)

typedef HRESULT (__stdcall *pbf_managed_execute_fn)(
    const BYTE *, ULONG, LONG *);

typedef struct pbf_managed_context_t {
    uint32_t size;
    uint32_t abi_version;
    BYTE *bundle_base;
    uint32_t bundle_size;
    uint32_t assembly_offset;
    uint32_t assembly_size;
    uint32_t status;
    LONG managed_result;
    pbf_managed_execute_fn execute_managed;
} pbf_managed_context;

#pragma pack(push, 1)
typedef struct pbf_managed_footer_t {
    uint8_t magic[PBF_MANAGED_MAGIC_SIZE];
    uint32_t version;
    uint32_t architecture;
    uint32_t entry_offset;
    uint32_t code_size;
    uint32_t assembly_offset;
    uint32_t assembly_size;
    uint32_t total_size;
    uint32_t standalone_entry_offset;
} pbf_managed_footer;
#pragma pack(pop)

typedef uint64_t (__fastcall *pbf_managed_entry_fn)(pbf_managed_context *);

#endif
