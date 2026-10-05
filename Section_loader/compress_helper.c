/*
 * compress_helper.c — RtlCompressBuffer XPRESS_HUFF helper.
 *
 * Usage:
 *   compress_helper.exe <input.bin> <output.compressed>
 *
 * Output format: [u32 uncompressed_size (LE)][compressed_blob]
 * This is then fed to the existing HSF IPv4/IPv6/MAC encoder → .hsf.
 *
 * Build (Windows, MSVC Developer Command Prompt):
 *   cl /std:c11 /O2 compress_helper.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

#define COMPRESSION_FORMAT_XPRESS_HUFF 4
#define COMPRESSION_ENGINE_MAXIMUM     0x100

typedef LONG (WINAPI *pRtlGetCompressionWorkSpaceSize_t)(
    USHORT CompressionFormatAndEngine,
    PULONG CompressBufferWorkSpaceSize,
    PULONG CompressFragmentWorkSpaceSize
);

typedef LONG (WINAPI *pRtlCompressBuffer_t)(
    USHORT CompressionFormatAndEngine,
    PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer, ULONG CompressedBufferSize,
    ULONG UncompressedChunkSize,
    PULONG FinalCompressedSize,
    PVOID  WorkSpace
);

static uint8_t *read_all(const char *path, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    rewind(fp);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); return NULL;
    }
    fclose(fp);
    *out_size = (size_t)sz;
    return buf;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    /* Read input */
    size_t in_size = 0;
    uint8_t *in_data = read_all(argv[1], &in_size);
    if (!in_data) {
        fprintf(stderr, "[!] fopen/fread fail: %s\n", argv[1]);
        return 1;
    }
    if (in_size > 0x7FFFFFFF) {
        fprintf(stderr, "[!] input too large\n");
        free(in_data);
        return 1;
    }
    printf("[*] Input: %zu bytes\n", in_size);

    /* Resolve ntdll functions */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pRtlGetCompressionWorkSpaceSize_t getWs =
        (pRtlGetCompressionWorkSpaceSize_t)GetProcAddress(hNtdll,
            "RtlGetCompressionWorkSpaceSize");
    pRtlCompressBuffer_t compress =
        (pRtlCompressBuffer_t)GetProcAddress(hNtdll, "RtlCompressBuffer");
    if (!getWs || !compress) {
        fprintf(stderr, "[!] ntdll compression exports not found\n");
        free(in_data);
        return 1;
    }

    /* Query workspace size */
    ULONG ws_size = 0, frag_size = 0;
    USHORT fmt = COMPRESSION_FORMAT_XPRESS_HUFF | COMPRESSION_ENGINE_MAXIMUM;
    LONG status = getWs(fmt, &ws_size, &frag_size);
    if (status < 0) {
        fprintf(stderr, "[!] RtlGetCompressionWorkSpaceSize: 0x%08lX\n",
                (unsigned long)status);
        free(in_data);
        return 1;
    }
    void *workspace = malloc((size_t)ws_size);
    if (!workspace) { free(in_data); return 1; }

    /* Output buffer with safety margin */
    size_t out_cap = in_size + (in_size / 16) + 64;
    uint8_t *out_buf = (uint8_t *)malloc(out_cap);
    if (!out_buf) { free(workspace); free(in_data); return 1; }

    ULONG final_size = 0;
    status = compress(fmt, in_data, (ULONG)in_size,
                      out_buf, (ULONG)out_cap,
                      4096, &final_size, workspace);
    if (status < 0) {
        fprintf(stderr, "[!] RtlCompressBuffer: 0x%08lX\n",
                (unsigned long)status);
        free(out_buf); free(workspace); free(in_data);
        return 1;
    }

    printf("[+] Compressed: %lu bytes (%.1f%% of original)\n",
           (unsigned long)final_size,
           (double)final_size * 100.0 / (double)in_size);

    /* Write [u32 uncompressed_size (LE)][compressed_blob] */
    FILE *out = fopen(argv[2], "wb");
    if (!out) {
        fprintf(stderr, "[!] fopen output fail: %s\n", argv[2]);
        free(out_buf); free(workspace); free(in_data);
        return 1;
    }
    uint32_t hdr = (uint32_t)in_size;
    uint8_t hdr_bytes[4] = {
        (uint8_t)(hdr & 0xFF),
        (uint8_t)((hdr >> 8) & 0xFF),
        (uint8_t)((hdr >> 16) & 0xFF),
        (uint8_t)((hdr >> 24) & 0xFF)
    };
    fwrite(hdr_bytes, 1, 4, out);
    fwrite(out_buf, 1, final_size, out);
    fclose(out);

    printf("[+] Wrote: %s (%lu bytes total, header 4 + compressed %lu)\n",
           argv[2], (unsigned long)(final_size + 4),
           (unsigned long)final_size);

    free(out_buf); free(workspace); free(in_data);
    return 0;
}
