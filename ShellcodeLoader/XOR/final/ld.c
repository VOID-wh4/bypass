/*
 * VXOR local in-process execution example, Windows/Linux x86-64.
 * Based on the uploaded decrypt(2).c. The VXOR format is unchanged.
 *
 * --run expects trusted, position-independent raw machine code whose entry
 * at offset 0 behaves like int entry(void) for the host ABI and returns.
 * It is NOT a PE/ELF loader, emulator, authenticity check, or sandbox.
 * No process injection, remote fetching, or protection bypass is implemented.
 */
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#elif defined(__linux__)
#include <sys/mman.h>
#else
#error "This example supports Windows and Linux only."
#endif

#if !defined(__x86_64__) && !defined(_M_X64)
#error "Build this example as x86-64; the test payload is x86-64 code."
#endif

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VXOR_MAGIC "VXOR"
#define VXOR_VERSION 1
#define VXOR_HEADER_SIZE 40
#define MAX_KEY_SIZE 64
#define BUFFER_SIZE 4096
#define FNV_OFFSET 1469598103934665603ULL
#define FNV_PRIME 1099511628211ULL

typedef struct VxorHeader {
    unsigned char version;
    size_t key_len;
    uint64_t plain_size;
    uint64_t plain_hash;
    uint64_t cipher_size;
    uint64_t cipher_hash;
} VxorHeader;

typedef struct DecodedBuffer {
    unsigned char *data;
    size_t size;
} DecodedBuffer;

static void secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
}

static void decoded_buffer_free(DecodedBuffer *decoded) {
    if (decoded == NULL) {
        return;
    }
    if (decoded->data != NULL) {
        secure_zero(decoded->data, decoded->size);
        free(decoded->data);
    }
    decoded->data = NULL;
    decoded->size = 0;
}

static uint64_t fnv1a_update(uint64_t hash, const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

static uint16_t get_u16_le(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint64_t get_u64_le(const unsigned char *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (i * 8);
    }
    return v;
}

static int hex_value(int c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    c = tolower(c);
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static int parse_hex_key(const char *text, unsigned char *key, size_t *key_len) {
    char compact[MAX_KEY_SIZE * 2 + 1];
    size_t n = 0;

    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text += 2;
    }

    for (; *text != '\0'; text++) {
        if (*text == ':' || *text == '-' || *text == '_' || isspace((unsigned char)*text)) {
            continue;
        }
        if (!isxdigit((unsigned char)*text) || n >= sizeof(compact) - 1) {
            return 0;
        }
        compact[n++] = *text;
    }
    compact[n] = '\0';

    if (n == 0 || (n % 2) != 0) {
        return 0;
    }

    *key_len = n / 2;
    for (size_t i = 0; i < *key_len; i++) {
        int hi = hex_value(compact[i * 2]);
        int lo = hex_value(compact[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        key[i] = (unsigned char)((hi << 4) | lo);
    }

    return 1;
}

static int parse_header(const unsigned char *raw, VxorHeader *header) {
    uint16_t flags;

    if (memcmp(raw, VXOR_MAGIC, 4) != 0) {
        fprintf(stderr, "invalid package: magic mismatch\n");
        return 0;
    }

    header->version = raw[4];
    if (header->version != VXOR_VERSION) {
        fprintf(stderr, "unsupported package version: %u\n", header->version);
        return 0;
    }

    header->key_len = raw[5];
    flags = get_u16_le(raw + 6);
    if (header->key_len == 0 || header->key_len > MAX_KEY_SIZE || flags != 0) {
        fprintf(stderr, "invalid package header fields\n");
        return 0;
    }

    header->plain_size = get_u64_le(raw + 8);
    header->plain_hash = get_u64_le(raw + 16);
    header->cipher_size = get_u64_le(raw + 24);
    header->cipher_hash = get_u64_le(raw + 32);

    return 1;
}

static int output_exists(const char *path) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    fclose(file);
    return 1;
}

static int decode_package_to_memory(const char *package_name,
                                    const unsigned char *key, size_t key_len,
                                    DecodedBuffer *decoded) {
    FILE *in = fopen(package_name, "rb");
    unsigned char raw_header[VXOR_HEADER_SIZE];
    unsigned char chunk[BUFFER_SIZE];
    VxorHeader header;
    unsigned char *buffer = NULL;
    uint64_t cipher_size = 0;
    uint64_t plain_hash = FNV_OFFSET;
    uint64_t cipher_hash = FNV_OFFSET;
    int ok = 0;

    if (decoded == NULL) {
        fprintf(stderr, "invalid decoded buffer argument\n");
        return 0;
    }
    decoded->data = NULL;
    decoded->size = 0;

    if (in == NULL) {
        fprintf(stderr, "package open failed: %s: %s\n", package_name, strerror(errno));
        return 0;
    }

    if (fread(raw_header, 1, sizeof(raw_header), in) != sizeof(raw_header)) {
        fprintf(stderr, "package header read failed\n");
        fclose(in);
        return 0;
    }

    if (!parse_header(raw_header, &header)) {
        fclose(in);
        return 0;
    }

    if (header.key_len != key_len) {
        fprintf(stderr, "key length mismatch: package=%zu provided=%zu\n", header.key_len, key_len);
        fclose(in);
        return 0;
    }

    if (header.plain_size != header.cipher_size) {
        fprintf(stderr, "invalid package: XOR payload sizes differ\n");
        fclose(in);
        return 0;
    }

    if (header.plain_size > (uint64_t)SIZE_MAX) {
        fprintf(stderr, "payload is too large for this process\n");
        fclose(in);
        return 0;
    }

    for (;;) {
        size_t n = fread(chunk, 1, sizeof(chunk), in);
        if (n > 0) {
            if (cipher_size > UINT64_MAX - (uint64_t)n) {
                fprintf(stderr, "package payload size overflow\n");
                goto done;
            }
            cipher_hash = fnv1a_update(cipher_hash, chunk, n);
            cipher_size += (uint64_t)n;
        }
        if (n < sizeof(chunk)) {
            if (ferror(in)) {
                fprintf(stderr, "package read failed: %s\n", strerror(errno));
                goto done;
            }
            break;
        }
    }

    if (cipher_size != header.cipher_size || cipher_hash != header.cipher_hash) {
        fprintf(stderr, "cipher verification failed: size/hash mismatch\n");
        goto done;
    }

    if (fseek(in, VXOR_HEADER_SIZE, SEEK_SET) != 0) {
        fprintf(stderr, "package rewind failed: %s\n", strerror(errno));
        goto done;
    }

    decoded->size = (size_t)header.plain_size;
    if (decoded->size > 0) {
        buffer = (unsigned char *)malloc(decoded->size);
        if (buffer == NULL) {
            fprintf(stderr, "payload allocation failed: %zu byte(s)\n", decoded->size);
            goto done;
        }

        if (fread(buffer, 1, decoded->size, in) != decoded->size) {
            fprintf(stderr, "package payload is truncated\n");
            goto done;
        }
    }

    for (size_t i = 0; i < decoded->size; i++) {
        buffer[i] ^= key[i % key_len];
    }

    plain_hash = fnv1a_update(plain_hash, buffer, decoded->size);
    if (plain_hash != header.plain_hash) {
        fprintf(stderr, "plain verification failed: wrong key or corrupted package\n");
        goto done;
    }

    decoded->data = buffer;
    buffer = NULL;
    ok = 1;

done:
    if (buffer != NULL) {
        secure_zero(buffer, decoded->size);
        free(buffer);
    }
    fclose(in);
    if (!ok) {
        decoded->size = 0;
        return 0;
    }

    printf("[+] decoded package into memory: %s\n", package_name);
    printf("[+] verified plain size: %zu byte(s)\n", decoded->size);
    printf("[+] verified plain fnv1a64: 0x%016" PRIx64 "\n", plain_hash);
    printf("[+] verified cipher fnv1a64: 0x%016" PRIx64 "\n", cipher_hash);
    return 1;
}

static int write_decoded_file(const char *output_name, const DecodedBuffer *decoded) {
    FILE *out;
    int ok = 1;

    if (output_exists(output_name)) {
        fprintf(stderr, "output already exists, refusing to overwrite: %s\n", output_name);
        return 0;
    }

    out = fopen(output_name, "wb");
    if (out == NULL) {
        fprintf(stderr, "output open failed: %s: %s\n", output_name, strerror(errno));
        return 0;
    }

    if (decoded->size > 0 && fwrite(decoded->data, 1, decoded->size, out) != decoded->size) {
        fprintf(stderr, "decoded output write failed: %s\n", strerror(errno));
        ok = 0;
    }
    if (fclose(out) != 0) {
        fprintf(stderr, "output close failed: %s\n", strerror(errno));
        ok = 0;
    }
    if (!ok) {
        remove(output_name);
    }
    return ok;
}

/*
 * The original decoded buffer remains owned by the caller.
 * Code lives in a separate mapping: RW -> copy -> RX -> call -> release.
 * Invalid code can crash or corrupt this process; no fault isolation exists.
 */
static int execute_decoded_buffer(const DecodedBuffer *decoded, int *return_value) {
    typedef int (*EntryPoint)(void);
    void *code;
    EntryPoint entry;
    int ok = 0;
#ifdef _WIN32
    DWORD old_protect;
#endif

    if (decoded == NULL || decoded->data == NULL ||
        decoded->size == 0 || return_value == NULL) {
        fprintf(stderr, "execution requires a nonempty decoded buffer\n");
        return 0;
    }

    /* Allocate dedicated writable, non-executable pages. */
#ifdef _WIN32
    code = VirtualAlloc(NULL, decoded->size,
                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (code == NULL) {
        fprintf(stderr, "VirtualAlloc failed: %lu\n", (unsigned long)GetLastError());
        return 0;
    }
#else
    code = mmap(NULL, decoded->size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        return 0;
    }
#endif

    /* Copy before removing write permission. Use the exact binary length. */
    memcpy(code, decoded->data, decoded->size);

    /* No RWX mapping is requested. Stop if executable permission is denied. */
#ifdef _WIN32
    if (!VirtualProtect(code, decoded->size, PAGE_EXECUTE_READ, &old_protect)) {
        fprintf(stderr, "VirtualProtect failed: %lu\n", (unsigned long)GetLastError());
        goto cleanup;
    }
    if (!FlushInstructionCache(GetCurrentProcess(), code, decoded->size)) {
        fprintf(stderr, "FlushInstructionCache failed: %lu\n",
                (unsigned long)GetLastError());
        goto cleanup;
    }
#else
    if (mprotect(code, decoded->size, PROT_READ | PROT_EXEC) != 0) {
        fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
        goto cleanup;
    }
    __builtin___clear_cache((char *)code, (char *)code + decoded->size);
#endif

    /*
     * Platform-specific conversion, not an ISO-C-portable way to execute data.
     * The cast does NOT grant execute permission; the API calls above do.
     * This is a function CALL, not a non-returning assembly JMP.
     */
    entry = (EntryPoint)code;
    printf("[+] calling %zu byte(s) from RX memory\n", decoded->size);
    fflush(stdout);
    *return_value = entry();
    ok = 1;

cleanup:
    /* Do not memset/secure_zero an RX region: it is no longer writable. */
#ifdef _WIN32
    if (!VirtualFree(code, 0, MEM_RELEASE)) {
        fprintf(stderr, "VirtualFree failed: %lu\n", (unsigned long)GetLastError());
        ok = 0;
    }
#else
    if (munmap(code, decoded->size) != 0) {
        fprintf(stderr, "munmap failed: %s\n", strerror(errno));
        ok = 0;
    }
#endif
    return ok;
}

static void usage(const char *argv0) {
    fprintf(stderr, "restore: %s <input.vxor> <decoded-output> <hex-key>\n", argv0);
    fprintf(stderr, "execute: %s --run <input.vxor> <hex-key>\n", argv0);
    fprintf(stderr, "example: %s --run return42.vxor 53\n", argv0);
    fprintf(stderr, "--run: trusted raw x86-64 code only; entry is int(void).\n");
}

int main(int argc, char **argv) {
    unsigned char key[MAX_KEY_SIZE] = {0};
    size_t key_len = 0;
    DecodedBuffer decoded = {0};
    const char *package_name;
    int run_mode;
    int return_value = 0;
    int ok;

    if (argc != 4) {
        usage(argv[0]);
        return 2;
    }

    run_mode = strcmp(argv[1], "--run") == 0;
    package_name = run_mode ? argv[2] : argv[1];

    if (!parse_hex_key(argv[3], key, &key_len)) {
        fprintf(stderr, "invalid key: use 1-%d bytes of hexadecimal text\n", MAX_KEY_SIZE);
        secure_zero(key, sizeof(key));
        return 2;
    }

    ok = decode_package_to_memory(package_name, key, key_len, &decoded);
    secure_zero(key, sizeof(key));
    if (!ok) {
        return 1;
    }

    if (run_mode) {
        ok = execute_decoded_buffer(&decoded, &return_value);
        if (ok) {
            printf("[+] entry returned: %d\n", return_value);
        }
    } else {
        ok = write_decoded_file(argv[2], &decoded);
        if (ok) {
            printf("[+] wrote verified memory buffer: %s\n", argv[2]);
        }
    }

    decoded_buffer_free(&decoded);
    return ok ? 0 : 1;
}
