/* packer.c -- build-time tool.
 *
 * Usage: ./packer <stub> <input_exe> <output_packed>
 *
 * It DEFLATEs the input, ENCODEs the compressed bytes (affine cipher), then
 * writes:  [ stub ][ encoded+compressed payload ][ orig u64 ][ comp u64 ][ magic ]
 *
 * Build: clang -O2 packer.c -o packer -lz   (or gcc)
 */

/* Feature test macros MUST precede any #include (see stub.c). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include "miniz.h"

#include "mathcrypt.h"

static const char MAGIC[8] = {'M','B','A','p','a','c','k','!'};

static void die(const char *msg) {
    fprintf(stderr, "packer: %s\n", msg);
    exit(1);
}

/* Read an entire file into a malloc'd buffer. */
static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot open input");
    if (fseek(f, 0, SEEK_END) != 0) die("seek failed");
    long n = ftell(f);
    if (n < 0) die("ftell failed");
    rewind(f);
    uint8_t *buf = malloc((size_t)n ? (size_t)n : 1);
    if (!buf) die("oom");
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) die("read failed");
    fclose(f);
    *out_len = (size_t)n;
    return buf;
}

/* Append raw bytes to an already-open file. */
static void append_all(FILE *f, const void *data, size_t n) {
    if (fwrite(data, 1, n, f) != n) die("write failed");
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <stub> <input_exe> <output_packed>\n", argv[0]);
        return 1;
    }
    const char *stub_path = argv[1];
    const char *in_path   = argv[2];
    const char *out_path  = argv[3];

    /* Read stub and input. */
    size_t stub_len, in_len;
    uint8_t *stub = read_file(stub_path, &stub_len);
    uint8_t *in   = read_file(in_path, &in_len);

    /* Step 1: DEFLATE the input. */
    uLongf comp_cap = compressBound(in_len);
    uint8_t *comp = malloc(comp_cap ? comp_cap : 1);
    if (!comp) die("oom comp");
    uLongf comp_len = comp_cap;
    if (compress2(comp, &comp_len, in, in_len, Z_BEST_COMPRESSION) != Z_OK)
        die("compress failed");

    /* Step 2: ENCODE the compressed bytes (affine cipher). */
    encode_buf(comp, comp_len);

    /* Step 3: write stub, then payload, then footer. */
    FILE *out = fopen(out_path, "wb");
    if (!out) die("cannot open output");
    append_all(out, stub, stub_len);
    append_all(out, comp, comp_len);

    uint64_t orig_size = (uint64_t)in_len;
    uint64_t comp_size = (uint64_t)comp_len;
    append_all(out, &orig_size, 8);
    append_all(out, &comp_size, 8);
    append_all(out, MAGIC, 8);
    fclose(out);

    /* Make the packed file executable (0755). */
    if (chmod(out_path, 0755) != 0) die("chmod output failed");

    /* Report. */
    double ratio = in_len ? (100.0 * (double)comp_len / (double)in_len) : 0.0;
    printf("packed: %s\n", out_path);
    printf("  original   : %zu bytes\n", in_len);
    printf("  compressed : %llu bytes (%.1f%% of original, encoded)\n",
           (unsigned long long)comp_size, ratio);
    printf("  stub       : %zu bytes\n", stub_len);
    printf("  total out  : %zu bytes\n", stub_len + (size_t)comp_len + 24);

    free(stub); free(in); free(comp);
    return 0;
}
