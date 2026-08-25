/* stub.c -- runtime loader.
 *
 * A packed file looks like:
 *   [ this stub binary ][ compressed+encoded payload ][ orig_size u64 ]
 *   [ comp_size u64 ][ "MBApack!" magic ]
 *
 * At run time the stub:
 *   1. opens its own executable,
 *   2. reads the footer to locate the payload,
 *   3. reads the payload, DECODEs it (MBA affine inverse), then INFLATEs it,
 *   4. writes the result to a temp file, chmod +x, and execv()s it.
 *
 * Build (Linux): clang -O2 stub.c -o stub -lz
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <zlib.h>

#include "mathcrypt.h"

static const char MAGIC[8] = {'M','B','A','p','a','c','k','!'};
#define FOOTER_SIZE (8 + 8 + 8) /* orig_size + comp_size + magic */

static void die(const char *msg) {
    fprintf(stderr, "stub: %s\n", msg);
    exit(1);
}

/* Read the full path to our own executable. */
static char *self_path(void) {
    static char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n < 0) die("readlink /proc/self/exe failed");
    buf[n] = '\0';
    return buf;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    const char *path = self_path();
    FILE *f = fopen(path, "rb");
    if (!f) die("cannot open self");

    if (fseek(f, 0, SEEK_END) != 0) die("seek end failed");
    long file_size = ftell(f);
    if (file_size < FOOTER_SIZE) die("file too small; not packed");

    /* Read footer. */
    uint8_t footer[FOOTER_SIZE];
    if (fseek(f, file_size - FOOTER_SIZE, SEEK_SET) != 0) die("seek footer failed");
    if (fread(footer, 1, FOOTER_SIZE, f) != FOOTER_SIZE) die("read footer failed");

    if (memcmp(footer + 16, MAGIC, 8) != 0)
        die("magic not found; this stub has no payload appended");

    uint64_t orig_size, comp_size;
    memcpy(&orig_size, footer + 0, 8);
    memcpy(&comp_size, footer + 8, 8);

    /* Locate and read the compressed+encoded payload. */
    long payload_off = file_size - FOOTER_SIZE - (long)comp_size;
    if (payload_off < 0) die("bad payload offset");

    uint8_t *enc = malloc(comp_size);
    if (!enc) die("oom enc");
    if (fseek(f, payload_off, SEEK_SET) != 0) die("seek payload failed");
    if (fread(enc, 1, comp_size, f) != comp_size) die("read payload failed");
    fclose(f);

    /* Step 1: DECODE (undo the affine cipher, MBA path). */
    decode_buf(enc, comp_size);

    /* Step 2: INFLATE (zlib) into a buffer of known original size. */
    uint8_t *out = malloc(orig_size ? orig_size : 1);
    if (!out) die("oom out");
    uLongf out_len = orig_size;
    int zr = uncompress(out, &out_len, enc, comp_size);
    if (zr != Z_OK) die("uncompress failed");
    if (out_len != orig_size) die("size mismatch after inflate");
    free(enc);

    /* Step 3: write to a temp file, make executable. */
    char tmpl[] = "/tmp/mbapack-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) die("mkstemp failed");
    size_t written = 0;
    while (written < out_len) {
        ssize_t w = write(fd, out + written, out_len - written);
        if (w <= 0) die("write temp failed");
        written += (size_t)w;
    }
    close(fd);
    free(out);
    if (chmod(tmpl, 0755) != 0) die("chmod failed");

    /* Step 4: exec the unpacked program. */
    char *newargv[] = { tmpl, NULL };
    execv(tmpl, newargv);
    die("execv failed"); /* only reached on error */
    return 1;
}
