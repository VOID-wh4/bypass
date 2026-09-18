#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
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

static uint64_t fnv1a_update(uint64_t hash, const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

static void put_u16_le(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
}

static void put_u64_le(unsigned char *p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (unsigned char)((v >> (i * 8)) & 0xff);
    }
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

static int write_header(FILE *out, size_t key_len, uint64_t plain_size,
                        uint64_t plain_hash, uint64_t cipher_size,
                        uint64_t cipher_hash) {
    unsigned char header[VXOR_HEADER_SIZE];

    memset(header, 0, sizeof(header));
    memcpy(header, VXOR_MAGIC, 4);
    header[4] = VXOR_VERSION;
    header[5] = (unsigned char)key_len;
    put_u16_le(header + 6, 0);
    put_u64_le(header + 8, plain_size);
    put_u64_le(header + 16, plain_hash);
    put_u64_le(header + 24, cipher_size);
    put_u64_le(header + 32, cipher_hash);

    if (fseek(out, 0, SEEK_SET) != 0) {
        return 0;
    }

    return fwrite(header, 1, sizeof(header), out) == sizeof(header);
}

static int output_exists(const char *path) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    fclose(file);
    return 1;
}

static int encode_file(const char *input_name, const char *output_name,
                       const unsigned char *key, size_t key_len) {
    FILE *in = fopen(input_name, "rb");
    FILE *out = NULL;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char zero_header[VXOR_HEADER_SIZE] = {0};
    uint64_t plain_size = 0;
    uint64_t cipher_size = 0;
    uint64_t plain_hash = FNV_OFFSET;
    uint64_t cipher_hash = FNV_OFFSET;
    size_t key_offset = 0;

    if (in == NULL) {
        fprintf(stderr, "input open failed: %s: %s\n", input_name, strerror(errno));
        return 0;
    }

    if (output_exists(output_name)) {
        fprintf(stderr, "output already exists, refusing to overwrite: %s\n", output_name);
        fclose(in);
        return 0;
    }

    out = fopen(output_name, "wb+");
    if (out == NULL) {
        fprintf(stderr, "output open failed: %s: %s\n", output_name, strerror(errno));
        fclose(in);
        return 0;
    }

    if (fwrite(zero_header, 1, sizeof(zero_header), out) != sizeof(zero_header)) {
        fprintf(stderr, "header placeholder write failed: %s\n", strerror(errno));
        fclose(in);
        fclose(out);
        return 0;
    }

    for (;;) {
        size_t n = fread(buffer, 1, sizeof(buffer), in);
        if (n > 0) {
            plain_hash = fnv1a_update(plain_hash, buffer, n);
            plain_size += (uint64_t)n;

            for (size_t i = 0; i < n; i++) {
                buffer[i] ^= key[key_offset];
                key_offset = (key_offset + 1) % key_len;
            }

            cipher_hash = fnv1a_update(cipher_hash, buffer, n);
            cipher_size += (uint64_t)n;

            if (fwrite(buffer, 1, n, out) != n) {
                fprintf(stderr, "payload write failed: %s\n", strerror(errno));
                fclose(in);
                fclose(out);
                return 0;
            }
        }

        if (n < sizeof(buffer)) {
            if (ferror(in)) {
                fprintf(stderr, "input read failed: %s\n", strerror(errno));
                fclose(in);
                fclose(out);
                return 0;
            }
            break;
        }
    }

    if (!write_header(out, key_len, plain_size, plain_hash, cipher_size, cipher_hash)) {
        fprintf(stderr, "final header write failed: %s\n", strerror(errno));
        fclose(in);
        fclose(out);
        return 0;
    }

    if (fclose(in) != 0 || fclose(out) != 0) {
        fprintf(stderr, "file close failed: %s\n", strerror(errno));
        return 0;
    }

    printf("[+] encoded package: %s -> %s\n", input_name, output_name);
    printf("[+] key length: %zu byte(s)\n", key_len);
    printf("[+] plain size: %" PRIu64 " byte(s)\n", plain_size);
    printf("[+] plain fnv1a64: 0x%016" PRIx64 "\n", plain_hash);
    printf("[+] cipher fnv1a64: 0x%016" PRIx64 "\n", cipher_hash);
    return 1;
}

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s <input> <output.vxor> <hex-key>\n", argv0);
    fprintf(stderr, "example: %s ld.bin xor.vxor 53\n", argv0);
    fprintf(stderr, "example: %s sample.bin sample.vxor 5A1F3C7E\n", argv0);
}

int main(int argc, char **argv) {
    unsigned char key[MAX_KEY_SIZE];
    size_t key_len = 0;

    if (argc != 4) {
        usage(argv[0]);
        return 2;
    }

    if (!parse_hex_key(argv[3], key, &key_len)) {
        fprintf(stderr, "invalid key: use 1-%d bytes of hexadecimal text\n", MAX_KEY_SIZE);
        return 2;
    }

    return encode_file(argv[1], argv[2], key, key_len) ? 0 : 1;
}
