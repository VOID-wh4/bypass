/* mathcrypt.h -- byte-wise affine cipher over the ring Z/256 (Z/2^8).
 *
 *   encode(x) = rol( ((A*x + B) mod 256) ^ C , R )
 *   decode(y) = A^{-1} * ( (ror(y,R) ^ C) - B )  mod 256
 *
 * A is ODD => a unit in Z/256 (gcd(A,256)=1) => invertible.
 *
 * Only the STUB ships in the packed file, and the stub only runs decode().
 * So decode() is what an attacker disassembles -- that is where the MBA
 * obfuscation lives. encode() runs at pack time and is kept clean/readable.
 *
 * All arithmetic is on uint8_t, so C's unsigned overflow gives us mod-256
 * for free (this is exactly ring arithmetic in Z/2^8).
 */
#ifndef MATHCRYPT_H
#define MATHCRYPT_H

#include <stdint.h>
#include <stddef.h>

/* Round parameters. affA is odd => invertible mod 256. */
#define AFF_A ((uint8_t)0xB5) /* 181, odd            */
#define AFF_B ((uint8_t)0x27) /* 39                  */
#define AFF_C ((uint8_t)0x9E) /* 158                 */
#define AFF_R ((unsigned)3)   /* 0 < R < 8           */

/* invOdd8: multiplicative inverse of an odd byte mod 256 via Newton/Hensel.
 * x_{k+1} = x_k*(2 - a*x_k); correct low bits double each step (3 => 8 bits). */
static inline uint8_t inv_odd8(uint8_t a) {
    uint8_t x = a;                 /* good seed: odd a is its own inverse mod 8 */
    x = (uint8_t)(x * (uint8_t)(2 - (uint8_t)(a * x)));
    x = (uint8_t)(x * (uint8_t)(2 - (uint8_t)(a * x)));
    x = (uint8_t)(x * (uint8_t)(2 - (uint8_t)(a * x)));
    return x;                      /* a * x == 1 (mod 256) */
}

static inline uint8_t rol8(uint8_t x, unsigned r) {
    return (uint8_t)((x << r) | (x >> (8 - r)));
}
static inline uint8_t ror8(uint8_t x, unsigned r) {
    return (uint8_t)((x >> r) | (x << (8 - r)));
}

/* ---- clean reference (pack time) --------------------------------------- */

static inline uint8_t encode_byte(uint8_t x) {
    uint8_t t = (uint8_t)(AFF_A * x + AFF_B);
    t = (uint8_t)(t ^ AFF_C);
    return rol8(t, AFF_R);
}

/* Clean decode, kept only for equivalence testing. Not used by the stub. */
static inline uint8_t decode_byte_ref(uint8_t y) {
    uint8_t t = ror8(y, AFF_R);
    t = (uint8_t)(t ^ AFF_C);
    return (uint8_t)(inv_odd8(AFF_A) * (uint8_t)(t - AFF_B));
}

/* ---- MBA building blocks (each verified exhaustively over Z/256) -------- */

/* add: a + b == (a^b) + 2*(a&b), expanded one extra level so the surviving
 * '+' operates on already-tangled subterms. */
static inline uint8_t add_mba(uint8_t a, uint8_t b) {
    uint8_t p = (uint8_t)(a ^ b);
    uint8_t q = (uint8_t)(2 * (a & b));
    return (uint8_t)((uint8_t)(p ^ q) + (uint8_t)(2 * (p & q)));
}

/* sub: a - b == a + (~b + 1) in two's complement (Z/256). */
static inline uint8_t sub_mba(uint8_t a, uint8_t b) {
    uint8_t neg_b = add_mba((uint8_t)~b, 1);
    return add_mba(a, neg_b);
}

/* xor: a ^ b == (a|b) - (a&b), '-' routed through sub_mba. */
static inline uint8_t xor_mba(uint8_t a, uint8_t b) {
    return sub_mba((uint8_t)(a | b), (uint8_t)(a & b));
}

/* decode_mba: obfuscated inverse. Bit-for-bit equal to decode_byte_ref,
 * but built from AND/OR/XOR/shift + a single constant multiply. */
static inline uint8_t decode_mba(uint8_t y) {
    uint8_t t = ror8(y, AFF_R);        /* rotate: clean primitive */
    t = xor_mba(t, AFF_C);             /* was: t ^ C */
    t = sub_mba(t, AFF_B);             /* was: t - B */
    return (uint8_t)(inv_odd8(AFF_A) * t);
}

/* Buffer helpers used by packer (encode) and stub (decode). */
static inline void encode_buf(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = encode_byte(buf[i]);
}
static inline void decode_buf(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = decode_mba(buf[i]);
}

#endif /* MATHCRYPT_H */
