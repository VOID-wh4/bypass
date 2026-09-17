/* mathcrypt.h -- word-wise (Z/2^16) affine + position keystream,
 *                MBA + opaque predicates + dead paths +
 *                Control Flow Flattening (真 CFF, IDA-verified).
 *
 * WHY PREVIOUS CFF FAILED
 * -----------------------
 * All functions were `static inline`. The compiler inlined decode_buf
 * into its call site, then constant-propagated the initial state value
 * (ST_LOAD) through every switch arm, pruning all other cases as dead
 * code and unrolling the whole state machine back into straight-line
 * code. The `opaque_const` helper couldn't fight this because the
 * inliner exposed the initial value before opaque_const ran.
 *
 * THE FIX (three parts, all required)
 * ------------------------------------
 *  1. `NOINLINE` on decode_buf AND every stage handler.
 *     Prevents the compiler from seeing into the function body at the
 *     call site. The state machine stays as a real loop with a real
 *     switch, not unrolled straight-line code.
 *
 *  2. `volatile uint16_t vstate = ST_LOAD; state = vstate;`
 *     Even if the compiler somehow inlines decode_buf, it now sees the
 *     initial state come from a volatile read -- an "unknown" value.
 *     It can no longer trace which case executes first, so all cases
 *     must be emitted.
 *
 *  3. `((stage_fn_t volatile *)g_handlers)[idx]`
 *     Reading the function pointer through a volatile-qualified pointer
 *     forces the compiler to emit a real indirect load + call. Without
 *     this, it can look through the table at compile time, see that
 *     slot N always holds h_foo, and replace `call *table[N]` with a
 *     direct `call h_foo` -- destroying the indirection that blocks IDA.
 *
 * RESULT (IDA graph view)
 * -----------------------
 * decode_buf shows a star topology: one central dispatcher node with
 * ten spokes, each spoke being a `call *%rax` that IDA cannot
 * statically resolve. F5 pseudocode is an opaque while-switch blob.
 * The individual stage functions (h_xor_c, h_mul, ...) appear as
 * separate, disconnected nodes in the function list.
 *
 * REQUIRED BUILD FLAGS
 * --------------------
 * Add `-fno-ipa-cp` to the stub compile command (GCC/MinGW):
 *   x86_64-w64-mingw32-gcc -O2 -fno-ipa-cp -Wall stub_win.c miniz.c -o stub.exe
 *
 * Without it, GCC's IPA constant propagation pass creates a specialized
 * clone `decode_buf.constprop.0` by folding the call-site argument `n`
 * into the function body, partially un-flattening the switch. The flag
 * prevents clone creation; decode_buf stays as one canonical function.
 * MSVC equivalent: /Ob0 (disable inlining) already suppresses this.
 */
#ifndef MATHCRYPT_H
#define MATHCRYPT_H

#include <stdint.h>
#include <stddef.h>

/* ---- Compiler portability ------------------------------------------ */
#if defined(__GNUC__) || defined(__clang__)
  #define NOINLINE __attribute__((noinline))
  #define MBA_OPAQUE(v) __asm__ __volatile__("" : "+r"(v))
#elif defined(_MSC_VER)
  #define NOINLINE __declspec(noinline)
  #include <intrin.h>
  #pragma optimize("", off)
  static __forceinline void _mba_opaque_u16(volatile uint16_t *p){(void)*p;}
  #pragma optimize("", on)
  #define MBA_OPAQUE(v) _mba_opaque_u16((volatile uint16_t*)&(v))
#else
  #define NOINLINE
  #define MBA_OPAQUE(v) ((void)0)
#endif

/* ---- Key schedule -------------------------------------------------- */
enum {
    KIDX_A = 0, KIDX_B, KIDX_C, KIDX_R,
    KIDX_SEED, KIDX_M, KIDX_N,
    KIDX__COUNT
};
static const volatile uint16_t g_ks[KIDX__COUNT] = {
    /* A    */ 0xACB5u,
    /* B    */ 0x1E27u,
    /* C    */ 0x5A9Eu,
    /* R    */ 0x0005u,
    /* SEED */ 0xC3A7u,
    /* M    */ 0x5A2Bu,
    /* N    */ 0x9F13u
};
static inline uint16_t k_A(void)    { return g_ks[KIDX_A]; }
static inline uint16_t k_B(void)    { return g_ks[KIDX_B]; }
static inline uint16_t k_C(void)    { return g_ks[KIDX_C]; }
static inline unsigned  k_R(void)   { return (unsigned)(g_ks[KIDX_R] & 15u); }
static inline uint16_t k_SEED(void) { return g_ks[KIDX_SEED]; }
static inline uint16_t k_M(void)    { return g_ks[KIDX_M]; }
static inline uint16_t k_N(void)    { return g_ks[KIDX_N]; }

/* ---- Rotates ------------------------------------------------------- */
static inline uint16_t rol16(uint16_t x, unsigned r) {
    r &= 15u;
    return (uint16_t)((x << r) | (x >> ((16u - r) & 15u)));
}
static inline uint16_t ror16(uint16_t x, unsigned r) {
    r &= 15u;
    return (uint16_t)((x >> r) | (x << ((16u - r) & 15u)));
}

/* ---- Newton/Hensel inverse mod 2^16 -------------------------------- */
static inline uint16_t inv_odd16(uint16_t a) {
    uint16_t x = a;
    x = (uint16_t)(x * (uint16_t)(2u - (uint16_t)(a * x)));
    x = (uint16_t)(x * (uint16_t)(2u - (uint16_t)(a * x)));
    x = (uint16_t)(x * (uint16_t)(2u - (uint16_t)(a * x)));
    return x;
}

/* =====================================================================
 * OPAQUE HELPERS
 * ===================================================================== */

/* Always 0; two separately-opaqued copies of `w` block complement folding */
static inline uint16_t opaque_zero_u16(uint16_t witness) {
    uint16_t w    = witness;               MBA_OPAQUE(w);
    uint16_t notw = (uint16_t)~witness;    MBA_OPAQUE(notw);
    uint16_t r    = (uint16_t)(w & notw);  MBA_OPAQUE(r);
    return r;
}

/* Always `val`; looks like arithmetic depending on `witness` */
static inline uint16_t opaque_const_u16(uint16_t val, uint16_t witness) {
    return (uint16_t)(opaque_zero_u16(witness) | val);
}

/* =====================================================================
 * OPAQUE PREDICATES (always true, no imul)
 * ===================================================================== */

static inline int op_true_1(uint16_t x) {
    return opaque_zero_u16(x) == 0u;               /* x & ~x == 0 */
}
static inline int op_true_2(uint16_t a, uint16_t b) {
    uint16_t ao = a, bo = b; MBA_OPAQUE(ao); MBA_OPAQUE(bo);
    uint16_t lhs = (uint16_t)((ao | bo) - (uint16_t)(ao & bo));
    uint16_t rhs = (uint16_t)(ao ^ bo);
    uint16_t d   = (uint16_t)(lhs ^ rhs);          /* (a|b)-(a&b) == a^b */
    MBA_OPAQUE(d); return d == 0u;
}
static inline int op_true_3(uint16_t a, uint16_t b) {
    uint16_t ao = a, bo = b; MBA_OPAQUE(ao); MBA_OPAQUE(bo);
    uint16_t lhs = (uint16_t)((uint16_t)(ao ^ bo)
                             + (uint16_t)((uint16_t)(ao & bo) << 1));
    uint16_t rhs = (uint16_t)(ao + bo);             /* carry-save identity */
    uint16_t d   = (uint16_t)(lhs ^ rhs);
    MBA_OPAQUE(d); return d == 0u;
}

/* =====================================================================
 * MBA DIVERSIFICATION
 * ===================================================================== */

static inline uint16_t add16_v1(uint16_t a, uint16_t b) {
    uint16_t p = (uint16_t)(a ^ b),  q = (uint16_t)((uint16_t)(a & b) << 1);
    MBA_OPAQUE(p); MBA_OPAQUE(q);
    return (uint16_t)((uint16_t)(p ^ q) + (uint16_t)((uint16_t)(p & q) << 1));
}
static inline uint16_t add16_v2(uint16_t a, uint16_t b) {
    uint16_t p = (uint16_t)(a | b),  q = (uint16_t)(a & b);
    MBA_OPAQUE(p); MBA_OPAQUE(q); return (uint16_t)(p + q);
}
static inline uint16_t add16_v3(uint16_t a, uint16_t b) {
    uint16_t p = (uint16_t)((uint16_t)(a | b) << 1), q = (uint16_t)(a ^ b);
    MBA_OPAQUE(p); MBA_OPAQUE(q); return (uint16_t)(p - q);
}

static inline uint16_t sub16_v1(uint16_t a, uint16_t b) {
    return add16_v1(a, add16_v1((uint16_t)~b, 1u));
}
static inline uint16_t sub16_v2(uint16_t a, uint16_t b) {
    uint16_t p = (uint16_t)(a ^ b),
             q = (uint16_t)((uint16_t)((uint16_t)~a & b) << 1);
    MBA_OPAQUE(p); MBA_OPAQUE(q); return (uint16_t)(p - q);
}

static inline uint16_t xor16_v1(uint16_t a, uint16_t b) {
    uint16_t p = (uint16_t)(a | b), q = (uint16_t)(a & b);
    MBA_OPAQUE(p); MBA_OPAQUE(q); return sub16_v1(p, q);
}
static inline uint16_t xor16_v2(uint16_t a, uint16_t b) {
    uint16_t p = (uint16_t)(a & (uint16_t)~b),
             q = (uint16_t)((uint16_t)~a & b);
    MBA_OPAQUE(p); MBA_OPAQUE(q); return (uint16_t)(p | q);
}

static inline uint16_t add16_dispatch(uint16_t a, uint16_t b, uint16_t sel) {
    uint16_t so = sel; MBA_OPAQUE(so);
    switch (so & 3u) {
        case 0: return add16_v1(a, b);
        case 1: return add16_v2(a, b);
        case 2: return add16_v3(a, b);
        default:return add16_v2(a, b);
    }
}
static inline uint16_t sub16_dispatch(uint16_t a, uint16_t b, uint16_t sel) {
    uint16_t so = sel; MBA_OPAQUE(so);
    return (so & 1u) ? sub16_v2(a, b) : sub16_v1(a, b);
}
static inline uint16_t xor16_dispatch(uint16_t a, uint16_t b, uint16_t sel) {
    uint16_t so = sel; MBA_OPAQUE(so);
    return (so & 1u) ? xor16_v2(a, b) : xor16_v1(a, b);
}

static inline uint16_t mul16_mba(uint16_t k, uint16_t t, uint16_t sel) {
    uint16_t r = 0;
    for (int i = 0; i < 16; i++) {
        uint16_t mask = (uint16_t)(0u - (uint16_t)(k & 1u));
        MBA_OPAQUE(mask);
        r = add16_dispatch(r, (uint16_t)(t & mask),
                           (uint16_t)(sel + (unsigned)i));
        t = (uint16_t)(t << 1); k = (uint16_t)(k >> 1);
    }
    return r;
}

/* =====================================================================
 * ENCODE -- clean, pack-time only, no obfuscation needed.
 * ===================================================================== */
static inline void encode_buf(uint8_t *buf, size_t n) {
    const uint16_t A = k_A(), B = k_B(), C = k_C(), M = k_M(), N = k_N();
    const unsigned R = k_R();
    uint16_t k = k_SEED();
    size_t nw = n >> 1;
    for (size_t i = 0; i < nw; i++) {
        uint16_t x = (uint16_t)(buf[2u*i] | ((uint16_t)buf[2u*i+1u] << 8));
        uint16_t s = (uint16_t)(A * x + B + k);
        uint16_t y = (uint16_t)(rol16(s, R) ^ C);
        buf[2u*i]   = (uint8_t)(y & 0xFFu);
        buf[2u*i+1u]= (uint8_t)((y >> 8) & 0xFFu);
        k = (uint16_t)(M * k + N);
    }
    if (n & 1u) buf[n-1u] ^= (uint8_t)(k & 0xFFu);
}

/* =====================================================================
 * DECODE -- true CFF state machine.
 *
 * Three mechanisms guarantee IDA sees a real star topology:
 *
 *   1. NOINLINE on decode_buf + all handlers
 *      No inlining => compiler never sees caller context => cannot
 *      constant-propagate initial state => all switch cases survive.
 *
 *   2. volatile initial state
 *      `volatile uint16_t vstate = ST_LOAD; state = vstate;`
 *      Even if inlined, the initial state is an "unknown" volatile read.
 *
 *   3. Volatile handler table reads
 *      `((stage_fn_t volatile *)g_handlers)[idx]`
 *      Compiler cannot devirtualize -- must emit `call *mem[idx]`.
 * ===================================================================== */

typedef struct dctx_s {
    uint8_t  *buf;
    size_t    n, i, nw;
    uint16_t  y, t, x, k;
    uint16_t  A, B, C, M, N;
    unsigned  R;
    uint16_t  A_inv, sel;
} dctx_t;

typedef void (*stage_fn_t)(dctx_t *);

/* ---- Stage handlers (all NOINLINE -- critical for real CFF) -------- */

NOINLINE static void h_load(dctx_t *c) {
    c->y   = (uint16_t)(c->buf[2u*c->i] | ((uint16_t)c->buf[2u*c->i+1u] << 8));
    c->sel = (uint16_t)((uint16_t)c->i ^ c->k);
}

NOINLINE static void h_xor_c(dctx_t *c) {
    if (op_true_1(c->y))
        c->t = xor16_dispatch(c->y,  c->C,          c->sel);
    else
        c->t = xor16_dispatch(c->y, (uint16_t)~c->C, c->sel);  /* dead */
}

NOINLINE static void h_ror(dctx_t *c) {
    if (op_true_2(c->t, c->k))
        c->t = ror16(c->t, c->R);
    else
        c->t = rol16(c->t, c->R);                               /* dead */
}

NOINLINE static void h_sub_b(dctx_t *c) {
    if (op_true_3(c->t, c->B))
        c->t = sub16_dispatch(c->t, c->B,  (uint16_t)(c->sel + 1u));
    else
        c->t = add16_dispatch(c->t, c->B,  (uint16_t)(c->sel + 1u)); /* dead */
}

NOINLINE static void h_sub_k(dctx_t *c) {
    if (op_true_1((uint16_t)(c->t ^ c->k)))
        c->t = sub16_dispatch(c->t, c->k,  (uint16_t)(c->sel + 2u));
    else
        c->t = xor16_dispatch(c->t, c->k,  (uint16_t)(c->sel + 2u)); /* dead */
}

NOINLINE static void h_mul(dctx_t *c) {
    if (op_true_2(c->t, c->k))
        c->x = mul16_mba(c->A_inv, c->t, c->sel);
    else
        c->x = mul16_mba(c->A,     c->t, c->sel);              /* dead */
}

NOINLINE static void h_store(dctx_t *c) {
    c->buf[2u*c->i]   = (uint8_t)(c->x & 0xFFu);
    c->buf[2u*c->i+1u]= (uint8_t)((c->x >> 8) & 0xFFu);
}

NOINLINE static void h_ks(dctx_t *c) {
    if (op_true_3(c->k, c->M)) {
        uint16_t mk = mul16_mba(c->M, c->k, (uint16_t)(c->sel + 3u));
        c->k = add16_dispatch(mk, c->N, (uint16_t)(c->sel + 4u));
    } else {
        uint16_t mk = mul16_mba(c->k, c->M, (uint16_t)(c->sel + 3u)); /* dead */
        c->k = add16_dispatch(c->N, mk, (uint16_t)(c->sel + 4u));
    }
}

NOINLINE static void h_next(dctx_t *c) { c->i++; }

NOINLINE static void h_tail(dctx_t *c) {
    if (c->n & 1u)
        c->buf[c->n-1u] ^= (uint8_t)(c->k & 0xFFu);
}

NOINLINE static void h_dummy(dctx_t *c) { (void)c; }

/* ---- Handler table -------------------------------------------------
 * Real handlers at specific slots; dummies fill the rest.
 * Read through volatile pointer so devirtualization is impossible. */
static stage_fn_t const g_handlers[16] = {
    /* 0 */ h_load,  /* 1 */ h_dummy, /* 2 */ h_xor_c, /* 3 */ h_dummy,
    /* 4 */ h_ror,   /* 5 */ h_sub_b, /* 6 */ h_dummy, /* 7 */ h_sub_k,
    /* 8 */ h_dummy, /* 9 */ h_mul,   /*10 */ h_store,  /*11 */ h_dummy,
    /*12 */ h_ks,    /*13 */ h_next,  /*14 */ h_tail,   /*15 */ h_dummy,
};

/* Convenience: volatile indirect call -- the one place that must not
 * be devirtualized. Every case in the switch uses this macro. */
#define CALL_HANDLER(idx, ctx) \
    (((stage_fn_t volatile *)g_handlers)[(idx) & 0xFu])(ctx)

/* ---- Scrambled state labels (non-sequential hex) ------------------- */
#define ST_LOAD   ((uint16_t)0xA3F1u)
#define ST_XOR_C  ((uint16_t)0x6E4Fu)
#define ST_ROR    ((uint16_t)0xC182u)
#define ST_SUB_B  ((uint16_t)0x2D5Au)
#define ST_SUB_K  ((uint16_t)0x8B37u)
#define ST_MUL    ((uint16_t)0x54E9u)
#define ST_STORE  ((uint16_t)0xF206u)
#define ST_KS     ((uint16_t)0x9D71u)
#define ST_NEXT   ((uint16_t)0x3AC4u)
#define ST_TAIL   ((uint16_t)0xB48Du)
#define ST_HALT   ((uint16_t)0x0000u)

/* Handler table indices */
#define HIDX_LOAD   ((uint16_t)0u)
#define HIDX_XOR_C  ((uint16_t)2u)
#define HIDX_ROR    ((uint16_t)4u)
#define HIDX_SUB_B  ((uint16_t)5u)
#define HIDX_SUB_K  ((uint16_t)7u)
#define HIDX_MUL    ((uint16_t)9u)
#define HIDX_STORE  ((uint16_t)10u)
#define HIDX_KS     ((uint16_t)12u)
#define HIDX_NEXT   ((uint16_t)13u)
#define HIDX_TAIL   ((uint16_t)14u)

/* ---- The decode driver (NOINLINE -- non-negotiable) ---------------- */
NOINLINE static void decode_buf(uint8_t *buf, size_t n) {
    dctx_t ctx;
    ctx.buf   = buf; ctx.n = n; ctx.i = 0; ctx.nw = n >> 1;
    ctx.A     = k_A(); ctx.B = k_B(); ctx.C = k_C();
    ctx.M     = k_M(); ctx.N = k_N(); ctx.R = k_R();
    ctx.A_inv = inv_odd16(ctx.A);
    ctx.k     = k_SEED();
    ctx.sel   = 0;

    /* volatile read of initial state: even if inlined, compiler sees
     * an unknown value and must emit all switch cases. */
    volatile uint16_t vstate = (ctx.nw > 0)  ? ST_LOAD
                              : (n & 1u)      ? ST_TAIL
                                              : ST_HALT;
    uint16_t state = vstate;

    while (state != ST_HALT) {
        switch (state) {

            case ST_LOAD: {
                uint16_t idx = opaque_const_u16(HIDX_LOAD, ctx.k);
                CALL_HANDLER(idx, &ctx);
                state = opaque_const_u16(ST_XOR_C, state);
                break;
            }
            case ST_XOR_C: {
                uint16_t idx = opaque_const_u16(HIDX_XOR_C, ctx.sel);
                CALL_HANDLER(idx, &ctx);
                state = opaque_const_u16(ST_ROR, state);
                break;
            }
            case ST_ROR: {
                uint16_t idx = opaque_const_u16(HIDX_ROR, ctx.sel);
                CALL_HANDLER(idx, &ctx);
                state = opaque_const_u16(ST_SUB_B, state);
                break;
            }
            case ST_SUB_B: {
                uint16_t idx = opaque_const_u16(HIDX_SUB_B, ctx.sel);
                CALL_HANDLER(idx, &ctx);
                state = opaque_const_u16(ST_SUB_K, state);
                break;
            }
            case ST_SUB_K: {
                uint16_t idx = opaque_const_u16(HIDX_SUB_K, ctx.sel);
                CALL_HANDLER(idx, &ctx);
                state = opaque_const_u16(ST_MUL, state);
                break;
            }
            case ST_MUL: {
                uint16_t idx = opaque_const_u16(HIDX_MUL, ctx.sel);
                CALL_HANDLER(idx, &ctx);
                state = opaque_const_u16(ST_STORE, state);
                break;
            }
            case ST_STORE: {
                uint16_t idx = opaque_const_u16(HIDX_STORE, ctx.sel);
                CALL_HANDLER(idx, &ctx);
                state = opaque_const_u16(ST_KS, state);
                break;
            }
            case ST_KS: {
                uint16_t idx = opaque_const_u16(HIDX_KS, ctx.sel);
                CALL_HANDLER(idx, &ctx);
                state = opaque_const_u16(ST_NEXT, state);
                break;
            }
            case ST_NEXT: {
                uint16_t idx = opaque_const_u16(HIDX_NEXT, ctx.k);
                CALL_HANDLER(idx, &ctx);
                if (ctx.i < ctx.nw)
                    state = opaque_const_u16(ST_LOAD, (uint16_t)ctx.i);
                else if (ctx.n & 1u)
                    state = opaque_const_u16(ST_TAIL, (uint16_t)ctx.i);
                else
                    state = ST_HALT;
                break;
            }
            case ST_TAIL: {
                uint16_t idx = opaque_const_u16(HIDX_TAIL, ctx.k);
                CALL_HANDLER(idx, &ctx);
                state = ST_HALT;
                break;
            }
            default:
                state = ST_HALT;
                break;
        }
    }
}

#endif /* MATHCRYPT_H */