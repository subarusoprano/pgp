//BEGIN TWOFISH CIPHER SUPPORT - Disastry
//This file was provided by Disastry
/* Twofish for GPG
 * By Matthew Skala <mskala@ansuz.sooke.bc.ca>, July 26, 1998
 * 256-bit key length added March 20, 1999
 * Some modifications to reduce the text size by Werner Koch, April, 1998
 *
 * The original author has disclaimed all copyright interest in this
 * code and thus putting it in the public domain.
 *
 * This code is a "clean room" implementation, written from the paper
 * _Twofish: A 128-Bit Block Cipher_ by Bruce Schneier, John Kelsey,
 * Doug Whiting, David Wagner, Chris Hall, and Niels Ferguson, available
 * through http://www.counterpane.com/twofish.html
 *
 * For background information on multiplication in finite fields, used for
 * the matrix operations in the key schedule, see the book _Contemporary
 * Abstract Algebra_ by Joseph A. Gallian, especially chapter 22 in the
 * Third Edition.
 *
 * Only the 128- and 256-bit key sizes are supported.  This code is intended
 * for GNU C on a 32-bit system, but it should work almost anywhere.  Loops
 * are unrolled, precomputation tables are used, etc., for maximum speed at
 * some cost in memory consumption. */

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h> /* for memcmp() */

#include "pgpSymmetricCipherPriv.h"
#include "pgpUsuals.h"
#include "pgpMem.h"


#define u32 PGPUInt32
#define byte PGPByte

/* Prototype for the self-test function. */
static const char *selftest(void);

/* Structure for an expanded Twofish key.  s contains the key-dependent
 * S-boxes composed with the MDS matrix; w contains the eight "whitening"
 * subkeys, K[0] through K[7].  k holds the remaining, "round" subkeys.  Note
 * that k[i] corresponds to what the Twofish paper calls K[i+8]. */
typedef struct {
   u32 s[4][256], w[8], k[32];
} TWOFISH_context;

#include "pgpTwofishTable.h"

/* Macro to perform one column of the RS matrix multiplication.  The
 * parameters a, b, c, and d are the four bytes of output; i is the index
 * of the key bytes, and w, x, y, and z, are the column of constants from
 * the RS matrix, preprocessed through the poly_to_exp table. */

#define CALC_S(a, b, c, d, i, w, x, y, z) \
   if (key[i]) { \
      tmp = poly_to_exp[key[i] - 1]; \
      (a) ^= exp_to_poly[tmp + (w)]; \
      (b) ^= exp_to_poly[tmp + (x)]; \
      (c) ^= exp_to_poly[tmp + (y)]; \
      (d) ^= exp_to_poly[tmp + (z)]; \
   }

/* Macros to calculate the key-dependent S-boxes for a 128-bit key using
 * the S vector from CALC_S.  CALC_SB_2 computes a single entry in all
 * four S-boxes, where i is the index of the entry to compute, and a and b
 * are the index numbers preprocessed through the q0 and q1 tables
 * respectively.  CALC_SB is simply a convenience to make the code shorter;
 * it calls CALC_SB_2 four times with consecutive indices from i to i+3,
 * using the remaining parameters two by two. */

#define CALC_SB_2(i, a, b) \
   ctx->s[0][i] = mds[0][q0[(a) ^ sa] ^ se]; \
   ctx->s[1][i] = mds[1][q0[(b) ^ sb] ^ sf]; \
   ctx->s[2][i] = mds[2][q1[(a) ^ sc] ^ sg]; \
   ctx->s[3][i] = mds[3][q1[(b) ^ sd] ^ sh]

#define CALC_SB(i, a, b, c, d, e, f, g, h) \
   CALC_SB_2 (i, a, b); CALC_SB_2 ((i)+1, c, d); \
   CALC_SB_2 ((i)+2, e, f); CALC_SB_2 ((i)+3, g, h)

/* Macros exactly like CALC_SB and CALC_SB_2, but for 256-bit keys. */

#define CALC_SB256_2(i, a, b) \
   ctx->s[0][i] = mds[0][q0[q0[q1[(b) ^ sa] ^ se] ^ si] ^ sm]; \
   ctx->s[1][i] = mds[1][q0[q1[q1[(a) ^ sb] ^ sf] ^ sj] ^ sn]; \
   ctx->s[2][i] = mds[2][q1[q0[q0[(a) ^ sc] ^ sg] ^ sk] ^ so]; \
   ctx->s[3][i] = mds[3][q1[q1[q0[(b) ^ sd] ^ sh] ^ sl] ^ sp];

#define CALC_SB256(i, a, b, c, d, e, f, g, h) \
   CALC_SB256_2 (i, a, b); CALC_SB256_2 ((i)+1, c, d); \
   CALC_SB256_2 ((i)+2, e, f); CALC_SB256_2 ((i)+3, g, h)

/* Macros to calculate the whitening and round subkeys.  CALC_K_2 computes the
 * last two stages of the h() function for a given index (either 2i or 2i+1).
 * a, b, c, and d are the four bytes going into the last two stages.  For
 * 128-bit keys, this is the entire h() function and a and c are the index
 * preprocessed through q0 and q1 respectively; for longer keys they are the
 * output of previous stages.  j is the index of the first key byte to use.
 * CALC_K computes a pair of subkeys for 128-bit Twofish, by calling CALC_K_2
 * twice, doing the Psuedo-Hadamard Transform, and doing the necessary
 * rotations.  Its parameters are: a, the array to write the results into,
 * j, the index of the first output entry, k and l, the preprocessed indices
 * for index 2i, and m and n, the preprocessed indices for index 2i+1.
 * CALC_K256_2 expands CALC_K_2 to handle 256-bit keys, by doing two
 * additional lookup-and-XOR stages.  The parameters a and b are the index
 * preprocessed through q0 and q1 respectively; j is the index of the first
 * key byte to use.  CALC_K256 is identical to CALC_K but for using the
 * CALC_K256_2 macro instead of CALC_K_2. */

#define CALC_K_2(a, b, c, d, j) \
     mds[0][q0[a ^ key[(j) + 8]] ^ key[j]] \
   ^ mds[1][q0[b ^ key[(j) + 9]] ^ key[(j) + 1]] \
   ^ mds[2][q1[c ^ key[(j) + 10]] ^ key[(j) + 2]] \
   ^ mds[3][q1[d ^ key[(j) + 11]] ^ key[(j) + 3]]

#define CALC_K(a, j, k, l, m, n) \
   x = CALC_K_2 (k, l, k, l, 0); \
   y = CALC_K_2 (m, n, m, n, 4); \
   y = (y << 8) + (y >> 24); \
   x += y; y += x; ctx->a[j] = x; \
   ctx->a[(j) + 1] = (y << 9) + (y >> 23)

#define CALC_K256_2(a, b, j) \
   CALC_K_2 (q0[q1[b ^ key[(j) + 24]] ^ key[(j) + 16]], \
             q1[q1[a ^ key[(j) + 25]] ^ key[(j) + 17]], \
             q0[q0[a ^ key[(j) + 26]] ^ key[(j) + 18]], \
             q1[q0[b ^ key[(j) + 27]] ^ key[(j) + 19]], j)

#define CALC_K256(a, j, k, l, m, n) \
   x = CALC_K256_2 (k, l, 0); \
   y = CALC_K256_2 (m, n, 4); \
   y = (y << 8) + (y >> 24); \
   x += y; y += x; ctx->a[j] = x; \
   ctx->a[(j) + 1] = (y << 9) + (y >> 23)

/* Perform the key setup.  Note that this works only with 128- and 256-bit
 * keys, despite the API that looks like it might support other sizes. */

static int
twofish_setkey (TWOFISH_context *ctx, const byte *key, const unsigned keylen)
{
    int i, j, k;

    /* Temporaries for CALC_K. */
    u32 x, y;

    /* The S vector used to key the S-boxes, split up into individual bytes.
     * 128-bit keys use only sa through sh; 256-bit use all of them. */
    byte sa = 0, sb = 0, sc = 0, sd = 0, se = 0, sf = 0, sg = 0, sh = 0;
    byte si = 0, sj = 0, sk = 0, sl = 0, sm = 0, sn = 0, so = 0, sp = 0;

    /* Temporary for CALC_S. */
    byte tmp;

    /* Flags for self-test. */
    static int initialized = 0;
    static const char *selftest_failed=0;

    /* Check key length. */
    if( ( ( keylen - 16 ) | 16 ) != 16 )
        return -1;

    /* Do self-test if necessary. */
    if (!initialized) {
       initialized = 1;
       selftest_failed = selftest ();
       if( selftest_failed )
         ;//fprintf(stderr, "%s\n", selftest_failed );
    }
    if( selftest_failed )
       return -2;

    /* Compute the first two words of the S vector.  The magic numbers are
     * the entries of the RS matrix, preprocessed through poly_to_exp.  The
     * numbers in the comments are the original (polynomial form) matrix
     * entries. */
    CALC_S (sa, sb, sc, sd, 0, 0x00, 0x2D, 0x01, 0x2D); /* 01 A4 02 A4 */
    CALC_S (sa, sb, sc, sd, 1, 0x2D, 0xA4, 0x44, 0x8A); /* A4 56 A1 55 */
    CALC_S (sa, sb, sc, sd, 2, 0x8A, 0xD5, 0xBF, 0xD1); /* 55 82 FC 87 */
    CALC_S (sa, sb, sc, sd, 3, 0xD1, 0x7F, 0x3D, 0x99); /* 87 F3 C1 5A */
    CALC_S (sa, sb, sc, sd, 4, 0x99, 0x46, 0x66, 0x96); /* 5A 1E 47 58 */
    CALC_S (sa, sb, sc, sd, 5, 0x96, 0x3C, 0x5B, 0xED); /* 58 C6 AE DB */
    CALC_S (sa, sb, sc, sd, 6, 0xED, 0x37, 0x4F, 0xE0); /* DB 68 3D 9E */
    CALC_S (sa, sb, sc, sd, 7, 0xE0, 0xD0, 0x8C, 0x17); /* 9E E5 19 03 */
    CALC_S (se, sf, sg, sh, 8, 0x00, 0x2D, 0x01, 0x2D); /* 01 A4 02 A4 */
    CALC_S (se, sf, sg, sh, 9, 0x2D, 0xA4, 0x44, 0x8A); /* A4 56 A1 55 */
    CALC_S (se, sf, sg, sh, 10, 0x8A, 0xD5, 0xBF, 0xD1); /* 55 82 FC 87 */
    CALC_S (se, sf, sg, sh, 11, 0xD1, 0x7F, 0x3D, 0x99); /* 87 F3 C1 5A */
    CALC_S (se, sf, sg, sh, 12, 0x99, 0x46, 0x66, 0x96); /* 5A 1E 47 58 */
    CALC_S (se, sf, sg, sh, 13, 0x96, 0x3C, 0x5B, 0xED); /* 58 C6 AE DB */
    CALC_S (se, sf, sg, sh, 14, 0xED, 0x37, 0x4F, 0xE0); /* DB 68 3D 9E */
    CALC_S (se, sf, sg, sh, 15, 0xE0, 0xD0, 0x8C, 0x17); /* 9E E5 19 03 */

    if (keylen == 32) { /* 256-bit key */
        /* Calculate the remaining two words of the S vector */
        CALC_S (si, sj, sk, sl, 16, 0x00, 0x2D, 0x01, 0x2D); /* 01 A4 02 A4 */
        CALC_S (si, sj, sk, sl, 17, 0x2D, 0xA4, 0x44, 0x8A); /* A4 56 A1 55 */
        CALC_S (si, sj, sk, sl, 18, 0x8A, 0xD5, 0xBF, 0xD1); /* 55 82 FC 87 */
        CALC_S (si, sj, sk, sl, 19, 0xD1, 0x7F, 0x3D, 0x99); /* 87 F3 C1 5A */
        CALC_S (si, sj, sk, sl, 20, 0x99, 0x46, 0x66, 0x96); /* 5A 1E 47 58 */
        CALC_S (si, sj, sk, sl, 21, 0x96, 0x3C, 0x5B, 0xED); /* 58 C6 AE DB */
        CALC_S (si, sj, sk, sl, 22, 0xED, 0x37, 0x4F, 0xE0); /* DB 68 3D 9E */
        CALC_S (si, sj, sk, sl, 23, 0xE0, 0xD0, 0x8C, 0x17); /* 9E E5 19 03 */
        CALC_S (sm, sn, so, sp, 24, 0x00, 0x2D, 0x01, 0x2D); /* 01 A4 02 A4 */
        CALC_S (sm, sn, so, sp, 25, 0x2D, 0xA4, 0x44, 0x8A); /* A4 56 A1 55 */
        CALC_S (sm, sn, so, sp, 26, 0x8A, 0xD5, 0xBF, 0xD1); /* 55 82 FC 87 */
        CALC_S (sm, sn, so, sp, 27, 0xD1, 0x7F, 0x3D, 0x99); /* 87 F3 C1 5A */
        CALC_S (sm, sn, so, sp, 28, 0x99, 0x46, 0x66, 0x96); /* 5A 1E 47 58 */
        CALC_S (sm, sn, so, sp, 29, 0x96, 0x3C, 0x5B, 0xED); /* 58 C6 AE DB */
        CALC_S (sm, sn, so, sp, 30, 0xED, 0x37, 0x4F, 0xE0); /* DB 68 3D 9E */
        CALC_S (sm, sn, so, sp, 31, 0xE0, 0xD0, 0x8C, 0x17); /* 9E E5 19 03 */

        /* Compute the S-boxes. */
        for(i=j=0,k=1; i < 256; i++, j += 2, k += 2 ) {
            CALC_SB256_2( i, calc_sb_tbl[j], calc_sb_tbl[k] );
        }

        /* Calculate whitening and round subkeys.  The constants are
         * indices of subkeys, preprocessed through q0 and q1. */
        CALC_K256 (w, 0, 0xA9, 0x75, 0x67, 0xF3);
        CALC_K256 (w, 2, 0xB3, 0xC6, 0xE8, 0xF4);
        CALC_K256 (w, 4, 0x04, 0xDB, 0xFD, 0x7B);
        CALC_K256 (w, 6, 0xA3, 0xFB, 0x76, 0xC8);
        CALC_K256 (k, 0, 0x9A, 0x4A, 0x92, 0xD3);
        CALC_K256 (k, 2, 0x80, 0xE6, 0x78, 0x6B);
        CALC_K256 (k, 4, 0xE4, 0x45, 0xDD, 0x7D);
        CALC_K256 (k, 6, 0xD1, 0xE8, 0x38, 0x4B);
        CALC_K256 (k, 8, 0x0D, 0xD6, 0xC6, 0x32);
        CALC_K256 (k, 10, 0x35, 0xD8, 0x98, 0xFD);
        CALC_K256 (k, 12, 0x18, 0x37, 0xF7, 0x71);
        CALC_K256 (k, 14, 0xEC, 0xF1, 0x6C, 0xE1);
        CALC_K256 (k, 16, 0x43, 0x30, 0x75, 0x0F);
        CALC_K256 (k, 18, 0x37, 0xF8, 0x26, 0x1B);
        CALC_K256 (k, 20, 0xFA, 0x87, 0x13, 0xFA);
        CALC_K256 (k, 22, 0x94, 0x06, 0x48, 0x3F);
        CALC_K256 (k, 24, 0xF2, 0x5E, 0xD0, 0xBA);
        CALC_K256 (k, 26, 0x8B, 0xAE, 0x30, 0x5B);
        CALC_K256 (k, 28, 0x84, 0x8A, 0x54, 0x00);
        CALC_K256 (k, 30, 0xDF, 0xBC, 0x23, 0x9D);
    }
    else {
        /* Compute the S-boxes. */
        for(i=j=0,k=1; i < 256; i++, j += 2, k += 2 ) {
            CALC_SB_2( i, calc_sb_tbl[j], calc_sb_tbl[k] );
        }

        /* Calculate whitening and round subkeys.  The constants are
         * indices of subkeys, preprocessed through q0 and q1. */
        CALC_K (w, 0, 0xA9, 0x75, 0x67, 0xF3);
        CALC_K (w, 2, 0xB3, 0xC6, 0xE8, 0xF4);
        CALC_K (w, 4, 0x04, 0xDB, 0xFD, 0x7B);
        CALC_K (w, 6, 0xA3, 0xFB, 0x76, 0xC8);
        CALC_K (k, 0, 0x9A, 0x4A, 0x92, 0xD3);
        CALC_K (k, 2, 0x80, 0xE6, 0x78, 0x6B);
        CALC_K (k, 4, 0xE4, 0x45, 0xDD, 0x7D);
        CALC_K (k, 6, 0xD1, 0xE8, 0x38, 0x4B);
        CALC_K (k, 8, 0x0D, 0xD6, 0xC6, 0x32);
        CALC_K (k, 10, 0x35, 0xD8, 0x98, 0xFD);
        CALC_K (k, 12, 0x18, 0x37, 0xF7, 0x71);
        CALC_K (k, 14, 0xEC, 0xF1, 0x6C, 0xE1);
        CALC_K (k, 16, 0x43, 0x30, 0x75, 0x0F);
        CALC_K (k, 18, 0x37, 0xF8, 0x26, 0x1B);
        CALC_K (k, 20, 0xFA, 0x87, 0x13, 0xFA);
        CALC_K (k, 22, 0x94, 0x06, 0x48, 0x3F);
        CALC_K (k, 24, 0xF2, 0x5E, 0xD0, 0xBA);
        CALC_K (k, 26, 0x8B, 0xAE, 0x30, 0x5B);
        CALC_K (k, 28, 0x84, 0x8A, 0x54, 0x00);
        CALC_K (k, 30, 0xDF, 0xBC, 0x23, 0x9D);
    }

    return 0;
}

/* Macros to compute the g() function in the encryption and decryption
 * rounds.  G1 is the straight g() function; G2 includes the 8-bit
 * rotation for the high 32-bit word. */

#define G1(a) \
     (ctx->s[0][(a) & 0xFF]) ^ (ctx->s[1][((a) >> 8) & 0xFF]) \
   ^ (ctx->s[2][((a) >> 16) & 0xFF]) ^ (ctx->s[3][(a) >> 24])

#define G2(b) \
     (ctx->s[1][(b) & 0xFF]) ^ (ctx->s[2][((b) >> 8) & 0xFF]) \
   ^ (ctx->s[3][((b) >> 16) & 0xFF]) ^ (ctx->s[0][(b) >> 24])

/* Encryption and decryption Feistel rounds.  Each one calls the two g()
 * macros, does the PHT, and performs the XOR and the appropriate bit
 * rotations.  The parameters are the round number (used to select subkeys),
 * and the four 32-bit chunks of the text. */

#define ENCROUND(n, a, b, c, d) \
   x = G1 (a); y = G2 (b); \
   x += y; y += x + ctx->k[2 * (n) + 1]; \
   (c) ^= x + ctx->k[2 * (n)]; \
   (c) = ((c) >> 1) + ((c) << 31); \
   (d) = (((d) << 1)+((d) >> 31)) ^ y

#define DECROUND(n, a, b, c, d) \
   x = G1 (a); y = G2 (b); \
   x += y; y += x; \
   (d) ^= y + ctx->k[2 * (n) + 1]; \
   (d) = ((d) >> 1) + ((d) << 31); \
   (c) = (((c) << 1)+((c) >> 31)); \
   (c) ^= (x + ctx->k[2 * (n)])

/* Encryption and decryption cycles; each one is simply two Feistel rounds
 * with the 32-bit chunks re-ordered to simulate the "swap" */

#define ENCCYCLE(n) \
   ENCROUND (2 * (n), a, b, c, d); \
   ENCROUND (2 * (n) + 1, c, d, a, b)

#define DECCYCLE(n) \
   DECROUND (2 * (n) + 1, c, d, a, b); \
   DECROUND (2 * (n), a, b, c, d)

/* Macros to convert the input and output bytes into 32-bit words,
 * and simultaneously perform the whitening step.  INPACK packs word
 * number n into the variable named by x, using whitening subkey number m.
 * OUTUNPACK unpacks word number n from the variable named by x, using
 * whitening subkey number m. */

#define INPACK(n, x, m) \
   x = in[4 * (n)] ^ (in[4 * (n) + 1] << 8) \
     ^ (in[4 * (n) + 2] << 16) ^ (in[4 * (n) + 3] << 24) ^ ctx->w[m]

#define OUTUNPACK(n, x, m) \
   x ^= ctx->w[m]; \
   out[4 * (n)] = x; out[4 * (n) + 1] = x >> 8; \
   out[4 * (n) + 2] = x >> 16; out[4 * (n) + 3] = x >> 24

/* Encrypt one block.  in and out may be the same. */

static void
twofish_encrypt (const TWOFISH_context *ctx, byte *out, const byte *in)
{
   /* The four 32-bit chunks of the text. */
   u32 a, b, c, d;

   /* Temporaries used by the round function. */
   u32 x, y;

   /* Input whitening and packing. */
   INPACK (0, a, 0);
   INPACK (1, b, 1);
   INPACK (2, c, 2);
   INPACK (3, d, 3);

   /* Encryption Feistel cycles. */
   ENCCYCLE (0);
   ENCCYCLE (1);
   ENCCYCLE (2);
   ENCCYCLE (3);
   ENCCYCLE (4);
   ENCCYCLE (5);
   ENCCYCLE (6);
   ENCCYCLE (7);

   /* Output whitening and unpacking. */
   OUTUNPACK (0, c, 4);
   OUTUNPACK (1, d, 5);
   OUTUNPACK (2, a, 6);
   OUTUNPACK (3, b, 7);
}

/* Decrypt one block.  in and out may be the same. */

static void
twofish_decrypt (const TWOFISH_context *ctx, byte *out, const byte *in)
{
   /* The four 32-bit chunks of the text. */
   u32 a, b, c, d;

   /* Temporaries used by the round function. */
   u32 x, y;

   /* Input whitening and packing. */
   INPACK (0, c, 4);
   INPACK (1, d, 5);
   INPACK (2, a, 6);
   INPACK (3, b, 7);

   /* Encryption Feistel cycles. */
   DECCYCLE (7);
   DECCYCLE (6);
   DECCYCLE (5);
   DECCYCLE (4);
   DECCYCLE (3);
   DECCYCLE (2);
   DECCYCLE (1);
   DECCYCLE (0);

   /* Output whitening and unpacking. */
   OUTUNPACK (0, a, 0);
   OUTUNPACK (1, b, 1);
   OUTUNPACK (2, c, 2);
   OUTUNPACK (3, d, 3);
}

/* Test a single encryption and decryption with each key size. */

static const char*
selftest (void)
{
   TWOFISH_context ctx; /* Expanded key. */
   byte scratch[16];    /* Encryption/decryption result buffer. */

   /* Test vectors for single encryption/decryption.  Note that I am using
    * the vectors from the Twofish paper's "known answer test", I=3 for
    * 128-bit and I=4 for 256-bit, instead of the all-0 vectors from the
    * "intermediate value test", because an all-0 key would trigger all the
    * special cases in the RS matrix multiply, leaving the math untested. */
   static const byte plaintext[16] = {
      0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
      0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19
   };
   static const byte key[16] = {
      0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
      0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A
   };
   static const byte ciphertext[16] = {
      0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85,
      0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3
   };
   static const byte plaintext_256[16] = {
      0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F,
      0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6
   };
   static const byte key_256[32] = {
      0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46,
      0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
      0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
      0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
   };
   static const byte ciphertext_256[16] = {
      0x6C, 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97,
      0x05, 0x93, 0x1C, 0xB6, 0xD4, 0x08, 0xE7, 0xFA
   };

   twofish_setkey (&ctx, key, sizeof(key));
   twofish_encrypt (&ctx, scratch, plaintext);
   if (memcmp (scratch, ciphertext, sizeof (ciphertext)))
     return "Twofish-128 test encryption failed.";
   twofish_decrypt (&ctx, scratch, scratch);
   if (memcmp (scratch, plaintext, sizeof (plaintext)))
     return "Twofish-128 test decryption failed.";

   twofish_setkey (&ctx, key_256, sizeof(key_256));
   twofish_encrypt (&ctx, scratch, plaintext_256);
   if (memcmp (scratch, ciphertext_256, sizeof (ciphertext_256)))
     return "Twofish-256 test encryption failed.";
   twofish_decrypt (&ctx, scratch, scratch);
   if (memcmp (scratch, plaintext_256, sizeof (plaintext_256)))
     return "Twofish-256 test decryption failed.";

   return NULL;
}

/* More complete test program.  This does 1000 encryptions and decryptions
 * with each of 250 128-bit keys and 2000 encryptions and decryptions with
 * each of 125 256-bit keys, using a feedback scheme similar to a Feistel
 * cipher, so as to be sure of testing all the table entries pretty
 * thoroughly.  We keep changing the keys so as to get a more meaningful
 * performance number, since the key setup is non-trivial for Twofish. */

#ifdef TEST

#include <stdio.h>
#include <string.h>
#include <time.h>

int
main()
{
   TWOFISH_context ctx;     /* Expanded key. */
   int i, j;                /* Loop counters. */

   const char *encrypt_msg; /* Message to print regarding encryption test;
                             * the printf is done outside the loop to avoid
                             * stuffing up the timing. */
   clock_t timer; /* For computing elapsed time. */

   /* Test buffer. */
   byte buffer[4][16] = {
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
       0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
      {0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
       0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2 ,0xE1, 0xF0},
      {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54 ,0x32, 0x10},
      {0x01, 0x23, 0x45, 0x67, 0x76, 0x54 ,0x32, 0x10,
       0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98}
   };

   /* Expected outputs for the million-operation test */
   static const byte test_encrypt[4][16] = {
      {0xC8, 0x23, 0xB8, 0xB7, 0x6B, 0xFE, 0x91, 0x13,
       0x2F, 0xA7, 0x5E, 0xE6, 0x94, 0x77, 0x6F, 0x6B},
      {0x90, 0x36, 0xD8, 0x29, 0xD5, 0x96, 0xC2, 0x8E,
       0xE4, 0xFF, 0x76, 0xBC, 0xE5, 0x77, 0x88, 0x27},
      {0xB8, 0x78, 0x69, 0xAF, 0x42, 0x8B, 0x48, 0x64,
       0xF7, 0xE9, 0xF3, 0x9C, 0x42, 0x18, 0x7B, 0x73},
      {0x7A, 0x88, 0xFB, 0xEB, 0x90, 0xA4, 0xB4, 0xA8,
       0x43, 0xA3, 0x1D, 0xF1, 0x26, 0xC4, 0x53, 0x57}
   };
   static const byte test_decrypt[4][16] = {
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
       0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
      {0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
       0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2 ,0xE1, 0xF0},
      {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54 ,0x32, 0x10},
      {0x01, 0x23, 0x45, 0x67, 0x76, 0x54 ,0x32, 0x10,
       0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98}
   };

   /* Start the timer ticking. */
   timer = clock ();

   /* Encryption test. */
   for (i = 0; i < 125; i++) {
      twofish_setkey (&ctx, buffer[0], sizeof (buffer[0]));
      for (j = 0; j < 1000; j++)
        twofish_encrypt (&ctx, buffer[2], buffer[2]);
      twofish_setkey (&ctx, buffer[1], sizeof (buffer[1]));
      for (j = 0; j < 1000; j++)
        twofish_encrypt (&ctx, buffer[3], buffer[3]);
      twofish_setkey (&ctx, buffer[2], sizeof (buffer[2])*2);
      for (j = 0; j < 1000; j++) {
        twofish_encrypt (&ctx, buffer[0], buffer[0]);
        twofish_encrypt (&ctx, buffer[1], buffer[1]);
      }
   }
   encrypt_msg = memcmp (buffer, test_encrypt, sizeof (test_encrypt)) ?
                 "encryption failure!\n" : "encryption OK!\n";

   /* Decryption test. */
   for (i = 0; i < 125; i++) {
      twofish_setkey (&ctx, buffer[2], sizeof (buffer[2])*2);
      for (j = 0; j < 1000; j++) {
        twofish_decrypt (&ctx, buffer[0], buffer[0]);
        twofish_decrypt (&ctx, buffer[1], buffer[1]);
      }
      twofish_setkey (&ctx, buffer[1], sizeof (buffer[1]));
      for (j = 0; j < 1000; j++)
        twofish_decrypt (&ctx, buffer[3], buffer[3]);
      twofish_setkey (&ctx, buffer[0], sizeof (buffer[0]));
      for (j = 0; j < 1000; j++)
        twofish_decrypt (&ctx, buffer[2], buffer[2]);
   }

   /* Stop the timer, and print results. */
   timer = clock () - timer;
   printf (encrypt_msg);
   printf (memcmp (buffer, test_decrypt, sizeof (test_decrypt)) ?
           "decryption failure!\n" : "decryption OK!\n");
   printf ("elapsed time: %.1f s.\n", (float) timer / CLOCKS_PER_SEC);

   return 0;
}

#endif /* TEST */

/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

void twofish_setkey2(void *priv, void const *key)
{
    twofish_setkey(priv, key, 32);
}
void twofish_encrypt2(void *priv, void const *in, void *out)
{
    twofish_encrypt(priv, out, in);
}
void twofish_decrypt2(void *priv, void const *in, void *out)
{
    twofish_decrypt(priv, out, in);
}

/*
 * Do one 128-bit step of a Tandem Davies-Meyer hash computation.
 * The hash buffer is 64 bytes long and contains H (0..15), then G (16..31),
 * then 32 bytes of scratch space.  The buf is 16 bytes long.
 * xkey is a temporary key schedule buffer.
 * This and the extra data in the hash buffer are allocated by the
 * caller to reduce the amount of buffer-wiping we have to do.
 * (It's only called from twofish_wash2, so the interface can be a bit
 * specialized.)
 */
static void
twofishStepTandemDM(PGPByte *hash, PGPByte const *buf, TWOFISH_context *xkey)
{
	int i;

	/* key1 = G << 128 + M, remembering that ?? is big-endian */
	/* it should not matter if the algo is big-endian or not as
	   the byte order of the key material doesnt influence
	   the security of the hash function */
	memcpy(hash+32, buf, 16);
	twofish_setkey(xkey, hash+16, 32);
	/* W = E_key1(H), key2 = M << 128 + W */
	twofish_encrypt(xkey, hash+48, hash);
	twofish_setkey(xkey, hash+32, 32);
	/* V = E_key2(G) */
	twofish_encrypt(xkey, hash+32, hash+16);
	/* H ^= W, G ^= V */
	for (i = 0; i < 16; i++) {
		hash[i] ^= hash[i+48];
		hash[i+16] ^= hash[i+32];
	}
}

/*
 * Munge the key of the CipherContext based on the supplied bytes.
 * This is for random-number generation, so the exact technique is
 * unimportant, but it happens to use the current key as the
 * IV for computing a tandem Davies-Meyer hash of the bytes,
 * and uses the output as the new key.
 */
static void
twofish_wash2(void *priv, void const *bufIn, PGPSize len)
{
	PGPSize i;
	PGPByte hash[64];
	TWOFISH_context *xkey = (TWOFISH_context *)priv;
	PGPByte		*buf = (PGPByte *) bufIn;
	
	/* Read out the key-dependant S-Box data in canonical byte order for the IV */
	/* Im not sure if this is the best solution; probably better would be
	   if we had the original (unexpanded) key data.
	   One could also combine the subkeys to, again, form one 256 bit IV */
	for (i = 0; i < 16; i++) {
		hash[2*i] = (PGPByte)(xkey->s[0][i]>>8);
		hash[2*i+1] = (PGPByte)xkey->s[0][i];
	}

	/* Do the initial blocks of the hash */
	i = len;
	while (i >= 16) {
		twofishStepTandemDM(hash, buf, xkey);
		buf += 16;
		i -= 16;
	}
	/*
	 * At the end, we do Damgard-Merkle strengthening, just like
	 * MD5 or SHA.  Pad with 0x80 then 0 bytes to 14 mod 16, then
	 * add the length.  We use a 16-bit length in bytes instead
	 * of a 64-bit length in bits, but that is cryptographically
	 * irrelevant.
	 */
	/* Do the first partial block - i <= 15 */
	memcpy(hash+48, buf, i);
	hash[48 + i++] = 0x80;
	if (i > 14) {
		pgpClearMemory(hash+48+i, 16-i);
		twofishStepTandemDM(hash, hash+48, xkey);
		i = 0;
	}
	pgpClearMemory(hash+48+i, 14-i);
	hash[62] = (PGPByte)(len >> 8);
	hash[63] = (PGPByte)len;
	twofishStepTandemDM(hash, hash+48, xkey);

	/* Re-schedule the key */
	twofish_setkey(xkey, hash, 32);

	pgpClearMemory( hash,  sizeof(hash));
}

/*
 * Define a Cipher for the generic cipher.  This is the only
 * real exported thing -- everything else can be static, since everything
 * is referenced through function pointers!
 */
PGPCipherVTBL const cipherTwofish256 = {
	"Twofish",
	kPGPCipherAlgorithm_Twofish256,
	16,			/* Blocksize */
	32,			/* Keysize */
	sizeof(TWOFISH_context),
	alignof(PGPUInt32),
	twofish_setkey2,
	twofish_encrypt2,
	twofish_decrypt2,
	twofish_wash2
};
//END TWOFISH CIPHER SUPPORT