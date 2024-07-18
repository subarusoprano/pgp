//BEGIN BLOWFISH CIPHER SUPPORT - Disastry
//This file was provided by Disastry
/*
 * Author     :  Paul Kocher
 * E-mail     :  pck@netcom.com
 * Date       :  1997
 * Description:  C implementation of the Blowfish algorithm.
 */


//#include <stdio.h>
#include "pgpSymmetricCipherPriv.h"
#include "pgpUsuals.h"
#include "pgpMem.h"
#include "pgpBLOWFISH.h"
#include "pgpBLOWFISHbox.h"

#define MAXKEYBYTES 56          /* 448 bits */

typedef struct {
  PGPUInt32 P[16 + 2];
  PGPUInt32 S[4][256];
} BLOWFISH_CTX;

void Blowfish_Init(BLOWFISH_CTX *ctx, PGPUInt8 *key, int keyLen);
void Blowfish_Encrypt(BLOWFISH_CTX *ctx, PGPUInt32 *xl, PGPUInt32 *xr);
void Blowfish_Decrypt(BLOWFISH_CTX *ctx, PGPUInt32 *xl, PGPUInt32 *xr);
int Blowfish_Test(BLOWFISH_CTX *ctx);       /* 0=ok, -1=bad */
void Blowfish_Encrypt1(BLOWFISH_CTX *ctx, PGPUInt8 *outbuf, PGPUInt8 *inbuf);
void Blowfish_Decrypt1(BLOWFISH_CTX *ctx, PGPUInt8 *outbuf, PGPUInt8 *inbuf);
static int selftest(void);

#define ROUNDS 16

static PGPUInt32 F(BLOWFISH_CTX *ctx, PGPUInt32 x);

PGPUInt32 F(BLOWFISH_CTX *ctx, PGPUInt32 x) {
   PGPUInt16 a, b, c, d;
   PGPUInt32  y;

   d = (PGPUInt16)x & 0x00FF;
   x >>= 8;
   c = (PGPUInt16)x & 0x00FF;
   x >>= 8;
   b = (PGPUInt16)x & 0x00FF;
   x >>= 8;
   a = (PGPUInt16)x & 0x00FF;
   y = ctx->S[0][a] + ctx->S[1][b];
   y = y ^ ctx->S[2][c];
   y = y + ctx->S[3][d];

   return y;
}


void Blowfish_Encrypt(BLOWFISH_CTX *ctx, PGPUInt32 *xl, PGPUInt32 *xr) {
  PGPUInt32  Xl;
  PGPUInt32  Xr;
  PGPUInt32  temp;
  int     i;

  Xl = *xl;
  Xr = *xr;

  for (i = 0; i < ROUNDS; ++i) {
    Xl = Xl ^ ctx->P[i];
    Xr = F(ctx, Xl) ^ Xr;

    temp = Xl;
    Xl = Xr;
    Xr = temp;
  }

  temp = Xl;
  Xl = Xr;
  Xr = temp;

  Xr = Xr ^ ctx->P[ROUNDS];
  Xl = Xl ^ ctx->P[ROUNDS + 1];

  *xl = Xl;
  *xr = Xr;
}


void Blowfish_Decrypt(BLOWFISH_CTX *ctx, PGPUInt32 *xl, PGPUInt32 *xr) {
  PGPUInt32  Xl;
  PGPUInt32  Xr;
  PGPUInt32  temp;
  int     i;

  Xl = *xl;
  Xr = *xr;

  for (i = ROUNDS + 1; i > 1; --i) {
    Xl = Xl ^ ctx->P[i];
    Xr = F(ctx, Xl) ^ Xr;

    /* Exchange Xl and Xr */
    temp = Xl;
    Xl = Xr;
    Xr = temp;
  }

  /* Exchange Xl and Xr */
  temp = Xl;
  Xl = Xr;
  Xr = temp;

  Xr = Xr ^ ctx->P[1];
  Xl = Xl ^ ctx->P[0];

  *xl = Xl;
  *xr = Xr;
}


void Blowfish_Init(BLOWFISH_CTX *ctx, PGPUInt8 *key, int keyLen) {
  int i, j, k;
  PGPUInt32 data, datal, datar;

  /*selftest();*/

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 256; j++)
      ctx->S[i][j] = ORIG_S[i][j];
  }

  j = 0;
  for (i = 0; i < ROUNDS + 2; ++i) {
    data = 0x00000000;
    for (k = 0; k < 4; ++k) {

      data <<= 8;
      data |= (PGPUInt32)key[j]&0xff;
      /*was: data = (data << 8) | key[j];
        see: http://www.counterpane.com/blowfish-bug.txt */

      j = j + 1;
      if (j >= keyLen)
        j = 0;
    }
    ctx->P[i] = ORIG_P[i] ^ data;
  }

  datal = 0x00000000;
  datar = 0x00000000;

  for (i = 0; i < ROUNDS + 2; i += 2) {
    Blowfish_Encrypt(ctx, &datal, &datar);
    ctx->P[i] = datal;
    ctx->P[i + 1] = datar;
  }

  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 256; j += 2) {
      Blowfish_Encrypt(ctx, &datal, &datar);
      ctx->S[i][j] = datal;
      ctx->S[i][j + 1] = datar;
    }
  }

  /* //test for weak keys
  for (i = 0; i < 4; i++) {
    for (j = 0; j < 256; j++) {
      int k;
      for (k = 0; k < 256; k++) {
        if (j == k)
          continue;
        if (ctx->S[i][j] == ctx->S[i][k]);
          return 0;
      }
    }
  }
  return 1;
  */
}


/*int Blowfish_Test(BLOWFISH_CTX *ctx) {
  PGPUInt32 L = 1, R = 2;
  PGPUInt8 a[8], b[8];

  Blowfish_Init (ctx, (PGPUInt8*)"TESTKEY", 7);
  Blowfish_Encrypt(ctx, &L, &R);
  if (L != 0xDF333FD2L || R != 0x30A71BB4L)
    return (-1);
  Blowfish_Decrypt(ctx, &L, &R);
  if (L != 1 || R != 2)
    return (-2);
  *(PGPUInt32 *)(a) = 0x1000000; *(PGPUInt32 *)(a+4) = 0x2000000;
  Blowfish_Encrypt1(ctx,  b, a);
  if (*(PGPUInt32 *)(b) != 0xD23F33DFL || *(PGPUInt32 *)(b+4) != 0xB41BA730L)
    return (-3);
  Blowfish_Decrypt1(ctx,  b, b);
  if (*(PGPUInt32 *)(b) != 0x1000000 || *(PGPUInt32 *)(b+4) != 0x2000000)
    return (-4);
  return (0);
}*/

/*static int selftest(void)
{
    static int initialized = 0;
    static char selftest_failed = 0;
    BLOWFISH_CTX ctx;

    if (!initialized) {
        initialized = 1;
        if (selftest_failed = Blowfish_Test(&ctx))
            fprintf(stderr,"\nBlowfish selftest failed: %d.\n", selftest_failed);
    }
    if (selftest_failed)
        return -1;
    return 0;
}*/ /* selftest */


#define byteA3(x) (PGPUInt8)(((x) >> 24)       )
#define byteB2(x) (PGPUInt8)(((x) >> 16) & 0xff)
#define byteC1(x) (PGPUInt8)(((x) >>  8) & 0xff)
#define byteD0(x) (PGPUInt8)(((x)      ) & 0xff)

#define makeword32(d0,c1,b2,a3) ( (PGPUInt32)(d0) | (PGPUInt32)(c1) << 8 | (PGPUInt32)(b2) << 16 | (PGPUInt32)(a3) << 24 )

void Blowfish_Encrypt2(void *ctx, void const *in, void *out)
{
    PGPUInt8 *inbuf, *outbuf;
    PGPUInt32 d1, d2;

    inbuf = (PGPUInt8 *)in; outbuf = out;
    d1 = makeword32(inbuf[3], inbuf[2], inbuf[1], inbuf[0]);
    d2 = makeword32(inbuf[7], inbuf[6], inbuf[5], inbuf[4]);
    Blowfish_Encrypt( ctx, &d1, &d2 );
    outbuf[0] = byteA3(d1);
    outbuf[1] = byteB2(d1);
    outbuf[2] = byteC1(d1);
    outbuf[3] = byteD0(d1);
    outbuf[4] = byteA3(d2);
    outbuf[5] = byteB2(d2);
    outbuf[6] = byteC1(d2);
    outbuf[7] = byteD0(d2);
}

void Blowfish_Decrypt2(void *ctx, void const *in, void *out)
{
    PGPUInt8 *inbuf, *outbuf;
    PGPUInt32 d1, d2;

    inbuf = (PGPUInt8 *)in; outbuf = out;
    d1 = makeword32(inbuf[3], inbuf[2], inbuf[1], inbuf[0]);
    d2 = makeword32(inbuf[7], inbuf[6], inbuf[5], inbuf[4]);
    Blowfish_Decrypt( ctx, &d1, &d2 );
    outbuf[0] = byteA3(d1);
    outbuf[1] = byteB2(d1);
    outbuf[2] = byteC1(d1);
    outbuf[3] = byteD0(d1);
    outbuf[4] = byteA3(d2);
    outbuf[5] = byteB2(d2);
    outbuf[6] = byteC1(d2);
    outbuf[7] = byteD0(d2);
}


void Blowfish_Init2(void *ctx, void const *key) {
    Blowfish_Init(ctx, (PGPUInt8 *)key, 16);
}



/*
 * Do one 64-bit step of a Tandem Davies-Meyer hash computation.
 * The hash buffer is 32 bytes long and contains H (0..7), then G (8..15),
 * then 16 bytes of scratch space.  The buf is 8 bytes long.
 * xkey is a temporary key schedule buffer.
 * This and the extra data in the hash buffer are allocated by the
 * caller to reduce the amount of buffer-wiping we have to do.
 * (It's only called from Blowfish_Wash2, so the interface can be a bit
 * specialized.)
 */
static void
BLOWFISHStepTandemDM(PGPByte *hash, PGPByte const *buf, BLOWFISH_CTX *xkey)
{
	int i;

	/* key1 = G << 64 + M, remembering that ???????? is big-endian */
	memcpy(hash+16, buf, 8);
	Blowfish_Init(xkey, hash+8, 16);
	/* W = E_key1(H), key2 = M << 64 + W */
	Blowfish_Encrypt2(xkey, hash, hash+24);
	Blowfish_Init(xkey, hash+16, 16);
	/* V = E_key2(G) */
	Blowfish_Encrypt2(xkey, hash+8, hash+16);
	/* H ^= W, G ^= V */
	for (i = 0; i < 8; i++) {
		hash[i] ^= hash[i+24];
		hash[i+8] ^= hash[i+16];
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
Blowfish_Wash2(void *priv, void const *bufIn, PGPSize len)
{
	PGPSize i;
	PGPByte hash[32];
	BLOWFISH_CTX 	*xkey = (BLOWFISH_CTX *)priv;
	PGPByte		*buf = (PGPByte *) bufIn;
	
	/* Read out the key in canonical byte order for the IV */
	for (i = 0; i < 8; i++) {
		hash[2*i] = (PGPByte)(xkey->S[0][i]>>8);
		hash[2*i+1] = (PGPByte)xkey->S[0][i];
	}

	/* Do the initial blocks of the hash */
	i = len;
	while (i >= 8) {
		BLOWFISHStepTandemDM(hash, buf, xkey);
		buf += 8;
		i -= 8;
	}
	/*
	 * At the end, we do Damgard-Merkle strengthening, just like
	 * MD5 or SHA.  Pad with 0x80 then 0 bytes to 6 mod 8, then
	 * add the length.  We use a 16-bit length in bytes instead
	 * of a 64-bit length in bits, but that is cryptographically
	 * irrelevant.
	 */
	/* Do the first partial block - i <= 7 */
	memcpy(hash+24, buf, i);
	hash[24 + i++] = 0x80;
	if (i > 6) {
		pgpClearMemory(hash+24+i, 8-i);
		BLOWFISHStepTandemDM(hash, hash+24, xkey);
		i = 0;
	}
	pgpClearMemory(hash+24+i, 6-i);
	hash[30] = (PGPByte)(len >> 8);
	hash[31] = (PGPByte)len;
	BLOWFISHStepTandemDM(hash, hash+24, xkey);

	/* Re-schedule the key */
	Blowfish_Init(xkey, hash, 16);

	pgpClearMemory( hash,  sizeof(hash));
}

/*
 * Define a Cipher for the generic cipher.  This is the only
 * real exported thing -- everything else can be static, since everything
 * is referenced through function pointers!
 */
PGPCipherVTBL const cipherBLOWFISH = {
	"BLOWFISH",
	kPGPCipherAlgorithm_BLOWFISH,
	8,			/* Blocksize */
	16,			/* Keysize */
	sizeof(BLOWFISH_CTX),
	alignof(PGPUInt32),
	Blowfish_Init2,
	Blowfish_Encrypt2,
	Blowfish_Decrypt2,
	Blowfish_Wash2
};
//END BLOWFISH CIPHER SUPPORT