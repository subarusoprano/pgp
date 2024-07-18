/*
 * An implementation of the SHA-256 hash function, this is endian neutral
 * so should work just about anywhere.
 *
 * This code works much like the MD5 code provided by RSA.  You sha_init()
 * a "sha_state" then sha_process() the bytes you want and sha_done() to get
 * the output.
 *
 * Revised Code:  Complies to SHA-256 standard now.
 *
 * Tom St Denis, Oct 12th 2000
 * Disastry, Aug 30th 2001, (self test)
 * Disastry, Jan 16th 2002, (64 bit length)
 * Disastry, Apr 22th 2002 ("off-by-one" bug fixed (output was wrong for length = 55 + 64 * n , where n = 0,1,2,3,...)
 * */
#include <stdio.h>
#include <string.h>

typedef struct {
	unsigned long state[8], length0, length1, curlen;
	unsigned char buf[64];
} sha_state;

/* the K array */
static const unsigned long K[64] = {
0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,0x3956c25bUL,0x59f111f1UL,
0x923f82a4UL,0xab1c5ed5UL,0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,0xe49b69c1UL,0xefbe4786UL,
0x0fc19dc6UL,0x240ca1ccUL,0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,0xc6e00bf3UL,0xd5a79147UL,
0x06ca6351UL,0x14292967UL,0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,0xa2bfe8a1UL,0xa81a664bUL,
0xc24b8b70UL,0xc76c51a3UL,0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,0x391c0cb3UL,0x4ed8aa4aUL,
0x5b9cca4fUL,0x682e6ff3UL,0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL };

/* Various logical functions */
#define Ch(x,y,z)	((x & y) ^ (~x & z))
#define Maj(x,y,z)	((x & y) ^ (x & z) ^ (y & z))
#define S(x, n)		(((x)>>(n))|((x)<<(32-n)))
#define R(x, n)		((x)>>(n))
#define Sigma0(x)	(S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)	(S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)	(S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)	(S(x, 17) ^ S(x, 19) ^ R(x, 10))

#define AddC(a, b, c)	((c)+=(((tmp=(a)+(b))<(b))?1:0),tmp)

/* compress 512-bits */
static void sha_compress(sha_state *md)
{
	unsigned long S[8], W[64], t0;
	unsigned i;

	/* copy state into S */
	for (i = 0; i < 8; i++)
		S[i] = md->state[i];

	/* copy the state into 512-bits into W[0..15] */
	for (i = 0; i < 16; i++)
		W[i] = 	(((unsigned long)md->buf[(i<<2)+0])<<24) |
			(((unsigned long)md->buf[(i<<2)+1])<<16) |
			(((unsigned long)md->buf[(i<<2)+2])<<8) |
			(((unsigned long)md->buf[(i<<2)+3]));

	/* fill W[16..63] */
	for (i = 16; i < 64; i++)
		W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];

	/* Compress */
	for (i = 0; i < 64; i++) {
		t0 = S[7] + Sigma1(S[4]) + Ch(S[4], S[5], S[6]) + K[i] + W[i];
		S[7] = S[6];
		S[6] = S[5];
		S[5] = S[4];
		S[4] = S[3] + t0;
		S[3] = S[2];
		S[2] = S[1];
		S[1] = S[0];
		S[0] = t0 + Sigma0(S[1]) + Maj(S[1], S[2], S[3]);
	}

	/* feedback */
	for (i = 0; i < 8; i++)
		md->state[i] += S[i];
}

/* init the SHA state */
static void sha_init(sha_state *md)
{
	md->curlen = md->length0 = md->length1 = 0;
	md->state[0] = 0x6A09E667UL;
	md->state[1] = 0xBB67AE85UL;
	md->state[2] = 0x3C6EF372UL;
	md->state[3] = 0xA54FF53AUL;
	md->state[4] = 0x510E527FUL;
	md->state[5] = 0x9B05688CUL;
	md->state[6] = 0x1F83D9ABUL;
	md->state[7] = 0x5BE0CD19UL;
}

static void sha_process(sha_state *md, unsigned char *buf, unsigned len)
{
	unsigned long tmp;
	while (len--) {
		/* copy byte */
		md->buf[md->curlen++] = *buf++;

		/* is 64 bytes full? */
		if (md->curlen == 64) {
			sha_compress(md);
			md->length0 = AddC(md->length0, 512, md->length1);
			md->curlen = 0;
		}
	}
}

static void sha_done(sha_state *md, unsigned char *hash)
{
	unsigned i;
	unsigned long tmp;

	/* increase the length of the message */
	md->length0 = AddC(md->curlen << 3, md->length0, md->length1);

	/* append the '1' bit */
	md->buf[md->curlen++] = 0x80;

	/* if the length is currenlly above 56 bytes we append zeros
	 * then compress.  Then we can fall back to padding zeros and length
	 * encoding like normal.
	 */
	if (md->curlen > 56) {
		for (; md->curlen < 64; )
			md->buf[md->curlen++] = 0;
		sha_compress(md);
		md->curlen = 0;
	}

	/* pad upto 56 bytes of zeroes */
	for (; md->curlen < 56; )
		md->buf[md->curlen++] = 0;

	/* append length */
	for (i = 56; i < 60; i++)
		md->buf[i] = (unsigned char)(md->length1 >> ((59-i)<<3)) & 255;
	for (i = 60; i < 64; i++)
		md->buf[i] = (unsigned char)(md->length0 >> ((63-i)<<3)) & 255;
	sha_compress(md);

	/* copy output */
	for (i = 0; i < 32; i++)
		hash[i] = (unsigned char)(md->state[i>>2] >> (((3-i)&3)<<3)) & 255;
}

#if 0
/* sha-256 a block of memory */
void sha_memory(unsigned char *buf, unsigned len, unsigned char *hash)
{
	sha_state md;

	sha_init(&md);
	sha_process(&md, buf, len);
	sha_done(&md, hash);
}

/* sha-256 a file, return 1 if ok */
int sha_file(char *filename, unsigned char *hash)
{
	unsigned char buf[512];
	unsigned i;
	FILE *in;
	sha_state md;

	sha_init(&md);
	in = fopen(filename, "rb");
	if (!in) return 0;
	do {
		i = fread(buf, 1, 512, in);
		sha_process(&md, buf, i);
	} while (i == 512);
	sha_done(&md, hash);
	fclose(in);
	return 1;
}
#endif

#if 0
int selftest (void)
{
	/* test vectors from sha256-384-512.pdf */
	static unsigned char *test1 = "abc";
	static unsigned char result1[] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
					  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
	static unsigned char *test2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	static unsigned char result2[] = {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
					  0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1};
	unsigned char hash[32];
	sha_state md;

	sha_init(&md);
	sha_process(&md, test1, 3);
	sha_done(&md, hash);
	if (memcmp(result1, hash, 32))
		return 1;
	sha_init(&md);
	sha_process(&md, test2, 56);
	sha_done(&md, hash);
	if (memcmp(result2, hash, 32))
		return 2;
	return 0;
}

unsigned long timetest (void)
{
	static unsigned char *test = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	unsigned char hash[32];
	sha_state md;
	unsigned long t = time(0);
	long i;

	sha_init(&md);
	for (i=0; i<1000000; i++) {
		sha_process(&md, test, 100);
		if (i%10000==0) printf(".");
	}
	sha_done(&md, hash);
	return time(0) - t;
}

/* test -- DEMO */
int main(int argc, char **argv)
{
	int i, i2;
	unsigned char buf[32];

	if (i = selftest()) {
		printf("Selftest #%d failed\n", i);
		return i;
	}
	if (argc==2 && argv[1][0]=='-' && argv[1][1]=='t') {
		printf("Wait");
		printf("\n100 000 000 bytes hashed in %u seconds\n", timetest());
		return 0;
	}

	if (argc == 1) {
		printf("Usage:\n%s: file1 [file2 file3 ...]\n", argv[0]);
		printf("For timetest:\n%s: -t\n", argv[0]);
		return 0;
	}

	for (i2 = 1; i2 < argc; i2++)
		if (sha_file(argv[i2], buf)) {
			printf("%20s: ", argv[i2]);
			for (i = 0; i < 32; ) {
				printf("%02x", buf[i]);
				if (!(++i & 3)) printf(" ");
				if (i == 16)
					printf("\n%22s", "");
			}
			printf("\n");
		} else
			printf("%20s: file not found.\n", argv[i2]);

	return 0;
}
#endif /* 0 */

//--------------------------------------------------------
//--------------------------------------------------------
//--------------------------------------------------------
#include "pgpSHA2.h"

/*
 * SHA.256 has an OID of 2.16.840.1.101.3.4.2.1
 */
PGPByte const SHA256DERprefix[] = {
	0x30, /* Universal, Constructed, Sequence */
	0x31, /* Length 49 (bytes following) */
		0x30, /* Universal, Constructed, Sequence */
		0x0D, /* Length 13 */
			0x06, /* Universal, Primitive, object-identifier */
			0x09, /* Length 9 */
				96,
				134,
				72,
				1,
				101,
				3,
				4,
				2,
				1,
			0x05, /* Universal, Primitive, NULL */
			0x00, /* Length 0 */
		0x04, /* Universal, Primitive, Octet string */
		0x20 /* Length 32 */
			/* 32 SHA.256 digest bytes go here */
};

static void sha256Init(void *priv)
{
	sha_init((sha_state *)priv);
}
static void sha256Update(void *priv, void const *bufIn, PGPSize len)
{
    sha_process((sha_state *)priv, (unsigned char *)bufIn, len);
}
static void const *sha256Final(void *priv)
{
	unsigned char hash[32];
    sha_state *md = (sha_state *)priv;
	sha_done(md, hash);
	sha_init(md);
    memcpy(md->buf, hash, 32);
    return md->buf;
}

PGPHashVTBL const HashSHA256 = {
	"SHA256", kPGPHashAlgorithm_SHA256,
	SHA256DERprefix, sizeof(SHA256DERprefix),
	32,
	sizeof(sha_state),
	0,
	sha256Init, sha256Update, sha256Final
};
