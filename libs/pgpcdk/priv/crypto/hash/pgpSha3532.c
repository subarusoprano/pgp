/*
* An implementation of the SHA-384 and 512 hash function, this is endian neutral
* so should work just about anywhere.
*
* This code works much like the MD5 code provided by RSA.  You sha_init()
* a "sha_state" then sha_process() the bytes you want and sha_done() to get
* the output.
*
* Revised Code:  Complies to SHA-384 and 512 standard now.
*
* Tom St Denis, Oct 12th 2000 (SHA-256)
* bubba, Oct 16th 2000 (SHA-512)
* David Crick, Oct 16th 2000 (SHA-384)
* Disastry, Aug 30th 2001 (SHA-384 and 512, self test, converted to 32bit)
* Disastry, Jan 16th 2002 (128 bit length)
* Disastry, Apr 22th 2002 ("off-by-one" bug fixed (output was wrong for length = 111 + 128 * n , where n = 0,1,2,3,...)
* */
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(DJGPP) || defined(__CYGWIN__) || defined(MSDOS) || defined(__BORLANDC__)
typedef unsigned long UINT32;
#else
#include <basetsd.h>
#endif

typedef struct {
   UINT32 state [16], length0, length1, length2, length3, curlen;
   unsigned char buf [128];
   } sha_state512;
typedef sha_state512 sha_state384;

/* the K array */
static const UINT32 K [160] =
   {
   0xD728AE22, 0x428A2F98, 0x23EF65CD, 0x71374491, 0xEC4D3B2F, 0xB5C0FBCF, 0x8189DBBC, 0xE9B5DBA5,
   0xF348B538, 0x3956C25B, 0xB605D019, 0x59F111F1, 0xAF194F9B, 0x923F82A4, 0xDA6D8118, 0xAB1C5ED5,
   0xA3030242, 0xD807AA98, 0x45706FBE, 0x12835B01, 0x4EE4B28C, 0x243185BE, 0xD5FFB4E2, 0x550C7DC3,
   0xF27B896F, 0x72BE5D74, 0x3B1696B1, 0x80DEB1FE, 0x25C71235, 0x9BDC06A7, 0xCF692694, 0xC19BF174,
   0x9EF14AD2, 0xE49B69C1, 0x384F25E3, 0xEFBE4786, 0x8B8CD5B5, 0x0FC19DC6, 0x77AC9C65, 0x240CA1CC,
   0x592B0275, 0x2DE92C6F, 0x6EA6E483, 0x4A7484AA, 0xBD41FBD4, 0x5CB0A9DC, 0x831153B5, 0x76F988DA,
   0xEE66DFAB, 0x983E5152, 0x2DB43210, 0xA831C66D, 0x98FB213F, 0xB00327C8, 0xBEEF0EE4, 0xBF597FC7,
   0x3DA88FC2, 0xC6E00BF3, 0x930AA725, 0xD5A79147, 0xE003826F, 0x06CA6351, 0x0A0E6E70, 0x14292967,
   0x46D22FFC, 0x27B70A85, 0x5C26C926, 0x2E1B2138, 0x5AC42AED, 0x4D2C6DFC, 0x9D95B3DF, 0x53380D13,
   0x8BAF63DE, 0x650A7354, 0x3C77B2A8, 0x766A0ABB, 0x47EDAEE6, 0x81C2C92E, 0x1482353B, 0x92722C85,
   0x4CF10364, 0xA2BFE8A1, 0xBC423001, 0xA81A664B, 0xD0F89791, 0xC24B8B70, 0x0654BE30, 0xC76C51A3,
   0xD6EF5218, 0xD192E819, 0x5565A910, 0xD6990624, 0x5771202A, 0xF40E3585, 0x32BBD1B8, 0x106AA070,
   0xB8D2D0C8, 0x19A4C116, 0x5141AB53, 0x1E376C08, 0xDF8EEB99, 0x2748774C, 0xE19B48A8, 0x34B0BCB5,
   0xC5C95A63, 0x391C0CB3, 0xE3418ACB, 0x4ED8AA4A, 0x7763E373, 0x5B9CCA4F, 0xD6B2B8A3, 0x682E6FF3,
   0x5DEFB2FC, 0x748F82EE, 0x43172F60, 0x78A5636F, 0xA1F0AB72, 0x84C87814, 0x1A6439EC, 0x8CC70208,
   0x23631E28, 0x90BEFFFA, 0xDE82BDE9, 0xA4506CEB, 0xB2C67915, 0xBEF9A3F7, 0xE372532B, 0xC67178F2,
   0xEA26619C, 0xCA273ECE, 0x21C0C207, 0xD186B8C7, 0xCDE0EB1E, 0xEADA7DD6, 0xEE6ED178, 0xF57D4F7F,
   0x72176FBA, 0x06F067AA, 0xA2C898A6, 0x0A637DC5, 0xBEF90DAE, 0x113F9804, 0x131C471B, 0x1B710B35,
   0x23047D84, 0x28DB77F5, 0x40C72493, 0x32CAAB7B, 0x15C9BEBC, 0x3C9EBE0A, 0x9C100D4C, 0x431D67C4,
   0xCB3E42B6, 0x4CC5D4BE, 0xFC657E2A, 0x597F299C, 0x3AD6FAEC, 0x5FCB6FAB, 0x4A475817, 0x6C44198C,
   };

/* Various logical functions */
#define Ch(x,y,z)	((x & y) ^ (~x & z))
#define Maj(x,y,z)	((x & y) ^ (x & z) ^ (y & z))
#define S(x0, x1, n)	(((x0)>>(n)) | ((x1)<<(32-n)))
#define R(x, n)		((x)>>(n))
#define Sigma00(x0, x1)	(S(x0, x1, 28) ^ S(x1, x0, 2 ) ^ S(x1, x0, 7 ))
#define Sigma01(x0, x1)	(S(x1, x0, 28) ^ S(x0, x1, 2 ) ^ S(x0, x1, 7 ))
#define Sigma10(x0, x1)	(S(x0, x1, 14) ^ S(x0, x1, 18) ^ S(x1, x0, 9 ))
#define Sigma11(x0, x1)	(S(x1, x0, 14) ^ S(x1, x0, 18) ^ S(x0, x1, 9 ))
#define Gamma00(x0, x1)	(S(x0, x1, 1 ) ^ S(x0, x1, 8 ) ^ S(x0, x1, 7 ))
#define Gamma01(x0, x1)	(S(x1, x0, 1 ) ^ S(x1, x0, 8 ) ^ R(x1, 7 ))
#define Gamma10(x0, x1)	(S(x0, x1, 19) ^ S(x1, x0, 29) ^ S(x0, x1, 6 ))
#define Gamma11(x0, x1)	(S(x1, x0, 19) ^ S(x0, x1, 29) ^ R(x1, 6 ))

#define AddC(a, b, c)	((c)+=(((tmp=(a)+(b))<(b))?1:0),tmp)
#define AddC64(a, b, c, d, e)	(tmp1=(c), (c)+=(((tmp=(a)+(b))<(b))?1:0), \
  tmp1=(d), (d)+=(((c)<tmp1)?1:0), (e)+=(((d)<tmp1)?1:0) ,tmp)

/* compress 1024-bits */
static void sha_compress(sha_state512 *md)
   {
   UINT32 S [16], W [160], t00, t01, t10, t11;
   unsigned i;
   UINT32 tmp;
   
   /* copy state into S */
   memcpy (S, md->state, 64);
   
   /* copy the state into 1024 bits into W [0..15] */
   for (i = 0; i < 128; i+=4)
      W [(i>>2)^1] = 
             ((UINT32)md->buf [i + 0]) << 24 |
             ((UINT32)md->buf [i + 1]) << 16 |
             ((UINT32)md->buf [i + 2]) <<  8 |
             ((UINT32)md->buf [i + 3]);

   /* fill W [16..79] */
   for (i = 32; i < 160; i+=2)
      {
      W [i+1] = 0;
      W [i]   = AddC(Gamma10 (W [i - 4], W [i - 3]), W [i - 14], W [i+1]);
      W [i]   = AddC(Gamma00 (W [i - 30], W [i - 29]), W [i], W [i+1]);
      W [i]   = AddC(W [i - 32], W [i], W [i+1]);
      W [i+1]+= Gamma11 (W [i - 4] , W [i - 3]) + W [i - 13] + Gamma01 (W [i - 30], W [i - 29]) + W [i - 31];
      }
   
   /* Compress */
   for (i = 0; i < 160; i+=2)
      {
      t01 = 0;
      t00 = AddC(Sigma10 (S [8], S [9]), S[14], t01);
      t00 = AddC(Ch (S [8], S [10], S [12]), t00, t01);
      t00 = AddC(K [i], t00, t01);
      t00 = AddC(W [i], t00, t01);
      t01+= S[15] + Sigma11 (S [8], S [9]) + Ch (S [9], S [11], S [13]) + K [i+1] + W [i+1];
      t11 = 0;
      t10 = Maj (S [0], S [2], S [4]);
      t10 = AddC(Sigma00 (S [0], S [1]), t10, t11);
      t11+= Sigma01 (S [0], S [1]) + Maj (S [1], S [3], S [5]);
      S [15] = S [13]; S [14] = S [12];
      S [13] = S [11]; S [12] = S [10];
      S [11] = S [9];  S [10] = S [8];
      S [9]  = 0;
      S [8]  = AddC(S [6], t00, S [9]);
      S [9] += S [7] + t01;
      S [7]  = S [5];  S [6]  = S [4];
      S [5]  = S [3];  S [4]  = S [2];
      S [3]  = S [1];  S [2]  = S [0];
      S [0]  = AddC(t00, t10, t01);
      S [1]  = t01 + t11;
      }
   
   /* feedback */
   for (i = 0; i < 16; i+=2)
      {
      md->state[i] = AddC(md->state[i], S[i], md->state[i+1]);
      md->state[i+1] += S[i+1];
      }
   }

/* init the SHA state */
static void sha_init384(sha_state384 *md)
   {
   md->curlen = md->length0 = md->length1 = md->length2 = md->length3 = 0;
   md->state [0] = 0xc1059ed8;
   md->state [1] = 0xcbbb9d5d;
   md->state [2] = 0x367cd507;
   md->state [3] = 0x629a292a;
   md->state [4] = 0x3070dd17;
   md->state [5] = 0x9159015a;
   md->state [6] = 0xf70e5939;
   md->state [7] = 0x152fecd8;
   md->state [8] = 0xffc00b31;
   md->state [9] = 0x67332667;
   md->state [10]= 0x68581511;
   md->state [11]= 0x8eb44a87;
   md->state [12]= 0x64f98fa7;
   md->state [13]= 0xdb0c2e0d;
   md->state [14]= 0xbefa4fa4;
   md->state [15]= 0x47b5481d;
   }
static void sha_init512(sha_state512 *md)
   {
   md->curlen = md->length0 = md->length1 = md->length2 = md->length3 = 0;
   md->state [0] = 0xF3BCC908;
   md->state [1] = 0x6A09E667;
   md->state [2] = 0x84CAA73B;
   md->state [3] = 0xBB67AE85;
   md->state [4] = 0xFE94F82B;
   md->state [5] = 0x3C6EF372;
   md->state [6] = 0x5F1D36F1;
   md->state [7] = 0xA54FF53A;
   md->state [8] = 0xADE682D1;
   md->state [9] = 0x510E527F;
   md->state [10]= 0x2B3E6C1F;
   md->state [11]= 0x9B05688C;
   md->state [12]= 0xFB41BD6B;
   md->state [13]= 0x1F83D9AB;
   md->state [14]= 0x137E2179;
   md->state [15]= 0x5BE0CD19;
   }

static void sha_process512(sha_state512 *md, unsigned char *buf, unsigned len)
   {
   UINT32 tmp, tmp1;
   while (len--)
      {
      /* copy byte */
      md->buf[md->curlen++] = *buf++;
      
      /* is 128 bytes full? */
      if (md->curlen == 128)
         {
         sha_compress(md);
         md->length0 = AddC64(md->length0, 1024, md->length1, md->length2, md->length3);
         md->curlen = 0;
         }
      }
   }
static void sha_process384(sha_state384 *md, unsigned char *buf, unsigned len)
   {
   sha_process512(md, buf, len);
   }

static void sha_done_(sha_state512 *md, unsigned char *hash, unsigned hs)
   {
   unsigned i;
   UINT32 tmp, tmp1;
   
   /* increase the length of the message */
   md->length0 = AddC64(md->curlen << 3, md->length0, md->length1, md->length2, md->length3);
   
   /* append the '1' bit */
   md->buf[md->curlen++] = 0x80;
   
   /* if the length is currenlly above 112 bytes we append zeros
   * then compress.  Then we can fall back to padding zeros and length
   * encoding like normal.
   */
   if (md->curlen > 112)
      {
      for (; md->curlen < 128; )
         md->buf[md->curlen++] = 0;
      sha_compress(md);
      md->curlen = 0;
      }
   
   /* pad upto 112 bytes of zeroes */
   for (; md->curlen < 112; )
      md->buf[md->curlen++] = 0;
   
   /* append length */
   for (i = 112; i < 116; i++)
      md->buf [i] = (md->length3 >> ((115-i)<<3)) & 255;
   for (i = 116; i < 120; i++)
      md->buf [i] = (md->length2 >> ((119-i)<<3)) & 255;
   for (i = 120; i < 124; i++)
      md->buf [i] = (md->length1 >> ((123-i)<<3)) & 255;
   for (i = 124; i < 128; i++)
      md->buf [i] = (md->length0 >> ((127-i)<<3)) & 255;
   sha_compress(md);
   
   /* copy output */
   hs = (hs==384)?48:64; //hs /= 8;
   for (i = 0; i < hs; i++)
      hash[i] = md->state [(i>>2)^1] >> ((3-(i&3))<<3);
   }
static void sha_done384(sha_state384 *md, unsigned char *hash)
   {
   sha_done_(md, hash, 384);
   }
static void sha_done512(sha_state512 *md, unsigned char *hash)
   {
   sha_done_(md, hash, 512);
   }

#if 0
/* sha-512 a block of memory */
void sha_memory384(unsigned char *buf, unsigned len, unsigned char *hash)
   {
   sha_state384 md;
   
   sha_init384(&md);
   sha_process384(&md, buf, len);
   sha_done384(&md, hash);
   }
void sha_memory512(unsigned char *buf, unsigned len, unsigned char *hash)
   {
   sha_state512 md;
   
   sha_init512(&md);
   sha_process512(&md, buf, len);
   sha_done512(&md, hash);
   }

/* sha-512 a file, return 1 if ok */
static int sha_file_(char *filename, unsigned char *hash, unsigned hs)
   {
   unsigned char buf[1024];
   unsigned i;
   FILE *in;
   sha_state512 md;
   
   if (hs==384)
      sha_init384(&md);
   else
      sha_init512(&md);
   in = fopen(filename, "rb");
   if (!in) return 0;
   do {
      i = fread(buf, 1, 1024, in);
      sha_process512(&md, buf, i);
      } while (i == 1024);
   if (hs==384)
      sha_done384(&md, hash);
   else
      sha_done512(&md, hash);
   fclose(in);
   return 1;
   }
int sha_file384(char *filename, unsigned char *hash)
   {
   return sha_file_(filename, hash, 384);
   }
int sha_file512(char *filename, unsigned char *hash)
   {
   return sha_file_(filename, hash, 512);
   }
#endif


#if 0
int selftest384 (void)
{
	/* test vectors from sha256-384-512.pdf */
	static unsigned char *test1 = "abc";
	static unsigned char result1[] = {0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
					  0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
					  0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};
	static unsigned char *test2 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	static unsigned char result2[] = {0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8, 0x3d, 0x19, 0x2f, 0xc7, 0x82, 0xcd, 0x1b, 0x47,
					  0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2, 0x2f, 0xa0, 0x80, 0x86, 0xe3, 0xb0, 0xf7, 0x12,
					  0xfc, 0xc7, 0xc7, 0x1a, 0x55, 0x7e, 0x2d, 0xb9, 0x66, 0xc3, 0xe9, 0xfa, 0x91, 0x74, 0x60, 0x39};
	unsigned char hash[48];
	sha_state384 md;

	sha_init384(&md);
	sha_process384(&md, test1, 3);
	sha_done384(&md, hash);
	if (memcmp(result1, hash, 48))
		return 1;
	sha_init384(&md);
	sha_process384(&md, test2, 112);
	sha_done384(&md, hash);
	if (memcmp(result2, hash, 48))
		return 2;
	return 0;
}
int selftest512 (void)
{
	/* test vectors from sha256-384-512.pdf */
	static unsigned char *test1 = "abc";
	static unsigned char result1[] = {0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
					  0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
					  0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
					  0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};
	static unsigned char *test2 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	static unsigned char result2[] = {0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
					  0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
					  0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
					  0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09};
	unsigned char hash[64];
	sha_state512 md;

	sha_init512(&md);
	sha_process512(&md, test1, 3);
	sha_done512(&md, hash);
	if (memcmp(result1, hash, 64))
		return 1;
	sha_init512(&md);
	sha_process512(&md, test2, 112);
	sha_done512(&md, hash);
	if (memcmp(result2, hash, 64))
		return 2;
	return 0;
}

unsigned long timetest (int hs)
{
	static unsigned char *test = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	unsigned char hash[64];
	sha_state512 md;
	unsigned long t = time(0);
	long i;

	if (hs==384)
		sha_init384(&md);
	else
		sha_init512(&md);
	for (i=0; i<1000000; i++) {
		sha_process512(&md, test, 100);
		if (i%10000==0) printf(".");
	}
	if (hs==384)
		sha_done384(&md, hash);
	else
		sha_done512(&md, hash);
	return time(0) - t;
}

/* test -- DEMO */
int main(int argc, char *argv [])
   {
   int i, i2;
   unsigned char buf[64];
   time_t elapsedTime, startTime = time (0);
   
   if (i = selftest384())
      {
      printf("Selftest384 #%d failed\n", i);
      return i;
      }
   if (i = selftest512())
      {
      printf("Selftest512 #%d failed\n", i);
      return i;
      }
   if (argc==2 && argv[1][0]=='-' && argv[1][1]=='t')
      {
      printf("Wait");
      printf("\n100 000 000 bytes hashed with SHA384 in %u seconds\n", timetest(384));
      printf("Wait");
      printf("\n100 000 000 bytes hashed with SHA512 in %u seconds\n", timetest(512));
      return 0;
      }

   if (argc == 1)
      {
      printf("Usage:\n%s: file1 [file2 file3 ...]\n", argv[0]);
      printf("For timetest:\n%s: -t\n", argv[0]);
      return 0;
      }
   
   for (i2 = 1; i2 < argc; i2++)
      {
      if (sha_file384(argv[i2], buf))
         {
         printf("\n%s:SHA384:\n",argv[i2]);
         for (i = 0; i < 48; )
            {
            printf("%02x", buf[i]);
            if (!(++i & 7)) printf(" ");
            if (i == 32)
               printf("\n");
            }
         printf("\n");
         }
      else
         printf("%20s: file not found.\n", argv[i2]);
      if (sha_file512(argv[i2], buf))
         {
         printf("\n%s:SHA512:\n",argv[i2]);
         for (i = 0; i < 64; )
            {
            printf("%02x", buf[i]);
            if (!(++i & 7)) printf(" ");
            if (i == 32)
               printf("\n");
            }
         printf("\n");
         }
      else
         printf("%20s: file not found.\n", argv[i2]);
      }
      
      elapsedTime = time (0) - startTime;
      if (elapsedTime > 4) printf ("%u seconds\n", elapsedTime);
      return 0;
   }
#endif /* 0 */

//--------------------------------------------------------
//--------------------------------------------------------
//--------------------------------------------------------
#include "pgpSHA2.h"

/*
 * SHA.384 has an OID of 2.16.840.1.101.3.4.2.2
 * SHA.512 has an OID of 2.16.840.1.101.3.4.2.3
 */
PGPByte const SHA384DERprefix[] = { 
     0x30, /* Universal, Constructed, Sequence */ 
     0x41, /* Length 65 (bytes following) */ 
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
                    2, 
               0x05, /* Universal, Primitive, NULL */ 
               0x00, /* Length 0 */ 
          0x04, /* Universal, Primitive, Octet string */ 
          0x30 /* Length 48 */ 
               /* 48 SHA.384 digest bytes go here */ 
}; 
 
PGPByte const SHA512DERprefix[] = { 
     0x30, /* Universal, Constructed, Sequence */ 
     0x51, /* Length 81 (bytes following) */ 
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
                    3, 
               0x05, /* Universal, Primitive, NULL */ 
               0x00, /* Length 0 */ 
          0x04, /* Universal, Primitive, Octet string */ 
          0x40 /* Length 64 */ 
               /* 64 SHA.512 digest bytes go here */ 
}; 



static void sha384Init(void *priv)
{
	sha_init384((sha_state384 *)priv);
}
static void sha384Update(void *priv, void const *bufIn, PGPSize len)
{
    sha_process384((sha_state384 *)priv, (unsigned char *)bufIn, len);
}
static void const *sha384Final(void *priv)
{
	unsigned char hash[48];
    sha_state384 *md = (sha_state384 *)priv;
	sha_done384(md, hash);
	sha_init384(md);
    memcpy(md->buf, hash, 48);
    return md->buf;
}

static void sha512Init(void *priv)
{
	sha_init512((sha_state512 *)priv);
}
static void sha512Update(void *priv, void const *bufIn, PGPSize len)
{
    sha_process512((sha_state512 *)priv, (unsigned char *)bufIn, len);
}
static void const *sha512Final(void *priv)
{
	unsigned char hash[64];
    sha_state512 *md = (sha_state512 *)priv;
	sha_done512(md, hash);
	sha_init512(md);
    memcpy(md->buf, hash, 64);
    return md->buf;
}

PGPHashVTBL const HashSHA384 = {
	"SHA384", kPGPHashAlgorithm_SHA384,
	SHA384DERprefix, sizeof(SHA384DERprefix),
	48,
	sizeof(sha_state384),
	0,
	sha384Init, sha384Update, sha384Final
};

PGPHashVTBL const HashSHA512 = {
	"SHA512", kPGPHashAlgorithm_SHA512,
	SHA512DERprefix, sizeof(SHA512DERprefix),
	64,
	sizeof(sha_state512),
	0,
	sha512Init, sha512Update, sha512Final
};
