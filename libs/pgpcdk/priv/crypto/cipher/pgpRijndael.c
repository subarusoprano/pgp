//BEGIN AES CIPHER SUPPORT - Disastry
//This file was provided by Disastry

/**
 * rijndael-alg-fst.c	v3.0	October '2000
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be> 
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is placed in the public domain.
 */
#include <assert.h>

#include "pgpSymmetricCipherPriv.h"
#include "pgpUsuals.h"
#include "pgpMem.h"
#include "pgpRijndael.h"
#include "pgpRijndaelBox.h"


static const PGPUInt32 rcon[] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1B000000, 0x36000000, 0x6C000000, 0xD8000000,
};

#define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)

#ifdef _MSC_VER
#define GETU32(p) SWAP(*((PGPUInt32 *)(p)))
#define PUTU32(ct, st) { *((PGPUInt32 *)(ct)) = SWAP((st)); }
#else
#define GETU32(pt) (((PGPUInt32)(pt)[0] << 24) ^ ((PGPUInt32)(pt)[1] << 16) ^ ((PGPUInt32)(pt)[2] <<  8) ^ ((PGPUInt32)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (PGPUInt8)((st) >> 24); (ct)[1] = (PGPUInt8)((st) >> 16); (ct)[2] = (PGPUInt8)((st) >>  8); (ct)[3] = (PGPUInt8)(st); }
#endif

/**
 * Expand the cipher key into the encryption key schedule.
 *
 * @return	the number of rounds for the given cipher key size.
 */
int rijndaelKeySetupEnc(PGPUInt32 rk[/*4*(Nr + 1)*/], const PGPUInt8 cipherKey[], int keyBits) {
	int i = 0;
	PGPUInt32 temp;

	rk[0] = GETU32(cipherKey     );
	rk[1] = GETU32(cipherKey +  4);
	rk[2] = GETU32(cipherKey +  8);
	rk[3] = GETU32(cipherKey + 12);
	if (keyBits == 128) {
		for (;;) {
			temp  = rk[3];
			rk[4] = rk[0] ^
				(Te4[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
				(Te4[(temp      ) & 0xff] & 0x0000ff00) ^
				(Te4[(temp >> 24)       ] & 0x000000ff) ^
				rcon[i];
			rk[5] = rk[1] ^ rk[4];
			rk[6] = rk[2] ^ rk[5];
			rk[7] = rk[3] ^ rk[6];

			if (++i == 10) { /* (Nk*i == 4*Nr) */
				break;
			}

			rk += 4;
		}
		return 10;
	}
	rk[4] = GETU32(cipherKey + 16);
	rk[5] = GETU32(cipherKey + 20);
	if (keyBits == 192) {
		for (;;) {
			temp = rk[ 5];
			rk[ 6] = rk[ 0] ^
				(Te4[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
				(Te4[(temp      ) & 0xff] & 0x0000ff00) ^
				(Te4[(temp >> 24)       ] & 0x000000ff) ^
				rcon[i];
			rk[ 7] = rk[ 1] ^ rk[ 6];
			rk[ 8] = rk[ 2] ^ rk[ 7];
			rk[ 9] = rk[ 3] ^ rk[ 8];

			if (++i == 8) { /* (Nk*i == 4*Nr) */
				break;
			}

			rk[10] = rk[ 4] ^ rk[ 9];
			rk[11] = rk[ 5] ^ rk[10];

			rk += 6;
		}
		return 12;
	}
	rk[6] = GETU32(cipherKey + 24);
	rk[7] = GETU32(cipherKey + 28);
	if (keyBits == 256) {
        for (;;) {
        	temp = rk[ 7];
        	rk[ 8] = rk[ 0] ^
        		(Te4[(temp >> 16) & 0xff] & 0xff000000) ^
        		(Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
        		(Te4[(temp      ) & 0xff] & 0x0000ff00) ^
        		(Te4[(temp >> 24)       ] & 0x000000ff) ^
        		rcon[i];
        	rk[ 9] = rk[ 1] ^ rk[ 8];
        	rk[10] = rk[ 2] ^ rk[ 9];
        	rk[11] = rk[ 3] ^ rk[10];

			if (++i == 7) { /* (Nk*i == 4*Nr) */
				break;
			}

        	temp = rk[11];
        	rk[12] = rk[ 4] ^
        		(Te4[(temp >> 24)       ] & 0xff000000) ^
        		(Te4[(temp >> 16) & 0xff] & 0x00ff0000) ^
        		(Te4[(temp >>  8) & 0xff] & 0x0000ff00) ^
        		(Te4[(temp      ) & 0xff] & 0x000000ff);
        	rk[13] = rk[ 5] ^ rk[12];
        	rk[14] = rk[ 6] ^ rk[13];
        	rk[15] = rk[ 7] ^ rk[14];

			rk += 8;
        }
		return 14;
	}
	return 0;
}

/**
 * Expand the cipher key into the decryption key schedule.
 *
 * @return	the number of rounds for the given cipher key size.
 */

int rijndaelMakeDecKey(PGPUInt32 rk[/*4*(Nr + 1)*/], int Nr);

int rijndaelKeySetupDec(PGPUInt32 rk[/*4*(Nr + 1)*/], const PGPUInt8 cipherKey[], int keyBits) {
	int Nr;

	/* expand the cipher key: */
	Nr = rijndaelKeySetupEnc(rk, cipherKey, keyBits);
    return rijndaelMakeDecKey(rk, Nr);
}

int rijndaelMakeDecKey(PGPUInt32 rk[/*4*(Nr + 1)*/], int Nr)
{
	int i, j;
	PGPUInt32 temp;
	PGPUInt32 *bk;

	bk = &rk[4*Nr];
	/* invert the order of the round keys: */
	temp = rk[0]; rk[0] = bk[0]; bk[0] = temp;
	temp = rk[1]; rk[1] = bk[1]; bk[1] = temp;
	temp = rk[2]; rk[2] = bk[2]; bk[2] = temp;
	temp = rk[3]; rk[3] = bk[3]; bk[3] = temp;
	for (i = 4, j = 4*(Nr - 1); i < j; i += 4, j -= 4) {
		temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
		temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
		temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
		temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
	}
	/* apply the inverse MixColumn transform to all round keys but the first and the last: */
	for (i = 1; i < Nr; i++) {
		rk += 4;
		rk[0] =
			Td0[Te4[(rk[0] >> 24)       ] & 0xff] ^
			Td1[Te4[(rk[0] >> 16) & 0xff] & 0xff] ^
			Td2[Te4[(rk[0] >>  8) & 0xff] & 0xff] ^
			Td3[Te4[(rk[0]      ) & 0xff] & 0xff];
		rk[1] =
			Td0[Te4[(rk[1] >> 24)       ] & 0xff] ^
			Td1[Te4[(rk[1] >> 16) & 0xff] & 0xff] ^
			Td2[Te4[(rk[1] >>  8) & 0xff] & 0xff] ^
			Td3[Te4[(rk[1]      ) & 0xff] & 0xff];
		rk[2] =
			Td0[Te4[(rk[2] >> 24)       ] & 0xff] ^
			Td1[Te4[(rk[2] >> 16) & 0xff] & 0xff] ^
			Td2[Te4[(rk[2] >>  8) & 0xff] & 0xff] ^
			Td3[Te4[(rk[2]      ) & 0xff] & 0xff];
		rk[3] =
			Td0[Te4[(rk[3] >> 24)       ] & 0xff] ^
			Td1[Te4[(rk[3] >> 16) & 0xff] & 0xff] ^
			Td2[Te4[(rk[3] >>  8) & 0xff] & 0xff] ^
			Td3[Te4[(rk[3]      ) & 0xff] & 0xff];
	}
	return Nr;
}

void rijndaelEncrypt(const PGPUInt32 rk[/*4*(Nr + 1)*/], int Nr, const PGPUInt8 pt[16], PGPUInt8 ct[16]) {
	int r;
	PGPUInt32 s0, s1, s2, s3, t0, t1, t2, t3;

    /*
	 * map byte array block to cipher state
	 * and add initial round key:
	 */
	s0 = GETU32(pt     ) ^ rk[0];
	s1 = GETU32(pt +  4) ^ rk[1];
	s2 = GETU32(pt +  8) ^ rk[2];
	s3 = GETU32(pt + 12) ^ rk[3];

    rk += 4;

    /*
	 * Nr - 1 full rounds:
	 */
	r = Nr >> 1;
    for (;;) {
		t0 =
			Te0[(s0 >> 24)       ] ^
			Te1[(s1 >> 16) & 0xff] ^
			Te2[(s2 >>  8) & 0xff] ^
			Te3[(s3      ) & 0xff] ^
			rk[0];
		t1 =
			Te0[(s1 >> 24)       ] ^
			Te1[(s2 >> 16) & 0xff] ^
			Te2[(s3 >>  8) & 0xff] ^
			Te3[(s0      ) & 0xff] ^
			rk[1];
		t2 =
			Te0[(s2 >> 24)       ] ^
			Te1[(s3 >> 16) & 0xff] ^
			Te2[(s0 >>  8) & 0xff] ^
			Te3[(s1      ) & 0xff] ^
			rk[2];
		t3 =
			Te0[(s3 >> 24)       ] ^
			Te1[(s0 >> 16) & 0xff] ^
			Te2[(s1 >>  8) & 0xff] ^
			Te3[(s2      ) & 0xff] ^
			rk[3];

		if (--r == 0) {
			break;
		}

		s0 =
			Te0[(t0 >> 24)       ] ^
			Te1[(t1 >> 16) & 0xff] ^
			Te2[(t2 >>  8) & 0xff] ^
			Te3[(t3      ) & 0xff] ^
			rk[4];
		s1 =
			Te0[(t1 >> 24)       ] ^
			Te1[(t2 >> 16) & 0xff] ^
			Te2[(t3 >>  8) & 0xff] ^
			Te3[(t0      ) & 0xff] ^
			rk[5];
		s2 =
			Te0[(t2 >> 24)       ] ^
			Te1[(t3 >> 16) & 0xff] ^
			Te2[(t0 >>  8) & 0xff] ^
			Te3[(t1      ) & 0xff] ^
			rk[6];
		s3 =
			Te0[(t3 >> 24)       ] ^
			Te1[(t0 >> 16) & 0xff] ^
			Te2[(t1 >>  8) & 0xff] ^
			Te3[(t2      ) & 0xff] ^
			rk[7];

		rk += 8;
    }

    /*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
	s0 =
		(Te4[(t0 >> 24)       ] & 0xff000000) ^
		(Te4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
		(Te4[(t2 >>  8) & 0xff] & 0x0000ff00) ^
		(Te4[(t3      ) & 0xff] & 0x000000ff) ^
		rk[4];
	PUTU32(ct     , s0);
	s1 =
		(Te4[(t1 >> 24)       ] & 0xff000000) ^
		(Te4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
		(Te4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
		(Te4[(t0      ) & 0xff] & 0x000000ff) ^
		rk[5];
	PUTU32(ct +  4, s1);
	s2 =
		(Te4[(t2 >> 24)       ] & 0xff000000) ^
		(Te4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
		(Te4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
		(Te4[(t1      ) & 0xff] & 0x000000ff) ^
		rk[6];
	PUTU32(ct +  8, s2);
	s3 =
		(Te4[(t3 >> 24)       ] & 0xff000000) ^
		(Te4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
		(Te4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
		(Te4[(t2      ) & 0xff] & 0x000000ff) ^
		rk[7];
	PUTU32(ct + 12, s3);
}

void rijndaelDecrypt(const PGPUInt32 rk[/*4*(Nr + 1)*/], int Nr, const PGPUInt8 ct[16], PGPUInt8 pt[16]) {
	int r;
	PGPUInt32 s0, s1, s2, s3, t0, t1, t2, t3;

    /*
	 * map byte array block to cipher state
	 * and add initial round key:
	 */
	s0 = GETU32(ct     ) ^ rk[0];
	s1 = GETU32(ct +  4) ^ rk[1];
	s2 = GETU32(ct +  8) ^ rk[2];
	s3 = GETU32(ct + 12) ^ rk[3];

    rk += 4;

    /*
	 * Nr - 1 full rounds:
	 */
	r = Nr >> 1;
    for (;;) {
		t0 =
			Td0[(s0 >> 24)       ] ^
			Td1[(s3 >> 16) & 0xff] ^
			Td2[(s2 >>  8) & 0xff] ^
			Td3[(s1      ) & 0xff] ^
			rk[0];
		t1 =
			Td0[(s1 >> 24)       ] ^
			Td1[(s0 >> 16) & 0xff] ^
			Td2[(s3 >>  8) & 0xff] ^
			Td3[(s2      ) & 0xff] ^
			rk[1];
		t2 =
			Td0[(s2 >> 24)       ] ^
			Td1[(s1 >> 16) & 0xff] ^
			Td2[(s0 >>  8) & 0xff] ^
			Td3[(s3      ) & 0xff] ^
			rk[2];
		t3 =
			Td0[(s3 >> 24)       ] ^
			Td1[(s2 >> 16) & 0xff] ^
			Td2[(s1 >>  8) & 0xff] ^
			Td3[(s0      ) & 0xff] ^
			rk[3];

		if (--r == 0) {
			break;
		}

		s0 =
			Td0[(t0 >> 24)       ] ^
			Td1[(t3 >> 16) & 0xff] ^
			Td2[(t2 >>  8) & 0xff] ^
			Td3[(t1      ) & 0xff] ^
			rk[4];
		s1 =
			Td0[(t1 >> 24)       ] ^
			Td1[(t0 >> 16) & 0xff] ^
			Td2[(t3 >>  8) & 0xff] ^
			Td3[(t2      ) & 0xff] ^
			rk[5];
		s2 =
			Td0[(t2 >> 24)       ] ^
			Td1[(t1 >> 16) & 0xff] ^
			Td2[(t0 >>  8) & 0xff] ^
			Td3[(t3      ) & 0xff] ^
			rk[6];
		s3 =
			Td0[(t3 >> 24)       ] ^
			Td1[(t2 >> 16) & 0xff] ^
			Td2[(t1 >>  8) & 0xff] ^
			Td3[(t0      ) & 0xff] ^
			rk[7];
		
		rk += 8;
    }

    /*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
   	s0 =
   		(Td4[(t0 >> 24)       ] & 0xff000000) ^
   		(Td4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
   		(Td4[(t2 >>  8) & 0xff] & 0x0000ff00) ^
   		(Td4[(t1      ) & 0xff] & 0x000000ff) ^
   		rk[4];
	PUTU32(pt     , s0);
   	s1 =
   		(Td4[(t1 >> 24)       ] & 0xff000000) ^
   		(Td4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
   		(Td4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
   		(Td4[(t2      ) & 0xff] & 0x000000ff) ^
   		rk[5];
	PUTU32(pt +  4, s1);
   	s2 =
   		(Td4[(t2 >> 24)       ] & 0xff000000) ^
   		(Td4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
   		(Td4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
   		(Td4[(t3      ) & 0xff] & 0x000000ff) ^
   		rk[6];
	PUTU32(pt +  8, s2);
   	s3 =
   		(Td4[(t3 >> 24)       ] & 0xff000000) ^
   		(Td4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
   		(Td4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
   		(Td4[(t0      ) & 0xff] & 0x000000ff) ^
   		rk[7];
	PUTU32(pt + 12, s3);
}

#ifdef INTERMEDIATE_VALUE_KAT

void rijndaelEncryptRound(const PGPUInt32 rk[/*4*(Nr + 1)*/], int Nr, PGPUInt8 block[16], int rounds) {
	int r, i = 0;
	PGPUInt32 s0, s1, s2, s3, t0, t1, t2, t3;

    /*
	 * map byte array block to cipher state
	 * and add initial round key:
	 */
	s0 = GETU32(block     ) ^ rk[0];
	s1 = GETU32(block +  4) ^ rk[1];
	s2 = GETU32(block +  8) ^ rk[2];
	s3 = GETU32(block + 12) ^ rk[3];

    rk += 4;

    /*
	 * Nr - 1 full rounds:
	 */
	r = Nr >> 1;
    for (;;) {
		t0 =
			Te0[(s0 >> 24)       ] ^
			Te1[(s1 >> 16) & 0xff] ^
			Te2[(s2 >>  8) & 0xff] ^
			Te3[(s3      ) & 0xff] ^
			rk[0];
		t1 =
			Te0[(s1 >> 24)       ] ^
			Te1[(s2 >> 16) & 0xff] ^
			Te2[(s3 >>  8) & 0xff] ^
			Te3[(s0      ) & 0xff] ^
			rk[1];
		t2 =
			Te0[(s2 >> 24)       ] ^
			Te1[(s3 >> 16) & 0xff] ^
			Te2[(s0 >>  8) & 0xff] ^
			Te3[(s1      ) & 0xff] ^
			rk[2];
		t3 =
			Te0[(s3 >> 24)       ] ^
			Te1[(s0 >> 16) & 0xff] ^
			Te2[(s1 >>  8) & 0xff] ^
			Te3[(s2      ) & 0xff] ^
			rk[3];

		if (++i == rounds) {
			break;
		}

		if (--r == 0) {
			break;
		}

		s0 =
			Te0[(t0 >> 24)       ] ^
			Te1[(t1 >> 16) & 0xff] ^
			Te2[(t2 >>  8) & 0xff] ^
			Te3[(t3      ) & 0xff] ^
			rk[4];
		s1 =
			Te0[(t1 >> 24)       ] ^
			Te1[(t2 >> 16) & 0xff] ^
			Te2[(t3 >>  8) & 0xff] ^
			Te3[(t0      ) & 0xff] ^
			rk[5];
		s2 =
			Te0[(t2 >> 24)       ] ^
			Te1[(t3 >> 16) & 0xff] ^
			Te2[(t0 >>  8) & 0xff] ^
			Te3[(t1      ) & 0xff] ^
			rk[6];
		s3 =
			Te0[(t3 >> 24)       ] ^
			Te1[(t0 >> 16) & 0xff] ^
			Te2[(t1 >>  8) & 0xff] ^
			Te3[(t2      ) & 0xff] ^
			rk[7];

		rk += 8;

		if (++i == rounds) {
			t0 = s0;
			t1 = s1;
			t2 = s2;
			t3 = s3;
			break;
		}

    }

    /*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
	if (rounds == Nr) {
    	s0 =
    		(Te4[(t0 >> 24)       ] & 0xff000000) ^
    		(Te4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
    		(Te4[(t2 >>  8) & 0xff] & 0x0000ff00) ^
    		(Te4[(t3      ) & 0xff] & 0x000000ff) ^
    		rk[4];
    	s1 =
    		(Te4[(t1 >> 24)       ] & 0xff000000) ^
    		(Te4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
    		(Te4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
    		(Te4[(t0      ) & 0xff] & 0x000000ff) ^
    		rk[5];
    	s2 =
    		(Te4[(t2 >> 24)       ] & 0xff000000) ^
    		(Te4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
    		(Te4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
    		(Te4[(t1      ) & 0xff] & 0x000000ff) ^
    		rk[6];
    	s3 =
    		(Te4[(t3 >> 24)       ] & 0xff000000) ^
    		(Te4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
    		(Te4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
    		(Te4[(t2      ) & 0xff] & 0x000000ff) ^
    		rk[7];
	} else {
		s0 = t0;
		s1 = t1;
		s2 = t2;
		s3 = t3;
	}

	PUTU32(block     , s0);
	PUTU32(block +  4, s1);
	PUTU32(block +  8, s2);
	PUTU32(block + 12, s3);
}

void rijndaelDecryptRound(const PGPUInt32 rk[/*4*(Nr + 1)*/], int Nr, PGPUInt8 block[16], int rounds) {
	int r, i = 0;
	PGPUInt32 s0, s1, s2, s3, t0, t1, t2, t3;

    /*
	 * map byte array block to cipher state
	 * and add initial round key:
	 */
	s0 = GETU32(block     ) ^ rk[0];
	s1 = GETU32(block +  4) ^ rk[1];
	s2 = GETU32(block +  8) ^ rk[2];
	s3 = GETU32(block + 12) ^ rk[3];

    rk += 4;

    /*
	 * Nr - 1 full rounds:
	 */
	r = Nr >> 1;
    for (;;) {
		t0 =
			Td0[(s0 >> 24)       ] ^
			Td1[(s3 >> 16) & 0xff] ^
			Td2[(s2 >>  8) & 0xff] ^
			Td3[(s1      ) & 0xff] ^
			rk[0];
		t1 =
			Td0[(s1 >> 24)       ] ^
			Td1[(s0 >> 16) & 0xff] ^
			Td2[(s3 >>  8) & 0xff] ^
			Td3[(s2      ) & 0xff] ^
			rk[1];
		t2 =
			Td0[(s2 >> 24)       ] ^
			Td1[(s1 >> 16) & 0xff] ^
			Td2[(s0 >>  8) & 0xff] ^
			Td3[(s3      ) & 0xff] ^
			rk[2];
		t3 =
			Td0[(s3 >> 24)       ] ^
			Td1[(s2 >> 16) & 0xff] ^
			Td2[(s1 >>  8) & 0xff] ^
			Td3[(s0      ) & 0xff] ^
			rk[3];

		if (++i == rounds) {
			break;
		}

		if (--r == 0) {
			break;
		}

		s0 =
			Td0[(t0 >> 24)       ] ^
			Td1[(t3 >> 16) & 0xff] ^
			Td2[(t2 >>  8) & 0xff] ^
			Td3[(t1      ) & 0xff] ^
			rk[4];
		s1 =
			Td0[(t1 >> 24)       ] ^
			Td1[(t0 >> 16) & 0xff] ^
			Td2[(t3 >>  8) & 0xff] ^
			Td3[(t2      ) & 0xff] ^
			rk[5];
		s2 =
			Td0[(t2 >> 24)       ] ^
			Td1[(t1 >> 16) & 0xff] ^
			Td2[(t0 >>  8) & 0xff] ^
			Td3[(t3      ) & 0xff] ^
			rk[6];
		s3 =
			Td0[(t3 >> 24)       ] ^
			Td1[(t2 >> 16) & 0xff] ^
			Td2[(t1 >>  8) & 0xff] ^
			Td3[(t0      ) & 0xff] ^
			rk[7];
		
		rk += 8;

		if (++i == rounds) {
			t0 = s0;
			t1 = s1;
			t2 = s2;
			t3 = s3;
			break;
		}

    }

    /*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
	if (rounds == Nr) {
    	s0 =
    		(Td4[(t0 >> 24)       ] & 0xff000000) ^
    		(Td4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
    		(Td4[(t2 >>  8) & 0xff] & 0x0000ff00) ^
    		(Td4[(t1      ) & 0xff] & 0x000000ff) ^
    		rk[4];
    	s1 =
    		(Td4[(t1 >> 24)       ] & 0xff000000) ^
    		(Td4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
    		(Td4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
    		(Td4[(t2      ) & 0xff] & 0x000000ff) ^
    		rk[5];
    	s2 =
    		(Td4[(t2 >> 24)       ] & 0xff000000) ^
    		(Td4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
    		(Td4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
    		(Td4[(t3      ) & 0xff] & 0x000000ff) ^
    		rk[6];
    	s3 =
    		(Td4[(t3 >> 24)       ] & 0xff000000) ^
    		(Td4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
    		(Td4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
    		(Td4[(t0      ) & 0xff] & 0x000000ff) ^
    		rk[7];
	} else {
		s0 = t0;
		s1 = t1;
		s2 = t2;
		s3 = t3;
	}

	PUTU32(block     , s0);
	PUTU32(block +  4, s1);
	PUTU32(block +  8, s2);
	PUTU32(block + 12, s3);
}

#endif /* INTERMEDIATE_VALUE_KAT */


/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/
/*--------------------------------------------------------------------*/

#define RKSIZE128 (sizeof(PGPUInt32) * 4 * (10 + 1))
#define RKSIZE192 (sizeof(PGPUInt32) * 4 * (12 + 1))
#define RKSIZE256 (sizeof(PGPUInt32) * 4 * (14 + 1))
typedef struct {
   PGPUInt32 Rk;
   PGPUInt32 enc[RKSIZE256];
   PGPUInt32 dec[RKSIZE256]; /* is decrypt ever used ? */
} Rctx;

void AESXXXKey(Rctx *ctx, void const *key, int keyBits)
{
    ctx->Rk = rijndaelKeySetupEnc(ctx->enc, key, keyBits);
    /* at this point we dont know if we are encrypting or decrypting */
    /* so make also decryption key. */
    /* but... is decrypt ever used ?  well, set up it anyway */
    memcpy(ctx->dec, ctx->enc, RKSIZE256);
    rijndaelMakeDecKey(ctx->dec, ctx->Rk);
}
void AES128Key(void *priv, void const *key)
{
    AESXXXKey((Rctx *)priv, key, 128);
}
void AES192Key(void *priv, void const *key)
{
    AESXXXKey((Rctx *)priv, key, 192);
}
void AES256Key(void *priv, void const *key)
{
    AESXXXKey((Rctx *)priv, key, 256);
}

void AESEncrypt(void *priv, void const *in, void *out)
{
    Rctx *ctx = (Rctx *)priv;
    rijndaelEncrypt(ctx->enc, ctx->Rk, in, out);
}

void AESDecrypt(void *priv, void const *in, void *out)
{   /* is decrypt ever used ? */
    Rctx *ctx = (Rctx *)priv;
    rijndaelDecrypt(ctx->dec, ctx->Rk, in, out);
}

/*
 * Do one 128-bit step of a Tandem Davies-Meyer hash computation.
 * The hash buffer is 64 bytes long and contains H (0..15), then G (16..31),
 * then 32 bytes of scratch space.  The buf is 16 bytes long.
 * xkey is a temporary key schedule buffer.
 * This and the extra data in the hash buffer are allocated by the
 * caller to reduce the amount of buffer-wiping we have to do.
 * (It's only called from AESWash2, so the interface can be a bit
 * specialized.)
 */
static void
AESStepTandemDM(PGPByte *hash, PGPByte const *buf, Rctx *xkey)
{
	int i;

	/* key1 = G << 128 + M, remembering that ?? is big-endian */
	/* it should not matter if the algo is big-endian or not as
	   the byte order of the key material doesnt influence
	   the security of the hash function */
	memcpy(hash+32, buf, 16);
	AESXXXKey(xkey, hash+16, 256);
	/* W = E_key1(H), key2 = M << 128 + W */
	AESEncrypt(xkey, hash, hash+48);
	AESXXXKey(xkey, hash+32, 256);
	/* V = E_key2(G) */
	AESEncrypt(xkey, hash+16, hash+32);
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
AESWash2(void *priv, void const *bufIn, PGPSize len, int keyBits)
{
	PGPSize i;
	PGPByte hash[64];
	Rctx		*xkey = (Rctx *)priv;
	PGPByte		*buf = (PGPByte *) bufIn;
	
	/* Read out the key in canonical byte order for the IV */
	for (i = 0; i < 16; i++) {
		hash[2*i] = (PGPByte)(xkey->enc[i]>>8);
		hash[2*i+1] = (PGPByte)xkey->enc[i];
	}

	/* Do the initial blocks of the hash */
	i = len;
	while (i >= 16) {
		AESStepTandemDM(hash, buf, xkey);
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
		AESStepTandemDM(hash, hash+48, xkey);
		i = 0;
	}
	pgpClearMemory(hash+48+i, 14-i);
	hash[62] = (PGPByte)(len >> 8);
	hash[63] = (PGPByte)len;
	AESStepTandemDM(hash, hash+48, xkey);

	/* Re-schedule the key */
	AESXXXKey(xkey, hash, keyBits);

	pgpClearMemory( hash,  sizeof(hash));
}

static void AES128Wash(void *priv, void const *bufIn, PGPSize len)
{
    AESWash2(priv, bufIn, len, 128);
}
static void AES192Wash(void *priv, void const *bufIn, PGPSize len)
{
    AESWash2(priv, bufIn, len, 192);
}
static void AES256Wash(void *priv, void const *bufIn, PGPSize len)
{
    AESWash2(priv, bufIn, len, 256);
}

/*
 * Define a Cipher for the generic cipher.  This is the only
 * real exported thing -- everything else can be static, since everything
 * is referenced through function pointers!
 */
PGPCipherVTBL const cipherAES128 = {
	"AES128",
	kPGPCipherAlgorithm_AES128,
	16,			/* Blocksize */
	16,			/* Keysize */
	sizeof(Rctx),
	alignof(PGPUInt32),
	AES128Key,
	AESEncrypt,
	AESDecrypt,
	AES128Wash
};

PGPCipherVTBL const cipherAES192 = {
	"AES192",
	kPGPCipherAlgorithm_AES192,
	16,			/* Blocksize */
	24,			/* Keysize */
	sizeof(Rctx),
	alignof(PGPUInt32),
	AES192Key,
	AESEncrypt,
	AESDecrypt,
	AES192Wash
};

PGPCipherVTBL const cipherAES256 = {
	"AES256",
	kPGPCipherAlgorithm_AES256,
	16,			/* Blocksize */
	32,			/* Keysize */
	sizeof(Rctx),
	alignof(PGPUInt32),
	AES256Key,
	AESEncrypt,
	AESDecrypt,
	AES256Wash
};
//END AES CIPHER SUPPORT
