//BEGIN AES CIPHER SUPPORT - Disastry
//This file was provided by Disastry


/**
 * rijndael-alg-fst.h	v3.0	October '2000
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is placed in the public domain.
 */
#ifndef __RIJNDAEL_ALG_FST_H
#define __RIJNDAEL_ALG_FST_H

#define MAXKC	(256/32)
#define MAXKB	(256/8)
#define MAXNR	14

int rijndaelKeySetupEnc(PGPUInt32 rk[/*4*(Nr + 1)*/], const PGPUInt8 cipherKey[], int keyBits);
int rijndaelKeySetupDec(PGPUInt32 rk[/*4*(Nr + 1)*/], const PGPUInt8 cipherKey[], int keyBits);
void rijndaelEncrypt(const PGPUInt32 rk[/*4*(Nr + 1)*/], int Nr, const PGPUInt8 pt[16], PGPUInt8 ct[16]);
void rijndaelDecrypt(const PGPUInt32 rk[/*4*(Nr + 1)*/], int Nr, const PGPUInt8 ct[16], PGPUInt8 pt[16]);

#ifdef INTERMEDIATE_VALUE_KAT
void rijndaelEncryptRound(const PGPUInt32 rk[/*4*(Nr + 1)*/], int Nr, PGPUInt8 block[16], int rounds);
void rijndaelDecryptRound(const PGPUInt32 rk[/*4*(Nr + 1)*/], int Nr, PGPUInt8 block[16], int rounds);
#endif /* INTERMEDIATE_VALUE_KAT */


#endif /* __RIJNDAEL_ALG_FST_H */

//END AES CIPHER SUPPORT

//BEGIN AES CIPHER SUPPORT - Disastry
#ifndef Included_pgpAES_h
#define Included_pgpAES_h

#include "pgpSymmetricCipherPriv.h"		/* for Cipher */

PGP_BEGIN_C_DECLARATIONS

/*
 * This is the definition of the AES cipher, for use with the
 * PGP Generic Cipher code.
 */
extern PGPCipherVTBL const cipherAES128;
extern PGPCipherVTBL const cipherAES192;
extern PGPCipherVTBL const cipherAES256;

PGP_END_C_DECLARATIONS

#endif /* !Included_pgpAES_h */
//END AES CIPHER SUPPORT
