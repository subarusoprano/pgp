/*
 * pgpDSAKey.c
 * Signatures using the Digital Signature Algorithm
 *
 * $Id: pgpDSAKey.c,v 1.58.6.1 1999/06/04 00:28:51 heller Exp $
 */
#include <string.h>
#include "pgpConfig.h"
#include "pgpMemoryMgr.h"

#include "pgpDebug.h"
#include "pgpDSAKey.h"
#include "pgpKeyMisc.h"
#include "bn.h"
#include "pgpSymmetricCipherPriv.h"
#include "pgpCFBPriv.h"
#include "pgpHashPriv.h"
#include "pgpMem.h"
#include "pgpErrors.h"
#include "pgpFixedKey.h"
#include "bnprime.h"
#include "pgpPubKey.h"
#include "pgpRandomPool.h"
#include "pgpRandomContext.h"
#include "pgpRandomX9_17.h"
#include "pgpStr2Key.h"
#include "pgpContext.h"
#include "pgpEnv.h"

#ifndef NULL
#define NULL 0
#endif

#define ASSERTDSA(alg) pgpAssert((ALGMASK(alg))==kPGPPublicKeyAlgorithm_DSA)

//BEGIN SHA DOUBLE MOD - Imad R. Faiad
//#define MAX_DSA_PRIME_BITS		1024
#define MAX_DSA_PRIME_BITS		2048
//END SHA DOUBLE MOD

typedef struct DSApub {
	BigNum p;		/* Public prime */
	BigNum q;		/* Public order of generator */
	BigNum g;		/* Public generator */
	BigNum y;		/* Public key, g**x mod p */
} DSApub;

typedef struct DSAsec {
	BigNum p;		/* Copy of public parameters */
	BigNum q;
	BigNum g;
	BigNum y;
	BigNum x;		/* Secret key, discrete log of y */
} DSAsec;


/* A PGPSecKey's priv points to this, an DSAsec plus the encrypted form... */
/* This struct is always allocated using PGPNewSecureData */
typedef struct DSAsecPlus
{
	PGPContextRef	context;
	DSAsec s;
	PGPByte *cryptkey;
	size_t ckalloc, cklen;
	int locked;
} DSAsecPlus;

/** Public key functions **/

static void
dsaPubDestroy(PGPPubKey *pubkey)
{
	DSApub *pub = (DSApub *)pubkey->priv;
	PGPContextRef		context;

	pgpAssertAddrValid( pubkey, PGPPubKey );
	context	= pubkey->context;

	pgpAssert( pgpContextIsValid( context ) );
	
	ASSERTDSA(pubkey->pkAlg);
	
	bnEnd(&pub->p);
	bnEnd(&pub->q);
	bnEnd(&pub->g);
	bnEnd(&pub->y);
	pgpClearMemory( pub,  sizeof(pub));
	pgpContextMemFree( context, pub);
	pgpClearMemory( pubkey,  sizeof(pubkey));
	pgpContextMemFree( context, pubkey);
}


static int
dsaKeyTooBig(struct DSApub const *pub, struct DSAsec const *sec)
{
	unsigned maxsize = MAX_DSA_PRIME_BITS;
	if (pub) {
		if (bnBits(&pub->p) > maxsize)
			return maxsize;
	}
	if (sec) {
		if (bnBits(&sec->p) > maxsize)
			return maxsize;
	}
	/* Else OK */
	return 0;
}


/* Return the largest possible PGPESK size for a given key */
static size_t
dsaPubMaxesk(PGPPubKey const *pubkey, PGPPublicKeyMessageFormat format)
{
	(void)pubkey;
	(void)format;
	return kPGPError_PublicKeyUnimplemented;
}

static size_t
dsaPubMaxdecrypted(PGPPubKey const *pubkey, PGPPublicKeyMessageFormat format)
{
	(void)pubkey;
	(void)format;
	return kPGPError_PublicKeyUnimplemented;
}

static size_t
dsaPubMaxsig(PGPPubKey const *pubkey, PGPPublicKeyMessageFormat format)
{
	DSApub const *pub = (DSApub *)pubkey->priv;

	ASSERTDSA(pubkey->pkAlg);
	if (format == kPGPPublicKeyMessageFormat_PGP)
		return 2*( 2 + bnBytes(&pub->q) );
	else if (format == kPGPPublicKeyMessageFormat_PKCS1 ||
			 format == kPGPPublicKeyMessageFormat_IKE)
		return 2*( bnBytes(&pub->q) );
	else if (format == kPGPPublicKeyMessageFormat_X509) {
		/* SEQUENCE, length, INT, INT */
		PGPUInt32 len;
		PGPUInt32 qbytes = bnBytes(&pub->q);
		len = 2*(pgpBnX509LenLen(qbytes+1) + 1 + qbytes+1);
		return 1 + pgpBnX509LenLen(len) + len;
	}
	pgpAssert(0);
	return 0;
}



/*
 * Given a buffer of at least "maxesk" bytes, make an PGPESK
 * into it and return the size of the PGPESK, or <0.
 */
static int
dsaEncrypt(PGPPubKey const *pubkey, PGPByte const *key,
           size_t keylen, PGPByte *esk, size_t *esklen,
           PGPRandomContext const *rc, PGPPublicKeyMessageFormat format)
{
	(void)pubkey;
	(void)key;
	(void)keylen;
	(void)esk;
	(void)esklen;
	(void)rc;
	(void)format;
	return kPGPError_PublicKeyUnimplemented;
}



/*
 * Return 1 if (sig,siglen) is a valid MPI which signs
 * hash, of type h.  Verify that the type is SHA.1 and
 * the hash itself matches.
 */
static int
dsaVerify(PGPPubKey const *pubkey, PGPByte const *sig,
	size_t siglen, PGPHashVTBL const *h, PGPByte const *hash,
	PGPPublicKeyMessageFormat format)
{
#if PGP_VERIFY_DISABLE /* [ */

	(void)pubkey;
	(void)sig;
	(void)siglen;
	(void)h;
	(void)hash;
	(void)format;
	return kPGPError_FeatureNotAvailable;

#else /* PGP_VERIFY_DISABLE */  /* ]  [ */

	DSApub const *pub = (DSApub *)pubkey->priv;
	BigNum r, s, w, u2;
	int i;
	unsigned qbytes;
	size_t off;
	PGPMemoryMgrRef	mgr	= PGPGetContextMemoryMgr( pubkey->context );

	ASSERTDSA(pubkey->pkAlg);

	//BEGIN MD5 HASH WITH DSA KEY SUPPORT - Imad R. Faiad
	/* Hashsize must be at least as big as size of q for legal sig
	if (h->hashsize*8 < bnBits(&pub->q)) {
		return 0;
	}*/
	//END MD5 HASH WITH DSA KEY SUPPORT

#if 0
	/* Allow generalizations of SHA, as long as they are big enough */
	if (h->algorithm != kPGPHashAlgorithm_SHA)
		return 0;	/* No match for sure! */
#endif

	bnBegin(&r, mgr, FALSE );
	bnBegin(&s, mgr, FALSE );
	bnBegin(&w, mgr, FALSE );
	bnBegin(&u2, mgr, FALSE );

	qbytes = bnBytes(&pub->q);

	/* sig holds two values.  Get first, r, from sig. */
	off = 0;
	if (format == kPGPPublicKeyMessageFormat_X509) {
		/* Parse SEQUENCE header for 509 sig data */
		PGPByte const *sigp = sig + off;
		PGPUInt32 len;
		if (pgpBnX509TagLen(&sigp, &len) != X509_TAG_SEQUENCE) {
			i = kPGPError_MalformedKeyComponent;
			goto done;
		}
		off += sigp - sig;
		if (len != siglen - off) {
			i = kPGPError_MalformedKeyComponent;
			goto done;
		}
	}
	i = pgpBnGetFormatted(&r, sig+off, siglen-off, qbytes, format);
	if (i <= 0)
		goto fail;
	/* Get 2nd value, s, from SIG */
	off += i;
	i = pgpBnGetFormatted(&s, sig+off, siglen-off, qbytes, format);
	if (i <= 0)
		goto fail;
	off += i;
	if (off != siglen) {
		i = kPGPError_BadSignatureSize;
		goto done;
	}

	/*
	 * Sanity-check r and s against the subprime q.  Both should
	 * be less than q.  If not, the signature is clearly bad.
	 */
	if (bnCmp(&r, &pub->q) >= 0 || bnCmp(&s, &pub->q) >= 0) {
		i = 0;	/* FAIL */
		goto done;
	}
	
	/* Reconstruct hash as u2 */
	//BEGIN MD5 HASH WITH DSA KEY SUPPORT - Imad R. Faiad
	if (h->hashsize*8 < bnBits(&pub->q)) {
		if (bnInsertBigBytes(&u2, hash, 0, h->hashsize) < 0)
			goto nomem;
	}
	else		
	//END MD5 HASH WITH DSA KEY SUPPORT
	if (bnInsertBigBytes(&u2, hash, 0, bnBytes(&pub->q)) < 0)
		goto nomem;

	/*
	 * Calculate DSS check function....
	 * Given signature (r,s) and hash H (in bn), compute:
	 * w = s^-1 mod q
	 * u1 = H * w mod q
	 * u2 = r * w mod q
	 * v = g^u1 * y^u2 mod p
	 * if v == r mod q, the signature checks.
	 *
	 * To save space, we put u1 into s, H into u2, and v into w.
	 */
	if (bnInv(&w, &s, &pub->q) < 0)
		goto nomem;
	if (bnMul(&s, &u2, &w) < 0 || bnMod(&s, &s, &pub->q) < 0)
		goto nomem;
	if (bnMul(&u2, &r, &w) < 0 || bnMod(&u2, &u2, &pub->q) < 0)
		goto nomem;

        /* Now for the expensive part... */

        if (bnDoubleExpMod(&w, &pub->g, &s, &pub->y, &u2, &pub->p) < 0)
                goto nomem;
        if (bnMod(&w, &w, &pub->q) < 0)
                goto nomem;

	/* Compare result with r, should be equal */
	i = bnCmp(&w, &r) == 0;

	goto done;

fail:
	if (!i)
		i = kPGPError_BadSignatureSize;
	goto done;
nomem:
	i = kPGPError_OutOfMemory;
	goto done;
done:
	bnEnd(&u2);
	bnEnd(&w);
	bnEnd(&s);
	bnEnd(&r);

	return i;

#endif /* PGP_VERIFY_DISABLE */ /* ] */
}


/*
 * Turn a PGPPubKey into the algorithm-specific parts of a public key.
 * A public key's DSA-specific part is:
 *
 *  0      2+i  MPI for prime
 * 2+i     2+t  MPI for order
 * 4+i+t   2+u	MPI for generator
 * 6+i+t+u 2+v	MPI for public key
 * 8+i+t+u+v
 */
static size_t
dsaPubBufferLength(PGPPubKey const *pubkey)
{
	DSApub const *pub = (DSApub *)pubkey->priv;

	return 8 + bnBytes(&pub->p) + bnBytes(&pub->q) +
		   bnBytes(&pub->g) + bnBytes(&pub->y);
}

static void
dsaPubToBuffer(PGPPubKey const *pubkey, PGPByte *buf)
{
	DSApub const *pub = (DSApub *)pubkey->priv;
	unsigned off;

	off = 0;
	off += pgpBnPutPlain(&pub->p, buf+off);
	off += pgpBnPutPlain(&pub->q, buf+off);
	off += pgpBnPutPlain(&pub->g, buf+off);
	off += pgpBnPutPlain(&pub->y, buf+off);
}


/* A little helper function that's used twice */
static void
dsaFillPubkey(PGPPubKey *pubkey, DSApub *pub)
{
	pubkey->next	 = NULL;
	pubkey->pkAlg	 = kPGPPublicKeyAlgorithm_DSA;
	pubkey->priv	 = pub;
	pubkey->destroy  = dsaPubDestroy;
	pubkey->maxesk   = dsaPubMaxesk;
	pubkey->maxsig   = dsaPubMaxsig;
	pubkey->maxdecrypted   = dsaPubMaxdecrypted;
	pubkey->encrypt  = dsaEncrypt;
	pubkey->verify   = dsaVerify;
	pubkey->bufferLength  = dsaPubBufferLength;
	pubkey->toBuffer = dsaPubToBuffer;
}


/*
 * Turn the algorithm-specific parts of a public key into a PGPPubKey
 * structure.  A public key's DSA-specific part is:
 *
 *  0      2+i  MPI for prime
 * 2+i     2+t  MPI for order
 * 4+i+t   2+u	MPI for generator
 * 6+i+t+u 2+v	MPI for public key
 * 8+i+t+u+v
 */
PGPPubKey *
dsaPubFromBuf(
	PGPContextRef	context,
	PGPByte const *	buf,
	size_t			size,
	PGPError *		error)
{
	PGPPubKey *pubkey;
	DSApub *pub;
	unsigned i, t, u, v;
	int w;
	PGPError	err = kPGPError_OutOfMemory;
	PGPMemoryMgrRef	mgr	= PGPGetContextMemoryMgr( context );
	
	bnInit();

	w = pgpBnParse(buf, size, 4, &i, &t, &u, &v);
	if (w < 0) {
		*error = (PGPError)w;
		return NULL;
	}
	if (t <= i+2 || (buf[t-1] & 1) == 0) {	/* Too small or even prime p */
		*error = kPGPError_MalformedKeyComponent;
		return NULL;
	}
	if (u <= t+2 || (buf[u-1] & 1) == 0) {	/* Too small or even order q */
		*error = kPGPError_MalformedKeyComponent;
		return NULL;
	}
	pub = (DSApub *)pgpContextMemAlloc( context,
		sizeof(*pub), kPGPMemoryMgrFlags_Clear);
	if (pub) {
		pubkey = (PGPPubKey *)pgpContextMemAlloc( context,
			sizeof(*pubkey), kPGPMemoryMgrFlags_Clear);
		if (pubkey) {
			pubkey->context	= context;
			
			bnBegin(&pub->p, mgr, FALSE );
			bnBegin(&pub->q, mgr, FALSE );
			bnBegin(&pub->g, mgr, FALSE );
			bnBegin(&pub->y, mgr, FALSE );
			if (bnInsertBigBytes(&pub->p, buf+i+2, 0, t-i-2) >= 0
			 && bnInsertBigBytes(&pub->q, buf+t+2, 0, u-t-2) >= 0
			 && bnInsertBigBytes(&pub->g, buf+u+2, 0, v-u-2) >= 0
			 && bnInsertBigBytes(&pub->y, buf+v+2, 0, w-v-2) >= 0)
			{
				if (dsaKeyTooBig (pub, NULL)) {
					err = kPGPError_KeyTooLarge;
				} else {
					dsaFillPubkey(pubkey, pub);
					*error = 0;
					return pubkey;
				}
			}
			/* Failed = clean up and return NULL */
			bnEnd(&pub->p);
			bnEnd(&pub->q);
			bnEnd(&pub->g);
			bnEnd(&pub->y);
			pgpContextMemFree( context, pubkey);
		}
		pgpContextMemFree( context, pub);
	}
	*error = err;
	return NULL;
}

/*
 * Return the size of the public portion of a key buffer.
 */
int
dsaPubKeyPrefixSize(PGPByte const *buf, size_t size)
{
	return pgpBnParse(buf, size, 4, NULL, NULL, NULL, NULL);
}


/** Secret key functions **/

static void
dsaSecDestroy(PGPSecKey *seckey)
{
	DSAsecPlus *sec = (DSAsecPlus *)seckey->priv;
	PGPContextRef		context;

	pgpAssertAddrValid( seckey, PGPSecKey );
	context	= seckey->context;

	ASSERTDSA(seckey->pkAlg);
	bnEnd(&sec->s.p);
	bnEnd(&sec->s.q);
	bnEnd(&sec->s.g);
	bnEnd(&sec->s.y);
	bnEnd(&sec->s.x);
	pgpClearMemory(sec->cryptkey, sec->ckalloc);
	pgpContextMemFree( context, sec->cryptkey);
	PGPFreeData( sec );			/* Wipes as it frees */
	pgpClearMemory( seckey,  sizeof(seckey));
	pgpContextMemFree( context, seckey);
}

/*
 * Generate a PGPPubKey from a PGPSecKey
 */
static PGPPubKey *
dsaPubkey(PGPSecKey const *seckey)
{
	DSAsecPlus const *sec = (DSAsecPlus *)seckey->priv;
	PGPPubKey *pubkey;
	DSApub *pub;
	PGPContextRef		context;
	PGPMemoryMgrRef		mgr	= NULL;

	pgpAssertAddrValid( seckey, PGPSecKey );
	context	= seckey->context;
	mgr	= PGPGetContextMemoryMgr( context );

	ASSERTDSA(seckey->pkAlg);
	pub = (DSApub *)pgpContextMemAlloc( context,
		sizeof(*pub), kPGPMemoryMgrFlags_Clear);
	if (pub) {
		pubkey = (PGPPubKey *)pgpContextMemAlloc( context,
			sizeof(*pubkey), kPGPMemoryMgrFlags_Clear);
		if (pubkey) {
			pubkey->context	= context;
			
			bnBegin(&pub->p, mgr, FALSE );
			bnBegin(&pub->q, mgr, FALSE );
			bnBegin(&pub->g, mgr, FALSE );
			bnBegin(&pub->y, mgr, FALSE );
			if (bnCopy(&pub->p, &sec->s.p) >= 0
			    && bnCopy(&pub->q, &sec->s.q) >= 0
			    && bnCopy(&pub->g, &sec->s.g) >= 0
			    && bnCopy(&pub->y, &sec->s.y) >= 0)
			{
				dsaFillPubkey(pubkey, pub);
				pubkey->pkAlg = seckey->pkAlg;
				memcpy(pubkey->keyID, seckey->keyID,
				       sizeof(pubkey->keyID));
				return pubkey;
			}
			/* Failed = clean up and return NULL */
			bnEnd(&pub->p);
			bnEnd(&pub->q);
			bnEnd(&pub->g);
			bnEnd(&pub->y);
			pgpContextMemFree( context, pubkey);
		}
		pgpContextMemFree( context, pub);
	}
	return NULL;
}

/*
 * Yes, there *is* a reason that this is a function and not a variable.
 * On a hardware device with an automatic timeout,
 * it actually might need to do some work to find out.
 */
static int
dsaIslocked(PGPSecKey const *seckey)
{
	DSAsecPlus const *sec = (DSAsecPlus *)seckey->priv;

	ASSERTDSA(seckey->pkAlg);
	return sec->locked;
}

/*
 * Return the algorithm and (symmetric) key size used for locking/unlocking
 * the secret key.
 */
static PGPError
dsaLockingAlgorithm(
	PGPSecKey const *seckey,
	PGPCipherAlgorithm *pAlg,
	PGPSize *pAlgKeySize
	)
{
	DSAsecPlus *sec = (DSAsecPlus *)seckey->priv;
	PGPCipherVTBL const *cipher;
	PGPByte alg;
	int i;

	ASSERTDSA(seckey->pkAlg);

	if( IsntNull( pAlg ) )
		*pAlg = (PGPCipherAlgorithm) 0;
	if( IsntNull( pAlgKeySize ) )
		*pAlgKeySize = (PGPSize) 0;

	/* Check packet for basic consistency */
	i = pgpBnParse(sec->cryptkey, sec->cklen, 4, NULL, NULL, NULL, NULL);
	if (i < 0)
		return (PGPError)i;

	/* Get the encryption algorithm (cipher number).  0 == no encryption */
	alg = sec->cryptkey[i] & 255;

	/* New style has 255 then algorithm value */
	if (alg == 255)
		alg = sec->cryptkey[i+1] & 255;

	cipher = pgpCipherGetVTBL( (PGPCipherAlgorithm)alg);
	if (!cipher)
		return kPGPError_BadCipherNumber;

	/* Success */
	if( IsntNull( pAlg ) )
		*pAlg = (PGPCipherAlgorithm) alg;
	if( IsntNull( pAlgKeySize ) )
		*pAlgKeySize = cipher->keysize;

	return kPGPError_NoErr;
}


/*
 * Return the StringToKey type for unlocking the given key.  We use
 * kPGPStringToKey_Literal to flag a secret split unlocking buffer.
 * Returns kPGPStringToKey_Simple if key has no passphrase.
 */
static PGPError
dsaS2KType(
	PGPSecKey const *seckey,
	PGPStringToKeyType *s2kType
	)
{
	DSAsecPlus *sec = (DSAsecPlus *)seckey->priv;
	PGPByte alg;
	int i;

	ASSERTDSA(seckey->pkAlg);

	/* note that 0 is a valid type, but use it as default anyway */
	if( IsntNull( s2kType ) )
		*s2kType = (PGPStringToKeyType) 0;

	/* Check packet for basic consistency */
	i = pgpBnParse(sec->cryptkey, sec->cklen, 4, NULL, NULL, NULL, NULL);
	if (i < 0)
		return (PGPError)i;

	/* Get the encryption algorithm (cipher number).  0 == no encryption */
	alg = sec->cryptkey[i] & 255;

	if (alg == 255) {
		/* New style has 255 then algorithm value then S2K */
		*s2kType = (PGPStringToKeyType) sec->cryptkey[i+2];
	} else {
		/* Unencrypted or old-style simple encryption */
		*s2kType = kPGPStringToKey_Simple;
	}

	return kPGPError_NoErr;
}

/*
 * Convert a passphrase into a s2k literal buffer for the key.
 * Returns error code.  Output buffer will be size of the *pAlgKeySize
 * parameter from pgpSecKeyLockingalgorithm.
 */
static PGPError
dsaConvertPassphrase(PGPSecKey *seckey, PGPEnv const *env,
	  char const *phrase, PGPSize plen, PGPByte *outbuf)
{
	DSAsecPlus *sec = (DSAsecPlus *)seckey->priv;
	PGPStringToKey *s2k;
	PGPByte alg;
	PGPBoolean hasS2K;
	PGPCipherVTBL const *cipher;
	int i;

	ASSERTDSA(seckey->pkAlg);
	pgpAssert (IsntNull( outbuf ) );

	/* Check packet for basic consistency */
	i = pgpBnParse(sec->cryptkey, sec->cklen, 4, NULL, NULL, NULL, NULL);
	if (i < 0)
		return (PGPError)i;

	/* Get the encryption algorithm (cipher number).  0 == no encryption */
	alg = sec->cryptkey[i++] & 255;

	hasS2K = (alg == 255);

	/* New style has 255 then algorithm value */
	if (hasS2K)
		alg = sec->cryptkey[i++] & 255;

	/* Now we are looking at the s2k object if there is one. */
	if (alg == 0) {
		/* Key is not locked */
		return kPGPError_BadParams;
	}
	cipher = pgpCipherGetVTBL( (PGPCipherAlgorithm)alg);
	if( IsNull( cipher ) )
		return kPGPError_BadCipherNumber;

	if (hasS2K) {
		pgpS2Kdecode(&s2k, env, sec->cryptkey+i, sec->cklen-i);
	} else {
		s2k = pgpS2Ksimple(env, pgpHashByNumber(kPGPHashAlgorithm_MD5));
	}
	if (IsNull( s2k ) )
		return kPGPError_OutOfMemory;
	pgpStringToKey(s2k, phrase, plen, outbuf, cipher->keysize);
	pgpS2Kdestroy (s2k);
	
	return kPGPError_NoErr;
}


/*
 * Try to decrypt the secret key wih the given passphrase.  Returns >0
 * if it was the correct passphrase. =0 if it was not, and <0 on error.
 * Does not alter the key even if it's the wrong passphrase and already
 * unlocked.  A NULL passphrae will work if the key is unencrypted.
 * 
 * A (secret) key's DSA-specific part is:
 *
 *  0                2+u  MPI for prime p
 *  2+u              2+v  MPI for order q
 *  4+u+v            2+w  MPI for generator g
 *  6+u+v+w	     2+x  MPI for public key y
 *  8+u+v+w+x        1    Encryption algorithm (0 for none, 1 for IDEA)
 *  9+u+v+w+x        t    Encryption IV: 0 or 8 bytes
 *  9+t+u+v+w+x      2+y  MPI for x (discrete log of public key)
 * 11+t+u+v+w+x+y    2    Checksum
 * 13+t+u+v+w+x+y
 *
 * Actually, that's the old-style, if pgpS2KoldVers is true.
 * If it's false, the algoruthm is 255, and is followed by the
 * algorithm, then the (varaible-length, self-delimiting)
 * string-to-key descriptor.
 */

static int
dsaUnlock(PGPSecKey *seckey, PGPEnv const *env,
	  char const *phrase, size_t plen, PGPBoolean hashedPhrase)
{
	DSAsecPlus *sec = (DSAsecPlus *)seckey->priv;
	BigNum x;
	PGPCFBContext *cfb = NULL;
	unsigned v;
	unsigned alg;
	unsigned checksum;
	int i;
	PGPMemoryMgrRef		mgr	= NULL;
	
	//BEGIN SANITY CHECKS OF ALL DSA KEY PARAMETERS - Imad R. Faiad
	unsigned qbits, maxqbits;
	BigNum pmodq, g2TheqModp, g2ThexModp;
	//END SANITY CHECKS OF ALL DSA KEY PARAMETERS
	
	mgr	= PGPGetContextMemoryMgr( seckey->context );

	bnBegin(&x, mgr, TRUE);

	ASSERTDSA(seckey->pkAlg);

	/* Check packet for basic consistency */
	i = pgpBnParse(sec->cryptkey, sec->cklen, 4, &v, NULL, NULL, NULL);
	if (i <= 0)
		goto fail;

	/* OK, read the public data */
	i = pgpBnGetPlain(&sec->s.p, sec->cryptkey+v, sec->cklen-v);
	if (i <= 0)
		goto fail;
	v += i;
	i = pgpBnGetPlain(&sec->s.q, sec->cryptkey+v, sec->cklen-v);
	if (i <= 0)
		goto fail;
	v += i;
	i = pgpBnGetPlain(&sec->s.g, sec->cryptkey+v, sec->cklen-v);
	if (i <= 0)
		goto fail;
	v += i;
	i = pgpBnGetPlain(&sec->s.y, sec->cryptkey+v, sec->cklen-v);
	if (i <= 0)
		goto fail;
	v += i;

	/* Get the encryption algorithm (cipher number).  0 == no encryption */
	alg  = sec->cryptkey[v];

	/* If the phrase is empty, set it to NULL */
	if (plen == 0)
		phrase = NULL;
	/*
	 * We need a pass if it is encrypted, and we cannot have a
	 * password if it is NOT encrypted.  I.e., this is a logical
	 * xor (^^)
	 */
	if (!phrase != !sec->cryptkey[v])
		goto badpass;

	i = pgpCipherSetup(sec->cryptkey + v, sec->cklen - v, phrase, plen,
					   hashedPhrase, env, &cfb);
	if (i < 0)
		goto done;
	v += i;

	checksum = 0;
	i = pgpBnGetNew(&x, sec->cryptkey + v, sec->cklen - v, cfb, &checksum);
	if (i <= 0)
		goto badpass;
	v += i;
	if (bnCmp(&x, &sec->s.q) >= 0)
		goto badpass;	/* Wrong passphrase: x must be < q */

	/* Check that we ended in the right place */
	if (sec->cklen - v != 2) {
		i = kPGPError_KEY_LONG;
		goto fail;
	}
	checksum &= 0xffff;
	if (checksum != pgpChecksumGetNew(sec->cryptkey+v, cfb))
		goto badpass;

	/*
	 * Note that the "nomem" case calls bnEnd()
	 * more than once, but this is guaranteed harmless.
 	 */
	if (bnCopy(&sec->s.x, &x) < 0)
		goto nomem;

	i = 1;	/* Decrypted! */
	sec->locked = 0;


	//BEGIN SANITY CHECKS OF ALL DSA KEY PARAMETERS - Imad R. Faiad
	//This is to prevent Klima & Rosa style attacks
	//Please refer to:-
	//"Attacks on Private Signature Keys of the OpenPGP format,
	//PGP programs and other applications compatible with OPenPGP",
	//Vlastimil Klima and Thomas Rosa, March 2001
	//http://www.i.cz/en/pdf/openPGP_attack_ENGvktr.pdf

	//check that 2^159 < q < 2^pgpDiscreteLogQBits(MAX_DSA_PRIME_BITS)
	//This is necessary to support DSA > 1,024 bits
	//where q can get as large as 2^232,
	//when MAX_DSA_PRIME_BITS is set to 2048 bits

	//get the number of significant bits in q
	qbits=bnBits(&sec->s.q);

	//maxqbits is the maximum number of significant bits
	//that q may have given MAX_DSA_PRIME_BITS
	maxqbits=pgpDiscreteLogQBits(MAX_DSA_PRIME_BITS);

	//check that 2^159 < q < 2^maxqbits
	if ((qbits < 159) || (qbits > maxqbits))
		goto fail;

	//check that g > 1
	if (bnCmpQ(&sec->s.g, 1) < 1)
		goto fail;

	//check that y > 1
	if (bnCmpQ(&sec->s.y, 1) < 1)
		goto fail;

	//p should be odd
	if ((bnLSWord(&sec->s.p) & 1) == 0)
		goto fail;

	//q should be odd
	if ((bnLSWord(&sec->s.q) & 1) == 0)
		goto fail;

	//check that p > y
	if (bnCmp(&sec->s.p, &sec->s.y) < 1)
		goto fail;

	//check that p > g
	if (bnCmp(&sec->s.p, &sec->s.g) < 1)
		goto fail;

	//check that q > x
	if (bnCmp(&sec->s.q, &sec->s.x) < 1)
		goto fail;

	//check that q|(p-1)
	//that is p mod q = 1
	bnBegin(&pmodq, mgr, FALSE);
	bnMod(&pmodq, &sec->s.p, &sec->s.q);
	if (bnCmpQ(&pmodq, 1) != 0){
		bnEnd(&pmodq);
		goto fail;
	}
	bnEnd(&pmodq);
	//check that g^q mod p = 1
	bnBegin(&g2TheqModp, mgr, FALSE);
	
	if (bnExpMod(&g2TheqModp, &sec->s.g, &sec->s.q, &sec->s.p) < 0) {
		bnEnd(&g2TheqModp);
		goto nomem;
	}

	if (bnCmpQ(&g2TheqModp, 1) != 0){
		bnEnd(&g2TheqModp);
		goto fail;
	}
	bnEnd(&g2TheqModp);

	//check that g^x mod p = y
	bnBegin(&g2ThexModp, mgr, FALSE);
	
	if (bnExpMod(&g2ThexModp, &sec->s.g, &sec->s.x, &sec->s.p) < 0) {
		bnEnd(&g2ThexModp);
		goto nomem;
	}

	if (bnCmp(&g2ThexModp, &sec->s.y) != 0){
		bnEnd(&g2ThexModp);
		goto fail;
	}
	bnEnd(&g2ThexModp);
	//END SANITY CHECKS OF ALL DSA KEY PARAMETERS
	goto done;

nomem:
	i = kPGPError_OutOfMemory;
	goto done;
fail:
	if (!i)
		i = kPGPError_KeyPacketTruncated;
	goto done;
badpass:
	i = 0;	/* Incorrect passphrase */
	goto done;
done:
	bnEnd(&x);
	if (cfb)
		PGPFreeCFBContext(cfb);
	return i;
}

/*
 * Relock the key.
 */
static void
dsaLock(PGPSecKey *seckey)
{
	DSAsecPlus *sec = (DSAsecPlus *)seckey->priv;

	ASSERTDSA(seckey->pkAlg);
	sec->locked = 1;
	/* bnEnd is documented as also doing a bnBegin */
	bnEnd(&sec->s.x);
}

/*
 * Try to decrypt the given esk.  If the key is locked, try the given
 * passphrase.  It may or may not leave the key unlocked in such a case.
 * (Some hardware implementations may insist on a password per usage.)
 */
static int
dsaDecrypt(PGPSecKey *seckey, PGPEnv const *env,
	   PGPByte const *esk, size_t esklen,
	   PGPByte *key, size_t *keylen, char const *phrase, size_t plen,
	   PGPPublicKeyMessageFormat format)
{
	(void)seckey;
	(void)env;
	(void)esk;
	(void)esklen;
	(void)key;
	(void)keylen;
	(void)phrase;
	(void)plen;
	(void)format;
	return kPGPError_PublicKeyUnimplemented;
}

/*
 * Return the size of the buffer needed, worst-case, for the decrypted
 * output.
 */
static size_t
dsaSecMaxdecrypted(PGPSecKey const *seckey, PGPPublicKeyMessageFormat format)
{
	(void)seckey;
	(void)format;
	return kPGPError_PublicKeyUnimplemented;
}

static size_t
dsaSecMaxesk(PGPSecKey const *seckey, PGPPublicKeyMessageFormat format)
{
	(void)seckey;
	(void)format;
	return kPGPError_PublicKeyUnimplemented;
}

static size_t
dsaSecMaxsig(PGPSecKey const *seckey, PGPPublicKeyMessageFormat format)
{
	DSAsecPlus const *sec = (DSAsecPlus *)seckey->priv;

	ASSERTDSA(seckey->pkAlg);
	if (format == kPGPPublicKeyMessageFormat_PGP)
		return 2*( 2 + bnBytes(&sec->s.q) );
	else if (format == kPGPPublicKeyMessageFormat_PKCS1 ||
			 format == kPGPPublicKeyMessageFormat_IKE)
		return 2*( bnBytes(&sec->s.q) );
	else if (format == kPGPPublicKeyMessageFormat_X509) {
		/* SEQUENCE, length, INT, INT */
		PGPUInt32 len;
		PGPUInt32 qbytes = bnBytes(&sec->s.q);
		len = 2*(pgpBnX509LenLen(qbytes+1) + 1 + qbytes+1);
		return 1 + pgpBnX509LenLen(len) + len;
	}

	pgpAssert(0);
	return 0;
}

/*
 * Helper function: seed a RandomContext from a BigNum.
 * Be very sure to leave nothing in memory!
 */
static void
pgpRandomBnSeed(PGPRandomContext const *rc, BigNum const *bn)
{
	PGPByte buf[32];	/* Big enough for 99.9% of all keys */
	unsigned bytes = (bnBits(bn) + 7)/8;
	unsigned off = 0;

	while (bytes > sizeof(buf)) {
		bnExtractLittleBytes(bn, buf, off, sizeof(buf));
		pgpRandomAddBytes(rc, buf, sizeof(buf));
		bytes -= sizeof(buf);
		off += sizeof(buf);
	}
	bnExtractLittleBytes(bn, buf, off, bytes);
	pgpRandomAddBytes(rc, buf, bytes);

	pgpClearMemory( buf,  sizeof(buf));
}



static int
dsaSign(PGPSecKey *seckey, PGPHashVTBL const *h, PGPByte const *hash,
	PGPByte *sig, size_t *siglen, PGPRandomContext const *rc,
	PGPPublicKeyMessageFormat format)
{
#if PGP_SIGN_DISABLE /* [ */

	(void)seckey;
	(void)h;
	(void)hash;
	(void)sig;
	(void)siglen;
	(void)rc;
	(void)format;
	return kPGPError_FeatureNotAvailable;

#else /* PGP_SIGN_DISABLE */  /* ]  [ */

	DSAsecPlus *sec = (DSAsecPlus *)seckey->priv;
	BigNum r, s, bn, k;
	unsigned t;
	unsigned qbits;
	unsigned qbytes;
	int i;
	PGPRandomContext *rc2;
	PGPMemoryMgrRef		mgr	= NULL;
	
	mgr	= PGPGetContextMemoryMgr( seckey->context );

	(void)h;
	/* We don't need this argument, although other algorithms may... */
	(void)format;

	ASSERTDSA(seckey->pkAlg);
	
	//BEGIN MD5 HASH WITH DSA KEY SUPPORT - Imad R. Faiad
	/* Allow generalizations of SHA as long as they are big enough */
/*#if 0
	pgpAssert(h->algorithm == kPGPHashAlgorithm_SHA);
#else
	pgpAssert(h->hashsize*8 >= bnBits(&sec->s.q));
	// Make sure that q is the right size of we are using regular SHA hash
	pgpAssert( ! (h->algorithm == kPGPHashAlgorithm_SHA
				&& bnBits(&sec->s.q) != h->hashsize*8) );
#endif*/
	//END MD5 HASH WITH DSA KEY SUPPORT

	if (sec->locked)
		return kPGPError_KeyIsLocked;

	/*
	 * DSA requires a secret k.  This k is *very* important
	 * to keep secret.  Consider, the DSA signing equations are:
	 * r = (g^k mod p) mod q, and
	 * s = k^-1 * (H(m) + x*r) mod q,
	 * so if you know k (and, the signature r, s and H), then
	 * x = r^-1 * (k*s - H(m))
	 * If we ever pick two k values the same, then
	 * r = (g^k mod p) mod q is the same for both signatures, and
	 * s1 = k^-1 * (H1 + x * r) 
	 * s2 = k^-1 * (H2 + x * r) 
	 * k = (H1-H2) / (s1-s2)
	 * and proceed from there.
	 *
	 * So we need to make *very* sure there's no problem.  To make
	 * sure, we add a layer on top of the passed-in RNG.  We assume
	 * the passed-in RNG is good enough to never repeat (not a
	 * difficult task), and apply an additional X9.17 generator on
	 * top of that, seeded with the secret x, which is destroyed
	 * before leaving this function.
	 *
	 * In addition, we add entropy from the hash to the original RNG.
	 * This will prevent us from using the same k value twice if the
	 * messages are different.
	 */
	//BEGIN MD5 HASH WITH DSA KEY SUPPORT - Imad R. Faiad
	//pgpRandomAddBytes(rc, hash, bnBytes(&sec->s.q));
	pgpRandomAddBytes(rc, hash, h->hashsize);
	//END MD5 HASH WITH DSA KEY SUPPORT
	rc2 = pgpRandomCreateX9_17( rc->context, kPGPCipherAlgorithm_CAST5, rc);
	if (!rc2)
		return kPGPError_OutOfMemory;
	pgpRandomBnSeed(rc2, &sec->s.x);

	/*
	 * Of these values, only k is inherently sensitive, but others may
	 * hold some intermediate results we would prefer not to have leaked.
	 * So mark all as sensitive.
	 */
	bnBegin(&r, mgr, TRUE );
	bnBegin(&s, mgr, TRUE );
	bnBegin(&bn, mgr, TRUE );
	bnBegin(&k, mgr, TRUE );

	/*
	 * Choose the random k value to be used for this signature.
	 * Make it a bit bigger than q so it is fairly uniform mod q.
	 */
	qbits = bnBits(&sec->s.q);
	qbytes = bnBytes(&sec->s.q);
	if (pgpBnGenRand(&k, rc2, qbits+8, 0, 1, qbits) < 0 ||
	    bnMod(&k, &k, &sec->s.q) < 0)
		goto nomem;
	
	/* Raise g to k power mod p then mod q to get r */
	if (bnExpMod(&r, &sec->s.g, &k, &sec->s.p) < 0 ||
	    bnMod(&r, &r, &sec->s.q) < 0)
		goto nomem;
	      
	/* r*x mod q into s */
	if (bnMul(&s, &r, &sec->s.x) < 0 ||
	    bnMod(&s, &s, &sec->s.q) < 0)
		goto nomem;

	/* Pack message hash M into buffer bn */
	//BEGIN MD5 HASH WITH DSA KEY SUPPORT - Imad R. Faiad
	if (h->hashsize*8 < bnBits(&sec->s.q)) {
		if (bnInsertBigBytes(&bn, hash, 0, h->hashsize) < 0)
			goto nomem;
	}
	else
	//END MD5 HASH WITH DSA KEY SUPPORT
	if (bnInsertBigBytes(&bn, hash, 0, bnBytes(&sec->s.q)) < 0)
		goto nomem;

	if (bnMod(&bn, &bn, &sec->s.q) < 0)
		goto nomem;

	/* Add into s */
	if (bnAdd(&s, &bn) < 0 ||
	    bnMod(&s, &s, &sec->s.q) < 0)
		goto nomem;

	/* Divide by k, mod q (k inverse held in bn) */
	if (bnInv(&bn, &k, &sec->s.q) < 0 ||
	    bnMul(&s, &s, &bn) < 0 ||
	    bnMod(&s, &s, &sec->s.q) < 0)
		goto nomem;

	/* That's it, now to pack r and then s into the buffer */
	t = 0;
	if (format == kPGPPublicKeyMessageFormat_X509) {
		/* Put in SEQUENCE header for 509 sig data */
		PGPUInt32 len_seq, lenlen_seq;
		/* Count size of sequence, counting a 0 byte if hi bit is set */
		if (8*qbytes == bnBits(&r))
			len_seq = pgpBnX509LenLen(qbytes+1) + 1 + qbytes+1;
		else
			len_seq = pgpBnX509LenLen(qbytes) + 1 + qbytes;
		if (8*qbytes == bnBits(&s))
			len_seq += pgpBnX509LenLen(qbytes+1) + 1 + qbytes+1;
		else
			len_seq += pgpBnX509LenLen(qbytes) + 1 + qbytes;
		lenlen_seq = pgpBnX509LenLen(len_seq);
		sig[t++] = X509_TAG_SEQUENCE | X509_TAG_CONSTRUCTED;
		if (--lenlen_seq == 0) {
			sig[t++] = len_seq;
		} else {
			sig[t++] = 0x80 | lenlen_seq;
			len_seq <<= 8 * (4-lenlen_seq);
			while (lenlen_seq--) {
				sig[t++] = (PGPByte)(len_seq >> 24);
				len_seq <<= 8;
			}
		}
	}
	t += pgpBnPutFormatted(&r, sig+t, qbytes, format);
	t += pgpBnPutFormatted(&s, sig+t, qbytes, format);
	if (siglen)
		*siglen = (size_t)t;

	i = 0;
	goto done;

nomem:
	i = kPGPError_OutOfMemory;
	/* fall through */
done:
	pgpRandomDestroy(rc2);
	bnEnd(&k);
	bnEnd(&bn);
	bnEnd(&s);
	bnEnd(&r);
	return i;

#endif /* PGP_SIGN_DISABLE */ /* ] */
}


/*
 * Re-encrypt a PGPSecKey with a new urn a PGPSecKey into a secret key.
 * A secret key is, after a non-specific prefix:
 *  0       1    Version (= 2 or 3)
 *  1       4    Timestamp
 *  5       2    Validity (=0 at present)
 *  7       1    Algorithm (=kPGPPublicKeyAlgorithm_DSA for DSA)
 * The following:
 *  0                2+u  MPI for prime p
 *  2+u              2+v  MPI for order q
 *  4+u+v            2+w  MPI for generator g
 *  6+u+v+w	     2+x  MPI for public key y
 *  8+u+v+w+x        1    Encryption algorithm (0 for none, 1 for IDEA)
 *  9+u+v+w+x        t    Encryption IV: 0 or 8 bytes
 *  9+t+u+v+w+x      2+y  MPI for x (discrete log of public key)
 * 11+t+u+v+w+x+y    2    Checksum
 * 13+t+u+v+w+x+y
 *
 * The Encryption algorithm is the cipher algorithm for the old-style
 * string-to-key conversion.  For the new type, it's 255, then a cipher
 * algorithm, then a string-to-key algorithm (variable-length),
 * then the encryption IV.  That's 16 bytes plus the string-to-key
 * conversion length.
 */
#if PGP_MACINTOSH
#pragma global_optimizer on
#endif

static int
dsaChangeLock(PGPSecKey *seckey, PGPEnv const *env, 
	PGPRandomContext const *rc, char const *phrase, size_t plen,
	PGPStringToKeyType s2ktype)
{
	DSAsecPlus *sec = (DSAsecPlus *)seckey->priv;
	PGPStringToKey *s2k = NULL;	/* Shut up warnings */
	PGPCipherVTBL const *cipher = NULL;	/* Shut up warnings */
	PGPCFBContext *cfb = NULL;	/* This is realy needed */
	PGPByte *p;
	PGPByte key[PGP_CIPHER_MAXKEYSIZE];
	int oldf = 0;				/* Shut up warnings */
	unsigned len;
	unsigned checksum;

	ASSERTDSA(seckey->pkAlg);
	if (sec->locked)
		return kPGPError_KeyIsLocked;
	len = bnBytes(&sec->s.p) + bnBytes(&sec->s.q) + bnBytes(&sec->s.g) +
	      bnBytes(&sec->s.y) + bnBytes(&sec->s.x) + 13;
	if (phrase) {
		s2k = pgpS2Kcreate(env, rc, s2ktype);
		if (!s2k)
			return kPGPError_OutOfMemory;
		cipher = pgpCipherDefaultKey(env);
		pgpAssert(cipher);
		if (!cipher) {
			pgpS2Kdestroy(s2k);
			return kPGPError_OutOfMemory;
		}
		len += cipher->blocksize;
		cfb = pgpCFBCreate(
				PGPGetContextMemoryMgr( pgpenvGetContext( env ) ), cipher);
		if (!cfb) {
			pgpS2Kdestroy(s2k);
			return kPGPError_OutOfMemory;
		}
		oldf = pgpS2KisOldVers(s2k);
		if (!oldf)
			len += 1 + s2k->encodelen;
	}
	if (len > sec->ckalloc) {
		PGPError err = kPGPError_NoErr;
		if( IsNull( sec->cryptkey ) ) {
			sec->cryptkey = (PGPByte *)
				pgpContextMemAlloc( sec->context, len, 0 );
			if( IsNull( sec->cryptkey ) ) {
				err = kPGPError_OutOfMemory;
			}
		} else {
			err = pgpContextMemRealloc( sec->context,
				(void **)&sec->cryptkey, len, 0 );
		}
		if( IsPGPError( err ) ) {
			PGPFreeCFBContext(cfb);
			pgpS2Kdestroy(s2k);
			return err;
		}
		sec->ckalloc = (size_t)len;
	}
	sec->cklen = len;
	p = sec->cryptkey;

	/* Okay, no more errors possible!   Start installing data */
	p += pgpBnPutPlain(&sec->s.p, p);
	p += pgpBnPutPlain(&sec->s.q, p);
	p += pgpBnPutPlain(&sec->s.g, p);
	p += pgpBnPutPlain(&sec->s.y, p);

	/* Encryption parameters */
	if (!phrase) {
		*p++ = 0;	/* Unencrypted */
	} else {
		if (oldf) {
			*p++ = cipher->algorithm;
		} else {
			*p++ = 255;
			*p++ = cipher->algorithm;
			memcpy(p, s2k->encoding, s2k->encodelen);
			p += s2k->encodelen;
		}
		/* Create IV */
		pgpRandomGetBytes(rc, p, cipher->blocksize);
		pgpStringToKey(s2k, phrase, plen, key, cipher->keysize);
		PGPInitCFB(cfb, key, p);
		pgpS2Kdestroy(s2k);
		p += cipher->blocksize;
		/* Wipe key *immediately* */
		pgpClearMemory( key,  cipher->keysize);
	}

	/* Now install x, encrypted */
	checksum = 0;
	p += pgpBnPutNew(&sec->s.x, p, cfb, &checksum);
	pgpChecksumPutNew(checksum, p, cfb);
	p += 2;
	pgpAssert((ptrdiff_t)len == p - sec->cryptkey);

	if (cfb)
		PGPFreeCFBContext(cfb);
	return 0;	/* Success */
}
#if PGP_MACINTOSH
#pragma global_optimizer reset
#endif

static size_t
dsaSecBufferLength(PGPSecKey const *seckey)
{
	DSAsecPlus const *sec = (DSAsecPlus *)seckey->priv;

	return sec->cklen;
}

static void
dsaSecToBuffer(PGPSecKey const *seckey, PGPByte *buf)
{
	DSAsecPlus const *sec = (DSAsecPlus *)seckey->priv;

	memcpy(buf, sec->cryptkey, sec->cklen);

	/* Return only algorithm-dependent portion */
}


/* Fill in secret key structure */
static void
dsaFillSecKey(PGPSecKey *seckey, DSAsecPlus *sec)
{
	seckey->pkAlg	            = kPGPPublicKeyAlgorithm_DSA;
	seckey->priv	            = sec;
	seckey->destroy             = dsaSecDestroy;
	seckey->pubkey              = dsaPubkey;
	seckey->islocked            = dsaIslocked;
	seckey->lockingalgorithm    = dsaLockingAlgorithm;
	seckey->s2ktype             = dsaS2KType;
	seckey->convertpassphrase   = dsaConvertPassphrase;
	seckey->unlock              = dsaUnlock;
	seckey->lock                = dsaLock;
	seckey->decrypt             = dsaDecrypt;
	seckey->maxdecrypted        = dsaSecMaxdecrypted;
	seckey->maxesk              = dsaSecMaxesk;
	seckey->maxsig              = dsaSecMaxsig;
	seckey->sign                = dsaSign;
	seckey->changeLock          = dsaChangeLock;
	seckey->bufferLength        = dsaSecBufferLength;
	seckey->toBuffer            = dsaSecToBuffer;
}


PGPSecKey *
dsaSecFromBuf(
	PGPContextRef	context,
	PGPByte const *	buf,
	size_t			size,
	PGPError *		error)
{
	PGPSecKey *seckey;
	DSAsecPlus *sec;
	PGPByte *cryptk;
	PGPError	err	= kPGPError_OutOfMemory;
	PGPMemoryMgrRef		mgr	= PGPGetContextMemoryMgr( context );
	PGPEnv *			pgpEnv = pgpContextGetEnvironment( context );

	bnInit();
	cryptk = (PGPByte *)pgpContextMemAlloc( context,
		size, kPGPMemoryMgrFlags_Clear);
	if (cryptk) {
		sec = (DSAsecPlus *)PGPNewSecureData( mgr, sizeof(*sec), 0 );
		if (sec) {
			pgpClearMemory( sec, sizeof(*sec) );
			sec->context	= context;
			
			seckey = (PGPSecKey *) pgpContextMemAlloc( context,
					sizeof(*seckey), kPGPMemoryMgrFlags_Clear);
			if (seckey) {
				seckey->context	= context;
			
				memcpy(cryptk, buf, size);
				bnBegin(&sec->s.p, mgr, FALSE );
				bnBegin(&sec->s.q, mgr, FALSE );
				bnBegin(&sec->s.g, mgr, FALSE );
				bnBegin(&sec->s.y, mgr, FALSE );
				bnBegin(&sec->s.x, mgr, TRUE );
				sec->cryptkey = cryptk;
				sec->cklen = sec->ckalloc = size;
				sec->locked = 1;
				/* We only need this to try unlocking... */
				seckey->pkAlg = kPGPPublicKeyAlgorithm_DSA;
				seckey->priv = sec;
				
				if (dsaUnlock(seckey, pgpEnv, NULL, 0, FALSE) >= 0) {
					if (dsaKeyTooBig (NULL, &sec->s)) {
						bnEnd(&sec->s.p);
						bnEnd(&sec->s.q);
						bnEnd(&sec->s.g);
						bnEnd(&sec->s.y);
						err = kPGPError_KeyTooLarge;
					} else {
						dsaFillSecKey(seckey, sec);
						*error = 0;
						return seckey;	/* Success! */
					}
				}

				/* Ka-boom.  Delete and free everything. */
				pgpClearMemory( cryptk,  size);
				pgpContextMemFree( context, seckey);
			}
			PGPFreeData( sec );			/* Wipes as it frees */
		}
		pgpContextMemFree( context, cryptk);
	}
	*error = err;
	return NULL;
}


/*
 * Generate an DSA secret key with prime of the specified number of bits.
 * Make callbacks to progress function periodically.
 * Secret key is returned in the unlocked form, with no passphrase set.
 * fastgen tells us to use canned primes if available.
 *
 * PGP attempts to acquire enough true random entropy in the randpool to
 * make the keys it generates fully random and unpredictable, even if the
 * RNG used to generate them were later found to have some weaknesses.  With
 * RSA keys it gets as many bits as the size of the modulus since the sizes
 * of the secret primes p and q will add up to the size of the modulus.
 * (This is slight overkill since the entropy in a random prime is less
 * than the entropy of a random number because not all numbers are prime.)
 *
 * With discrete log based keys, DSA and ElGamal, only the private exponent
 * x needs to be kept secret.  However, the public values are generated at
 * the same time as x, and are seeded ultimately from the same randpool.
 * These values could theoretically leak information about the state of the
 * randpool when they were generated, and therefore about x.  This would
 * require a very powerful attack which will probably never be possible,
 * but we want to defend against it.  One approach would simply be to acquire
 * as much additional entropy as is needed for the public values, but that
 * is wasteful.  The public values don't need to be random, we just want them
 * to be different among users.
 *
 * Instead, we create a "firewall" between the randpool and the public
 * key values.  We instantiate a second PGPRandomContext which is not
 * based on the randpool but is a simple pseudo RNG, and seed it with
 * a fixed number of bits from the true RNG.  We choose enough bits
 * for the seeding that different keys will not share the same public
 * values.  Only this fixed number of bits reflects the state of the
 * randpool, so we acquire that many bits of additional entropy before
 * beginning the keygen.  This second RNG, rcdummy below and in the
 * ElGamal keygen, is used to generate the public values for the discrete
 * log key.
 */
PGPSecKey *
dsaSecGenerate(
	PGPContextRef	context,
	unsigned bits, PGPBoolean fastgen,
	PGPRandomContext const *rc,
	int progress(void *arg, int c), void *arg, PGPError *error)
{
	PGPSecKey *seckey	= NULL;
	DSAsecPlus *sec;
	PGPRandomContext *rcdummy = NULL;
	BigNum h;
	BigNum e;
	unsigned qbits;
	int i;
	PGPByte dummyseed[DSADUMMYBITS/8];
	PGPMemoryMgrRef		mgr	= PGPGetContextMemoryMgr( context );
	PGPEnv *			pgpEnv = pgpContextGetEnvironment( context );

	*error = kPGPError_NoErr;

	/*
	 * Make bits a multiple of 64.  This is required by the standard,
	 * and also makes it likely that all the various crypto libraries,
	 * smart cards, etc. will be able to work with the keys.
	 */
	bits = 64 * ((bits + 63) / 64);

	/* Initialize local pointers (simplify cleanup below) */
	seckey = NULL;
	sec = NULL;
	bnBegin(&h, mgr, FALSE );
	bnBegin(&e, mgr, FALSE );
	
	/* Limit the size we will generate at this time */
	if (bits > MAX_DSA_PRIME_BITS) {
		*error = kPGPError_PublicKeyTooLarge;
		goto done;
	}



	/* Allocate data structures */
	seckey = (PGPSecKey *)pgpContextMemAlloc( context,
		sizeof(*seckey), kPGPMemoryMgrFlags_Clear);
	if (!seckey)
		goto memerror;
	seckey->context	= context;
	sec = (DSAsecPlus *)PGPNewSecureData( mgr, sizeof(*sec), 0 );
	if (!sec)
		goto memerror;
	pgpClearMemory( sec, sizeof(*sec) );
	sec->context	= context;
	
	bnBegin(&sec->s.p, mgr, FALSE );
	bnBegin(&sec->s.q, mgr, FALSE );
	bnBegin(&sec->s.g, mgr, FALSE );
	bnBegin(&sec->s.y, mgr, FALSE );
	bnBegin(&sec->s.x, mgr, TRUE );

	/* Use fixed primes and generator if in our table */
	if (fastgen) {
		PGPByte const *fixedp, *fixedq;
		size_t fixedplen, fixedqlen;
		if (pgpDSAfixed (bits, &fixedp, &fixedplen, &fixedq, &fixedqlen) > 0) {
			bnInsertBigBytes (&sec->s.q, fixedq, 0, fixedqlen);
			if (progress != NULL)
				progress(arg, ' ');
			bnInsertBigBytes (&sec->s.p, fixedp, 0, fixedplen);
			if (progress != NULL)
				progress(arg, ' ');
			qbits = bnBits (&sec->s.q);
			goto choose_g;
		}
	}

	/* Set up and seed local random number generator for p and q */
	rcdummy = pgpPseudoRandomCreate ( rc->context );
	if (!rcdummy)
		goto memerror;
	pgpRandomGetBytes (rc, dummyseed, sizeof(dummyseed));
	pgpRandomAddBytes (rcdummy, dummyseed, sizeof(dummyseed));

	/*
	 * Choose a random starting place for q, in the high end of the range
	 */
	if (bits <= 1024)
		qbits = 160;	/* Follow the published standard */
	else
		qbits = pgpDiscreteLogQBits(bits);
	if (pgpBnGenRand(&sec->s.q, rcdummy, qbits, 0xFF, 1, qbits-9) < 0)
		goto nomem;
	/* And search for a prime */
	i = bnPrimeGen(&sec->s.q, NULL, progress, arg, 0);
	if (i < 0)
		goto nomem;
	if (progress != NULL)
		progress(arg, ' ');

	/* ...and now a random start for p (we discard qbits bits of it) */
	(void)bnSetQ(&sec->s.p, 0);
	if (pgpBnGenRand(&sec->s.p, rcdummy, bits, 0xC0, 1, bits-qbits) < 0)
		goto nomem;

	/* Temporarily double q */
	if (bnLShift(&sec->s.q, 1) < 0)
		goto nomem;

	/* Set p = p - (p mod q) + 1, i.e. congruent to 1 mod 2*q */
	if (bnMod(&e, &sec->s.p, &sec->s.q) < 0)
		goto nomem;
	if (bnSub(&sec->s.p, &e) < 0 || bnAddQ(&sec->s.p, 1) < 0)
		goto nomem;

	/* And search for a prime, 1+2kq for some k */
	i = bnPrimeGenStrong(&sec->s.p, &sec->s.q, progress, arg);
	if (i < 0)
		goto nomem;
	if (progress != NULL)
		progress(arg, ' ');

	/* Reduce q again */
	bnRShift(&sec->s.q, 1);

	/* May get here directly from above if fixed primes are used */
choose_g:

	/* Now hunt for a suitable g - first, find (p-1)/q */
	if (bnDivMod(&e, &h, &sec->s.p, &sec->s.q) < 0)
		goto nomem;
	/* e is now the exponent (p-1)/q, and h is the remainder (one!) */
	pgpAssert(bnBits(&h)==1);

	if (progress != NULL)
		progress(arg, '.');

	/* Search for a suitable h */
	if (bnSetQ(&h, 2) < 0 ||
	    bnTwoExpMod(&sec->s.g, &e, &sec->s.p) < 0)
		goto nomem;
	while (bnBits(&sec->s.g) < 2) {
		if (progress != NULL)
			progress(arg, '.');
		if (bnAddQ(&h, 1) < 0 ||
		    bnExpMod(&sec->s.g, &h, &e, &sec->s.p) < 0)
			goto nomem;
	}
	if (progress != NULL)
		progress(arg, ' ');

	/* Choose a random 0 < x < q of reasonable size as secret key */
	if (pgpBnGenRand(&sec->s.x, rc, qbits + 8, 0, 0, qbits) < 0 ||
	    bnMod(&sec->s.x, &sec->s.x, &sec->s.q) < 0)
		goto nomem;
	/* prob. failure < 2^-140 is awful unlikely... */
	pgpAssert(bnBits(&sec->s.x) > 20);

	/* And calculate g**x as public key */
	if (bnExpMod(&sec->s.y, &sec->s.g, &sec->s.x, &sec->s.p) < 0)
		goto nomem;

	/* And that's it... success! */

	/* Fill in structs */
	sec->cryptkey = NULL;
	sec->ckalloc = sec->cklen = 0;
	sec->locked = 0;
	dsaFillSecKey(seckey, sec);

	/* Fill in cryptkey structure, unencrypted */
	dsaChangeLock (seckey, pgpEnv, NULL, NULL, 0, kPGPStringToKey_Simple);

	goto done;

nomem:
	bnEnd(&sec->s.p);
	bnEnd(&sec->s.q);
	bnEnd(&sec->s.g);
	bnEnd(&sec->s.y);
	bnEnd(&sec->s.x);
	/* Fall through */
memerror:
	if ( IsntNull( seckey ) )
		pgpContextMemFree( context, seckey);
	if ( IsntNull( sec ) )
		PGPFreeData( sec );			/* Wipes as it frees */
	seckey = NULL;
	*error = kPGPError_OutOfMemory;
	/* Fall through */
done:
	bnEnd(&h);
	bnEnd(&e);

	if (rcdummy)
	{
		pgpRandomDestroy (rcdummy);
	}
	
	return seckey;
}

