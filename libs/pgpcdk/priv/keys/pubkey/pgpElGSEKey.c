/*
 * pgpElGSEKey.c
 * El Gamal encryption
 *
 * $Id: pgpElGKey.c,v 1.56.6.1 1999/06/04 00:28:55 heller Exp $
 */
#define ELGSIGS 1
#include "pgpConfig.h"
#include <string.h>
#include <stddef.h>

#include "pgpSDKBuildFlags.h"
#include "pgpDebug.h"
#include "pgpElGSEKey.h"
#include "pgpKeyMisc.h"
#include "bn.h"
#include "bnprime.h"
#include "pgpCFBPriv.h"
#include "pgpSymmetricCipherPriv.h"
#include "pgpHashPriv.h"
#include "pgpFixedKey.h"
#include "bngermain.h"
#include "pgpHash.h"
#include "pgpMem.h"
#include "pgpErrors.h"
#include "bnprime.h"
#include "pgpPubKey.h"
#include "pgpRandomX9_17.h"
#include "pgpStr2Key.h"
#include "pgpContext.h"
#include "pgpEnv.h"

#ifndef NULL
#define NULL 0
#endif



//BEGIN ElGamal Sign SUPPORT - Imad R. Faiad

#define ASSERTelgSE(alg) pgpAssert((ALGMASK(alg))==kPGPPublicKeyAlgorithm_ElGamalSE)
//END ElGamal Sign SUPPORT

typedef struct ELGpub
{
	BigNum p;		/* Public prime */
	BigNum g;		/* Public generator */
	BigNum y;		/* Public key, g**x mod p */
} ELGpub;

typedef struct ELGsec
{
	BigNum p;		/* Copy of public parameters */
	BigNum g;
	BigNum y;
	BigNum x;		/* Secret key, discrete log of y */
} ELGsec;

/* A PGPSecKey's priv points to this, an ELGsec plus the encrypted form... */
/* This struct is always allocated using PGPNewSecureData */
typedef struct ELGsecPlus
{
	PGPContextRef	context;
	
	ELGsec s;
	PGPByte *cryptkey;
	size_t ckalloc, cklen;
	int locked;
} ELGsecPlus;

/** Public key functions **/

static void
elgSEPubDestroy(PGPPubKey *pubkey)
{
	ELGpub *pub = (ELGpub *)pubkey->priv;
	PGPContextRef	context	= pubkey->context;

	ASSERTelgSE(pubkey->pkAlg);
	
	bnEnd(&pub->p);
	bnEnd(&pub->g);
	bnEnd(&pub->y);
	pgpClearMemory( pub,  sizeof(pub));
	pgpContextMemFree( context, pub);
	pgpClearMemory( pubkey,  sizeof(pubkey));
	pgpContextMemFree( context, pubkey);
}

/*
 * Return the largest possible PGPESK size for a given key.
 * Must hold two numbers up to p in size.
 */
static size_t
elgSEPubMaxesk(PGPPubKey const *pubkey, PGPPublicKeyMessageFormat format)
{
	ELGpub const *pub = (ELGpub *)pubkey->priv;

	ASSERTelgSE(pubkey->pkAlg);
	if (format == kPGPPublicKeyMessageFormat_PGP)
		return 2*( 2 + bnBytes(&pub->p) );
	else if (format == kPGPPublicKeyMessageFormat_PKCS1 ||
			 format == kPGPPublicKeyMessageFormat_IKE)
		return 2*( bnBytes(&pub->p) );

	pgpAssert(0);
	return 0;
}

/*
 * Return the size of the buffer needed, worst-case, for the decrypted
 * output.  A trivially padded key (random padding length = 0)
 * can just be 0 2 0 <key>.
 */
static size_t
elgSEPubMaxdecrypted(PGPPubKey const *pubkey, PGPPublicKeyMessageFormat format)
{
	ELGpub const *pub = (ELGpub *)pubkey->priv;
	size_t size;

	ASSERTelgSE(pubkey->pkAlg);
	(void) format;

	size = bnBytes(&pub->p);
	return size < 3 ? 0 : size-3;
}


static size_t
elgSEPubMaxsig(PGPPubKey const *pubkey, PGPPublicKeyMessageFormat format)
{
#ifndef ELGSIGS
	(void)pubkey;
	(void)format;
	return kPGPError_PublicKeyUnimplemented;
#else
	ELGpub const *pub = (ELGpub *)pubkey->priv;

	(void)format;
	ASSERTelgSE(pubkey->pkAlg);
	return 2*( 2 + bnBytes(&pub->p) );
#endif
}


/*
 * Given a buffer of at least "maxesk" bytes, make an PGPESK
 * into it and return the size of the PGPESK, or <0.
 *
 * ElGamal encryption is a simple variant on non-interactove
 * Diffie-Hellman.  The recipient publishes g, p, and y = g**x mod p.
 * the sender picks a random xx, computes yy = g**xx mod p, and
 * the shared secret z = y**xx mod p = yy**x mod p = g**(x*xx) mod p, then
 * then sends z*m, where m is the message.  (Padded in the usual
 * PKCS manner.)
 */
static int
elgSEEncrypt(PGPPubKey const *pubkey, PGPByte const *key,
           size_t keylen, PGPByte *esk, size_t *esklen,
           PGPRandomContext const *rc, PGPPublicKeyMessageFormat format)
{
#if PGP_ENCRYPT_DISABLE /* [ */

	(void)pubkey;
	(void)key;
	(void)keylen;
	(void)esk;
	(void)esklen;
	(void)rc;
	(void)format;
	return kPGPError_FeatureNotAvailable;

#else /* PGP_ENCRYPT_DISABLE */  /* ]  [ */

	ELGpub const *pub = (ELGpub *)pubkey->priv;
	BigNum xx;		/* Random exponent */
	BigNum yy;		/* g**xx mod p */
	BigNum z;		/* y**xx mod p */
	unsigned t;
	unsigned xxbits, pbytes;
	int i;
	PGPMemoryMgrRef		mgr	= NULL;
	
	mgr	= PGPGetContextMemoryMgr( pubkey->context );

	/* We don't need this argument, although other algorithms may... */
	(void)format;
	
	/*
	 * Of these values, only xx is inherently sensitive, but others may
	 * hold some intermediate results we would prefer not to have leaked.
	 * So mark all as sensitive.
	 */
	bnBegin(&xx, mgr, TRUE );
	bnBegin(&yy, mgr, TRUE );
	bnBegin(&z, mgr, TRUE );

	ASSERTelgSE(pubkey->pkAlg);
	t = bnBits(&pub->p);
	if (t > 0xffff)
		return kPGPError_PublicKeyTooLarge;
	pbytes = (t + 7) / 8;
	if (keylen > pbytes)
		return kPGPError_PublicKeyTooSmall; /* data too big for pubkey */

	if( format == kPGPPublicKeyMessageFormat_PGP ) {
		/* Add checksum to key, place temporarily in esk buffer */
		t = 0;
		esk[0] = key[0];
		for (i = 1; i < (int)keylen; i++)
			t += esk[i] = key[i];
		esk[keylen] = (PGPByte)(t >> 8 & 255);
		esk[keylen+1] = (PGPByte)(t & 255);
		keylen += 2;
		key = esk;
	}

	/* Choose the random xx value to be used for this encryption */
	xxbits = pgpDiscreteLogExponentBits(bnBits(&pub->p))*3/2;
	if (pgpBnGenRand(&xx, rc, xxbits, 0, 0, xxbits) < 0)
		goto nomem;

	/* Do the two exponentiations necessary to compute yy and z */
	if (bnExpMod(&yy, &pub->g, &xx, &pub->p) < 0 ||
	    bnExpMod(&z,  &pub->y, &xx, &pub->p) < 0)
		goto nomem;

	/* Re-use xx to hold the PKCS-padded conventional key */
	if (pgpPKCSPack(&xx, key, keylen, PKCS_PAD_ENCRYPTED, pbytes, rc)<0)
		goto nomem;
	pgpAssert (bnCmp(&xx, &pub->p) < 0);
	
	/* Compute xx*z mod p, the encrypted session key we will transmit */
	if (bnMul(&z, &z, &xx) < 0 ||
	    bnMod(&z, &z, &pub->p) < 0)
		goto nomem;

	/* Pack the two values into the esk, first yy and then k+z */
	t  = pgpBnPutFormatted(&yy, esk, pbytes, format);
	t += pgpBnPutFormatted(&z, esk+t, pbytes, format);
	if (esklen)
		*esklen = (size_t)t;
	
	i = 0;
	goto done;
nomem:
	i = kPGPError_OutOfMemory;
done:
	bnEnd(&z);
	bnEnd(&yy);
	bnEnd(&xx);
	return i;

#endif /* PGP_ENCRYPT_DISABLE */ /* ] */
}

#ifdef ELGSIGS
/*
 * Helper routine to pack a hash into a buffer with DER prefix
 * Return size of packed data
 */
static unsigned
elgSEPack (
PGPByte *buf, unsigned buflen,
PGPHashVTBL const *h, PGPByte const *hash)
{
	unsigned t = h->DERprefixsize + h->hashsize;
	pgpAssert (t <= buflen);
	memcpy(buf, h->DERprefix, h->DERprefixsize);
	memcpy(buf+h->DERprefixsize, hash, h->hashsize);
	return t;
}
#endif

/*
 * Return 1 if (sig,siglen) is a valid MPI which signs
 * (hash, hashlen).
 * Not implementing ElGamal signatures, using DSS.
 */
static int
elgSEVerify(PGPPubKey const *pubkey, PGPByte const *sig,
	size_t siglen, PGPHashVTBL const *h, PGPByte const *hash,
	PGPPublicKeyMessageFormat format)
{
#ifndef ELGSIGS
	(void)pubkey;
	(void)sig;
	(void)siglen;
	(void)h;
	(void)hash;
	(void)format;
	return kPGPError_PublicKeyUnimplemented;
#else
	/* Check an El Gamal signature */
	ELGpub const *pub = (ELGpub *)pubkey->priv;
	BigNum a,b,yaab;
	//BEGIN LARGE HASHES SUPPORT - Imad R. Faiad
	//PGPByte buf[64];	/* largest hash size + DER prefix */
	PGPByte buf[84];
	//END LARGE HASHES SUPPORT
	int i;
	size_t off;
	unsigned t;
	PGPMemoryMgrRef	mgr	= PGPGetContextMemoryMgr( pubkey->context );

	(void)format;

	bnBegin(&a, mgr, FALSE);
	bnBegin(&b, mgr, FALSE);
	bnBegin(&yaab, mgr, FALSE);

	ASSERTelgSE(pubkey->pkAlg);

	/* sig holds two values.  Get first, a, from sig. */
	off = 0;
	i = pgpBnGetFormatted(&a, sig+off, siglen-off, bnBytes(&pub->p), format);
	if (i <= 0)
		goto fail;
	/* Get 2nd value, b, from SIG */
	off += i;
	i = pgpBnGetFormatted(&b, sig+off, siglen-off, bnBytes(&pub->p), format);
	if (i <= 0)
		goto fail;
	off += i;
	if (off != siglen) {
		i = kPGPError_BadSignatureSize;
		goto done;
	}
	
	/* Compute y**a * a**b, put in a */
	if (bnExpMod(&yaab, &pub->y, &a, &pub->p) < 0 ||
	    bnExpMod(&a, &a, &b, &pub->p)         < 0 ||
	    bnMul(&yaab, &a, &yaab)               < 0 ||
	    bnMod(&yaab, &yaab, &pub->p)          < 0)
		goto nomem;

	/* Reconstruct PKCS packed hash as b */
	t = elgSEPack(buf, sizeof(buf), h, hash);
	i = pgpPKCSPack(&b, buf, t, PKCS_PAD_SIGNED, bnBytes(&pub->p),
			(PGPRandomContext const *)NULL);
	pgpClearMemory( buf,  t);
	if (i < 0)
		goto nomem;

	/* Calculate g**M, leave in a */
	if (bnExpMod(&a, &pub->g, &b, &pub->p) < 0)
		goto nomem;

	/* Compare y**a * a**b with g**M, should be equal */
	i = bnCmp(&a, &yaab) == 0;
	goto done;
nomem:
	i = kPGPError_OutOfMemory;
	goto done;
fail:
	if (!i)
		i = kPGPError_BadSignatureSize;
	goto done;
done:
	bnEnd(&yaab);
	bnEnd(&b);
	bnEnd(&a);

	return i;
#endif
}

/*
 * Turn a PGPPubKey into the algorithm-specific parts of a public key.
 * A public key's ELG-specific part is:
 *
 *  0      2+i  MPI for prime
 * 2+i     2+t  MPI for generator
 * 4+i+t   2+u	MPI for public key
 * 6+i+t+u
 */
static size_t
elgSEPubBufferLength(PGPPubKey const *pubkey)
{
	ELGpub const *pub = (ELGpub *)pubkey->priv;

	return 6 + bnBytes(&pub->p) + bnBytes(&pub->g) +
		bnBytes(&pub->y);
}

static void
elgSEPubToBuffer(PGPPubKey const *pubkey, PGPByte *buf)
{
	ELGpub const *pub = (ELGpub *)pubkey->priv;
	unsigned off;

	off = 0;
	off += pgpBnPutPlain(&pub->p, buf+off);
	off += pgpBnPutPlain(&pub->g, buf+off);
	off += pgpBnPutPlain(&pub->y, buf+off);
}


/* A little helper function that's used twice */
static void
elgSEFillPubkey(PGPPubKey *pubkey, ELGpub *pub)
{
	pubkey->next	 = NULL;
	pubkey->pkAlg	 = kPGPPublicKeyAlgorithm_ElGamalSE;
	pubkey->priv	 = pub;
	pubkey->destroy  = elgSEPubDestroy;
	pubkey->maxesk   = elgSEPubMaxesk;
	pubkey->maxdecrypted   = elgSEPubMaxdecrypted;
	pubkey->maxsig   = elgSEPubMaxsig;
	pubkey->encrypt  = elgSEEncrypt;
	pubkey->verify   = elgSEVerify;
	pubkey->bufferLength  = elgSEPubBufferLength;
	pubkey->toBuffer = elgSEPubToBuffer;
}


/*
 * Turn the algorithm-specific parts of a public key into a PGPPubKey
 * structure.  A public key's ELG-specific part is:
 *
 *  0      2+i  MPI for prime
 * 2+i     2+t  MPI for generator
 * 4+i+t   2+u	MPI for public key
 * 6+i+t+u
 */
PGPPubKey *
elgSEPubFromBuf(
	PGPContextRef	context,
	PGPByte const *buf, size_t size, PGPError *error)
{
	PGPPubKey *pubkey;
	ELGpub *pub;
	unsigned i, t, u;
	int v;
	PGPError	err	= kPGPError_OutOfMemory;
	PGPMemoryMgrRef		mgr	= PGPGetContextMemoryMgr( context );
	
	bnInit();

	v = pgpBnParse(buf, size, 3, &i, &t, &u);
	if (v < 0) {
		*error = (PGPError)v;
		return NULL;
	}
	if ((buf[t-1] & 1) == 0) {	/* Too small or even prime p */
		*error = kPGPError_MalformedKeyComponent;
		return NULL;
	}

	pub = (ELGpub *)pgpContextMemAlloc( context,
			sizeof(*pub), kPGPMemoryMgrFlags_Clear);
	if (pub) {
		pubkey = (PGPPubKey *)pgpContextMemAlloc( context,
			sizeof(*pubkey), kPGPMemoryMgrFlags_Clear);
		if (pubkey) {
			pubkey->context	= context;
			bnBegin(&pub->p, mgr, FALSE );
			bnBegin(&pub->g, mgr, FALSE );
			bnBegin(&pub->y, mgr, FALSE );
			if (bnInsertBigBytes(&pub->p, buf+i+2, 0, t-i-2) >= 0
			    && bnInsertBigBytes(&pub->g, buf+t+2, 0,
						u-t-2) >= 0
			    && bnInsertBigBytes(&pub->y, buf+u+2, 0,
						v-u-2) >= 0)
			{
				elgSEFillPubkey(pubkey, pub);

				*error = kPGPError_NoErr;
				return pubkey;
			}
			else
			{
				err	= kPGPError_UnknownError;
			}
			
			/* Failed = clean up and return NULL */
			bnEnd(&pub->p);
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
elgSEPubKeyPrefixSize(PGPByte const *buf, size_t size)
{
	return pgpBnParse(buf, size, 3, NULL, NULL, NULL);
}


/** Secret key functions **/

static void
elgSESecDestroy(PGPSecKey *seckey)
{
	ELGsecPlus *sec = (ELGsecPlus *)seckey->priv;
	PGPContextRef		context;

	pgpAssertAddrValid( seckey, PGPSecKey );
	context	= seckey->context;
	
	pgpAssert( pgpContextIsValid( context ) );

	ASSERTelgSE(seckey->pkAlg);
	bnEnd(&sec->s.p);
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
elgSEPubkey(
	PGPSecKey const *seckey)
{
	ELGsecPlus const *sec = (ELGsecPlus *)seckey->priv;
	PGPPubKey *pubkey;
	ELGpub *pub;
	PGPContextRef		context;
	PGPMemoryMgrRef		mgr	= NULL;

	pgpAssertAddrValid( seckey, PGPSecKey );
	context	= seckey->context;
	mgr	= PGPGetContextMemoryMgr( context );

	ASSERTelgSE(seckey->pkAlg);
	pub = (ELGpub *)pgpContextMemAlloc( context,
		sizeof(*pub), kPGPMemoryMgrFlags_Clear);
	if (pub) {
		pubkey = (PGPPubKey *)pgpContextMemAlloc( context,
			sizeof(*pubkey), kPGPMemoryMgrFlags_Clear);
		if (pubkey) {
			pubkey->context	= context;
			
			bnBegin(&pub->p, mgr, FALSE );
			bnBegin(&pub->g, mgr, FALSE );
			bnBegin(&pub->y, mgr, FALSE );
			if (bnCopy(&pub->p, &sec->s.p) >= 0
			    && bnCopy(&pub->g, &sec->s.g) >= 0
			    && bnCopy(&pub->y, &sec->s.y) >= 0)
			{
				elgSEFillPubkey(pubkey, pub);
				pubkey->pkAlg = seckey->pkAlg;
				memcpy(pubkey->keyID, seckey->keyID,
				       sizeof(pubkey->keyID));
				return pubkey;
			}
			/* Failed = clean up and return NULL */
			bnEnd(&pub->p);
			bnEnd(&pub->g);
			bnEnd(&pub->y);
			pgpContextMemFree( context, pubkey);
		}
		pgpContextMemFree( context, pub);
	}
	return NULL;
}

/*
 * Yes, there *is* a reason that this is a function and no a variable.
 * On a hardware device with an automatic timeout,
 * it actually might need to do some work to find out.
 */
static int
elgSEIslocked(PGPSecKey const *seckey)
{
	ELGsecPlus const *sec = (ELGsecPlus *)seckey->priv;

	ASSERTelgSE(seckey->pkAlg);
	return sec->locked;
}


/*
 * Return the algorithm and (symmetric) key size used for locking/unlocking
 * the secret key.
 */
static PGPError
elgSELockingAlgorithm(
	PGPSecKey const *seckey,
	PGPCipherAlgorithm *pAlg,
	PGPSize *pAlgKeySize
	)
{
	ELGsecPlus *sec = (ELGsecPlus *)seckey->priv;
	PGPCipherVTBL const *cipher;
	PGPByte alg;
	int i;

	ASSERTelgSE(seckey->pkAlg);

	if( IsntNull( pAlg ) )
		*pAlg = (PGPCipherAlgorithm) 0;
	if( IsntNull( pAlgKeySize ) )
		*pAlgKeySize = (PGPSize) 0;

	/* Check packet for basic consistency */
	i = pgpBnParse(sec->cryptkey, sec->cklen, 3, NULL, NULL, NULL);
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
elgSES2KType(
	PGPSecKey const *seckey,
	PGPStringToKeyType *s2kType
	)
{
	ELGsecPlus *sec = (ELGsecPlus *)seckey->priv;
	PGPByte alg;
	int i;

	ASSERTelgSE(seckey->pkAlg);

	/* note that 0 is a valid type, but use it as default anyway */
	if( IsntNull( s2kType ) )
		*s2kType = (PGPStringToKeyType) 0;

	/* Check packet for basic consistency */
	i = pgpBnParse(sec->cryptkey, sec->cklen, 3, NULL, NULL, NULL);
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
elgSEConvertPassphrase(PGPSecKey *seckey, PGPEnv const *env,
	  char const *phrase, PGPSize plen, PGPByte *outbuf)
{
	ELGsecPlus *sec = (ELGsecPlus *)seckey->priv;
	PGPStringToKey *s2k;
	PGPByte alg;
	PGPBoolean hasS2K;
	PGPCipherVTBL const *cipher;
	int i;

	ASSERTelgSE(seckey->pkAlg);
	pgpAssert (IsntNull( outbuf ) );

	/* Check packet for basic consistency */
	i = pgpBnParse(sec->cryptkey, sec->cklen, 3, NULL, NULL, NULL, NULL);
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
	pgpS2Kdestroy(s2k);

	return kPGPError_NoErr;
}


/*
 * Try to decrypt the secret key wih the given passphrase.  Returns >0
 * if it was the correct passphrase. =0 if it was not, and <0 on error.
 * Does not alter the key even if it's the wrong passphrase and already
 * unlocked.  A NULL passphrae will work if the key is unencrypted.
 * 
 * A (secret) key's ELG-specific part is:
 *
 *  0                2+u  MPI for prime
 *  2+u              2+v  MPI for generator
 *  4+u+v	     2+w  MPI for public key
 *  6+u+v+w          1    Encryption algorithm (0 for none, 1 for IDEA)
 *  7+u+v+w          t    Encryption IV: 0 or 8 bytes
 *  7+t+u+v+w        2+x  MPI for x (discrete log of public key)
 *  9+t+u+v+w+x      2    Checksum
 * 11+t+u+v+w+x
 *
 * Actually, that's the old-style, if pgpS2KoldVers is true.
 * If it's false, the algorithm is 255, and is followed by the
 * algorithm, then the (varaible-length, self-delimiting)
 * string-to-key descriptor.
 */

static int
elgSEUnlock(PGPSecKey *seckey, PGPEnv const *env,
	  char const *phrase, size_t plen, PGPBoolean hashedPhrase)
{
	ELGsecPlus *sec = (ELGsecPlus *)seckey->priv;
	BigNum x;
	PGPCFBContext *cfb = NULL;
	unsigned v;
	unsigned alg;
	unsigned checksum;
	int i;
	PGPMemoryMgrRef		mgr	= NULL;
	mgr	= PGPGetContextMemoryMgr( seckey->context );

	ASSERTelgSE(seckey->pkAlg);
	bnInit();

	/* Check packet for basic consistency */
	i = pgpBnParse(sec->cryptkey, sec->cklen, 3, &v, NULL, NULL, NULL);
	if (i < 0)
		return i;

	/* OK, read the public data */
	i = pgpBnGetPlain(&sec->s.p, sec->cryptkey+v, sec->cklen-v);
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
	if (!phrase != !alg)
		return 0;

	i = pgpCipherSetup(sec->cryptkey + v, sec->cklen - v, phrase, plen,
					   hashedPhrase, env, &cfb);
	if (i < 0)
		goto done;
	v += i;

	checksum = 0;
	bnBegin(&x, mgr, TRUE );
	i = pgpBnGetNew(&x, sec->cryptkey + v, sec->cklen - v, cfb, &checksum);
	if (i <= 0)
		goto badpass;
	v += i;
	if (bnCmp(&x, &sec->s.p) >= 0)
		goto badpass;	/* Wrong passphrase: x must be < p */

	/* Check that we ended in the right place */
	if (sec->cklen - v != 2) {
		i = kPGPError_KEY_LONG;
		goto done;
	}
	checksum &= 0xffff;
	if (checksum != pgpChecksumGetNew(sec->cryptkey + v, cfb))
		goto badpass;

	/*
	 * Note that the "nomem" case calls bnEnd()
	 * more than once, but this is guaranteed harmless.
 	 */
	if (bnCopy(&sec->s.x, &x) < 0)
		goto nomem;
	bnEnd(&x);

	i = 1;	/* Decrypted! */
	sec->locked = 0;
	if (cfb)
		PGPFreeCFBContext(cfb);
	return 1;	/* Decrypted */

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
elgSELock(PGPSecKey *seckey)
{
	ELGsecPlus *sec = (ELGsecPlus *)seckey->priv;

	ASSERTelgSE(seckey->pkAlg);
	sec->locked = 1;
	/* bnEnd is documented as also doing a bnBegin */
	bnEnd(&sec->s.x);
}

static size_t
elgSESecMaxdecrypted(PGPSecKey const *seckey, PGPPublicKeyMessageFormat format);



/*
 * Try to decrypt the given esk.  If the key is locked, try the given
 * passphrase.  It may or may not leave the key unlocked in such a case.
 * (Some hardware implementations may insist on a password per usage.)
 */
static int
elgSEDecrypt(PGPSecKey *seckey, PGPEnv const *env,
		   PGPByte const *esk, size_t esklen,
		   PGPByte *key, size_t *keylen,
		   char const *phrase, size_t plen,
		   PGPPublicKeyMessageFormat format)
{
#if PGP_DECRYPT_DISABLE /* [ */

	(void)seckey;
	(void)env;
	(void)esk;
	(void)esklen;
	(void)key;
	(void)keylen;
	(void)phrase;
	(void)plen;
	(void)format;
	return kPGPError_FeatureNotAvailable;

#else /* PGP_DECRYPT_DISABLE */  /* ]  [ */

	ELGsecPlus *sec = (ELGsecPlus *)seckey->priv;
	BigNum k, yy;
	int i, j;
	unsigned t, pbytes;
	size_t len;
	size_t off;
	PGPMemoryMgrRef		mgr	= NULL;
	mgr	= PGPGetContextMemoryMgr( seckey->context );

	ASSERTelgSE(seckey->pkAlg);
	if (sec->locked) {
		i = elgSEUnlock(seckey, env, phrase, plen, FALSE);
		if (i <= 0)
			return i ? i : kPGPError_KeyIsLocked;
		pgpAssert(!sec->locked);
	}

	bnBegin(&k, mgr, TRUE );
	bnBegin(&yy, mgr, TRUE );
	pbytes = (bnBits(&sec->s.p) + 7) / 8;

	/* ESK holds two values.  Get first, yy, from ESK. */
	off = 0;
	i = pgpBnGetFormatted(&yy, esk+off, esklen-off, pbytes, format);
	if (i <= 0)
		goto fail;
	/* Get 2nd value, k, from ESK */
	off += i;
	i = pgpBnGetFormatted(&k, esk+off, esklen-off, pbytes, format);
	if (i <= 0)
		goto fail;
	off += i;
	if (off != esklen) {
		i = kPGPError_BadSessionKeySize;
		goto done;
	}
	
	/* Calculate yy = yy**x mod p, which is what is multiplied by k */
	if (bnExpMod(&yy, &yy, &sec->s.x, &sec->s.p) < 0)
		goto nomem;

	/* Set k = k / (new)yy , revealing PKCS padded session key */
	if (bnInv(&yy, &yy, &sec->s.p) < 0 ||
		bnMul(&k, &k, &yy) < 0 ||
		bnMod(&k, &k, &sec->s.p) < 0) {
			goto nomem;
	}
	bnEnd(&yy);
	
	/* k is now suitable for unpacking */
	len = elgSESecMaxdecrypted(seckey, format);
	i = pgpPKCSUnpack (key, len, &k, PKCS_PAD_ENCRYPTED, pbytes);
	bnEnd(&k);
	if (i < 0)
		return i;

	if (format == kPGPPublicKeyMessageFormat_PGP) {
		/* Check checksum */
		t = 0;
		for (j = 1; j < i-2; j++)
			t += key[j];
		if (t != ((unsigned)key[i-2]<<8) + key[i-1])
			return kPGPError_CorruptData;
		pgpClearMemory(key+i-2, 2);

		/* The actual key */
		if (keylen)
			*keylen = (size_t)i-2;
	} else {
		if( keylen)
			*keylen = (size_t)i;
	}
	
	return 0;

fail:
	if (!i)
		i = kPGPError_BadSessionKeySize;
	goto done;
nomem:
	i = kPGPError_OutOfMemory;
	goto done;
done:
	bnEnd(&yy);
	bnEnd(&k);
	return i;

#endif /* PGP_DECRYPT_DISABLE */ /* ] */
}



/*
 * Return the size of the buffer needed, worst-case, for the decrypted
 * output.  A trivially padded key (random padding length = 0)
 * can just be 0 2 0 <key>.
 */
static size_t
elgSESecMaxdecrypted(PGPSecKey const *seckey, PGPPublicKeyMessageFormat format)
{
	ELGsecPlus const *sec = (ELGsecPlus *)seckey->priv;
	size_t size;

	ASSERTelgSE(seckey->pkAlg);
	(void) format;

	size = bnBytes(&sec->s.p);
	return size < 3 ? 0 : size-3;
}

static size_t
elgSESecMaxesk(PGPSecKey const *seckey, PGPPublicKeyMessageFormat format)
{
	ELGsecPlus const *sec = (ELGsecPlus *)seckey->priv;

	ASSERTelgSE(seckey->pkAlg);
	if (format == kPGPPublicKeyMessageFormat_PGP)
		return 2*( 2 + bnBytes(&sec->s.p) );
	else if (format == kPGPPublicKeyMessageFormat_PKCS1 ||
			 format == kPGPPublicKeyMessageFormat_IKE)
		return 2*( bnBytes(&sec->s.p) );

	pgpAssert(0);
	return 0;
}

static size_t
elgSESecMaxsig(PGPSecKey const *seckey, PGPPublicKeyMessageFormat format)
{
#ifndef ELGSIGS
	(void)seckey;
	(void)format;
	return kPGPError_PublicKeyUnimplemented;
#else
	ELGsecPlus const *sec = (ELGsecPlus *)seckey->priv;

	(void)format;
	ASSERTelgSE(seckey->pkAlg);
	return 2*( 2 + bnBytes(&sec->s.p) );
#endif
}

static int
elgSESign(PGPSecKey *seckey, PGPHashVTBL const *h, PGPByte const *hash,
	PGPByte *sig, size_t *siglen, PGPRandomContext const *rc,
	PGPPublicKeyMessageFormat format)
{
#ifndef ELGSIGS
	(void)seckey;
	(void)h;
	(void)hash;
	(void)sig;
	(void)siglen;
	(void)rc;
	(void)format;
	return kPGPError_PublicKeyUnimplemented;
#else
	/* Calculate an El Gamal signature */

	ELGsecPlus *sec = (ELGsecPlus *)seckey->priv;
	BigNum pm1, x1, a, bn, xk, xa;
	unsigned t;
	unsigned x1bits;
	int i;
	PGPMemoryMgrRef		mgr	= NULL;
	
	mgr	= PGPGetContextMemoryMgr( seckey->context );

	/* We don't need this argument, although other algorithms may... */
	(void)format;

	ASSERTelgSE(seckey->pkAlg);
	if (sec->locked)
		return kPGPError_KeyIsLocked;
	if (h->DERprefixsize + h->hashsize  > elgSESecMaxsig(seckey, format))
		return kPGPError_PublicKeyTooSmall;
       
	bnBegin(&pm1, mgr, TRUE);
	bnBegin(&x1, mgr, TRUE);
	bnBegin(&a, mgr, TRUE);
	bnBegin(&bn, mgr, TRUE);
	bnBegin(&xk, mgr, TRUE);
	bnBegin(&xa, mgr, TRUE);

	/* Some calculations done mod p-1 */
	if (bnCopy (&pm1, &sec->s.p) < 0 ||
	    bnSubQ (&pm1, 1) < 0)
		goto nomem;

	/*
	 * Choose the random x1 value to be used for this signature.
	 * Make sure it is relatively prime to p-1
	 */
	x1bits = pgpDiscreteLogExponentBits(bnBits(&sec->s.p))*3/2;
	do {
		if (pgpBnGenRand(&x1, rc, x1bits, 0, 1, x1bits-1) < 0 ||
		    bnGcd(&a, &x1, &pm1) < 0)
			goto nomem;
	} while (bnBits(&a) > 1);

	/* Raise g to x1 power to get a */
	if (bnExpMod(&a, &sec->s.g, &x1, &sec->s.p) < 0)
		goto nomem;
	      
	/* Calculate x**-1 mod p-1, keep in x1 */
	if (bnInv(&x1, &x1, &pm1) < 0)
		goto nomem;

	/* Pack message hash M into buffer bn (use sig temporarily) */
	t = elgSEPack(sig, elgSESecMaxsig(seckey, format), h, hash);
	if (pgpPKCSPack(&bn, sig, t, PKCS_PAD_SIGNED,
			bnBytes(&sec->s.p), rc) < 0)
		goto nomem;

	/* Calculate b = (M-xa)/k mod p-1, put it in bn */
	if (bnMul(&xa, &sec->s.x, &a) < 0 ||
	    bnMod(&xa, &xa, &pm1) < 0)
		goto nomem;

	if (bnCmp(&bn, &xa) < 0) {
		if (bnAdd(&bn, &pm1) < 0)
			goto nomem;
	}
	bnSub(&bn, &xa);
	if (bnMul(&bn, &bn, &x1) < 0 ||
	    bnMod(&bn, &bn, &pm1) < 0)
		goto nomem;

	/* Success, now just pack into sig buffer */
	t  = pgpBnPutFormatted(&a, sig, bnBytes(&sec->s.p), format);
	t += pgpBnPutFormatted(&bn, sig+t, bnBytes(&sec->s.p), format);
	if (siglen)
		*siglen = (size_t)t;

	i = 0;
	goto done;

nomem:
	i = kPGPError_OutOfMemory;
	/* fall through */
done:
	bnEnd(&xa);
	bnEnd(&bn);
	bnEnd(&pm1);
	bnEnd(&x1);
	bnEnd(&a);
	bnEnd(&bn);
	bnEnd(&xk);
	return i;
#endif
}

/*
 * Re-encrypt a PGPSecKey with a new passphrase.
 * A secret key is, after a non-specific prefix:
 *  0       1    Version (= 2 or 3)
 *  1       4    Timestamp
 *  5       2    Validity (=0 at present)
 *  7       1    Algorithm (=kPGPPublicKeyAlgorithm_ElGamalSign for ELG)
 * The following:
 *  0                2+u  MPI for prime
 *  2+u              2+v  MPI for generator
 *  4+u+v	     2+w  MPI for public key
 *  6+u+v+w          1    Encryption algorithm (0 for none, 1 for IDEA)
 *  7+u+v+w          t    Encryption IV: 0 or 8 bytes
 *  7+t+u+v+w        2+x  MPI for x (discrete log of public key)
 *  9+t+u+v+w+x      2    Checksum
 * 11+t+u+v+w+x
 *
 * The Encryption algorithm is the cipher algorithm for the old-style
 * string-to-key conversion.  For the new type, it's 255, then a cipher
 * algorithm, then a string-to-key algorithm (variable-length),
 * then the encryption IV.  That's 16 bytes plus the string-to-key
 * conversion length.
 */

static int
elgSEChangeLock(PGPSecKey *seckey, PGPEnv const *env, 
	PGPRandomContext const *rc, char const *phrase, size_t plen,
	PGPStringToKeyType s2ktype)
{
	ELGsecPlus *sec = (ELGsecPlus *)seckey->priv;
	PGPStringToKey *s2k = NULL;	/* Shut up warnings */
	PGPCipherVTBL const *cipher = NULL;	/* Shut up warnings */
	PGPCFBContext *cfb = NULL;	/* This is realy needed */
	PGPByte *p;
	PGPByte key[PGP_CIPHER_MAXKEYSIZE];
	int oldf = 0;				/* Shut up warnings */
	unsigned len;
	unsigned checksum;
	PGPContextRef	context	= pgpenvGetContext( env );

	ASSERTelgSE(seckey->pkAlg);
	if (sec->locked)
		return kPGPError_KeyIsLocked;

	len = bnBytes(&sec->s.p) + bnBytes(&sec->s.g) +
	      bnBytes(&sec->s.y) + bnBytes(&sec->s.x) + 11;
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
		cfb = pgpCFBCreate( PGPGetContextMemoryMgr( context ), cipher);
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
				pgpContextMemAlloc( sec->context, len,
					0 );
			if( IsNull( sec->cryptkey ) ) {
				err = kPGPError_OutOfMemory;
			}
		} else {
			err = pgpContextMemRealloc( context,
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

static size_t
elgSESecBufferLength(PGPSecKey const *seckey)
{
	ELGsecPlus const *sec = (ELGsecPlus *)seckey->priv;

	return sec->cklen;
}

static void
elgSESecToBuffer(PGPSecKey const *seckey, PGPByte *buf)
{
	ELGsecPlus const *sec = (ELGsecPlus *)seckey->priv;

	memcpy(buf, sec->cryptkey, sec->cklen);

	/* Return only algorithm-dependent portion */
}


/* Fill in secret key structure */
static void
elgFillSecKey(PGPSecKey *seckey, ELGsecPlus *sec)
{
	seckey->pkAlg	            = kPGPPublicKeyAlgorithm_ElGamalSE;
	seckey->priv	            = sec;
	seckey->destroy             = elgSESecDestroy;
	seckey->pubkey              = elgSEPubkey;
	seckey->islocked            = elgSEIslocked;
	seckey->lockingalgorithm    = elgSELockingAlgorithm;
	seckey->s2ktype             = elgSES2KType;
	seckey->convertpassphrase   = elgSEConvertPassphrase;
	seckey->unlock              = elgSEUnlock;
	seckey->lock                = elgSELock;
	seckey->decrypt             = elgSEDecrypt;
	seckey->maxdecrypted        = elgSESecMaxdecrypted;
	seckey->maxesk		        = elgSESecMaxesk;
	seckey->maxsig              = elgSESecMaxsig;
	seckey->sign                = elgSESign;
	seckey->changeLock          = elgSEChangeLock;
	seckey->bufferLength        = elgSESecBufferLength;
	seckey->toBuffer            = elgSESecToBuffer;
}


PGPSecKey *
elgSESecFromBuf(
	PGPContextRef	context,
	PGPByte const *	buf,
	size_t			size,
	PGPError *		error)
{
	PGPSecKey *seckey;
	ELGsecPlus *sec;
	PGPByte *cryptk;
	PGPError	err	= kPGPError_OutOfMemory;
	PGPMemoryMgrRef		mgr	= PGPGetContextMemoryMgr( context );
	PGPEnv *			pgpEnv = pgpContextGetEnvironment( context );

	bnInit();
	cryptk = (PGPByte *)pgpContextMemAlloc( context,
		size, kPGPMemoryMgrFlags_Clear);
	if (cryptk) {
		sec = (ELGsecPlus *)PGPNewSecureData( mgr, sizeof(*sec), 0 );
		if (sec) {
			pgpClearMemory( sec, sizeof(*sec) );
			sec->context	= context;
			
			seckey = (PGPSecKey *) pgpContextMemAlloc( context,
					sizeof(*seckey), kPGPMemoryMgrFlags_Clear);
			if (seckey) {
				seckey->context	= context;
				
				memcpy(cryptk, buf, size);
				bnBegin(&sec->s.p, mgr, FALSE );
				bnBegin(&sec->s.g, mgr, FALSE );
				bnBegin(&sec->s.y, mgr, FALSE );
				bnBegin(&sec->s.x, mgr, TRUE );
				sec->cryptkey = cryptk;
				sec->cklen = sec->ckalloc = size;
				sec->locked = 1;
				/* We only need this to try unlocking... */
				seckey->pkAlg = kPGPPublicKeyAlgorithm_ElGamalSE;
				seckey->priv = sec;
				
				if (elgSEUnlock(seckey, pgpEnv, NULL, 0, FALSE) >= 0) {
					elgFillSecKey(seckey, sec);
					*error = kPGPError_NoErr;
					return seckey;	/* Success! */
				}
				else
				{
					err	= kPGPError_UnknownError;
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

/* Generate super-strong primes? (Warning: slow!) */
#ifndef ELG_GERMAIN
#define ELG_GERMAIN 0
#endif

/*
 * Generate an ELG secret key with prime of the specified number of bits.
 * Make callbacks to progress function periodically.
 * Secret key is returned in the unlocked form, with no passphrase set.
 * fastgen tells us to use canned primes if available.
 *
 * If ELG_GERMAIN is set to 1, we generate p such that (p-1)/2 is also
 * prime.  This takes long time.  (Pseudoprimality tests take time
 * cubic in the number of bits, and the number of tests needed is
 * linear in the number of bits, so it's quartic overall.  Searching
 * for Sophier Germain primes makes it quintic(!), although the constant
 * factor improves to make up for a lot of that.
 *
 * The alternative (which is really just as safe, really) is to generate
 * primes which have a large prime factor q about 10 bits shorter than
 * the requested length.  We will guarantee that 2 is a generator of a
 * subgroup with period at least q.
 *
 * If it is OK, we could speed it up more by generating multiple primes
 * qi such that p = 2*k*q1*q2*q3*...*qn + 1, and where each qi is greater
 * than 2**160 (or whatever exponent value we are using).  Again, once we
 * verify that 2's period is > 2k we know it as at least min(qi), which
 * should be long enough for prevention of discrete log attacks.
 *
 * A bit of theory: the average density of primes around n is 1/ln(n),
 * so the average gap between primes is ln(n).  However, the maximum
 * gap is ln(n)^2.  The fact that we're searching in steps other than
 * 1 doesn't matter - it'll take an average of ln(n) steps.
 *
 * So to produce a prime of the desired size, we should have p/q at
 * least ln(p) and to guarantee it, we need p/q = ln(p)^2.  This
 * means that we want
 * log2(ln(p))           < log2(p/q)         < log2(ln(p)^2)
 * log2(0.693*log2(p))   < log2(p) - log2(q) < 2 * log2(0.693 * log2(p))
 * log2(log2(p)) - 0.529 < log2(p) - log2(q) < 2 * log2(log2(p)) - 1.058
 *
 * At this point, it's safe to start getting crude, because if we're
 * only counting bits, 2^(bits(x)-1) <= x < 2^bits(x) <= 2*x, or
 * bits(x)-1 <= log2(x) < bits(x) <= log2(x)+1.  Another way of looking
 * at all this is that log2(x) is bits(x) - 0.5 +/- 0.5.
 * So let's split the difference and use 1.5 * bits(bits(p)) - 1 as the
 * difference in bits between p and q.  
 *
 * See the discussion preceding the DSA keygen routine dsaSecGenerate
 * in pgpDSAKey.c for an explanation of the rcdummy random number
 * generator below.  It serves to limit leakage of the state of the
 * randpool into the public values generated as part of the key.
 */
PGPSecKey *
elgSESecGenerate(
	PGPContextRef	context,
	unsigned bits, PGPBoolean fastgen,
	PGPRandomContext const *rc,
	int progress(void *arg, int c), void *arg, PGPError *error)
{
	PGPSecKey *seckey;
	ELGsecPlus *sec;
	PGPRandomContext *rcdummy = NULL;
	unsigned bits2;
#if !ELG_GERMAIN
	unsigned lengthdiff;
	BigNum q, h, e;
	int i;
#endif
	PGPByte dummyseed[ELGDUMMYBITS/8];
	PGPMemoryMgrRef		mgr	= PGPGetContextMemoryMgr( context );
	PGPEnv *			pgpEnv = pgpContextGetEnvironment( context );

	*error = kPGPError_NoErr;

	/* Initialize local pointers (simplify cleanup below) */
	seckey = NULL;
	sec = NULL;

	/* Allocate data structures */
	seckey = (PGPSecKey *)pgpContextMemAlloc( context,
		sizeof(*seckey), kPGPMemoryMgrFlags_Clear);
	if (!seckey)
		goto memerror;
	seckey->context	= context;
	sec = (ELGsecPlus *)PGPNewSecureData( mgr, sizeof(*sec), 0 );
	sec->context	= context;
	if (!sec)
		goto memerror;
	
	bnBegin(&sec->s.p, mgr, FALSE );
	bnBegin(&sec->s.g, mgr, FALSE );
	bnBegin(&sec->s.y, mgr, FALSE );
	bnBegin(&sec->s.x, mgr, TRUE );

	/* Use a fixed prime and generator if in our table */
	if (fastgen) {
		PGPByte const *fixedp, *fixedg;
		size_t fixedplen, fixedglen;
		if (pgpElGfixed (bits, &fixedp, &fixedplen, &fixedg, &fixedglen) > 0) {
			if (progress != NULL)
				progress(arg, ' ');
			bnInsertBigBytes (&sec->s.p, fixedp, 0, fixedplen);
			if (progress != NULL)
				progress(arg, ' ');
			bnInsertBigBytes (&sec->s.g, fixedg, 0, fixedglen);
			goto choose_x;
		}
	}

	/* Set up local random number generator for p and q */
	rcdummy = pgpPseudoRandomCreate ( rc->context );
	if (!rcdummy)
		goto memerror;
	pgpRandomGetBytes (rc, dummyseed, sizeof(dummyseed));
	pgpRandomAddBytes (rcdummy, dummyseed, sizeof(dummyseed));

#if ELG_GERMAIN
	/* Strong ("sophie germain") prime search */

	/* Find p - choose a starting place */
	if (pgpBnGenRand(&sec->s.p, rcdummy, bits, 0xC0, 3, bits-4) < 0)
		goto nomem;

	/* And search for a prime */
	if (bnGermainPrimeGen(&sec->s.p, 1, progress, arg) < 0)
		goto nomem;

	/* We have chosen p so 2 is a good choice for generator */
	if (bnSetQ(&sec->s.g, 2) < 0)
		goto nomem;

	/* Choose a random x of reasonable size as secret key */
	expbits = elgExpBits(bits);
	if (pgpBnGenRand(&sec->s.x, rc, expbits, 0, 0, expbits) < 0)
		goto nomem;

	/* And calculate g**x as public key */
	if (bnTwoExpMod(&sec->s.y, &sec->s.x, &sec->s.p) < 0)
		goto nomem;
#else /* !ELG_GERMAIN - the faster version */
	bnBegin(&q, mgr, FALSE );
	bnBegin(&h, mgr, FALSE );
	bnBegin(&e, mgr, FALSE );

	/*
	 * Choose a random starting place for q, a bit less than p.
	 * (See function header comment above for the theory behind this.)
	 */
	lengthdiff = 0;
	for (bits2 = bits; bits2; bits2 >>= 1)
		lengthdiff++;
	lengthdiff += (lengthdiff+1)/2;
	bits2 = bits - lengthdiff;

	if (pgpBnGenRand(&q, rcdummy, bits2, 0x80, 1, bits2-2) < 0)
		goto nomem;
	/* And search for a prime */
	i = bnPrimeGen(&q, NULL, progress, arg, 0);
	if (i < 0)
		goto nomem;
	if (progress != NULL)
		progress(arg, ' ');

	/* ...and now a random start for p */
	(void)bnSetQ(&sec->s.p, 0);
	if (pgpBnGenRand(&sec->s.p, rcdummy, bits, 0xC0, 1, bits-bits2-3) < 0)
		goto nomem;

	/* Double q to make it a suitable stride */
	if (bnLShift(&q, 1) < 0)
		goto nomem;

	/* Set p = p - (p mod 2q) + 1, i.e. congruent to 1 mod 2q */
	if (bnMod(&h, &sec->s.p, &q) < 0)
		goto nomem;
	if (bnSub(&sec->s.p, &h) < 0 || bnAddQ(&sec->s.p, 1) < 0)
		goto nomem;

	/* This loop is very rarely executed */
retry:
	/* And search for a prime, 1+2kq for some k */
	i = bnPrimeGenStrong(&sec->s.p, &q, progress, arg);
	if (i < 0)
		goto nomem;
	if (progress != NULL)
		progress(arg, ' ');

	/* Now check two as g: first, find (p-1)/q = 2*((p-1)/(2*q)) */
	if (bnDivMod(&e, &h, &sec->s.p, &q) < 0 || bnLShift(&e, 1) < 0)
		goto nomem;
	/* e is now (p-1)/q, and h is the remainder (one!) */
	pgpAssert (bnBits(&h) == 1);

	/*
	 * Make sure 2**((p-1)/q) mod p is not small.  This should imply
	 * that the period of 2 as a generator has at least q as a factor,
	 * meaning it is very big.
	 * With (p-1)/q as small as it is, the chances are *excellent*
	 * that it will work.  If (p-1)/q were less than a few hundred
	 * 2**((p-1)/q) would be less than p and coundn't possibly be 1.
	 */
	if (bnTwoExpMod(&h, &e, &sec->s.p) < 0)
		goto nomem;
	if (bnBits(&h) < 2) {
		if (progress != NULL)
			progress(arg, ' ');
		goto retry;
	}
	bnEnd(&e);
	bnEnd(&h);
	bnEnd(&q);
#endif
	/* We have done things so 2 is a good choice for generator */
	if (bnSetQ(&sec->s.g, 2) < 0)
		goto nomem;

	/* May get here directly from above if fixed primes are used */
choose_x:

	/* Choose a random x of reasonable size as secret key */
	bits2 = pgpDiscreteLogExponentBits(bits)*3/2;
	if (pgpBnGenRand(&sec->s.x, rc, bits2, 0, 0, bits2) < 0)
		goto nomem;

	/* And calculate g**x as public key */
	if (bnExpMod(&sec->s.y, &sec->s.g, &sec->s.x, &sec->s.p) < 0)
		goto nomem;
	

	/* And that's it... success! */

	/* Fill in structs */
	sec->cryptkey = NULL;
	sec->ckalloc = sec->cklen = 0;
	sec->locked = 0;
	elgFillSecKey(seckey, sec);

	/* Fill in cryptkey structure, unencrypted */
	elgSEChangeLock (seckey, pgpEnv, NULL, NULL, 0, kPGPStringToKey_Simple);

	goto done;

nomem:
#if !ELG_GERMAIN
	bnEnd(&e);
	bnEnd(&h);
	bnEnd(&q);
#endif
	bnEnd(&sec->s.p);
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

done:
	if (rcdummy)
	{
		pgpRandomDestroy (rcdummy);
	}
		
	return seckey;
}

