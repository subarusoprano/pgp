/*
 * True random number computation and storage
 *
 * Wrtten by Colin Plumb.
 *
 * This performs a strong hash on the data as it is fed into the
 * pool, and the pool is again strongly hashed to produce the output
 * of the random-number generator.  This is overkill, as either step
 * should produce high-quality numbers.
 *
 * $Id: pgpRandomPool.c,v 1.20.6.1.8.2 1999/08/06 20:56:49 cpeterson Exp $
 */
#include  "pgpConfig.h"

#include <stdlib.h>
#include <string.h>

#include "pgpBase.h"
#include "pgpMem.h"

#include "pgpSHA.h"
#include "pgpRnd.h"

#include "pgpDebug.h"
#include "pgpRandomPoolPriv.h"
#include "pgpRndSeed.h"
#include "pgpRMWOLock.h"
#include "pgpSDKBuildFlags.h"

#if !PGP_WIN32
#undef PGP_INTEL_RNG_SUPPORT
#define PGP_INTEL_RNG_SUPPORT 0
#endif

#if PGP_INTEL_RNG_SUPPORT
#include "isec.h"
#endif


/* We import the following things from the SHA code */
#define HashTransform pgpSHATransform
#define HASH_INWORDS 16
#define HASH_OUTWORDS 5

/*
 * The pool must be a multiple of the hash input size and the hash
 * output size.  For SHA, these are 16 and 5 words, respectively,
 * so the pool must be a multiple of 80 words.  If the hash were
 * MD5, it would have to be a multiple of 16 and of 4, or a multiple
 * of 16 all together.  (80 words is 2560 bits.)
 */
//BEGIN RSA KEYSIZE MOD - Imad R. Faiad
//#define RANDPOOLWORDS 160	/* 5,120 bits */
#define RANDPOOLWORDS 640	/* 20480 bits */
//END RSA KEYSIZE MOD
#define RANDPOOLBITS (32*RANDPOOLWORDS)
#if RANDPOOLWORDS % HASH_OUTWORDS
#error RANDPOOLWORDS must be a multiple of HASH_OUTWORDS
#endif
#if RANDPOOLWORDS % HASH_INWORDS
#error RANDPOOLWORDS must be a multiple of HASH_INWORDS
#endif

#define RANDKEYBITS	(8*HASH_INWORDS)

/* minimum number of bytes to consider the random pool seeded */
#define kMinimumSeedBytes		24
#define kMinimumSeedBits		( 8 * kMinimumSeedBytes )

typedef struct RandomPool
{
	/*
	 * Accumulators to estimate entropy in the pool.
	 * See comments with pgpGlobalRandomPoolEntropyWasAdded for how
	 * fractional bits are stored.
	 */
	PGPUInt32	randBits; /* Bits of entropy in pool */
	PGPUInt32	randFrac; /* Fraction of a bit of entropy in pool */
	PGPUInt32	randInBits; /* Bits of entropy added to pool */

	/* Estimate entropy in randKey array, a buffer which dumps into pool */
	PGPUInt32	randKeyBits; /* Bits of entropy in randKey */
	PGPUInt32	randKeyFrac; /* Fraction of a bit of entropy in randKey */

	/* Must be word-aligned, so make it words.  Cast to bytes as needed. */
	PGPUInt32	randPool[RANDPOOLWORDS];	/* Random pool */
	PGPUInt32	randPoolAddPos;	/* Position to encrypt into (words) */

	PGPUInt32	randKey[HASH_INWORDS];	/* Random input buffer */
	PGPUInt32	randKeyAddPos;	/* Position to add to (bytes) */

	PGPUInt32	randOut[HASH_OUTWORDS];	/* Random output buffer */
	PGPUInt32	randOutGetPos; /* Position to get from (b) */

	/* Keeps track of when we need to do another hashing step */
	PGPUInt32	randHashCounter;
	
	PGPRMWOLock	criticalLock;
		
} RandomPool;

/* This is the global random pool */
static RandomPool	sPool;
#define GetPool()		( &sPool )

static void sRandAddKeyEntropy( RandomPool *pool );


	PGPError
pgpInitGlobalRandomPool()
{
	RandomPool *	pool	= NULL;
	
	pool	= GetPool();
	
	pool->randBits			= 0;
	pool->randFrac			= 0;
	pool->randInBits		= 0;
	pool->randKeyBits		= 0;
	pool->randKeyFrac		= 0;
	pool->randPoolAddPos	= 0;
	pool->randKeyAddPos		= 0;
	pool->randOutGetPos		= sizeof( pool->randOut);
	pool->randHashCounter	= 0;
	
	InitializePGPRMWOLock( &pool->criticalLock );
	
	return( kPGPError_NoErr );
}

/*
 * To mix input into the pool, we insert it into a key buffer and then
 * use the key buffer to CBC-encrypt the pool.  Actually, to make sure
 * that the input (which includes such sensitive information as passphrase
 * keystrokes) is not left in memory, we XOR it with the old contents of
 * the key buffer along with some of the the data about to be encrypted.
 * Since none of the disguising data depends on the byte, this does
 * not destroy any entropy inherent in the input byte.
 *
 * To reduce burstiness in the timing, rather than wait until the key
 * buffer is full to encrypt the entire pool, we update part of the key
 * and then encrypt part of the pool.  The randHashCounter keeps track
 * of what's going on to ensure that a byte of key is not overwritten
 * until it has participated in the encryption of every block of the pool.
 *
 * The pool contains RANDPOOLWORDS/HASH_OUTWORDS blocks.  We must do
 * that many hash-encryption steps before 4*HASH_INWORDS bytes of the
 * key have been overwritten.  So randHashCounter is incremented by
 * RANDPOOLWORDS/HASH_OUTWORDS each time a byte is added to the
 * randKey array, and it is decreased by 4*HASH_INWORDS each time we
 * do a hash-encryption step.  This keeps the two processes in
 * balance.
 *
 * We store entropy in the randKey array until some minimum is
 * reached, or until we have filled the entire randKey array, then we
 * dump the entropy into the randPool as just described.  This
 * prevents an attacker who knows the initial seed value and who has
 * access to the output of the randPool from guessing the input values
 * by trying all possibilities.
 *
 * The bits deposited need not have any particular distribution; the
 * stirring operation transforms them to uniformly-distributed bits.
 */
	static void
sRandPoolAddByte(
	RandomPool *	pool,
	PGPByte			b)
{
	int				i;
	PGPUInt32		pos;

	/* Mix new byte into pool */
	((PGPByte *)pool->randKey)[pool->randKeyAddPos] ^= b;
	if (++pool->randKeyAddPos == sizeof(pool->randKey))
		pool->randKeyAddPos = 0;

	/*
	 * If we've reached the end of a word, mask the next word with
	 * a soon-to-be-overwritten byte of the pool.  With a 64-byte input
	 * hash, this will use a different word for masking each of the
	 * 16 words as long as there are at least 16 output blocks
	 * (64 words at 4 words per output block, or 512 bits total) in the
	 * pool.  Just to be sure, let's enforce it...
	 */
#if HASH_INWORDS > RANDPOOLWORDS / HASH_OUTWORDS
#error Please make RANDPOOLWORDS bigger than HASH_INWORDS * HASH_OUTWORDS.
#endif
	if (pool->randKeyAddPos % sizeof(PGPUInt32) == 0)
		*(PGPUInt32 *)((PGPByte *)pool->randKey + pool->randKeyAddPos) ^=
		                            pool->randPool[pool->randPoolAddPos];

	/* Do a hashing step if required */
	pool->randHashCounter += RANDPOOLWORDS/HASH_OUTWORDS;

	/* Update pool every 64 bits of entropy, or when about to wrap around */
	if (pool->randKeyBits >= 64 ||
		pool->randHashCounter >= 4*HASH_INWORDS*RANDPOOLWORDS/HASH_OUTWORDS) {
		while (pool->randHashCounter >= 4*HASH_INWORDS) {
			pool->randHashCounter -= 4*HASH_INWORDS;

			/* CBC-encrypt the current block */
			pos = pool->randPoolAddPos;
			HashTransform(pool->randPool + pos, pool->randKey);

			/* Get the offset of the next block and XOR this one in */
			pool->randPoolAddPos = pos + HASH_OUTWORDS;
			if (pool->randPoolAddPos == RANDPOOLWORDS)
				pool->randPoolAddPos = 0;
			for (i = 0; i < HASH_OUTWORDS; i++)
				pool->randPool[pool->randPoolAddPos + i] ^=
													pool->randPool[pos+i];
		}
		/* Accumulate entropy from key into pool */
		sRandAddKeyEntropy( pool );
	}
}

/*
 * Make a deposit of information (entropy) into the pool.
 */
	static void
sRandPoolAddBytes(
	void *			priv,
	PGPByte const *	p,
	unsigned		len)
{
	RandomPool *pool	= GetPool();
	
	pgpAssert( pool );

	(void)priv;

	while (len--) {
		sRandPoolAddByte( pool, *p++ );
	}

	/* Pool has changed, randOut is out of date */
	pool->randOutGetPos = sizeof(pool->randOut);
}

static void
sRandGetOutput( RandomPool *	pool )
{
	int i;

	/*
	 * Hash the pending input and the entire pool, with the old
	 * randOut as IV.
	 */
	HashTransform( pool->randOut, pool->randKey );
	for (i = 0; i < RANDPOOLWORDS; i += HASH_INWORDS)
		HashTransform( pool->randOut, pool->randPool + i );

	/* Okay, we can now fetch starting at the beginning of randOut */
	pool->randOutGetPos = 0;
}

/*
 * Withdraw some bits from the pool.  Regardless of the distribution of the
 * input bits, the bits returned are uniformly distributed, although they
 * cannot, of course, contain more Shannon entropy than the input bits.
 */
	static void
sRandPoolGetBytesEntropy(
	void *			priv,
	PGPByte *		buf,
	unsigned		len,
	unsigned		bits)
{
	RandomPool *pool	= GetPool();
	unsigned t;
	
	pgpAssert( pool );

	(void)priv;

	if (pool->randBits >= bits)
		pool->randBits -= bits;
	else
		pool->randFrac = pool->randBits = 0;

	while (len > (t = sizeof(pool->randOut) - pool->randOutGetPos)) {
		pgpCopyMemory( (PGPByte *)pool->randOut + pool->randOutGetPos, buf, t);
		buf += t;
		len -= t;
		sRandGetOutput( pool );
	}

	if (len) {
		pgpCopyMemory( (PGPByte *)pool->randOut+pool->randOutGetPos, buf, len);
		pool->randOutGetPos += len;
	}
}


/*
 * Destroys already-used random numbers.  Ensures no sensitive data
 * remains in memory that can be recovered later.  This repeatedly
 * mixes the output of the generator back into itself until all internal
 * state has been overwritten.
 */
	static void
sRandPoolStir(void *	priv )
{
	RandomPool *pool	= GetPool();
	unsigned	i;
	
	pgpAssert( pool );

	(void)priv;

	for (i = 0; i < 5*sizeof(pool->randKey)/sizeof(pool->randOut); i++) {
		sRandPoolAddBytes(priv, (PGPByte *)pool->randOut,
						  sizeof(pool->randOut));
		sRandGetOutput( pool );
	}
}

	static void
sRandPoolAddBytesLock(
	void *			priv,
	PGPByte const *	p,
	unsigned		len)
{
	RandomPool *pool	= GetPool();
	
	PGPRMWOLockStartWriting( &pool->criticalLock );
		sRandPoolAddBytes( priv, p, len );
	PGPRMWOLockStopWriting( &pool->criticalLock );
}

	static void
sRandPoolGetBytesEntropyLock(
	void *			priv,
	PGPByte *		buf,
	unsigned		len,
	unsigned		bits)
{
	RandomPool *pool	= GetPool();
	
	PGPRMWOLockStartWriting( &pool->criticalLock );
		sRandPoolGetBytesEntropy( priv, buf, len, bits );
	PGPRMWOLockStopWriting( &pool->criticalLock );
}

	static void
sRandPoolStirLock(void *priv)
{
	RandomPool *pool	= GetPool();
	
	PGPRMWOLockStartWriting( &pool->criticalLock );
		sRandPoolStir( priv );
	PGPRMWOLockStopWriting( &pool->criticalLock );
}

static const PGPRandomVTBL sGlobalRandomPoolVTBL =
{
	"Global true random-number pool",
	sRandPoolAddBytesLock,
	sRandPoolGetBytesEntropyLock,
	sRandPoolStirLock
};


	PGPRandomVTBL const *
pgpGetGlobalRandomPoolVTBL( void )
{
	return( &sGlobalRandomPoolVTBL );
}


/*
 * Used for cases where we want to create a temporary PGPRandomContext
 * which wraps the random pool.
 */
	void
pgpInitGlobalRandomPoolContext( PGPRandomContext *rc )
{
	rc->context	= NULL;
	rc->vtbl	= pgpGetGlobalRandomPoolVTBL();
	rc->priv	= NULL;
	rc->destroy	= NULL;
}




/*
 * True random bit accumulation.  These are extra functions exported
 * for entropy estimation.
 *
 * Entropy is expressed in terms of a delta, essentially the difference
 * between the observed value and the expected value, whose logarithm
 * is a measure of entropy.  (The logarithm to the base 2 is entropy
 * expressed in bits.)
 *
 * The internal amount-of-entropy accumulator is maintained in two
 * halves: a counter of bits, and a fraction of a bit, expressed
 * in the form of a normalized delta.  If 0 <= f < 1 is a fraction
 * of a bit, then 1 <= 2^f < 2, so it's remembered as
 * 0 <= x = 2^f - 1 < 1, a fixed-point number.
 *
 * Given a new fractional-bit delta, 1+y in similar form (obtained
 * by normalizing the delta into the desired form), the output
 * fractional bit delta 1+z = (1+x) * (1+y).  If this exceeds 2,
 * divide it by 2 and add a full bit to the bit counter.
 *
 * The implementation, of course, actually computes z = x + y + x*y,
 * where 0 <= z < 3.  This can be done by adding each of the three terms
 * (each of which is less than 1) and noticing the overflow.  If the
 * addition does not overflow, z < 1 and nothing needs to be done.
 *
 * If one addition overflows, 1 <= z < 2, but after overflow we get
 * z-1.  We want (1+z)/2-1 = (z-1)/2, so just divide the result of
 * the wrapped addition by 2.
 *
 * If both additions overflow, the addition wraps to z-2, but we
 * still want (z-1)/2 = (z-2)/2 + 1/2, so divide the wrapped result
 * by 2 and add 1/2.
 *
 * Due to the way that the fixed-point numbers are stored, the x*y part is
 * the high half of the 32-bit unsigned product of x and y.  This can be
 * safely underestimated if desired, if a 64-bit product is difficult to
 * compute.
 *
 * The simplest snd safest definition is
 * #define UMULH_32(r,a,b) (r) = 0
 */
#ifndef UMULH_32
#if defined(__GNUC__) && defined(__i386__)
/* Inline asm goodies */
#define UMULH_32(r,a,b) __asm__("mull %2" : "=d"(r) : "%a"(a), "mr"(b) : "ax")
#elif HAVE64
#define UMULH_32(r,a,b) ((r) = (PGPUInt32)((word64)(a) * (b) >> 32))
#else
/* Underestimate the product */
#define UMULH_32(r,a,b) ((r) = ((a) >> 16) * ((b) >> 16))
#endif
#endif /* !UMULH_32 */

#define DERATING 2	/* # of bits to underestimate */

	static PGPUInt32
pgpGlobalRandomPoolEntropyWasAdded(
	PGPUInt32		delta )
{
	PGPUInt32		frac,
					t;
	unsigned		n;
	RandomPool	*	pool	= GetPool();

	if (delta < 1 << DERATING)
		return 0;
	
	n = 31-DERATING;
	if (!(delta & 0xffff0000))
		delta <<= 16, n -= 16;
	if (!(delta & 0xff000000))
		delta <<= 8, n -= 8;
	if (!(delta & 0xf0000000))
		delta <<= 4, n -= 4;
	if (!(delta & 0xc0000000))
		delta <<= 2, n -= 2;
	if (!(delta & 0x80000000))
		delta <<= 1, n -= 1;
	pgpAssert(n < 32);

	/* Lose high-order bit of delta */
	pgpAssert(delta & 0x80000000);
	delta <<= 1;

	frac = pool->randKeyFrac;
	UMULH_32(t,delta,frac);
	if ((frac += t) < t) {
		if ((frac += delta) < delta)
			frac = (frac >> 1) + 0x80000000ul;
		else
			frac >>= 1;
		n++;
	} else if ((frac += delta) < delta) {
		frac >>= 1;
		n++;
	}

	/* The timers used are very high-resolution. Be
	** conservative with our estimates. No more than
	** 10 bits per sample.
	*/

	if( n > 10 )
		n = 10;

	/* Store back updated fractional bits */
	pool->randKeyFrac = frac;

	/* n is now the count of whole bits */
	if ((pool->randKeyBits += n) >= RANDKEYBITS) {
		/* Overflow - saturate at RANDKEYBITS */
		pool->randKeyBits = RANDKEYBITS;
		pool->randKeyFrac = 0;
	}
	
	return n;
}

	PGPUInt32
PGPGlobalRandomPoolGetEntropy()
{
	PGPUInt32	randBits;
	RandomPool	*pool = GetPool();

	PGPRMWOLockStartReading( &pool->criticalLock );
	randBits = pool->randBits;

#if PGP_INTEL_RNG_SUPPORT
	/*
	 * If the pool isn't full and we have Intel RNG,
	 * add RNG bits into the pool.
	 */
	if (randBits < RANDPOOLBITS && pgpIntelRngEnabled()) {
		while (randBits < RANDPOOLBITS) {
			uint32 uiRandom;
			if (IsdGetRandomNumber(&uiRandom) != ISD_EOK)
				break;
			pgpGlobalRandomPoolAddEntropyBits(INTEL_RNG_ENTROPY_BITS);
			sRandPoolAddBytes(NULL, (PGPByte *)&uiRandom, sizeof(uiRandom));
			randBits = pool->randBits;
		}
	}
#endif

	PGPRMWOLockStopReading( &pool->criticalLock );
	
	return( randBits );
}

	void
pgpGlobalRandomPoolAddEntropyBits(PGPInt32 num)
{
	RandomPool *pool = GetPool();
	if ((pool->randKeyBits += num) >= RANDKEYBITS) {
		pool->randKeyBits = RANDKEYBITS;
		pool->randKeyFrac = 0;
	}
}

	PGPUInt32
PGPGlobalRandomPoolGetSize()
{
	return RANDPOOLBITS;
}



	PGPUInt32
pgpGlobalRandomPoolGetInflow()
{
	PGPUInt32	randInBits;
	RandomPool	*pool = GetPool();

	PGPRMWOLockStartReading( &pool->criticalLock );
		randInBits = pool->randInBits;
	PGPRMWOLockStopReading( &pool->criticalLock );
	
	return( randInBits );
}


/*
 * Returns true if we have enough entropy to proceed with signature or
 * encryption functions.  We go ahead if we have either seeded the RNG
 * successfully from the disk, or if we have acquired a certain
 * minimum of bits from the environment during our run.
 */
	PGPBoolean
PGPGlobalRandomPoolHasMinimumEntropy( void )
{
	return  pgpGlobalRandomPoolIsSeeded() ||
		    pgpGlobalRandomPoolGetInflow() >= kMinimumSeedBits ;
}

/*
 * Returns the minimum amount of entropy we would like to see in the random
 * pool before signing or encryption.  Before doing one of those functions,
 * we first use PGPGlobalRandomPoolHasMinimumEntropy to determine whether
 * to proceed.  If that returns FALSE, we should acquire entropy until the
 * amount in the random pool is at least equal to what this function returns.
 * Note that PGPGlobalRandomPoolHasMinimumEntropy uses the inflow value,
 * while if that returns false we will use the actual amount of randomness
 * in the pool, which is always <= the inflow value.  Using the inflow value
 * is safe enough as it indicates that we are seeded, but once we decide we
 * need to go to the effort of acquiring more entropy from the environment,
 * we might as well use the GetEntropy() value, which is more conservative.
 */
	PGPUInt32
PGPGlobalRandomPoolGetMinimumEntropy( void )
{
	return kMinimumSeedBits;
}


/* Number of elements in the given array */
#define elemsof(x) ( (PGPUInt32)( sizeof(x) / sizeof(*x) ) )

/*
 * Estimate the amount of entropy in an input value x by seeing how
 * different it is from what has come before.
 *
 * This is based on computing the delta from the previous value, and the
 * second-order delta from the previous delta, and so on, for h orders.
 * The minimum of any of those deltas is returned as the entropy estimate.
 * (Which must, of course, have a logarithm taken to produce a "number
 * of bits" output.)
 *
 * This requires a pointer to a h-word history table of previous deltas.
 * A value of h = 3 is generally good, but some things (like keystroke
 * timings) feed deltas and not input values into this, so that removes
 * the first level.
 */
static PGPUInt32
randEstimate(PGPUInt32 x, PGPUInt32 *history, unsigned h)
{
	PGPUInt32		t,
					min = x;

	while (h--) {
		t = history[h];			/* Last delta */
		t = (x > t) ? x - t : t - x;	/* |x - history[h]| */
		history[h] = x;
		x = t;
		if (min > x)
			min = x;
	}
	return min;
}


	static PGPUInt32
sCollectEntropy()
{
	PGPUInt32			delta;
	PGPRandomContext	rc;
	
	/* call machine specific routine to get some entropy */
	pgpInitGlobalRandomPoolContext( &rc );
	delta	= pgpRandomCollectEntropy( &rc );
	
	return( delta );
}


/*
 * Gather and estimate entropy from keyboard timings.  Double letters
 * are allowed, but triples and more are considered suspiscious and
 * entropy is not counted.  (The actual criterion is that the current
 * letter has appeared more than once in the previous four letters,
 * which rejects aaaa... and ababa...)
 *
 * The "letter" can be generalized to mouse-clicks, button-pushes, menu
 * selections, or anything else that can be categorized into a finite
 * number of events.
 *
 * Question: is there a way to achieve this effect without remembering
 * the recent keystrokes so explicitly?  It seems like a possible
 * security hole.
 *
 * We incorporate entropy from the first 3 samples, but don't count them
 * since only after that many do we get reliable per-sample entropy estimates.
 * (This is time for the two entries in teh hist array to get initialized,
 * plus the one level of delta history implicitly included in the
 * ranGetEntropy timing.  It has to be there unless we want to export
 * knowledge about the modulus at which the timer it uses wraps.)
 */
	PGPUInt32
PGPGlobalRandomPoolAddKeystroke( PGPInt32 event)
{
	static PGPInt32		pastevent[4];	/* Last 4 events */
	static PGPUInt32	hist[2];
	static unsigned		histcount=elemsof(hist)+1;
						/* # invalid entries in hist array */
	PGPUInt32			delta;
	unsigned			n = 0;
	int					i;
	RandomPool			*pool = GetPool();
	PGPUInt32			result;
	

	delta = sCollectEntropy();
	delta = randEstimate(delta, hist, elemsof(hist));
    
	PGPRMWOLockStartWriting( &pool->criticalLock );

	sRandPoolAddBytes(NULL, (PGPByte *)&event, sizeof(event));

	/* Check for repetitive keystroke patterns */
	i = elemsof(pastevent) - 1;
	n = (event == pastevent[i]);
	do {
		n += (event == (pastevent[i] = pastevent[i-1]));
	} while (--i);
	pastevent[0] = event;

	if (histcount > 0) {
		/* Not yet filled hist array */
		--histcount;
		result = 0;
	}
	else if( n > 1 )
	{
		result = 0;
	}
	else
	{
		result = pgpGlobalRandomPoolEntropyWasAdded(delta);
	}
	
	PGPRMWOLockStopWriting( &pool->criticalLock );

	return( result );
}

/*
 * Generate entropy from mouse motion.  This simply measures entropy
 * of timing, although that may be pretty low due to OS synchrony.
 *
 * We incorporate entropy from the first 2 samples, but don't count them
 * since only after that many do the predictors start working.
 */
 
	PGPUInt32
PGPGlobalRandomPoolMouseMoved(void)
{
	static PGPUInt32	hist[2];			/* Timing history */
	static unsigned		histcount=elemsof(hist);
						/* # invalid entries in histx array */
	PGPUInt32			delta;				/* Timing delta */
	RandomPool			*pool = GetPool();
	PGPUInt32			result;
	
	delta = sCollectEntropy();
	delta = randEstimate(delta, hist, elemsof(hist));

	PGPRMWOLockStartWriting( &pool->criticalLock );

	/* Wait until we have filled our arrays to start counting entropy */
	if (histcount > 0)
	{
		--histcount;
		result = 0;
	}
	else
	{
		result = pgpGlobalRandomPoolEntropyWasAdded(delta);
	}
	
	PGPRMWOLockStopWriting( &pool->criticalLock );
	
	return( result );
}

/*
 * Generate entropy from mouse motion. This all is provided for backwards
 * compatability. Mouse coordinates are no longer used.
 */
 
	PGPUInt32
PGPGlobalRandomPoolAddMouse(
	PGPUInt32		x,
	PGPUInt32		y)
{
	(void) x;
	(void) y;
	
	return( PGPGlobalRandomPoolMouseMoved() );
}


/*
 *	DUMMY POOL
 *
 *	The dummy pool is a pluggable replacement for the RandPool to be used
 *	for generating values which we want to be unique but don't have to be
 *	cryptographically strong: such as the p and q values used in discrete
 *	log keys.  We prefer not to use the regular RandPool for such values
 *	so that we don't leak information about the secret values which are
 *	calculated in close proximity.
 *
 *	The dummy pool should be used as the "base" paramater for
 *	pgpRandomCreateX9_17.  It always returns 0 values, and the X9.17 RNG
 *	will then produce non-cryptographically-strong pseudo-random numbers.
 *
 *	Use pgpRandomAddBytes on the X9.17 RandomContext to seed it.
 */

/* Dummy pool always returns zeros */
	static void
sDummyPoolGetBytesEntropy(
	void *			priv,
	PGPByte *		buf,
	unsigned		len,
	unsigned		bits)
{
	(void)priv;
	(void)bits;
	
	pgpClearMemory( buf, len );
}

	static void
sDummyPoolAddBytes(
	void *			priv,
	PGPByte const *	p,
	unsigned		len)
{
	(void)priv;
	(void)p;
	(void)len;
}
	static void
sDummyPoolStir(void *priv)
{
	(void)priv;
}

static const PGPRandomVTBL sDummyRandomPoolVTBL =
{
	"Dummy random-number pool",
	sDummyPoolAddBytes,
	sDummyPoolGetBytesEntropy,
	sDummyPoolStir
};


	PGPRandomVTBL const *
pgpGetGlobalDummyRandomPoolVTBL( void )
{
	return( &sDummyRandomPoolVTBL );
}

PGPError
PGPGlobalRandomPoolAddSystemState()
{
	PGPRandomContext rc;
	
	pgpInitGlobalRandomPoolContext( &rc );
	if (pgpRandomCollectOsData( &rc )) {
		pgpSetIsSeeded();
		return kPGPError_NoErr;
	}
	else {
		return kPGPError_UnknownError;
	}
}


/*
 * Accumulate entropy from key into pool.
 * See comments with pgpGlobalRandomPoolEntropyWasAdded for how
 * the arithmetic works.
 */
static void
sRandAddKeyEntropy( RandomPool *pool )
{
	PGPUInt32		frac,		/* Fractional bits to add */
					keyfrac,
					t;
	PGPUInt32		n;			/* Number of whole bits to add */

	/* Add entropy from randKey into randPool */
	keyfrac = pool->randKeyFrac;
	frac = pool->randFrac;
	n = pool->randKeyBits;
	UMULH_32(t,keyfrac,frac);

	/* The comparison idiom used here detects overflow on addition */
	if ((frac += t) < t) {
		if ((frac += keyfrac) < keyfrac)
			frac = (frac >> 1) + 0x80000000ul;
		else
			frac >>= 1;
		n++;
	} else if ((frac += keyfrac) < keyfrac) {
		frac >>= 1;
		n++;
	}

	pool->randFrac = frac;
	if ((pool->randBits += n) >= RANDPOOLBITS) {
		/* Overflow - saturate at RANDPOOLBITS */
		pool->randBits = RANDPOOLBITS;
		pool->randFrac = 0;
	}
	/* Also count the inflow without regard to outflow */
	if ((pool->randInBits += n) >= RANDPOOLBITS) {
		pool->randInBits = RANDPOOLBITS;
	}
	pool->randKeyBits = pool->randKeyFrac = 0;
}


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
