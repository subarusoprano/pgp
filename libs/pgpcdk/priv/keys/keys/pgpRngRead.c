/*
 * pgpRngRead.c - Read in various parts of a keyring.
 *
 * The big function (>500 lines, yeep!) is ringFileOpen(); it opens another
 * keyring and merges it with the collection in memory.	 Most of the others
 * are its helpers.  This is where PGPlib's great robustness in the face of
 * badly mangled keyrings is achieved.	*Every* keyring comes through here,
 * and it validates its inputs to the point of paranoia.
 *
 * This file is too big - what should be split out?
 * There are a lot of similar-but-not-quite functions.	Perhaps some
 * rethinking will allow parts of them to be merged?
 *
 * Written by Colin Plumb.
 *
 * $Id: pgpRngRead.c,v 1.96.18.1 2000/08/25 01:48:26 hal Exp $
 */
#include "pgpConfig.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "pgpDebug.h"
#include "pgpMakeSig.h"
#include "pgpMemPool.h"
#include "pgpPktByte.h"
#include "pgpRngMnt.h"
#include "pgpRngPars.h"
#include "pgpRngPkt.h"
#include "pgpRngPriv.h"
#include "pgpTrust.h"
#include "pgpTrstPkt.h"		/* for PGP_SIGTRUSTF_CHECKED_TRIED */
#include "pgpHash.h"
#include "pgpKeySpec.h"
#include "pgpMem.h"
#include "pgpSymmetricCipherPriv.h"
#include "pgpEnv.h"
#include "pgpErrors.h"
#include "pgpPubKey.h"
#include "pgpFile.h"
#include "pgpRngRead.h"
#include "pgpSigSpec.h"
#include "pgpContext.h"
#include "pgpX509Priv.h"

#ifndef NULL
#define NULL 0
#endif

static PGPContextRef
RingSetGetContext( const RingSet *set )
{
	pgpAssert( pgpContextIsValid( set->pool->context ) );
	return( set->pool->context );
}


/*
 * The largest legal PGP key uses a 64Kbit key, which is 8Kbytes.
 * As a public key, there's also 12 bytes of overhead, plus a
 * public exponent (usually 1 byte, sometimes 3, it's just stupid
 * to make it any larger).  
 * Stored in a secret key an extra 11+IV bytes of overhead and
 * the secret exponent (8K), factors p and q (4+4=8K), and multiplicative
 * inverse u (4K).  A total of 28K of data, plus 23+IV+e extra bytes.
 * With an 8-byte IV, that's 31+e bytes.  Add an extra byte to allow
 * for p and q of differing lengths.
 * But for now, reduce this by a factor of 8, to 8Kbits, which changes
 * the maximum sizes to 1K+overhead and 3.5K + overhead.
 *
 * Without these limits, a non-fatal error (object too big) becomes
 * a fatal error (out of memory) and the implementation becomes
 * less robust.  However, the limits can be set quite high without
 * harm.  (Keep the maximum key size to 64K, though.)
 *
 * The limits above were derived for RSA keys.  DSA/ElG keys have a prime
 * p, a small (~160 bit) prime q, a generator g, and a public exponent y.
 * That's four numbers, one of them small.  If we allow enough space for four
 * full-sized numbers that should be safe.  Secrets have in addition a
 * secret exponent x, generally small, so allow an additional number.
 * Signatures are small with DSA, two 160 bit numbers.  However the new
 * signature packets can in principle have a lot of data.  Allow two full
 * sized numbers to give us plenty of room; we may have to increase the value
 * in the future.
 */
//BEGIN RSA KEYSIZE MOD - Imad R. Faiad
//#define RINGMPI_MAX	1024				/* Maximum 8Kbits */
#define RINGMPI_MAX	4096	/* Maximum 32Kbits */
//END RSA KEYSIZE MOD				/* Maximum 8Kbits */
#define RINGKEY_MAXLEN	(4*RINGMPI_MAX)	/* Public key maximum size */
#define RINGSEC_MAXLEN	(5*RINGMPI_MAX)	/* Secret key maximum size */
#define RINGNAME_MAXLEN	150000			/* Name/attribute maximum size */
#define RINGSIG_MAXLEN	150000			/* Signature maximum size */
#define RINGCRL_MAXLEN	MAX_PGPSize		/* CRL maximum size */
#define RINGUNK_MAXLEN	RINGSEC_MAXLEN
/* RINGTRUST_MAXLEN is implicit */

/* Threshold for caching name/attribute objects in memory */
#define NAMECACHETHRESHOLD	1024

/*** Working with the FilePos chain ***/

/*
 * A note about the FilePos chain.  Each object has one FilePos right
 * inside itself, which is the head of a list of external (allocated)
 * ones.  There is one FilePos for each key file an object exists in,
 * and they are kept in increasing order by bit number.
 * Every object (except dummy keys, which aren't excessively numerous,
 * especially in large keyrings) is present in at least one physical
 * keyring, so this saves one next pointer when we're trying to conserve
 * memory for MS-DOS, at the expense of complicating the task of
 * adding to and removing from the list.
 *
 * This is because the first entry in the chain is statically allocated.
 * An actual allocation is performed when an entry is added to the
 * chain in a location other than the first, or is bumped from first
 * place by something else.  A FilePos is freed when an entry is deleted
 * from the chain, or the first one is deleted and the second moves into
 * its place.
 *
 * One more special feature: the MEMRING filepos is put as the last entry
 * in the chain.  In that filepos, the "next" pointer actually points at
 * the memory data, and the fpos field holds the size of the memory block.
 */

/* Find the position of an object in the given file */
static FilePos *
ringFilePos(union RingObject const *obj, RingFile const *file)
{
	FilePos const *pos = &obj->g.pos;
	PGPVirtMask mask;
	RingPool *pool = file->set.pool;

	pgpVirtMaskInit (pool, &mask);
	pgpVirtMaskCopy (pool, &obj->g.mask, &mask);
	pgpVirtMaskAND (pool, &pool->filemask, &mask);
	/* Keep only bits before the one we are interested in */
	/* But for MEMRING go to the last in the chain */
	pgpVirtMaskANDNOT(pool, &pool->memringmask, &mask);
	if (!pgpVirtMaskIsEqual (&file->set.mask, &pool->memringmask)) {
		PGPInt32 filebit = pgpVirtMaskLSBit (&file->set.mask);
		pgpVirtMaskClearGreaterBits (pool, &mask, filebit);
	}
	while (!pgpVirtMaskIsEmpty(&mask)) {
		PGPInt32 bit = pgpVirtMaskLSBit (&mask);
		pgpAssert (bit >= 0);
		pgpVirtMaskClearBit (pool, &mask, bit);
		pos = pos->ptr.next;
	}
	pgpVirtMaskCleanup (pool, &mask);
	return (FilePos *)pos;
}

/* Allocate a FilePos from a RingFile. */
static FilePos *
ringFileNewFilePos(RingFile *file)
{
	FilePos *pos = file->freepos;

	if (pos) {
		file->freepos = pos->ptr.next;
	} else {
		pos = (FilePos *)memPoolNew(&file->fpos,FilePos);
		if (!pos)
			ringAllocErr(file->set.pool);
	}

	return pos;
}

static void
ringFileFreeFilePos(RingFile *file, FilePos *pos)
{
	pos->ptr.next = file->freepos;
	file->freepos = pos;
}

/*
 * Allocate and add a FilePos to the object's chain in the right place.
 * This function makes no attempt to initialize the resultant FilePos.
 *
 * NOTE that the bit specified to add may or may not be present in
 * the ring's filemask.  This function must not care.
 */
static FilePos *
ringAddFilePos(union RingObject *obj, RingFile *file)
{
	RingPool *pool = file->set.pool;
	PGPVirtMask mask, tmpmask;
	FilePos *pos, *pos2;
	PGPInt32 bit;
	RingFile *file2;

	pgpVirtMaskInit (pool, &mask);
	pgpVirtMaskInit (pool, &tmpmask);

	pgpVirtMaskCopy (pool, &obj->g.mask, &mask);
	pgpVirtMaskAND (pool, &pool->filemask, &mask);

	pgpAssert (!pgpVirtMaskIsOverlapping (&mask, &file->set.mask));

	pgpVirtMaskCopy (pool, &mask, &tmpmask);
	pgpVirtMaskANDNOT (pool, &pool->memringmask, &tmpmask);
	if (!pgpVirtMaskIsEqual(&pool->memringmask, &file->set.mask)) {
		PGPInt32 filebit = pgpVirtMaskLSBit (&file->set.mask);
		pgpVirtMaskClearGreaterBits (pool, &tmpmask, filebit);
	}
	if (!pgpVirtMaskIsEmpty (&tmpmask)) {
		/* FilePos to add is not the first in the chain */
		pgpVirtMaskCopy (pool, &tmpmask, &mask);
		pos2 = ringFileNewFilePos(file);
		if (!pos2)
			return NULL;
		/* Find the predecessor of the one to be added */
		pos = &obj->g.pos;
		bit = pgpVirtMaskLSBit (&mask);
		pgpAssert (bit >= 0);
		pgpVirtMaskClearBit (pool, &mask, bit);
		while ((bit = pgpVirtMaskLSBit (&mask)) >= 0) {
			pos = pos->ptr.next;
			pgpAssert(IsntNull(pos));
			pgpVirtMaskClearBit (pool, &mask, bit);
		}
		/* Insert pos2 into the chain after pos */
		pos2->ptr.next = pos->ptr.next;
		pos->ptr.next = pos2;
	} else {
		/* First FilePos in the chain */
		pos2 = &obj->g.pos;
		if (pgpVirtMaskIsEmpty(&mask)) {
			/* First and only FilePos on chain */
			pos = NULL;
		} else {
			/* First FilePos; bump down the old first */
			bit = pgpVirtMaskLSBit(&mask);
			pgpAssert(bit >= 0);
			/* Allocate pos from pool for existing bit */
			file2 = file->set.pool->files[bit];
			pos = ringFileNewFilePos(file2);
			if (!pos)
				return NULL;
			*pos = *pos2;
		}
		pos2->ptr.next = pos;
	}
	pgpVirtMaskOR (pool, &file->set.mask, &obj->g.mask);
	pgpVirtMaskCleanup (pool, &mask);
	pgpVirtMaskCleanup (pool, &tmpmask);
	return pos2;
}

static int
ringAddPos(union RingObject *obj, RingFile *file, PGPUInt32 fpos)
{
	FilePos *pos;

	pos = ringAddFilePos(obj, file);
	if (!pos)
		return kPGPError_OutOfMemory;
	pos->fpos = fpos;
	return 0;
}

/*
 * This is needed in one obscure error case to keep things
 * consistent.  The case is when a secret key appears in the same
 * file as the corresponding public key, only later.
 */
static void
ringAlterFilePos(union RingObject *obj, RingFile const *file,
	PGPUInt32 fpos)
{
	PGPVirtMask mask;
	RingPool *pool = file->set.pool;
	FilePos *pos;

	pgpVirtMaskInit (pool, &mask);
	pgpVirtMaskCopy (pool, &obj->g.mask, &mask);
	pgpVirtMaskAND (pool, &pool->filemask, &mask);

	pgpAssert (pgpVirtMaskIsOverlapping(&mask, &file->set.mask));
	
	pgpVirtMaskANDNOT (pool, &pool->memringmask, &mask);

	if (!pgpVirtMaskIsEqual (&file->set.mask, &pool->memringmask)) {
		PGPInt32 filebit = pgpVirtMaskLSBit (&file->set.mask);
		pgpVirtMaskClearGreaterBits (pool, &mask, filebit);
	}
	pos = &obj->g.pos;
	while (!pgpVirtMaskIsEmpty (&mask)) {
		PGPInt32 bit = pgpVirtMaskLSBit (&mask);
		pgpVirtMaskClearBit (pool, &mask, bit);
		pos = pos->ptr.next;
	}
	pos->fpos = fpos;
	pgpVirtMaskCleanup (pool, &mask);
}

/*
 * Remove a FilePos from an object's list.
 *
 * file is the filepos corresponding to "bit", pos is the head of a
 * FilePos chain, mask is the bitmask of physical key rings, and
 * bit is the number of the ring to have its position removed.
 *
 * NOTE that the bit specified to remove may or may not be present in
 * the ring->filemask.  This function must not care.
 */
static void
ringRemFilePos(union RingObject *obj, RingFile *file)
{
	PGPVirtMask mask, tmpmask;
	RingPool *pool = file->set.pool;
	FilePos *pos, *pos2;
	PGPInt32 bit;
	RingFile *file2;

	pgpVirtMaskInit (pool, &mask);
	pgpVirtMaskInit (pool, &tmpmask);

	pgpVirtMaskCopy (pool, &obj->g.mask, &mask);
	pgpVirtMaskAND (pool, &pool->filemask, &mask);

	/* Is the bit to remove *not* the least significant bit? */
	pgpVirtMaskCopy (pool, &mask, &tmpmask);
	pgpVirtMaskANDNOT (pool, &pool->memringmask, &tmpmask);
	if (!pgpVirtMaskIsEqual (&file->set.mask, &pool->memringmask)) {
		bit = pgpVirtMaskLSBit (&file->set.mask);
		pgpVirtMaskClearGreaterBits (pool, &tmpmask, bit);
	}
	if (!pgpVirtMaskIsEmpty (&tmpmask)) {
		/* FilePos to remove is not the first in the chain */
		/* Find the predecessor of the one to be removed */
		pgpVirtMaskCopy (pool, &tmpmask, &mask);
		pos = &obj->g.pos;
		bit = pgpVirtMaskLSBit (&mask);
		pgpAssert (bit >= 0);
		pgpVirtMaskClearBit (pool, &mask, bit);
		while ((bit = pgpVirtMaskLSBit (&mask)) >= 0) {
			pos = pos->ptr.next;
			pgpAssert(IsntNull(pos));
			pgpVirtMaskClearBit (pool, &mask, bit);
		}
		/* pos->next is the one to be removed */
		pos2 = pos->ptr.next;
		pgpAssert(IsntNull(pos2));
		pos->ptr = pos2->ptr;
		if (pgpVirtMaskIsEqual (&file->set.mask, &pool->memringmask))
			pos->ptr.next = NULL;	/* debugging aid */
		file2 = file;
	} else {
		/* First FilePos - copy second to first, remove second */

		/* Clear this bit from the mask (in case we need to) */
		pgpVirtMaskANDNOT (pool, &file->set.mask, &mask);

		/*
		 * That's it?  Well, return then.  The caller better
		 * deallocate this object, 'cause it no longer exists
 		 * anywhere.  Use position -1 to mark an unused slot.
		 */
		if (pgpVirtMaskIsEmpty(&mask)) {
			pgpVirtMaskANDNOT (pool, &file->set.mask, &obj->g.mask);
			if (pgpVirtMaskIsEqual (&file->set.mask, &pool->memringmask))
				obj->g.pos.ptr.next = NULL;		/* Debugging aid */
			obj->g.pos.fpos = (PGPUInt32)-1;	/* Debugging aid */
			pgpVirtMaskCleanup (pool, &mask);
			pgpVirtMaskCleanup (pool, &tmpmask);
			return;
		}

		/* Find the bit of the fpos we are removing, the 2nd fpos in list */
		/* Note we have already cleared the bit for the 1st fpos */
		pgpVirtMaskANDNOT (pool, &pool->memringmask, &mask);
		if (pgpVirtMaskIsEmpty(&mask))
			bit = 0;
		else
			bit = pgpVirtMaskLSBit (&mask);
		pgpAssert(bit >= 0);
		file2 = file->set.pool->files[bit];	/* where to stash reclaimed pos */

		/* Copy the next pos to the current one */
		pos2 = obj->g.pos.ptr.next;
		pgpAssert(IsntNull(pos2));
		obj->g.pos = *pos2;
	}
	/* Free the FilePos */
	ringFileFreeFilePos(file2, pos2);
	pgpVirtMaskANDNOT (pool, &file->set.mask, &obj->g.mask);
	pgpVirtMaskCleanup (pool, &mask);
	pgpVirtMaskCleanup (pool, &tmpmask);
}


/* Remove an object and its children from a specific file */
/* If an object is left unhomed, delete it */
static void
ringRemFileObjChildren(union RingObject *obj, RingFile *file)
{
	RingPool *pool = file->set.pool;
	RingObject *obj1, *nextobj1;
	RingObject *obj2, *nextobj2;

	if (pgpIsRingSetMember(&file->set, obj)) {
		ringRemFilePos(obj, file);
		if (!OBJISBOT(obj)) {
			for (obj1=obj->g.down; obj1; obj1=nextobj1) {
				nextobj1 = obj1->g.next;
				if (pgpIsRingSetMember(&file->set, obj1)) {
					ringRemFilePos(obj1, file);
					if (!OBJISBOT(obj1)) {
						for (obj2=obj1->g.down; obj2; obj2=nextobj2) {
							nextobj2 = obj2->g.next;
							if (pgpIsRingSetMember(&file->set, obj2)) {
								ringRemFilePos(obj2, file);
								if (!pgpVirtMaskIsOverlapping (&obj2->g.mask,
														&pool->filemask))
									ringRemObject (pool, obj2);
							}
						}
					}
					if (!pgpVirtMaskIsOverlapping (&obj1->g.mask,
												   &pool->filemask)) {
						/* Parents share all homes of children */
						pgpAssert (OBJISBOT(obj1) || IsNull(obj1->g.down));
						ringRemObject (pool, obj1);
					}
				}
			}
		}
		if (!pgpVirtMaskIsOverlapping (&obj->g.mask, &pool->filemask)) {
			pgpAssert (OBJISBOT(obj) || IsNull(obj->g.down));
			ringRemObject (pool, obj);
		}
	}
}



/*** Closing a Ringfile ***/

/*
 * Set the destruction function for a RingFile.
 */
void
ringFileSetDestructor(RingFile *file,
	void (*destructor)(RingFile *, PGPFile *, void *),
	void *arg)
{
	file->destructor = destructor;
	file->arg = arg;
}

/*
 * Helper function for ringFileDoClose.
 *
 * Delete the given file's FilePos entries from the objects in
 * the given list, and delete the objects if they are no longer
 * needed (mask has gone to 0).  Recurse as necessary.
 *
 * Note that this is not used on the main keys list, because
 * there we need to preserve dummy keys which this does not
 * understand.
 *
 * This also removes any cached names from objects.
 */
static void
ringFileCloseList(union RingObject **objp, RingFile *file,
	PGPVirtMask *allocmask)
{
	union RingObject *obj;
	PGPVirtMask mask;
	RingPool *pool = file->set.pool;

	pgpVirtMaskInit (pool, &mask);

	while ((obj = *objp) != NULL) {
		/*
		 * Delete low-level objects with mask==0 as well as objects on
		 * the ringfile which is going away.  We create those objects, e.g.
		 * when importing a non-exportable sig, and then they prevent the
		 * parent objects from being deleted properly, later leading to
		 * an assertion in keysdiffer.
		 */
		if (pgpIsRingSetMember(&file->set, obj) ||
			pgpVirtMaskIsEmpty (&obj->g.mask)) {
			if (!OBJISBOT(obj))
				ringFileCloseList(&obj->g.down, file, allocmask);
			ringRemFilePos(obj, file);
			/*
			 * Delete objects which have no homes other than MEMRING.
			 * But:
			 * Do not delete objects which have children, because they may
			 * have a child obj in the MEMRING which didn't get deleted
			 * because it was not in this RingFile.
			 * Do not delete objects whose only home is in the MEMRING
			 * but which are currently in use in active RingSets.  They
			 * may be newly created objects which will soon be given homes
			 * in some other RingFile.
			 */
			pgpVirtMaskCopy (pool, &pool->filemask, &mask);
			pgpVirtMaskANDNOT (pool, &pool->memringmask, &mask);
			if (!pgpVirtMaskIsOverlapping (&mask, &obj->g.mask)
					&& (OBJISBOT(obj) || !obj->g.down)
					&& !pgpVirtMaskIsOverlapping (allocmask, &obj->g.mask)) {
				*objp = obj->g.next;
				ringFreeObject(file->set.pool, obj);
			} else {
				/*
				 * If a name is cached from the file which is closing,
				 * purge it since the file's strings table holds the cached
				 * names and it's going away.
				 */
				if (OBJISNAME(obj))
					ringPurgeCachedName(file->set.pool, &obj->n,
										&file->set.mask);
				objp = &obj->g.next;
			}
		} else
			objp = &obj->g.next;
	}
	pgpVirtMaskCleanup (pool, &mask);
}

/*
 * Close the given Ringfile.  Returns an error if it can't due to
 * conflicts, in which case the file is NOT closed.
 *
 * This performs four passes over the pool.
 * 1. The first does the bulk of the deletion, removing the
 *    FilePos from the objects and deleting all things
 *    at levels greater than 1.
 * 2. The second rebuilds the sigs-by lists which were broken by
 *    deleting objects in the middle of them.
 * 3. The third finds all keys that are not referenced and do not
 *    make any signatures, and deletes those keys.
 * 4. The fourth rebuilds the hash index of the remaining keys.
 *
 * Note that the second and third passes delete any allocated-but-not
 * linked keys, which are left by ringFileOpen if it runs out of memory
 * in mid-operation.
 */
static void
ringFileDoClose(RingFile *file)
{
	union RingObject *obj, **objp;
	RingPool *pool = file->set.pool;
	int i;
	PGPVirtMask allocmask;
	PGPVirtMask mask;
	PGPUInt32 filebit;

	pgpVirtMaskInit (pool, &allocmask);
	pgpVirtMaskInit (pool, &mask);

	ringAllocMask (pool, &file->set, &allocmask);

	/* Free some memory right away */
	ringFilePurgeTrouble(file);

	/* 1: Remove everything in the keyring, but don't delete the keys */
	for (obj = pool->keys; obj; obj = obj->g.next) {
		if (pgpIsRingSetMember (&file->set, obj)) {
			if (!OBJISBOT(obj))
				ringFileCloseList(&obj->g.down, file, &allocmask);
			ringRemFilePos(obj, file);
		}
	}

	/* 2: Recreate the shattered sigs-by lists */
	ringPoolListSigsBy(pool);

	/* 3: Now purge the unneeded keys */
	objp = &pool->keys;
	while ((obj = *objp) != NULL) {
		pgpAssert(OBJISTOPKEY(obj));
		pgpVirtMaskCopy (pool, &obj->g.mask, &mask);
		pgpVirtMaskANDNOT (pool, &pool->memringmask, &mask);
		if (pgpVirtMaskIsOverlapping (&mask, &pool->filemask) || obj->g.down) {
			objp = &obj->g.next;
		} else if (obj->k.sigsby) {
			/* Retain key as a dummy key */
			pgpAssert(!pgpVirtMaskIsOverlapping (&mask, &allocmask));
			pgpAssert(!obj->g.down);
			pgpVirtMaskCleanup (pool, &obj->g.mask);
			objp = &obj->g.next;
		} else {
			/* Delete the key */
			pgpAssert(!pgpVirtMaskIsOverlapping (&mask, &allocmask));
			pgpAssert(!obj->g.down);
			*objp = obj->g.next;
			ringFreeObject(pool, obj);
		}
	}

	/* 4: Re-initialize the hash chains */
	ringPoolHash(pool);

	/* Clean up the file's memory pools */
	memPoolEmpty(&file->strings);
	file->freepos = NULL;
	memPoolEmpty(&file->fpos);

	pgpAssert(!file->set.next);

	/*
	 * If there's nothing in the structs MemPool that's
	 * allocated, purge all the memory.
	 */
	if (!pool->keys && !pool->sets) {
		for (i = 0; i < RINGTYPE_MAX; i++)
			pool->freeobjs[i] = NULL;
		pool->freesets = NULL;
		pool->freeiter = NULL;
		memPoolEmpty(&pool->structs);
	}

	/* Cal the file's destructor function, if any */
	if (file->destructor) {
		file->destructor(file, file->f, file->arg);
		file->destructor = NULL;
	}

	/* Final deallocation of the file */
	file->flags = 0;
	pgpVirtMaskANDNOT (pool, &file->set.mask, &pool->filemask);

	filebit = pgpVirtMaskLSBit (&file->set.mask);
	pgpVirtMaskCleanup (pool, &file->set.mask);
	pgpVirtMaskCleanup (pool, &file->higherpri);
	pgpAssert (pool->files[filebit] == file);
	pgpContextMemFree (pool->context, file);
	pool->files[filebit] = NULL;

	pgpVirtMaskCleanup (pool, &mask);
	pgpVirtMaskCleanup (pool, &allocmask);
}

/*
 * Check to see if an object anywhere on the list (including children,
 * recursively) is included in "allocmask" but not in "filemask."
 * Such an object is orphaned, an undesirable state of affairs.
 * We have to check the entire keyring, recursively, because a
 * given key or name might be duplicated in another keyring, but
 * a signature lower down might not be.
 */
static int
ringFileCheckList(union RingObject const *obj, PGPVirtMask *filemask,
	PGPVirtMask *allocmask)
{
	while (obj) {
		if (pgpVirtMaskIsOverlapping (&obj->g.mask, allocmask)) {
			/* Would closing orphan this object? */
			if (!pgpVirtMaskIsOverlapping (&obj->g.mask, filemask))
				return 1;
			/* Would closing orphan its children? */
			if (!OBJISBOT(obj) && ringFileCheckList(obj->g.down,
			                                        filemask,
			                                        allocmask))
				return 1;
		}
		obj = obj->g.next;
	}
	return 0;
}

/* Is it safe to close the given file? */
int
ringFileCheckClose(RingFile const *file)
{
	RingPool const *pool = file->set.pool;
	int rtrn;
	PGPVirtMask allocmask;
	PGPVirtMask mask;

	if (!file)
		return 0;
	pgpVirtMaskInit (pool, &allocmask);
	pgpVirtMaskInit (pool, &mask);
	ringAllocMask (pool, &file->set, &allocmask);
	pgpVirtMaskCopy (pool, &pool->filemask, &mask);
	pgpVirtMaskANDNOT (pool, &file->set.mask, &mask);

	rtrn = ringFileCheckList(pool->keys, &mask, &allocmask);

	pgpVirtMaskCleanup (pool, &allocmask);
	pgpVirtMaskCleanup (pool, &mask);
	return rtrn;
}

/*
 * Close the given Ringfile.  Returns an error if it can't due to
 * conflicts, in which case the file is NOT closed.
 */
	PGPError
ringFileClose(RingFile *file)
{
	if (!file)
		return kPGPError_NoErr;	/* close(NULL) is defines as harmless */

	if (ringFileCheckClose(file))
		return kPGPError_LazyProgrammer;

	/* Okay, nothing can fail now */
	ringFileDoClose(file);

	return kPGPError_NoErr;
}

/*** Routines for fetching things from the keyring ***/

/* Make sure the pool's packet buffer is large enough */
char *
ringReserve(RingPool *pool, size_t len)
{
	PGPError	err	= kPGPError_NoErr;

	if (pool->pktbufalloc >= len)
		return pool->pktbuf;
	
	if( IsNull( pool->pktbuf ) ) {
		pool->pktbuf = (char *)
			pgpContextMemAlloc( pool->context, len, 0 );
				
		if( IsNull( pool->pktbuf ) )
			err = kPGPError_OutOfMemory;
	} else {
		void *vpktbuf = pool->pktbuf;
		err	= pgpContextMemRealloc( pool->context, &vpktbuf, len,
									0 );
		pool->pktbuf = (char *)vpktbuf;
	}
	if ( IsPGPError( err ) )
	{
		ringAllocErr(pool);
		return NULL;
	}
	pool->pktbufalloc = len;
	return pool->pktbuf;
}


/*
 * File priorities are handled by a "higherpri" mask with each file,
 * which is a mask of other files of higher priority than that file.
 * If obj->g.mask & pool->filmask && file->higherpri is 0,
 * this is the highest-priority file.
 */
/* Set file to the highest priority, except for the memory file */
void
ringFileHighPri(RingFile *file)
{
	RingPool *pool = file->set.pool;
	unsigned i;

	/* Add this file to everything else's higher priority mask */
	for (i = 0; i < pool->nfiles; i++)
		if (IsntNull(pool->files[i]))
			pgpVirtMaskOR (pool, &file->set.mask, &pool->files[i]->higherpri);
	/* The only thing higher priority than this file is MEMRING */
	pgpVirtMaskCopy (pool, &pool->memringmask, &file->higherpri);
}

/* Set file to the lowest priority */
void
ringFileLowPri(RingFile *file)
{
	RingPool *pool = file->set.pool;
	unsigned i;

	/* Remove this file from everything else's higher priority mask */
	for (i = 0; i < pool->nfiles; i++) {
		if (IsntNull(pool->files[i])) {
			pgpVirtMaskANDNOT (pool, &file->set.mask,
							   &pool->files[i]->higherpri);
			if (pool->files[i] != file)
				pgpVirtMaskSetBit (pool, &file->higherpri, i);
		}
	}
}


/* The mask of sets that this key has *any* secret components in */
static PGPError
ringKeySecMask(RingPool *pool, RingObject const *obj, PGPVirtMask *omask)
{
	pgpAssert(OBJISKEY(obj));

	pgpVirtMaskCleanup (pool, omask);
	for (obj = obj->g.down; obj; obj = obj->g.next)
		if (OBJISSEC(obj)) {
			pgpVirtMaskOR (pool, &obj->g.mask, omask);
		}
	return kPGPError_NoErr;
}

/*
 * Given an object, find the best RingFile to fetch it from,
 * for fetching purposes.  Bits set in "avoidmask" are
 * NOT valid for fetching, if avoidmask is nonnull.
 */
static RingFile *
ringBestFile(RingPool *pool, union RingObject const *obj,
	PGPVirtMask *avoidmask)
{
	PGPVirtMask mask, tmpmask;
	RingFile *file;
	int bit;

	pgpVirtMaskInit (pool, &mask);
	pgpVirtMaskInit (pool, &tmpmask);

	pgpVirtMaskCopy (pool, &obj->g.mask, &mask);
	pgpVirtMaskAND (pool, &pool->filemask, &mask);

	pgpVirtMaskCopy (pool, &mask, &tmpmask);
	if (IsntNull(avoidmask))
		pgpVirtMaskANDNOT (pool, avoidmask, &tmpmask);
	if (pgpVirtMaskIsEmpty (&tmpmask)) {
		pgpVirtMaskCleanup (pool, &mask);
		pgpVirtMaskCleanup (pool, &tmpmask);
		return NULL;
	}

	/* find highest-priority fetchable file */
	for (;;) {
		/* Is least-significant bit set in mask fetchable? */
		bit = pgpVirtMaskLSBit (&mask);
		pgpVirtMaskCleanup (pool, &tmpmask);
		pgpVirtMaskSetBit (pool, &tmpmask, bit);
		if (IsNull(avoidmask) ||
			!pgpVirtMaskIsOverlapping (&tmpmask, avoidmask)) {
			file = pool->files[bit];
			/* Is it highest priority? */
			pgpVirtMaskCopy (pool, &mask, &tmpmask);
			if (IsntNull(avoidmask))
				pgpVirtMaskANDNOT (pool, avoidmask, &tmpmask);
			if (!pgpVirtMaskIsOverlapping (&tmpmask, &file->higherpri))
				break;
			pgpAssert(file->f);
		}
		pgpVirtMaskClearBit (pool, &mask, bit);
		pgpAssert(!pgpVirtMaskIsEmpty(&mask));
	}
	pgpVirtMaskCleanup (pool, &mask);
	pgpVirtMaskCleanup (pool, &tmpmask);
	return file;
}

/* Macro wrapper to inline the important part */
#define ringReserve(pool, len) \
	((pool)->pktbufalloc < (len) ? ringReserve(pool, len) : (pool)->pktbuf)

/* 
 * This is the routine which fetches a packet from a keyring file.
 * It tries the highest-priority file that the object is in which is also
 * listed in "avoidmask."  If the memory keyring is one of those, it has
 * absolute priority.  (It is also not verified; it is assumed correct.)
 * Otherwise, the object is fetched from the highest-priority open file.
 *
 * The files are assigned priorities for fetching.  The default is
 * that the first opened file is highest and subsequent files are of
 * lower priority.  This is done by having each Ringfile keep a mask
 * of higher-priority RingFiles.  We walk along the list until we hit
 * a RingFile whose higher-priority mask doesn't include any files that
 * the object being sought is in.
 *
 * The packet fetched must pass the following validity checks:
 * - It must be of the given packet type.
 * - It must be no longer than "maxlen".
 * - If those pass, it must be read into memory successfully.
 * - It must then pass the caller-supplied "verify" function,
 *   which checks object-type-specific information against the
 *   summary information stored in the RingObject.
 *
 * Question: what to return when the avoidmask doesn't allow anything to
 * be fetched?  Is this case just an error?
 */
static void const *
ringFetchPacket(RingPool *pool, union RingObject const *obj,
	PGPVirtMask *avoidmask, int pkttype, PGPSize maxlen, PGPSize *lenp,
	int (*verify)(RingPool *pool, union RingObject const *, PGPByte const *,
				  size_t))
{
	RingFile *file;
	FilePos const *pos;
	PGPSize len, len1;
	int i;
	void *p;

	/* find highest-priority fetchable file */
	file = ringBestFile(pool, obj, avoidmask);
	if (!file) {
		*lenp = (size_t)0;
		return NULL;	/* Is this The Right Thing? */
	}

	pos = ringFilePos(obj, file);
	pgpAssert(pos);

	/* If it's in memory, that was easy... */
	if (pgpVirtMaskIsEqual (&file->set.mask, &pool->memringmask)) {
		pgpAssert (!verify
		        || verify(pool, obj, (PGPByte *)pos->ptr.buf, pos->fpos) == 0);
		*lenp = pos->fpos;
		return pos->ptr.buf;
	}

	/* We now have highest-priority fetchable file */
	pgpAssert(file->f);
	if (pgpFileSeek(file->f, pos->fpos, SEEK_SET) != 0) {
		i = kPGPError_FileOpFailed;
		goto err;
	}
	i = pktByteGet(file->f, &len, &len1, (PGPSize *)NULL);
	if (i <= 0)
		goto err;
	if (PKTBYTE_TYPE(i) != pkttype || len > maxlen) {
		i = kPGPError_BadPacket;
		goto err;
	}
	p = ringReserve(pool, (size_t)len);
	if (!p)
		goto errmem;	/* ringErr() already called */
	pool->pktbuflen = len;
	i = pktBodyRead(pool->pktbuf, len, len1, file->f);
	if ((size_t)i != (size_t)len) {
		i = pgpFileError(file->f) ? kPGPError_ReadFailed :
					    kPGPError_EOF;
		goto err;
	}
	p = pool->pktbuf;

	/* Okay, now verify with supplied function */
	if (verify && (i = verify(pool, obj, (PGPByte const *)p, len)) != 0) {
		if (pkttype == PKTBYTE_SECKEY
		    && len
		    && obj->g.flags & SECF_VERSION_BUG
		    && ((PGPByte *)p)[0] == PGPVERSION_3) {
			/*
			 * Failure may be due to version bug; fix and try
			 * again.  If success, put it back so we behave
			 * consistently.  Verify doesn't always fail with
			 * version bug, it depends on whether sec or pub was
			 * seen first.
			 */
			((PGPByte *)p)[0] = PGPVERSION_2;
			if (verify &&
			    (i = verify(pool, obj, (PGPByte const *)p, len)) != 0)
				goto err;
			((PGPByte *)p)[0] = PGPVERSION_3;
		} else {
			goto err;
		}
	}

	/* Success! */
	*lenp = len;
	return p;

	/* Error cases (out of line) */
err:
	ringErr(file, pos->fpos, (PGPError)i);
errmem:
	*lenp = 0;
	return NULL;
}

/*
 * The verify functions here should *never* fail under normal
 * conditions.  They fail only if the keyring file has been
 * changed while PGP is accessing it (which causes a fatal error).
 * Did I mention that this code is *paranoid*?
 * ("The computer is your friend.  The computer wants you to be happy.")
 *
 * They operate by re-parsing the fetched data and checking that
 * the cached data matches the data just fetched.
 */

/* Verify that the key we just read looks like the one we wanted to read. */
static int
ringKeyVerify(RingPool *pool, union RingObject const *obj,
	PGPByte const *p, size_t len)
{
	int i;
	PGPByte pkalg, keyID[8], fp20n[20];
	PGPUInt16 keybits, validity;
	PGPUInt32 tstamp;
	PGPByte v3;

	i = ringKeyParse(pool->context, p, len, &pkalg, keyID, fp20n, &keybits,
	                 &tstamp, &validity, &v3, 0);

	if (memcmp(keyID, obj->k.keyID, 8) == 0
		&& fp20n[0] == obj->k.fp20n
	    && keybits  == obj->k.keybits
	    && tstamp   == obj->k.tstamp
/*	    && validity == obj->k.validity  Validity sometimes stored elsewhere */
	    && pkalg    == obj->k.pkalg
		&& v3		== !!KEYISV3(&obj->k)
	    && (i == 0) == !(obj->g.flags & KEYF_ERROR))
		return 0;	/* All copascetic */

	return kPGPError_BadPacket;
}

/* Verify that the secret we just read looks like the one we wanted to read. */
static int
ringSecVerify(RingPool *pool, union RingObject const *obj,
	PGPByte const *p, size_t len)
{
	int i;
	PGPByte pkalg, keyID[8], fp20n[20];
	PGPUInt16 keybits, validity;
	PGPUInt32 tstamp;
	PGPByte v3;
	union RingObject *key = obj->g.up;

	pgpAssert(OBJISSEC(obj));
	pgpAssert(OBJISKEY(key));

	i = ringKeyParse(pool->context, p, len, &pkalg, keyID, fp20n, &keybits,
	                 &tstamp, &validity, &v3, 1);

	if (ringHashBuf(p, len) == obj->c.hash
	    && memcmp(keyID, key->k.keyID, 8) == 0
		&& fp20n[0] == key->k.fp20n
	    && keybits  == key->k.keybits
	    && tstamp   == key->k.tstamp
/*	    && validity == key->k.validity	Validity sometimes stored elsewhere */
	    && pkalg    == key->k.pkalg
		&& v3		== !!KEYISV3(&key->k)
	    && (i == 0) == !(key->g.flags & KEYF_ERROR))
		return 0;	/* All copascetic */

	return kPGPError_BadPacket;
}

/*
 * Verify that the signature we just read looks like the one we wanted to read.
 */
static int
ringSigVerify(RingPool *pool, union RingObject const *obj,
	PGPByte const *p, size_t len)
{
	int i;
	PGPByte pkalg, keyID[8];
	PGPUInt32 tstamp;
	PGPUInt32 sigvalidity;
	size_t extralen;
	PGPByte type, hashalg;
	PGPByte version;
	PGPBoolean exportable;
	PGPBoolean revocable;
	PGPBoolean hasRegExp;
	PGPBoolean isX509;
	PGPBoolean primaryUID;
	PGPByte trustLevel;
	PGPByte trustValue;

	(void) pool;

	i = ringSigParse(p, len, &pkalg, keyID, &tstamp, &sigvalidity,
	                 &type, &hashalg, &extralen, &version, &exportable,
					 &revocable, &trustLevel, &trustValue, &hasRegExp,
					 &isX509, &primaryUID);
	/* Allow mismatch on keyid on X509 sigs */
	if ((isX509 || memcmp(keyID, obj->s.by->k.keyID, 8) == 0)
		&& version == obj->s.version
	    && tstamp == obj->s.tstamp
	    && sigvalidity == obj->s.sigvalidity
	    && type == obj->s.type
	    && hashalg == obj->s.hashalg
	    && (extralen == 5) == !(obj->g.flags & SIGF_NONFIVE)
	    && (i == 0) == !(obj->g.flags & SIGF_ERROR)
		&& (!exportable == !SIGISEXPORTABLE(&obj->s))
		&& (!revocable == !SIGISREVOCABLE(&obj->s))
		&& (!hasRegExp == !SIGUSESREGEXP(&obj->s))
		&& (!isX509 == !SIGISX509(&obj->s))
		&& (!primaryUID == !SIGISPRIMARYUID(&obj->s)))
		return 0;	/* All copascetic */

	return kPGPError_BadPacket;
}

/*
 * Verify that the CRL we just read looks like the one we wanted to read.
 */
static int
ringCRLVerify(RingPool *pool, union RingObject const *obj,
	PGPByte const *p, size_t len)
{
	PGPByte version;
	PGPByte type;
	PGPUInt32 tstamp;
	PGPUInt32 tstampnext;
	PGPByte const *dpoint;
	PGPSize dpointlen;

	(void) pool;

	(void)ringCRLParse(pool, p, len, &version, &type, &tstamp, &tstampnext,
					   &dpoint, &dpointlen);

	if (ringHashBuf(p, len) == obj->r.hash
		&& version == obj->r.version
		&& (type == PGPCRLTYPE_X509 ||
			type == PGPCRLTYPE_X509DPOINT) == CRLISX509(&obj->r)
		&& (type == PGPCRLTYPE_X509DPOINT) == CRLHASDPOINT(&obj->r)
		&& (!CRLHASDPOINT(&obj->r) ||
			ringHashBuf(dpoint, dpointlen) == obj->r.dpointhash)
		&& tstamp == obj->r.tstamp
		&& tstampnext == obj->r.tstampnext
		)
		return 0;	/* All copascetic */

	return kPGPError_BadPacket;
}

/*
 * Verify that the unknown we just read looks like the one we wanted to read.
 */
static int
ringUnkVerify(RingPool *pool, union RingObject const *obj,
	PGPByte const *p, size_t len)
{
	(void) pool;

	if (ringHashBuf(p, len) == obj->u.hash)
		return 0;	/* All copascetic */

	return kPGPError_BadPacket;
}

/*
 * Getting names is special due to the in-memory cache.
 * We don't have to support "avoidmask", though.
 *
 * Return a pointer to a name string.  Note that the string is NOT
 * null-terminated; all 256 values are legal!  The "lenp" argument
 * returns the length.  Tries to get it from memory if possible,
 * then tries to load it into the cache.  If it can't load it into
 * the preferred file cache, load it into the pktbuf.  If even
 * that fails, try to find another cache that it wil fit into.
 *
 * (Note: although strings are not in general null-terminated, hence we
 * return a length field, we do in fact put a null character at name[length]
 * so that callers can be sure that there is a null either within or just
 * beyond the name itself.  This facilitates our regexp matching.)
 *
 * Note that ringNamesDiffer() uses the fact that this either returns
 * with NAMEISCACHED(name) true, *or* the buffer returned is the
 * pktbuf.  Never both, and never a third choice.
 *
 * @@@ Is the ability to hande a pool==NULL still useful?
 */
static char const *
ringPoolGetName(RingPool *pool, RingName *name, PGPSize *lenp)
{
	int i;
	MemPool cut;
	PGPVirtMask mask;
	RingFile *file, *file2;
	FilePos const *pos;
	char *str;
	PGPSize len, len1;

	*lenp = name->len;

	/* If we already have it, boom. */
	if (NAMEISCACHED(name))
		return name->name.ptr;

	/* If we weren't given a pool, we can't fetch it */
	if (!pool)
		return NULL;

	pgpVirtMaskInit (pool, &mask);

	/* find highest-priority fetchable file */
	file = ringBestFile(pool, (union RingObject *)name, 0);
	pgpAssert(file);
	pgpAssert(file->f ||
			  pgpVirtMaskIsEqual (&file->set.mask, &pool->memringmask));

	pos = ringFilePos((union RingObject *)name, file);
	pgpAssert(pos);

	/* If it's in memory, that was fast - set cached if it wasn't already*/
	if (pgpVirtMaskIsEqual (&file->set.mask, &pool->memringmask)) {
		pgpAssert(pos->fpos == name->len);
		pgpAssert(ringHashBuf((PGPByte *)pos->ptr.buf, name->len) ==
		       name->name.hash);
		NAMESETCACHED(name);
		NAMESETFILEMASK(name, MEMRINGBIT);
		pgpVirtMaskCleanup (pool, &mask);
		return name->name.ptr = (char *)pos->ptr.buf;
	}

	/* Allocate cache space for it */
	/* Dummy loop to break out of */
	do {
		/* Try the preferred cache */
		file2 = file;
		cut = file2->strings;	/* Remember cutback position */
		str = (char *)memPoolAlloc(&file2->strings, name->len + 1, 1);
		if (str)
			break;
		/* Try the pktbuf */
		str = ringReserve(pool, name->len + 1);
		if (str) {
			file2 = NULL;
			pool->pktbuflen = name->len;
			break;
		}
		/* Okay, desperation time - look for any cache */
		pgpVirtMaskCopy (pool, &name->mask, &mask);
		pgpVirtMaskAND (pool, &pool->filemask, &mask);
		pgpVirtMaskANDNOT (pool, &pool->memringmask, &mask);
		pos = &name->pos;
		for (;;) {
			i = pgpVirtMaskLSBit(&mask);
			pgpAssert(i >= 0);
			pgpAssert(pool->files[i]->f);
			file2 = pool->files[i];
			cut = file2->strings;
			str = (char *)memPoolAlloc(&file2->strings,
			                           name->len + 1, 1);
			if (str)
				break;
			pgpVirtMaskClearBit (pool, &mask, i);
			if (pgpVirtMaskIsEmpty (&mask)) {
				ringAllocErr(pool);
				pgpVirtMaskCleanup (pool, &mask);
				return NULL;
			}
			pos = pos->ptr.next;
		}
	} while (0);	/* Dummy loop to break out of */

	/* Okay, we got buffer space... get the packet */

	if (pgpFileSeek(file->f, pos->fpos, SEEK_SET) != 0) {
		i = kPGPError_FileOpFailed;
		goto error;
	}
	i = pktByteGet(file->f, &len, &len1, (PGPSize *)NULL);
	if (i < 0)
		goto error;
	if (PKTBYTE_TYPE(i) !=
					(NAMEISATTR(name) ? PKTBYTE_ATTRIBUTE : PKTBYTE_NAME)
			|| len != name->len)
		goto badpkt;

	i = pktBodyRead(str, len, len1, file->f);
	str[len] = '\0';			/* null char beyond end of name */
	if ((size_t)i != (size_t)len) {
		i = pgpFileError(file->f) ? kPGPError_ReadFailed :
					    kPGPError_EOF;
		goto error;
	}

	/* Double-check that we got the right thing. */
	if (ringHashBuf((PGPByte *)str, len) != name->name.hash)
		goto badpkt;

	/* Success at last! */
	if (file2) {
		/* It's cached in file2 - set flags appropriately */
		NAMESETCACHED(name);
		NAMESETFILEMASK(name, pgpVirtMaskLSBit(&file2->set.mask));
		name->name.ptr = str;
	}
	pgpVirtMaskCleanup (pool, &mask);
	return str;
	
badpkt:
	i = kPGPError_BadPacket;
error:
	if (file2)
		memPoolCutBack(&file2->strings, &cut);
	ringErr(file, pos->fpos, (PGPError)i);
	pgpVirtMaskCleanup (pool, &mask);
	return NULL;
}


void const *
ringFetchObject(RingSet const *set, union RingObject *obj, PGPSize *lenp)
{
	PGPByte const *buf = NULL;
	PGPVirtMask secmask, bestfile;	/* Needed in RINGTYPE_KEY */
	PGPVirtMask notsecmask;
	RingPool *pool = set->pool;
	PGPByte pktbyte;

	pgpVirtMaskInit (pool, &secmask);
	pgpVirtMaskInit (pool, &notsecmask);
	pgpVirtMaskInit (pool, &bestfile);
	
	pgpAssert(pgpIsRingSetMember(set, obj));
	pgpAssert(pgpVirtMaskIsOverlapping(&obj->g.mask, &pool->filemask));

	switch (ringObjectType(obj)) {
	  case RINGTYPE_NAME:
		buf = (PGPByte const *)ringPoolGetName(pool, &obj->n, lenp);
		break;
	  case RINGTYPE_SIG:
		buf = (PGPByte const *)ringFetchPacket(pool, obj, NULL, PKTBYTE_SIG,
					  RINGSIG_MAXLEN, lenp, ringSigVerify);
		break;
	  case RINGTYPE_CRL:
		buf = (PGPByte const *)ringFetchPacket(pool, obj, NULL, PKTBYTE_CRL,
					  RINGCRL_MAXLEN, lenp, ringCRLVerify);
		break;
	  case RINGTYPE_UNK:
		buf = (PGPByte const *)ringFetchPacket(pool, obj, NULL,
		                          PKTBYTE_TYPE(obj->u.pktbyte),
					  RINGUNK_MAXLEN, lenp, ringUnkVerify);
		break;
	  case RINGTYPE_SEC:
	       pktbyte = OBJISTOPKEY(obj->g.up) ? PKTBYTE_SECKEY :
		       PKTBYTE_SECSUBKEY;
		buf = (PGPByte const *)ringFetchPacket(pool, obj, NULL,
		                          pktbyte, RINGSEC_MAXLEN,
		                          lenp, ringSecVerify);
               /* Compensate for version bug */
		if (buf
		    && *lenp > 0
		    && obj->g.flags & SECF_VERSION_BUG
		    && buf[0] == PGPVERSION_3)
			((PGPByte *)buf)[0] = PGPVERSION_2;
		break;
	  case RINGTYPE_KEY:
		/* File we'd like to fetch from */
		pgpVirtMaskCopy (pool,
						 &(ringBestFile(pool, obj, 0)->set.mask), &bestfile);
		/* Where secrets are located */
		ringKeySecMask(pool, obj, &secmask);

		/* Is where we want to fetch from secret? */
		if (pgpVirtMaskIsOverlapping (&bestfile, &secmask)) {
			pktbyte = OBJISTOPKEY(obj) ? PKTBYTE_SECKEY :
				PKTBYTE_SECSUBKEY;
			/* Have to fetch the secret key and extract. */
			obj = obj->g.down;
			while (!pgpVirtMaskIsOverlapping(&obj->g.mask, &bestfile)
				   || !OBJISSEC(obj)) {
				obj = obj->g.next;
				pgpAssert(obj);
			}
			pgpVirtMaskCopy(pool, &secmask, &notsecmask);
			pgpVirtMaskNOT(pool, &notsecmask, pool->nfiles);
			buf = (PGPByte const *)ringFetchPacket(pool, obj,
					&notsecmask, pktbyte, RINGSEC_MAXLEN,
					lenp, ringSecVerify);
			if (buf) {
				size_t len;

				/* Compensate for version bug */
				if (*lenp > 0
				    && obj->g.flags & SECF_VERSION_BUG
				    && buf[0] == PGPVERSION_3)
					((PGPByte *)buf)[0] = PGPVERSION_2;

				len = ringKeyParsePublicPrefix(buf, *lenp);
				/* If unparseable, take the whole thing. */
				if (len)
					*lenp = len;
			}
		} else {
			pktbyte = OBJISTOPKEY(obj) ? PKTBYTE_PUBKEY :
				PKTBYTE_PUBSUBKEY;
			/* Fetch public components */
			buf = (PGPByte const *)ringFetchPacket(pool, obj, &secmask,
			                      pktbyte, RINGKEY_MAXLEN,
			                      lenp, ringKeyVerify);
		}
		break;
	  default:
		pgpAssert(0);
		break;
	}
	pgpVirtMaskCleanup (pool, &bestfile);
	pgpVirtMaskCleanup (pool, &secmask);
	pgpVirtMaskCleanup (pool, &notsecmask);
	return buf;
}

/*** Various bookkeeping helper functions ***/

/*
 * Sort all the keys in a pool into keyID order.  This uses 8 passes
 * of a byte-wise radix sort.  Each pass is stable, so sorting on the
 * least significant byte, proceeding to the most will result in a
 * completely sorted list.
 *
 * Actually, it's sorted with the *visible* part (the low 32 bits) of the
 * keyID more significant than the invisible part.  This makes the ordering
 * more sensible to a human watching what's going on.
 *
 * There are 256 lists, with a head and a tail pointer.	 The tail
 * pointer is a pointer to a pointer, namely the slot the pointer to
 * the next entry to be added to the list goes in.  It is initialized
 * to point to the head pointer.  So adding an element to the list
 * consists of setting *tail = object; and then tail = &object->next;
 *
 * After each pass, concatenate the lists, starting at the end.
 * Begin with an empty list and keep appending the current list to
 * the tail of the one before it, grabbing the head as the new
 * current list.
 */
#if 0
static int
ringKeyIDcmp(PGPByte const id1[8], PGPByte const id2[8])
{
	int i;

	i = memcmp(id1+4, id2+4, 4);
	return i ? i : memcmp(id1, id2, 4);
}
#endif

static void
ringSortKeys(RingPool *pool)
{
#if 1
	/* 
	 * Disable sort, users who switch back to old versions of
	 * PGP are unhappy to see their keyring reordered.  The reason
	 * for the sort was to hide the order with which keys had been
	 * added to the keyring, and to make merges more efficient.
	 * For now neither of those is compelling enough to keep.
	 */
	(void)pool;
#else
	int i, j;
	int pass;
	int lastpass;
	union RingObject *list = pool->keys;
	union RingObject *head[256];
	union RingObject **tail[256];

	for (pass=0; pass<9; ++pass) {
		/* XXX Experimental backwards compat code - put DSA keys at end */
		/* On last pass we sort by pkalg */
		lastpass = (pass==8);
		i = (pass < 4) ? (3-pass) : (11-pass); /* 3,2,1,0,7,6,5,4 */

		/* Clear the table for the next distribution pass */
		for (j = 0; j < 256; j++)
			tail[j] = head+j;

		/* Distribute the list elements among the sublists */
		while (list) {
			if (lastpass)
				j = list->k.pkalg;
			else
				j = list->k.keyID[i];
			*tail[j] = list;
			tail[j] = &list->k.next;
			list = list->k.next;
		}

		j = 256;
		/* list is already 0 from the previous loop */

		/* Gather the sublists back into one big list */
		while (j--) {
			*tail[j] = list;
			list = head[j];
		}
	}


	pool->keys = list;
#endif
}

static void
ringPoolLinkKey(RingPool *pool, union RingObject *parent,
	union RingObject *key, PGPByte pkalg, PGPByte const keyID[8])
{
	union RingObject **ptr;

	pgpAssert(OBJISKEY(key));
	pgpCopyMemory( keyID, key->k.keyID, 8 );
	key->k.pkalg = pkalg;

	if (parent) {
		key->g.up = parent;
		ptr = &parent->g.down;
		while (*ptr)
			ptr = &(*ptr)->g.next;
	} else {
		ptr = &pool->keys;
	}
	key->g.next = *ptr;
	*ptr = key;
	RINGPOOLHASHKEY(pool, key);
}

/* Remove specified key from the top-level keys list */
static void
ringPoolUnlinkKey(RingPool *pool, union RingObject *key)
{
	union RingObject *obj, **objp;

	pgpAssert(pool && key);

	objp = &pool->keys;
	while ((obj = *objp) != NULL && obj != key) {
		objp = &obj->g.next;
	}
	pgpAssert(obj == key);
	*objp = key->g.next;
	key->g.next = NULL;
	return;
}

/*
 * Search for an X.509 key with the specified subject name.
 * Return an X.509 signature which gives it that name.
 * Calls ringFetchPacket, which may harm the pktbuf.
 */
union RingObject *
ringPoolFindX509NamedSig (RingPool *pool, PGPByte *name, PGPSize namelen)
{
	PGPASN_XTBSCertificate *xtbscert;
	RingObject *keys, *names, *sigs;
	PGPByte *sigbuf;
	PGPSize siglen;
	PGPByte *certbuf;
	PGPSize certlen;
	PGPByte *subjectname;
	PGPSize subjectlen;
	PGPError err;

	for (keys=pool->keys; keys; keys=keys->g.next) {
		if (!OBJISTOPKEY(keys))
			continue;
		for (names=keys->g.down; names; names = names->g.next) {
			if (!OBJISNAME(names))
				continue;
			for (sigs=names->g.down; sigs; sigs = sigs->g.next) {
				if (OBJISSIG(sigs) && SIGISX509(&sigs->s)) {
					sigbuf = (PGPByte *)ringFetchPacket (pool, sigs, NULL,
						PKTBYTE_SIG, RINGSIG_MAXLEN, &siglen,
						 ringSigVerify);
					/* Find subject name, compare with issuer name above */
					certbuf = (PGPByte *)ringSigFindNAISubSubpacket (sigbuf,
						SIGSUBSUB_X509, 0, &certlen, NULL, NULL, NULL, NULL);
					pgpAssert( IsntNull( certbuf ) );
					pgpAssert( certbuf[0] == SIGSUBSUB_X509 );
					certbuf += 3;
					certlen -= 3;
					err = pgpX509BufferToXTBSCert( pool->context, certbuf,
												   certlen, &xtbscert);
					if( IsPGPError( err ) )
						continue;
					subjectname = xtbscert->subject.val;
					subjectlen = xtbscert->subject.len;
					if (namelen == subjectlen &&
						0 == memcmp (name, subjectname, namelen)) {
						/* Have a match! */
						pgpX509FreeXTBSCert( pool->context, xtbscert );
						return sigs;
					}
					pgpX509FreeXTBSCert( pool->context, xtbscert );
				}
			}
		}
	}

	/* No match */
	return NULL;
}


/*
 * Search for an X.509 key which signed this one.  Information on the
 * current key is in the pool->pktbuf.
 */
static union RingObject *
ringPoolFindDummyX509Key(RingPool *pool, RingFile *file)
{
	PGPASN_XTBSCertificate *xtbscert;
	PGPByte *issuername;		/* issuer name subpart of cert */
	PGPSize issuerlen;
	PGPByte *pktcopy;			/* copy of signature packet */
	PGPSize pktlen;
	PGPByte *certbuf;
	PGPSize certlen;
	PGPByte hash[20];			/* hash of issuer name */
	PGPByte *keyid;				/* faked-up keyid for dummy key */
	RingObject *keys;
	PGPUInt32 fpos;				/* File pos */
	PGPError err;

	certbuf = (PGPByte *)ringSigFindNAISubSubpacket ((PGPByte *)pool->pktbuf,
					SIGSUBSUB_X509, 0, &certlen, NULL, NULL, NULL, NULL);
	
	pgpAssert (IsntNull( certbuf ) );
	
	/* Skip type, version bytes */
	pgpAssert (certbuf[0] == SIGSUBSUB_X509);
	certbuf += 3;
	certlen -= 3;

	/* Find issuer name in cert */
	err = pgpX509BufferToXTBSCert( pool->context, certbuf, certlen, &xtbscert);
	if( IsPGPError( err ) )
		return NULL;
	issuername = xtbscert->issuer.val;
	issuerlen = xtbscert->issuer.len;

	/* Calculate hash of issuer name */
	pgpFingerprint20HashBuf(pool->context, issuername, issuerlen, hash);

	/*
	 * First look to see if we have a key with that keyid.  We set this
	 * on dummy keys that we create.
	 */
	keyid = hash + sizeof(hash) - 8;
	keys = ringPoolFindKey(pool, 0, keyid);
	if (IsntNull( keys ) && pgpVirtMaskIsEmpty (&keys->g.mask)) {
		pgpX509FreeXTBSCert( pool->context, xtbscert );
		return keys;
	}

	/* Make a copy of the pktbuf area, we'll overwrite it */
	pktlen = pool->pktbuflen;
	pktcopy = (PGPByte *) pgpContextMemAlloc (pool->context,
									pool->pktbuflen, 0);
	if (IsNull (pktcopy)) {
		pgpX509FreeXTBSCert( pool->context, xtbscert );
		ringSimpleErr(pool, kPGPError_OutOfMemory);
		return NULL;
	}
	pgpCopyMemory (pool->pktbuf, pktcopy, pktlen);

	/* We may move our file pointer below */
	fpos = pgpFileTell(file->f);

	/* Search for an X.509 key with subject name equal to our issuer name */
	/* Overwrites pktbuf */
	keys = ringPoolFindX509NamedSig (pool, issuername, issuerlen);
	pgpAssert (IsNull(keys) || OBJISSIG(keys));
	if( IsntNull( keys ) ) {
		while (!OBJISTOPKEY(keys))
			keys = keys->g.up;
	}
	/* Here, if keys is non-NULL, we found a match */

	/* Restore pool->pktbuf */
	ringReserve (pool, pktlen);
	pgpCopyMemory( pktcopy, pool->pktbuf, pktlen );
	pool->pktbuflen = pktlen;
	pgpContextMemFree (pool->context, pktcopy);
	pgpFileSeek (file->f, fpos, SEEK_SET);
	pgpX509FreeXTBSCert( pool->context, xtbscert );
	
	if( IsNull( keys ) ) {
		/* Must make dummy key, set keyid from hash of issuer name */
		keys = ringNewKey(pool);
		if (IsntNull (keys)) {
			ringPoolLinkKey (pool, NULL, keys, 0, keyid);
		}
	}

	return keys;
}



/*
 * Same as ringPoolFindKey, but creates a dummy key with the given parent
 * if one is not found.
 * Note that a dummy key is a RingObject with its mask set to 0.
 */
static union RingObject *
ringPoolFindDummyKey(RingPool *pool, RingFile *file, RingObject *parent,
	PGPByte pkalg, PGPByte const keyID[8], PGPBoolean isX509)
{
	union RingObject *key;

	if (isX509) {
		pgpAssert (IsNull (parent));
		key = ringPoolFindDummyX509Key (pool, file);
		pgpAssert (IsntNull (key));
	} else
		key = ringPoolFindKey(pool, pkalg, keyID);

	if (!key) {
		key = ringNewKey(pool);
		if (key) {
			if (parent)
				key->k.flags |= RINGOBJF_SUBKEY;
			ringPoolLinkKey(pool, parent, key, pkalg, keyID);
		}
	}
	return key;
}

/*
 * Free an entire tree of objects.
 * This does not do anything with the FilePos chain, but since the
 * first entry is preallocated, if the object has at most one FilePos,
 * (as is the case in newly created objects), no memory is leaked.
 */
static void
ringFreeTree(RingPool *pool, union RingObject *obj)
{
	union RingObject *down;

	if (!OBJISBOT(obj)) {
		while ((down = obj->g.down) != NULL) {
			obj->g.down = down->g.next;
			ringFreeTree(pool, down);
		}
	}
	ringFreeObject(pool, obj);
}

/*
 * Free up a newly created dummy key. 
 * Unlink it from the pool and free it and all descendents.
 */
static void
ringFreeDummyKey(RingPool *pool, union RingObject *key)
{
	union RingObject **objp;

	pgpAssert(OBJISKEY(key));

	/* Find head of list this object is on */
	if (OBJISTOP(key))
		objp = &pool->keys;
	else
		objp = &key->g.up->g.down;

	while (*objp != key) {
		pgpAssert(*objp);
		objp = &(*objp)->g.next;
	}
	*objp = key->g.next;
	ringFreeTree(pool, key);
}

/*
 * Return 0 if the packet in the pktbuf is the same as the packet in
 * the given file at the given offset, and the file packet is of type
 * pkttype.  Returns 1 if they differ, and -1 (and sets the ring's error
 * status) if there is an error, including an unexpected packet byte.
 * Compare at most max bytes.
 *
 * This does NOT examine any more of the object than its filepos
 * chain; in particular, it does NOT examine the object's type.
 * Thus, it is possible to have a key object and use it to
 * fetch a secret-key packet.
 *
 * Special case: returns pktbuf[0] if pktbuf[0] is 2 or 3 and the file's
 * packet begins with 5-pktbuf[0].  This is used by the key difference
 * code to detect the version byte bug.  The other things can ignore it,
 * and just treat all positive return values as "different".
 */
static int
ringPacketDiffers(RingFile *file, union RingObject const *obj,
	int pkttype, PGPUInt32 max)
{
	RingPool *pool = file->set.pool;
	FilePos const *pos;
	PGPByte *p;
	PGPFile *f;
	PGPSize len, len1;
	int i;
	PGPByte c;
	int magic;

	pos = ringFilePos(obj, file);

	/* Memory file, special case for comparison */
	if (pgpVirtMaskIsEqual (&file->set.mask, &pool->memringmask)) {
		len = pos->fpos;
		if (len > max)
			len = max;
		if (max > pool->pktbuflen)
			max = pool->pktbuflen;
		if (len != max)
			return 1;	/* Different */
		if (!len)
			return 0;
		/* Check first character specially */
		p = (PGPByte *)pos->ptr.buf;
		magic = 0;
		if (p[0] != ((PGPByte *)pool->pktbuf)[0]) {
			if ((p[0] ^ ((PGPByte *)pool->pktbuf)[0]) != 1
			    || (p[0] & ((PGPByte *)pool->pktbuf)[0]) != 2)
		{
			return 1;	/* First char different */
		}
			magic = ((PGPByte *)pool->pktbuf)[0]; /* First char magic */
		}
		return memcmp(p+1, pool->pktbuf+1, (size_t)len-1) ? 1 : magic;
	}

	/* Usual case - external file */
	f = file->f;
	pgpAssert(f);

	i = pgpFileSeek(f, pos->fpos, SEEK_SET);
	if (i != 0) {
		ringErr(file, pos->fpos, kPGPError_FileOpFailed);
		return kPGPError_FileOpFailed;
	}
	i = pktByteGet(f, &len, &len1, (PGPSize *)NULL);
	if (i < 0) {
		ringErr(file, pos->fpos, (PGPError)i);
		return i;
	}
	if (PKTBYTE_TYPE(i) != pkttype) {
		ringErr(file, pos->fpos, kPGPError_BadPacket);
		return kPGPError_BadPacket;
	}
	if (len > max)
		len = max;
	if (max > pool->pktbuflen)
		max = pool->pktbuflen;
	if (len != max)
		return 1;	/* Different */
	if (!len)
		return 0;
	/* Check first character specially */
	if (pgpFileRead(&c, 1, f) != 1)  {
		i = pgpFileError(f) ? kPGPError_ReadFailed : kPGPError_EOF;
		ringErr(file, pos->fpos, (PGPError)i);
		return i;
	}
	i = c & 255;
	magic = 0;	/* First char the same */
	if (i != ((PGPByte *)pool->pktbuf)[0]) {
		if ((i ^ ((PGPByte *)pool->pktbuf)[0]) != 1
			|| (i & ((PGPByte *)pool->pktbuf)[0]) != 2)
			return 1;
		magic = ((PGPByte *)pool->pktbuf)[0]; /* First char magic */
	}
	i = fileUnequalBuf(f, pool->pktbuf+1, len-1, len1-1);
	if (i < 0)
		ringErr(file, pos->fpos, (PGPError)i);

	return i ? i : magic;
}

/*
 * Return 1 if the key in the ring's pktbuf differs from the
 * key in its other homes, 0 if it is the same, and <0 if there
 * is some sort of error.
 * Does *not* alter file1's read position unless there is an error.
 * (I.e. if it needs to seek file1, it saves and restores the file
 * position.  It doesn't bother for other files.  Use the MEMRING file
 * if you don't need this feature.)
 *
 * SPECIAL CASE:
 * Returns >1 if the version byte bug was detected.  This is the case
 * wherein version 2.6 would write out an edited secret key with a
 * version byte of 3 even if it was originally 2.
 * This function returns the current pktbuf's version byte (2 or 3)
 * if the keys are identical except that the version byte differs
 * from something read previously.
 * The caller must decide what sort of trouble to log.
 */
int
keysdiffer(RingFile *file1, union RingObject const *key, int pktbyte)
{
	RingPool *pool = file1->set.pool;
	RingFile *file2;
	size_t savelen, publen;
	PGPVirtMask secmask;
	PGPUInt32 max;
	int i, type;
	long retpos=0;

	pgpVirtMaskInit (pool, &secmask);

	pgpAssert(OBJISKEY(key));
	pgpAssert(file1->f ||
			  pgpVirtMaskIsEqual(&file1->set.mask, &pool->memringmask));


	/*
	 * If this is a secret key, find the prefix which is a public key,
	 * and limit it to that if reasonable.
	 */
	savelen = pool->pktbuflen;
	if ((PKTBYTE_TYPE(pktbyte) == PKTBYTE_SECKEY ||
		 PKTBYTE_TYPE(pktbyte) == PKTBYTE_SECSUBKEY)
	    && !(key->g.flags & KEYF_ERROR))
	{
		publen = ringKeyParsePublicPrefix((PGPByte const *)pool->pktbuf,
		                                  pool->pktbuflen);
		if (publen)
			pool->pktbuflen = publen;
	}

	/* Find a file containing the key - try for public first */
	ringKeySecMask(pool, key, &secmask);

	file2 = ringBestFile(pool, key, &secmask);
	if (file2) {
		max = (PGPUInt32)-1;
		type = OBJISTOPKEY(key) ? PKTBYTE_PUBKEY : PKTBYTE_PUBSUBKEY;
	} else {
		file2 = ringBestFile(pool, key, 0);
		pgpAssert(file2);
		max = (PGPUInt32)pool->pktbuflen;
		type = OBJISTOPKEY(key) ? PKTBYTE_SECKEY : PKTBYTE_SECSUBKEY;
	}

	if (file2 == file1 && file1->f && (retpos=pgpFileTell(file1->f)) < 0) {
		ringErr(file1, pgpFileTell(file1->f), kPGPError_FileOpFailed);
		pgpVirtMaskCleanup (pool, &secmask);
		return kPGPError_FileOpFailed;
	}
		
	/* Note that we don't need to seek file2 here, ringPacketDiffers does */
	i = ringPacketDiffers(file2, key, type, max);

	/*
	 * If we compared against a secret key, and encountered the version
	 * bug, and the version bug has already been noted, ignore the
	 * difference.
	 */
	if (i == PGPVERSION_2
            && type == PKTBYTE_SECKEY
	    && key->g.flags & SECF_VERSION_BUG)
		i = 0;

	if (file2 == file1 && file1->f &&
			pgpFileSeek(file1->f, retpos, SEEK_SET) != 0) {
		ringErr(file1, pgpFileTell(file1->f), kPGPError_FileOpFailed);
		pgpVirtMaskCleanup (pool, &secmask);
		return kPGPError_FileOpFailed;
	}
	
	/* Restore pktbuflen, may have been changed above */
	pool->pktbuflen = savelen;

	pgpVirtMaskCleanup (pool, &secmask);
	return i;
}

/*
 * Return 1 if the secret in the ring's pktbuf differs from the
 * key in its other homes, 0 if it is the same, and <0 if there
 * is some sort of error.
 * Does *not* alter file1's read position unless there is an error.
 *
 * SPECIAL CASE:
 * Returns >1 if the version byte bug was detected.  This is the case
 * wherein version 2.6 would write out an edited secret key with a
 * version byte of 3 even if it was originally 2.
 * This function returns the current pktbuf's version byte (2 or 3)
 * if the keys are identical except that the version byte differs
 * from something read previously.
 * The caller must decide what sort of trouble to log.
 */
/*
 * Return 1 if the signature in the ring's pktbuf differs from the
 * sig in its various homes, 0 if it is the same, and <0 if there
 * is some sort of error.
 * Does *not* alter file1's read position unless there is an error.
 * (I.e. if it needs to seek file1, it saves and restores the file
 * position.  It doesn't bother for other files.  Use the MEMRING file
 * if you don't need this feature.)
 */
static int
secsdiffer(RingFile *file1, union RingObject const *sec)
{
	RingPool *pool = file1->set.pool;
	RingFile *file2;
	long retpos=0;
	PGPByte pktbyte;
	int i;

	pgpAssert(OBJISSEC(sec));

	/* Find a matching signature */
	file2 = ringBestFile(pool, sec, 0);
	pgpAssert (file2);
	pgpAssert (file2->f ||
			   pgpVirtMaskIsEqual (&file2->set.mask, &pool->memringmask));
	if (file2 == file1 && file1->f && (retpos=pgpFileTell(file1->f)) < 0) {
		ringErr(file1, pgpFileTell(file1->f), kPGPError_FileOpFailed);
		return kPGPError_FileOpFailed;
	}

	pktbyte = OBJISTOPKEY(sec->g.up) ? PKTBYTE_SECKEY :
	          PKTBYTE_SECSUBKEY;

	/* Note that we don't need to seek file2 here, ringPacketDiffers does */
	i = ringPacketDiffers(file2, sec, pktbyte, (PGPUInt32)-1);
	if (i < 0)
		return i;

	if (file2 == file1 && file1->f &&
			pgpFileSeek(file1->f, retpos, SEEK_SET) != 0) {
		ringErr(file1, sec->g.pos.fpos, kPGPError_FileOpFailed);
		return kPGPError_FileOpFailed;
	}
	return i;
}

static union RingObject *
ringFindSec(RingFile *file, union RingObject *parent)
{
	RingPool *pool = file->set.pool;
	union RingObject *sec, **secp;
	int i;

	/* Properties of the secret */
	PGPUInt32 hash;

	hash = ringHashBuf((PGPByte const *)pool->pktbuf, pool->pktbuflen);
	
	/* Search for matching sigs */
	for (secp=&parent->g.down; (sec=*secp) != NULL; secp=&sec->g.next) {
		if (OBJISSEC(sec)
		    && sec->c.hash == hash
		    && (i = secsdiffer(file, sec)) <= 0)
			return i<0 ? NULL : sec;
	}

	/* Not found - allocate a new secret */
	sec = ringNewSec(pool);
	if (sec) {
		/*
		 * Make secret object the first thing.  This is assumed by
		 * ringFindSig which tries to keep sigs together just past
		 * the sec obj.  Especially important with subkeys where it's
		 * hard to tell which sigs go with which keys as we read.
		 */
		sec->g.next = parent->g.down;
		parent->g.down = sec;
		sec->g.up = parent;
		sec->c.hash = hash;
	}
	return sec;
}

/*
 * Return 1 if the name in the ring's pktbuf differs from the
 * name in its various homes, 0 if it is the same, and <0 if there
 * is some sort of error.
 * Does *not* alter file1's read position unless there is an error.
 * (I.e. if it needs to seek file1, it saves and restores the file
 * position.  It doesn't bother for other files.  Use the MEMRING file
 * if you don't need this feature.)
 */
int
namesdiffer(RingFile *file1, union RingObject const *name,
			PGPBoolean fAttribute)
{
	RingPool *pool = file1->set.pool;
	RingFile *file2;
	long retpos=0;
	int i;

	/* Find a matching name */
	file2 = ringBestFile(pool, name, 0);
	pgpAssert (file2);
	pgpAssert (file2->f ||
			   pgpVirtMaskIsEqual (&file2->set.mask, &pool->memringmask));
	if (file2 == file1 && file1->f && (retpos=pgpFileTell(file1->f)) < 0) {
		ringErr(file1, pgpFileTell(file1->f), kPGPError_FileOpFailed);
		return kPGPError_FileOpFailed;
	}

	/* Note that we don't need to seek file2 here, ringPacketDiffers does */
	i = ringPacketDiffers(file2, name,
			(fAttribute?PKTBYTE_ATTRIBUTE:PKTBYTE_NAME), (PGPUInt32)-1);

	if (file2 == file1 && file1->f &&
			pgpFileSeek(file1->f, retpos, SEEK_SET) != 0) {
		ringErr(file1, name->g.pos.fpos, kPGPError_FileOpFailed);
		return kPGPError_FileOpFailed;
	}
	return i;
}

/*
 * Exported variant of namesdiffer.  This has a similar function, but
 * a very different interface - it does not assume that the name has been
 * fetched into the pktbuf.
 * Returns 1 if the two names differ, 0 if the same, < 0 on error.
 */
int
ringNamesDiffer (RingSet const *set, union RingObject *name1,
	union RingObject *name2)
{
	char const *buf1, *buf2;	/* Pointers to the names */
	PGPSize len, tlen;
	PGPUInt32 hash1, hash2;		/* HAshes of the two names */
	
	pgpAssert (OBJISNAME(name1));
	pgpAssert (OBJISNAME(name2));
	pgpAssert (pgpIsRingSetMember(set, name1));
	pgpAssert (pgpIsRingSetMember(set, name2));

	/* Quick test of lengths */
	len = name1->n.len;
	if (len != name2->n.len)
		return 1;

	/* Trivial case: both names are in memory */
	if (NAMEISCACHED(&name1->n) && NAMEISCACHED(&name2->n))
		return memcmp(name1->n.name.ptr, name2->n.name.ptr, len) != 0;

	/* First, compare hashes to see what's what */
	hash1 = NAMEISCACHED(&name1->n) 
		? ringHashBuf((const unsigned char *) name1->n.name.ptr, len)
		: name1->n.name.hash;
	hash2 = NAMEISCACHED(&name2->n) 
		? ringHashBuf((const unsigned char *) name2->n.name.ptr, len)
		: name2->n.name.hash;
	if (hash1 != hash2)
		return 1;
	/*
	 * At this point, we're 99% sure the names are the same, but
	 * we need to confirm...
	 * Load the first name.  This may go into a cache, or the pktbuf.
	 */
	buf1 = ringPoolGetName(ringSetPool(set), &name1->n, &tlen);
	if (!buf1)
		return ringSetError(set)->error;
	pgpAssert(tlen == len);
	/* If name2 is available without using the pktbuf, great. */
	if (NAMEISCACHED(&name2->n)) {
		buf2 = name2->n.name.ptr;
		return memcmp(buf1, buf2, len) != 0;
	}
	/*
	 * Otherwise, if name1 isn't in the pktbuf, we can fetch name2
	 * without fear of clobbering it.
	 */
	if (NAMEISCACHED(&name1->n)) {
		pgpAssert(buf1 == name1->n.name.ptr);
		buf2 = ringPoolGetName(ringSetPool(set), &name2->n, &tlen);
		if (!buf2)
			return ringSetError(set)->error;
		pgpAssert(tlen == len);
		return memcmp(buf1, buf2, len) != 0;
	}
	/* name1 is not cached, so it's in the pktbuf... */
	pgpAssert(buf1 == ringSetPool(set)->pktbuf);
	/*
	 * Otherwise, compare name1 in pktbuf to name2 on disk.
	 * Use MEMRING as dummy entry for file1; it is only used to
	 * make sure that any seeks which move its position get undone,
	 * and we don't care about that at this point.
	 */
	return namesdiffer(ringSetPool(set)->files[MEMRINGBIT], name2,
											(PGPBoolean)NAMEISATTR(&name1->n));
}
	

/*
 * Get a RingName on the given chain matching the one in the ring's
 * pktbuf.  Returns 0 if it runs out of memory or can't read the file.
 * (The ring's error is set to reflect this.)
 * It does *not* add the FilePos or set the mask bit.
 * Does *not* alter the given file's read position unless there is an error.
 */
static union RingObject *
ringFindName(RingFile *file, union RingObject *parent, PGPBoolean fAttribute)
{
	RingPool *pool = file->set.pool;
	union RingObject *name, **np, **pname=NULL;
	size_t const len = pool->pktbuflen;
	PGPUInt32 hash;
	int i;
	char *buf;	/* Used when trying to cache name */

	hash = ringHashBuf((PGPByte const *)pool->pktbuf, len);

	pname = &parent->g.down;
	for (np = &parent->g.down; (name=*np) != NULL; np = &name->g.next) {
		/* Position name after names, key-sigs, sec's */
		if (OBJISNAME(name) || OBJISSIG(name) || OBJISSEC(name))
			pname = &name->g.next;
		/* If not a name or wrong length, no match */
		if (!OBJISNAME(name) || name->n.len != len
			|| !NAMEISATTR(&name->n)!=!fAttribute)
			continue;

		/* If in memory, compare that */
		if (NAMEISCACHED(&name->n)) {
			if (memcmp(name->n.name.ptr, pool->pktbuf, len) == 0)
				return name;	/* Success */
		} else {
			if (name->n.name.hash == hash
			    && (i = namesdiffer(file, name, fAttribute)) <= 0)
				return i<0 ? NULL : name;
		}
	}

	/* Failed to find a name - create one */
	name = ringNewName(pool);
	if (name) {
		name->g.next = *pname;
		*pname = name;
		name->g.up = parent;
		name->n.len = len;
		name->n.name.hash = hash;	/* May overwrite below */
		/* Default new names to unknown trust */
		name->n.trust = kPGPNameTrust_Unknown;
		if( fAttribute )
			NAMESETATTR(&name->n);
#if PGPTRUSTMODEL>0
		name->n.valid = name->n.validity = 0;
		name->n.confidence = PGP_NEWTRUST_UNDEFINED;
		NAMESETNEWTRUST(&name->n);
#endif
#if 1
		/* You might want to disable this for MSDOS */
		/* Don't "cache" in memring, it is for new creations */
		if (!pgpVirtMaskIsEqual(&file->set.mask, &pool->memringmask) &&
					len < NAMECACHETHRESHOLD) {
			buf = (char *)memPoolAlloc(&file->strings, len+1, 1);
			if (buf) {
				pgpCopyMemory( pool->pktbuf, buf, len );
				buf[len] = '\0'; /* null after names in memory */
				name->n.name.ptr = buf;
				NAMESETFILEMASK(&name->n, pgpVirtMaskLSBit(&file->set.mask));
				NAMESETCACHED(&name->n);
			}
		}
#endif
	}
	return name;
}

/*
 * Return 1 if the signature in the ring's pktbuf differs from the
 * sig in its various homes, 0 if it is the same, and <0 if there
 * is some sort of error.
 * Does *not* alter file1's read position unless there is an error.
 */
int
sigsdiffer(RingFile *file1, union RingObject const *sig)
{
	RingPool *pool = file1->set.pool;
	RingFile *file2;
	long retpos=0;
	int i;

	/* Find a matching signature */
	file2 = ringBestFile(pool, sig, 0);
	pgpAssert (file2);
	pgpAssert (file2->f ||
			   pgpVirtMaskIsEqual (&file2->set.mask, &pool->memringmask));
	if (file2 == file1 && file1->f &&
			(retpos = pgpFileTell(file1->f)) < 0) {
		ringErr(file1, pgpFileTell(file1->f), kPGPError_FileOpFailed);
		return kPGPError_FileOpFailed;
	}

	/* Note that we don't need to seek file2 here, ringPacketDiffers does */
	i = ringPacketDiffers(file2, sig, PKTBYTE_SIG, (PGPUInt32)-1);

	if (file2 == file1 && file1->f &&
			pgpFileSeek(file1->f, retpos, SEEK_SET) != 0) {
		ringErr(file1, sig->g.pos.fpos, kPGPError_FileOpFailed);
		return kPGPError_FileOpFailed;
	}
	return i;
}

static union RingObject *
ringFindSig(RingFile *file, union RingObject *parent)
{
	RingPool *pool = file->set.pool;
	union RingObject *key;
	union RingObject *sig, **sigp, **fsigp;
	int i;

	/* Properties of the signature */
	int err;
	PGPByte pkalg, keyID[8];
	PGPUInt32 tstamp;
	PGPUInt32 sigvalidity;
	PGPByte type;	
	PGPByte hashalg;
	PGPByte version;
	PGPBoolean exportable;
	PGPBoolean revocable;
	PGPBoolean hasRegExp;
	PGPBoolean primaryUID;
	PGPBoolean isX509;
	PGPByte trustLevel;
	PGPByte trustValue;
	size_t extralen;

	pkalg = 0;
	err = ringSigParse((PGPByte const *)pool->pktbuf, pool->pktbuflen,
	                   &pkalg, keyID, &tstamp, &sigvalidity, &type,
	                   &hashalg, &extralen, &version, &exportable,
					   &revocable, &trustLevel, &trustValue, &hasRegExp,
					   &isX509, &primaryUID);
	/* Don't allow bogus signatures, we have a bug where they cause trouble */
	if (err)
		return NULL;

	/* Get key this signature is by */
	key = ringPoolFindDummyKey(pool, file, NULL, pkalg, keyID, isX509);
	if (!key)
		return NULL;

	/* Search for matching sigs */
	fsigp = &parent->g.down;
	for (sigp = fsigp; (sig=*sigp) != NULL; sigp = &sig->g.next) {
		if (OBJISSEC(sig) || OBJISSIG(sig))
			fsigp = &sig->g.next; /* predecessor to new sig */
		if (OBJISSIG(sig)
		    && sig->s.by       == key
		    && (sig->s.by->k.pkalg == pkalg || isX509 || pkalg==1)/*ViaCrypt*/
		    && sig->s.tstamp		== tstamp
		    && sig->s.type			== type
			&& sig->s.version		== version
		    && sig->s.sigvalidity	== sigvalidity
		    && sig->s.hashalg		== hashalg
		    && sig->s.trustLevel	== trustLevel
		    && sig->s.trustValue	== trustValue
		    && !(sig->g.flags & SIGF_ERROR) == !err
		    && !(sig->g.flags & SIGF_NONFIVE) == (extralen == 5)
			&& !SIGISEXPORTABLE(&sig->s) == !exportable
			&& !SIGISREVOCABLE(&sig->s) == !revocable
			&& !SIGUSESREGEXP(&sig->s) == !hasRegExp
			&& !SIGISX509(&sig->s) == !isX509
			&& !SIGISPRIMARYUID(&sig->s) == !primaryUID
		    && (i = sigsdiffer(file, sig)) <= 0)
		{
			return i<0 ? NULL : sig;
		}
	}

	/* Not found - allocate a new sig */
	sig = ringNewSig(pool);
	if (sig) {
		/* Add new sig before any user ID's */
		sig->g.next = *fsigp;
		*fsigp = sig;
		sig->s.by = (union RingObject *)key;
		sig->g.up = parent;
		if (err)
			sig->g.flags |= SIGF_ERROR;
		if (extralen != 5)
			sig->g.flags |= SIGF_NONFIVE;
		sig->s.tstamp = tstamp;
		sig->s.sigvalidity = sigvalidity;
		sig->s.type = type;
		sig->s.version = version;
		sig->s.hashalg = hashalg;
		sig->s.trust = 0;
		sig->s.trustLevel = trustLevel;
		sig->s.trustValue = trustValue;
		if (exportable)
			SIGSETEXPORTABLE(&sig->s);
		else
			SIGSETNONEXPORTABLE(&sig->s);
		if (revocable)
			SIGSETREVOCABLE(&sig->s);
		else
			SIGSETNONREVOCABLE(&sig->s);
		if (hasRegExp)
			SIGSETUSESREGEXP(&sig->s);
		else
			SIGCLEARUSESREGEXP(&sig->s);
		if (isX509)
			SIGSETX509(&sig->s);
		else
			SIGCLEARX509(&sig->s);
		if (primaryUID)
			SIGSETPRIMARYUID(&sig->s);
		else
			SIGCLEARPRIMARYUID(&sig->s);
	}
	return sig;
}

/*
 * Return 1 if the CRL in the ring's pktbuf differs from the
 * CRL in its various homes, 0 if it is the same, and <0 if there
 * is some sort of error.
 * Does *not* alter file1's read position unless there is an error.
 */
int
crlsdiffer(RingFile *file1, union RingObject const *crl)
{
	RingPool *pool = file1->set.pool;
	RingFile *file2;
	long retpos=0;
	int i;

	/* Find a matching crl */
	file2 = ringBestFile(pool, crl, 0);
	pgpAssert (file2);
	pgpAssert (file2->f ||
			   pgpVirtMaskIsEqual (&file2->set.mask, &pool->memringmask));
	if (file2 == file1 && file1->f && (retpos=pgpFileTell(file1->f)) < 0) {
		ringErr(file1, pgpFileTell(file1->f), kPGPError_FileOpFailed);
		return kPGPError_FileOpFailed;
	}

	/* Note that we don't need to seek file2 here, ringPacketDiffers does */
	i = ringPacketDiffers(file2, crl, PKTBYTE_CRL, pool->pktbuflen+1);

	if (file2 == file1 && file1->f &&
			pgpFileSeek(file1->f, retpos, SEEK_SET) != 0) {
		ringErr(file1, crl->g.pos.fpos, kPGPError_FileOpFailed);
		return kPGPError_FileOpFailed;
	}
	return i;
}

/*
 * Get a RingCRL on the given chain matching the one in the ring's
 * pktbuf with the given pktbyte.  Returns 0 if it runs out of memory
 * or can't read the file.  (The ring's error is set to reflect this.)
 * It does *not* add the FilePos or set the mask bit.
 * Does *not* alter the given file's read position unless there is an error.
 */
static union RingObject *
ringFindCRL(RingFile *file, union RingObject *parent)
{
	RingPool *pool = file->set.pool;
	union RingObject *crl, **crlp;
	PGPUInt32 hash;
	PGPUInt32 tstamp, tstampnext;
	PGPByte version;
	PGPByte type;
	PGPByte const *dpoint;
	PGPSize dpointlen;
	int i;

	hash = ringHashBuf((PGPByte const *)pool->pktbuf, pool->pktbuflen);

	for (crlp = &parent->g.down; (crl=*crlp) != NULL;
			crlp = &crl->g.next) {
		/*
		 * If the hash matches, try to compare...
		 */
		if (OBJISCRL(crl)
		    && crl->r.hash    == hash
		    && (i = crlsdiffer(file, crl)) <= 0)
		{
			return i<0 ? NULL : crl;
		}
	}

	/* Failed to find a CRL - create one */
	crl = ringNewCRL(pool);
	if (crl) {
		(void)ringCRLParse(pool, (PGPByte const *)pool->pktbuf,pool->pktbuflen,
						   &version, &type, &tstamp, &tstampnext,
						   &dpoint, &dpointlen);
		*crlp = crl;
		crl->g.up = parent;
		crl->r.hash = hash;
		crl->r.version = version;
		crl->r.tstamp = tstamp;
		crl->r.tstampnext = tstampnext;
		if (type == PGPCRLTYPE_X509 || type == PGPCRLTYPE_X509DPOINT)
			CRLSETX509(&crl->r);
		else
			CRLCLEARX509(&crl->r);
		if (type == PGPCRLTYPE_X509DPOINT) {
			CRLSETDPOINT(&crl->r);
			crl->r.dpointhash = ringHashBuf( dpoint, dpointlen );
		} else {
			CRLCLEARDPOINT(&crl->r);
		   crl->r.dpointhash = 0;
		}
	}
	return crl;
}

/*
 * Return 1 if the blob in the ring's pktbuf differs from the
 * blob in its various homes, 0 if it is the same, and <0 if there
 * is some sort of error.
 * Does *not* alter file1's read position unless there is an error.
 */
int
unkdiffer(RingFile *file1, union RingObject const *unk)
{
	RingPool *pool = file1->set.pool;
	RingFile *file2;
	long retpos=0;
	int i;

	/* Find a matching unk */
	file2 = ringBestFile(pool, unk, 0);
	pgpAssert (file2);
	pgpAssert (file2->f ||
			   pgpVirtMaskIsEqual (&file2->set.mask, &pool->memringmask));
	if (file2 == file1 && file1->f && (retpos=pgpFileTell(file1->f)) < 0) {
		ringErr(file1, pgpFileTell(file1->f), kPGPError_FileOpFailed);
		return kPGPError_FileOpFailed;
	}

	/* Note that we don't need to seek file2 here, ringPacketDiffers does */
	i = ringPacketDiffers(file2, unk, PKTBYTE_TYPE(unk->u.pktbyte),
	                      pool->pktbuflen+1);

	if (file2 == file1 && file1->f &&
			pgpFileSeek(file1->f, retpos, SEEK_SET) != 0) {
		ringErr(file1, unk->g.pos.fpos, kPGPError_FileOpFailed);
		return kPGPError_FileOpFailed;
	}
	return i;
}

/*
 * Get a RingUnk on the given chain matching the one in the ring's
 * pktbuf with the given pktbyte.  Returns 0 if it runs out of memory
 * or can't read the file.  (The ring's error is set to reflect this.)
 * It does *not* add the FilePos or set the mask bit.
 * Does *not* alter the given file's read position unless there is an error.
 */
static union RingObject *
ringFindUnk(RingFile *file, union RingObject *parent, PGPByte pktbyte)
{
	RingPool *pool = file->set.pool;
	union RingObject *unk, **unkp;
	PGPUInt32 hash;
	int i;

	hash = ringHashBuf((PGPByte const *)pool->pktbuf, pool->pktbuflen);

	for (unkp = &parent->g.down; (unk=*unkp) != NULL;
			unkp = &unk->g.next) {
		/*
		 * If the type, hash and pktbyte match, try to compare...
		 * Note that the pktbyte *must* match or namesdiffer()
		 * will complain loudly.
		 */
		if (OBJISUNK(unk)
		    && unk->u.hash    == hash
		    && unk->u.pktbyte == pktbyte
		    && (i = unkdiffer(file, unk)) <= 0)
		{
			return i<0 ? NULL : unk;
		}
	}

	/* Failed to find a name - create one */
	unk = ringNewUnk(pool);
	if (unk) {
		*unkp = unk;
		unk->g.up = parent;
		unk->u.pktbyte = pktbyte;
		unk->u.hash = hash;
		/* Default new names to unknown trust */
	}
	return unk;
}

/* Return the list of trpuble associated with a RingFile. */
RingTrouble const *
ringFileTrouble(RingFile const *file)
{
	return file->trouble;
}

/*
 * Functions for manipulating the Trouble list.
 */

/* Zero out a RingFile's Trouble list; it has been dealt with. */
void
ringFilePurgeTrouble(RingFile *file)
{
	memPoolEmpty(&file->troublepool);
	file->trouble = NULL;
	file->troubletail = &file->trouble;
}

/*
 * Log some trouble with a RingFile.
 */
static int
ringFileLog(RingFile *file, union RingObject *obj, PGPUInt32 num,
	    PGPUInt32 fpos, int type)
{
	RingTrouble *t;

	t = (RingTrouble *)memPoolNew(&file->troublepool,
			RingTrouble);
	if (!t)
		return kPGPError_OutOfMemory;

	t->next = NULL;
	t->obj = obj;
	t->num = num;
	t->fpos = fpos;
	t->type = type;

	*file->troubletail = t;
	file->troubletail = &t->next;
	return 0;
}

/*
 * @@@ This needs fixing - we should complain about a key without
 * names in *this* file, even if it has names in others.
 */
static union RingObject const *
ringKeyHasName(union RingObject const *obj)
{
	for (obj = obj->g.down; obj; obj = obj->g.next)
		if (OBJISNAME(obj))
			break;
	return obj;
}



/*
 * Keep only one name attribute object with the specified type.
 * Keep the one with the newest self sig.
 */
static int
ringAttributeKeepNewest(RingObject *key, RingFile *file, PGPUInt32 atype)
{
#if 1
/* This function does not really accomplish what we were hoping to
 * achieve.  It does prevent imports from bringing in more than one
 * photo id per key.  But it does not deal with the problem that the
 * base key ring may have a different photo id than the one being
 * imported.  In that case we may need to go back and remove the photo
 * id which is part of the base key ring.  That is difficult to do
 * safely from here.  For now we will disable this functionality.
 */
	(void) key;
	(void) file;
	(void) atype;
	return kPGPError_NoErr;
#else
	RingObject *name, *sig, *nextname;
	PGPUInt32 attrtype;
	PGPUInt32 attrtime;
	RingObject *prevattr = NULL;
	PGPUInt32 prevattrtime = 0;
	PGPUInt32 sigtime;
	RingObject *newestsig = NULL;
	PGPUInt32 newestsigtime;
	RingSet *set = &file->set;
	long pos = 0;

	for (name=key->g.down; name; name=nextname) {
		/* May delete name so must do iteration here */
		nextname = name->g.next;
		/* Skip if not an attribute name */
		if (!OBJISNAME(name))
			continue;
		if (!pgpIsRingSetMember(set, name))
			continue;
		if (!NAMEISATTR(&name->n))
			continue;
		/* Skip if not the right kind of attribute */
		/* This call may change the file pointer! */
		pos = pgpFileTell(file->f);
		if (pos == -1)
			return kPGPError_FileOpFailed;
		if (!ringNameAttributeSubpacket (name, set, 0, &attrtype, NULL, NULL))
			continue;
		if (pgpFileSeek(file->f, pos, SEEK_SET) != 0)
			return kPGPError_FileOpFailed;
		if (attrtype != atype)
			continue;
		/* Here, have the desired attribute.  Find date of newest self sig. */
		attrtime = 0;
		newestsigtime = 0;
		newestsig = NULL;
		for (sig=name->g.down; sig; sig=sig->g.next) {
			if (!OBJISSIG(sig))
				continue;
			if (!pgpIsRingSetMember(set, sig))
				continue;
			if (sig->s.by != key)
				continue;
			/* Have self sig on name */
			sigtime = ringSigTimestamp(set, sig);
			if (sigtime > newestsigtime) {
				newestsig = sig;
				newestsigtime = sigtime;
			}
		}
		if (IsntNull(newestsig) &&
			    (newestsig->s.type & 0xF0) == PGP_SIGTYPE_KEY_GENERIC) {
			attrtime = newestsigtime;
		}
		if (prevattr) {
			if (prevattrtime < attrtime) {
				/* Previous attribute is superceded by this one */
				ringRemFileObjChildren (prevattr, file);
				prevattr = name;
				prevattrtime = attrtime;
			} else {
				/* This attribute is superceded by previously seen one */
				ringRemFileObjChildren (name, file);
			}
		} else {
			prevattr = name;
			prevattrtime = attrtime;
		}
	}
	return kPGPError_NoErr;
#endif
}


/*
 * Return true if sig is nonimportable.  We normally treat nonexportable
 * sigs as nonimportable, but there may be some exceptions.
 */
static int
ringSigNonimportable(RingObject *sig, RingFile *file, RingSet *set)
{
	PGPByte *p;
	PGPSize len;
	PGPUInt32 i = 0;
	long pos = 0;

	pgpAssert (pgpIsRingSetMember (set, sig));
	pgpAssert (OBJISSIG(sig));

	if (SIGISEXPORTABLE(&sig->s))
		return 0;

	/* Import sig if it makes us a revoker for this key */
	/* (Preserve file position) */
	pos = pgpFileTell(file->f);
	if (pos == -1)
		return kPGPError_FileOpFailed;
	p = (PGPByte *)ringFetchObject(set, sig, &len);
	if (pgpFileSeek(file->f, pos, SEEK_SET) != 0)
		return kPGPError_FileOpFailed;

	while (p) {
		RingObject *rkey;
		RingSet *allkeys;
		PGPByte *subp;

		/* Look for ith revocation subpacket */
		subp = (PGPByte *)ringSigFindSubpacket (p,
							SIGSUB_KEY_REVOCATION_KEY, i++, NULL, NULL,
							NULL, NULL, NULL);
		if (IsNull(subp)) {
			p = NULL;
			break;
		}

		/* Hack to create keyset of all keys in pool */
		allkeys = ringSetCopy (set);
		if (IsNull( allkeys ) ) {
			return ringSetError(set)->error;
		}
		ringAllocMask (set->pool, NULL, &allkeys->mask);

		/* See if we have revoking key as a secret key */
		rkey = ringKeyById8 (allkeys, subp[1], subp+2+20-8);
		if (rkey && !pgpVirtMaskIsEmpty (&rkey->g.mask) &&
									ringKeyIsSec (allkeys, rkey)) {
			/* Break w/p non-null, we are revoker */
			ringSetDestroy(allkeys);
			break;
		}
		ringSetDestroy(allkeys);
	}

	/* If p is non-null, we are revoker and can keep it */
	return IsNull(p);
}

/*
 * Eliminate nonexportable signatures, except in special cases.
 * This function may harm the pktbuf so should not be called when it holds
 * necessary data.
 */
static int
ringKeyCleanupNonexportables(RingObject *key, RingFile *file)
{
	RingObject *name, *nextname;
	RingObject *sig, *nextsig;
	RingSet *set = &file->set;

	for (name=key->g.down; name; name=nextname) {
		nextname = name->g.next;
		if (!pgpIsRingSetMember(set, name))
			continue;
		if (OBJISSIG(name)) {
			if (ringSigNonimportable(name, file, set)) {
				ringRemFileObjChildren (name, file);
			}
		} else {
			for (sig=name->g.down; sig; sig=nextsig) {
				nextsig = sig->g.next;
				if (!pgpIsRingSetMember(set, sig))
					continue;
				if (!OBJISSIG(sig))
					continue;
				if (ringSigNonimportable(sig, file, set)) {
					ringRemFileObjChildren (sig, file);
				}
			}
		}
	}
	return 0;
}

/* Called when we have finished reading in a key and all its children,
 * to make sure that it is kosher - must have a name, etc.
 * We can also eliminate redundant or nonimportable objects here.
 * This function may harm the pktbuf so should not be called when it holds
 * necessary data.
 */
static int
ringKeyCleanup(RingFile *file, union RingObject *key, int trusted)
{
	int i;
	RingObject *primaryname;

	pgpAssert(OBJISKEY(key));

	/* Complain about a key with no Names */
	if (!ringKeyHasName(key)) {
		i = ringFileLog(file, key, 0,
						ringFilePos(key, file)->fpos,
						kPGPError_TroubleBareKey);
		if (i < 0) {
			return i;
		}
	}
	if (!trusted) {
		/* If importing a nonexportable signature, delete it */
		i = ringKeyCleanupNonexportables (key, file);
	}

#define PHOTOATTRIBUTE 1
	if (!trusted) {
		/* Only allow one photo userid */
		i = ringAttributeKeepNewest(key, file, PHOTOATTRIBUTE);
		if (i < 0) {
			return i;
		}
	}

	/* Make sure primary userid is at the top */
	primaryname = ringKeyPrimaryName (key, &file->set, 0);
	if (primaryname)
		ringRaiseName (&file->set, primaryname);

	/* @@@ Should we not care about this? */
	/* If keys not in sorted order, dirty */
#if 0
	/* @@@ ringSortKeys orders keys by algorithm
	   so this test no longer works. */
	if (ringKeyIDcmp(key->k.keyID, keyID) > 0)
		ringFileMarkDirty(file);
#endif

	return 0;	/* All OK */
}


/*
 * How to skip things.  Various helper functions return either
 * negative fatal error codes or these codes indicating what to
 * do to recover from any warnings.  These never exceed 15 bits,
 * so "int" is the right type.
 */

typedef int skip_t;
#define SKIP_TRUST 1
#define SKIP_SIG 2
#define SKIP_NAME 4
#define SKIP_SUBKEY 8
#define SKIP_KEY 16

#define SKIP_SIGS (SKIP_TRUST | SKIP_SIG)
#define SKIP_TO_KEY (SKIP_SIGS | SKIP_NAME | SKIP_SUBKEY)

#define PB_PUBKEY(key) (OBJISTOPKEY(key) ? \
	PKTBYTE_BUILD(PKTBYTE_PUBKEY, 0) : \
	PKTBYTE_BUILD(PKTBYTE_PUBSUBKEY, 0))
#define PB_SECKEY(key) (OBJISTOPKEY(key) ? \
	PKTBYTE_BUILD(PKTBYTE_SECKEY, 0) : \
	PKTBYTE_BUILD(PKTBYTE_SECSUBKEY, 0))
#define PB_SIG PKTBYTE_BUILD(PKTBYTE_SIG, 0)

/*
 * Add a new key to the Pool, with its *parent* at the given level
 * (0 means adding top-level key) in the RingIterator.  Leave the
 * RingIterator pointing to the newly created key.  Return <0 on error,
 * 0 if the key was created, and a skip code > 0 if it was created with
 * a warning of some sort.
 */
static int
ringAddKey(RingFile *file, RingIterator *iter, PGPUInt32 fpos,
	int trusted, PGPByte pkttype)
{
	union RingObject *key, *sec, *parent;
	PGPByte pkalg, keyID[8], fp20n[20];
	PGPUInt16 keybits;
	PGPUInt32 tstamp;
	PGPUInt16 validity;
	PGPByte v3;
	PGPVirtMask secmask, pubmask;
	RingPool *pool = file->set.pool;
	int i, err, level;

	(void) trusted;

	pgpVirtMaskInit (pool, &secmask);
	pgpVirtMaskInit (pool, &pubmask);

	pkalg = 0;
	err = ringKeyParse(file->set.pool->context,
					   (PGPByte const *)file->set.pool->pktbuf,
	                   file->set.pool->pktbuflen, &pkalg,
	                   keyID, fp20n, &keybits, &tstamp, &validity, &v3, 0);

	if (pkttype == PKTBYTE_PUBSUBKEY) {
		/* Subkey */
		if (!iter->level) {
			i = ringFileLog(file, NULL, 0, fpos,
					kPGPError_TroubleUnexpectedSubKey);
			pgpVirtMaskCleanup (pool, &secmask);
			pgpVirtMaskCleanup (pool, &pubmask);
			return i < 0 ? i : SKIP_SIGS;
		}
		parent = iter->stack[0];
		level = 1;
	} else {
		parent = NULL;
		level = 0;
	}

	/* Find the matching key structure */
	key = ringPoolFindDummyKey(file->set.pool, file, parent, pkalg, keyID,
							   FALSE);
	if (!key) {
		pgpVirtMaskCleanup (pool, &secmask);
		pgpVirtMaskCleanup (pool, &pubmask);
		return ringFileError(file)->error;
	}

	/* See if it's a new key or the same key */
	if (pgpVirtMaskIsEmpty (&key->g.mask)) {
		/* Newly created dummy key; fill in info */
		if (pkttype == PKTBYTE_PUBSUBKEY  &&  OBJISTOPKEY(key)) {
			/*
			 * Here on a former dummy top-level key which
			 * has turned out to be a subkey.  Dummy key
			 * would have been created if we saw a sig by
			 * it.  Change key to a subkey.
			 */
			i = ringFileLog(file, NULL, 0, fpos,
					kPGPError_TroubleSigSubKey);
			if (i < 0) {
				pgpVirtMaskCleanup (pool, &secmask);
				pgpVirtMaskCleanup (pool, &pubmask);
				return i;
			}
			ringPoolUnlinkKey(file->set.pool, key);
			key->k.flags |= RINGOBJF_SUBKEY;
			ringPoolLinkKey(file->set.pool, parent, key,
					pkalg, keyID);
		}

		key->k.fp20n = fp20n[0];
		key->k.pkalg = pkalg;	/* ViaCrypt */
		key->k.tstamp = tstamp;
		key->k.validity = validity;
		key->k.keybits = keybits;
		key->k.trust = 0;
		if (v3)
			KEYSETV3(&key->k);
		if (err)
			key->g.flags |= KEYF_ERROR;

	} else if (keybits     != key->k.keybits
		   || fp20n[0] != key->k.fp20n
		   || pkalg    != key->k.pkalg		/* ViaCrypt */
		   || tstamp   != key->k.tstamp
/*		   || validity != key->k.validity	Validity may be in sig */
		   || parent   != (OBJISTOP(key) ? NULL : key->g.up)
		   || v3	   != !!KEYISV3(&key->k)
		   || !(key->g.flags & KEYF_ERROR) != !err)
	{
		i = ringFileLog(file, key, 0, fpos,
		                kPGPError_TroubleDuplicateKeyID);
		pgpVirtMaskCleanup (pool, &secmask);
		pgpVirtMaskCleanup (pool, &pubmask);
		return i < 0 ? i : SKIP_TO_KEY;

	} else if ((i=keysdiffer(file,key,PB_PUBKEY(key))) != 0) {
		if (i < 0) {
			pgpVirtMaskCleanup (pool, &secmask);
			pgpVirtMaskCleanup (pool, &pubmask);
			return i;
		}
		if ((OBJISTOPKEY(key) && pkttype==PKTBYTE_PUBSUBKEY) ||
		    (OBJISSUBKEY(key) && pkttype==PKTBYTE_PUBKEY)) {
			i = ringFileLog(file, key, 0, fpos,
				kPGPError_TroubleKeySubKey);
			pgpVirtMaskCleanup (pool, &secmask);
			pgpVirtMaskCleanup (pool, &pubmask);
			return (i < 0) ? i : SKIP_TO_KEY;
		}
/* KLUDGE: version byte bug */
		/*
		 * A key with a version byte of 2 only overrides previous
		 * keys with a byte of 3 if they are all untrusted
		 * secret keys.
		 * A key with a version byte
		 * of 3 is only overridden if it's secret and previous
		 * keys include a secret key or a trusted public key.
		 * We will relax the previous rules to allow public keys with
		 * version 2 to override even when not from a trusted keyring.
		 * This happens when we import secret and public keyfiles as
		 * when we move our keyring.  Normally this should not introduce
		 * a weakness as the first keyrings we open will be trusted and
		 * therefore the key will have at least one public keyring as a
		 * home before we begin opening untrusted rings.
		 */
		ringKeySecMask(pool, key, &secmask);
		pgpVirtMaskCopy (pool, &key->g.mask, &pubmask);
		pgpVirtMaskANDNOT (pool, &secmask, &pubmask);
		if (i == PGPVERSION_2
		    && !(key->g.flags & RINGOBJF_TRUST)
			&& !pgpVirtMaskIsOverlapping (&pubmask, &pool->filemask))
		{
			i = ringFileLog(file, key, 0, fpos,
			       kPGPError_TroubleVersionBugPrev);
			if (i < 0) {
				pgpVirtMaskCleanup (pool, &secmask);
				pgpVirtMaskCleanup (pool, &pubmask);
				return i;
			}
			/* Set all those secret version bug flags */
			for (sec = key->g.down; sec; sec = sec->g.next)
				if (OBJISSEC(sec))
					sec->g.flags |= SECF_VERSION_BUG;
		} else {
/* End of KLUDGE */
			i = ringFileLog(file, key, 0, fpos,
					kPGPError_TroubleDuplicateKeyID);
			pgpVirtMaskCleanup (pool, &secmask);
			pgpVirtMaskCleanup (pool, &pubmask);
			return i < 0 ? i : SKIP_TO_KEY;
		}
	}

	/*
	 * Already present in this keyring?
	 * If so, accept following sigs & userids (they may
	 * not be duplicates), but flag a warning.
	 */
	if (pgpIsRingSetMember(&file->set, key)) {
		i = ringFileLog(file, key, 0, fpos, kPGPError_TroubleDuplicateKey);
		if (i < 0)
			goto failed;
		i = SKIP_TRUST;
	} else {
		/* Add the FilePos */
		i = ringAddPos(key, file, fpos);
		if (i < 0)
			goto failed;
	}
	/* Add successful; indicate it in the mask */
	pgpVirtMaskOR (pool, &iter->set.mask, &key->g.mask);
	iter->stack[level] = key;
	iter->level = level+1;
	pgpVirtMaskCleanup (pool, &secmask);
	pgpVirtMaskCleanup (pool, &pubmask);
	return i;

failed:
	if (pgpVirtMaskIsEmpty(&key->g.mask))
		ringFreeDummyKey(file->set.pool, key);
	pgpVirtMaskCleanup (pool, &secmask);
	pgpVirtMaskCleanup (pool, &pubmask);
	return i;
}

/*
 * Add a new secret to the Pool, as two objects: a key (with its *parent*
 * at the given level in the RingIterator; 0 means add a top-level key)
 * and a signature as its child.  Leave the RingIterator pointing to the
 * newly created secret.  Return <0 on error, 0 if the key was created,
 * and a skip code >0 if they key was created with a warning of some sort.
 *
 * This is *ridiculously* hairy.  Is there a way to clean it up?
 * @@@ TODO: Add kPGPError_TroubleOldSecretKey and _NEWSEC handling.
 */
static int
ringAddSec(RingFile *file, RingIterator *iter, PGPUInt32 fpos,
	PGPByte pkttype)
{
	union RingObject *key, *sec, *parent;
	PGPByte pkalg, keyID[8], fp20n[20];
	PGPUInt16 keybits;
	PGPUInt32 tstamp;
	PGPUInt16 validity;
	PGPVirtMask secmask, pubmask;
	PGPByte v3;
	RingPool *pool = file->set.pool;
	int i, err;
	int level;
	int flags = 0;

	pgpVirtMaskInit (pool, &secmask);
	pgpVirtMaskInit (pool, &pubmask);

	pkalg = 0;
	err = ringKeyParse(file->set.pool->context,
					   (PGPByte const *)file->set.pool->pktbuf,
	                   file->set.pool->pktbuflen, &pkalg,
	                   keyID, fp20n, &keybits, &tstamp, &validity, &v3, 1);

	if (pkttype == PKTBYTE_SECSUBKEY) {
		/* Subkey */
		if (!iter->level) {
			i = ringFileLog(file, NULL, 0, fpos,
					kPGPError_TroubleUnexpectedSubKey);
			pgpVirtMaskCleanup (pool, &secmask);
			pgpVirtMaskCleanup (pool, &pubmask);
			return i < 0 ? i : SKIP_SIGS;
		}
		parent = iter->stack[0];
		level = 1;
	} else {
		parent = NULL;
		level = 0;
	}

	/* Find the matching key structure */
	key = ringPoolFindDummyKey(file->set.pool, file, parent, pkalg, keyID,
							   FALSE);
	if (!key) {
		pgpVirtMaskCleanup (pool, &secmask);
		pgpVirtMaskCleanup (pool, &pubmask);
		return ringFileError(file)->error;
	}

	/* See if it's a new key or the same key */
	if (pgpVirtMaskIsEmpty (&key->g.mask)) {
		/* Newly created dummy key; fill in info */
		if (pkttype == PKTBYTE_SECSUBKEY  &&  OBJISTOPKEY(key)) {
			/*
			 * Here on a former dummy top-level key which
			 * has turned out to be a subkey.  Dummy key
			 * would have been created if we saw a sig by
			 * it.  Change key to a subkey.
			 */
			i = ringFileLog(file, NULL, 0, fpos,
					kPGPError_TroubleSigSubKey);
			if (i < 0) {
				pgpVirtMaskCleanup (pool, &secmask);
				pgpVirtMaskCleanup (pool, &pubmask);
				return i;
			}
			ringPoolUnlinkKey(file->set.pool, key);
			key->k.flags |= RINGOBJF_SUBKEY;
			ringPoolLinkKey(file->set.pool, parent, key,
					pkalg, keyID);
		}

		/* Newly created dummy key; fill in info */
		key->k.fp20n = fp20n[0];
		key->k.pkalg = pkalg;	/* ViaCrypt */
		key->k.tstamp = tstamp;
		key->k.validity = validity;
		key->k.keybits = keybits;
		key->k.trust = 0;
		if (v3)
			KEYSETV3(&key->k);
		if (err)
			key->g.flags |= KEYF_ERROR;

	} else if (keybits     != key->k.keybits
		   || fp20n[0] != key->k.fp20n
		   || pkalg    != key->k.pkalg		/* ViaCrypt */
		   || tstamp   != key->k.tstamp
/*		   || validity != key->k.validity	Validity may be in sig */
		   || parent   != (OBJISTOP(key) ? NULL : key->g.up)
		   || v3	   != !!KEYISV3(&key->k)
		   || !(key->g.flags & KEYF_ERROR) != !err)
	{
		i = ringFileLog(file, key, 0, fpos, kPGPError_TroubleDuplicateKeyID);
		pgpVirtMaskCleanup (pool, &secmask);
		pgpVirtMaskCleanup (pool, &pubmask);
		return i < 0 ? i : SKIP_TO_KEY;

	} else if ((i=keysdiffer(file,key,PB_SECKEY(key))) != 0) {
		if (i < 0) {
			pgpVirtMaskCleanup (pool, &secmask);
			pgpVirtMaskCleanup (pool, &pubmask);
			return i;
		}
		if ((OBJISTOPKEY(key) && pkttype==PKTBYTE_PUBSUBKEY) ||
		    (OBJISSUBKEY(key) && pkttype==PKTBYTE_PUBKEY)) {
			i = ringFileLog(file, key, 0, fpos,
				kPGPError_TroubleKeySubKey);
			pgpVirtMaskCleanup (pool, &secmask);
			pgpVirtMaskCleanup (pool, &pubmask);
			return (i < 0) ? i : SKIP_TO_KEY;
		}
/* KLUDGE: version byte bug */
		/*
		 * A key with a version byte of 2 only overrides previous
		 * keys with a PGPByte of 3 if they are all untrusted
		 * secret keys and this is either a secret key or from
		 * a trusted public keyring.  A key with a version byte
		 * of 3 is only overridden if it's secret and previous
		 * keys include a secret key or a trusted public key.
		 */
		ringKeySecMask(pool, key, &secmask);
		pgpVirtMaskCopy (pool, &key->g.mask, &pubmask);
		pgpVirtMaskANDNOT (pool, &secmask, &pubmask);
		if (i == PGPVERSION_2
		    && !(key->g.flags & RINGOBJF_TRUST)
			&& !pgpVirtMaskIsOverlapping (&pubmask, &pool->filemask))
		{
			i = ringFileLog(file, key, 0, fpos,
			       kPGPError_TroubleVersionBugPrev);
			if (i < 0) {
				pgpVirtMaskCleanup (pool, &secmask);
				pgpVirtMaskCleanup (pool, &pubmask);
				return i;
			}
			/* Set all those secret version bug flags */
			for (sec = key->g.down; sec; sec = sec->g.next)
				if (OBJISSEC(sec))
					sec->g.flags |= SECF_VERSION_BUG;
		} else if (i == PGPVERSION_3
		           && (key->g.flags & RINGOBJF_TRUST
					   || !pgpVirtMaskIsEmpty (&secmask)))
		{
			i = ringFileLog(file, key, 0, fpos,
			       kPGPError_TroubleVersionBugCur);
			if (i < 0) {
				pgpVirtMaskCleanup (pool, &secmask);
				pgpVirtMaskCleanup (pool, &pubmask);
				return i;
			}
			flags |= SECF_VERSION_BUG;
			/* Fix the problem */
			((PGPByte *)file->set.pool->pktbuf)[0] = PGPVERSION_2;
		} else {
/* End of KLUDGE */
			i = ringFileLog(file, key, 0, fpos,
					kPGPError_TroubleDuplicateKeyID);
			pgpVirtMaskCleanup (pool, &secmask);
			pgpVirtMaskCleanup (pool, &pubmask);
			return i < 0 ? i : SKIP_TO_KEY;
		}
	}

	/* Okay, we've got the public key.  Now add the secret. */

	sec = ringFindSec(file, key);
	if (!sec) {
		i = ringFileError(file)->error;
		goto failed;
	}
	sec->c.flags |= flags;

	if (pgpIsRingSetMember (&file->set, sec)) {
		i = ringFileLog(file, key, 0,
				fpos, kPGPError_TroubleDuplicateSecretKey);
		if (i < 0)
			goto failed;
		i = SKIP_TRUST;
	} else {
		/* Add the FilePos */
		i = ringAddPos(sec, file, fpos);
		if (i < 0) {
			pgpAssert(!pgpVirtMaskIsEmpty(&sec->g.mask));
			goto failed;
		}
	}

	/*
	 * Already present in this keyring?
	 * If so, accept following sigs & userids (they may
	 * not be duplicates), but flag a warning.
	 * If the previous instances were all public keys,
	 * but this is a secret key, "upgrade" the reference.
	 */
	if (pgpIsRingSetMember (&file->set, key)) {
		/* Only do this if it wasn't a duplicate *secret* */
		if (i != SKIP_TRUST) {
			i = ringFileLog(file, key, 0, fpos,
					kPGPError_TroubleDuplicateKey);
			if (i < 0)
				goto failed;
			ringAlterFilePos(key, file, fpos);
			i = SKIP_TRUST;
		}
	} else {
		/* Add the FilePos */
		err = i;
		i = ringAddPos(key, file, fpos);
		if (i < 0)
			goto failed;
		i = err;
	}
	/* Add successful; indicate it in the mask */
	pgpVirtMaskOR (pool, &iter->set.mask, &key->g.mask);
	pgpVirtMaskOR (pool, &iter->set.mask, &sec->g.mask);
	iter->stack[level] = key;
	iter->stack[level+1] = sec;
	iter->level = level+2;
	pgpVirtMaskCleanup (pool, &secmask);
	pgpVirtMaskCleanup (pool, &pubmask);
	return i;

failed:
	if (pgpVirtMaskIsEmpty(&key->g.mask))
		ringFreeDummyKey(file->set.pool, key);
	pgpVirtMaskCleanup (pool, &secmask);
	pgpVirtMaskCleanup (pool, &pubmask);
	return i;
}

/*
 * Add the name in the RingPool's pktbuf to the sets mentioned
 * in the given iterator, which points to the location where the
 * name should be added.  Leaves the RingIterator pointing to the
 * name just added.  fAttribute is true if it is a generalized attribute
 * packet.
 */
static int
ringAddName(RingFile *file, RingIterator *iter, PGPUInt32 fpos,
	PGPBoolean fAttribute)
{
	union RingObject *name;
	int i;

	pgpAssert(iter->level >= 1);
	name = ringFindName(file, iter->stack[0], fAttribute);
	if (!name)
		return ringFileError(file)->error;

	/*
	 * Already present in this keyring?
	 *
	 * If so, accept following sigs (they may not be
	 * duplicates), but flag a warning.
	 */
	if (pgpIsRingSetMember (&file->set, name)) {
		i = ringFileLog(file, name, 0, fpos, kPGPError_TroubleDuplicateName);
		if (i < 0)
			return i;
		i = SKIP_TRUST;
	} else {
		/* Add the FilePos */
		i = ringAddPos(name, file, fpos);
		if (i < 0) {
			pgpAssert (!pgpVirtMaskIsEmpty(&name->g.mask));
			return i;
		}
	}
	pgpVirtMaskOR (file->set.pool, &iter->set.mask, &name->g.mask);
	iter->stack[1] = name;
	iter->level = 2;
	return i;
}


/*
 * Given an X.509 sig in the pktbuf, look for any dummy keys which
 * might have been created to represent the top-level key above this
 * sig.  When we read in X.509 certs where we can't find the signer,
 * we create dummy keys with keyids set as the hash of the issuer
 * name.  We will see if there are any such dummy keys whose keyid
 * matches the hash of our subject name, and if so, we will change all
 * sigs whose "by" pointers point at the dummy so that they point at
 * our top level instead.  Then we will delete the dummy (otherwise
 * the next X.509 cert we read will point to it instead of searching
 * for our top level key).
 */
static PGPError
ringSigFixupX509Dummy (RingPool *pool, RingObject *topkey, RingObject *sig)
{
	PGPASN_XTBSCertificate *xtbscert;
	PGPByte *certbuf;
	PGPSize certlen;
	PGPByte *subjectname;
	PGPSize subjectlen;
	PGPByte hash[20];
	PGPByte *keyid;
	RingObject *keys;
	RingObject *k, *n, *s;
	RingObject **pkey;
	PGPByte const *dpoint;
	PGPError err = kPGPError_NoErr;

	certbuf = (PGPByte *)ringSigFindNAISubSubpacket ((PGPByte *)pool->pktbuf,
				SIGSUBSUB_X509, 0, &certlen, NULL, NULL, NULL, NULL);
	pgpAssert( IsntNull( certbuf ) );
	pgpAssert( certbuf[0] == SIGSUBSUB_X509 );
	certbuf += 3;
	certlen -= 3;

	/* Find subject name in cert */
	err = pgpX509BufferToXTBSCert( pool->context, certbuf, certlen, &xtbscert);
	if( IsPGPError( err ) )
		return err;
	subjectname = xtbscert->subject.val;
	subjectlen = xtbscert->subject.len;

	pgpFingerprint20HashBuf(pool->context, subjectname, subjectlen, hash);

	/* Take advantage of this opportunity to set DISTPOINT flag */
	dpoint =  pgpX509XTBSCertToDistPoint( xtbscert, NULL );
	if( dpoint != NULL ) {
		SIGSETDISTPOINT( &sig->s );
		PGPFreeData( (PGPByte *)dpoint );
	}

	pgpX509FreeXTBSCert( pool->context, xtbscert );

	keyid = hash + sizeof(hash) - 8;
	keys = ringPoolFindKey(pool, 0, keyid);
	if (IsntNull( keys ) && pgpVirtMaskIsEmpty (&keys->g.mask)) {
		/* Yes, we must fix all pointers.  No easy way to do this! */
		for (k=pool->keys; k; k=k->g.next) {
			if (!OBJISTOPKEY(k))
				continue;
			for (n=k->g.down; n; n=n->g.next) {
				if (!OBJISNAME(n))
					continue;
				for (s=n->g.down; s; s=s->g.next) {
					if (OBJISSIG(s) && SIGISX509(&s->s) &&
						keys == s->s.by)
						/* Fix pointer to our grandparent */
						s->s.by = topkey;
				}
			}
		}
		/* Remove dummy key from the keys list */
		pkey = &pool->keys;
		while (*pkey != keys)
			pkey = &(*pkey)->g.next;
		*pkey = keys->g.next;
		/* And from the hash chain */
		pkey = (RingObject **)&pool->hashtable[keys->k.keyID[0]];
		while (*pkey != keys)
			pkey = (RingObject **)&(*pkey)->k.util;
		*pkey = (RingObject *)keys->k.util;

		ringFreeObject(pool, keys);
	}
	return err;
}


static int
ringAddSig(RingFile *file, RingIterator *iter, PGPUInt32 fpos, int trusted)
{
	union RingObject *sig;
	int level;
	int i;

	(void)trusted;

	pgpAssert(iter->level >= 1);
	/* Stack position of parent: 0 or 1 */
	level = (iter->level > 1 &&
		 (OBJISNAME(iter->stack[1]) || OBJISSUBKEY(iter->stack[1])));
	sig = ringFindSig(file, iter->stack[level]);
	if (!sig)
		return ringFileError(file)->error;

	/* Already present in this keyring?  Complain. */
	if (pgpIsRingSetMember(&file->set, sig)) {
		i = ringFileLog(file, sig, 0, fpos,
						kPGPError_TroubleDuplicateSignature);
		if (i < 0)
			return i;
		i = SKIP_TRUST;
	} else {
		/* Add the FilePos */
		i = ringAddPos(sig, file, fpos);
		if (i < 0) {
			pgpAssert(!pgpVirtMaskIsEmpty(&sig->g.mask));
			return i;
		}
	}
	pgpVirtMaskOR (file->set.pool, &iter->set.mask, &sig->g.mask);
	iter->stack[level+1] = sig;
	iter->level = level+2;

	/* Upon adding an X.509 signature, see if there is a dummy key
	 * with keyid which matches the hash of the sig's subject name.
	 * If so, delete the dummy key and replace the s.by's which point
	 * at it with pointers to the top level key.
	 */
	if (SIGISX509 (&sig->s)) {
		ringSigFixupX509Dummy (file->set.pool, iter->stack[0], sig);
	}

	return i;
}

/*
 * Add the CRL in the RingPool's pktbuf to the sets mentioned
 * in the given iterator, which points to the location where the
 * object should be added.  Leaves the RingIterator pointing to the
 * object just added.
 */
static int
ringAddCRL(RingFile *file, RingIterator *iter, PGPUInt32 fpos)
{
	union RingObject *crl;
	int level;
	int i;

	pgpAssert(iter->level >= 1);
	
	/* Apply CRL to most recent key or subkey */
	level = iter->level - 1;
	while (level >= 1 && !OBJISKEY(iter->stack[level]))
		--level;
	pgpAssert( OBJISKEY( iter->stack[level] ) );

	crl = ringFindCRL(file, iter->stack[level]);
	if (!crl)
		return ringFileError(file)->error;

	/*
	 * Already present in this keyring?  If so, warn...
	 */
	if (pgpIsRingSetMember(&file->set, crl)) {
		i = ringFileLog(file, crl, 0, fpos, kPGPError_TroubleDuplicateCRL);
		if (i < 0)
			return i;
		i = SKIP_TRUST;
	} else {
		/* Add the FilePos */
		i = ringAddPos(crl, file, fpos);
		if (i < 0) {
			pgpAssert(!pgpVirtMaskIsEmpty(&crl->g.mask));
			return i;
		}
	}
	/* All done, we're happy... */
	pgpVirtMaskOR (file->set.pool, &iter->set.mask, &crl->g.mask);
	iter->stack[level+1] = crl;
	iter->level = level+2;
	return i;
}

/*
 * Add the unknown object in the RingPool's pktbuf to the sets mentioned
 * in the given iterator, which points to the location where the
 * object should be added.  Leaves the RingIterator pointing to the
 * object just added.
 */
static int
ringAddUnk(RingFile *file, RingIterator *iter, PGPUInt32 fpos,
	PGPByte pktbyte)
{
	union RingObject *unk;
	int level;
	int i;

	pgpAssert(iter->level >= 1);
	
	/* Stack position of parent: 0 or 1 */
	level = iter->level - 1;
	/* Place this */
	if (OBJISUNK(iter->stack[level]) && level)
		level--;
	/* Can't put it below a bottom-level object, make it a sib */
	if (OBJISBOT(iter->stack[level]) && level)
		level--;
	unk = ringFindUnk(file, iter->stack[level], pktbyte);
	if (!unk)
		return ringFileError(file)->error;

	/*
	 * Already present in this keyring?  If so, warn...
	 */
	if (pgpIsRingSetMember(&file->set, unk)) {
		i = ringFileLog(file, unk, 0, fpos, kPGPError_TroubleDuplicateUnknown);
		if (i < 0)
			return i;
		i = SKIP_TRUST;
	} else {
		/* Add the FilePos */
		i = ringAddPos(unk, file, fpos);
		if (i < 0) {
			pgpAssert(!pgpVirtMaskIsEmpty(&unk->g.mask));
			return i;
		}
	}
	/* All done, we're happy... */
	pgpVirtMaskOR (file->set.pool, &iter->set.mask, &unk->g.mask);
	iter->stack[level+1] = unk;
	iter->level = level+2;
	return i;
}


/*** The feature presentation ***/

/*
 * KLUDGE: PGP 2.6 had a bug wherein if you changed the passphrase on
 * a secret key, the newly encrpyted secret key would be written out
 * with a version byte of PGPVERSION_3 (= 3), even if the original
 * was PGPVERSION_2 (= 2).  PGP 2.6 didn't notice the problem and
 * would continue to function very happily with the problem.
 *
 * The code here notices and attempts to undo the problem,
 * "overriding" the version byte of 3 and forming a consistent
 * idea of the key's version byte.
 * The only problem is avoiding a denial-of-service attack if
 * someone sends me a public key with a version byte of 2 and
 * I compare it with my secret key with a (correct) version
 * byte of 3, and fix my secret key to 2 to correspond.
 * It could cause problems unfixable except with a binary file
 * editor.  So we only accept evidence of the bug under certain
 * conditions.  To be precise:
 *
 * - A key with a version byte of 2 can only override the previous
 *   version bytes of 3 if all previous keys are secret keys
 *   without trust information and the key is either a secret key
 *   or from a trusted public keyring.
 * - A key with a version byte of 3 is only overridden by previous
 *   keys if it is a secret key and the previous keys include a
 *   secret key or a key from a trusted keyring.
 *
 * A Trouble record is logged in either case.  TROUBLE_VERSION_BUG_PREV
 * if previous keys had the version bug and TROUBLE_VERSION_BUG_CUR if
 * the current key has it.
 *
 * - Fixing instructions:
 *   - We want to split out a function to add a single object.
 *   - Replace parse tree state with ringIterator.
 *   - Fiddle with trust packets somehow.
 *   - Use the fact that ringFileDoClose gets rid of half-built
 *     keys to simplify the public-key-gathering part.
 * DANGER, WILL ROBINSON: What about running out of memory when creating
 * a new key?  That's one case when it's *not* desirable to close
 * the whole file.  Grumble moan bitch complain...
 *
 * Okay a few cases:
 * - The secret is old, as is the key.
 *   In that case, we're only ZZ
 */
RingFile *
ringFileOpen(RingPool *pool, PGPFile *f, int trusted, PGPError *error)
{
	/* Oy, what a lot of variables! */

	/* The RingFile being opened */
	RingFile *file;
	PGPVirtMask mask;
	unsigned bit;

	/* The current state of the parse tree */
	RingIterator iter;
	union RingObject *obj;

	/* Current packet info */
	int pktbyte;
	PGPSize len, len1, fpos;
	char *buf;		/* Current pktbuf */

	/* Information from selfsig subpackets associated with parent key */
	union RingObject   *sigkeyparent = NULL;
	PGPUInt32				sigkeyvalidity = 0;

	/* Various temporaries */
	int i;			/* Multi-purpose temp */
#if PGPTRUSTMODEL>0
	int j, k;		/* Additional trust packet bytes */
#endif
	PGPByte c;			/* for pgpFileRead */
	size_t size;		/* Return value from pgpFileRead() */
	PGPByte *tp;		/* Pointer to trust byte */
	RingTrouble const *trouble;

	/* Flags */
	int dirty = 0, trustdirty = 0;
	skip_t skip;
	int trustf;		/* 1 for trust, 2 for optional trust */
	int trustmissing;	/* OR of trustf values */

	PGPError err;

	/*
	 * The code starts here
	 */

	if (!f || !pool) {
		*error = kPGPError_NoErr;
		return (RingFile *)NULL;
	}
		
	err = ringBitAlloc(pool, &bit);
	if (IsPGPError(err)) {
		*error = err;
		return NULL;
	}

	pgpVirtMaskInit (pool, &mask);

	/* Make sure enough pool->files entries are allocated */
	ringFilesInit (pool, bit);

	pgpVirtMaskSetBit (pool, &mask, bit);
	file = pool->files[bit];
	pgpAssert(pgpVirtMaskIsEqual (&file->set.mask, &mask));

	pgpVirtMaskOR (pool, &mask, &pool->filemask);
	pgpVirtMaskOR (pool, &mask, &pool->allocmask);

	/* Set this file as the lowest-priority file */
	ringFileLowPri(file);

	pgpAssert(!file->set.next);

	file->f = f;
	file->destructor = NULL;
	file->arg = NULL;
	file->version = PGPVERSION_2;

	/* Start out with a clean slate */
	*error = kPGPError_NoErr;

	/* Initialize a null RingIterator */
	iter.set.pool = pool;
	pgpVirtMaskInit (pool, &iter.set.mask);

	/* There is no current key */
	iter.level = 0;
	/* There is no current packet to give trust to */
	trustf = 0;
	/* No trust is missing, yet */
	trustmissing = 0;
	/* Pay attention to all the packets */
	skip = 0;
	

	/*
	 * The main loop over each packet.
	 */
	while ((pktbyte = pktByteGet(file->f, &len, &len1, &fpos)) > 0) {
		switch (PKTBYTE_TYPE(pktbyte)) {
skipkey:
			skip = SKIP_TO_KEY;
			goto skippkt;
skipname:
			skip = SKIP_SIGS;
			goto skippkt;
skipcrl:
skipunk:
skipsig:
			skip = SKIP_TRUST;
			goto skippkt;
		  default:
			/*
			 * Add it as an unknown object if it's not the first
			 * thing in the keyring...
			 */
			if (!iter.level) {
				i = ringFileLog(file, (union RingObject *)NULL,
					0, fpos, kPGPError_TroubleUnexpectedUnknown);
				if (i < 0)
					goto failed;
				goto skipunk;
			}
			if (len > RINGUNK_MAXLEN) {	/* Too big */
				i = ringFileLog(file, (union RingObject *)NULL,
					len, fpos, kPGPError_TroubleUnknownTooBig);
				if (i < 0)
					goto failed;
				goto skipunk;
			}
			/* Read in the unknown for hashing */
			buf = ringReserve(pool, (size_t)len);
			if (!buf)
				goto fatal;
			size = pktBodyRead(buf, len, len1, file->f);
			if (size != (size_t)len)
				goto readerr;
			pool->pktbuflen = size;

			i = ringAddUnk(file, &iter, fpos, (PGPByte)pktbyte);
			if (i < 0)
				goto failed;
			obj = iter.stack[iter.level-1];
			
			/* Unexpected packet */
			i = ringFileLog(file, obj, pktbyte, fpos, 
			                kPGPError_TroubleUnknownPacketByte);
			if (i < 0)
				goto failed;
			break;
		  case PKTBYTE_COMMENT:
		//BEGIN GPG NEW PACKET COMMENT (#61) SUPPORT - Imad R. Faiad
		  case PKTBYTE_NEWCOMMENT:
		//END GPG NEW PACKET COMMENT (#61) SUPPORT
			/* Silently ignore this packet */
skippkt:
			trustmissing |= trustf;
			trustf = 0;
			dirty = 1;
skiptrust:
			i = pgpFileSeek(file->f, len, SEEK_CUR);
			if (i != 0)
				goto readerr;
			break;

		  case PKTBYTE_PUBKEY:
		  case PKTBYTE_PUBSUBKEY:

			if (iter.level > 0 && PKTBYTE_TYPE(pktbyte) == PKTBYTE_PUBKEY) {
				/* Check validity of previous key */
				i = ringKeyCleanup(file, iter.stack[0], trusted);
				if (i < 0)
					goto failed;
			}

			trustmissing |= trustf;
			trustf = 1;

			if (skip & SKIP_KEY)
				goto skippkt;
			skip = 0;

			/* Check for grossly oversized key */
			if (len > RINGKEY_MAXLEN) {
				i = ringFileLog(file, (union RingObject *)NULL,
					len, fpos, kPGPError_TroubleKeyTooBig);
				if (i < 0)
					goto failed;
				goto skipkey;
			}
			buf = ringReserve(pool, (size_t)len);
			if (!buf)
				goto fatal;
			size = pktBodyRead(buf, len, len1, file->f);
			if (size != (size_t)len)
				goto readerr;
			pool->pktbuflen = size;

			i = ringAddKey(file, &iter, fpos, trusted,
				(PGPByte)PKTBYTE_TYPE(pktbyte));
			if (i < 0)
				goto failed;
			skip = i;
			trustf = 1;

			break;

		  case PKTBYTE_SECKEY:
		  case PKTBYTE_SECSUBKEY:

			if (iter.level > 0 && PKTBYTE_TYPE(pktbyte) == PKTBYTE_SECKEY) {
				/* Check validity of previous key */
				i = ringKeyCleanup(file, iter.stack[0], trusted);
				if (i < 0)
					goto failed;
			}

			trustmissing |= trustf;
			trustf = 1;

			if (skip & SKIP_KEY)
				goto skippkt;
			skip = 0;

			/* Check for grossly oversized key */
			if (len > RINGSEC_MAXLEN) {
				i = ringFileLog(file, (union RingObject *)NULL,
					len, fpos, kPGPError_TroubleKeyTooBig);
				if (i < 0)
					goto failed;
				goto skipkey;
			}
			buf = ringReserve(pool, (size_t)len);
			if (!buf)
				goto fatal;
			size = pktBodyRead(buf, len, len1, file->f);
			if (size != (size_t)len)
				goto readerr;
			pool->pktbuflen = size;

			i = ringAddSec(file, &iter, fpos, (PGPByte)PKTBYTE_TYPE(pktbyte));
			if (i < 0)
				goto failed;
			skip = i;
			trustf = 1;

			break;

		  case PKTBYTE_ATTRIBUTE:
		  case PKTBYTE_NAME:
			trustmissing |= trustf;
			trustf = 1;

			if (skip & SKIP_NAME)
				goto skippkt;
			skip = 0;

			if (iter.level < 1) {
				i = ringFileLog(file, (union RingObject *)NULL,
					0, fpos, kPGPError_TroubleUnexpectedName);
				if (i < 0)
					goto failed;
				goto skipname;
			}
			/* Check for grossly oversized name */
			if (len > RINGNAME_MAXLEN) {
				i = ringFileLog(file, (union RingObject *)NULL,
					len, fpos, kPGPError_TroubleNameTooBig);
				if (i < 0)
					goto failed;
				goto skipname;
			}
			buf = ringReserve(pool, (size_t)len);
			if (!buf)
				goto fatal;
			size = pktBodyRead(buf, len, len1, file->f);
			if (size != (size_t)len)
				goto readerr;
			pool->pktbuflen = size;

			i = ringAddName(file, &iter, fpos,
					  (PGPBoolean)(PKTBYTE_TYPE(pktbyte)==PKTBYTE_ATTRIBUTE));
			if (i < 0)
				goto failed;
			skip = i;

			trustf = 1;

			break;

		  case PKTBYTE_SIG:
			trustmissing |= trustf;
			trustf = 1;
			
			if (skip & SKIP_SIG)
				goto skippkt;
			skip = 0;

			if (iter.level < 1) {	/* No key yet - huh? */
				i = ringFileLog(file, (union RingObject *)NULL,
					0, fpos, kPGPError_TroubleUnexpectedSignature);
				if (i < 0)
					goto failed;
				goto skipsig;
			}
			if (len > RINGSIG_MAXLEN) {	/* Sig too damn big */
				i = ringFileLog(file, (union RingObject *)NULL,
					len, fpos, kPGPError_TroubleSignatureTooBig);
				if (i < 0)
					goto failed;
				goto skipsig;
			}
			/* Read in the signature for future analysis */
			buf = ringReserve(pool, (size_t)len);
			if (!buf)
				goto fatal;
			size = pktBodyRead(buf, len, len1, file->f);
			if (size != (size_t)len)
				goto readerr;
			pool->pktbuflen = size;

			i = ringAddSig(file, &iter, fpos, trusted);
			if (i < 0)
				goto failed;
			skip = i;
			trustf = 1;

			/* We will put these values into the key if sig is valid */
			sigkeyparent = NULL;
			sigkeyvalidity = 0;
			obj = iter.stack[iter.level-1];
			if (i == 0) {
				/* See if a self signature; if so, store some info */
				RingObject *sigowner = obj;   /* top level key above sig */
				RingObject *sigparent = NULL; /* first key above sig */
				/* Find key above sig */
				do {
					sigowner = sigowner->g.up;
					if (OBJISKEY(sigowner) && !sigparent) {
						sigparent = sigowner;
					}
				} while (!OBJISTOPKEY(sigowner));
				if (obj->s.by == sigowner) {
					/* Self signature */
					PGPByte const *pk;
					/* Note that this may alter the contents of buf */
					pk = ringSigFindSubpacket ( (PGPByte *)buf,
						SIGSUB_KEY_EXPIRATION,
						0, NULL, NULL, NULL, NULL, NULL);
					if (pk) {
						PGPUInt32 keyexp;
						keyexp = (PGPUInt32)((unsigned)pk[0]<<8|pk[1]) << 16 |
										((unsigned)pk[2]<<8|pk[3]);
						/* These values will be used later if sig is trusted */
						sigkeyparent = sigparent;
						sigkeyvalidity = (PGPUInt16) (keyexp / (24 * 3600));
					}
				}
			}
			break;

		  case PKTBYTE_CRL:

			trustmissing |= trustf;
			trustf = 1;

			if (skip & SKIP_SIG)
				goto skippkt;
			skip = 0;

			/* Check for grossly oversized crl */
			if (len > RINGCRL_MAXLEN) {
				i = ringFileLog(file, (union RingObject *)NULL,
					len, fpos, kPGPError_TroubleCRLTooBig);
				if (i < 0)
					goto failed;
				goto skipcrl;
			}
			buf = ringReserve(pool, (size_t)len);
			if (!buf)
				goto fatal;
			size = pktBodyRead(buf, len, len1, file->f);
			if (size != (size_t)len)
				goto readerr;
			pool->pktbuflen = size;

			i = ringAddCRL(file, &iter, fpos);
			if (i < 0)
				goto failed;
			skip = i;
			trustf = 1;

			break;

		  case PKTBYTE_TRUST:

			if (!trustf) {
				i = ringFileLog(file, NULL, len, fpos,
				                kPGPError_TroubleUnexpectedTrust);
				if (i < 0)
					goto failed;
				goto skippkt;
			}
			pgpAssert(iter.level);
			trustf = 0;
			if (skip & SKIP_TRUST)
				goto skippkt;
			skip = 0;
			/* If not a trusted keyring, ignore trust packets */
			if (!trusted)
				goto skiptrust;
			obj = iter.stack[iter.level-1];
			if (OBJISSEC(obj)) {
				pgpAssert(iter.level >= 2);
				obj = iter.stack[iter.level-2];
			}
#if PGPTRUSTMODEL==0
			/* Skip bad trust packets */
			if (len != 1) {
				i = ringFileLog(file, obj, len, fpos,
					kPGPError_TroubleBadTrust);
				goto skippkt;
			}
			if (pgpFileRead(&c, 1, file->f) != 1)
				goto readerr;
			i = c & 255;

			/* Set the appropriate flags */
			pgpAssert(!OBJISSEC(obj));
			switch (ringObjectType(obj)) {
			  default:
				pgpAssert(0);
			  case RINGTYPE_KEY:
				tp = &obj->k.trust;
				break;
			  case RINGTYPE_NAME:
				tp = &obj->n.trust;
				break;
			  case RINGTYPE_SIG:
				tp = &obj->s.trust;
				break;
			  case RINGTYPE_CRL:
				tp = &obj->r.trust;
				break;
			  case RINGTYPE_UNK:
				tp = &obj->u.trust;
				break;
			}
			if (obj->g.flags & RINGOBJF_TRUST) {
				if (i != *tp)
					trustdirty = 1;
			} else {
				*tp = (PGPByte)i;
				obj->g.flags |= RINGOBJF_TRUST;
			}
#else /* NEWTRUST */
			if (OBJISNAME(obj)) {
				/*
				 * Name trust packets can be up to 3 bytes
				 * long:
				 * Byte 1: old-style trust packet
				 * Byte 2: validity of name
				 * Byte 3: confidence in name as introducer
				 */
				if (len < 1 || len > 3) {
					i = ringFileLog(file, obj, len,
						fpos, kPGPError_TroubleBadTrust);
					goto skippkt;
				}
				if (pgpFileRead(&c, 1, file->f) != 1)
					goto readerr;
				i = c & 255;
				/* Default trust and validity bytes */
				switch (i & kPGPNameTrust_Mask) {
				  case kPGPNameTrust_Complete:
				     /* j = pool->threshold; */
					j = pool->completeconfidence;
					break;
				  case kPGPNameTrust_Marginal:
				     /* j = pool->threshold/2; */
					j = pool->marginalconfidence;
					break;
				  default:
					j = 0;
					break;
				}
				pgpAssert(OBJISKEY(obj->g.up));
				k = ringTrustOldToExtern(pool, obj->g.up->k.trust);

				if (len > 1) {
				        file->version = PGPVERSION_4;
					/* Fetch validity */
					if (pgpFileRead(&c, 1, file->f) != 1)
						goto readerr;
					j = c & 255;
					if (len > 2) {
						/* Fetch confidence */
						if (pgpFileRead(&c, 1, file->f)
						    != 1)
							goto readerr;
						k = c & 255;
					}
				}
				if (obj->g.flags & RINGOBJF_TRUST) {
					if (i != obj->n.trust
					    || j != obj->n.validity
					    || k != obj->n.confidence
					    || (len == 1) !=
					       !NAMEHASNEWTRUST(&obj->n))
						trustdirty = 1;
				} else {
					obj->n.trust = (PGPByte)i;
					obj->n.validity = (PGPByte)j;
					obj->n.confidence = (PGPByte)k;
					obj->g.flags |= RINGOBJF_TRUST;
					if (len > 1)
						NAMESETNEWTRUST(&obj->n);
					obj->n.valid = ringTrustToIntern ((PGPByte)j);
				}
			} else {	/* Not a name */
				if (len != 1) {
					i = ringFileLog(file, obj, len,
						fpos, kPGPError_TroubleBadTrust);
					goto skippkt;
				}
				if (pgpFileRead(&c, 1, file->f) != 1)
					goto readerr;
				i = c & 255;

				/* Set the appropriate flags */
				pgpAssert(!OBJISSEC(obj));
				switch (ringObjectType(obj)) {
				  default:
					pgpAssert(0);
				  case RINGTYPE_KEY:
					tp = &obj->k.trust;
					break;
				  case RINGTYPE_SIG:
					tp = &obj->s.trust;
					break;
				  case RINGTYPE_CRL:
					tp = &obj->r.trust;
					break;
				  case RINGTYPE_UNK:
					tp = &obj->u.trust;
					break;
				}
				if (obj->g.flags & RINGOBJF_TRUST) {
					if (i != *tp)
						trustdirty = 1;
				} else {
					*tp = (PGPByte)i;
					obj->g.flags |= RINGOBJF_TRUST;
				}
			}
#endif
			/* Handle information from self-signatures */
			if (OBJISSIG(obj) && (obj->s.trust & PGP_SIGTRUSTF_CHECKED) &&
				!(obj->s.trust & PGP_SIGTRUSTF_REVOKEDBYCRL)) {
				if (sigkeyparent) {
					sigkeyparent->k.validity = sigkeyvalidity;
					sigkeyparent = NULL;
					sigkeyvalidity = 0;
				}
			}

			break;
		} /* switch (PKTBYTE_TYPE(pktbyte)) */

	} /* while ((pktbyte = pktByteGet(file->f)) > 0) */

	/* Check validity of final key */
	if (iter.level) {
		i = ringKeyCleanup(file, iter.stack[0], trusted);
		if (i < 0)
			goto failed;
	}

	/* Okay, we're done - handle errors in pktByteGet() and return */
	if (pktbyte < 0) {
		/*
		 * Call it fatal if it was on the first packet.  May not
		 * have been a keyring file at all.
		 */
		if (iter.level == 0) {
			ringErr (file, fpos, (PGPError)pktbyte);
			goto fatal;
		}
		len = (PGPUInt32)errno;	/* Capture before *ANY* libc calls */
ioerror:
		*error = (PGPError)pktbyte;
		i = ringFileLog(file, (union RingObject *)NULL, len,
		                fpos, pktbyte);
		if (i < 0)
			goto failed;
		/* A keyring with errors is *always* dirty */
		dirty = 1;
	}

	/*
	 * Did we get any bad trouble reports?  "Dirty" means that
	 * the result of writing out the RingFile's set will not
 	 * be the same as the original file.  Some troubles don't
	 * have that property.
	 */
	for (trouble = file->trouble; trouble; trouble = trouble->next) {
		if (trouble->type != kPGPError_TroubleVersionBugPrev
		    && trouble->type != kPGPError_TroubleOldSecretKey
		    && trouble->type != kPGPError_TroubleNewSecretKey
		    && trouble->type != kPGPError_TroubleBareKey)
		{
			break;
		}
	}
	if (dirty || trouble)
		ringPoolMarkDirty(pool, &mask);
	if (trusted && (trustdirty || (trustmissing & 1)))
		ringPoolMarkTrustChanged(pool, &mask);

	ringSortKeys(pool);
	ringPoolListSigsBy(pool);
	pgpVirtMaskCleanup (pool, &mask);

	return file;

	/*
	 * Read error: figure out error code and use general error
	 * handler.  Not fatal.
	 */
readerr:
	/* If an error, or neither error nor eof (i.e. unknown), error */
	len = (PGPUInt32)errno;	/* Capture before *ANY* libc cals */
	if (pgpFileError(file->f) || !pgpFileEof(file->f))
		pktbyte = kPGPError_ReadFailed;
	else
		pktbyte = kPGPError_EOF;
	goto ioerror;

	/*
	 * Fatal errors: undo all work in memory, return NULL,
	 * *error is non-zero.
	 */
fatal:
	i = ringPoolError(pool)->error;
failed:			/* Generic fatal entry point, error in "i" */
	*error = (PGPError)i;
	(void)ringFileClose(file);

	pgpVirtMaskCleanup (pool, &mask);
	return NULL;
}

/** Keyring writing (this is a *lot* simpler!) **/

/*
 * Write out the trust packet for an object.
 *
 * This is generally pretty simple, but there are different formats based
 * on the object type and version, and there is a kludge to omit
 * writing out trust on signatures on keys if the signature is good.
 * This is a PGP 2.x compatibility feature, since that chokes if it
 * finds a trust packet on a key signature.
 */
static int
ringCopyTrust(union RingObject const *obj, PGPFile *f,
              PgpVersion version)
{
	char trust[3];
	size_t trustlen = 1;
	int i;

	(void)version;
	switch (ringObjectType(obj)) {
	  case RINGTYPE_KEY:
		trust[0] = (char)obj->k.trust;
		break;
	  case RINGTYPE_SEC:
		trust[0] = (char)obj->g.up->k.trust;
		break;
	  case RINGTYPE_NAME:
		/*
		 * Names have 1 to 3 bytes of trust.  The first byte
		 * is a 2.x-compatible trust byte.  The second is
		 * a validity value (how sure are we that this name
		 * is correct - computed), and the third is a confidence
		 * in the named individual as an introducer.
		 *
		 * Note:  If we are requested to write out a pre-PGP 3.0
		 * keyring, the name validity is not converted back to
		 * an old KEYLEGIT value.  We could do this, but it's 
		 * better that a maintenance pass is run prior to 
		 * using such a keyring.
		 * @@@ Is this really the best way to handle it?
		 */
		trust[0] = (char)obj->n.trust;
#if 0
/* Output only one byte trust packets for backwards compatibility */
#if PGPTRUSTMODEL>0
		if (version >= PGPVERSION_4) {
		        trust[1] = (char)obj->n.validity;
		        trust[2] = (char)obj->n.confidence;
		        trustlen = 3;
		}
#endif
#endif
		break;
	  case RINGTYPE_SIG:
		/*
		 * 2.x compatibility kludge: Don't write trust
		 * on good compromise certificates.  PGP 2.x
		 * maintenance dies (assert fail) if it finds
		 * trust packets on key sigs.
		 */
		trust[0] = (char)obj->s.trust;
		if (/*version < PGPVERSION_4 &&*/
		    OBJISKEY(obj->g.up) && obj->g.up == obj->s.by
		    && obj->s.type == PGP_SIGTYPE_KEY_REVOKE)
			return 0;
		break;
	  case RINGTYPE_CRL:
		trust[0] = (char)obj->r.trust;
		break;
	  default:
		pgpAssert(0);
	}
	i = pktBytePut(f, PKTBYTE_BUILD(PKTBYTE_TRUST, 0), trustlen, NULL);
	if (i < 0)
		return i;
	if (pgpFileWrite(trust, trustlen, f) != trustlen)
		return kPGPError_WriteFailed;
	return 0;
}

/*
 * Copy the packet to the given file.  If "trust" is non-negative,
 * it is appended as a trust packet.  If "file" is non-NULL and the
 * write is successful, the location in that file is listed as a
 * position for the object.
 *
 * This function is careful to not add a FilePos to the object until
 * it is known to be completely written out.
 *
 * If keyobj is non-null, it is a key object corresponding to the secret
 * object we are writing out, and we must set the FilePos for it, too.
 */
static int
ringCopyObject(RingSet const *set, union RingObject *obj,
	union RingObject *keyobj, PGPFile *f, int writetrust,
	PgpVersion version, RingFile *file)
{
	void const *buf;
	PGPSize len, len1;
	int i;
	PGPByte pktbyte;
	long pos = 0;	/* Initialized to suppress warnings */

	static int const pktbytes[RINGTYPE_MAX] = {
		PKTBYTE_BUILD(PKTBYTE_PUBKEY, 1),
		PKTBYTE_BUILD(PKTBYTE_SECKEY, 1),
		PKTBYTE_BUILD(PKTBYTE_NAME, 0),
		PKTBYTE_BUILD(PKTBYTE_SIG, 1),
		PKTBYTE_BUILD(PKTBYTE_CRL, 0)
	};

	buf = ringFetchObject(set, obj, &len);
	if (!buf)
		return ringSetError(set)->error;

	/*  If this is a secret object and it has the version bug,
	    then *do not* fix it on disk.  This ensures that if the
	    packet exists in more than ringFile, the packets remain
	    consistent. We'll always have to check for the bug in
	    the future anyway, so doing this doesn't cause any harm. */
	    
	if (OBJISSEC(obj) && (obj->g.flags & SECF_VERSION_BUG))
	    ((PGPByte *) buf)[0] = PGPVERSION_3;

	if (file) {
		pos = pgpFileTell(f);
		if (pos == -1)
			return kPGPError_FileOpFailed;
	}

	i = ringObjectType(obj);
	pgpAssert(i > 0 && i <= RINGTYPE_MAX);
	if (OBJISSUBKEY(obj))
		pktbyte = PKTBYTE_BUILD(PKTBYTE_PUBSUBKEY, 1);
	else if (OBJISSEC(obj) && OBJISSUBKEY(obj->g.up))
		pktbyte = PKTBYTE_BUILD(PKTBYTE_SECSUBKEY, 1);
	else if (OBJISNAME(obj) && NAMEISATTR(&obj->n))
		pktbyte = PKTBYTE_BUILD_NEW(PKTBYTE_ATTRIBUTE);
	else
		pktbyte = (i == RINGTYPE_UNK) ? obj->u.pktbyte : pktbytes[i-1];

	i = pktBytePut(f, pktbyte, len, &len1);
	if (i < 0)
		return i;
	if (pktBodyWrite(buf, len, len1, f) != len)
		return kPGPError_WriteFailed;
	if (writetrust) {
		i = ringCopyTrust(obj, f, version);
		if (i < 0)
			return i;
	}

	/* All successful - add to file if requested */
	if (file) {
		i = ringAddPos (obj, file, (PGPUInt32)pos);
		if (keyobj && !i)
			i = ringAddPos (keyobj, file, (PGPUInt32)pos);
		return i;
	}
	return 0;
}

	PGPError
ringSetWrite(RingSet const *set, PGPFile *f,
	RingFile **filep, PgpVersion version, int flags)
{
	RingFile *file;
	RingIterator *iter;
	union RingObject *obj, *sec;
	union RingObject *keyobj;
	unsigned level;
	PGPVirtMask mask;
	unsigned bit;
	int i;
	int writetrust;
	RingPool *pool = set->pool;
	PGPBoolean keycrldone = FALSE;
	PGPError err;

	pgpAssert(set);
	pgpAssert(f);

	pgpVirtMaskInit (pool, &mask);

	if (filep) {
		/* Set up a RingFile to add to */
		pgpAssert(f);

		err = ringBitAlloc(set->pool, &bit);
		if (IsPGPError(err)) {
			*filep = (RingFile *)0;
			pgpVirtMaskCleanup (pool, &mask);
			return err;
		}

		/* Make sure enough pool->files entries are allocated */
		ringFilesInit (set->pool, bit);

		file = set->pool->files[bit];
		pgpVirtMaskSetBit (pool, &mask, bit);
		pgpAssert(pgpVirtMaskIsEqual (&file->set.mask, &mask));
		pgpAssert(!pgpVirtMaskIsOverlapping (&pool->filemask, &mask));

		pgpVirtMaskOR (pool, &mask, &pool->filemask);
		pgpVirtMaskOR (pool, &mask, &pool->allocmask);

		/* Set this file as the lowest-priority file */
		ringFileLowPri(file);

		pgpAssert(!file->set.next);

		file->f = f;
		file->destructor = NULL;	/* May be set later */
		file->arg = 0;
		*filep = NULL;	/* For now, to be fixed later */
	} else {
		file = NULL;
	}

	iter = ringIterCreate(set);
	if (!iter) {
		ringFileClose(file);	/* Okay for file to be NULL */
		pgpVirtMaskCleanup (pool, &mask);
		return ringSetError(set)->error;
	}

	/* Okay, the main loop */
	level = 1;
	writetrust = 0;	/* Silence warnings */

	while ((i = ringIterNextObjectAnywhere(iter)) > 0) {
		obj = ringIterCurrentObject(iter, (unsigned)i);
		keyobj = NULL;
		pgpAssert(obj);
		if (OBJISKEY(obj)) {
			writetrust = flags & PGP_RINGSETWRITE_PUBTRUST;
			sec = ringBestSec(set, obj);
			if (sec) {
				keyobj = obj;
				obj = sec;	/* Write out the sec */
				if (OBJISTOP(obj))
					writetrust = flags&PGP_RINGSETWRITE_SECTRUST;
			}
			keycrldone = FALSE;
		} else if (OBJISSEC(obj)) {
			continue;
		} else if (OBJISSIG(obj) && !flags && !SIGISEXPORTABLE(&obj->s)) {
			/* Don't output non-exportable sigs to untrusted sets */
			continue;
		} else if (OBJISCRL(obj)) {
			/* Only output latest CRL per key for a given dist point */
			if( !flags || !ringCRLIsCurrent(set, obj, 0) )
				continue;
		}
		i = ringCopyObject(set, obj, keyobj, f, writetrust, version, file);
		if (i < 0)
			break;
	} /* while ringIternextObjectAnywhere */
	ringIterDestroy(iter);
	
	/*
	 * If we broke out on error, close the output file.  We could leave
	 * the partial file open, as all the pointers that exist are valid.
	 * Is that useful?
	 */
	if (i < 0 && file)
		ringFileClose(file);
	else if (filep)
		*filep = file;

	pgpVirtMaskCleanup (pool, &mask);

	return (PGPError)i;
}


/*
 * Bring an object into the MEMRING.
 */
static int
ringCacheObject(RingSet *set, union RingObject *obj)
{
	PGPByte *buf;
	PGPByte const *pktbuf;
	PGPSize buflen;
	MemPool cut;
	RingFile *file;
	int err;

	/* Do nothing if already there */
	if (pgpVirtMaskIsOverlapping(&obj->g.mask, &set->pool->memringmask)) {
		return 0;
	}
	
	/* Get the object into the pktbuf */
	pktbuf = (PGPByte const *)ringFetchObject (set, obj, &buflen);
	if (!pktbuf) {
		return ringSetError(set)->error;
	}
	
	/* Allocate space in memory ringfile */
	file = set->pool->files[MEMRINGBIT];
	cut = file->strings;
	buf = (PGPByte *)memPoolAlloc(&file->strings, (unsigned)buflen, 1);
	if (!buf) {
		return kPGPError_OutOfMemory;
	}

	/* Copy to memory file buffer */
	pgpCopyMemory( pktbuf, buf, buflen );

	/* Add the FilePos */
	err = ringAddPos(obj, file, (PGPUInt32)buflen);
	if (err < 0) {
		memPoolCutBack(&file->strings, &cut);
		return ringSetError(set)->error;
	}
	ringFilePos(obj, file)->ptr.buf = buf;

	return 0;
}

/*
 * Bring the ancestors of an object into the MEMRING.
 *
 * When we create a new object using the routines below, it is necessary
 * that any parents of the object be brought into the MEMRING.  This is
 * so that we can maintain our global invariant that all of an object's
 * ancestors are in all sets that the object is in.
 */
static int
ringCacheParents (RingSet *set, union RingObject *obj)
{
	int err;

	if (OBJISTOP(obj)) {
		return 0;
	}

	do {
		obj = obj->g.up;
		err = ringCacheObject(set, obj);
		if (err < 0)
			return err;
	} while (!OBJISTOP(obj));
	
	return 0;
}


/*
 *
 * Create a new name in a mutable RingSet.
 *
 */
union RingObject *
ringCreateName(RingSet *dest, union RingObject *key,
	char const *str, size_t len)
{
	RingIterator iter;
	MemPool cut;
	RingFile *file;
	PGPByte *pktbuf, *buf;
	int i;

	pgpAssert(RINGSETISMUTABLE(dest));
	pgpAssert(OBJISKEY(key));
	pgpAssert(pgpIsRingSetMember(dest, key));

	iter.set = *dest;

	if (len >= RINGNAME_MAXLEN) {
		ringSimpleErr(dest->pool, kPGPError_TroubleNameTooBig);
		return NULL;
	}

	pktbuf = (PGPByte *)ringReserve(dest->pool, len);
	if (!pktbuf) {
		ringAllocErr(dest->pool);
		return NULL;
	}

	/* Add to memory file */
	file = dest->pool->files[MEMRINGBIT];
	cut = file->strings;
	/* Allocate an extra byte in buf so we can put a null after name */
	buf = (PGPByte *)memPoolAlloc(&file->strings, (unsigned)len+1, 1);
	if (!buf) {
		ringAllocErr(dest->pool);
		return NULL;
	}

	pgpCopyMemory( str, pktbuf, len );
	dest->pool->pktbuflen = len;
	iter.stack[0] = key;
	iter.level = 1;
	i = ringAddName(file, &iter, (PGPUInt32)len, FALSE);
	pgpAssert(i < 0 || iter.level == 2);	/* error or object created */

	/* ringAddName returns <0 on error, and >0 on duplicate! 
	   Note:  "Duplicate" means it's already on the memring,
	   *not* that it's already on dest.  ringAddName adds
	   it to dest, so we can't easily check to see if it's a 
	   real duplicate. */
	if (i != 0) {
		memPoolCutBack(&file->strings, &cut);
		return i < 0 ? NULL : iter.stack[1]; 
	}

	/* Make sure name's parent key is in the MEMRING too */
	i = ringCacheParents(dest, iter.stack[1]);
	if (i < 0) {
		memPoolCutBack(&file->strings, &cut);
		return NULL;
	}

	/* Okay, success - we can't fail */
	/*
	 * Remember that the memory pool's FilePos pointers are a bit
	 * wierd.  Instead of pos->ptr.next, we have pos->ptr.buf,
	 * a pointer to a buffer holding the object.  And pos->fpos
	 * is the length of the object.  That is already filled in
	 * by ringAddName(), but the ptr->buf needs to be done
	 * explicitly.  (The ringAddName() code is optimized for
	 * the reading-from-a-file case, since that's by far the
	 * most common one.)
	 */
	pgpCopyMemory( str, buf, len );
	buf[len] = '\0';			/* null after name in memory */
	ringFilePos(iter.stack[1], file)->ptr.buf = buf;

	/* Ta-dah! */
	return iter.stack[1];
}

/*
 *
 * Create a new attribute object (variant of Name) in a mutable RingSet.
 *
 */
union RingObject *
ringCreateAttribute(RingSet *dest, union RingObject *key,
					PGPByte attributeType, PGPByte const *data, size_t len)
{
	RingIterator iter;
	MemPool cut;
	RingFile *file;
	PGPByte *pktbuf, *buf;
	PGPSize totallen;
	int i;

	pgpAssert(RINGSETISMUTABLE(dest));
	pgpAssert(OBJISKEY(key));
	pgpAssert(pgpIsRingSetMember(dest, key));

	iter.set = *dest;

	if (len >= RINGNAME_MAXLEN) {
		ringSimpleErr(dest->pool, kPGPError_TroubleNameTooBig);
		return NULL;
	}

	totallen = len + 1;		/* account for attribute type */
	totallen += pktSubpacketByteLen (totallen);

	pktbuf = (PGPByte *)ringReserve(dest->pool, totallen);
	if (!pktbuf) {
		ringAllocErr(dest->pool);
		return NULL;
	}

	/* Add to memory file */
	file = dest->pool->files[MEMRINGBIT];
	cut = file->strings;
	buf = (PGPByte *)memPoolAlloc(&file->strings, totallen, 1);
	if (!buf) {
		ringAllocErr(dest->pool);
		return NULL;
	}

	pktSubpacketCreate (attributeType, data, len, pktbuf);

	/* ringCacheParents corrupts pktbuf, so copy to buf here */
	pgpCopyMemory( pktbuf, buf, totallen );

	dest->pool->pktbuflen = totallen;
	iter.stack[0] = key;
	iter.level = 1;
	i = ringAddName(file, &iter, totallen, TRUE);
	pgpAssert(i < 0 || iter.level == 2);	/* error or object created */

	/* ringAddName returns <0 on error, and >0 on duplicate! 
	   Note:  "Duplicate" means it's already on the memring,
	   *not* that it's already on dest.  ringAddName adds
	   it to dest, so we can't easily check to see if it's a 
	   real duplicate. */
	if (i != 0) {
		memPoolCutBack(&file->strings, &cut);
		return i < 0 ? NULL : iter.stack[1]; 
	}

	/* Make sure name's parent key is in the MEMRING too */
	i = ringCacheParents(dest, iter.stack[1]);
	if (i < 0) {
		memPoolCutBack(&file->strings, &cut);
		return NULL;
	}

	/* Okay, success - we can't fail */
	/*
	 * Remember that the memory pool's FilePos pointers are a bit
	 * wierd.  Instead of pos->ptr.next, we have pos->ptr.buf,
	 * a pointer to a buffer holding the object.  And pos->fpos
	 * is the length of the object.  That is already filled in
	 * by ringAddName(), but the ptr->buf needs to be done
	 * explicitly.  (The ringAddName() code is optimized for
	 * the reading-from-a-file case, since that's by far the
	 * most common one.)
	 */
	ringFilePos(iter.stack[1], file)->ptr.buf = buf;

	/* Ta-dah! */
	return iter.stack[1];
}

/*
 * Create a new signature object in a mutable RingSet.
 */
union RingObject *
ringCreateSig(RingSet *dest, union RingObject *obj,
	PGPByte *sig, size_t siglen)
{
	RingIterator iter;
	MemPool cut;
	RingFile *file;
	union RingObject *newsig;
	PGPByte *pktbuf, *buf;
	int i;

	pgpAssert(RINGSETISMUTABLE(dest));
	pgpAssert(pgpIsRingSetMember(dest, obj));

	iter.set = *dest;
	iter.set.type = RINGSET_ITERATOR; /* kludge for ringIterSeekTo() */

	i = ringIterSeekTo(&iter, obj);
	pgpAssert(i >= 0);

	if (siglen >= RINGSIG_MAXLEN) {
		ringSimpleErr(dest->pool, kPGPError_TroubleSignatureTooBig);
		return NULL;
	}

	pktbuf = (PGPByte *)ringReserve(dest->pool, siglen);
	if (!pktbuf) {
		ringAllocErr(dest->pool);
		return NULL;
	}

	/* Add to memory file */
	file = dest->pool->files[MEMRINGBIT];
	cut = file->strings;
	buf = (PGPByte *)memPoolAlloc(&file->strings, (unsigned)siglen, 1);
	if (!buf) {
		ringAllocErr(dest->pool);
		return NULL;
	}

	pgpCopyMemory( sig, pktbuf, siglen );
	dest->pool->pktbuflen = siglen;
	i = ringAddSig(file, &iter, (PGPUInt32)siglen, 1);
	newsig = iter.stack[iter.level - 1];

	/* ringAddSig returns <0 on error, and >0 on duplicate! */
	if (i != 0) {
		memPoolCutBack(&file->strings, &cut);
		return i < 0 ? NULL : newsig;
	}

	/* Make sure sig's parent objects are in the MEMRING too */
	i = ringCacheParents(dest, newsig);
	if (i < 0) {
		memPoolCutBack(&file->strings, &cut);
		return NULL;
	}

	/* Okay, success - we can't fail */
	/*
	 * Remember that the memory pool's FilePos pointers are a bit
	 * wierd.  Instead of pos->ptr.next, we have pos->ptr.buf,
	 * a pointer to a buffer holding the object.  And pos->fpos
	 * is the length of the object.  That is already filled in
	 * by ringAddName(), but the ptr->buf needs to be done
	 * explicitly.  (The ringAddName() code is optimized for
	 * the reading-from-a-file case, since that's by far the
	 * most common one.)
	 */
	pgpCopyMemory( sig, buf, siglen );
	ringFilePos(newsig, file)->ptr.buf = buf;

	return newsig;
}


/*
 * Create a new CRL object in a mutable RingSet.
 */
union RingObject *
ringCreateCRL(RingSet *dest, union RingObject *obj,
	PGPByte *crl, size_t crllen)
{
	RingIterator iter;
	MemPool cut;
	RingFile *file;
	union RingObject *newcrl;
	PGPByte *pktbuf, *buf;
	int i;

	pgpAssert(RINGSETISMUTABLE(dest));
	pgpAssert(pgpIsRingSetMember(dest, obj));

	iter.set = *dest;
	iter.set.type = RINGSET_ITERATOR; /* kludge for ringIterSeekTo() */

	i = ringIterSeekTo(&iter, obj);
	pgpAssert(i >= 0);

	if (crllen >= RINGCRL_MAXLEN) {
		ringSimpleErr(dest->pool, kPGPError_TroubleCRLTooBig);
		return NULL;
	}

	pktbuf = (PGPByte *)ringReserve(dest->pool, crllen);
	if (!pktbuf) {
		ringAllocErr(dest->pool);
		return NULL;
	}

	/* Add to memory file */
	file = dest->pool->files[MEMRINGBIT];
	cut = file->strings;
	buf = (PGPByte *)memPoolAlloc(&file->strings, (unsigned)crllen, 1);
	if (!buf) {
		ringAllocErr(dest->pool);
		return NULL;
	}

	pgpCopyMemory( crl, pktbuf, crllen );
	dest->pool->pktbuflen = crllen;
	i = ringAddCRL(file, &iter, (PGPUInt32)crllen);
	newcrl = iter.stack[iter.level - 1];

	/* ringAddCRL returns <0 on error, and >0 on duplicate! */
	if (i != 0) {
		memPoolCutBack(&file->strings, &cut);
		return i < 0 ? NULL : newcrl;
	}

	/* Make sure crl's parent objects are in the MEMRING too */
	i = ringCacheParents(dest, newcrl);
	if (i < 0) {
		memPoolCutBack(&file->strings, &cut);
		return NULL;
	}

	/* Okay, success - we can't fail */
	/*
	 * Remember that the memory pool's FilePos pointers are a bit
	 * wierd.  Instead of pos->ptr.next, we have pos->ptr.buf,
	 * a pointer to a buffer holding the object.  And pos->fpos
	 * is the length of the object.  That is already filled in
	 * by ringAddName(), but the ptr->buf needs to be done
	 * explicitly.  (The ringAddName() code is optimized for
	 * the reading-from-a-file case, since that's by far the
	 * most common one.)
	 */
	pgpCopyMemory( crl, buf, crllen );
	ringFilePos(newcrl, file)->ptr.buf = buf;

	return newcrl;
}


/*
 * Create a new public key in a mutable RingSet.  To create a
 * public/secret key pair, use ringCreateSec.  That is normally
 * the routine to use, not this one.
 */
union RingObject *
ringCreateKey(RingSet *dest, union RingObject *parent,
	PGPPubKey const *key, PGPKeySpec const *ks, PGPByte pkalg)
{
	RingIterator iter;
	MemPool cut;
	RingFile *file;
	union RingObject *newkey;
	PGPByte *pktbuf, *buf;
	size_t len, prefixlen;
	PGPByte pkttype;
	int i;

	pgpAssert(RINGSETISMUTABLE(dest));
	
	prefixlen = ringKeyBufferLength(ks, pkalg);
	len = prefixlen + pgpPubKeyBufferLength(key);
	if (len >= RINGKEY_MAXLEN) {
		ringSimpleErr(dest->pool, kPGPError_TroubleKeyTooBig);
		return NULL;
	}

	/* Add to pktbuf for compatibility with other routines */
	pktbuf = (PGPByte *)ringReserve(dest->pool, len);
	if (!pktbuf) {
		ringAllocErr(dest->pool);
		return NULL;
	}

	ringKeyToBuffer(pktbuf, ks, pkalg);
	pgpPubKeyToBuffer(key, pktbuf+prefixlen);
	dest->pool->pktbuflen = len;

	/* Add to memory file as permanent home for data */
	file = dest->pool->files[MEMRINGBIT];
	cut = file->strings;
	buf = (PGPByte *)memPoolAlloc(&file->strings, (unsigned)len, 1);
	if (!buf) {
		ringAllocErr(dest->pool);
		return NULL;
	}
	pgpCopyMemory( pktbuf, buf, len );

	/* Set iter to point at beginning */
	iter.set = *dest;
	if (parent) {
		iter.stack[0] = parent;
		iter.level = 1;
	} else {
		iter.level = 0;
	}
	
	pkttype = parent ? PKTBYTE_PUBSUBKEY : PKTBYTE_PUBKEY;

	i = ringAddKey(file, &iter, (PGPUInt32)len, 1/*trusted*/, pkttype);

	/* ringAddKey returns <0 on error, and >0 on duplicate! */
	pgpAssert(i < 0 || (int)iter.level == 1 + (parent != NULL));

	if (i != 0) {
		memPoolCutBack(&file->strings, &cut);
		return i < 0 ? NULL : iter.stack[1];
	}
	
	/* Set buffer pointer in FilePos */
	newkey = iter.stack[0];
	pgpAssert(OBJISKEY(newkey));
	ringFilePos(newkey, file)->ptr.buf = buf;

	/* Put key into right place in key ring (sorted by keyID) */
	ringSortKeys(file->set.pool);

	return newkey;
}


/*
 * Create a new public/secret keypair.  Return pointer to the RingKey object,
 * which will be followed by a RingSec.
 */
union RingObject *
ringCreateSec(RingSet *dest, union RingObject *parent,
	PGPSecKey const *sec, PGPKeySpec const *ks, PGPByte pkalg)
{
	RingIterator iter;
	MemPool cut;
	RingFile *file;
	union RingObject *newkey, *newsec;
	PGPByte *pktbuf, *buf;
	size_t len, prefixlen;
	PGPByte pkttype;
	int i;

	pgpAssert(RINGSETISMUTABLE(dest));
	
	prefixlen = ringSecBufferLength(ks, pkalg);
	len = prefixlen + pgpSecKeyBufferLength(sec);
	if (len >= RINGSEC_MAXLEN) {
		ringSimpleErr(dest->pool, kPGPError_TroubleSecretKeyTooBig);
		return NULL;
	}

	/* Add to pktbuf for compatibility with other routines */
	pktbuf = (PGPByte *)ringReserve(dest->pool, len);
	if (!pktbuf) {
		ringAllocErr(dest->pool);
		return NULL;
	}

	ringSecToBuffer(pktbuf, ks, pkalg);
	pgpSecKeyToBuffer(sec, pktbuf+prefixlen);
	dest->pool->pktbuflen = len;

	/* Add to memory file as permanent home for data */
	file = dest->pool->files[MEMRINGBIT];
	cut = file->strings;
	buf = (PGPByte *)memPoolAlloc(&file->strings, (unsigned)len, 1);
	if (!buf) {
		ringAllocErr(dest->pool);
		return NULL;
	}
	pgpCopyMemory( pktbuf, buf, len );

	/* Set iter to point at beginning */
	iter.set = *dest;
	if (parent) {
		iter.stack[0] = parent;
		iter.level = 1;
	} else {
		iter.level = 0;
	}

	pkttype = parent ? PKTBYTE_SECSUBKEY : PKTBYTE_SECKEY;

	/*
	 * Clear trouble list so we can distinguish duplicate keys from
	 * duplicate sigs
	 */
	ringFilePurgeTrouble(file);

	/* Create the secret object and the parent key */
	i = ringAddSec(file, &iter, (PGPUInt32)len, pkttype);

	/* ringAddSec returns <0 on error, and >0 on duplicate! */
	pgpAssert(i < 0 || (int)iter.level == 2 + (parent != NULL));

	if (i > 0) {
		RingTrouble const *trouble = ringFileTrouble(file);
		pgpAssert (trouble);
		/*
		 * If this sec was a dup, just return it; if it was
		 * something else it was probably a duplicate key and
		 * so we can ignore it and use the new mempool data
		 */
		if (trouble->type == kPGPError_TroubleDuplicateSecretKey) {
			memPoolCutBack(&file->strings, &cut);
			return iter.stack[1];
		}
	}
	if (i < 0) {
		memPoolCutBack(&file->strings, &cut);
		return NULL;
	}
	
	/* Set buffer pointer in FilePos */
	newkey = iter.stack[iter.level-2];
	pgpAssert(OBJISKEY(newkey));
	newsec = iter.stack[iter.level-1];
	pgpAssert(OBJISSEC(newsec));
	ringFilePos(newkey, file)->ptr.buf = buf;
	ringFilePos(newsec, file)->ptr.buf = buf;
	
	/* Put key into right place in key ring (sorted by keyID) */
	ringSortKeys(file->set.pool);

	return newkey;
}

/*
 * Takes a name and moves it to the front of the list of names on a
 * key.  Normally ringCreateName puts the new name at the end; this can
 * move it up.
 */
int
ringRaiseName(RingSet *dest, union RingObject *name)
{
	union RingObject *key;
	union RingObject **np, **np1;

	/* We use this on ringfiles which are technically not mutable */
	/* But we do it just while reading in so it works OK */
	/*	pgpAssert (RINGSETISMUTABLE(dest)); */
	pgpAssert (OBJISNAME(name));
	pgpAssert (pgpIsRingSetMember(dest, name));
	pgpAssert (!OBJISTOP(name));
	key = name->g.up;
	pgpAssert (OBJISKEY(key));
	
	/* Guaranteed to hit at least one name, ours */
	np = &key->g.down;
	while (!pgpIsRingSetMember(dest, *np)  ||  !OBJISNAME(*np)) {
		np = &(*np)->g.next;
	}

	/* Continue till we hit pointer to our name */
	np1 = np;
	while (*np1 != name)
		np1 = &(*np1)->g.next;

	/* Swap if not already first */
	if (np != np1) {
		*np1 = name->g.next;	/* Delete name from the list */
		name->g.next = *np;	/* Set its tail pointer as *np */
		*np = name;		/* Insert it in new spot */
	}
	return 0;
}


/*
 * Signs an object (and its parents); then deposits the new signature
 * object in place on the set.
 */
	PGPError
ringSignObject(RingSet *set, union RingObject *obj,
	       PGPSigSpec *spec, PGPRandomContext const *rc)
{
	PGPByte *sig;
	int siglen;
	union RingObject *sigobj	= NULL;
	PGPContextRef	cdkContext	= RingSetGetContext( set );
	PGPError		err	= kPGPError_NoErr;

	/*
	 * Force signatures with newer-than-RSA keys to use version 4,
	 * and also if the hash is newer than those supported by PGP 5.0.
	 * A bug in PGP 5.0 won't let it load keyrings using version 2.6 sigs
	 * which have a hash not recognized by it.  
	 * The exception is revocation sigs on top-level keys.  A different
	 * bug in PGP 5.0 won't let it validate V4 sigs on top-level keys.
	 * The only sigs it tries to recognize on top-level keys are revocation
	 * sigs.  So those we leave as V3.
	 *
	 * Now we are also using V4 signatures when signing with an RSA key on
	 * a non-RSA key.  There is no backwards compatibility issue there
	 * so we'd rather move forward with the V4 signatures consistently.
	 */
	if( pgpSigSpecVersion (spec) == PGPVERSION_3 ) {
		PGPSecKey *seckey = pgpSigSpecSeckey (spec);
		PGPByte pkAlg = seckey->pkAlg;
		PGPByte hashtype = pgpSigSpecHashtype (spec);
		PGPByte const *extra = pgpSigSpecExtra (spec, NULL);
		RingObject *topobj = obj;
		while (!OBJISTOP (topobj))
			topobj = topobj->g.up;
		pgpAssert (OBJISTOPKEY(topobj));
		if( ! (extra[0] == PGP_SIGTYPE_KEY_REVOKE && OBJISTOPKEY(obj)) ) {
			if( pkAlg > kPGPPublicKeyAlgorithm_RSA + 2
					|| topobj->k.pkalg > kPGPPublicKeyAlgorithm_RSA + 2)
                    // BEGIN - SHA2 mod - Disastry 
                         //|| hashtype > kPGPHashAlgorithm_RIPEMD160)
                    // END - SHA2 mod
			{
				pgpSigSpecSetVersion( spec, PGPVERSION_4 );
			}
		}
	}

	siglen = pgpMakeSigMaxSize (spec);
	sig = (PGPByte *)pgpContextMemAlloc( cdkContext,
		siglen, kPGPMemoryMgrFlags_Clear);
	if ( IsntNull( sig ) )
	{
		siglen = ringSignObj (sig, set, obj, spec, rc);
		if (siglen < 0)
		{
			pgpContextMemFree( cdkContext, sig);
			return (PGPError)siglen;
		}
		if (!siglen)
		{
			pgpContextMemFree( cdkContext, sig);
			return kPGPError_OutOfMemory;
		}
		sigobj = ringCreateSig (set, obj, sig, siglen);
		sigobj->s.trust = PGP_SIGTRUSTF_CHECKED_TRIED | kPGPKeyTrust_Complete;

		pgpContextMemFree( cdkContext, sig);
	}
	else
	{
		err	= kPGPError_OutOfMemory;
	}
	
	return sigobj ? kPGPError_NoErr : kPGPError_OutOfMemory;
}

/*
 * Given a seckey, two mutable ringsets, and some other information,
 * create the ring objects and put them on the appropriate ringsets.
 * Then self-sign the pubkey.
 */
RingObject *
ringCreateKeypair (PGPEnv const *env, PGPSecKey *seckey,
		   PGPKeySpec *keyspec,
		   char const *name, size_t namelen,
		   PGPRandomContext const *rc,
		   RingSet *pubset, RingSet *secset,
		   RingSet const *rakset, PGPByte rakclass,
		   PGPByte *prefAlg, size_t prefAlgLength,
		   RingSet const *adkset, PGPByte adkclass,
		   PGPError *error)
{
	union RingObject *keyobj=NULL, *nameobj;
	PGPSigSpec *sigspec = NULL;
	RingIterator *rakIter = NULL;
	RingIterator *adkIter = NULL;
	PGPUInt16 validity;
	int keyv4;
	//BEGIN RSAv4 SUPPORT MOD - Disastry
    PGPStringToKeyType s2kType;
	//END RSAv4 SUPPORT MOD

	pgpAssert( error );
	*error = kPGPError_NoErr;

#define CHECKRETVAL(val, err) if (val) { *error = err; goto cleanup; }

	/* SECRET KEY stuff */

	/*
	 * If we ever create V4 RSA keys, rsaSecGenerate must
	 * be updated as well to clear its v3 flag.
	 */
	//BEGIN RSAv4 SUPPORT MOD - Disastry
    seckey->s2ktype(seckey, &s2kType);
	//END RSAv4 SUPPORT MOD
	keyv4 = (seckey->pkAlg > kPGPPublicKeyAlgorithm_RSA + 2)
	        //BEGIN RSAv4 SUPPORT MOD - Disastry
             || (s2kType != kPGPStringToKey_Simple)
	        //END RSAv4 SUPPORT MOD
             ;
	if (keyv4)
		pgpKeySpecSetVersion (keyspec, PGPVERSION_4);
	keyobj = ringCreateSec (secset, NULL, seckey, keyspec, seckey->pkAlg);
	CHECKRETVAL (!keyobj, kPGPError_OutOfMemory);
	pgpAssert(OBJISKEY(keyobj));
	pgpCopyMemory( keyobj->k.keyID, seckey->keyID, sizeof(keyobj->k.keyID) );
	nameobj = ringCreateName (secset, keyobj, name, namelen);
	CHECKRETVAL (!nameobj, kPGPError_OutOfMemory);

	/* PUBLIC KEY stuff */
	*error = (PGPError)ringSetAddObject (pubset, keyobj);
	CHECKRETVAL (*error, *error);
	*error = (PGPError)ringSetAddObject (pubset, nameobj);
	CHECKRETVAL (*error, *error);

	/* Self-Sign the new pubkey */
	if (pgpKeyUse(pgpPkalgByNumber(seckey->pkAlg)) & PGP_PKUSE_SIGN) {
		sigspec = pgpSigSpecCreate (env, seckey,
					    PGP_SIGTYPE_KEY_GENERIC);
		CHECKRETVAL (!sigspec, kPGPError_OutOfMemory);
		if (keyv4) {
			/* New keys self-sign with special info! */
			//BEGIN MORE REASONABLE DEFAULT CIPHERS - Imad R. Faiad
			static PGPByte defaultPrefAlg[] = {kPGPCipherAlgorithm_AES256,
											   kPGPCipherAlgorithm_Twofish256,
											   kPGPCipherAlgorithm_AES192,
											   kPGPCipherAlgorithm_3DES,
											   kPGPCipherAlgorithm_AES128,
											   kPGPCipherAlgorithm_CAST5,
											   kPGPCipherAlgorithm_IDEA,
											   kPGPCipherAlgorithm_BLOWFISH};
			//END MORE REASONABLE DEFAULT CIPHERS
/*Legacy stuff follows
			static PGPByte defaultPrefAlg[] = {kPGPCipherAlgorithm_CAST5,
											   kPGPCipherAlgorithm_IDEA,
//BEGIN MORE CIPHERS SUPPORT - Disastry
//											   kPGPCipherAlgorithm_3DES};
											   kPGPCipherAlgorithm_3DES,
											   kPGPCipherAlgorithm_BLOWFISH,
											   kPGPCipherAlgorithm_AES128,
											   kPGPCipherAlgorithm_AES192,
											   kPGPCipherAlgorithm_AES256,
											   kPGPCipherAlgorithm_Twofish256};
//END MORE CIPHERS SUPPORT*/

			if( IsntNull( prefAlg ) ) {
				pgpSigSpecSetPrefAlgs (sigspec, 0, prefAlg, prefAlgLength);
			} else {
				pgpSigSpecSetPrefAlgs (sigspec, 0, defaultPrefAlg,
									   sizeof(defaultPrefAlg));
			}
			pgpSigSpecSetVersion (sigspec, PGPVERSION_4);
			pgpSigSpecSetPrimaryUserID (sigspec, 0, TRUE);
			if ((validity=pgpKeySpecValidity (keyspec)) != 0) {
				pgpSigSpecSetKeyExpiration (sigspec, 0,
					(PGPUInt32)validity*24*60*60);
				keyobj->k.validity = validity;
			}
			/* Add any additional decryption packets requested */
			if (IsntNull (adkset) ) {
				adkIter = ringIterCreate (adkset);
				if (!adkIter) {
					*error = ringSetError(adkset)->error;
					goto cleanup;
				}
				while (ringIterNextObject (adkIter, 1) > 0) {
					PGPByte adinfo[22];
					RingObject *adkey = ringIterCurrentObject (adkIter, 1);
					adinfo[0] = adkclass;
					adinfo[1] = adkey->k.pkalg;
					ringKeyFingerprint20 (adkset, adkey, adinfo+2);
					*error = pgpSigSpecSetAdditionalRecipientRequest (sigspec,
									0, adinfo, sizeof(adinfo) );
					CHECKRETVAL (*error, *error);
				}
				ringIterDestroy (adkIter);
				adkIter = NULL;
			}
		}
		*error = ringSignObject (pubset, nameobj, sigspec, rc);
		if (IsntPGPError(*error) && keyv4 && IsntNull (rakset)) {
			/* Add any Revocation Authorization Keys requested */
			/* These go in a separate, irrevocable signature on the key */
			pgpSigSpecDestroy (sigspec);
			sigspec = pgpSigSpecCreate (env, seckey,
							PGP_SIGTYPE_KEY_PROPERTY);
			CHECKRETVAL (!sigspec, kPGPError_OutOfMemory);
			rakIter = ringIterCreate (rakset);
			if (!rakIter) {
				*error = ringSetError(rakset)->error;
				goto cleanup;
			}
			while (ringIterNextObject (rakIter, 1) > 0) {
				PGPByte krinfo[22];
				RingObject *krkey = ringIterCurrentObject (rakIter, 1);
				/* Note that rakclass must have 0x80 set to be effective */
				krinfo[0] = rakclass;
				krinfo[1] = krkey->k.pkalg;
				ringKeyFingerprint20 (rakset, krkey, krinfo+2);
				*error = pgpSigSpecSetRevocationKey (sigspec, 0, krinfo,
													 sizeof(krinfo) );
				CHECKRETVAL (*error, *error);
			}
			ringIterDestroy (rakIter);
			rakIter = NULL;
			/* Make this signature non-revocable */
			pgpSigSpecSetRevocable (sigspec, 0, FALSE);
			*error = ringSignObject (pubset, keyobj, sigspec, rc);
		}
	}

	/* This sets both key and name trust */
	ringKeySetAxiomatic(secset, keyobj);

 cleanup:
	if (sigspec)
		pgpSigSpecDestroy (sigspec);
	if (rakIter)
		ringIterDestroy (rakIter);
	if (adkIter)
		ringIterDestroy (adkIter);
	return keyobj;
}


/*
 * Given a seckey, two mutable ringsets, and some other information,
 * create subkey ring objects and put them on the appropriate ringsets.
 * Then sign the pubkey using the master signature key.
 * seckey is the secret key coresponding to the master signature key,
 * subseckey is the secret key to be used for creating the new subkey.
 */
RingObject *
ringCreateSubkeypair (PGPEnv const *env, PGPSecKey *seckey,
	PGPSecKey *subseckey, PGPKeySpec *keyspec,
	PGPRandomContext const *rc,
	RingSet *pubset, RingSet *secset,
	PGPError *error)
{
	union RingObject *keyobj;
	union RingObject *subkeyobj = NULL;
	PGPSigSpec *sigspec = NULL;
	PGPUInt16 validity;
	int keyv4;
	//BEGIN RSAv4 SUPPORT MOD - Disastry
    PGPStringToKeyType s2kType;
	//END RSAv4 SUPPORT MOD

	pgpAssert( error );
	*error = kPGPError_NoErr;

	/*
	 * If we ever create PGPVERSION_4 (aka V4) RSA keys, rsaSecGenerate must
	 * be updated as well to clear its v3 flag.
	 */
	//BEGIN RSAv4 SUPPORT MOD - Disastry
    seckey->s2ktype(seckey, &s2kType);
	//END RSAv4 SUPPORT MOD
	keyv4 = (seckey->pkAlg > kPGPPublicKeyAlgorithm_RSA + 2)
        	//BEGIN RSAv4 SUPPORT MOD - Disastry
             || (s2kType != kPGPStringToKey_Simple)
        	//END RSAv4 SUPPORT MOD
             ;
	if (keyv4)
		pgpKeySpecSetVersion (keyspec, PGPVERSION_4);

	/* Get keyobj for the master key */
	keyobj = ringKeyById8(secset, seckey->pkAlg, seckey->keyID);
	pgpAssert(keyobj);

	/* Create the subkey object on the secret keyring */
	subkeyobj = ringCreateSec (secset, keyobj, subseckey,
				      keyspec, subseckey->pkAlg);
	if (!subkeyobj) {
		*error = kPGPError_OutOfMemory;
		return NULL;
	}
	pgpCopyMemory( subkeyobj->k.keyID, subseckey->keyID,
	       sizeof(subkeyobj->k.keyID) );

	/* Add it to the public keyring */
	*error = (PGPError)ringSetAddObject (pubset, subkeyobj);
	if (*error)
		return NULL;

	/* Sign the encryption key with the master signature key */
	sigspec = pgpSigSpecCreate (env, seckey, PGP_SIGTYPE_KEY_SUBKEY);
	if (!sigspec) {
		*error = kPGPError_OutOfMemory;
		return NULL;
	}
	if (keyv4) {
		/* New keys self-sign with special info */
		if ((validity=pgpKeySpecValidity (keyspec)) != 0) {
			pgpSigSpecSetVersion (sigspec, PGPVERSION_4);
			pgpSigSpecSetKeyExpiration (sigspec, 0,
										(PGPUInt32)validity*24*3600);
			subkeyobj->k.validity = validity;
		}
	}
	*error = ringSignObject (pubset, subkeyobj, sigspec, rc);
	if (*error)
		goto cleanup;
	ringKeySetAxiomatic(secset, subkeyobj);

cleanup:

	if (sigspec)
		pgpSigSpecDestroy (sigspec);

	return subkeyobj;		/* success */
}
