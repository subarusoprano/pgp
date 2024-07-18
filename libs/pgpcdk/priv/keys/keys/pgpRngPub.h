/*
 * $Id: pgpRngPub.h,v 1.58 1999/05/27 18:43:37 hal Exp $
 */

#ifndef Included_pgpRngPub_h
#define Included_pgpRngPub_h
/* Public */

#include "pgpUsuals.h"
#include "pgpContext.h"		/* for PGPContextRef */

PGP_BEGIN_C_DECLARATIONS

typedef enum {
	PGPTRUST0=0, PGPTRUST1, PGPTRUST2
} PgpTrustModel;

/* Signature subpacket types.  Many of these are not supported yet. */
enum sigsubbyte {
	/* Signature specific properties */
	SIGSUB_VERSION			= 1,
	SIGSUB_CREATION,
	SIGSUB_EXPIRATION,
	SIGSUB_EXPORTABLE,
	SIGSUB_TRUST,
	SIGSUB_REGEXP,
	SIGSUB_REVOCABLE,
	/* Properties of key being self signed */
	SIGSUB_KEY_CAPABILITIES = 8,
	SIGSUB_KEY_EXPIRATION,
	SIGSUB_KEY_ADDITIONAL_RECIPIENT_REQUEST,
	SIGSUB_PREFERRED_ENCRYPTION_ALGS,
	SIGSUB_KEY_REVOCATION_KEY,
	/* Hints to find signer */
	SIGSUB_KEYID			= 16,
	SIGSUB_USERID,
	SIGSUB_URL,
	SIGSUB_FINGER,
	/* Miscellaneous packets */
	SIGSUB_NOTATION			= 20,
	SIGSUB_PREFERRED_HASH_ALGS,
	SIGSUB_PREFERRED_COMPRESSION_ALGS,
	SIGSUB_KEYSERVER_PREFERENCES,
	SIGSUB_PREFERRED_KEYSERVER,
	SIGSUB_PRIMARY_USERID,
	SIGSUB_POLICY_URL,
	SIGSUB_KEYFLAGS,
	SIGSUB_SIGNER_USERID	= 28,
	SIGSUB_REVOCATION_REASON,
	/* 100-110 are for private use */
	/* Reserve 100 for internal Network Associates use */
	SIGSUB_NAI				= 100,
	/* Used internally for unrecognized packet types */
	SIGSUB_UNRECOGNIZED		= 255	/* crit bit is ignored here */
};

/* Critical bit means we must handle this subpacket */
#define SIGSUBF_CRITICAL	0x80

/* Flag bits within SIGSUB_KEYFLAGS */
#define SIGSUBF_KEYFLAG0_USAGE_CERTIFY			0x01
#define SIGSUBF_KEYFLAG0_USAGE_SIGN				0x02
#define SIGSUBF_KEYFLAG0_USAGE_ENCRYPT_COMM		0x04
#define SIGSUBF_KEYFLAG0_USAGE_ENCRYPT_STORAGE	0x08
/* Meaningful only on self signature */
#define SIGSUBF_KEYFLAG0_PRIVATE_SPLIT			0x10
#define SIGSUBF_KEYFLAG0_PRIVATE_SHARED			0x80

/* Flag bits within SIGSUB_KEYSERVER_PREFERENCES */
#define SIGSUBF_KEYSERVER0_

/* Signature sub-subpacket types, within SIGSUB_NAI packets */
enum sigsubsubbyte {
	SIGSUBSUB_X509			= 1
};

/* Version of X509 translation code */
#define SIGSUBSUB_X509_VERSION_HI	0x01
#define SIGSUBSUB_X509_VERSION_LO	0x04


#include "pgpOpaqueStructs.h"

/*
 * Okay, finally we start the function declarations.
 */
RingPool  *ringPoolCreate(PGPEnv const *env);
/* Destroy everything immediately, dropping all locks! */
void  ringPoolDestroy(RingPool *);
PGPContextRef ringPoolContext(RingPool *pool);

struct RingError
{
	RingFile *	f;	/* The RingFile for I/O errors */
	PGPUInt32	fpos;	/* The file position for I/O errors */
	PGPError	error;	/* PGP error code - kPGPError_* */
	int			syserrno;	/* Don't use plain "errno"; that's a macro! */
};

RingError const  *ringPoolError(RingPool const *);
void  ringPoolClearError(RingPool *);

/*
 * A RingSet is the root of a tree of objects.  The RingSet itself
 * is not a RingObject, but everything else under it is.
 * A full tree looks basically like this:
 * RingSet
 *  +--Key
 *  |   +--Secret (0 or more)
 *  |   +--Signature (0 or more)
 *  |   +--Signature (0 or more)
 *  |   +--Name (0 or more)
 *  |   |   +--Signature (0 or more)
 *  |   |   \--Signature (0 or more)
 *  |   \--Name (0 or more)
 *  |       \--Signature (0 or more)
 *  +--Key
 *  |   +--etc.
 * etc.
 *
 * A "secret" object is present if the key's secret components are
 * available.  In the standard PGP keyring file format, this is
 * actually stored with the key as a different type of key packet,
 * but the representation here is logically equivalent.
 *
 * There is one secret object per encrypted form of the secret
 * components.  Barring duplicate key errors, there is only one
 * secret object per file (if you attempt to write out more, the
 * library will make a guess at the best and write that out), but,
 * for example, changing the passphrase will create a second secret.
 *
 * Some sets are mutable, and RingObjects can be added to or deleted from
 * them, but the tree property is always preserved.  Adding an object
 * implicitly adds all of its parents.  Deleting an object implicitly
 * deletes all of its children.
 */
int  ringObjectType(union RingObject const *obj);
/* Type 0 is reserved for application use; it will never be allocated */
#define RINGTYPE_KEY	1
#define RINGTYPE_SEC	2
#define RINGTYPE_NAME	3
#define RINGTYPE_SIG	4
#define RINGTYPE_CRL	5
#define RINGTYPE_UNK	6	/* Object of unknown type */
#define RINGTYPE_MAX	6
/* Adding a new type needs to update ringObjectType() and ringNewObject() */

/*
 * Increase and decrease RingObject reference counts.  The ringIter
 * functions hold their current objects (at the current level and all
 * parent levels) automatically and release them when the ringIterator is
 * advanced to another location.  If you wish to refer to them after
 * advancing the RingIterator, Other functions that return RingObject
 * pointers hold them automatically, and they must be released explicitly
 * by ringObjectRelease().
 */
void  ringObjectHold(union RingObject *obj);
void  ringObjectRelease(union RingObject *obj);

/* Operations on RingSets */

RingPool  *ringSetPool(RingSet const *);

RingError const  *ringSetError(RingSet const *);
void  ringSetClearError(RingSet *);

int  ringSetIsMember(RingSet const *set,
	union RingObject const *object);
int  ringSetCount(RingSet const *set, unsigned *counts,
	unsigned depth);
int  ringSetCountTypes(RingSet const *set, unsigned *counts,
	unsigned max);

/* Create a new mutable RingSet */
RingSet  *ringSetCreate(RingPool *pool);
/* Create the universal RingSet */
RingSet  *ringSetCreateUniversal(RingPool *pool);
/* Free a RingSet (mutable or immutable) */
void  ringSetDestroy(RingSet *set);

/* Operate on a mutable RingSet */
int  ringSetAddObject(RingSet *set, union RingObject *obj);
int  ringSetRemObject(RingSet *set, union RingObject *obj);
int  ringSetAddSet(RingSet *set, RingSet const *set2);
int  ringSetSubtractSet(RingSet *set,
	RingSet const *set2);
int  ringSetAddObjectChildren(RingSet *dest,
	RingSet const *src, union RingObject *obj);
/* Convert a mutable RingSet to immutable */
PGPError  ringSetFreeze(RingSet *set);

/* Operate on immutable RingSets */
RingSet  *ringSetCopy(RingSet const *s);
RingSet  *
ringSetUnion(RingSet const *s1, RingSet const *s2);
RingSet  *
ringSetIntersection(RingSet const *s1, RingSet const *s2);
RingSet  *
ringSetDifference(RingSet const *s1, RingSet const *s2);

/* Lookups by keyID */
union RingObject  *
ringKeyById4(RingSet const *set, PGPByte pkalg, PGPByte const *keyid);
union RingObject  *
ringKeyById8(RingSet const *set, PGPByte pkalg, PGPByte const *keyid);

/* Operations on RingIterators */

RingIterator  *ringIterCreate(RingSet const *set);
void  ringIterDestroy(RingIterator *iter);
RingSet const  *ringIterSet(RingIterator const *iter);
RingError const  *ringIterError(
	RingIterator const *iter);
void  ringIterClearError(RingIterator *iter);
int  ringIterNextObject(RingIterator *iter, unsigned level);
int  ringIterPrevObject(RingIterator *iter, unsigned level);
unsigned  ringIterCurrentLevel(RingIterator const *iter);
union RingObject  *ringIterCurrentObject(
	RingIterator const *iter, unsigned level);

int  ringIterNextObjectAnywhere(RingIterator *iter);
int  ringIterRewind(RingIterator *iter, unsigned level);
int  ringIterFastForward(RingIterator *iter, unsigned level);
int  ringIterSeekTo(RingIterator *iter, union RingObject *obj);

/* RingFile access functions */

struct PGPFile  *ringFileFile(RingFile const *file);
RingSet const  *ringFileSet(RingFile const *file);
PgpVersion  ringFileVersion(RingFile const *file);

int  ringFileIsDirty(RingFile const *file);
int  ringFileIsTrustChanged(RingFile const *file);

PGPError  ringFileSwitchFile(RingFile *file, struct PGPFile *newPGPFile);

/* Alias for ringSetError(ringFileSet(file)) */
RingError const  *ringFileError(RingFile const *file);
void  ringFileClearError(RingFile *file);

int 
ringSetFilter(RingSet const *src, RingSet *dest,
              int (*predicate)(void *arg, RingIterator *iter,
                               union RingObject *object, unsigned level),
              void *arg);
int  ringSetFilterSpec(RingSet const *src,
	RingSet *dest, char const *string, int use);

union RingObject  *
ringLatestSecret(RingSet const *set, char const *string, PGPUInt32 tstamp,
	int use);


/* Object access functions */

PgpTrustModel  pgpTrustModel(RingPool const *pool);
int  ringKeyError(RingSet const *set, union RingObject *key);
unsigned  ringKeyBits(RingSet const *set,
	union RingObject *key);
PGPUInt32  ringKeyCreation(RingSet const *set,
	union RingObject *key);
PGPUInt32  ringKeyExpiration(RingSet const *set,
	union RingObject *key);
void  ringKeyID4(RingSet const *set,
	union RingObject const *key, PGPByte *pkalg, PGPKeyID *keyID);
void  ringKeyID8(RingSet const *set,
	union RingObject const *key, PGPByte *pkalg, PGPKeyID *keyID);
PGPBoolean ringKeyV3(RingSet const *set, union RingObject const *key);
//BEGIN DECRYPT WITH REVOKED SUBKEYS - Imad R. Faiad
//int  ringKeyUseInternal(RingSet const *set, union RingObject *key,
//	PGPBoolean unExpired);
//#define ringKeyUse(s,k)					ringKeyUseInternal(s,k,FALSE)
//#define ringKeyUnexpiredUse(s,k)		ringKeyUseInternal(s,k,TRUE)

int  ringKeyUseInternal(RingSet const *set, union RingObject *key,
	PGPBoolean unExpired, PGPBoolean revokedOK);
#define ringKeyUse(s,k)					ringKeyUseInternal(s,k,FALSE,FALSE)
#define ringKeyUnexpiredUse(s,k)		ringKeyUseInternal(s,k,TRUE,FALSE)
#define ringKeyUseRevokedOK(s,k)		ringKeyUseInternal(s,k,FALSE,TRUE)
//END DECRYPT WITH REVOKED SUBKEYS
PGPByte  ringKeyTrust(RingSet const *set, union RingObject *key);
void  ringKeySetTrust(RingSet const *set,
	union RingObject *key, PGPByte trust);
int  ringKeyDisabled(RingSet const *set,
	union RingObject *key);
void  ringKeyDisable(RingSet const *set,
	union RingObject *key);
void  ringKeyEnable(RingSet const *set,
	union RingObject *key);
int  ringKeyRevoked(RingSet const *set,
	union RingObject *key);
void  ringKeySetAxiomatic(RingSet const *set,
	union RingObject *key);
void  ringKeyResetAxiomatic(RingSet const *set,
	union RingObject *key);
int  ringKeyAxiomatic(RingSet const *set,
	union RingObject *key);
int  ringKeyIsSubkey(RingSet const *set,
	union RingObject const *key);

int  ringKeyFingerprint16(RingSet const *set,
	union RingObject *key, PGPByte *buf);
int  ringKeyFingerprint20(RingSet const *set,
	union RingObject *key, PGPByte *buf);
int  ringKeyFingerprint20n(RingSet const *set,
	union RingObject *key, PGPByte *buf);
int  ringKeyAddSigsby(RingSet const *set,
	union RingObject *key, RingSet *dest);

/* Given a Ring Object, obtain a PGPPubKey or a PGPSecKey */
int  ringKeyIsSec(RingSet const *set, union RingObject *key);
int  ringKeyIsSecOnly(RingSet const *set,
				union RingObject *key);
union RingObject  *ringKeySubkey(RingSet const *set,
				union RingObject const *key);
union RingObject  *ringKeyMasterkey(RingSet const *set,
				union RingObject const *subkey);
PGPPubKey  *ringKeyPubKey(RingSet const *set,
				union RingObject *key, int use);
PGPSecKey  *ringSecSecKey(RingSet const *set,
				union RingObject *sec, int use);
union RingObject *ringBestSec(RingSet const *set,
	union RingObject const *key);
PgpVersion  ringSecVersion (RingSet const *set,
				union RingObject *sec);

RingObject *ringLatestSigByKey (RingObject const *obj, RingSet const *set,
	RingObject const *key);

char const  *ringNameName(RingSet const *set,
	union RingObject *name, PGPSize *lenp);
PGPBoolean ringNameIsAttribute(RingSet const *set, union RingObject *name);
PGPUInt32 ringNameCountAttributes(RingSet const *set, union RingObject *name);
PGPByte const *ringNameAttributeSubpacket(RingObject *name, RingSet const *set,
	PGPUInt32 nth, PGPUInt32 *subpacktype, PGPSize *plen, PGPError *error);
RingObject * ringKeyPrimaryName (RingObject *key, RingSet const *set,
	PGPUInt32 type);
PGPByte  ringNameTrust(RingSet const *set,
	union RingObject *name);
int  ringNameWarnonly(RingSet const *set,
	union RingObject *name);
void  ringNameSetWarnonly(RingSet const *set,
	union RingObject *name);

int  ringSigError(RingSet const *set, union RingObject *sig);
union RingObject  *ringSigMaker(RingSet const *sset,
	union RingObject *sig, RingSet const *kset);
void  ringSigID8(RingSet const *set,
	union RingObject const *sig, PGPByte *pkalg, PGPKeyID *buf);
PGPByte  ringSigTrust(RingSet const *set, union RingObject *sig);
PGPByte  ringSigTrustLevel(RingSet const *set, union RingObject const *sig);
PGPByte  ringSigTrustValue(RingSet const *set, union RingObject const *sig);
//BEGIN SHOW SIGNATURE HASH ALGORITHM - Disastry
PGPByte  ringSigHashAlg(RingSet const *set, union RingObject const *sig);
//END SHOW SIGNATURE HASH ALGORITHM
int  ringSigChecked(RingSet const *set, union RingObject const *sig);
int  ringSigTried(RingSet const *set, union RingObject const *sig);
int  ringSigType(RingSet const *Set, union RingObject const *sig);
PGPUInt32  ringSigTimestamp(RingSet const *Set, union RingObject const *sig);
PGPUInt32  ringSigExpiration(RingSet const *set, union RingObject const *sig);
int  ringSigRevoked (RingSet const *set, union RingObject *sig);
int	ringSigExportable (RingSet const *set, union RingObject const *sig);
PGPBoolean ringSigIsSelfSig(RingSet const *set, RingObject const *sig);
PGPBoolean ringSigIsX509(RingSet const *set, RingObject const *sig);
PGPByte *ringSigX509Certificate(RingSet const *set, RingObject *sig,
   PGPSize *len);

int ringCRLChecked(RingSet const *set, union RingObject const *crl);
int ringCRLTried(RingSet const *set, union RingObject const *crl);
PGPUInt32 ringCRLCreation(RingSet const *set, union RingObject const *crl);
PGPUInt32 ringCRLExpiration(RingSet const *set, union RingObject const *crl);
PGPBoolean ringCRLIsCurrent (RingSet const *set, RingObject *crl,
	PGPUInt32 tstamp);
RingObject * ringKeyEarliestCRL(RingSet const *set, RingObject *key,
	PGPBoolean expiration);
RingObject * ringKeyNthCRL(RingSet const *set, RingObject *key, PGPUInt32 n,
	PGPUInt32 *crlcount);
PGPBoolean ringKeyHasCRL(RingSet const *set, RingObject *key);
PGPByte const * ringCRLDistributionPoint( RingSet const *set, RingObject *crl,
	PGPSize *len );
PGPError ringListCRLDistributionPoints(PGPMemoryMgrRef mgr, RingObject *key,
	RingSet const *set, PGPUInt32 *pnDistPoints, PGPByte **pbuf,
	PGPSize **pbufsizes);


/* Only valid if PgpTrustModel > PGPTRUST0 */
PGPUInt16  ringKeyConfidence(RingSet const *set,
	union RingObject *key);
PGPUInt16  ringNameValidity(RingSet const *set,
	union RingObject *name);
PGPUInt16  ringNameConfidence(RingSet const *set,
	union RingObject *name);
int  ringNameConfidenceUndefined(RingSet const *set, 
				union RingObject *name);
void  ringNameSetConfidence(RingSet const *set, 
			     union RingObject *name, PGPUInt16 confidence);
PGPUInt16  ringSigConfidence(RingSet const *set,
	union RingObject *sig);

PGPByte const  *
ringKeyFindSubpacket (RingObject *obj, RingSet const *set,
	int subpacktype, unsigned nth,
	PGPSize *plen, int *pcritical, int *phashed, PGPUInt32 *pcreation,
	unsigned *pmatches, PGPError *error);
union RingObject  *
ringKeyAdditionalRecipientRequestKey (RingObject *obj, RingSet const *set,
					unsigned nth, PGPByte *pkalg, PGPKeyID *keyid,
					PGPByte *pclass, unsigned *pkeys, PGPError *error);
union RingObject  *
ringKeyRevocationKey (union RingObject *obj, RingSet const *set, unsigned nth,
					PGPByte *pkalg, PGPKeyID *keyid,
					PGPByte *pclass, unsigned *pkeys, PGPError *error);
PGPBoolean
ringKeyIsRevocationKey (RingObject *key, RingSet const *set,
					RingObject *rkey);
PGPBoolean
ringKeyHasThirdPartyRevocation (RingObject *obj, RingSet const *set,
					RingObject **revkey, PGPByte *pkalg, PGPKeyID *keyid,
					PGPError *error);
PGPSigSpec *
ringSigSigSpec (RingObject *sig, RingSet const *set,
					PGPError *error);

PGPBoolean
ringSetHasExpiringObjects( RingSet const *set, PGPTime time1, PGPTime time2 );

void ringPoolConsistent (RingPool *pool, int *pnsets,
	int *pnfiles);


PGP_END_C_DECLARATIONS

#endif /* Included_pgpRngPub_h */
