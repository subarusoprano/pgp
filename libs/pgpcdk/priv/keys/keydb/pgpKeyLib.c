/*
 * pgpKeyLib.c
 * Initialization and cleanup functions related to the keydb library
 *
 * Copyright (C) 1996,1997 Network Associates Inc. and affiliated companies.
 * All rights reserved
 *
 * $Id: pgpKeyLib.c,v 1.134.2.1 1999/06/11 00:30:38 heller Exp $
 */

#include "pgpConfig.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif


#include "pgpContext.h"
#include "pgpKeyDB.h"
#include "pgpDebug.h"
#include "pgpKDBInt.h"
#include "pgpEncodePriv.h"
#include "pgpEnv.h"
#include "pgpErrors.h"
#include "pgpFileNames.h"
#include "pgpFileRef.h"
#include "pgpFileSpec.h"
#include "pgpPipeline.h"
#include "pgpRandomX9_17.h"
#include "pgpRandomPoolPriv.h"
#include "pgpRndSeed.h"
#include "pgpRngRead.h"
#include "pgpSigSpec.h"
#include "pgpTimeDate.h"
#include "pgpTrstPkt.h"
#include "pgpSDKPrefs.h"
#include "pgpOptionList.h"
#include "pgpUtilitiesPriv.h"
#include "pgpX509Priv.h"


#if PGP_MACINTOSH
#include "MacStrings.h"
#include "MacFiles.h"
#endif


#include "pgpDEBUGStartup.h"

#define elemsof(x) ((unsigned)(sizeof(x)/sizeof(*x)))



/* See if the newly opened keyring appears to needs sig checking */
	static PGPError
sIsSigCheckNeeded( PGPKeySetRef set, PGPBoolean *sigCheckNeeded )
{
	RingSet const *		rset;
	RingIterator *		riter;
	int					level;
	PGPBoolean			needSigCheck;

	*sigCheckNeeded = FALSE;
	needSigCheck = FALSE;

	rset = pgpKeyDBRingSet( set->keyDB );
	riter = ringIterCreate( rset );
	if ( !riter )
		return ringSetError( rset )->error;

	/*
	 * We look for a key with a revocation signature which has not
	 * been tried, such that the key's revoke bit is not set.  This is
	 * how some old version of PGP leave revocations.  We always set the
	 * key's revocation bit in the file, so this will not happen with
	 * keyrings written by this library.
	 */
	while ( (level = ringIterNextObjectAnywhere( riter ) ) > 0 )
	{
		if ( level == 2 )
		{
			RingObject *obj = ringIterCurrentObject( riter, level );
			if ( ringObjectType( obj ) == RINGTYPE_SIG  &&
				 ringSigType( rset, obj ) == PGP_SIGTYPE_KEY_REVOKE &&
				 ringSigTrust( rset, obj ) == PGP_SIGTRUST_UNTRIED )
			 {
				RingObject *parent = ringIterCurrentObject( riter, level - 1 );
				if ( ringObjectType( parent ) == RINGTYPE_KEY &&
					 !ringKeyRevoked( rset, parent ) )
				{
					/* Here we have our case we are looking for */
					needSigCheck = TRUE;
					break;
				}
			}
		}
	}
	ringIterDestroy( riter );

	*sigCheckNeeded = needSigCheck;
	return kPGPError_NoErr;
}

	static PGPError
pgpGetDefaultRingFileRefs(
	PGPContextRef	cdkContext,
	PFLFileSpecRef		*pubRefOut,
	PFLFileSpecRef		*privRefOut )
{
	PGPError		err = kPGPError_NoErr;

	/* set outputs to default */
	if ( IsntNull( privRefOut ) )
		*privRefOut = NULL;
	if ( IsntNull( pubRefOut ) )
		*pubRefOut = NULL;
		
	/* load preferences if not already loaded */
	if ( IsNull( pgpContextGetPrefs( cdkContext ) ) )
	{
		err	= PGPsdkLoadDefaultPrefs( cdkContext );
	}
	
	if ( IsntPGPError( err ) )
	{
		if ( IsntNull( privRefOut ) )
		{
			err = PGPsdkPrefGetFileSpec( cdkContext,
				kPGPsdkPref_PrivateKeyring, (PGPFileSpecRef *)privRefOut);
		}

		if ( IsntPGPError( err ) && IsntNull( pubRefOut ) )
		{
			err = PGPsdkPrefGetFileSpec( cdkContext,
				kPGPsdkPref_PublicKeyring, (PGPFileSpecRef *)pubRefOut);
			if ( IsPGPError( err ) )
			{
				PFLFreeFileSpec( *privRefOut );
				*privRefOut	= NULL;
			}
		}
	}
	
	return err;
}

//BEGIN FLOPPY PROMPT FIX - Imad R. Faiad
static BOOL	sPromptUser = TRUE;
//END FLOPPY PROMPT FIX

/*
 * Open default keyrings for user, return keyset for it.
 * If isMutable is false, keyrings are read only.
 */
	PGPError
PGPOpenDefaultKeyRings(
	PGPContextRef		cdkContext,
	PGPKeyRingOpenFlags	openFlags,
	PGPKeySetRef *		keySetOut )
{
	PFLFileSpecRef	secFileRef = NULL;	/* File reference for secret keyring */
	PFLFileSpecRef	pubFileRef = NULL;	/* File reference for public keyring */
	PGPError		err = kPGPError_NoErr;
	PGPKeySetRef	set	= NULL;

	//BEGIN FLOPPY PROMPT FIX - Imad R. Faiad
//#undef MYGUI
#ifdef MYGUI
	LPSTR	lpsz;
 	CHAR sztmp[3];
#endif
	//END FLOPPY PROMPT FIX

	PGPValidatePtr( keySetOut );
	*keySetOut	= NULL;
	PGPValidateContext( cdkContext );

	err	= pgpGetDefaultRingFileRefs( cdkContext, &pubFileRef, &secFileRef);
	if ( IsntPGPError( err ) )
	{
		//BEGIN FLOPPY PROMPT FIX - Imad R. Faiad
#ifdef MYGUI
 		if (sPromptUser){
 
 			sPromptUser = FALSE;
 
 			PGPGetFullPathFromFileSpec ((PGPFileSpecRef)secFileRef,&lpsz);
 			lstrcpyn (sztmp, lpsz, 3);
 			PGPFreeData (lpsz);
 
 			if ((sztmp[0] == 'A') || (sztmp[0] == 'a')
				 || (sztmp[0] == 'B') || (sztmp[0] == 'b')) {
 				MessageBox(NULL, 
 				"Please insert your Keyrings floppy into the diskette drive\nclick ok when done",
 				"Insert Floppy Alert",MB_OK);	
 			}
 		}
#endif
 		//END FLOPPY PROMPT FIX
		pgpAssert( IsntNull( pubFileRef ) );
		pgpAssert( IsntNull( secFileRef ) );
		
		err = PGPOpenKeyRingPair(cdkContext, openFlags,
					(PGPFileSpecRef)pubFileRef,
					(PGPFileSpecRef)secFileRef, &set);
			
		PFLFreeFileSpec( secFileRef );
		PFLFreeFileSpec( pubFileRef );
	}
		
	if ( IsPGPError( err ) && IsntNull( set ) )
	{
		PGPFreeKeySet( set );
		set	= NULL;
	}
	
	*keySetOut	= set;
	pgpAssertErrWithPtr( err, *keySetOut );
	return err;
}

/*
 * Open the specified keyrings for user, return keyset for it.
 * If isMutable is false, keyrings are read only.
 */
	PGPError
PGPOpenKeyRingPair(
	PGPContextRef		cdkContext,
	PGPKeyRingOpenFlags	openFlags,
	PGPFileSpecRef		pubFileRefIn,
	PGPFileSpecRef		privFileRefIn,
	PGPKeySetRef *		keySetOut )
{
	PGPKeyDB	   *dbsec = NULL,		/* KeyDB for secret keyring */
				   *dbpub = NULL,		/* KeyDB for public keyring */
				   *dbunion = NULL;		/* KeyDB for union of both keyrings */
	RingPool	   *pgpRingPool;		/* RingPool from cdkContext */
	PGPKeySet	   *set = NULL;
	PGPBoolean		sigCheckNeeded;
	PGPError		err;
	PFLFileSpecRef	pubFileRef	= (PFLFileSpecRef)pubFileRefIn;
	PFLFileSpecRef	privFileRef	= (PFLFileSpecRef)privFileRefIn;
	PFLFileInfo		pubFileInfo;
	PGPTime			curTime, pubModTime;

	PGPValidatePtr( keySetOut );
	*keySetOut	= NULL;
	PGPValidateContext( cdkContext );
	PFLValidateFileSpec( pubFileRef );
	PFLValidateFileSpec( privFileRef );
	
	pgpAssert( (openFlags & kPGPKeyRingOpenFlags_Reserved) == 0 );
	pgpAssert(0 == (openFlags & (kPGPKeyRingOpenFlags_Private |
								 kPGPKeyRingOpenFlags_Trusted)));

	pgpRingPool = pgpContextGetRingPool( cdkContext );

	/*
	 * Check creation time of pub file so we can check for objects
	 * expired since then.
	 */
	err = PFLGetFileInfo( pubFileRef, &pubFileInfo );
	if( IsPGPError( err ) )
	{
		err = kPGPError_NoErr;
		pubModTime = 0UL;
	} else {
		pubModTime = PGPGetPGPTimeFromStdTime( pubFileInfo.modificationTime );
	}

	/* Create key databases for these files.  Don't bother with keypool. 
	   Private keyring is not trusted (no trust packets) */
	if ((dbsec = pgpCreateFileKeyDB(cdkContext, privFileRef,
								(PGPKeyRingOpenFlags)
								(openFlags | kPGPKeyRingOpenFlags_Private),
								pgpRingPool, &err)) == NULL)
		goto error;
	if ((dbpub = pgpCreateFileKeyDB(cdkContext, pubFileRef,
								(PGPKeyRingOpenFlags)
								(openFlags | kPGPKeyRingOpenFlags_Trusted),
								pgpRingPool, &err)) == NULL)
		goto error;

	/* Create union database for these two files */
	if ((dbunion = pgpCreateUnionKeyDB(cdkContext, &err)) == NULL)
		goto error;
	
	err	= pgpUnionKeyDBAdd(dbunion, dbsec);
	if ( IsPGPError( err ) )
		goto error;
	dbsec = NULL;	/* dbunion now has responsibility for freeing dbsec */
	
	err	= pgpUnionKeyDBAdd(dbunion, dbpub);
	if ( IsPGPError( err ) )
		goto error;
	dbpub = NULL;	/* dbunion now has responsibility for freeing dbpub */

	/*
	 * Verify that we have sufficient ringsets to work with union.
	 * It is easier to check for this now than to check everywhere we
	 * ask for a ringset.
	 */
	if (dbunion->getRingSet(dbunion) == NULL) {
		/* Insufficient ringsets */
		err = kPGPError_OutOfRings;
		goto error;
	}

	err	= pgpBuildKeyPool(dbunion, 0);
	if ( IsPGPError( err ) )
		goto error;

	set = pgpKeyDBRootSet(dbunion);
	if ( IsNull( set ) )
	{
		err = kPGPError_OutOfMemory;	/* XXX Improve error */
		goto error;
	}

	/*
	 * Some earlier versions of PGP don't cache revocation info.  We will
	 * check signatures if the keyring has unchecked revocation signatures
	 * where the key does not have the revoke flag cached.
	 */
	if( IsPGPError( err = sIsSigCheckNeeded( set, &sigCheckNeeded ) ) )
		goto error;
	if( sigCheckNeeded )
	{
		if ( IsPGPError( err = PGPCheckKeyRingSigs( set, set, FALSE,
													NULL, NULL ) ) )
			goto error;
		if ( IsPGPError( err = PGPPropagateTrust( set ) ) )
			goto error;
		if ( PGPKeySetIsMutable( set ) )
		{
			if ( IsPGPError( err = PGPCommitKeyRingChanges( set ) ) )
				goto error;
		}
	} else {
		/* We will re-run trust propagation if anything has expired */
		RingSet const *ringset = pgpKeyDBRingSet( dbunion );
		curTime = PGPGetTime();
		if( ringSetHasExpiringObjects( ringset, curTime, pubModTime ) ) {
			if ( IsPGPError( err = PGPPropagateTrust( set ) ) )
				goto error;
		}
	}

	err = kPGPError_NoErr;
	
error:
	if (dbsec != NULL)
		pgpFreeKeyDB(dbsec);
	if (dbpub != NULL)
		pgpFreeKeyDB(dbpub);
	if (dbunion != NULL)
		pgpFreeKeyDB(dbunion);
	if (set != NULL && IsPGPError( err ))
	{
		PGPFreeKeySet(set);
		set = NULL;
	}
	*keySetOut	= set;
	
	pgpAssertErrWithPtr( err, *keySetOut );
	return err;
}

/*
 * Open a single specified keyring for user, return keyset for it.
 * If isMutable is false, keyrings are read only.
 * If isTrusted is false, trust packets are ignored.
 */
	PGPError
PGPOpenKeyRing(
	PGPContextRef		cdkContext,
	PGPKeyRingOpenFlags	openFlags,
	PGPFileSpecRef		fileRefIn,
	PGPKeySetRef *		keySetOut )
{
	PGPKeyDB	   *db = NULL;
	PGPKeySet	   *set = NULL;
	RingPool	   *pgpRingPool;
	PGPBoolean		sigCheckNeeded;
	PGPError		err = kPGPError_NoErr;
	PFLFileSpecRef	fileRef	= (PFLFileSpecRef)fileRefIn;

	PGPValidatePtr( keySetOut );
	*keySetOut	= NULL;
	PGPValidateContext( cdkContext );
	PFLValidateFileSpec( fileRef );
	
	pgpAssert( (openFlags & kPGPKeyRingOpenFlags_Reserved) == 0 );
	

	pgpRingPool = pgpContextGetRingPool( cdkContext );

	/* Create key database for this files.  Don't bother with keypool. */
	if ((db = pgpCreateFileKeyDB(cdkContext, fileRef, openFlags,
								 pgpRingPool, &err)) == NULL)
		goto error;

	err	= pgpBuildKeyPool(db, 0);
	if ( IsPGPError( err ) )
		goto error;

	set = pgpKeyDBRootSet(db);
	if ( IsNull( set ) )
	{
		err = kPGPError_OutOfMemory;	/* XXX Improve error */
		goto error;
	}

	/*
	 * Some earlier versions of PGP don't cache revocation info.  We will
	 * check signatures if the keyring has unchecked revocation signatures
	 * where the key does not have the revoke flag cached.
	 */
	if( IsPGPError( err = sIsSigCheckNeeded( set, &sigCheckNeeded ) ) )
		goto error;
	if( sigCheckNeeded )
	{
		if ( IsPGPError( err = PGPCheckKeyRingSigs( set, set, FALSE,
													NULL, NULL ) ) )
			goto error;
		if ( IsPGPError( err = PGPPropagateTrust( set ) ) )
			goto error;
		if ( PGPKeySetIsMutable( set ) )
		{
			if ( IsPGPError( err = PGPCommitKeyRingChanges( set ) ) )
				goto error;
		}
	}
	err = kPGPError_NoErr;
	
error:
	if (db != NULL)
		pgpFreeKeyDB(db);
	if (set != NULL && IsPGPError( err ))
	{
		PGPFreeKeySet(set);
		set = NULL;
	}
	*keySetOut	= set;
	pgpAssertErrWithPtr( err, *keySetOut );
	return err;
}

/*
 * Add keys to a keyset from a dynamically allocated binary key buffer.
 * Makes a copy of the binary key buffer data, so caller can dispose of
 * it after this call.
 */
	PGPError
pgpImportKeyBinary (
	PGPContextRef	cdkContext,
	PGPByte		   *buffer,
	size_t			length,
	PGPKeySetRef *	outRef
	)
{
	PGPKeyDBRef		kdb;
	PGPKeySetRef	set	= NULL;
	RingPool	   *pgpRingPool;
	PGPError		err	= kPGPError_NoErr;

	*outRef	= NULL;
	
	/* Create a file type KeyDB from the buffer */
	pgpRingPool = pgpContextGetRingPool( cdkContext );
	kdb = pgpCreateMemFileKeyDB (cdkContext, buffer, length, pgpRingPool,
								 &err);
	if ( IsNull( kdb ) )
	{
		pgpAssert( IsPGPError( err ) );
	}
	else
	{
		err = pgpBuildKeyPool (kdb, 0);
		if ( IsntPGPError( err ) )
		{
			set = pgpKeyDBRootSet (kdb);
		}
		pgpFreeKeyDB (kdb);
	}
	
	*outRef	= set;
	
	return err;
}


/* Import an x509 cert from the specified optionlist input */
	static PGPError
sImportX509Certificate( PGPContextRef context, PGPKeySetRef *keys,
	PGPInputFormat inputFormat, PGPOptionListRef optionList)
{
	PGPByte		   *bufPtr;
	PGPSize			bufLength;
	PGPByte		   *outBuf=NULL, *certSet=NULL;
	PGPSize			outBufLength, certSetLength;
	PGPBoolean		mustFreeBuf = FALSE;
	PGPKeySet	   *keys2 = NULL;
	char		   *passphrase;
	PGPSize			passphraseLength = 0;
	PGPError		err = kPGPError_NoErr;
	
	err = pgpSetupInputToBuffer( context, optionList, &bufPtr, &bufLength,
								 &mustFreeBuf );
	if( IsPGPError( err ) )
		goto error;

	if( inputFormat == kPGPInputFormat_PKCS12 ||
		inputFormat == kPGPInputFormat_PrivateKeyInfo )
	{
		/* Input a private X.509 key */
		RingObject *key = NULL;
		if( inputFormat == kPGPInputFormat_PKCS12 )
		{

			/* Pick up optional passphrase */
			if( IsPGPError( err = pgpFindOptionArgs( optionList,
								kPGPOptionType_Passphrase, FALSE,
								"%p%l", &passphrase, &passphraseLength ) ) )
				goto error;

			err = PKCS12InputKey( context, bufPtr, bufLength,
								  (PGPByte *) passphrase, passphraseLength,
								  &outBuf, &outBufLength,
								  &certSet, &certSetLength );
			if( IsPGPError( err ) )
				goto error;
			
			/* Switch input to PKCS-8 data */
			if( mustFreeBuf )
				PGPFreeData( bufPtr );
			bufPtr = outBuf;
			bufLength = outBufLength;
			mustFreeBuf = TRUE;
		}

		/* Now have PKCS-8 data in bufPtr/bufLength */
		
		/* Create empty keyset */
		err = PGPNewKeySet( context, keys );
		if( IsPGPError( err ) )
			goto error;

		/* Process the returned cert set */
		if( IsntNull( certSet ) ) {
			err = pgpDecodeX509CertSet( certSet, certSetLength,
										context, &keys2 );
			if( IsPGPError( err ) )
				goto error;
			err = PGPAddKeys( keys2, *keys );
			if( IsPGPError( err ) )
				goto error;
			PGPFreeKeySet( keys2 );
			keys2 = NULL;
		}

		/* Decode PKCS-8 data */
		err = pgpDecodePCKS8( bufPtr, bufLength, context, &keys2 );
		if( IsPGPError( err ) )
			goto error;

		/* Combine keysets */
		err = PGPAddKeys( keys2, *keys );
		if( IsPGPError( err ) )
			goto error;

		/* Set passphrase on newly imported key */
		if( passphraseLength != 0 ) {
			RingSet const *ringset;
			RingIterator *ringiter;

			ringset = pgpKeyDBRingSet ((*keys)->keyDB);
			ringiter = ringIterCreate(ringset);
			if (ringiter) {
				/* Find key we just imported */
				while (ringIterNextObject (ringiter, 1) == 1) {
					key = ringIterCurrentObject (ringiter, 1);
					if (ringKeyIsSec( ringset, key ) )
						break;
					key = NULL;
				}
				ringIterDestroy (ringiter);
			}
			if( key ) {
				err = pgpDoChangePassphraseInternal( (*keys)->keyDB, ringset,
						key, NULL, NULL, 0, passphrase, passphraseLength,
						FALSE );
				if( IsPGPError( err ) )
					goto error;
				/* Ringset for keydb may be changed by above call */
				ringset = pgpKeyDBRingSet ((*keys)->keyDB);
			}
		}

		err = PGPCommitKeyRingChanges( *keys );
		if( IsPGPError( err ) )
			goto error;

		/* Done */
		goto error;
	}

	if( inputFormat >= kPGPInputFormat_PEMEncodedX509Cert &&
		inputFormat <= kPGPInputFormat_EntrustV1_PEMEncoded )
	{
		/* Need to remove PEM encoding */
		PGPByte *tmpBuf;
		PGPSize tmpBufLength;
		err = pgpRemovePEMEncoding( context, bufPtr, bufLength,
									&tmpBuf, &tmpBufLength );
		if( IsPGPError( err ) )
			goto error;
		/* Replace bufPtr, bufLength with tmp versions (which must be freed) */
		if( mustFreeBuf )
			PGPFreeData( bufPtr );
		mustFreeBuf = TRUE;
		bufPtr = tmpBuf;
		bufLength = tmpBufLength;
	}

	/* Now data is in bufPtr, of length bufLength */
	err = pgpDecodeX509Cert( bufPtr, bufLength,  context, keys );

error:
	if( mustFreeBuf )
		PGPFreeData( bufPtr );
	if( IsntNull( certSet ) )
		PGPFreeData( certSet );
	if( IsntNull( keys2 ) )
		PGPFreeKeySet( keys2 );

	return err;
}



static const PGPOptionType impkeyOptionSet[] = {
	kPGPOptionType_InputFileRef,
	kPGPOptionType_LocalEncoding,
	kPGPOptionType_InputBuffer,
	kPGPOptionType_EventHandler,
	kPGPOptionType_SendNullEvents,
	kPGPOptionType_InputFormat,
	kPGPOptionType_Passphrase,
	kPGPOptionType_X509Encoding
};

/* Frees optionList, unlike most other internal functions */
	PGPError
pgpImportKeySetInternal (PGPContextRef context, PGPKeySetRef *keys,
	PGPOptionListRef optionList)
{
	PGPError		err = kPGPError_NoErr;
	PGPKeySetRef	keyset;
	PGPInputFormat	inputFormat;
	PGPUInt32		fDo509;

	if (IsPGPError( err = pgpCheckOptionsInSet( optionList,
						impkeyOptionSet, elemsof( impkeyOptionSet ) ) ) )
		return err;

	pgpAssertAddrValid( keys, PGPKeySetRef );
	*keys = NULL;
	
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_X509Encoding, FALSE,
						 "%d", &fDo509 ) ) )
		goto error;

	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_InputFormat, FALSE,
						 "%d", &inputFormat ) ) )
		goto error;

	if( fDo509 || inputFormat >= kPGPInputFormat_X509DataInPKCS7 ) {
		err = sImportX509Certificate( context, keys, inputFormat, optionList );
		PGPFreeOptionList( optionList );
		goto error;
	}

	if( IsPGPError( err = PGPNewKeySet( context, &keyset ) ) )
		goto error;

	if( IsPGPError( err = PGPDecode( context, optionList,
									 PGPODiscardOutput(context, TRUE),
									 PGPOImportKeysTo(context, keyset),
									 PGPOLastOption(context) ) ) ) {
		PGPFreeKeySet( keyset );
		goto error;
	}
	*keys = keyset;
	
error:
	return err;
}


/*
 * Handle X509 based export formats.
 * Key is the top level key we are exporting; ringset controls which
 * sub objects if any we should look at
 */
static PGPError
sExportKeyX509 (
	PGPContextRef		context,
	PGPKeyRef		   key,
	RingSet const	   *ringset,
	PGPExportFormat		exportFormat,
	PGPOptionListRef	optionList
	)
{
	PGPEnv			   *env;
	PGPError			err = kPGPError_NoErr;
	PGPUInt32			fAppendOutput;
	PGPPipeline			*head = NULL, **tail = &head;
	PFLConstFileSpecRef	 outFileRef;
	PGPFile				*pfout;
	PGPByte				*outBufPtr;
	PGPByte			   **outBufPtrPtr;
	PGPSize				 outBufMaxLength;
	PGPSize				*outBufUsedLength;
	PGPPipeline			*outPipe;
	PGPByte				*buf = NULL;
	PGPSize				 bufLength = 0;
	PGPBoolean			 freeBuf = FALSE;
	PGPMemoryMgrRef		 mgr;
	void				*vFormatData;
	PGPAttributeValue	*formatData;
	PGPAttributeValue	*formatDataCopy = NULL;
	PGPAttributeValue	*newAV;
	PGPSize				 formatDataLength;
	PGPOptionListRef	 passphrase = NULL;
	PGPByte				*dpoint = NULL;
	PGPSize				 dpointlen = 0;
	static char			 s_pgpkeycr[] = "PGPKeyCreation=0x";
	static PGPByte		 s_pgpx509keycr [] = {
		0x30, 0x0e,		/* SEQUENCE */
			/* PGP Extension OID */
			/* (1 3 6 1 4 1 3401 8 1 1) */
			0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x9a, 0x49, 0x08,
					0x01, 0x01,
			0x04, 0x00	/* Octet string */
			/* Value as UTCTime value goes here */
	};
	char				 pgpkeycr[40];	/* big enough for either case */

	env = pgpContextGetEnvironment( context );
	mgr = PGPGetContextMemoryMgr( context );

	if (exportFormat == kPGPExportFormat_X509Cert) {
		/* Find the right X509 sig, somehow */
		RingObject *obj = NULL;
		RingObject *bestsig = NULL;
		RingIterator *ringiter;
		PGPInt32 level;

		ringiter = ringIterCreate (ringset);
		if( IsNull( ringiter ) ) {
			err = ringSetError( ringset )->error;
			goto error;
		}
		while ((level = ringIterNextObjectAnywhere(ringiter)) > 0) {
			obj = ringIterCurrentObject (ringiter, level);
			if (ringObjectType(obj) == RINGTYPE_SIG &&
				ringSigIsX509 (ringset, obj)) {
				RingObject *signer = ringSigMaker (ringset, obj, ringset);
				/* Use a self-sig if exists, else use first sig */
				if (signer == ringIterCurrentObject (ringiter, 1)) {
					bestsig = obj;
				} else if (bestsig == NULL) {
					bestsig = obj;
				}
			}
		}
		ringIterDestroy( ringiter );
		if (bestsig != NULL) {
			buf = ringSigX509Certificate( ringset, bestsig, &bufLength );
		}
	} else if (exportFormat >= kPGPExportFormat_X509GetCRL) {
		time_t curtime = PGPGetStdTimeFromPGPTime( PGPGetTime() );

		/* If InputBuffer is specified, it is CRL distribution point */
		if( IsPGPError( err = pgpFindOptionArgs( optionList,
							 kPGPOptionType_InputBuffer, FALSE,
							 "%p%l", &dpoint, &dpointlen ) ) )
			goto error;

		err = X509CreateCRLRequest ( context, key, dpoint, dpointlen,
				exportFormat, curtime, &buf, &bufLength );
		if( IsPGPError( err ) )
			goto error;

		freeBuf = TRUE;
	} else if (exportFormat >= kPGPExportFormat_X509GetCertInitial) {
		/* Structure for now will be a fixed empty sequence */
		static PGPByte emptysequence[] = {0x30, 0x00};
		buf = emptysequence;
		bufLength = sizeof(emptysequence);
		freeBuf = FALSE;
	} else if (exportFormat >= kPGPExportFormat_X509CertReq) {
		PGPOption passop;

		if( IsPGPError( err = pgpSearchOptionSingle( optionList,
									kPGPOptionType_Passphrase, &passop ) ) )
			goto error;
		if( IsntOp( passop ) ) {
			if( IsPGPError( err = pgpSearchOptionSingle( optionList,
										kPGPOptionType_Passkey, &passop ) ) )
				goto error;
		}

		if( IsOp( passop ) ) {
			PGPOption passopcopy;
			pgpCopyOption( context, &passop, &passopcopy );
			passphrase = pgpNewOneOptionList( context, &passopcopy );
		}

		if( IsPGPError( err = pgpFindOptionArgs( optionList,
							 kPGPOptionType_AttributeValue, FALSE,
							 "%p%l",
							 &vFormatData, &formatDataLength ) ) )
			goto error;
		formatData = vFormatData;
		formatDataLength /= sizeof(PGPAttributeValue);
		formatDataCopy = PGPNewData( mgr,
					(formatDataLength+1)*sizeof(PGPAttributeValue), 0 );
		if( IsNull( formatDataCopy ) ) {
			err = kPGPError_OutOfMemory;
			goto error;
		}
		pgpCopyMemory( formatData, formatDataCopy+1,
					   formatDataLength*sizeof(PGPAttributeValue) );
		newAV = formatDataCopy;

		/* Add "description" or extension field to hold keycreation data */
		if( exportFormat == kPGPExportFormat_VerisignV1_CertReq )
		{
			/* Use a new extension */
			PGPUInt32 kcr = ringKeyCreation (ringset, key->key);
			PGPByte *px = (PGPByte *)pgpkeycr + sizeof(s_pgpx509keycr);
			PGPSize tlen;
			char tbuf[PGPX509TIMELEN+1];

			tlen = pgpTimeToX509Time( kcr, tbuf );
			pgpCopyMemory( s_pgpx509keycr, pgpkeycr, sizeof(s_pgpx509keycr) );
			pgpkeycr[1] += tlen + 2;
			pgpkeycr[sizeof(s_pgpx509keycr)-1] += tlen + 2;
			/* Choose GeneralizedTime vs UTCTime tag */
			*px++ = (tlen == PGPX509TIMELEN) ? 24 : 23;
			*px++ =  tlen;
			pgpCopyMemory( tbuf, px, tlen );
			newAV->attribute = kPGPAVAttribute_CertificateExtension;
			newAV->size = sizeof(s_pgpx509keycr) + 2 + tlen;
			newAV->value.pointervalue = pgpkeycr;
			newAV->unused = 0;
		}
		else
		{
			/* Use description field in subject name */
			pgpCopyMemory( s_pgpkeycr, pgpkeycr, sizeof(s_pgpkeycr)-1 );
			sprintf ( pgpkeycr+sizeof(s_pgpkeycr)-1, "%08x",
					  ringKeyCreation (ringset, key->key) );
			newAV->attribute = kPGPAVAttribute_Description;
			newAV->size = sizeof(s_pgpkeycr)-1 + 8;
			newAV->value.pointervalue = pgpkeycr;
			newAV->unused = 0;
		}

		err = X509CreateCertificateRequest ( context, key, exportFormat,
				formatDataCopy, formatDataLength+1, passphrase,
				&buf, &bufLength );
		passphrase = NULL;
		PGPFreeData( formatDataCopy );
		formatDataCopy = NULL;
		if( IsPGPError( err ) )
			goto error;

		freeBuf = TRUE;

	} else {
		pgpAssert (0);
	}

	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_AppendOutput, FALSE,
						 "%d", &fAppendOutput ) ) )
		goto error;

	err = pgpSetupOutputPipeline( context, optionList,
							env, FALSE, FALSE, FALSE,
							(PGPBoolean)fAppendOutput, TRUE,
							&tail, &outFileRef, &pfout,
							&outBufPtr, &outBufPtrPtr,
							&outBufMaxLength, &outBufUsedLength,
							&outPipe );
	
	if( IsPGPError( err ) )
		goto error;

	err = pgpPumpMem( head, buf, bufLength, NULL, NULL );
	if( IsPGPError( err ) )
		goto error;

	if( outPipe ) {
		if( IsntNull( outBufPtrPtr ) ) {
			/* Dynamically allocated buffer - tell user size & position */
			if( IsPGPError( err = pgpGetVariableMemOutput( outPipe,
							outBufMaxLength, outBufPtrPtr,
							outBufUsedLength ) ) )
				goto error;
		} else {
			/* Fixed size buffer - tell user actual size used */
			pgpAssert( IsntNull( outBufPtr ) );
			if( IsPGPError( err = pgpGetMemOutput( outPipe,
						outBufMaxLength, outBufUsedLength ) ) )
				goto error;
		}
	}

	head->teardown( head );
	head = NULL;

error:

	if( IsntNull( passphrase ) )
		pgpFreeOptionList( passphrase );
	if( IsntNull( formatDataCopy ) )
		PGPFreeData( formatDataCopy );
	if( freeBuf && IsntNull( buf ) )
		PGPFreeData( buf );
	if( IsntNull( head ) )
		head->teardown( head );

	return err;
}




/* 
 * Filter function for extraction.  Remove any secret objects.
 * If addarrs is true, also add any additional decryption key objects to
 * the set.  This will cause ADK's to be extracted with the keys
 * that use them.
 * XXX AUTOMATIC ADK EXTRACTION DOES NOT YET WORK.
 * There is no RingSet available in which
 * to look for ADK's.  The export functions typically are called with
 * just a memory RingSet.  We need to add versions which take an extra
 * PGPKeySet to flag that ADK's should be looked for there.
 */
static RingSet *
filterPubRingSet (RingSet const *rset,
	PGPBoolean exportmastersecrets, PGPBoolean exportsubsecrets,
	PGPBoolean addarks, PGPBoolean includeattributes)
{
	RingSet		   *rsetnew;	/* Set of recipients */
	RingSet		   *adkeyset;	/* Set of additional decryption keys */
	RingIterator   *riter;		/* Iterator over adding sets */
	int				level;
	PGPBoolean		exportsecrets = exportmastersecrets;
	PGPError		err	= kPGPError_NoErr;

	if (!rset)
		return NULL;
	adkeyset = NULL;
	rsetnew = ringSetCreate (ringSetPool (rset));
	if (!rsetnew)
		return NULL;
	riter = ringIterCreate (rset);
	if (!riter) {
		ringSetDestroy (rsetnew);
		return NULL;
	}
	/* 
	 * Copy objects in PGPKeySet to rsetnew except secret objects.
	 * At the same time, accumulate any additional decryption keys into
	 * adkeyset.
	 */
	while ((level = ringIterNextObjectAnywhere(riter)) > 0) {
		RingObject *obj = ringIterCurrentObject (riter, level);
		if (ringObjectType(obj) == RINGTYPE_KEY) {
			exportsecrets = ringKeyIsSubkey(rset, obj) ? exportsubsecrets :
														 exportmastersecrets;
		}
		/* Possibly skip secret objects */
		if (!exportsecrets && ringObjectType (obj) == RINGTYPE_SEC)
			continue;
		/* Skip signatures if exporting secret keys */
		if (exportsecrets && ringObjectType (obj) == RINGTYPE_SIG)
			continue;
		if (!includeattributes && ringObjectType (obj) == RINGTYPE_NAME
			&& ringNameIsAttribute (rset, obj))
			continue;
		if (!includeattributes && ringObjectType (obj) == RINGTYPE_SIG) {
			RingObject *parent = ringIterCurrentObject (riter, level-1);
			if (ringObjectType(parent) == RINGTYPE_NAME &&
				ringNameIsAttribute (rset, parent))
				continue;
		}
		ringSetAddObject (rsetnew, obj);
		/* For key objects, look for additional decryption keys */
		if (addarks && ringObjectType (obj) == RINGTYPE_KEY)
		{
			RingObject	   *rkey;		/* Decryption key */
			unsigned		nrkeys;		/* Number of decryption keys */
			
			if (ringKeyAdditionalRecipientRequestKey (obj, rset, 0, NULL,
										NULL, NULL, &nrkeys, &err) != NULL )
			{
				/* Add to special set for additional decryption keys */
				while (nrkeys-- > 0)
				{
					rkey = ringKeyAdditionalRecipientRequestKey (obj, rset, 0,
											NULL, NULL, NULL, &nrkeys, &err);
					pgpAssert (rkey);
					if (!adkeyset)
					{
						adkeyset = ringSetCreate (ringSetPool(rset));
						if (!adkeyset)
						{
							ringIterDestroy (riter);
							ringSetDestroy (rsetnew);
							return NULL;
						}
					}
					ringSetAddObjectChildren (adkeyset, rset, rkey);
				}
			}
		}
	}
	ringIterDestroy (riter);

	/* Last, merge adkeyset into rsetnew, also stripping secrets */
	if (adkeyset) {
		ringSetFreeze (adkeyset);
		riter = ringIterCreate (adkeyset);
		if (!riter) {
			ringSetDestroy (adkeyset);
			ringSetDestroy (rsetnew);
			return NULL;
		}
		/* Loop over rsetnew iterator, adding non-secret objects */
		/* We will always strip ADK secrets, he can export those explicitly */
		while ((level = ringIterNextObjectAnywhere(riter)) > 0) {
			RingObject *obj = ringIterCurrentObject (riter, level);
			if (ringObjectType (obj) == RINGTYPE_SEC)
				continue;
			ringSetAddObject (rsetnew, obj);
		}
		ringIterDestroy (riter);
		ringSetDestroy (adkeyset);
	}

	/* Return new set in frozen form */
	ringSetFreeze (rsetnew);
	return rsetnew;
}



#if PGP_MACINTOSH
#pragma global_optimizer on
#endif


/*
 * Frees optionList, unlike most other internal functions.  rset
 * defines the exact set to be exported; key is the first key in the
 * set.
 */
static PGPError
sExportKeySetInternal (PGPContextRef context, PGPKeyRef key,
	RingSet const *rset, PGPOptionListRef optionList)
{
	PGPUInt32			fExportSecrets;
	PGPUInt32			fExportSubSecrets;
	PGPBoolean			fExportAttributes;
	PGPBoolean			fExportFormat;
	PGPByte				*buf;
	PGPSize				bufSize;
	PGPSize				bufSizeRead;
	PGPFile				*pfile;
	RingSet const		*rsetpub;
	PGPOptionListRef	optList;
	PGPExportFormat		exportFormat = kPGPExportFormat_Complete;
	PGPUInt32			wExportFormat;
	PGPBoolean			armorop;
	PGPError			err = kPGPError_NoErr;

	pgpAssert( pgpContextIsValid( context ) );

	buf = NULL;
	pfile = NULL;
	rsetpub = NULL;
	optList = NULL;

	/* Read optional options */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_ExportPrivateKeys, FALSE,
						 "%d", &fExportSecrets ) ) )
		goto error;

	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_ExportPrivateSubkeys, FALSE,
						 "%d", &fExportSubSecrets ) ) )
		goto error;

	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_ExportFormat, FALSE,
						 "%b%d", &fExportFormat, &wExportFormat ) ) )
		goto error;

	if (fExportFormat)
		exportFormat = (PGPExportFormat) wExportFormat;

	/* Handle X509 export formats */
	if (exportFormat == kPGPExportFormat_X509Cert ||
		exportFormat >= kPGPExportFormat_X509CertReq) {
		err = sExportKeyX509 (context, key, rset,
							  exportFormat, optionList);
		goto error;
	}

	fExportAttributes = (exportFormat > kPGPExportFormat_Basic);

	/* Output public or private portion */
	rsetpub = filterPubRingSet (rset, (PGPBoolean)fExportSecrets,
								(PGPBoolean)(fExportSubSecrets|fExportSecrets),
								FALSE, fExportAttributes);
	if (!rsetpub) {
		err = kPGPError_OutOfMemory;
		goto error;
	}

	/* Create memory buffer to write to */
	pfile = pgpFileMemOpen( context, NULL, 0 );
	if( IsNull( pfile ) ) {
		err = kPGPError_OutOfMemory;
		goto error;
	}

	/* Output data to memory buffer */
	if( IsPGPError( err = ringSetWrite (rsetpub, pfile, NULL, PGPVERSION_3,
										0) ) )
		goto error;
	ringSetDestroy( (RingSet *)rsetpub );
	rsetpub = NULL;

	/* Read data we just wrote */
	bufSize = pgpFileTell (pfile );
	buf = (PGPByte *)pgpContextMemAlloc( context, bufSize, 0 );
	if( IsNull( buf ) ) {
		err = kPGPError_OutOfMemory;
		goto error;
	}
	(void)pgpFileSeek( pfile, 0, SEEK_SET );
	bufSizeRead = pgpFileRead( buf, bufSize, pfile );
	pgpAssert( bufSizeRead == bufSize );
	pgpFileClose( pfile );
	pfile = NULL;

	/* Do ascii armoring */
	/* If user specified an ascii armor option, use his, else use TRUE */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						kPGPOptionType_ArmorOutput, FALSE,
						"%b", &armorop ) ) )
		goto error;

	/* This next call frees optionList */
	if( IsPGPError( err = PGPBuildOptionList( context, &optList, optionList, 
									 (armorop ?
									  PGPONullOption(context) :
									  PGPOArmorOutput(context, TRUE)),
									 PGPORawPGPInput(context, TRUE),
									 PGPOCompression(context, FALSE),
									 PGPOLastOption(context) ) ) )
		goto error;
	optionList = NULL;

	if( IsPGPError( err = PGPEncode( context, optList,
									 PGPOInputBuffer(context, buf, bufSize),
									 PGPOLastOption(context) ) ) )
		goto error;

	pgpContextMemFree( context, buf );
	buf = NULL;

	/*
	 * If exporting private keys, append public keys to the buffer.
	 * We can't export them both together, as we end up with an output
	 * which has private keys followed by names and sigs.  This can not
	 * be safely imported, because of the "version bug".  The private key
	 * may have the incorrect version.  So we instead output the public
	 * part with names and sigs, after the private part with private keys
	 * and names.
	 */
	if( fExportSecrets || fExportSubSecrets ) {

		/* Get ringset for public portion */
		rsetpub = filterPubRingSet (rset, FALSE, FALSE, FALSE,
									fExportAttributes);
		if (!rsetpub) {
			err = kPGPError_OutOfMemory;
			goto error;
		}

		/* Create memory buffer to write to */
		pfile = pgpFileMemOpen( context, NULL, 0 );
		if( IsNull( pfile ) ) {
			err = kPGPError_OutOfMemory;
			goto error;
		}

		/* Output data to memory buffer */
		if( IsPGPError( err = ringSetWrite (rsetpub, pfile, NULL,
											PGPVERSION_3, 0) ) )
			goto error;
		ringSetDestroy( (RingSet *)rsetpub );
		rsetpub = NULL;

		/* Read data we just wrote */
		bufSize = pgpFileTell (pfile );
		buf = (PGPByte *)pgpContextMemAlloc( context, bufSize, 0 );
		if( IsNull( buf ) ) {
			err = kPGPError_OutOfMemory;
			goto error;
		}
		(void)pgpFileSeek( pfile, 0, SEEK_SET );
		bufSizeRead = pgpFileRead( buf, bufSize, pfile );
		pgpAssert( bufSizeRead == bufSize );
		pgpFileClose( pfile );
		pfile = NULL;

		/* Do ascii armoring, append to existing output */
		PGPAppendOptionList( optList,
							 PGPOAppendOutput(context, TRUE),
							 PGPOLastOption(context) );
		if( IsPGPError( err = PGPEncode( context, optList,
									PGPOInputBuffer(context, buf, bufSize),
									PGPOLastOption(context) ) ) )
			goto error;

		pgpContextMemFree( context, buf );
		buf = NULL;
	}

	err = kPGPError_NoErr;

	/* Fall through */
error:
	if( IsntNull( optList ) )
		PGPFreeOptionList( optList );
	if( IsntNull( optionList ) )
		PGPFreeOptionList( optionList );
	if( IsntNull( pfile ) )
		pgpFileClose( pfile );
	if( IsntNull( rsetpub ) )
		ringSetDestroy ( (RingSet *)rsetpub);
	if( IsntNull( buf ) )
		pgpContextMemFree( context, buf );
	return err;
}

#if PGP_MACINTOSH
#pragma global_optimizer reset
#endif


static const PGPOptionType expkeyOptionSet[] = {
	kPGPOptionType_ExportPrivateKeys,
	kPGPOptionType_ExportPrivateSubkeys,
	kPGPOptionType_ExportFormat,
	kPGPOptionType_OutputFileRef,
	kPGPOptionType_OutputBuffer,
	kPGPOptionType_OutputAllocatedBuffer,
	kPGPOptionType_DiscardOutput,
	kPGPOptionType_ArmorOutput,
	kPGPOptionType_CommentString,
	kPGPOptionType_VersionString,
	kPGPOptionType_EventHandler,
	kPGPOptionType_SendNullEvents,
	kPGPOptionType_OutputLineEndType,
	kPGPOptionType_OutputFormat,
	/* Used for cert requests */
	kPGPOptionType_Passphrase,
	kPGPOptionType_Passkey,
	kPGPOptionType_AttributeValue,
	kPGPOptionType_InputBuffer
};



/* Frees optionList, unlike most other internal functions. */
PGPError
pgpExportKeySetInternal (PGPKeySet *keys, PGPOptionListRef optionList)
{
	RingSet const		*rset = NULL;
	PGPContextRef		context;
	PGPKeyRef			key;
	PGPKeyListRef		klist;
	PGPKeyIterRef		kiter;
	PGPError			err = kPGPError_NoErr;

	if (IsPGPError( err = pgpCheckOptionsInSet( optionList,
						expkeyOptionSet, elemsof( expkeyOptionSet ) ) ) )
		return err;

	context = PGPGetKeySetContext( keys );

	/* Get ringset corresponding to keyset */
	if( IsPGPError( err = pgpKeySetRingSet( keys, TRUE, &rset ) ) )
		goto error;

	/* Extract first key from keyset */
	if( IsPGPError( err = PGPOrderKeySet( keys, kPGPAnyOrdering, &klist ) ) )
		goto error;
	if( IsPGPError( err = PGPNewKeyIter( klist, &kiter ) ) ) {
		PGPFreeKeyList( klist );
		goto error;
	}
	err = PGPKeyIterNext( kiter, &key );
	PGPFreeKeyIter( kiter );
	PGPFreeKeyList( klist );
	if( IsPGPError( err ) )
		goto error;


	if( IsPGPError( err = sExportKeySetInternal (context, key, rset,
												 optionList ) ) )
		goto error;

	/* Fall through */
error:
	if( IsntNull( rset ) )
		ringSetDestroy ( (RingSet *)rset);

	return err;

}


static const PGPOptionType expOptionSet[] = {
	kPGPOptionType_ExportPrivateKeys,
	kPGPOptionType_ExportPrivateSubkeys,
	kPGPOptionType_ExportFormat,
	kPGPOptionType_OutputFileRef,
	kPGPOptionType_OutputBuffer,
	kPGPOptionType_OutputAllocatedBuffer,
	kPGPOptionType_DiscardOutput,
	kPGPOptionType_ArmorOutput,
	kPGPOptionType_CommentString,
	kPGPOptionType_VersionString,
	kPGPOptionType_EventHandler,
	kPGPOptionType_SendNullEvents,
	kPGPOptionType_OutputLineEndType,
	kPGPOptionType_OutputFormat,
	kPGPOptionType_ExportKeySet,
	kPGPOptionType_ExportKey,
	kPGPOptionType_ExportUserID,
	kPGPOptionType_ExportSig,
	/* Used for cert requests */
	kPGPOptionType_Passphrase,
	kPGPOptionType_Passkey,
	kPGPOptionType_AttributeValue,
	kPGPOptionType_InputBuffer
};



/*
 * Frees optionList, unlike most other internal functions.  This is
 * like exportkeyset, but it allows a single userid or sig to be
 * specified.  We only export that object, plus its parent object(s)
 * and all its children.  This is especially convenient when exporting
 * a particular X.509 certificate.
 */
PGPError
pgpExportInternal (PGPContextRef context, PGPOptionListRef optionList)
{
	PGPKeyRef			key;
	PGPUserIDRef		userid;
	PGPSigRef			sig;
	RingPool	   	   *pool;
	RingSet			   *rset = NULL;
	PGPKeySet		   *keys;
	RingSet const	   *dbrset;
	PGPBoolean			fExportKeyRef, fExportUserIDRef, fExportSigRef;
	PGPBoolean			fExportKeySetRef;
	void			   *wExportKeyRef, *wExportUserIDRef, *wExportSigRef;
	void			   *wExportKeySetRef;
	PGPInt32			successes = 0;
	PGPError			err = kPGPError_NoErr;

	if (IsPGPError( err = pgpCheckOptionsInSet( optionList,
						expOptionSet, elemsof( expOptionSet ) ) ) )
		return err;


	/* See if we have a target key/name/sig to export */

	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_ExportKeySet, FALSE,
						 "%b%d", &fExportKeySetRef, &wExportKeySetRef ) ) )
		goto error;
	if (fExportKeySetRef)
		++successes;
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_ExportKey, FALSE,
						 "%b%d", &fExportKeyRef, &wExportKeyRef ) ) )
		goto error;
	if (fExportKeyRef)
		++successes;
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_ExportUserID, FALSE,
						 "%b%d", &fExportUserIDRef, &wExportUserIDRef ) ) )
		goto error;
	if (fExportUserIDRef)
		++successes;
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_ExportSig, FALSE,
						 "%b%d", &fExportSigRef, &wExportSigRef ) ) )
		goto error;
	if (fExportSigRef)
		++successes;
	
	if (successes > 1) {
		pgpDebugMsg( "too many key object selection options for PGPExport" );
		err = kPGPError_BadParams;
		goto error;
	} else if (successes == 0) {
		pgpDebugMsg( "no key object selection options for PGPExport" );
		err = kPGPError_BadParams;
		goto error;
	}

	/* Create ringset we will export */
	pool = pgpContextGetRingPool( context );
	pgpAssert( IsntNull( pool ) );

	/* Handle the different cases */
	if (fExportKeySetRef) {
		PGPKeyListRef		klist;
		PGPKeyIterRef		kiter;
		keys = (PGPKeySet *) wExportKeySetRef;
		/* Extract first key from keyset */
		if( IsPGPError( err = PGPOrderKeySet( keys, kPGPAnyOrdering,
											  &klist ) ) )
			goto error;
		if( IsPGPError( err = PGPNewKeyIter( klist, &kiter ) ) ) {
			PGPFreeKeyList( klist );
			goto error;
		}
		err = PGPKeyIterNext( kiter, &key );
		PGPFreeKeyIter( kiter );
		PGPFreeKeyList( klist );
		if( IsPGPError( err ) )
			goto error;
		if( IsPGPError( err = pgpKeySetRingSet( keys, TRUE,
												(RingSet const **)&rset ) ) )
			goto error;
	} else {
		RingObject *obj = NULL;
		rset = ringSetCreate (pool);
		if( IsNull( rset ) ) {
			err = ringPoolError(pool)->error;
			goto error;
		}
		if (fExportKeyRef) {
			key = (PGPKey *) wExportKeyRef;
			obj = key->key;
		} else if (fExportUserIDRef) {
			userid = (PGPUserID *) wExportUserIDRef;
			key = userid->key;
			obj = userid->userID;
		} else if (fExportSigRef) {
			sig = (PGPSig *) wExportSigRef;
			if (sig->type == keycert) {
				key = sig->up.key;
			} else {
				key = sig->up.userID->key;
			}
			obj = sig->cert;
		} else {
			pgpAssert(0);
		}
		pgpAssert( IsntNull( obj ) );
		dbrset = pgpKeyDBRingSet (key->keyDB);
		ringSetAddObjectChildren( rset, dbrset, obj );
		ringSetFreeze( rset );
	}

	if( IsPGPError( err = sExportKeySetInternal (context, key, rset,
												 optionList ) ) )
		goto error;

	/* Fall through */
error:
	if( IsntNull( rset ) )
		ringSetDestroy ( (RingSet *)rset);

	return err;
}


/*
 * Local Variables:
 * tab-width: 4
 * End:
 * vi: ts=4 sw=4
 * vim: si
 */
