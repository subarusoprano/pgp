/*____________________________________________________________________________
	pgpEncode.c
	High level encode functionality
	
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: pgpEncode.c,v 1.107 1999/05/07 23:47:45 hal Exp $
____________________________________________________________________________*/
#include "pgpConfig.h"	/* or pgpConfig.h in the CDK */

#include <string.h>

/* Public headers */
#include "pgpPubTypes.h"
#include "pgpContext.h"
#include "pgpEncode.h"
#include "pgpErrors.h"
#include "pgpKeys.h"
#include "pgpMem.h"

/* Private headers */
#include "pgpDebug.h"
#include "pgpEncodePriv.h"
#include "pgpAnnotate.h"
#include "pgpArmor.h"
#include "pgpBufMod.h"
#include "pgpSymmetricCipherPriv.h"
#include "pgpConvKey.h"
#include "pgpDevNull.h"
#include "pgpEncPipe.h"
#include "pgpEnv.h"
#include "pgpEventPriv.h"
#include "pgpFile.h"
#include "pgpFileMod.h"
#include "pgpFileRef.h"
#include "pgpFileSpec.h"
#include "pgpFileType.h"
#include "pgpHash.h"
#include "pgpKeyDB.h"
#include "pgpKDBInt.h"
#include "pgpMem.h"
#include "pgpMemMod.h"
#include "pgpOptionList.h"
#include "pgpPipeline.h"
#include "pgpPubKey.h"
#include "pgpRandomPoolPriv.h"
#include "pgpRndSeed.h"
#include "pgpRngPub.h"
#include "pgpSigSpec.h"
#include "pgpTextFilt.h"
#include "pgpTrstPkt.h"
#include "pgpVMemMod.h"
#include "pgpX509Priv.h"

#define elemsof(x) ((unsigned)(sizeof(x)/sizeof(*x)))


/*********************** Helper functions for below ************************/


/* Set up PGPEnv structure for library internals */

	static PGPError
pgpMakeEnvFromOptionList(
	PGPOptionListRef	 optionList,
	PGPEnv				*env
	)
{
	PGPError		 err;				/* Error flag */
	PGPUInt32		 hashalg;			/* Default hash alg */
	PGPUInt32		 cipheralg;			/* Default cipher alg */
	PGPUInt32		 fOption;			/* Generic option flag */
	PGPBoolean		 fDefault;			/* True if have the option from usr */
	char			*comment;			/* Comment string for output */
	char			*version;			/* Version string for output */

	/* Ascii armor mode */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_ArmorOutput, FALSE,
						 "%d", &fOption ) ) )
		goto error;
	pgpenvSetInt( env, PGPENV_ARMOR, fOption, PGPENV_PRI_FORCE );

	/* Text mode (as compared to binary) */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_DataIsASCII, FALSE,
						 "%d", &fOption ) ) )
		goto error;
	pgpenvSetInt( env, PGPENV_TEXTMODE, fOption, PGPENV_PRI_FORCE );

	/* Control of compression (default on) */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_Compression, FALSE,
						 "%b%d", &fDefault, &fOption ) ) )
		goto error;
	if( !fDefault )
		fOption = TRUE;
	pgpenvSetInt( env, PGPENV_COMPRESS, fOption, PGPENV_PRI_FORCE );

	/* Clearsign mode, implies textmode and ascii armor */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_ClearSign, FALSE,
						 "%d", &fOption ) ) )
		goto error;
	if( fOption ) {
		pgpenvSetInt( env, PGPENV_CLEARSIG, TRUE, PGPENV_PRI_FORCE );
		pgpenvSetInt( env, PGPENV_TEXTMODE, TRUE, PGPENV_PRI_FORCE );
		pgpenvSetInt( env, PGPENV_ARMOR, TRUE, PGPENV_PRI_FORCE );
	} else {
		pgpenvSetInt( env, PGPENV_CLEARSIG, FALSE, PGPENV_PRI_FORCE );
	}

	/* PGP-MIME output, implies ascii armor */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_PGPMIMEEncoding, FALSE,
						 "%b%d", &fDefault, &fOption ) ) )
		goto error;
	if( fDefault ) {
		pgpenvSetInt( env, PGPENV_PGPMIME, fOption, PGPENV_PRI_FORCE );
		pgpenvSetInt( env, PGPENV_ARMOR, TRUE, PGPENV_PRI_FORCE );
	}
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_OmitMIMEVersion, FALSE,
						 "%d", &fOption ) ) )
		goto error;
	pgpenvSetInt( env, PGPENV_PGPMIMEVERSIONLINE, !fOption, PGPENV_PRI_FORCE );

	/* Non-default hash algorithm */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_HashAlgorithm, FALSE,
						 "%b%d", &fDefault, &hashalg ) ) )
		goto error;
	if( fDefault ) {
		pgpenvSetInt( env, PGPENV_HASH, hashalg, PGPENV_PRI_FORCE );
	}

	/* Non-default cipher algorithm - only effective with conv encr */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_CipherAlgorithm, FALSE,
						 "%b%d", &fDefault, &cipheralg ) ) )
		goto error;
	if( fDefault ) {
		if( IsNull( pgpCipherGetVTBL ( (PGPCipherAlgorithm)cipheralg ) ) ) {
			pgpDebugMsg( "Unsupported cipher algorithm" );
			err = kPGPError_FeatureNotAvailable;
			goto error;
		}
		pgpenvSetInt( env, PGPENV_CIPHER, cipheralg, PGPENV_PRI_FORCE );
	}

	/* Comment string */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_CommentString, FALSE,
						 "%b%p", &fDefault, &comment ) ) )
		goto error;
	if( fDefault ) {
		pgpenvSetString( env, PGPENV_COMMENT, comment, PGPENV_PRI_FORCE );
	}

	/* Comment string */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						 kPGPOptionType_VersionString, FALSE,
						 "%b%p", &fDefault, &version ) ) )
		goto error;
	if( fDefault ) {
		pgpenvSetString( env, PGPENV_VERSION_STRING,
						 version, PGPENV_PRI_FORCE );
	}
	return kPGPError_NoErr;

error:
	return err;
}





/* Preferred algorithm calculations */

/* Data structure to record preferences of recipients */
struct PGPPreferredAlgs_ {
	PGPUInt32		 n;					/* Number of algorithms */
	PGPByte			*algok;				/* # recips who can accept this */
	PGPUInt32		*votes;				/* Preference voting, lower=better */
	PGPUInt32		counts;				/* Number of recips */
};
typedef struct PGPPreferredAlgs_ PGPPreferredAlgs;


/* Init the structure we will use to choose the conv encryption alg */

	static PGPError
pgpInitPreferredAlgorithms(
	PGPContextRef	 	 context,
	PGPPreferredAlgs	*algInfo
	)
{
	PGPUInt32			n;
	PGPError			err;

	pgpa( pgpaAddrValid( algInfo, PGPPreferredAlgs ) );

	pgpClearMemory( algInfo, sizeof( *algInfo ) );
	
	n = kPGPCipherAlgorithm_Last + 1;
	
	algInfo->n = n;
	algInfo->algok = (PGPByte *)pgpContextMemAlloc( context, n, 0 );
	if ( IsNull( algInfo->algok ) ) {
		err = kPGPError_OutOfMemory;
		goto error;
	}
	algInfo->votes = (PGPUInt32 *)
		pgpContextMemAlloc( context, n * sizeof( PGPUInt32 ), 0 );
	if ( IsNull( algInfo->votes ) ) {
		err = kPGPError_OutOfMemory;
		goto error;
	}
	pgpClearMemory( algInfo->algok, n );
	pgpClearMemory( algInfo->votes, n * sizeof( PGPUInt32 ) );
	return kPGPError_NoErr;

error:
	if( IsntNull( algInfo->algok ) )
		pgpContextMemFree( context, algInfo->algok );
	if( IsntNull( algInfo->votes ) )
		pgpContextMemFree( context, algInfo->votes );
	return err;
}
	
/*
 * Add info for the preferred algs for one recipient.   We record which algs
 * are acceptable and then use preference voting.
 */

	static PGPError
pgpCheckPreferredAlgorithms(
	PGPPreferredAlgs	*algInfo,
	PGPKey				*key,
	RingSet const		*ringSet
	)
{
	RingObject			*ringObj;
	PGPByte const		*prefs;
	PGPSize				 plen;

	//BEGIN MORE CIPHERS SUPPORT - Disastry
	//PGPByte				 algDefault[3];
	PGPByte				 algDefault[8];
	//END MORE CIPHERS SUPPORT

	PGPByte				 alg;
	PGPUInt32			 i;
	PGPError			 err;
    PGPBoolean v3;


	if( IsPGPError( err = pgpGetKeyRingObject( key, TRUE, &ringObj ) ) )
		goto error;

	prefs = ringKeyFindSubpacket (ringObj, ringSet,
					SIGSUB_PREFERRED_ENCRYPTION_ALGS,
					0, &plen, NULL, NULL, NULL, NULL, &err);
	if( IsNull( prefs ) ) {
		/* Use a default.  RSA keys get IDEA, later get CAST.  */
		PGPByte pkalg;
		ringKeyID8 (ringSet, ringObj, &pkalg, NULL);
		//BEGIN RSAv4 SUPPORT MOD - Disastry
		if (IsPGPError(PGPGetKeyBoolean (key, kPGPKeyPropIsV3, &v3)))
			v3 = TRUE;
		if (pkalg <= kPGPPublicKeyAlgorithm_RSA+2 && v3)
		//if (pkalg <= kPGPPublicKeyAlgorithm_RSA+2)
		//END RSAv4 SUPPORT MOD
		{
			algDefault[0] = kPGPCipherAlgorithm_IDEA;
			prefs = algDefault;
			plen = 1;
		} else {
			//BEGIN MORE REASONABLE DEFAULT CIPHERS - Imad R. Faiad
			algDefault[0] = kPGPCipherAlgorithm_AES256;
			algDefault[1] = kPGPCipherAlgorithm_Twofish256;
			algDefault[2] = kPGPCipherAlgorithm_AES192;
			algDefault[3] = kPGPCipherAlgorithm_3DES;
			algDefault[4] = kPGPCipherAlgorithm_AES128;
			algDefault[5] = kPGPCipherAlgorithm_CAST5;
			algDefault[6] = kPGPCipherAlgorithm_IDEA;
			algDefault[7] = kPGPCipherAlgorithm_BLOWFISH;
			prefs = algDefault;
			plen = 8;
			//END MORE REASONABLE DEFAULT CIPHERS

/* Legacy stuff follows
			algDefault[0] = kPGPCipherAlgorithm_CAST5;
			algDefault[1] = kPGPCipherAlgorithm_IDEA;
			algDefault[2] = kPGPCipherAlgorithm_3DES;
			prefs = algDefault;

			//BEGIN MORE CIPHERS SUPPORT - Disastry
			algDefault[3] = kPGPCipherAlgorithm_BLOWFISH;
			algDefault[4] = kPGPCipherAlgorithm_AES128;
			algDefault[5] = kPGPCipherAlgorithm_AES192;
			algDefault[6] = kPGPCipherAlgorithm_AES256;
			algDefault[7] = kPGPCipherAlgorithm_Twofish256;
			plen = 8;
			//plen = 3;
			//END MORE CIPHERS SUPPORT*/
		}
	}

	++algInfo->counts;
	for( i=0; i<plen; ++i ) {
		alg = prefs[i];
		if( alg > algInfo->n )
			continue;
		algInfo->votes[alg-1] += i;	  /* Preference voting, lower=better */
		++algInfo->algok[alg-1];
	}
	return kPGPError_NoErr;
error:
	return err;
}


/*
 * Choose the most popular algorithm of those which were acceptable to all,
 * taking into consideration sender preferences if any
 */

	static PGPError
pgpSetPreferredAlgorithm(
	PGPOptionListRef	 optionList,
	PGPPreferredAlgs	*algInfo,
	PGPEnv				*env
	)
{
	PGPUInt32			 bestvote = 0;	/* Silence warning */
	PGPUInt32			 bestalg = 0;
	PGPUInt32			 i;
	PGPUInt32			 algsOK = 0;	/* Number of acceptable algs */
	PGPCipherAlgorithm	*prefalg;
	PGPCipherAlgorithm	 alg;
	PGPSize				 prefalgLength;
	PGPError			 err = kPGPError_NoErr;

	/* See if sender has a preferred algorithm specification */
	if( IsPGPError( err = pgpFindOptionArgs( optionList,
						kPGPOptionType_PreferredAlgorithms, FALSE,
						"%p%l", &prefalg, &prefalgLength ) ) )
		goto error;
	/* Convert prefalgLength from bytes to number of entries */
	prefalgLength /= sizeof(PGPCipherAlgorithm);
	
	/* If so, let sender have a veto vote too */
	if( prefalgLength != 0 ) {
		++algInfo->counts;
		for( i=0; i<prefalgLength; ++i ) {
			alg = prefalg[i];
			if( (PGPUInt32)alg > algInfo->n )
				continue;
			++algInfo->algok[alg-1];
			/* Don't bother with a preference vote, handled below */
		}
	}

	/* Loop for all algorithms we know about, see how many are OK */
	for( i=0; i<algInfo->n; ++i ) {
		if( algInfo->algok[i] == algInfo->counts ) {
			/* This algorithm was acceptable to all */
			/* Skip if not supported by this library */
			if( IsNull( pgpCipherGetVTBL( (PGPCipherAlgorithm)(i+1) ) ) )
				continue;
			algsOK += 1;
			if (prefalgLength != 0) {
				PGPUInt32 j;
				/* Choose acceptable algorithm which sender likes best */
				for( j=0; j<prefalgLength; ++j ) {
					if (prefalg[j] == (PGPCipherAlgorithm)(i+1))
						break;
				}
				pgpAssert (j < prefalgLength);
				if( bestalg == 0 || j < bestvote ) {
					/* First acceptable, or best one so far */
					bestvote = j;
					bestalg = i+1;
				}
			} else {
				/* Case of no sender preferences, choose favorite of others */
				if( bestalg == 0  ||  algInfo->votes[i] < bestvote ) {
					/* First acceptable, or best one so far */
					bestvote = algInfo->votes[i];
					bestalg = i+1;
				}
			}
		}
	}


	/* If no choice OK for all, choose sender's favorite if any */
	if (algsOK == 0 && prefalgLength != 0) {
		for (i=0; i<prefalgLength; ++i) {
			/* Find highest-sender-preference supported one */
			if( IsntNull( pgpCipherGetVTBL(
							   (PGPCipherAlgorithm) prefalg[i] ) ) ) {
				bestalg = prefalg[i];
				algsOK = 1;
				break;
			}
		}
	}
	
	/* If still no acceptable algorithms, choose most acceptable one */
	if (algsOK == 0) {
		/* Choose an algorithm which we support and most people accept */
		for( i=0; i<algInfo->n; ++i ) {
			if( IsNull( pgpCipherGetVTBL( (PGPCipherAlgorithm)(i+1) ) ) )
				continue;
			algsOK += 1;
			if ( bestalg == 0 || algInfo->algok[i] > bestvote ) {
				/* First acceptable, or best one so far */
				bestvote = algInfo->algok[i];
				bestalg = i+1;
			}
		}
	}
	
	if (algsOK == 0) {
		/* None of the algs we support are acceptable to anyone */
		/* Just choose the first algorithm we support */
		for (i=0; i<kPGPCipherAlgorithm_Last; ++i) {
			if( IsNull( pgpCipherGetVTBL( (PGPCipherAlgorithm)(i+1) ) ) )
				continue;
			algsOK += 1;
			bestalg = i;
			break;
		}
	}

	pgpAssert (algsOK != 0);
	pgpAssert (IsntNull( pgpCipherGetVTBL ( (PGPCipherAlgorithm)bestalg ) ) );

	/* Have choice in bestalg */
	pgpenvSetInt (env, PGPENV_CIPHER, bestalg, PGPENV_PRI_FORCE);

error:
	return err;
}
	
	static PGPError
pgpCleanupPreferredAlgorithms (
	PGPContextRef	 	 context,
	PGPPreferredAlgs	*algInfo
	)
{
	pgpContextMemFree (context, algInfo->votes);
	pgpContextMemFree (context, algInfo->algok);
	return kPGPError_NoErr;
}



/*********** Functions to set up data structures for pipeline *************/


/* Extract conventional encryption info from optionList */

	static PGPError
pgpSetupConventionalEncryption(
	PGPContextRef	 	  context,
	PGPOptionListRef	  optionList,
	PGPEventHandlerProcPtr func,
	PGPUserValue		 userValue,
	PGPConvKey			**convkey
	)
{
	PGPOption			 op;			/* Selected option from list */
	PGPError			 err;			/* Error return code */
	PGPByte				*passPhrase;	/* Pass phrase for conv encr */
	PGPSize				 passLength;	/* Length of passPhrase */

	(void)func;
	(void)userValue;

	/* Init return pointer */
	pgpa( pgpaAddrValid( convkey, PGPConvKey * ) );
	*convkey = NULL;

	if( IsPGPError( err = pgpSearchOptionSingle( optionList,
							kPGPOptionType_ConventionalEncrypt, &op ) ) )
		goto error;
	if( IsOp( op ) ) {
		/* Conventional encryption */
		if( IsPGPError( err = pgpSearchOptionSingle( op.subOptions,
								kPGPOptionType_Passphrase, &op ) ) )
		{
			goto error;
		}
		if( IsntOp( op ) ) {
			pgpDebugMsg( "no passphrase specified for conventional encrypt" );
			err = kPGPError_MissingPassphrase;
			goto error;
		} else {
			if( IsPGPError( err = pgpOptionPtrLength( &op,
								 ( void ** )&passPhrase, &passLength ) ) )
				goto error;
			if ( passLength == 0 ) {
				pgpDebugMsg( "passphrases of length 0 are "\
					"illegal for conventional encryption" );
				err	= kPGPError_BadParams;
				goto error;
			}
		}
		if( IsNull( ( *convkey = (PGPConvKey *)pgpContextMemAlloc(
									  context, sizeof( PGPConvKey ),
									  0 ) ) ) ) {
			err = kPGPError_OutOfMemory;
			goto error;
		}
		(*convkey)->pass = NULL;
		(*convkey)->next = NULL;
		(*convkey)->stringToKey = 0;
		(*convkey)->pass = (char *)pgpContextMemAlloc( context, passLength,
					0 );
		if( IsNull( (*convkey)->pass ) ) {
			err = kPGPError_OutOfMemory;
			goto error;
		}
		pgpCopyMemory( passPhrase, (char *)(*convkey)->pass, passLength );
		(*convkey)->passlen = passLength;
	}
	return kPGPError_NoErr;

error:
	if( IsntNull( *convkey ) ) {
		pgpClearMemory( (*convkey)->pass, (*convkey)->passlen );
		pgpContextMemFree( context, (char *)(*convkey)->pass );
		pgpContextMemFree( context, *convkey );
	}
	return err;
}


/* Service routine for pgpSetupPublicKeyEncryption, to do checks for a
 * single key, and append it to pubkeys list */

	static PGPError
pgpSetupPubkey(
	PGPContextRef	 	  context,
	PGPOptionListRef	  optionList,
	PGPKey				 *key,
	PGPValidity			 failValidity,
	PGPValidity			 warnValidity,
	PGPPreferredAlgs	*preferredAlgs,
	PGPPubKey		   **pubkeys,
	PGPKeySetRef		 warnKeySet
	)
{
	PGPError			 err;			/* Error return code */
	RingObject			*ringKey;		/* Keyring obj for encryption key */
	RingSet const		*ringSet;		/* Lowlevel keyring set for enc key */
	PGPPubKey			*pubkey;		/* Internal struct for current key */

	if( IsPGPError( err = pgpGetKeyRingObject( key, FALSE, &ringKey ) ) )
		goto error;
	if( IsPGPError( err = pgpGetKeyRingSet( key, FALSE, &ringSet ) ) )
		goto error;
	if( IsPGPError( err = pgpCheckKeyValidity( context, optionList,
					key, ringSet, failValidity, warnValidity, warnKeySet,
					NULL ) ) )
		goto error;
	if( IsPGPError( err = pgpCheckPreferredAlgorithms( preferredAlgs, key,
							ringSet ) ) )
		goto error;
	pubkey = ringKeyPubKey( ringSet, ringKey, PGP_PKUSE_ENCRYPT );
	if( IsNull( pubkey ) ) {
/*		err = kPGPError_KeyUnusableForEncryption; */
		err = ringSetError( ringSet ) -> error;
		goto error;
	}
	pubkey->next = *pubkeys;
	*pubkeys = pubkey;
	return kPGPError_NoErr;

error:
	return err;
}


	
/* Extract public key encryption info from optionList */

	static PGPError
pgpSetupPublicKeyEncryption(
	PGPContextRef	 	  context,
	PGPOptionListRef	  optionList,
	PGPEnv				 *env,
	PGPPubKey			**pubkeys,
	PGPKeyRef			 *enckeyref
	)
{
	PGPOption			 op;			/* Selected option from list */
	PGPError			 err;			/* Error return code */
	PGPInt32			 keyCount;		/* Number of key we are doing */
	PGPKey				*key;			/* PGPKey structure for current key */
	PGPUserID			*userid;		/* UserID to encrypt to */
	PGPKeySet			*keySet;		/* Keyset to encrypt to */
	PGPKeyList			*keyList;		/* Sorted version of keySet */
	PGPKeyIter			*keyIter;		/* Iterator over keyList */
	PGPValidity			 failValidity,	/* Fail on keys less valid */
						 warnValidity;	/* Warn on keys less valid */
	PGPPreferredAlgs	 preferredAlgs;	/* Preferred algorithm data */
	PGPKeySet			*warnKeySet;	/* Keys with warnable trusts */

	/* Init return pointer */
	pgpa( pgpaAddrValid( pubkeys, PGPPubKey * ) );
	pgpa( pgpaAddrValid( enckeyref, PGPKeyRef ) );
	*pubkeys = NULL;
	*enckeyref = kInvalidPGPKeyRef;
	warnKeySet = NULL;
	keyList = NULL;
	keyIter = NULL;

	/* Initialize for loops below */
	if( IsPGPError( err = pgpInitPreferredAlgorithms( context,
													  &preferredAlgs ) ) )
		goto error;
	if( IsPGPError( err = pgpGetMinValidity( optionList,
					&failValidity, &warnValidity ) ) )
		goto error;

	/* Accumulate warning keys here */
	if( IsPGPError( err = PGPNewKeySet( context, &warnKeySet ) ) )
		goto error;

	/* Find any encryption keys specified as keys */
	keyCount = 0;
	if( IsPGPError( err = pgpSearchOption( optionList,
							kPGPOptionType_EncryptToKey, keyCount, &op ) ) )
		goto error;
	while( IsOp( op ) ) {
		if( IsPGPError( err = pgpOptionPtr( &op, (void **)&key ) ) )
			goto error;
		pgpa(pgpaPGPKeyValid(key));
		if( !pgpKeyIsValid(key) ) {
			pgpDebugMsg( "Error: invalid EncryptToKey keyref" );
			err = kPGPError_BadParams;
			goto error;
		}
		if( *enckeyref == kInvalidPGPKeyRef )
			*enckeyref = key;
		if( IsPGPError( err = pgpSetupPubkey( context, optionList, key,
											  failValidity, warnValidity,
											  &preferredAlgs, pubkeys,
											  warnKeySet ) ) )
			goto error;
		if( IsPGPError( err = pgpSearchOption( optionList,
						  kPGPOptionType_EncryptToKey, ++keyCount, &op ) ) )
			goto error;
	}

	/* Find any encryption keys specified as userids */
	keyCount = 0;
	if( IsPGPError( err = pgpSearchOption( optionList,
						 kPGPOptionType_EncryptToUserID, keyCount, &op ) ) )
		goto error;
	while( IsOp( op ) ) {
		if( IsPGPError( err = pgpOptionPtr( &op, (void **)&userid ) ) )
			goto error;
		pgpa(pgpaPGPUserIDValid(userid));
		if( !pgpUserIDIsValid(userid) ) {
			pgpDebugMsg( "Error: invalid EncryptToUserID useridref" );
			err = kPGPError_BadParams;
			goto error;
		}
		if( IsPGPError( err = pgpGetUserIDKey( userid, FALSE, &key ) ) )
			goto error;
		if( *enckeyref == kInvalidPGPKeyRef )
			*enckeyref = key;
		if( IsPGPError( err = pgpSetupPubkey( context, optionList, key,
											  failValidity, warnValidity,
											  &preferredAlgs, pubkeys,
											  warnKeySet ) ) )
			goto error;
		if( IsPGPError( err = pgpSearchOption( optionList,
						kPGPOptionType_EncryptToUserID, ++keyCount, &op ) ) )
			goto error;
	}

	/* Find any encryption keys specified as keysets */
	keyCount = 0;
	if( IsPGPError( err = pgpSearchOption( optionList,
						 kPGPOptionType_EncryptToKeySet, keyCount, &op ) ) )
		goto error;
	while( IsOp( op ) ) {
		PGPUInt32 keySetCount;
		if( IsPGPError( err = pgpOptionPtr( &op, (void **)&keySet ) ) )
			goto error;
		pgpa(pgpaPGPKeySetValid(keySet));
		if( !pgpKeySetIsValid(keySet) ) {
			pgpDebugMsg( "Error: invalid EncryptToKeySet keyset" );
			err = kPGPError_BadParams;
			goto error;
		}
		if( IsPGPError( err = PGPCountKeys( keySet, &keySetCount ) ) )
			goto error;
		if ( keySetCount < 1 ) {
			pgpDebugMsg( "Error: empty EncryptToKeySet keyset" );
			err = kPGPError_BadParams;
			goto error;
		}
		if( IsPGPError( err = PGPOrderKeySet( keySet, kPGPAnyOrdering,
											  &keyList ) ) )
			goto error;
		if( IsPGPError( err = PGPNewKeyIter ( keyList, &keyIter ) ) )
			goto error;
	
		while( IsntPGPError( err = PGPKeyIterNext( keyIter, &key ) ) ) {
		
			if( *enckeyref == kInvalidPGPKeyRef )
				*enckeyref = key;
			if( IsPGPError( err = pgpSetupPubkey( context, optionList, key,
											  failValidity, warnValidity,
											  &preferredAlgs, pubkeys,
											  warnKeySet ) ) )
				goto error;
		}
		PGPFreeKeyIter( keyIter );
		keyIter = NULL;
		PGPFreeKeyList( keyList );
		keyList = NULL;
		if( IsPGPError( err = pgpSearchOption( optionList,
						kPGPOptionType_EncryptToKeySet, ++keyCount, &op ) ) )
				goto error;
	}

	if( IsntNull( warnKeySet ) ) {
		PGPUInt32	numKeys;
		
		if ( IsPGPError( PGPCountKeys( warnKeySet, &numKeys ) ) )
			goto error;
			
		if( numKeys > 0 ) {
			if( IsPGPError( pgpWarnUser( context, optionList,
								  kPGPError_KeyInvalid, warnKeySet ) ) )
				goto error;
		}
		PGPFreeKeySet( warnKeySet );
		warnKeySet = NULL;
	}

	if( IsntNull( *pubkeys ) ) {
		if( IsPGPError( err = pgpSetPreferredAlgorithm( optionList,
								&preferredAlgs, env ) ) )
			goto error;
	}
	pgpCleanupPreferredAlgorithms( context, &preferredAlgs );
	return kPGPError_NoErr;

error:
	pgpCleanupPreferredAlgorithms( context, &preferredAlgs );
	while( IsntNull( *pubkeys ) ) {
		PGPPubKey *pk1 = pgpPubKeyNext (*pubkeys);
		pgpPubKeyDestroy (*pubkeys);
		*pubkeys = pk1;
	}
	if( IsntNull( warnKeySet ) )
		PGPFreeKeySet( warnKeySet );
	if( IsntNull( keyList ) )
		PGPFreeKeyList( keyList );
	if( IsntNull( keyIter ) )
		PGPFreeKeyIter( keyIter );
	return err;
}




/* Extract public key signature info from optionList */
/* Currently only allows a single signing key */

	static PGPError
pgpSetupSigning(
	PGPContextRef	 	  context,
	PGPOptionListRef	  optionList,
	PGPBoolean			  fHaveEncryption,
	PGPEnv				 *env,
	PGPEventHandlerProcPtr func,
	PGPUserValue		  userValue,
	PGPBoolean			 knownBinaryInput,
	PGPBoolean			 sepsig,
	PGPSigSpec			**sigspec,
	PGPKeyRef			 *signkeyref
	)
{
	PGPOption			 op;			/* Selected option from list */
	PGPError			 err;			/* Error return code */
	PGPKey				*signKey;		/* PGPKey struct for signing key */
	PGPKeySet			*signKeySet;	/* PGPKeySet holding signKey */
	PGPSecKey			*seckey;		/* Internal struct for signKey */
	RingObject			*ringKey;		/* Keyring obj for signing key */
	RingSet const		*ringSet;		/* Lowlevel keyring set for enc key */
	PGPByte				 signMode;		/* Text vs binary mode for sig */
	PGPByte				*passPhrase;	/* Signing key pass phrase */
	PGPSize				 passLength;	/* Length of passPhrase */
	PGPBoolean			 hashedPhrase = FALSE; /* True if passkey given */
	PGPValidity			 failValidity,	/* Fail on keys less valid */
						 warnValidity;	/* Warn on keys less valid */
	PGPInt32			 rslt;			/* Success code on unlock */

	(void)func;
	(void)userValue;

	/* Init return pointers */
	pgpa( pgpaAddrValid( sigspec, PGPSigSpec * ) );
	pgpa( pgpaAddrValid( signkeyref, PGPKeyRef ) );
	*sigspec = NULL;
	*signkeyref = kInvalidPGPKeyRef;
	seckey = NULL;
	signKeySet = NULL;
	
	/* See if signature requested.  Only one signing key allowed. */
	if( IsPGPError( err = pgpSearchOptionSingle( optionList,
							kPGPOptionType_SignWithKey, &op ) ) )
		goto error;

	if( IsOp( op ) ) {
		/* Get signing key and data */
		if( IsPGPError( err = pgpOptionPtr( &op, (void **)&signKey ) ) )
			goto error;
		pgpa(pgpaPGPKeyValid(signKey));
		if( !pgpKeyIsValid(signKey) ) {
			pgpDebugMsg( "Error: invalid SignWithKey keyref" );
			err = kPGPError_BadParams;
			goto error;
		}
		*signkeyref = signKey;
		if( IsPGPError( err = pgpGetKeyRingObject( signKey, FALSE, &ringKey )))
			goto error;
		if( IsPGPError( err = pgpGetKeyRingSet( signKey, FALSE, &ringSet ) ) )
			goto error;
		if( IsPGPError( err = pgpGetMinValidity( optionList,
						&failValidity, &warnValidity ) ) )
			goto error;
		if( IsPGPError( err = pgpCheckKeyValidity( context, optionList,
						signKey, ringSet, failValidity, warnValidity,
						NULL, NULL ) ) )
			goto error;
		seckey = ringSecSecKey( ringSet, ringKey, PGP_PKUSE_SIGN );
		if( IsNull( seckey ) ) {
/*			err = kPGPError_KeyUnusableForSignature; */
			err = ringSetError( ringSet ) -> error;
			goto error;
		}

		/* Try to unlock secret key */
		/* First see if a passphrase is needed at all for signing key */
		rslt = pgpSecKeyUnlock( seckey, env, NULL, 0, FALSE );
		if ( rslt <= 0 ) {
			/* Failed, must try passphrase */
			if( IsPGPError( err = pgpFindOptionArgs( op.subOptions,
								 kPGPOptionType_Passphrase, FALSE,
								 "%p%l", &passPhrase, &passLength ) ) )
				goto error;
			if( IsNull( passPhrase ) ) {
				hashedPhrase = TRUE;
				if( IsPGPError( err = pgpFindOptionArgs( op.subOptions,
								kPGPOptionType_Passkey, FALSE,
								"%p%l", &passPhrase, &passLength ) ) )
					goto error;
				if( IsNull( passPhrase ) ) {
					err = kPGPError_MissingPassphrase;
					goto error;
				}
			}
			rslt = pgpSecKeyUnlock( seckey, env, (char *) passPhrase,
									passLength, hashedPhrase );
			if( rslt <= 0 ) {
				err = kPGPError_BadPassphrase;
				goto error;
			}
		}
		/* At this point we have unlocked successfully */
		/* See if text or binary mode */
		if( knownBinaryInput )
		{
			signMode = PGP_SIGTYPE_BINARY;
		}
		else
		{
			signMode =
				( PGPByte ) ( pgpenvGetInt( env, PGPENV_TEXTMODE, NULL, NULL ) ?
							PGP_SIGTYPE_TEXT : PGP_SIGTYPE_BINARY );
		}
		
		*sigspec = pgpSigSpecCreate( env, seckey, signMode );
	}

	if( sepsig && IsNull( *sigspec ) ) {
		/* Error, detached sig requested without signing! */
		pgpDebugMsg( "Error: detached signature without signing key" );
		err = kPGPError_BadParams;
		goto error;
	}
	if( sepsig && fHaveEncryption ) {
		/* Error, can't do detached sig if encrypting */
		pgpDebugMsg( "Error: detached signature with encryption" );
		err = kPGPError_BadParams;
		goto error;
	}
	return kPGPError_NoErr;

error:
	if( IsntNull( *sigspec ) )
		pgpSigSpecDestroy (*sigspec);
	if( IsntNull( seckey ) )
		pgpSecKeyDestroy (seckey);
	if( IsntNull( signKeySet ) )
		PGPFreeKeySet( signKeySet );
	return err;
}



/************************** Main encode function ****************************/


/* All state information for pgpEncode is kept in a struct like this */
struct pgpEncodeJobState_
{
	PGPContextRef		 context;		/* Context pointer */
	PGPOptionListRef	 optionList;	/* List of all our options */
	PGPOptionListRef	 newOptionList;	/* Options changed by callback */
	PGPError			 err;			/* Error */
	PGPPipeline			*head, **tail;	/* Low level pipeline */
	PGPConvKey			*convkey;		/* Conventional encryption params */
	PGPSigSpec			*sigspec;		/* Message signing params */
	PGPPubKey			*pubkeys;		/* Message encryption keys */
	PgpLiteralParams	 literal;		/* Filename, type info */
	PGPBoolean			 sepsig;		/* Create detached signature */
	PFLConstFileSpecRef	 inFileRef;		/* Input filename handle */
	PGPFileRead			*pfrin;			/* Input file reading structure */
	PGPByte				*inBufPtr;		/* Input buffer pointer */
	PGPSize				 inBufLength;	/* Size of input buffer */
	PFLConstFileSpecRef	 outFileRef;	/* Output filename handle */
	PGPFile				*pfout;			/* Output file writing structure */
	PGPByte				*outBufPtr;		/* Output buffer pointer */
	PGPByte			   **outBufPtrPtr;	/* Dynamically allocated buf ptr */
	PGPSize				 outBufMaxLength; /* Allocated size of outBufPtr */
	PGPSize				*outBufUsedLength; /* Amount output to outBufPtr */
	PGPPipeline			*outPipe;		/* Output-buffer pipeline module */
	PGPEnv				*env;			/* Environment for low-level fns */
	PGPRandomContext	*rng;			/* Random state */
	PGPOption			 op;			/* Selected option from list */
	PGPEventHandlerProcPtr func;		/* Pointer to user callback func */
	PGPUserValue		 userValue;		/* Arg to callback func */
	PGPBoolean			 fNullEvents;	/* True if user wants null events */
	PGPOutputFormat		 outputFormat;	/* Format of output data, PGP vs ... */
	PGPKeyRef			 enckeyref;		/* One of the encryption keys */
	PGPKeyRef			 signkeyref;	/* One of the signature keys */
};
typedef struct pgpEncodeJobState_ pgpEncodeJobState;

static PGPError sPackageOutputX509( pgpEncodeJobState  *s );


/* Local callback function */

	static PGPError
encodeLocalCallBack (
	void				*arg,
	PGPFileOffset		soFar,
	PGPFileOffset		total
	)
{
	PGPError			  err = kPGPError_NoErr;
	pgpEncodeJobState	 *s = ( pgpEncodeJobState * ) arg;

	if( IsntNull( s->func )  &&  s->fNullEvents ) {
		err = pgpEventNull( s->context, &s->newOptionList, s->func,
							s->userValue, soFar, total );
		pgpCleanupOptionList( &s->newOptionList );
	}
	return err;
}

	static PGPError
encodePKEncryptCallBack (
	void				*arg,
	int					code
	)
{
	PGPError			  err = kPGPError_NoErr;
	pgpEncodeJobState	 *s = ( pgpEncodeJobState * ) arg;

	(void) code;

	if( IsntNull( s->func )  &&  s->fNullEvents ) {
		err = pgpEventNull( s->context, &s->newOptionList, s->func,
							s->userValue, 0, 1 );
		pgpCleanupOptionList( &s->newOptionList );
	}
	return err;
}




static const PGPOptionType encodeOptionSet[] = {
	kPGPOptionType_InputFileRef,
	kPGPOptionType_InputBuffer,
	kPGPOptionType_InputFileName,
	kPGPOptionType_OutputFileRef,
	kPGPOptionType_OutputBuffer,
	kPGPOptionType_OutputAllocatedBuffer,
	kPGPOptionType_AppendOutput,
	kPGPOptionType_DiscardOutput,
	kPGPOptionType_LocalEncoding,
	kPGPOptionType_RawPGPInput,
	kPGPOptionType_EncryptToKey,
	kPGPOptionType_EncryptToKeySet,
	kPGPOptionType_EncryptToUserID,
	kPGPOptionType_SignWithKey,
	kPGPOptionType_ConventionalEncrypt,
	kPGPOptionType_Passphrase,
	kPGPOptionType_Passkey,
	kPGPOptionType_DetachedSignature,
	kPGPOptionType_CipherAlgorithm,
	kPGPOptionType_HashAlgorithm,
	kPGPOptionType_FailBelowValidity,
	kPGPOptionType_WarnBelowValidity,
	kPGPOptionType_PGPMIMEEncoding,
	kPGPOptionType_OutputLineEndType,
	kPGPOptionType_EventHandler,
	kPGPOptionType_SendNullEvents,
	kPGPOptionType_AskUserForEntropy,
	kPGPOptionType_ArmorOutput,
	kPGPOptionType_DataIsASCII,
	kPGPOptionType_ClearSign,
	kPGPOptionType_ForYourEyesOnly,
	kPGPOptionType_CommentString,
	kPGPOptionType_Compression,
	kPGPOptionType_VersionString,
	kPGPOptionType_OmitMIMEVersion,
	kPGPOptionType_PreferredAlgorithms,
	kPGPOptionType_OutputFormat,
	/* really only for PGPExport, but that routine calls this */
	kPGPOptionType_ExportPrivateKeys,
	kPGPOptionType_ExportPrivateSubkeys,
	kPGPOptionType_ExportFormat,
	kPGPOptionType_ExportKeySet,
	kPGPOptionType_ExportKey,
	kPGPOptionType_ExportUserID,
	kPGPOptionType_ExportSig
};


/* Main entry point for this module */

	PGPError
pgpEncodeInternal(
	PGPContextRef		context,
	PGPOptionListRef	optionList
	)
{
	pgpEncodeJobState	 jobState,		/* State in a struct */
						*s=&jobState;	/* Use s-> to access all state  */
	PGPByte				*charMap;		/* Charmap for armor output */
	PGPLineEndType		 lineEnd;		/* Line endings for armor output */
	PGPBoolean			 fEncrypt;		/* Encryption */
	PGPBoolean			 fSign;			/* Signature */
	PGPUInt32			 fRawPGPInput;	/* Don't put on literal packet */
	PGPUInt32			 fAppendOutput;	/* Append to existing outfile */
	PGPOption			 op;			/* Selected option from list */
	PGPByte				*sessionKey = NULL;	/* session key for encryption */
	PGPSize				 sessionKeyLength;
	PGPFileDataType		 inFileDataType;	/* Input file data trype (ascii or binary) */
	//BEGIN TRAP ERRORS FROM pgpEventFinal - Imad R. Faiad
	PGPError			 TrapErr = kPGPError_NoErr;	
	//END TRAP ERRORS FROM pgpEventFinal	
	
	/* Initialize pointers to NULL for easier error cleanup */
	pgpClearMemory( s, sizeof( *s ) );
	s->context = context;
	s->optionList = optionList;
	s->tail = &s->head;

	if (IsPGPError( s->err = pgpCheckOptionsInSet( optionList,
						encodeOptionSet, elemsof( encodeOptionSet ) ) ) )
		return s->err;

	/* Get copies of info from context */
	s->rng = pgpContextGetX9_17RandomContext ( s->context );

	/* Get a copy of the env to work with so our changes aren't permanent */
	if( IsPGPError( pgpenvCopy( pgpContextGetEnvironment( s->context ),
								&s->env ) ) )
		goto error;
	
	/* Set up PGPEnv structure for library internals */
	if( IsPGPError( s->err = pgpMakeEnvFromOptionList( s->optionList,
							s->env ) ) )
		goto error;

	/* Set up callback pointers and data */
	if( IsPGPError( s->err = pgpSetupCallback( s->optionList,
							 &s->func, &s->userValue, &s->fNullEvents ) ) )
		goto error;
	s->err = pgpEventInitial( s->context, &s->newOptionList,
							  s->func, s->userValue );
	pgpCleanupOptionList( &s->newOptionList );
	if( IsPGPError( s->err ) )
		goto error;

	/* Set up for conventional encryption if requested */
	if( IsPGPError( s->err = pgpSetupConventionalEncryption( s->context,
							  s->optionList, s->func, s->userValue,
							  &s->convkey ) ) )
		goto error;

	/* Set up for public key encryption if requested */
	if( IsPGPError( s->err = pgpSetupPublicKeyEncryption( s->context,
							  s->optionList,
							  s->env, &s->pubkeys, &s->enckeyref ) ) )
		goto error;

	/* Determine if a detached signature has been requested */
	if( IsPGPError( s->err = pgpSearchOptionSingle( s->optionList,
							kPGPOptionType_DetachedSignature, &op ) ) )
		goto error;
		
	s->sepsig = IsOp( op );
	
	/* Check output format and handle X.509 related formats */
	if( IsPGPError( s->err = pgpFindOptionArgs( s->optionList,
						 kPGPOptionType_OutputFormat, FALSE,
						 "%d", &s->outputFormat ) ) )
		goto error;
	if( s->outputFormat >= kPGPOutputFormat_X509CertReqInPKCS7 ) {
		/* Handle output X.509 data */
		s->err = sPackageOutputX509 (s);
		goto error;
	}

	/* Set up input filenames and open file if any */
	if( IsPGPError( s->err = pgpSetupInput( s->context, s->optionList,
					&s->literal, s->rng, TRUE, s->sepsig,
					&s->inFileRef, &s->pfrin, &inFileDataType,
					&s->inBufPtr, &s->inBufLength ) ) )
		goto error;

	/* Set up for any signing operation requested */
	if( IsPGPError( s->err = pgpSetupSigning( s->context, s->optionList,
				  (PGPBoolean) ( IsntNull( s->convkey )
								 || IsntNull( s->pubkeys ) ),
				  s->env, s->func, s->userValue,
				  (PGPBoolean) (inFileDataType == kPGPFileDataType_Binary),
				  s->sepsig, &s->sigspec, &s->signkeyref ) ) )
		goto error;

	/* Set up main processing pipeline (will set up output afterwards) */
	if( IsPGPError( s->err = pgpFindOptionArgs( s->optionList,
						 kPGPOptionType_RawPGPInput, FALSE,
						 "%d", &fRawPGPInput ) ) )
		goto error;

	/* Allocate space for session key if needed */
	if( s->convkey || s->pubkeys ) {
		sessionKey = (PGPByte *)PGPNewSecureData(
					PGPGetContextMemoryMgr( context ),
					//BEGIN FIX FOR LARGE CIPHERS - Imad R. Faiad
					//PGP_CIPHER_MAXKEYSIZE, 0 );
					PGP_CIPHER_MAXKEYSIZE+1, 0 );
					//END FIX FOR LARGE CIPHERS
		if (!sessionKey)
			goto error;
	}
	s->tail = pgpEncryptPipelineCreate( context, &s->head, s->env, NULL,
			s->rng, s->convkey, s->pubkeys, s->sigspec,
			(fRawPGPInput?NULL:&s->literal), s->sepsig, sessionKey,
			(PGPBoolean) (inFileDataType == kPGPFileDataType_Binary),
			encodePKEncryptCallBack, s, &sessionKeyLength, &s->err );
	if( IsPGPError( s->err ) )
		goto error;
	
	if( IsntNull( sessionKey ) ) {
		s->err = pgpEventEncryption( s->context, &s->newOptionList,
									 s->func, s->userValue,
									 (PGPCipherAlgorithm)sessionKey[0],
									 sessionKey, sessionKeyLength );
		pgpCleanupOptionList( &s->newOptionList );
		PGPFreeData( sessionKey );		/* wipes it automatically */
		sessionKey = NULL;
	}

	/* Add a text conversion if needed for output */
	if( pgpenvGetInt( s->env, PGPENV_ARMOR, NULL, NULL ) ) {
		/* Ascii armoring output */
		/* Convert to local line endings if appropriate */
		charMap = (PGPByte *)pgpenvGetPointer( s->env, PGPENV_CHARMAPTOLATIN1,
											   NULL );
		lineEnd = pgpGetDefaultLineEndType ();
		if( IsPGPError( s->err = pgpSearchOptionSingle( optionList,
							  kPGPOptionType_OutputLineEndType, &s->op ) ) )
			goto error;
		if( IsOp( s->op ) ) {
			PGPUInt32 uintLineEnd;
			if( IsPGPError( s->err = pgpOptionUInt( &s->op, &uintLineEnd ) ) )
				goto error;
			lineEnd = (PGPLineEndType)uintLineEnd;
		}
		s->tail = pgpTextFiltCreate( s->context, s->tail, charMap,0,lineEnd );
	}

	/*
	 * Check for sufficient entropy.  Error if not enough, unless
	 * AskUserForEntropy option is specified, in which case we give an event.
	 */
	if( IsntNull( s->sigspec ) || IsntNull( s->pubkeys ) ) {
		if( !PGPGlobalRandomPoolHasMinimumEntropy() ) {
			PGPUInt32 fEntropyEvent;
			if( IsPGPError( s->err = pgpFindOptionArgs( s->optionList,
								kPGPOptionType_AskUserForEntropy,
							   FALSE, "%d", &fEntropyEvent ) ) )
				goto error;
			if( !fEntropyEvent ) {
				s->err = kPGPError_OutOfEntropy;
				goto error;
			}
			while( !PGPGlobalRandomPoolHasMinimumEntropy() ) {
				PGPUInt32 entropy_needed;
				entropy_needed = PGPGlobalRandomPoolGetMinimumEntropy() -
								 PGPGlobalRandomPoolGetEntropy();
				s->err = pgpEventEntropy( s->context, &s->newOptionList,
									  s->func, s->userValue, entropy_needed );
				pgpCleanupOptionList( &s->newOptionList );
				if( IsPGPError( s->err ) )
					goto error;
			}
		}
	}

	/* Set up output pipeline */
	fEncrypt = (PGPBoolean) (IsntNull( s->pubkeys ) || IsntNull( s->convkey ));
	fSign = (PGPBoolean) IsntNull( s->sigspec );
	if( IsPGPError( s->err = pgpFindOptionArgs( s->optionList,
						 kPGPOptionType_AppendOutput, FALSE,
						 "%d", &fAppendOutput ) ) )
		goto error;
	if( IsPGPError( s->err = pgpSetupOutputPipeline( s->context, s->optionList,
							s->env, fEncrypt, fSign, s->sepsig,
							(PGPBoolean)fAppendOutput, FALSE,
							&s->tail, &s->outFileRef, &s->pfout,
							&s->outBufPtr, &s->outBufPtrPtr,
							&s->outBufMaxLength, &s->outBufUsedLength,
							&s->outPipe ) ) )
		goto error;

	/* Now pump the data through the pipes */
	if( s->inFileRef ) {
		/* File input */
		if( IsntNull( s->func ) && s->fNullEvents ) {
			pgpFileReadSetCallBack( s->pfrin, encodeLocalCallBack, s );
		}
		s->err = pgpFileReadPump( s->pfrin, s->head );
		pgpFileReadDestroy( s->pfrin );
		s->pfrin = NULL;
		if( IsPGPError( s->err ) )
			goto error;
		s->err = s->head->sizeAdvise( s->head, 0 );
		if( IsPGPError( s->err ) )
			goto error;
	} else {
		/* Buffer input */
		if( IsntNull( s->func ) && s->fNullEvents ) {
			s->err = pgpPumpMem( s->head, s->inBufPtr, s->inBufLength,
								 encodeLocalCallBack, s );
		} else {
			s->err = pgpPumpMem( s->head, s->inBufPtr, s->inBufLength,
								 NULL, NULL );
		}
		if( IsPGPError( s->err ) )
			goto error;
	}

	/* Get output buffer bytes-used info if appropriate */
	if( s->outPipe ) {
		if( IsntNull( s->outBufPtrPtr ) ) {
			/* Dynamically allocated buffer - tell user size & position */
			if( IsPGPError( s->err = pgpGetVariableMemOutput( s->outPipe,
							s->outBufMaxLength, s->outBufPtrPtr,
							s->outBufUsedLength ) ) )
				goto error;
		} else {
			/* Fixed size buffer - tell user actual size used */
			pgpAssert( IsntNull( s->outBufPtr ) );
			if( IsPGPError( s->err = pgpGetMemOutput( s->outPipe,
						s->outBufMaxLength, s->outBufUsedLength ) ) )
				goto error;
		}
	}

	/* Get PGPMIME header offset if appropriate */
	if( IsPGPError( s->err = pgpGetPGPMIMEBodyOffset( s->head, 
					s->optionList ) ) )
		goto error;

	/* Now we can tear down the pipeline */
	s->head->teardown( s->head );
	s->head = NULL;

	/* Done, clean up and return */
	s->err = kPGPError_NoErr;

error:

	if( IsntNull( sessionKey ) ) {
		PGPFreeData( sessionKey );
		sessionKey = NULL;
	}
	if( IsntNull( s->env ) ) {
		pgpenvDestroy( s->env );
		s->env = NULL;
	}
	if( IsntNull( s->head ) ) {
		s->head->teardown( s->head );
		s->head = NULL;
	}
	if( IsntNull( s->sigspec ) ) {
		PGPSecKey *skey = pgpSigSpecSeckey(s->sigspec);
		if( IsntNull( skey ) )
			pgpSecKeyDestroy(skey);
		pgpSigSpecDestroy( s->sigspec );
		s->sigspec = NULL;
	}
	while( IsntNull( s->pubkeys ) ) {
		PGPPubKey *pk1 = pgpPubKeyNext( s->pubkeys );
		pgpPubKeyDestroy( s->pubkeys );
		s->pubkeys = pk1;
	}
	if( IsntNull( s->convkey ) ) {
		pgpClearMemory( (s->convkey)->pass, (s->convkey)->passlen );
		pgpContextMemFree( context, (char *)(s->convkey)->pass );
		pgpContextMemFree( context, s->convkey );
		s->convkey = NULL;
	}
	if( IsntNull( s->literal.filename ) ) {
		pgpContextMemFree( context, (char *)s->literal.filename );
		s->literal.filename = NULL;
	}
	if( IsntNull( s->pfrin ) ) {
		pgpFileReadDestroy( s->pfrin );
		s->pfrin = NULL;
	}
	if ( s->err != kPGPError_NoErr && IsntNull( s->outFileRef ) ) {
		PFLFileSpecDelete( s->outFileRef );
		s->outFileRef = NULL;
	}

	/* Notify user via callback of error if requested */
	if( IsPGPError( s->err ) && IsntNull( s->func ) ) {
		(void)pgpEventError( s->context, &s->newOptionList, s->func,
							 s->userValue, s->err, NULL );
		pgpCleanupOptionList( &s->newOptionList );
	}

	//BEGIN TRAP ERRORS FROM pgpEventFinal - Imad R. Faiad
	//(void)pgpEventFinal( s->context, &s->newOptionList, s->func,
	//					 s->userValue );
	TrapErr = pgpEventFinal( s->context, &s->newOptionList, s->func,
						 s->userValue );
	

	if( IsPGPError( TrapErr ) ) {
		s->err = TrapErr;
	}
	//END TRAP ERRORS FROM pgpEventFinal

	pgpCleanupOptionList( &s->newOptionList );

	return s->err;
}


/************************** X509 encode function ****************************/

static PGPError
sPackageOutputX509( pgpEncodeJobState  *s )
{
	PGPOption			passop;
	PGPOptionListRef	passphrase = NULL;
	PGPCipherAlgorithm	encalg;
	PGPByte				*outBuf = NULL;
	PGPSize				 outBufLength;
	PGPBoolean			 fEncrypt;
	PGPBoolean			 fSign;
	PGPBoolean			 fMustFreeBuf;
	PGPUInt32			 fAppendOutput;

	/* Set up for any signing operation requested */
	if( IsPGPError( s->err = pgpSetupSigning( s->context, s->optionList,
				  (PGPBoolean) ( IsntNull( s->convkey )
								 || IsntNull( s->pubkeys ) ),
				  s->env, s->func, s->userValue, FALSE,
				  s->sepsig, &s->sigspec, &s->signkeyref ) ) )
		goto error;

	if( IsntNull( s->convkey ) ||
		( IsntNull( s->pubkeys ) &&
		  IsntNull( pgpPubKeyNext( s->pubkeys ) ) ) ||
		( IsntNull( s->sigspec) &&
		  IsntNull( pgpSigSpecNext (s->sigspec) ) ) ||
		s->sepsig )
		return kPGPError_BadParams;

	encalg = (PGPCipherAlgorithm) pgpenvGetInt (s->env, PGPENV_CIPHER,
												NULL, NULL);

	/* Get passphrase from suboptions of signwithkey */
	passphrase = NULL;
	if( s->sigspec ) {
		PGPOption signop;

		if( IsPGPError( s->err = pgpSearchOptionSingle( s->optionList,
									kPGPOptionType_SignWithKey, &signop ) ) )
			goto error;
		if( IsPGPError( s->err = pgpSearchOptionSingle( signop.subOptions,
									kPGPOptionType_Passphrase, &passop ) ) )
			goto error;
		if( IsntOp( passop ) ) {
			if( IsPGPError( s->err = pgpSearchOptionSingle( signop.subOptions,
										kPGPOptionType_Passkey, &passop ) ) )
				goto error;
		}

		if( IsOp( passop ) ) {
			PGPOption passopcopy;
			pgpCopyOption( s->context, &passop, &passopcopy );
			passphrase = pgpNewOneOptionList( s->context, &passopcopy );
		}
	}

	/*
	 * Check for sufficient entropy.  Error if not enough, unless
	 * AskUserForEntropy option is specified, in which case we give an event.
	 */
	if( IsntNull( s->sigspec ) || IsntNull( s->pubkeys ) ) {
		if( !PGPGlobalRandomPoolHasMinimumEntropy() ) {
			PGPUInt32 fEntropyEvent;
			if( IsPGPError( s->err = pgpFindOptionArgs( s->optionList,
								kPGPOptionType_AskUserForEntropy,
							   FALSE, "%d", &fEntropyEvent ) ) )
				goto error;
			if( !fEntropyEvent ) {
				s->err = kPGPError_OutOfEntropy;
				goto error;
			}
			while( !PGPGlobalRandomPoolHasMinimumEntropy() ) {
				PGPUInt32 entropy_needed;
				entropy_needed = PGPGlobalRandomPoolGetMinimumEntropy() -
								 PGPGlobalRandomPoolGetEntropy();
				s->err = pgpEventEntropy( s->context, &s->newOptionList,
									  s->func, s->userValue, entropy_needed );
				pgpCleanupOptionList( &s->newOptionList );
				if( IsPGPError( s->err ) )
					goto error;
			}
		}
	}


	/* Get input into a memory buffer */
	s->err = pgpSetupInputToBuffer( s->context, s->optionList, &s->inBufPtr,
								 &s->inBufLength, &fMustFreeBuf );
	if( IsPGPError( s->err ) )
		goto error;

	/* Do the operation */
    s->err = X509PackageCertificateRequest (s->context,
											s->inBufPtr, s->inBufLength,
											s->enckeyref, encalg,
											s->signkeyref, passphrase,
											s->outputFormat,
											&outBuf, &outBufLength );

	passphrase = NULL;
	if( fMustFreeBuf ) {
		PGPFreeData( s->inBufPtr );
		s->inBufPtr = NULL;
		s->inBufLength = 0;
	}

	if( IsPGPError( s->err ) )
		goto error;

	/* Push result out to user */

	fEncrypt = (PGPBoolean) IsntNull( s->pubkeys );
	fSign = (PGPBoolean) IsntNull( s->sigspec );
	if( IsPGPError( s->err = pgpFindOptionArgs( s->optionList,
						 kPGPOptionType_AppendOutput, FALSE,
						 "%d", &fAppendOutput ) ) )
		goto error;
	if( IsPGPError( s->err = pgpSetupOutputPipeline( s->context, s->optionList,
							s->env, fEncrypt, fSign, s->sepsig,
							(PGPBoolean)fAppendOutput, FALSE,
							&s->tail, &s->outFileRef, &s->pfout,
							&s->outBufPtr, &s->outBufPtrPtr,
							&s->outBufMaxLength, &s->outBufUsedLength,
							&s->outPipe ) ) )
		goto error;

	s->err = pgpPumpMem( s->head, outBuf, outBufLength, NULL, NULL );
	if( IsPGPError( s->err ) )
		goto error;

	if( s->outPipe ) {
		if( IsntNull( s->outBufPtrPtr ) ) {
			/* Dynamically allocated buffer - tell user size & position */
			if( IsPGPError( s->err = pgpGetVariableMemOutput( s->outPipe,
							s->outBufMaxLength, s->outBufPtrPtr,
							s->outBufUsedLength ) ) )
				goto error;
		} else {
			/* Fixed size buffer - tell user actual size used */
			pgpAssert( IsntNull( s->outBufPtr ) );
			if( IsPGPError( s->err = pgpGetMemOutput( s->outPipe,
						s->outBufMaxLength, s->outBufUsedLength ) ) )
				goto error;
		}
	}

	s->head->teardown( s->head );
	s->head = NULL;


error:
	if( IsntNull( passphrase ) )
		pgpFreeOptionList( passphrase );
	if( IsntNull( s->head ) )
		s->head->teardown( s->head );
	if( IsntNull( outBuf ) )
		PGPFreeData( outBuf );

	return s->err;
}




/*__Editor_settings____

	Local Variables:
	tab-width: 4
	comment-column: 40
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
