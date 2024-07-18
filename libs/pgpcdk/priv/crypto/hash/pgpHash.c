/*____________________________________________________________________________
	pgpHash.c
	
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: pgpHash.c,v 1.40.20.1 1999/08/04 18:35:44 sluu Exp $
____________________________________________________________________________*/
#include "pgpConfig.h"
#include "pgpErrors.h"
#include "pgpMem.h"

#include "pgpMD5.h"
#include "pgpMD2.h"
#include "pgpSHA.h"
#include "pgpRIPEMD160.h"
//BEGIN SHA DOUBLE MOD - Imad R. Faiad
#include "pgpSHADouble.h"
//END SHA DOUBLE MOD
//BEGIN SHA2 MOD - Disastry
#include "pgpSHA2.h"
//END SHA2 MOD - Disastry
//BEGIN SHA2 MOD - Disastry
#include "pgpTIGER192.h"
//END SHA2 MOD - Disastry

#include "pgpHash.h"
#include "pgpHashPriv.h"
#include "pgpUtilitiesPriv.h"



struct PGPHashContext
{
#define kHashContextMagic		0xABBADABA
	PGPUInt32			magic;
	PGPHashVTBL const *	vtbl;
	PGPMemoryMgrRef		memoryMgr;
	void *				hashData;
};

struct PGPHashList
{
	PGPUInt32		numHashes;
	PGPMemoryMgrRef	memoryMgr;
	PGPHashContext	hashes[ 1 ];	/* open ended */
};

static void	sDisposeHashData( PGPHashContextRef	ref );


#define CallInit(hc)	(hc)->vtbl->init((hc)->hashData)
#define CallUpdate(hc, buf, len) (hc)->vtbl->update((hc)->hashData, buf, len)
#define CallFinal(hc) (hc)->vtbl->final((hc)->hashData)


	static PGPBoolean
pgpHashContextIsValid( const PGPHashContext * ref)
{
	return( IsntNull( ref ) &&
			IsntNull( ref->hashData ) &&
			ref->magic == kHashContextMagic  );
}


#define pgpValidateHash( ref )		\
	PGPValidateParam( pgpHashContextIsValid( ref ) )
	
#define IsValidAlgorithm( alg )		\
	IsntNull( pgpHashByNumber( alg ) )


	static PGPError
sHashInit(
	PGPHashContextRef		ref,
	PGPMemoryMgrRef			memoryMgr,
	PGPHashAlgorithm		algorithm )
{
	PGPError				err	= kPGPError_NoErr;
	
	pgpClearMemory( ref, sizeof( *ref ) );
	ref->magic		= kHashContextMagic;
	ref->memoryMgr	= memoryMgr;
	ref->vtbl		= pgpHashByNumber( algorithm );
	pgpAssert( IsntNull( ref->vtbl ) );
	
	ref->hashData	= PGPNewData( memoryMgr,
		ref->vtbl->context_size, 0);
	if ( IsntNull( ref->hashData ) )
	{
		CallInit( ref );
	}
	else
	{
		err	= kPGPError_OutOfMemory;
	}
	
	return( err );
}


	static PGPError
sHashCreate(
	PGPMemoryMgrRef			memoryMgr,
	PGPHashAlgorithm		algorithm,
	PGPHashContextRef *		outRef )
{
	PGPHashContextRef		ref	= NULL;
	PGPError				err	= kPGPError_NoErr;
	
	*outRef	= NULL;
	
	ref	= (PGPHashContextRef)
		PGPNewData( memoryMgr, sizeof( *ref ),
			0 | kPGPMemoryMgrFlags_Clear );
	
	if ( IsntNull( ref ) )
	{
		err	= sHashInit( ref, memoryMgr, algorithm );
		
		if ( IsPGPError( err ) )
		{
			PGPFreeData( ref );
			ref	= NULL;
		}
	}
	else
	{
		err	= kPGPError_OutOfMemory;
	}
	
	*outRef	= ref;
	return( err );
}




	PGPError 
PGPNewHashContext(
	PGPMemoryMgrRef		memoryMgr,
	PGPHashAlgorithm	algorithm,
	PGPHashContextRef *	outRef )
{
	PGPError	err	= kPGPError_NoErr;
	
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidateMemoryMgr( memoryMgr );
	PGPValidateParam( IsValidAlgorithm( algorithm ) );
	
	err	= sHashCreate( memoryMgr, algorithm, outRef );
	
	return( err );
}



	PGPError 
PGPFreeHashContext( PGPHashContextRef ref )
{
	PGPError		err	= kPGPError_NoErr;
	
	pgpValidateHash( ref );
	
	sDisposeHashData(ref);
	pgpClearMemory( ref, sizeof( *ref ) );
	PGPFreeData( ref );
	
	return( err );
}


	PGPError 
PGPCopyHashContext(
	PGPHashContextRef	ref,
	PGPHashContextRef *	outRef)
{
	PGPError			err	= kPGPError_NoErr;
	PGPHashContextRef	newRef	= NULL;
	
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	pgpValidateHash( ref );
	
	err	= sHashCreate( ref->memoryMgr, ref->vtbl->algorithm, &newRef );
	if ( IsntPGPError( err ) )
	{
		pgpCopyMemory( ref->hashData,
			newRef->hashData, ref->vtbl->context_size );
		
	}
	
	*outRef	= newRef;
	return( err );
}



	PGPError 
PGPResetHash( PGPHashContextRef ref )
{
	PGPError	err	= kPGPError_NoErr;
	
	pgpValidateHash( ref );
	
	CallInit( ref );
	
	return( err );
}


	PGPError 
PGPContinueHash(
	PGPHashContextRef	ref,
	const void *		in,
	PGPSize			numBytes )
{
	PGPError	err	= kPGPError_NoErr;
	
	pgpValidateHash( ref );
	PGPValidatePtr( in );

	if ( numBytes != 0 )
	{
		CallUpdate( ref, in, numBytes );
	}
	
	return( err );
}


	PGPError 
PGPFinalizeHash(
	PGPHashContextRef	ref,
	void *				hashOut )
{
	PGPError		err	= kPGPError_NoErr;
	const void *	result;
	PGPSize			hashSize;
	
	pgpValidateHash( ref );
	PGPValidatePtr( hashOut );
	
	(void)PGPGetHashSize( ref, &hashSize);
	
	result	= CallFinal( ref );
	pgpCopyMemory( result, hashOut, hashSize );
	
	return( err );
}


	PGPError 
PGPGetHashSize(
	PGPHashContextRef	ref,
	PGPSize *			hashSize )
{
	PGPError	err	= kPGPError_NoErr;
	
	PGPValidatePtr( hashSize );
	*hashSize	= 0;
	pgpValidateHash( ref );
	
	*hashSize	= ref->vtbl->hashsize;
	
	return( err );
}





	PGPHashContextRef
pgpHashCreate(
	PGPMemoryMgrRef		memoryMgr,
	PGPHashVTBL const *	vtbl)
{
	PGPError			err	= kPGPError_NoErr;
	PGPHashContextRef	newRef;
	
	pgpAssert( PGPMemoryMgrIsValid( memoryMgr ) );
	
	err	= PGPNewHashContext( memoryMgr, vtbl->algorithm, &newRef );

	pgpAssert( ( IsntPGPError( err ) && IsntNull( newRef ) ) ||
		( IsPGPError( err ) && IsNull( newRef ) ) );
	
	return( newRef );
}




	static void
sDisposeHashData (PGPHashContextRef	ref)
{
	if ( pgpHashContextIsValid( ref ) )
	{
		pgpClearMemory (ref->hashData, ref->vtbl->context_size);
		PGPFreeData( ref->hashData );
		ref->hashData	= NULL;
	}
}


	void const *
pgpHashFinal( PGPHashContextRef ref )
{
	pgpAssert( pgpHashContextIsValid( ref ) );
	
	return( CallFinal( ref ) );
}


	PGPHashContextRef
pgpHashCopy(const PGPHashContext *ref)
{
	PGPHashContextRef	newRef;

	pgpAssert( pgpHashContextIsValid( ref ) );
	
	(void)PGPCopyHashContext( (PGPHashContextRef)ref, &newRef );
	
	return newRef;
}

	void
pgpHashCopyData(
	PGPHashContext  *	src,
	PGPHashContext *	dest )
{
	pgpAssert( pgpHashContextIsValid( src ) );
	pgpAssert(dest->vtbl == src->vtbl);
	
	pgpCopyMemory( src->hashData, dest->hashData, src->vtbl->context_size);
}


/* Access to all known hashes */
/* The order of the entries in this table is not significant */
static PGPHashVTBL const * const sHashList[]  =
{
	&HashMD5,
	&HashSHA,
	&HashRIPEMD160,
	&HashMD2,
	//BEGIN SHA DOUBLE MOD - Imad R. Faiad
	&HashSHADouble,
	//END SHA DOUBLE MOD
	//BEGIN TIGER192 MOD - Imad R. Faiad
	&HashTIGER192,
	//END TIGER192 MOD
	//BEGIN SHA2 MOD - Disastry
	&HashSHA256,
	&HashSHA384,
	&HashSHA512
	//END SHA2 MOD - Disastry
};
#define kNumHashes	 ( sizeof( sHashList ) / sizeof( sHashList[ 0 ] ) )

	PGPHashVTBL const *
pgpHashByNumber (PGPHashAlgorithm	algorithm)
{
	const PGPHashVTBL *	vtbl	= NULL;
	PGPUInt32			algIndex;
	
	for( algIndex = 0; algIndex < kNumHashes; ++algIndex )
	{
		if ( sHashList[ algIndex ]->algorithm == algorithm )
		{
			vtbl	= sHashList[ algIndex ];
			break;
		}
	}
	
	return vtbl;
}

/*
 * Given a hash name, return the corresponding hash.
 */
	PGPHashVTBL const *
pgpHashByName (char const *name, PGPSize namelen)
{
	PGPUInt32	algIndex;

	for( algIndex = 0; algIndex < kNumHashes; ++algIndex )
	{
		PGPHashVTBL const *vtbl;
	
		vtbl = sHashList[ algIndex ];
		
		if ( pgpMemoryEqual (name, vtbl->name, namelen) && 
		    vtbl->name[ namelen ] == '\0')
		{
			return vtbl;
		}
	}
	return NULL;	/* Not found */
}



	PGPHashVTBL const  *
pgpHashGetVTBL( const PGPHashContext *ref )
{
	pgpAssert( pgpHashContextIsValid( ref ) );
	
	return( ref->vtbl );
}

/*____________________________________________________________________________
	Given a list of hash identifiers, create a list of hash contexts.
	Ignores unknown algorithms.  Returns the number of PgpHashContexts
	created and stored in the "hashes" buffer, or an Error (and none created)
	on error.
	
	Note that the formal data type returned is an opaque 'PGPHashListRef',
	although the actual format of the list is just an array of PGPHashContext.
	The formal data type is used to preserve opacity of the PGPHashContext.
____________________________________________________________________________*/
	PGPError
pgpHashListCreate (
	PGPMemoryMgrRef		memoryMgr,
	void const *		bufParam,
	PGPHashListRef *	hashListPtr,
	PGPUInt32			numHashes )
{
	PGPInt32				numHashesCreated;
	PGPHashListRef			hashList;
	PGPError				err	= kPGPError_NoErr;
	PGPUInt32				listSize;
	const PGPByte *			buf;
	
	PGPValidatePtr( hashListPtr );
	*hashListPtr = NULL;
	PGPValidatePtr( bufParam );
	PGPValidateParam( numHashes != 0 );
	PGPValidateMemoryMgr( memoryMgr );

	buf 		= (const PGPByte *) bufParam;
	listSize	= sizeof( *hashList ) +
		( numHashes -1 )  * sizeof( hashList->hashes[ 0 ] );
		
	hashList	= (PGPHashListRef)
		PGPNewData( memoryMgr, listSize,
		0 | kPGPMemoryMgrFlags_Clear );
	
	if ( IsNull( hashList ) )
		return( kPGPError_OutOfMemory );
		
	pgpClearMemory( hashList, listSize );
	hashList->numHashes	= 0;
	hashList->memoryMgr	= memoryMgr;

	numHashesCreated = 0;
	while (numHashes--)
	{
		PGPHashAlgorithm		algorithm;
		PGPHashVTBL const *		vtbl;
		
		algorithm	= (PGPHashAlgorithm) ( *buf++ );
		
		vtbl	= pgpHashByNumber ( algorithm );
		if ( IsntNull( vtbl ) )
		{
			PGPHashContext *	curHash;
			
			curHash	= &hashList->hashes[ numHashesCreated ];
			
			err	= sHashInit( curHash, memoryMgr, vtbl->algorithm );
			if ( IsPGPError( err ) )
			{
				while ( numHashesCreated-- )
				{
					sDisposeHashData( curHash );
				}
				
				PGPFreeData( hashList );
				hashList	= NULL;
				err	= kPGPError_OutOfMemory;
				break;
			}
			numHashesCreated++;
		}
	}

	hashList->numHashes	= numHashesCreated;
	
	*hashListPtr = hashList;
	
	return err;
}


	void
pgpHashListDestroy ( PGPHashListRef	hashList )
{
	PGPUInt32		hashIndex;
	
	pgpAssertAddrValid( hashList, PGPHashList );
	
	hashIndex	= hashList->numHashes;
	if ( hashIndex != 0 )
	{
		while ( hashIndex--)
		{
			sDisposeHashData( &hashList->hashes[ hashIndex ] );
		}
		
		PGPFreeData( hashList );
	}
}


	PGPUInt32
pgpHashListGetSize( PGPHashListRef	list  )
{
	pgpAssertAddrValid( list, PGPHashList );
	return( list->numHashes );
}

/*____________________________________________________________________________
	pgpHashListGetIndHash() is made necessary by incestuous code that wants
	to be able to index over a struct.  Since we want to keep the structure
	of a PGPHashContext opaque, we need to provide this accessor.
____________________________________________________________________________*/

	PGPHashContext *
pgpHashListGetIndHash(
	PGPHashListRef	list,
	PGPUInt32		algIndex )
{
	pgpAssertAddrValid( list, PGPHashList );
	pgpAssert( algIndex < list->numHashes );
	
	if ( algIndex < list->numHashes )
		return( &list->hashes[ algIndex ] );
		
	return( NULL );
}


	PGPHashContext *
pgpHashListFind (
	PGPHashListRef		hashList,
	PGPHashVTBL const *	vtbl)
{
	PGPHashContext *	cur;
	PGPUInt32			remaining;
	
	pgpAssertAddrValid( hashList, PGPHashList );
	
	cur	= &hashList->hashes[ 0 ];
	remaining	= hashList->numHashes;
	while (remaining--)
	{
		if ( cur->vtbl == vtbl )
			return cur;
		cur++;
	}
	return NULL;
}






















/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
