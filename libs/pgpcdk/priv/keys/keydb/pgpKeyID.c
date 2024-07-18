/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: pgpKeyID.c,v 1.31 1999/03/10 02:52:01 heller Exp $
____________________________________________________________________________*/
#include "pgpConfig.h"

#include <string.h>
#include "pgpMem.h"
#include "pgpHex.h"
#include "pgpErrors.h"
#include "pgpContext.h"
#include "pgpUtilitiesPriv.h"

#include "pgpKeys.h"
#include "pgpKeyIDPriv.h"
#include "pgpKDBInt.h"

#define kMaxKeyBytes			8
/* 0x + str + NULL */
#define kMaxKeyStringLength		( 2 + ( kMaxKeyBytes * 2 ) + 1 )


	PGPBoolean
pgpKeyIDIsValid( PGPKeyID const * id )
{
	PGPKeyIDPriv const *	priv	= (PGPKeyIDPriv const *)id;
	
	return( IsntNull( priv ) &&
		( priv->length == 4 || priv->length == 8 ) );
}
#define PGPValidateKeyID( id )	PGPValidateParam( pgpKeyIDIsValid( id ) )



	static void
sNewKeyID(
	PGPUInt32		length,
	PGPByte const *	bytes,
	PGPKeyID *		outID )
{
	PGPKeyIDPriv *	priv	= (PGPKeyIDPriv *)outID;
	
	pgpAssert( length == 4 || length == 8 );
	priv->length	= length;
	priv->reserved	= 0;
	pgpCopyMemory( bytes, priv->bytes, length );
}



	PGPError
pgpNewKeyIDFromRawData(
	const void *	data,
	PGPSize			dataSize,
	PGPKeyID *		outID )
{
	PGPError	err	= kPGPError_NoErr;
	
	PGPValidateParam( dataSize == 4 || dataSize == 8 );
	
	sNewKeyID( dataSize, (PGPByte const *)data, outID );
	
	return( err );
}
				
				
//BEGIN SHORT KEYID SORT MOD - Disastry
PGPError pgpKeyID8to4( PGPKeyID *inID, PGPKeyID *outID )
{
	PGPError	err	= kPGPError_NoErr;
	PGPKeyIDPriv *	priv	= (PGPKeyIDPriv *)inID;

	PGPValidateKeyID( inID );
	if ( priv->length == 4 ) {
		sNewKeyID( 4, priv->bytes, outID );
    } else {
		sNewKeyID( 4, priv->bytes+4, outID );
    }
	return( err );
}
//END SHORT KEYID SORT MOD

/*____________________________________________________________________________
	Convert a string into a key id.
	
	string must be of the form:
		0xdddddddd
		0xdddddddddddddddd
		dddddddd
		dddddddddddddddd
	which represents either a 4 byte or 8 byte key id.
____________________________________________________________________________*/
	PGPError 
PGPGetKeyIDFromString(
	const char *	string,
	PGPKeyID *		outID )
{
	PGPError		err	= kPGPError_NoErr;
	PGPSize			stringLength;
	const char *	cur	= NULL;
	PGPByte *		outCur	= NULL;
	PGPByte			keyBytes[ kMaxKeyBytes ];
	PGPSize			inputRemaining;
	
	PGPValidatePtr( outID );
	pgpClearMemory( outID, sizeof( *outID ) );
	PGPValidatePtr( string );
	
	/* optionally starts with "0x" */
	stringLength	= strlen( string );
	if ( string[ 0 ] == '0' && string[ 1 ] == 'x' )
	{
		stringLength	-= 2;
		cur				= string + 2;
	}
	else
	{
		cur		= string;
	}
	
	/* two hex chars for each raw byte */
	PGPValidateParam( stringLength == 4 * 2 || stringLength == 8 * 2 );
	
	outCur	= &keyBytes[ 0 ];
	inputRemaining	= stringLength;
	while ( inputRemaining != 0 )
	{
		const char	char1	= *cur++;
		const char	char2	= *cur++;
		
		inputRemaining	-= 2;	/* we used 2 bytes */
		
		PGPValidateParam( pgpIsValidHexChar( char1 ) &&
			pgpIsValidHexChar( char2 ) );
		
		*outCur++	= (pgpHexCharToNibble( char1 ) << 4 ) |
						pgpHexCharToNibble( char2 );
	}
	
	sNewKeyID( stringLength / 2, keyBytes, outID );
	return( err );
}

		
	PGPError
PGPGetKeyIDFromKey(
	PGPKeyRef	key,
	PGPKeyID *	outID )
{
	PGPError			err	= kPGPError_NoErr;
	RingSet const  *	ringSet;
	
	PGPValidatePtr( outID );
	pgpClearMemory( outID, sizeof( *outID ) );
	PGPValidateKey( key );
	
	ringSet	= pgpKeyDBRingSet( key->keyDB );

	ringKeyID8( ringSet, key->key, NULL, outID );
	
	return( err );
}


	PGPError
PGPGetKeyIDFromSubKey(
	PGPSubKeyRef	subKey,
	PGPKeyID *		outID )
{
	PGPError			err	= kPGPError_NoErr;
	RingSet const  *	ringSet;
	
	PGPValidatePtr( outID );
	pgpClearMemory( outID, sizeof( *outID ) );
	PGPValidateSubKey( subKey );
	
	ringSet	= pgpKeyDBRingSet( subKey->key->keyDB );

	ringKeyID8( ringSet, subKey->subKey, NULL, outID );
	
	return( err );
}


	PGPByte const *
pgpGetKeyBytes( PGPKeyID const *keyID )
{
	PGPKeyIDPriv *	priv	= (PGPKeyIDPriv *)keyID;
	
	return( &priv->bytes[ 0 ] );
}


	PGPError
PGPGetKeyIDString(
	PGPKeyID const *	keyID,
	PGPKeyIDStringType	type,
	char				outString[ 128 ] )
{
	PGPError		err	= kPGPError_NoErr;
	PGPKeyIDPriv *	priv	= (PGPKeyIDPriv *)keyID;
	
	PGPValidatePtr( outString );
	pgpClearMemory( outString, 128 );
	PGPValidateKeyID( keyID );
	PGPValidateParam( type == kPGPKeyIDString_Abbreviated ||
		type == kPGPKeyIDString_Full );
	
	if ( type == kPGPKeyIDString_Full || priv->length == 4 )
	{
		/* all the bytes */
		pgpBytesToHex( priv->bytes, priv->length, TRUE, outString );
	}
	else
	{
		/* abbreviated version */
		pgpAssert( priv->length == 8 );
		pgpBytesToHex( priv->bytes + 4, 4, TRUE, outString );
	}
	
	return( err );
}




/*____________________________________________________________________________
	Compare two key IDs.  Return 0 if they are the same, -1 if key1 < key2,
	1 if key1 > key2. 
____________________________________________________________________________*/
	PGPInt32 
PGPCompareKeyIDs(
	PGPKeyID const *	key1,
	PGPKeyID const *	key2)
{
	PGPKeyIDPriv const *	priv1	= (PGPKeyIDPriv *)key1;
	PGPKeyIDPriv const *	priv2	= (PGPKeyIDPriv *)key2;
	
	pgpAssert( pgpKeyIDIsValid( key1 ) );
	pgpAssert( pgpKeyIDIsValid( key2 ) );
	
	if ( (! pgpKeyIDIsValid( key1 )) ||
		( ! pgpKeyIDIsValid( key2 )) )
		return( 0 );
	
	if ( priv1->length == priv2->length )
	{
		PGPSize		numBytes	= priv1->length;
		PGPUInt32	idx;
		
		/* compare as if first byte is high order byte */
		for( idx = 0; idx < numBytes; ++idx )
		{
			if ( priv1->bytes[ idx ] < priv2->bytes[ idx ] )
				return( -1 );
			if ( priv1->bytes[ idx ] > priv2->bytes[ idx ] )
				return( 1 );
		}
	}
	else
	{
		/* unequal sizes 4 vs 8 bytes */
		PGPByte const *	ptr1;
		PGPByte const *	ptr2;
		PGPBoolean		priv1Is8Byte	= priv1->length == 8;
		
		ptr1	= &priv1->bytes[ 0 ];
		ptr2	= &priv2->bytes[ 0 ];
		if ( priv1Is8Byte )
			ptr1	+= 4;	/* use low order 4 bytes */
		else
			ptr2	+= 4;	/* use low order 4 bytes */
		
		/* if not the same, arbitrarily say 4 byte ids are < 8 byte IDs */
		if ( ! pgpMemoryEqual( ptr1, ptr2, 4 ) )
			return( priv1Is8Byte ? 1 : -1 );
	}
	
	return( 0 );
}

	PGPBoolean
pgpKeyIDsEqual(
	PGPKeyID const *	key1,
	PGPKeyID const *	key2)
{
	return( PGPCompareKeyIDs( key1, key2 ) == 0 );
}


enum PGPKeyIDType_
{
	kKeyID4Byte = 13,
	kKeyID8Byte = 14,
	
	PGP_ENUM_FORCE( PGPKeyIDType_ )
};
PGPENUM_TYPEDEF( PGPKeyIDType_, PGPKeyIDType );


/*____________________________________________________________________________
	Caution: these exported IDs are used in client software.  If changed,
	they will break things like groups, which uses exported key IDs.
____________________________________________________________________________*/
	PGPError
PGPExportKeyID(
	PGPKeyID const *	keyID,
	PGPByte				exportedData[ kPGPMaxExportedKeyIDSize ],
	PGPSize *			exportedLength )
{
	PGPError				err	= kPGPError_NoErr;
	PGPSize					size	= 0;
	PGPKeyIDType			type;
	PGPKeyIDPriv const *	priv	= (PGPKeyIDPriv const *)keyID;
	
	if ( IsntNull( exportedLength ) )
		*exportedLength	= 0;
	PGPValidatePtr( exportedData );
	pgpClearMemory( exportedData, kPGPMaxExportedKeyIDSize );
	PGPValidateKeyID( keyID );
	
	/* output one byte to indicate type, followed by bytes */
	size		= 1 + priv->length;
	type		= ( priv->length == 4 ) ? kKeyID4Byte : kKeyID8Byte;
	exportedData[ 0 ]	= (PGPByte)type;
	pgpCopyMemory( priv->bytes, &exportedData[ 1 ], priv->length );
	
	if ( IsntNull( exportedLength ) )
		*exportedLength	= size;
	
	return( err );
}



	PGPError
PGPImportKeyID(
	void const *	dataParam,
	PGPKeyID *		id )
{
	PGPError		err	= kPGPError_NoErr;
	PGPKeyIDType	type;
	PGPSize			length;
	const PGPByte *	data;
	
	PGPValidatePtr( id );
	pgpClearMemory( id, sizeof( *id ) );
	PGPValidatePtr( dataParam );
	
	data = (const PGPByte *) dataParam;
	
	type	= (PGPKeyIDType)data[ 0 ];
	PGPValidateParam( type == kKeyID4Byte || type == kKeyID8Byte );
	
	length	= ( type == kKeyID4Byte ) ? 4 : 8;
	sNewKeyID( length, &data[ 1 ], id);
	
	return( err );
}

















/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
