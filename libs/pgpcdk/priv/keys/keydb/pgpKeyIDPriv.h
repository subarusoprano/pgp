/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: pgpKeyIDPriv.h,v 1.6 1999/03/10 02:52:02 heller Exp $
____________________________________________________________________________*/
#ifndef Included_pgpKeyIDPriv_h	/* [ */
#define Included_pgpKeyIDPriv_h

#include "pgpPubTypes.h"

/* the non-opaque PGPKeyID */
struct PGPKeyIDPriv
{
	PGPByte		length;
	PGPByte		reserved;
	PGPByte		bytes[ 32 ];
};

PGPError	pgpNewKeyIDFromRawData( const void *data,
				PGPSize dataSize, PGPKeyID *outID );

//BEGIN SHORT KEYID SORT MOD - Disastry
PGPError	pgpKeyID8to4( PGPKeyID *inID, PGPKeyID *outID );
//END SHORT KEYID SORT MOD

PGPBoolean	pgpKeyIDsEqual( const PGPKeyID *id1, const PGPKeyID *id2 );

PGPByte const *	pgpGetKeyBytes( PGPKeyID const *keyID );

PGPBoolean	pgpKeyIDIsValid( PGPKeyID const * id );
#define PGPValidateKeyID( id )	PGPValidateParam( pgpKeyIDIsValid( id ) )

#endif /* ] Included_pgpKeyIDPriv_h */


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
