/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.


	$Id: pgpFeatures.c,v 1.35.6.3.6.1 1999/08/17 20:04:30 cpeterson Exp $



____________________________________________________________________________*/
#include "pgpSDKBuildFlags.h"
#include "pgpConfig.h"
#include <string.h>
#include "pgpDebug.h"

#include "pgpErrors.h"
#include "pgpMem.h"
#include "pgpUtilities.h"
#include "pgpRnd.h"

#include "pgpFeatures.h"
#include "pgpTimeBomb.h"

#include "pgpPubKey.h"
#include "pgpDES3.h"
#include "pgpCAST5.h"

//BEGIN MORE CIPHERS SUPPORT - Disastry
#include "pgpBLOWFISH.h"
#include "pgpRijndael.h"
#include "pgpTwofish.h"
//END MORE CIPHERS SUPPORT


#if PGP_IDEA
#include "pgpIDEA.h"
#endif

#ifndef PGP_RSA
#error "PGP_RSA requires a value"
#endif

#if PGP_ENCRYPT_DISABLE && PGP_DECRYPT_DISABLE
	#define PGP_HAVE_SYMMETRIC_CIPHERS	0
#else
	#define PGP_HAVE_SYMMETRIC_CIPHERS	1
#endif

#if !PGP_WIN32
#undef PGP_INTEL_RNG_SUPPORT
#define PGP_INTEL_RNG_SUPPORT 0
#endif

	PGPError 
PGPGetSDKVersion( PGPUInt32 *version )
{
	PGPValidatePtr( version );
	*version	= kPGPsdkAPIVersion;
	
	return( kPGPError_NoErr );
}






/*____________________________________________________________________________
	Return a flags word for the feature selector
____________________________________________________________________________*/
	PGPError 
PGPGetFeatureFlags(
	PGPFeatureSelector	selector,
	PGPFlags *			flagsPtr )
{
	PGPError	err		= kPGPError_NoErr;
	PGPFlags	flags	= 0;
	
	PGPValidatePtr( flagsPtr );
	*flagsPtr	= 0;
	
	switch ( selector )
	{
		default:
			/* update comment in pgpFeatures.h if this changes */
			err		= kPGPError_ItemNotFound;
			flags	= 0;
			break;
			
		case kPGPFeatures_GeneralSelector:
		{
			flags	=	0
#if !PGP_ENCRYPT_DISABLE
						| kPGPFeatureMask_CanEncrypt
#endif
#if !PGP_DECRYPT_DISABLE
						| kPGPFeatureMask_CanDecrypt
#endif
#if !PGP_SIGN_DISABLE
						| kPGPFeatureMask_CanSign
#endif
#if !PGP_VERIFY_DISABLE
						| kPGPFeatureMask_CanVerify
#endif
						;

#if PGP_INTEL_RNG_SUPPORT
			if (pgpIntelRngEnabled()) 
				flags |= kPGPFeatureMask_RngHardware;
#endif
			break;
		}
			
		case kPGPFeatures_ImplementationSelector:
		{
			flags	= 0;
			
		#if PGP_DEBUG
			flags	|= kPGPFeatureMask_IsDebugBuild;
		#endif
		
		#ifndef PGP_TIME_BOMB
		#error PGP_TIME_BOMB must be defined
		#endif
		
		#if PGP_TIME_BOMB
			flags	|= kPGPFeatureMask_HasTimeout;
		#endif
			break;
		}
	}
	
	*flagsPtr	= flags;
	
	return( err );
}



/*____________________________________________________________________________
	Return a C string of the form:
		"PGPsdk version 1.0 (C) 1997 Pretty Good Privacy, Inc"
____________________________________________________________________________*/
	PGPError 
PGPGetSDKString( char theString[ 256 ] )
{
	static const char	kVersionString[]	=
		"PGPsdk version 1.7.1 (C) 1997-1999 Network Associates, Inc. and its "
		"affiliated companies."
#if ! PGP_RSA
		" (Diffie-Helman/DSS-only version)"
#endif
		;
	
	PGPValidatePtr( theString );
	/* leave this in even in non-debug; enforce having the space */
	pgpClearMemory( theString, 256 );
	
	strcpy( theString, kVersionString );
	
	return( kPGPError_NoErr );
}


static PGPPublicKeyAlgorithmInfo	sPublicKeyAlgs[] =
{

#if PGP_RSA
	#if PGP_USECAPIFORRSA
		#define kRSALongVersionString	"RSA (CAPI)"
		#define kRSACopyrightString		""
	#elif PGP_USEBSAFEFORRSA
		#define kRSALongVersionString	"RSA (BSAFE)"
		#define kRSACopyrightString		\
			"Uses the BSafe(tm) Toolkit, which is copyright RSA Data Security, Inc."
	#elif PGP_USERSAREF
		#define kRSALongVersionString	"RSA (RSAREF)"
		#define kRSACopyrightString		\
			"Uses the RSAREF(tm) Toolkit, which is copyright RSA Data Security, Inc."
	#elif PGP_USEPGPFORRSA
		#define kRSALongVersionString	"RSA (PGP)"
		#define kRSACopyrightString		""
	#else
		#error Unknown RSA implementation
	#endif
	
/* Must be first one, we skip it if not available at run time */
	{{ "RSA", kRSALongVersionString, kRSACopyrightString, 0, {0,} },
		kPGPPublicKeyAlgorithm_RSA,
	 	!PGP_ENCRYPT_DISABLE, !PGP_DECRYPT_DISABLE,
	 	!PGP_SIGN_DISABLE, !PGP_VERIFY_DISABLE, TRUE,
	    0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } },
#endif /* PGP_RSA */
		
	{{ "ElGamal",	"ElGamal",	"", 0, {0,} },
		kPGPPublicKeyAlgorithm_ElGamal,
	 	!PGP_ENCRYPT_DISABLE, !PGP_DECRYPT_DISABLE, FALSE, FALSE, TRUE,
	    0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } },
		
	{{ "DSA",		"Digital Signature Standard",	"", 0, {0,} },
		kPGPPublicKeyAlgorithm_DSA,
	 	FALSE, FALSE, !PGP_SIGN_DISABLE, !PGP_VERIFY_DISABLE, TRUE,
        0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } },
		
	{{ "ElGamalSE",	"ElGamal Encrypt or Sign",	"", 0, {0,} },
		kPGPPublicKeyAlgorithm_ElGamalSE,
		!PGP_ENCRYPT_DISABLE, !PGP_DECRYPT_DISABLE,
		!PGP_SIGN_DISABLE, !PGP_VERIFY_DISABLE, TRUE,
	    0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } },
};
#define kNumPublicKeyAlgs	\
( sizeof( sPublicKeyAlgs ) / sizeof( sPublicKeyAlgs[ 0 ] ) )


	PGPError
PGPCountPublicKeyAlgorithms( PGPUInt32 *numAlgs )
{
	PGPValidatePtr( numAlgs );
	
	*numAlgs	= kNumPublicKeyAlgs;
#if PGP_RSA
	if( pgpKeyUse( pgpPkalgByNumber( kPGPPublicKeyAlgorithm_RSA ) ) == 0 )
		*numAlgs -= 1;
#endif
	return( kPGPError_NoErr );
}


	PGPError
PGPGetIndexedPublicKeyAlgorithmInfo(
	PGPUInt32					idx,
	PGPPublicKeyAlgorithmInfo *	info)
{
	PGPValidatePtr( info );
	pgpClearMemory( info, sizeof( *info ) );

#if PGP_RSA
	{
		int rsause =
			pgpKeyUse( pgpPkalgByNumber( kPGPPublicKeyAlgorithm_RSA ) );
		if (rsause == 0)
			idx += 1;
		if( idx == 0 ) {
#if PGP_ENCRYPT_DISABLE
			sPublicKeyAlgs[0].canEncrypt	= FALSE;
#else
			sPublicKeyAlgs[0].canEncrypt	= !!(rsause & PGP_PKUSE_ENCRYPT);
#endif
#if PGP_DECRYPT_DISABLE
			sPublicKeyAlgs[0].canDecrypt	= FALSE;
#else
			sPublicKeyAlgs[0].canDecrypt	= !!(rsause & PGP_PKUSE_ENCRYPT);
#endif
#if PGP_SIGN_DISABLE
			sPublicKeyAlgs[0].canSign		= FALSE;
#else
			sPublicKeyAlgs[0].canSign		= !!(rsause & PGP_PKUSE_SIGN);
#endif
#if PGP_VERIFY_DISABLE
			sPublicKeyAlgs[0].canVerify	= 	FALSE;
#else
			sPublicKeyAlgs[0].canVerify		= !!(rsause & PGP_PKUSE_SIGN);
#endif
		}
	}
#endif	

	PGPValidateParam( idx < kNumPublicKeyAlgs );

	*info	= sPublicKeyAlgs[ idx ];
	
	return( kPGPError_NoErr );
}


#if PGP_HAVE_SYMMETRIC_CIPHERS	/* [ */

static const PGPSymmetricCipherInfo	sSymmetricCipherAlgs[] =
{
#if PGP_IDEA
	{{ "IDEA",	"IDEA",		"",	0, {0,} },		kPGPCipherAlgorithm_IDEA, {0,}},
#endif

#if PGP_DES3
	{{ "3DES",	"3DES",		"",	0, {0,} },		kPGPCipherAlgorithm_3DES, {0,}},
#endif
	
#if PGP_CAST5
	{{ "CAST5",	"CAST5",	"",	0, {0,} },		kPGPCipherAlgorithm_CAST5,  {0,}},
#endif

//BEGIN MORE CIPHERS SUPPORT - Disastry
#if PGP_BLOWFISH
	{{ "BLOWFISH",	"BLOWFISH",	"",	0, {0,} },		kPGPCipherAlgorithm_BLOWFISH,  {0,}},
#endif

#if PGP_AES
	{{ "AES128",	"AES128",	"",	0, {0,} },		kPGPCipherAlgorithm_AES128,  {0,}},
	{{ "AES192",	"AES192",	"",	0, {0,} },		kPGPCipherAlgorithm_AES192,  {0,}},
	{{ "AES256",	"AES256",	"",	0, {0,} },		kPGPCipherAlgorithm_AES256,  {0,}},
#endif

#if PGP_TWOFISH
	{{ "TWOFISH",	"TWOFISH",	"",	0, {0,} },		kPGPCipherAlgorithm_Twofish256,  {0,}},
#endif
//END MORE CIPHERS SUPPORT


};
#define kNumSymmetricCipherAlgs		\
	( sizeof( sSymmetricCipherAlgs ) / sizeof( sSymmetricCipherAlgs[ 0 ] ) )


/*____________________________________________________________________________
	The call to this routine ensures that these algorithms are actually
	present; it's intended to make the programmer notice if one or more
	of them are not linked in.
____________________________________________________________________________*/
	static const PGPCipherVTBL *
sEnsureSymmetricCipherLinked( PGPCipherAlgorithm	alg)
{
	PGPCipherVTBL const *vtbl	= NULL;
	
	switch( alg )
	{
		default:
			break;
	#if PGP_IDEA
		case kPGPCipherAlgorithm_IDEA:		vtbl = &cipherIDEA;	break;
	#endif
	
	#if PGP_DES3
		case kPGPCipherAlgorithm_3DES:		vtbl = &cipher3DES;	break;
	#endif
	
	#if PGP_CAST5
		case kPGPCipherAlgorithm_CAST5:		vtbl = &cipherCAST5;	break;
	#endif

	//BEGIN MORE CIPHERS SUPPORT - Imad R. Faiad
	
	#if PGP_BLOWFISH
		case kPGPCipherAlgorithm_BLOWFISH:	vtbl = &cipherBLOWFISH;	break;
	#endif
	
	#if PGP_AES
		case kPGPCipherAlgorithm_AES128:	vtbl = &cipherAES128;	break;
		case kPGPCipherAlgorithm_AES192:	vtbl = &cipherAES192;	break;
		case kPGPCipherAlgorithm_AES256:	vtbl = &cipherAES256;	break;
	#endif
	
	#if PGP_TWOFISH
		case kPGPCipherAlgorithm_Twofish256:	vtbl = &cipherTwofish256;	break;
	#endif
	//END MORE CIPHERS SUPPORT

	}
	
	return( vtbl );
}
#endif	/* ] */

	PGPError
PGPCountSymmetricCiphers( PGPUInt32 *numAlgs )
{
	PGPValidatePtr( numAlgs );
	
#if PGP_HAVE_SYMMETRIC_CIPHERS
	*numAlgs = kNumSymmetricCipherAlgs;
#else
	*numAlgs = 0;
#endif

	return( kPGPError_NoErr );
}


	PGPError
PGPGetIndexedSymmetricCipherInfo(
	PGPUInt32					idx,
	PGPSymmetricCipherInfo *	info)
{
#if PGP_HAVE_SYMMETRIC_CIPHERS	/* [ */

	PGPValidatePtr( info );
	pgpClearMemory( info, sizeof( *info ) );
	PGPValidateParam( idx < kNumSymmetricCipherAlgs );

	*info	= sSymmetricCipherAlgs[ idx ];
	
	sEnsureSymmetricCipherLinked( info->algID );

	return( kPGPError_NoErr );

#else	/* ] PGP_HAVE_SYMMETRIC_CIPHERS [ */

	(void) idx;
	(void) info;
	
	return( kPGPError_BadParams );
	
#endif	/* ] PGP_HAVE_SYMMETRIC_CIPHERS */	
}
				



		
/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
