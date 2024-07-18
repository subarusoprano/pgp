/*
 * $Id: pgpRSAKey.h,v 1.14 1998/06/11 18:28:23 hal Exp $
 */

#ifndef Included_pgpRSAKey_h
#define Included_pgpRSAKey_h


#include "pgpSDKBuildFlags.h"

#ifndef PGP_RSA
#error "PGP_RSA requires a value"
#endif

#if PGP_RSA

#include "pgpPubTypes.h"	/* For PGPBoolean and PGPByte */
#include "pgpOpaqueStructs.h"

PGP_BEGIN_C_DECLARATIONS

PGPPubKey *rsaPubFromBuf(PGPContextRef	context,
				PGPByte const *buf, size_t len, PGPError *error);
				
PGPSecKey *rsaSecFromBuf( PGPContextRef	context,
				PGPByte const *buf, size_t len, PGPBoolean v3,
				PGPError *error);
				
int rsaPubKeyPrefixSize(PGPByte const *buf, size_t size);

PGPSecKey *rsaSecGenerate( PGPContextRef	context,
				unsigned bits, PGPBoolean fastgen,
				PGPRandomContext const *rc,
				int progress(void *arg, int c), void *arg, PGPError *error
	            //BEGIN RSAv4 SUPPORT MOD - Disastry
                , PGPBoolean v3
	            //END RSAv4 SUPPORT MOD
                );

PGP_END_C_DECLARATIONS

#endif /* PGP_RSA */

#endif /* Included_pgpRSAKey_h */
