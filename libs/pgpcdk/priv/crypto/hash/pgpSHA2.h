/*
 * pgpSHA2.h -- NIST Secure Hash Algorithm 2
 *
 * This is a PRIVATE header file, for use only within the PGP Library.
 * You should not be using these functions in an application.
 *
 * $Id: pgpSHA2.h,v 1.0 2001/01/15 03:06:31 disastry Exp $
 */

#ifndef Included_pgpSHA2_h
#define Included_pgpSHA2_h

#include "pgpHashPriv.h"
#include "pgpDebug.h"

PGP_BEGIN_C_DECLARATIONS

extern PGPHashVTBL const HashSHA256;
extern PGPHashVTBL const HashSHA384;
extern PGPHashVTBL const HashSHA512;

PGP_END_C_DECLARATIONS

#endif /* !Included_pgpSHA2_h */
