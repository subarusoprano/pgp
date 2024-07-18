/*____________________________________________________________________________
    config.h

    Copyright(C) 1998,1999 Network Associates, Inc.
    All rights reserved.

	PGP 6.5 Command Line 

    $Id: config.h,v 1.14 1999/05/12 21:01:03 sluu Exp $
____________________________________________________________________________*/

#ifndef CONFIGP_H
#define CONFIGP_H

#include "pgpBase.h"

#if PGP_WIN32
#define MSDOS
#endif

/* how to delay an arbitrary number of milliseconds.
   used in pgpAcquireEntropy */
#if PGP_UNIX
#define SLEEP_POLL 1
#define SLEEP_SELECT 0
#endif

#if PGP_WIN32
#define SLEEP_SELECT 1
#define SLEEP_POLL 0
#endif

#if SLEEP_POLL || SLEEP_SELECT
#define SLEEP_UNKNOWN 0
#else
#define SLEEP_UNKNOWN 1
#endif

#define kMaxPassPhraseLength 254
//BEGIN SHA DOUBLE MOD - Imad R. Faiad
//#define kMaxDSS_Bits 1024
#define kMaxDSS_Bits 2048
//END SHA DOUBLE MOD
#define kMaxKeyExpirationDays 10950
        /* 30 years */

 /*
    Currently if the for-your-eyes-only buffer isn't large enough,
    there is no way to catch the error.
  */
#ifdef HUGE_MORE_BUFFER
#define kMaxMoreBufferLength 16777216
#else
#ifdef TINY_MORE_BUFFER
#define kMaxMoreBufferLength 16384
#else
#define kMaxMoreBufferLength 524288
        /* a reasonable upper limit */
#endif
#endif

/* The maximum length of the file path for this system.  Varies on UNIX
   systems */

#ifndef MAX_PATH
#if defined(MSDOS) && !defined(WIN32)
#define MAX_PATH 64
#elif defined(WIN32)
#define MAX_PATH 260
#else
#define MAX_PATH 256
#endif
#endif


#if PGP_DEBUG || UNFINISHED_CODE_ALLOWED
#define TEMP_VERSION
#endif

/* The types of input we can expect */

typedef enum { BOOLE, NUMERIC, STRING } INPUT_TYPE;

struct pgpenvBones;
int processConfigLine( struct pgpenvBones *envbPtr, char *option,
        PGPInt32 pri );
int processConfigFile( struct pgpenvBones *envbPtr, char *configFileName,
        PGPInt32 pri );

#endif /* ifndef CONFIGP_H */
