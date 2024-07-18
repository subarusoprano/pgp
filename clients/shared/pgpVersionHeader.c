/*____________________________________________________________________________
	Copyright (C) 6.5.1 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: pgpVersionHeader.c,v 1.137.2.28.2.10 1999/07/01 21:28:25 build Exp $
____________________________________________________________________________*/
#include "pgpBuildFlags.h"
#include "pgpVersionHeader.h"

extern char pgpVersionHeaderString[] =
#if PGP_BUSINESS_SECURITY
	"6.5.8ckt <http://www.ipgpp.com/>";
#elif PGP_PERSONAL_PRIVACY
	"6.5.8ckt <http://www.ipgpp.com/>";
#elif PGP_FREEWARE
	"PGPfreeware 6.5.1 Int. for non-commercial use <http://www.pgpinternational.com>";
#elif PGP_DEMO
	"PGP Personal Privacy 6.5.1 Int. Trialware";
#else
	#error unknown build
#endif

//BEGIN VERSION STRING MOD - Imad R. Faiad
extern const char gDefaultVersionString [] = "6.5.8ckt http://www.ipgpp.com/";
//END VERSION STRING MOD

/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/


