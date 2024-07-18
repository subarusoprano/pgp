// $Id: setup.h,v 1.93.2.26.2.13.2.44 2000/08/26 20:32:40 build Exp $
//____________________________________________________________________________
//	Copyright (C) 1999 Network Associates Inc. and affiliated companies.
//	All rights reserved.
//	
//  Author: Philip Nathan
//____________________________________________________________________________


////////////////////// global defines ////////////////////////////
	#ifndef TITLE
		#define TITLE                   "PGP 6.5.8ckt - Build:08"
	#endif
	
	#ifndef TITLE2
		//no newline title
		#define TITLE2                  "PGP 6.5.8ckt - Build:08"
	#endif

	#ifndef PRODUCT_VERSION
		#define PRODUCT_VERSION			"PGP 6.5.8ckt - Build:08"
	#endif
	
//////////////////////      Flags     ////////////////////////////
	#ifndef PERSONALPRIVACY
		#define PERSONALPRIVACY			"FALSE"      // TRUE or FALSE
	#endif
	
	#ifndef FREEWARE
		#define FREEWARE				"FALSE"      // TRUE or FALSE	
	#endif

	#ifndef INCLUDE_PGPDISK
		#define INCLUDE_PGPDISK			"TRUE"		// TRUE or FALSE	
	#endif
	
	#ifndef INCLUDE_GROUPWISE
		#define INCLUDE_GROUPWISE		"FALSE"		// TRUE or FALSE	
	#endif
	
	#ifndef WINNTONLY
		#define WINNTONLY				"FALSE"		// TRUE or FALSE	
	#endif
	
	#ifndef ALLOWDUALPROCESSORS
		#define ALLOWDUALPROCESSORS		"TRUE"		// TRUE or FALSE	
	#endif

	#ifndef INCLUDECOMMANDLINE
		#define INCLUDECOMMANDLINE		"TRUE"		// TRUE or FALSE	
	#endif

	#ifndef INCLUDE_LOTUS
		#define INCLUDE_LOTUS			"FALSE"		// TRUE or FALSE	
	#endif







