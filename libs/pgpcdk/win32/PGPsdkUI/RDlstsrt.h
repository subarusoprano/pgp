/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: RDlstsrt.h,v 1.3 1999/03/10 03:01:21 heller Exp $
____________________________________________________________________________*/
#ifndef Included_RDLSTSRT_h	/* [ */
#define Included_RDLSTSRT_h

/*
 * ListSort.h  List View sorting routine
 *
 * Apparently the sorting algorithm used in PGPlib is somehow different than
 * Microsoft employs in their standard listview control. This makes things 
 * sometimes confusing, since PGPkeys follows the PGPlib convention. Albeit
 * bucking PC GUI standards SortEm changes the listview sort to comply with
 * PGPlib and PGPkeys.
 *
 * Copyright (C) 1996 Network Associates Inc. and affiliated companies.
 * All rights reserved.
 */

void SortEm(HWND hwndLView);

int CALLBACK ListViewCompareProc(LPARAM lParam1,
                                 LPARAM lParam2,LPARAM lParamSort);
#define HEADUSERID 0
#define HEADVALIDITY 1
//#define HEADTRUST 2
#define HEADSIZE 2

//BEGIN KEY ID COLUMN IN KEY SELECTION DIALOG - Imad R. Faiad
#define HEADKEYID 3
//END KEY ID COLUMN IN KEY SELECTION DIALOG


#endif /* ] Included_RDLSTSRT_h */


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
