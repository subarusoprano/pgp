/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: RDlstsrt.c,v 1.4 1999/03/10 03:01:01 heller Exp $
____________________________________________________________________________*/

#include "RDprecmp.h"


/*
 * ListSort.c  List View sorting routine
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

//BEGIN KEY ID COLUMN IN KEY SELECTION DIALOG - Imad R. Faiad
CompareStringsIgnoreCase(
	const char *	s1,
	const char *	s2 )
{
	while ((*s1 != 0) && (*s2 != 0) && (tolower(*s1) == tolower(*s2))) {
		s1++;
		s2++;
	}
	return (*s1 - *s2);
}
//END KEY ID COLUMN IN KEY SELECTION DIALOG



int CALLBACK ListViewCompareProc(LPARAM lParam1,
                                 LPARAM lParam2,LPARAM lParamSort)
{
    PUSERKEYINFO pui1,pui2;
    int result;
    int *SortSub;
    BOOL *SortAscending;
    HWND hwnd;
	PRECGBL prg;

    hwnd=(HWND)lParamSort;

	prg=(PRECGBL)GetWindowLong(GetParent(hwnd),GWL_USERDATA);

    if(hwnd==prg->hwndRecipients)
    {
        SortSub=&(prg->RSortSub);
        SortAscending=&(prg->RSortAscending);
    }
    else
    {
        SortSub=&(prg->USortSub);
        SortAscending=&(prg->USortAscending);
    }

    pui1=(PUSERKEYINFO)lParam1;
    pui2=(PUSERKEYINFO)lParam2;

    switch(*SortSub)
    {
        case HEADUSERID:
        {
            if(*SortAscending)
                result=PGPCompareUserIDStrings(pui1->UserId,pui2->UserId);
            else
                result=PGPCompareUserIDStrings(pui2->UserId,pui1->UserId);
            break;
        }
        case HEADVALIDITY:
        {
            if(*SortAscending)
                result=(pui2->Validity)-(pui1->Validity);
            else
                result=(pui1->Validity)-(pui2->Validity);
            break;
        }
		/*
        case HEADTRUST:
        {
            if(*SortAscending)
                result=(pui2->Trust)-(pui1->Trust);
            else
                result=(pui1->Trust)-(pui2->Trust);
            break;
        }*/
        case HEADSIZE:
        {
            if(*SortAscending)
                result=(atoi(pui2->szSize))-(atoi(pui1->szSize));
            else
                result=(atoi(pui1->szSize))-(atoi(pui2->szSize));
            break;
        }
		//BEGIN KEY ID COLUMN IN KEY SELECTION DIALOG - Imad R. Faiad
		case HEADKEYID:
         {
			if(*SortAscending)
				result=CompareStringsIgnoreCase(pui1->szID,pui2->szID);
			else
				result=CompareStringsIgnoreCase(pui2->szID,pui1->szID);
		 }
		//END KEY ID COLUMN IN KEY SELECTION DIALOG

    }

    return result;
}

void SortEm(HWND hwndLView)
{
    ListView_SortItems(hwndLView,ListViewCompareProc,(LPARAM)hwndLView);
}


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/

