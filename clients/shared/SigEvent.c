/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.
	
	


	$Id: SigEvent.c,v 1.19 1999/03/10 03:03:18 heller Exp $



____________________________________________________________________________*/

#include <windows.h>
#include <windowsx.h>
#include <stdio.h>

#include "pgpKeys.h"
#include "pgpConfig.h"
#include "pgpErrors.h"
#include "pgpEncode.h"
#include "pgpUtilities.h"
#include "..\include\PGPsc.h"
#include "pgpPubTypes.h"

void SigTimeToSystemTime (
	struct tm*	ptm, 
	SYSTEMTIME* pst) 
{
	pst->wYear = ptm->tm_year + 1900;
	pst->wMonth = ptm->tm_mon + 1;
	pst->wDay = ptm->tm_mday;
	pst->wDayOfWeek = ptm->tm_wday;
	pst->wHour = ptm->tm_hour;
	pst->wMinute = ptm->tm_min;
	pst->wSecond = ptm->tm_sec;
	pst->wMilliseconds = 0;
}

void ConvertSigTimeToString (
		PGPTime		Time, 
		LPSTR		sz, 
		INT			iLen) 
{
	SYSTEMTIME	systemtime;
	time_t		ttTime;
	struct tm*	ptm;

	ttTime = PGPGetStdTimeFromPGPTime (Time);
	ptm = localtime (&ttTime);

	SigTimeToSystemTime (ptm, &systemtime);
	GetDateFormat(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &systemtime, 
		NULL, sz, iLen);
	strcat(sz," ");
	GetTimeFormat(LOCALE_USER_DEFAULT, LOCALE_NOUSEROVERRIDE, &systemtime,
		NULL, &(sz[strlen(sz)]),iLen-strlen(sz));
}
//BEGIN 64 BITS KEY ID DISPLAY MOD - Imad R. Faiad
void
SEGetPref64BitsKeyIDDisplay ( PGPUInt32 *H64BitsKeyIDDisplay )
{
	HKEY	hKey;
	LONG	lResult;
	DWORD	dw;
	char	path[] = "Software\\Network Associates\\PGP\\Pref64BitsKeyIDDisplay";

	lResult = RegOpenKeyEx(	HKEY_CURRENT_USER,
							path, 
							0, 
							KEY_ALL_ACCESS, 
							&hKey);

	if (lResult == ERROR_SUCCESS) 
	{
		DWORD  size = sizeof(dw);
		DWORD  type = 0;

		RegQueryValueEx(hKey, 
						"64BitsKeyIDDisplay", 
						0, 
						&type, 
						(LPBYTE)&dw, 
						&size);
		if ((dw < 0) || (dw > 1)) dw = 1;
		RegCloseKey (hKey);
	}
	else // Init Values
	{
		lResult = RegCreateKeyEx (	HKEY_CURRENT_USER, 
									path, 
									0, 
									NULL,
									REG_OPTION_NON_VOLATILE, 
									KEY_ALL_ACCESS, 
									NULL, 
									&hKey, 
									&dw);

		if (lResult == ERROR_SUCCESS) 
		{
			dw = 0;

			RegSetValueEx (	hKey, 
							"64BitsKeyIDDisplay", 
							0, 
							REG_DWORD, 
							(LPBYTE)&dw, 
							sizeof(dw));

			RegCloseKey (hKey);

		}
	}

	*H64BitsKeyIDDisplay = (PGPUInt32) dw;
}
//END 64 BITS KEY ID DISPLAY MOD
BOOL SEGetKeyIDString(PGPKeyID KeyID, LPSTR sz, UINT u) 
{

	CHAR		szID[kPGPMaxKeyIDStringSize];
	//BEGIN KEY ID COLUMN IN PGPLOG - Imad R. Faiad
	UINT		uDisplay;
	PGPBoolean	abbrev;
	if (u < 19) return FALSE;

	SEGetPref64BitsKeyIDDisplay(&uDisplay);

	if (uDisplay == 1)
		abbrev = kPGPKeyIDString_Full;
	else
		abbrev = kPGPKeyIDString_Abbreviated;
	//END KEY ID COLUMN IN PGPLOG - Imad R. Faiad

	PGPGetKeyIDString (&KeyID, abbrev, szID);
	lstrcpy (sz, "0x");
	lstrcat (sz, &szID[2]);

	return TRUE;
}

// SigEvent
//
// Call after kPGPEvent_SignatureEvent. Must link to PGPsc.
//
// Params:
//    d          Event data (cast)
//    fileName   fileName (or application name)

void SigEvent(HWND hwnd,PGPContextRef context,
			  PGPEventSignatureData *d,char *fileName)
{
	DWORD Validity;
	PGPBoolean bAxiomatic,bKeyCanSign;
	char szMsgStr[500];
	BOOL bMarginalInvalid;

//BEGIN KEY ID COLUMN IN PGPLOG - Imad R. Faiad	
	char mykeyidstr[19];
//END KEY ID COLUMN IN PGPLOG

	bAxiomatic=FALSE;
	bKeyCanSign=TRUE;

	// Icon information for PGPlog

	if(d->verified)
		strcpy(szMsgStr,"Good Signature\n");
	else
		strcpy(szMsgStr,"Bad Signature\n");

	// Filename (or Clipboard... or Eudora.. etc)
	sprintf(&(szMsgStr[strlen(szMsgStr)]),"%s\n",
		JustFile(fileName));

	// Get name and raw Validity number
	if((d->signingKey)==0)
	{
//BEGIN KEY ID COLUMN IN PGPLOG - Imad R. Faiad
		//char keyidstr[11];
		char keyidstr[19];
//END KEY ID COLUMN IN PGPLOG

		SEGetKeyIDString(d->signingKeyID,keyidstr,sizeof(keyidstr));
		
		strcat(szMsgStr,"(Unknown, KeyID=");
		strcat(szMsgStr,keyidstr);
		strcat(szMsgStr,")\n");
		Validity=kPGPValidity_Unknown ;
	}
	else
	{
		int namelen=kPGPMaxUserIDSize-1;
		char name[kPGPMaxUserIDSize];

		PGPGetPrimaryUserIDNameBuffer( d->signingKey,
			sizeof( name ), name, &namelen );
		sprintf(&(szMsgStr[strlen(szMsgStr)]),"%s\n",name);

		PGPGetKeyNumber(d->signingKey,kPGPKeyPropValidity,
			&Validity);

	    PGPGetKeyBoolean (d->signingKey, kPGPKeyPropIsAxiomatic, 
			&bAxiomatic);

	    PGPGetKeyBoolean (d->signingKey, kPGPKeyPropIsSigningKey, 
			&bKeyCanSign);
	}

	//BEGIN KEY ID COLUMN IN PGPLOG - Imad R. Faiad
	SEGetKeyIDString(d->signingKeyID,mykeyidstr,sizeof(mykeyidstr));
	strcat(szMsgStr,mykeyidstr);
	strcat(szMsgStr,"\n");
	//END KEY ID COLUMN IN PGPLOG

	// Decode validity into string

	if(bAxiomatic)
		strcat(szMsgStr,"Implicit Trust\n"); // Axiomatic
	else switch(Validity)
	{
		case kPGPValidity_Marginal :
			strcat(szMsgStr,"Marginal Key\n");
			break;
		case kPGPValidity_Complete :
			strcat(szMsgStr,"Valid Key\n");
			break;
		default :
			strcat(szMsgStr,"Invalid Key\n");
			break;
	}

	// Output date and/or extra info
	if(!bKeyCanSign)
		strcat(szMsgStr,"Signing algorithm not supported");
	else if((d->verified==0)&&(d->signingKey!=0))
		strcat(szMsgStr,"Bad Signature\n");
	else
	{
/*		sprintf(&(szMsgStr[strlen(szMsgStr)]), 
			"%s", ctime((time_t *)&d->creationTime));

		// Get rid of ctime \n
		szMsgStr[strlen(szMsgStr)-1]=0;*/

		GetMarginalInvalidPref(context,&bMarginalInvalid);

		ConvertSigTimeToString (
			d->creationTime,
			&(szMsgStr[strlen(szMsgStr)]),
			500-strlen(szMsgStr));

		if(d->signingKey==0)
			strcat(szMsgStr," (Unknown Key)");
		else if (d->keyRevoked)
			strcat(szMsgStr," (Revoked Key)");
		else if (d->keyExpired)
			strcat(szMsgStr," (Expired Key)");
		else if (d->keyDisabled)
			strcat(szMsgStr," (Disabled Key)");
		else if((Validity==kPGPValidity_Unknown)||
		   (Validity==kPGPValidity_Invalid))
			strcat(szMsgStr," (Invalid Key)");
		else if((bMarginalInvalid)&&
			(Validity==kPGPValidity_Marginal))
			strcat(szMsgStr," (Invalid Key)");
	}
				
	// Send DDEML msg to PGPlog
	SendPGPlogMsg(hwnd,szMsgStr);
}

/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
