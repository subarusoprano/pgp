/*____________________________________________________________________________
	Copyright (C) 1998 Network Associates, Inc.
	All rights reserved.
	
	KMConvrt.c - miscellaneous conversion routines
	

	$Id: KMConvrt.c,v 1.6 1999/01/05 00:50:10 pbj Exp $
____________________________________________________________________________*/
#include "pgpPFLConfig.h"	

// project header files
#include "pgpkmx.h"

// external globals
extern HINSTANCE g_hInst;

//	________________________
//
//	Convert tm to SystemTime

VOID 
sTimeToSystemTime (
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

//BEGIN DATE AND TIME DISPLAY MOD - Imad R. Faiad
void
KMGetPrefLongDateDisplay ( PGPUInt32 *HLongDateDisplay )
{
	HKEY	hKey;
	LONG	lResult;
	DWORD	dw;
	char	path[] = "Software\\Network Associates\\PGP\\PrefLongDateDisplay";

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
						"PrefLongDateDisplay", 
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
							"PrefLongDateDisplay", 
							0, 
							REG_DWORD, 
							(LPBYTE)&dw, 
							sizeof(dw));

			RegCloseKey (hKey);

		}
	}

	*HLongDateDisplay = (PGPUInt32) dw;
}

void
KMSetPrefLongDateDisplay ( PGPUInt32 HLongDateDisplay )
{
	HKEY	hKey;
	LONG	lResult;
	DWORD	dw = (DWORD) HLongDateDisplay;
	char	path[] = "Software\\Network Associates\\PGP\\PrefLongDateDisplay";

	if ((dw < 0) || (dw > 1)) dw = 1;

	lResult = RegOpenKeyEx(	HKEY_CURRENT_USER,
							path, 
							0, 
							KEY_ALL_ACCESS, 
							&hKey);

	if (lResult == ERROR_SUCCESS) 
	{

		RegSetValueEx (	hKey, 
							"PrefLongDateDisplay", 
							0, 
							REG_DWORD, 
							(LPBYTE)&dw, 
							sizeof(dw));
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
			dw = (DWORD) HLongDateDisplay;
			if ((dw < 0) || (dw > 1)) dw = 1;

			RegSetValueEx (	hKey, 
							"PrefLongDateDisplay", 
							0, 
							REG_DWORD, 
							(LPBYTE)&dw, 
							sizeof(dw));

			RegCloseKey (hKey);

		}
	}
}
//END DATE AND TIME DISPLAY MOD

//	______________________________________________________
//
//	Convert time to string format based on system settings

VOID
KMConvertTimeToString (
		PGPTime		Time, 
		LPSTR		sz, 
		INT			iLen) 
{
	struct tm*	ptm				= NULL;
	SYSTEMTIME	systemtime;
	time_t		ttTime;
		
    CHAR szDate[20] = "";
    CHAR szTime[20] = "";
	
	//BEGIN DATE AND TIME DISPLAY MOD - Imad R. Faiad
	PGPUInt32			uLongDateDisplay;
	//END DATE AND TIME DISPLAY MOD

	if (Time > 0)
	{
		ttTime = PGPGetStdTimeFromPGPTime (Time);
		ptm = localtime (&ttTime);
	}

	if (ptm) {
		sTimeToSystemTime (ptm, &systemtime);

		//BEGIN DATE AND TIME DISPLAY MOD - Imad R. Faiad

		KMGetPrefLongDateDisplay (&uLongDateDisplay);

		if (uLongDateDisplay == 1) {
			GetTimeFormat (LOCALE_USER_DEFAULT,
			(TIME_FORCE24HOURFORMAT | TIME_NOTIMEMARKER), &systemtime, NULL, szTime, 20);
			GetDateFormat (LOCALE_USER_DEFAULT, DATE_SHORTDATE, &systemtime, NULL, szDate, 20);
			if (!((INT)(lstrlen (szDate) + lstrlen (szTime) + 2) > iLen))
			wsprintf (sz, "%s %s", szDate, szTime);
		}
		
		else {
			GetDateFormat (LOCALE_USER_DEFAULT, DATE_SHORTDATE, &systemtime, 
			NULL, sz, iLen);
		}
		//END DATE AND TIME DISPLAY MOD - Imad R. Faiad
	}
	else 
		LoadString (g_hInst, IDS_INVALIDDATE, sz, iLen);
}


//	______________________________________________________
//
//	Convert time to Win32 systemtime

VOID
KMConvertTimeToDays (
		PGPTime		time, 
		INT*		piDays) 
{
	SYSTEMTIME	st;
	time_t		ttTime;
	struct tm*	ptm;

	if (piDays == NULL) return;
	*piDays = 0;

	ttTime = PGPGetStdTimeFromPGPTime (time);
	ptm = localtime (&ttTime);

	if (ptm) {
		sTimeToSystemTime (ptm, &st);
		PGPclSystemTimeToDays (&st, piDays);
	}
}


//	___________________________________________________________
//
//	Convert Fingerprint from string format to presentation format
//	NB: sz must be at least 42 bytes long for RSA and 52 bytes
//     for DSA keys

VOID 
KMConvertStringFingerprint (
	    //BEGIN RSAv4 SUPPORT MOD - Disastry
		//UINT	uAlgorithm, 
		UINT	uSize, 
	    //END RSAv4 SUPPORT MOD
		LPSTR	sz) 
{
	INT		i;
	UINT	u;
	CHAR	szBuf[20];
	CHAR*	p;

	//BEGIN RSAv4 SUPPORT MOD - Disastry
	//switch (uAlgorithm)
	switch (uSize)
	//END RSAv4 SUPPORT MOD
    {
	//BEGIN RSAv4 SUPPORT MOD - Disastry
	//case kPGPPublicKeyAlgorithm_RSA :
    case 16 :
	//END RSAv4 SUPPORT MOD
		memcpy (szBuf, sz, 16);
		p = sz;
		for (i=0; i<16; i+=2) {
			switch (i) {
			case 0:
				break;
			case 8:
				*p++ = ' ';
			default :
				*p++ = ' ';
				break;
			}
			u = ((unsigned long)szBuf[i] & 0xFF);
			u <<= 8;
			u |= ((unsigned long)szBuf[i+1] & 0xFF);
			wsprintf (p, "%04lX", u);
			p += 4;
		}
		break;

	//BEGIN RSAv4 SUPPORT MOD - Disastry
	//case kPGPPublicKeyAlgorithm_DSA :
    case 20 :
	//END RSAv4 SUPPORT MOD
		memcpy (szBuf, sz, 20);
		p = sz;
		for (i=0; i<20; i+=2) {
			switch (i) {
			case 0:
				break;
			case 10:
				*p++ = ' ';
			default :
				*p++ = ' ';
				break;
			}
			u = ((unsigned long)szBuf[i] & 0xFF);
			u <<= 8;
			u |= ((unsigned long)szBuf[i+1] & 0xFF);
			wsprintf (p, "%04lX", u);
			p += 4;
		}
		break;

	default :
		lstrcpy (sz, "");
		break;
	}
}

//	________________________________________________
//
//	Convert trust from weird PGP values to 0-3 scale

UINT 
KMConvertFromPGPTrust (UINT uPGPTrust) 
{
	switch (uPGPTrust & kPGPKeyTrust_Mask) {
	case kPGPKeyTrust_Undefined	:
	case kPGPKeyTrust_Unknown :
	case kPGPKeyTrust_Never :
		return 0;
	case kPGPKeyTrust_Marginal :
		return 1;
	case kPGPKeyTrust_Complete :
	case kPGPKeyTrust_Ultimate :
		return 2;
	default :
		return 0;
	}
}

//	___________________________________________________
//
//	Convert validity from weird PGP values to 0-2 scale

UINT 
KMConvertFromPGPValidity (UINT uPGPValidity) 
{
	switch (uPGPValidity) {
	case kPGPValidity_Unknown :
	case kPGPValidity_Invalid :
		return KM_VALIDITY_INVALID;
	case kPGPValidity_Marginal :
		return KM_VALIDITY_MARGINAL;
	case kPGPValidity_Complete :
		return KM_VALIDITY_COMPLETE;
	default :
		return 0;
	}
}

//	__________________________________________
//
//	Convert trust from 0-3 scale to PGP values

UINT 
KMConvertToPGPTrust (UINT uTrust) 
{
	switch (uTrust & 0x03) {
	case 0 :
		return kPGPKeyTrust_Never;
	case 1 :
		return kPGPKeyTrust_Marginal;
	case 2 :
		return kPGPKeyTrust_Complete;
	case 3 :
		return kPGPKeyTrust_Ultimate;
	default :
		return 0;
	}
}


