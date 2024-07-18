/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: VerificationBlock.c,v 1.6 1999/03/10 03:04:51 heller Exp $
____________________________________________________________________________*/

#include <windows.h>
#include <windowsx.h>
#include <stdio.h>

#include "pgpKeys.h"
#include "pgpConfig.h"
#include "pgpErrors.h"
#include "pgpEncode.h"
#include "pgpUtilities.h"
#include "pgpPubTypes.h"
#include "pgpMem.h"

#include "Prefs.h"
#include "SharedStrings.h"
//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
#include "pgpClientPrefs.h"
#include "PGPcl.h"
//END VERIFICATION BLOCK STRING

static void StdTimeToSystemTime(struct tm *ptm, SYSTEMTIME *pst) 
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


static void ConvertPGPTimeToString(PGPTime time,
								   char *dateString, 
								   PGPUInt32 dateStrLength,
								   char *timeString,
								   PGPUInt32 timeStrLength) 
{
	SYSTEMTIME	systemtime;
	time_t		ttTime;
	struct tm*	ptm;

	ttTime = PGPGetStdTimeFromPGPTime(time);
	ptm = localtime(&ttTime);

	StdTimeToSystemTime(ptm, &systemtime);

	GetDateFormat(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &systemtime, 
		NULL, dateString, dateStrLength);

	GetTimeFormat(LOCALE_USER_DEFAULT, LOCALE_NOUSEROVERRIDE, &systemtime,
		NULL, timeString, timeStrLength);

	return;
}


static PGPBoolean GetKeyIDString(PGPKeyID keyID, 
								 char *idBuffer, 
								 PGPUInt32 bufferSize) 
{

	char tempBuffer[kPGPMaxKeyIDStringSize];

	if (bufferSize < 11) return FALSE;

	PGPGetKeyIDString(&keyID, kPGPKeyIDString_Abbreviated, tempBuffer);
	lstrcpy(idBuffer, "0x");
	lstrcat(idBuffer, &tempBuffer[2]);

	return TRUE;
}
//BEGIN 64 BITS KEY ID DISPLAY MOD - Imad R. Faiad
void
VBGetPref64BitsKeyIDDisplay ( PGPUInt32 *H64BitsKeyIDDisplay )
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
//BEGIN SIGNER KEY INFO IN VERIFICATION BLOCK - Imad R. Faiad
static PGPBoolean GetKeyIDString64(PGPKeyID keyID, 
								 char *idBuffer, 
								 PGPUInt32 bufferSize) 
{

	char tempBuffer[kPGPMaxKeyIDStringSize];
	UINT		u, uMinBufSize;
	PGPBoolean	abbrev;

	VBGetPref64BitsKeyIDDisplay(&u);

	if (u == 1) {
		abbrev = kPGPKeyIDString_Full;
		uMinBufSize = 19;
	}
	else {
		abbrev = kPGPKeyIDString_Abbreviated;
		uMinBufSize = 11;
	}


	if (bufferSize < uMinBufSize) return FALSE;

	PGPGetKeyIDString(&keyID, abbrev, tempBuffer);
	lstrcpy(idBuffer, "0x");
	lstrcat(idBuffer, &tempBuffer[2]);

	return TRUE;
}

VOID 
VBConvertStringFingerprint (
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
//END SIGNER KEY INFO IN VERIFICATION BLOCK

//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
void GetVerificationBlockString(PGPMemoryMgrRef memoryMgr, 
					  char *szVBlockStr, 
					  int nLength, char * datetimeString)
{
	UINT				u = kVBSPrefOff;
	PGPPrefRef			prefRef = NULL;
	char				tempString[256];
	PGPUInt32			HashResult[5];//160 bits
	PGPHashContextRef	HashRef;
	PGPError			err = kPGPError_NoErr;

	strcpy(szVBlockStr,"");

	PGPclOpenClientPrefs(memoryMgr, &prefRef);

	PGPGetPrefNumber(prefRef, kPGPPrefVerificationBlockStringType, &u);
	switch (u)
	{
	case kVBSPrefOff:
		break;

	case kVBSPrefCustom:
		PGPGetPrefStringBuffer(prefRef, kPGPPrefVerificationBlockString, nLength, szVBlockStr);
		break;

	case kVBSPrefVerifyDateTime:
		strcpy(szVBlockStr,datetimeString);
		break;

	case kVBSPrefRandomize:
		err = PGPNewHashContext( memoryMgr, kPGPHashAlgorithm_SHA, &HashRef );
		if (IsntPGPError( err ))
			err = PGPContinueHash( HashRef, datetimeString, strlen(datetimeString)+1 );
		if (IsntPGPError( err ))
			err = PGPFinalizeHash( HashRef, HashResult );
		if (IsntNull(HashRef)) PGPFreeHashContext( HashRef );
		if (IsntPGPError( err )) {
			srand( (unsigned)time( NULL ) );
			sprintf(tempString,"%.8X",HashResult[(rand() % 5)]);
			strcpy(szVBlockStr,tempString);
			}
		else
			strcpy(szVBlockStr,datetimeString);
		break;

	default:
		break;
	}

	PGPclCloseClientPrefs(prefRef, FALSE);

}
//END VERIFICATION BLOCK STRING

//Yuk! too much Butchering
//Here is the streamlined code - Imad R. Faiad
//Please note that the following HACK:-
//"wasEncrypted" is loaded with the
//cipher algorithm when this routine is called
PGPError CreateVerificationBlock(HINSTANCE hInst, 
								 PGPContextRef context,
								 PGPEventSignatureData *sigData, 
								 unsigned char wasEncrypted,
								 char **blockBegin,
								 char **blockEnd)
{
	PGPUInt32 validity;
	PGPBoolean isAxiomatic;
	PGPBoolean keyCanSign;
	PGPMemoryMgrRef memoryMgr;
	char dateString[256];
	char timeString[256];
	char datetimeString[256];
	char tempString[256];
	char keyIDStr[20];
	char szVBlockStr[256];
	PGPBoolean bAddVBlockStr;

	PGPError err = kPGPError_NoErr;

if (sigData) PGPValidatePtr(sigData);

	PGPValidatePtr(blockBegin);
	PGPValidatePtr(blockEnd);

	isAxiomatic = FALSE;
	keyCanSign = TRUE;

	memoryMgr = PGPGetContextMemoryMgr(context);


	ConvertPGPTimeToString(PGPGetTime(), dateString, sizeof(dateString),
		timeString, sizeof(timeString));

	strcpy(datetimeString, dateString);
	strcat(datetimeString, " ");
	strcat(datetimeString, timeString);

	GetVerificationBlockString(memoryMgr, tempString, sizeof(tempString), datetimeString);

	bAddVBlockStr = (strlen(tempString) > 0);
	
	if (bAddVBlockStr){
		strcpy(szVBlockStr,"***[");
		strcat(szVBlockStr,tempString);
		strcat(szVBlockStr,"] ");
	}
	else
		strcpy(szVBlockStr,"*** ");


	*blockBegin = (char *) PGPNewData(memoryMgr,
								1024,
								kPGPMemoryMgrFlags_Clear);
								
	if (IsNull(*blockBegin))
		return kPGPError_OutOfMemory;

	*blockEnd = (char *) PGPNewData(memoryMgr,
							1024,
							kPGPMemoryMgrFlags_Clear);
								
	if (IsNull(*blockEnd))
		return kPGPError_OutOfMemory;

if (sigData) {
	strcat(*blockBegin,"\r\n");
	strcat(*blockBegin, szVBlockStr);
	strcat(*blockBegin, "PGP Signature Status: ");

	if (sigData->signingKey != 0)
	    PGPGetKeyBoolean(sigData->signingKey, kPGPKeyPropIsSigningKey, 
			&keyCanSign);

	if (!keyCanSign)
		strcpy(tempString,"signing algorithm not supported\r\n");
	else if (sigData->verified)
		strcpy(tempString,"good\r\n");
	else if (sigData->signingKey == 0)
		strcpy(tempString,"unknown\r\n");
	else
		strcpy(tempString,"bad\r\n");

	strcat(*blockBegin, tempString);

	switch (sigData->SigHashAlgorithm)
	{
	case kPGPHashAlgorithm_Invalid:
		strcpy( tempString, "" );
		break;
	case kPGPHashAlgorithm_MD5:
		strcpy( tempString, "Hash: MD5\r\n" );
		break;
	case kPGPHashAlgorithm_SHA:
		strcpy( tempString, "Hash: SHA1\r\n" );
		break;
	case kPGPHashAlgorithm_SHADouble:
		strcpy( tempString, "Hash: SHA1x\r\n" );
		break;
	case kPGPHashAlgorithm_RIPEMD160:
		strcpy( tempString, "Hash: RIPEMD160\r\n" );
		break;
	case kPGPHashAlgorithm_SHA256:
		strcpy( tempString, "Hash: SHA256\r\n" );
		break;
	case kPGPHashAlgorithm_SHA384:
		strcpy( tempString, "Hash: SHA384\r\n" );
		break;
	case kPGPHashAlgorithm_SHA512:
		strcpy( tempString, "Hash: SHA512\r\n" );
		break;
	case kPGPHashAlgorithm_TIGER192:
		strcpy(tempString, "Hash: TIGER192\r\n");
		break;
	case 7: strcpy(tempString, "Hash: HAVAL-5-160(Not Implemented)\r\n");
		break;
	case 11: strcpy(tempString, "Hash: HAVAL-5-256(Not Implemented)\r\n");
		break;
	default:
		sprintf( tempString, "Hash: Unknown (Algorithm ID: %i\r\n)", sigData->SigHashAlgorithm );
		break;
	}
	if (tempString[0]) {
		strcat(*blockBegin, szVBlockStr);

		strcat(*blockBegin, tempString);
	}
	strcat(*blockBegin, szVBlockStr);
	strcpy(tempString, "Signer: ");
	strcat(*blockBegin, tempString);

	// Get name and raw Validity number
	if (sigData->signingKey == 0)
	{
		GetKeyIDString64(sigData->signingKeyID, keyIDStr, sizeof(keyIDStr));
		
		strcpy(tempString, "Unknown\r\n");

		strcat(*blockBegin, tempString);

		strcpy(tempString, "Signer Key ID:");

		strcat(*blockBegin, szVBlockStr);

		strcat(*blockBegin, tempString);
		strcat(*blockBegin, keyIDStr);
		strcat(*blockBegin,"\r\n");
	}
	else
	{
		int nameLength = kPGPMaxUserIDSize-1;
		char name[kPGPMaxUserIDSize];
		PGPByte		fingerprintBytes[256];
		UINT		u, uAlgorithm;
		PGPBoolean bAppendSigKeyStatus;

		PGPGetPrimaryUserIDNameBuffer(sigData->signingKey,
			sizeof(name), name, &nameLength);

		strcat(*blockBegin, name);	
		strcat(*blockBegin,"\r\n");
		GetKeyIDString64(sigData->signingKeyID, keyIDStr, sizeof(keyIDStr));

		strcpy(tempString, "Signer Key ID:");

		strcat(*blockBegin, szVBlockStr);

		strcat(*blockBegin, tempString);
		strcat(*blockBegin, " ");
		strcat(*blockBegin, keyIDStr);
		strcat(*blockBegin,"\r\n");

		PGPGetKeyPropertyBuffer(sigData->signingKey, kPGPKeyPropFingerprint,
					sizeof( fingerprintBytes ), fingerprintBytes, &u);
		PGPGetKeyNumber (sigData->signingKey, kPGPKeyPropAlgID, &uAlgorithm);

    	VBConvertStringFingerprint (u, fingerprintBytes);

		strcpy(tempString, "Signer Key Fingerprint:");

		strcat(*blockBegin, szVBlockStr);

		strcat(*blockBegin, tempString);
		strcat(*blockBegin, " ");
		strcat(*blockBegin, fingerprintBytes);
		bAppendSigKeyStatus = TRUE;

		PGPGetKeyNumber(sigData->signingKey, kPGPKeyPropValidity,
			&validity);

	    PGPGetKeyBoolean(sigData->signingKey, kPGPKeyPropIsAxiomatic, 
			&isAxiomatic);

		if (sigData->keyRevoked)
			strcpy(tempString, "Revoked\r\n");
		else if (sigData->keyExpired)
			strcpy(tempString, "Expired\r\n");
		else if (sigData->keyDisabled)
			strcpy(tempString, "Disabled\r\n");
		else if (!isAxiomatic)
		{
			if ((validity == kPGPValidity_Invalid) ||
				(validity == kPGPValidity_Unknown) ||
					((validity == kPGPValidity_Marginal) && 
					MarginalIsInvalid(memoryMgr)))
			{
				strcpy(tempString, "Invalid\r\n");
			}
			else {
				strcpy(tempString, "\r\n");
				bAppendSigKeyStatus = FALSE;
			}
		}
		else {
			strcpy(tempString, "\r\n");
			bAppendSigKeyStatus = FALSE;
		}

		if (bAppendSigKeyStatus) {
			strcat(*blockBegin, "\r\n");
			strcat(*blockBegin, szVBlockStr);
			strcat(*blockBegin,"Signer Key Status: ");
		}

		strcat(*blockBegin, tempString);
	}

	strcpy(tempString, "Signed: ");
	strcat(*blockBegin, szVBlockStr);
	strcat(*blockBegin, tempString);

	ConvertPGPTimeToString(sigData->creationTime, dateString, 
		sizeof(dateString), timeString, sizeof(timeString));

	strcat(*blockBegin, dateString);
	strcat(*blockBegin, " ");
	strcat(*blockBegin, timeString);
	strcat(*blockBegin, "\r\n");

	strcpy(tempString, "Verified: ");

	strcat(*blockBegin, szVBlockStr);

	strcat(*blockBegin, tempString);

	strcat(*blockBegin, datetimeString);
	strcat(*blockBegin, "\r\n");
}

	if (wasEncrypted)
	{
		PGPBoolean	bWasSigned=**blockBegin;
		if (!bWasSigned) strcat(*blockBegin,"\r\n");
		switch(wasEncrypted) {
		case kPGPCipherAlgorithm_IDEA:
			strcpy( tempString, "Cipher: IDEA\r\n" );
			break;
		case kPGPCipherAlgorithm_3DES:
			strcpy( tempString, "Cipher: 3DES\r\n" );
			break;
		case kPGPCipherAlgorithm_CAST5:
			strcpy( tempString, "Cipher: CAST5\r\n" );
			break;
		case kPGPCipherAlgorithm_BLOWFISH:
			strcpy( tempString, "Cipher: BLOWFISH\r\n" );
			break;
		case kPGPCipherAlgorithm_AES128:
			strcpy( tempString, "Cipher: AES128\r\n" );
			break;
		case kPGPCipherAlgorithm_AES192:
			strcpy( tempString, "Cipher: AES192\r\n" );
			break;
		case kPGPCipherAlgorithm_AES256:
			strcpy( tempString, "Cipher: AES256\r\n" );
			break;
		case kPGPCipherAlgorithm_Twofish256:
			strcpy( tempString, "Cipher: Twofish256\r\n" );
			break;
		case 5:
			strcpy(tempString, "Cipher: SAFER-SK128(Not Implemented)\r\n");
			break;
		case 6:
			strcpy(tempString, "Cipher: DES/SK(Not Implemented)\r\n");
			break;
		default:
			if ((wasEncrypted <100) || (wasEncrypted > 110))
				sprintf( tempString,
				"Cipher: Unknown (Algorithm ID: %i\r\n)", wasEncrypted );
			else
				sprintf( tempString,
				"Cipher: Private/Experimental (Algorithm ID: %i\r\n)", wasEncrypted );
			break;
		}
		
		strcat(*blockBegin, szVBlockStr);
		strcat(*blockBegin, tempString);

		if (bWasSigned)
			strcpy(tempString, "BEGIN PGP DECRYPTED/VERIFIED MESSAGE ***\r\n\r\n");
		else
			strcpy(tempString, "BEGIN PGP DECRYPTED MESSAGE ***\r\n\r\n");

		strcat(*blockBegin, szVBlockStr);
		strcat(*blockBegin, tempString);

		if (bWasSigned)
			strcpy(tempString, "END PGP DECRYPTED/VERIFIED MESSAGE ***\r\n\r\n");
		else
			strcpy(tempString, "END PGP DECRYPTED MESSAGE ***\r\n\r\n");

		strcpy(*blockEnd, "\r\n");
		strcat(*blockEnd, szVBlockStr);
		strcat(*blockEnd, tempString);
	}
	else
	{
		strcpy(tempString, "BEGIN PGP VERIFIED MESSAGE ***\r\n\r\n");
		strcat(*blockBegin, szVBlockStr);
		strcat(*blockBegin, tempString);
		strcpy(tempString, "END PGP VERIFIED MESSAGE ***\r\n");
		strcpy(*blockEnd, "\r\n\r\n");
		strcat(*blockEnd, szVBlockStr);
		strcat(*blockEnd, tempString);
	}

	return err;
}

//Here is the code in it's last butchered state
/*PGPError CreateVerificationBlock(HINSTANCE hInst, 
								 PGPContextRef context,
								 PGPEventSignatureData *sigData, 
								 unsigned char wasEncrypted,
								 char **blockBegin,
								 char **blockEnd)
{
	PGPUInt32 validity;
	PGPBoolean isAxiomatic;
	PGPBoolean keyCanSign;
	PGPMemoryMgrRef memoryMgr;
	char dateString[256];
	char timeString[256];
	char datetimeString[256];
	char tempString[256];
	//BEGIN SIGNER KEY INFO IN VERIFICATION BLOCK - Imad R. Faiad
	char keyIDStr[20];
	//END SIGNER KEY INFO IN VERIFICATION BLOCK

	//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
	char szVBlockStr[256];
	PGPBoolean bAddVBlockStr;
	//END VERIFICATION BLOCK STRING

	PGPError err = kPGPError_NoErr;

//BEGIN - VERIFICATION BLOCK STRING for encrypted msgs - Disastry
if (sigData)
//END
PGPValidatePtr(sigData);

	PGPValidatePtr(blockBegin);
	PGPValidatePtr(blockEnd);

	isAxiomatic = FALSE;
	keyCanSign = TRUE;

	memoryMgr = PGPGetContextMemoryMgr(context);

	//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad

	ConvertPGPTimeToString(PGPGetTime(), dateString, sizeof(dateString),
		timeString, sizeof(timeString));

	strcpy(datetimeString, dateString);
	strcat(datetimeString, " ");
	strcat(datetimeString, timeString);

	GetVerificationBlockString(memoryMgr, tempString, sizeof(tempString), datetimeString);

	bAddVBlockStr = (strlen(tempString) > 0);
	
	if (bAddVBlockStr){
		strcpy(szVBlockStr,"***[");
		strcat(szVBlockStr,tempString);
		strcat(szVBlockStr,"] ");
	}
	else
		strcpy(szVBlockStr,"*** ");
	//END VERIFICATION BLOCK STRING



	*blockBegin = (char *) PGPNewData(memoryMgr,
								1024,
								kPGPMemoryMgrFlags_Clear);
								
	if (IsNull(*blockBegin))
		return kPGPError_OutOfMemory;

	*blockEnd = (char *) PGPNewData(memoryMgr,
							1024,
							kPGPMemoryMgrFlags_Clear);
								
	if (IsNull(*blockEnd))
		return kPGPError_OutOfMemory;

	//LoadString(hInst, IDS_SIGSTATUS, tempString, sizeof(tempString));
	//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
	
	//BEGIN - VERIFICATION BLOCK STRING for encrypted msgs - Disastry
if (sigData) {
//END
	strcat(*blockBegin,"\r\n");
	//if (bAddVBlockStr) strcat(*blockBegin, szVBlockStr);
	strcat(*blockBegin, szVBlockStr);
	//END VERIFICATION BLOCK STRING
	strcat(*blockBegin, "PGP Signature Status: ");


	if (sigData->signingKey != 0)
	    PGPGetKeyBoolean(sigData->signingKey, kPGPKeyPropIsSigningKey, 
			&keyCanSign);

	if (!keyCanSign)
		strcpy(tempString,"signing algorithm not supported\r\n");
		//LoadString(hInst, IDS_ALGNOTSUPPORTED, tempString, 
			//sizeof(tempString));
	else if (sigData->verified)
		strcpy(tempString,"good\r\n");
		//LoadString(hInst, IDS_GOODSIG, tempString, sizeof(tempString));
	else if (sigData->signingKey == 0)
		strcpy(tempString,"unknown\r\n");
		//LoadString(hInst, IDS_UNKNOWNSIG, tempString, sizeof(tempString));
	else
		strcpy(tempString,"bad\r\n");
		//LoadString(hInst, IDS_BADSIG, tempString, sizeof(tempString));

	strcat(*blockBegin, tempString);
	
	//BEGIN SIGNATURE HASH ALGORITHM INFO IN VERIFICATION BLOCK - Imad R. Faiad
	switch (sigData->SigHashAlgorithm)
	{
	case kPGPHashAlgorithm_Invalid:
		strcpy( tempString, "" );
		break;
	case kPGPHashAlgorithm_MD5:
		strcpy( tempString, "Hash: MD5\r\n" );
		break;
	case kPGPHashAlgorithm_SHA:
		strcpy( tempString, "Hash: SHA1\r\n" );
		break;
	case kPGPHashAlgorithm_SHADouble:
		strcpy( tempString, "Hash: SHA1x\r\n" );
		break;
	case kPGPHashAlgorithm_RIPEMD160:
		strcpy( tempString, "Hash: RIPEMD160\r\n" );
		break;
	case kPGPHashAlgorithm_SHA256:
		strcpy( tempString, "Hash: SHA256\r\n" );
		break;
	case kPGPHashAlgorithm_SHA384:
		strcpy( tempString, "Hash: SHA384\r\n" );
		break;
	case kPGPHashAlgorithm_SHA512:
		strcpy( tempString, "Hash: SHA512\r\n" );
		break;
	case 6: strcpy(tempString, "Hash: TIGER192(Not Implemented)\r\n");
		break;
	case 7: strcpy(tempString, "Hash: HAVAL-5-160(Not Implemented)\r\n");
		break;
	case 11: strcpy(tempString, "Hash: HAVAL-5-256(Not Implemented)\r\n");
		break;
	default:
		sprintf( tempString, "Hash: Unknown (Algorithm ID: %i\r\n)", sigData->SigHashAlgorithm );
		break;
	}
	//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
	if (tempString[0]) {

		//if (bAddVBlockStr)
		//	strcat(*blockBegin, szVBlockStr);
		strcat(*blockBegin, szVBlockStr);

		strcat(*blockBegin, tempString);
	}
	//END VERIFICATION BLOCK STRING
	//END SIGNATURE HASH ALGORITHM INFO IN VERIFICATION BLOCK

	//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
	//if (bAddVBlockStr) strcat(*blockBegin, szVBlockStr);
	strcat(*blockBegin, szVBlockStr);
	//END VERIFICATION BLOCK STRING

	//LoadString(hInst, IDS_SIGNER, tempString, sizeof(tempString));
	strcpy(tempString, "Signer: ");
	strcat(*blockBegin, tempString);

	// Get name and raw Validity number
	if (sigData->signingKey == 0)
	{
		//BEGIN SIGNER KEY INFO IN VERIFICATION BLOCK - Imad R. Faiad
		//char keyIDStr[11];

		GetKeyIDString64(sigData->signingKeyID, keyIDStr, sizeof(keyIDStr));
		//END SIGNER KEY INFO IN VERIFICATION BLOCK
		
		//LoadString(hInst, IDS_UNKNOWNSIGNER, tempString, sizeof(tempString));
		strcpy(tempString, "Unknown\r\n");

		strcat(*blockBegin, tempString);
		//BEGIN SIGNER KEY INFO IN VERIFICATION BLOCK - Imad R. Faiad
		//LoadString(hInst, IDS_SIGNING_KEY_ID, tempString, sizeof(tempString));
		strcpy(tempString, "Signer Key ID:");

		//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
		//if (bAddVBlockStr) strcat(*blockBegin, szVBlockStr);
		strcat(*blockBegin, szVBlockStr);	
		//END VERIFICATION BLOCK STRING

		strcat(*blockBegin, tempString);
		//END SIGNER KEY INFO IN VERIFICATION BLOCK
		strcat(*blockBegin, keyIDStr);
		strcat(*blockBegin,"\r\n");
	}
	else
	{
		int nameLength = kPGPMaxUserIDSize-1;
		char name[kPGPMaxUserIDSize];
		//BEGIN SIGNER KEY INFO IN VERIFICATION BLOCK - Imad R. Faiad
		PGPByte		fingerprintBytes[256];
		UINT		u, uAlgorithm;
		PGPBoolean bAppendSigKeyStatus;
		//END SIGNER KEY INFO IN VERIFICATION BLOCK

		PGPGetPrimaryUserIDNameBuffer(sigData->signingKey,
			sizeof(name), name, &nameLength);

		strcat(*blockBegin, name);
		//BEGIN SIGNER KEY INFO IN VERIFICATION BLOCK - Imad R. Faiad		
		strcat(*blockBegin,"\r\n");
		GetKeyIDString64(sigData->signingKeyID, keyIDStr, sizeof(keyIDStr));

		//LoadString(hInst, IDS_SIGNING_KEY_ID, tempString, sizeof(tempString));
		strcpy(tempString, "Signer Key ID:");

		//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
		//if (bAddVBlockStr) strcat(*blockBegin, szVBlockStr);
		strcat(*blockBegin, szVBlockStr);
		//END VERIFICATION BLOCK STRING

		strcat(*blockBegin, tempString);
		strcat(*blockBegin, " ");
		strcat(*blockBegin, keyIDStr);
		strcat(*blockBegin,"\r\n");

		PGPGetKeyPropertyBuffer(sigData->signingKey, kPGPKeyPropFingerprint,
					sizeof( fingerprintBytes ), fingerprintBytes, &u);
		PGPGetKeyNumber (sigData->signingKey, kPGPKeyPropAlgID, &uAlgorithm);
    	//BEGIN RSAv4 SUPPORT MOD - Disastry
    	//VBConvertStringFingerprint (uAlgorithm, fingerprintBytes);
    	VBConvertStringFingerprint (u, fingerprintBytes);
    	//END RSAv4 SUPPORT MOD
		//LoadString(hInst, IDS_SIGNING_KEY_FP, tempString, sizeof(tempString));
		strcpy(tempString, "Signer Key Fingerprint:");

		//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
		//if (bAddVBlockStr) strcat(*blockBegin, szVBlockStr);
		strcat(*blockBegin, szVBlockStr);
		//END VERIFICATION BLOCK STRING

		strcat(*blockBegin, tempString);
		strcat(*blockBegin, " ");
		strcat(*blockBegin, fingerprintBytes);
		//strcat(*blockBegin,"\r\n");
		//strcat(*blockBegin, " ");
		bAppendSigKeyStatus = TRUE;
		//END SIGNER KEY INFO IN VERIFICATION BLOCK

		PGPGetKeyNumber(sigData->signingKey, kPGPKeyPropValidity,
			&validity);

	    PGPGetKeyBoolean(sigData->signingKey, kPGPKeyPropIsAxiomatic, 
			&isAxiomatic);

		if (sigData->keyRevoked)
			//LoadString(hInst, IDS_REVOKEDKEY, tempString, sizeof(tempString));
			strcpy(tempString, "Revoked\r\n");
		else if (sigData->keyExpired)
			//LoadString(hInst, IDS_EXPIREDKEY, tempString, sizeof(tempString));
			strcpy(tempString, "Expired\r\n");
		else if (sigData->keyDisabled)
			//LoadString(hInst, IDS_DISABLEDKEY, tempString, sizeof(tempString));
			strcpy(tempString, "Disabled\r\n");
		else if (!isAxiomatic)
		{
			if ((validity == kPGPValidity_Invalid) ||
				(validity == kPGPValidity_Unknown) ||
					((validity == kPGPValidity_Marginal) && 
					MarginalIsInvalid(memoryMgr)))
			{
				//LoadString(hInst, IDS_INVALIDKEY, tempString, sizeof(tempString));
				strcpy(tempString, "Invalid\r\n");
			}
			else {
				strcpy(tempString, "\r\n");
				//BEGIN SIGNER KEY INFO IN VERIFICATION BLOCK - Imad R. Faiad
				bAppendSigKeyStatus = FALSE;
				//END SIGNER KEY INFO IN VERIFICATION BLOCK
			}
		}
		else {
			strcpy(tempString, "\r\n");			
			//BEGIN SIGNER KEY INFO IN VERIFICATION BLOCK - Imad R. Faiad
			bAppendSigKeyStatus = FALSE;			
			//END SIGNER KEY INFO IN VERIFICATION BLOCK
		}
		//BEGIN SIGNER KEY INFO IN VERIFICATION BLOCK - Imad R. Faiad
		if (bAppendSigKeyStatus) {
			//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
			strcat(*blockBegin, "\r\n");
			//if (bAddVBlockStr) strcat(*blockBegin, szVBlockStr);
			strcat(*blockBegin, szVBlockStr);
			//END VERIFICATION BLOCK STRING
			strcat(*blockBegin,"Signer Key Status: ");
		}
		//END SIGNER KEY INFO IN VERIFICATION BLOCK

		strcat(*blockBegin, tempString);
	}

	//LoadString(hInst, IDS_SIGDATE, tempString, sizeof(tempString));
	strcpy(tempString, "Signed: ");
	//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
	//if (bAddVBlockStr) strcat(*blockBegin, szVBlockStr);
	strcat(*blockBegin, szVBlockStr);
	//END VERIFICATION BLOCK STRING
	strcat(*blockBegin, tempString);

	ConvertPGPTimeToString(sigData->creationTime, dateString, 
		sizeof(dateString), timeString, sizeof(timeString));

	strcat(*blockBegin, dateString);
	strcat(*blockBegin, " ");
	strcat(*blockBegin, timeString);
	strcat(*blockBegin, "\r\n");

	//LoadString(hInst, IDS_VERIFIED, tempString, sizeof(tempString));
	strcpy(tempString, "Verified: "); 
	//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
	//if (bAddVBlockStr) strcat(*blockBegin, szVBlockStr);
	strcat(*blockBegin, szVBlockStr);
	//END VERIFICATION BLOCK STRING
	strcat(*blockBegin, tempString);

	//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad

	//ConvertPGPTimeToString(PGPGetTime(), dateString, sizeof(dateString),
		//timeString, sizeof(timeString));

	//strcat(*blockBegin, dateString);
	//strcat(*blockBegin, " ");
	//strcat(*blockBegin, timeString);
	strcat(*blockBegin, datetimeString);
	//END VERIFICATION BLOCK STRING
	strcat(*blockBegin, "\r\n");
//BEGIN - VERIFICATION BLOCK STRING for encrypted msgs - Disastry
}
//END

	if (wasEncrypted)
	{
		//BEGIN CIPHER ALGORITHM IN VERIFICATION BLOCK - Imad R. Faiad
		PGPBoolean	bWasSigned=**blockBegin;
		if (!bWasSigned) strcat(*blockBegin,"\r\n");
		switch(wasEncrypted) {
		case kPGPCipherAlgorithm_IDEA:
			strcpy( tempString, "Cipher: IDEA\r\n" );
			break;
		case kPGPCipherAlgorithm_3DES:
			strcpy( tempString, "Cipher: 3DES\r\n" );
			break;
		case kPGPCipherAlgorithm_CAST5:
			strcpy( tempString, "Cipher: CAST5\r\n" );
			break;
		case kPGPCipherAlgorithm_BLOWFISH:
			strcpy( tempString, "Cipher: BLOWFISH\r\n" );
			break;
		case kPGPCipherAlgorithm_AES128:
			strcpy( tempString, "Cipher: AES128\r\n" );
			break;
		case kPGPCipherAlgorithm_AES192:
			strcpy( tempString, "Cipher: AES192\r\n" );
			break;
		case kPGPCipherAlgorithm_AES256:
			strcpy( tempString, "Cipher: AES256\r\n" );
			break;
		case kPGPCipherAlgorithm_Twofish256:
			strcpy( tempString, "Cipher: Twofish256\r\n" );
			break;
		case 5:
			strcpy(tempString, "Cipher: SAFER-SK128(Not Implemented)\r\n");
			break;
		case 6:
			strcpy(tempString, "Cipher: DES/SK(Not Implemented)\r\n");
			break;
		default:
			if ((wasEncrypted <100) || (wasEncrypted > 110))
				sprintf( tempString,
				"Cipher: Unknown (Algorithm ID: %i\r\n)", wasEncrypted );
			else
				sprintf( tempString,
				"Cipher: Private/Experimental (Algorithm ID: %i\r\n)", wasEncrypted );
			break;
		}
		
		strcat(*blockBegin, szVBlockStr);
		strcat(*blockBegin, tempString);
		//strcat(*blockBegin, "\r\n");
		//END CIPHER ALGORITHM IN VERIFICATION BLOCK

		//LoadString(hInst, IDS_BEGINDECRYPTED, tempString, sizeof(tempString));
		if (bWasSigned)
			strcpy(tempString, "BEGIN PGP DECRYPTED/VERIFIED MESSAGE ***\r\n\r\n");
		else
			strcpy(tempString, "BEGIN PGP DECRYPTED MESSAGE ***\r\n\r\n");
		//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
		//if (bAddVBlockStr) strcat(*blockBegin, szVBlockStr);
		strcat(*blockBegin, szVBlockStr);
		//END VERIFICATION BLOCK STRING
		strcat(*blockBegin, tempString);
		//LoadString(hInst, IDS_ENDDECRYPTED, tempString, sizeof(tempString));
		if (bWasSigned)
			strcpy(tempString, "END PGP DECRYPTED/VERIFIED MESSAGE ***\r\n\r\n");
		else
			strcpy(tempString, "END PGP DECRYPTED MESSAGE ***\r\n\r\n");
		//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
		strcpy(*blockEnd, "\r\n");
		//if (bAddVBlockStr) strcat(*blockEnd, szVBlockStr);
		strcat(*blockEnd, szVBlockStr);
		strcat(*blockEnd, tempString);
		//strcpy(*blockEnd, tempString);
		//END VERIFICATION BLOCK STRING
	}
	else
	{
		//LoadString(hInst, IDS_BEGINVERIFIED, tempString, sizeof(tempString));
		strcpy(tempString, "BEGIN PGP VERIFIED MESSAGE ***\r\n\r\n");
		//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
		//if (bAddVBlockStr) strcat(*blockBegin, szVBlockStr);
		strcat(*blockBegin, szVBlockStr);
		//END VERIFICATION BLOCK STRING
		strcat(*blockBegin, tempString);
		//LoadString(hInst, IDS_ENDVERIFIED, tempString, sizeof(tempString));
		strcpy(tempString, "END PGP VERIFIED MESSAGE ***\r\n");
		//BEGIN VERIFICATION BLOCK STRING - Imad R. Faiad
		strcpy(*blockEnd, "\r\n\r\n");
		//if (bAddVBlockStr) strcat(*blockEnd, szVBlockStr);
		strcat(*blockEnd, szVBlockStr);
		strcat(*blockEnd, tempString);
		//strcpy(*blockEnd, tempString);
		//END VERIFICATION BLOCK STRING
	}

	return err;
}*/

/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
