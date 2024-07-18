/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: EncryptSign.c,v 1.13 1999/04/13 17:29:55 wjb Exp $
____________________________________________________________________________*/
// System Headers
#include <windows.h> 
#include <windowsx.h>
#include <assert.h>

// PGPsdk Headers
#include "pgpConfig.h"
#include "pgpKeys.h"
#include "pgpErrors.h"
#include "pgpWerr.h"
#include "pgpUtilities.h"
#include "pgpMem.h"
#include "pgpSDKPrefs.h"

// Shared Headers
#include "pgpVersionHeader.h"
#include "PGPcl.h"
#include "BlockUtils.h"
#include "Working.h"
#include "Prefs.h"
#include "EncryptSign.h"
#include "WorkingResource.h"
#include "SharedStrings.h"


//BEGIN KEY INFO IN COMMENT BLOCK - Imad R. Faiad
#include "pgpClientPrefs.h"
//END KEY INFO IN COMMENT BLOCK

static int nProgressCount = 0;

static PGPError EncryptSign(HINSTANCE hInst, HWND hwnd, PGPContextRef context, 
							PGPtlsContextRef tlsContext, 
							char *szName, char *szModule,
							RECIPIENTDIALOGSTRUCT *prds,
							PGPOptionListRef ioOptions,
							PGPOptionListRef mimeOptions,
							PGPOptionListRef *pSignOptions,
							BOOL bEncrypt, BOOL bSign, BOOL bBinary);

PGPError EncodeEventHandler(PGPContextRef context, 
							PGPEvent *event, 
							PGPUserValue userValue);

static void DisplayErrorCode(char *szFile, 
							 int nLine, 
							 char *szModule, 
							 int nCode);

BOOL WrapBuffer(char **pszOutText,
				char *szInText,
				PGPUInt16 wrapLength)
{
	BOOL RetVal = FALSE;
	PGPError err;
	char *cmdlgBuffer;

	err=PGPclWrapBuffer(
					szInText,
					wrapLength,
					&cmdlgBuffer);

	if(IsntPGPError (err))
	{
		int memamt,length;

		length=strlen(cmdlgBuffer);
		memamt=length+1;

		*pszOutText=(char *)malloc(memamt);
		memcpy(*pszOutText,cmdlgBuffer,length);
		(*pszOutText)[length]=0;
		PGPclFreeWrapBuffer(cmdlgBuffer);
		RetVal = TRUE;
	}

	return RetVal;
}


PGPError EncryptSignBuffer(HINSTANCE hInst, HWND hwnd, PGPContextRef context, 
						   PGPtlsContextRef tlsContext, 
						   char *szName, char *szModule,
						   void *pInput, DWORD dwInSize, 
						   RECIPIENTDIALOGSTRUCT *prds,
						   PGPOptionListRef mimeOptions,
						   PGPOptionListRef *pSignOptions,
						   void **ppOutput, PGPSize *pOutSize, BOOL bEncrypt, 
						   BOOL bSign, BOOL bBinary)
{
	PGPError			err				= kPGPError_NoErr;
	PGPMemoryMgrRef		memoryMgr		= NULL;
	PGPOptionListRef	options			= NULL;
	void *				pFinalInput		= NULL;
	long				lWrapWidth		= 0;
	BOOL				bInputWrapped	= FALSE;

	pgpAssert(pInput != NULL);
	pgpAssert(prds != NULL);
	pgpAssert(prds->OriginalKeySetRef != NULL);
	pgpAssert(pSignOptions != NULL);
	pgpAssert(ppOutput != NULL);
	pgpAssert(pOutSize != NULL);
	pgpAssert(PGPRefIsValid(context));

	memoryMgr = PGPGetContextMemoryMgr(context);
	pFinalInput = pInput;

	if (!bBinary)
	{
		if (ByDefaultWordWrap(memoryMgr, &lWrapWidth))
		{
			pFinalInput = NULL;
			bInputWrapped = WrapBuffer((char **) &pFinalInput, 
								(char *) pInput, (short) lWrapWidth);
			dwInSize = strlen((char *) pFinalInput);
		}
	}

	err = PGPBuildOptionList(context, &options, 
			PGPOInputBuffer(context, pFinalInput, dwInSize),
			PGPOAllocatedOutputBuffer(context, 
				ppOutput, 
				INT_MAX, 
				pOutSize),
			PGPOLastOption(context));

	if (IsPGPError(err))
	{
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto EncryptSignBufferError;
	}

	err = EncryptSign(hInst, hwnd, context, tlsContext, szName, szModule, 
			prds, options, mimeOptions, pSignOptions, bEncrypt, bSign, 
			bBinary);

EncryptSignBufferError:

	if (bInputWrapped)
		free(pFinalInput);

	if (options != NULL)
		PGPFreeOptionList(options);

	return err;
}


PGPError EncryptSignFile(HINSTANCE hInst, HWND hwnd, PGPContextRef context, 
						 PGPtlsContextRef tlsContext, 
						 char *szName, char *szModule, char *szInFile, 
						 RECIPIENTDIALOGSTRUCT *prds, 
						 PGPOptionListRef mimeOptions,
						 PGPOptionListRef *pSignOptions, char *szOutFile, 
						 BOOL bEncrypt, BOOL bSign, BOOL bBinary)
{
	PGPError			err				= kPGPError_NoErr;
	PGPOptionListRef	options			= NULL;
	PGPFileSpecRef		inputFile		= NULL;
	PGPFileSpecRef		outputFile		= NULL;

	pgpAssert(szInFile != NULL);
	pgpAssert(prds != NULL);
	pgpAssert(prds->OriginalKeySetRef != NULL);
	pgpAssert(pSignOptions != NULL);
	pgpAssert(szOutFile != NULL);
	pgpAssert(PGPRefIsValid(context));

	err = PGPNewFileSpecFromFullPath(context, szInFile, &inputFile);
	if (IsPGPError(err))
	{
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto EncryptSignFileError;
	}

	err = PGPNewFileSpecFromFullPath(context, szOutFile, &outputFile);
	if (IsPGPError(err))
	{
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto EncryptSignFileError;
	}

	err = PGPBuildOptionList(context, &options, 
			PGPOInputFile(context, inputFile),
			PGPOOutputFile(context, outputFile),
			PGPOLastOption(context));

	if (IsPGPError(err))
	{
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto EncryptSignFileError;
	}

	err = EncryptSign(hInst, hwnd, context, tlsContext, szName, szModule, 
			prds, options, mimeOptions, pSignOptions, bEncrypt, bSign, 
			bBinary);

EncryptSignFileError:

	if (options != NULL)
		PGPFreeOptionList(options);

	if (inputFile != NULL)
		PGPFreeFileSpec(inputFile);

	if (outputFile != NULL)
		PGPFreeFileSpec(outputFile);

	return err;
}
//BEGIN VERSION STRING MOD - Imad R. Faiad
//	_______________________________________________
//
//  Get appropriate Version string

void
SHRememberVersionHeaderString ( PGPContextRef context)
{
	PGPPrefRef	PrefRefClient=NULL;
	PGPError	err;
	PGPMemoryMgrRef memMgr;
	char sz[72]="";

	memMgr=PGPGetContextMemoryMgr(context);


	err=PGPclOpenClientPrefs (memMgr,&PrefRefClient);

	if(IsntPGPError(err))
	{

		err=PGPGetPrefStringBuffer (PrefRefClient,
			kPGPPrefVersionStringHeader, sizeof(sz),sz);
		PGPclCloseClientPrefs (PrefRefClient, FALSE);
	}

	if (sz[0])
		lstrcpy (pgpVersionHeaderString, sz);
	else
		lstrcpy (pgpVersionHeaderString, "");
}
//END VERSION STRING MOD
//BEGIN 64 BITS KEY ID DISPLAY MOD - Imad R. Faiad
void
GetPref64BitsKeyIDDisplay ( PGPUInt32 *H64BitsKeyIDDisplay )
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
//BEGIN KEY INFO IN COMMENT BLOCK - Imad R. Faiad
VOID 
ConvertStringFingerprint (
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

BOOL AppendKeyIDToComment(PGPContextRef context)
{
	PGPPrefRef	PrefRefClient=NULL;
	PGPBoolean	bAppendKeyIDReturn;
	PGPError	err;
	PGPMemoryMgrRef memMgr;

	memMgr=PGPGetContextMemoryMgr(context);

	bAppendKeyIDReturn=TRUE;

	err=PGPclOpenClientPrefs (memMgr,&PrefRefClient);

	if(IsntPGPError(err))
	{

		err=PGPGetPrefBoolean (PrefRefClient,
			kPGPPrefAppendKeyIDToComment, &bAppendKeyIDReturn);
		PGPclCloseClientPrefs (PrefRefClient, FALSE);
	}

	return bAppendKeyIDReturn;
}

BOOL AppendKeyFPToComment(PGPContextRef context)
{
	PGPPrefRef	PrefRefClient=NULL;
	PGPBoolean	bAppendKeyFPReturn;
	PGPError	err;
	PGPMemoryMgrRef memMgr;

	memMgr=PGPGetContextMemoryMgr(context);

	bAppendKeyFPReturn=TRUE;

	err=PGPclOpenClientPrefs (memMgr,&PrefRefClient);

	if(IsntPGPError(err))
	{

		err=PGPGetPrefBoolean (PrefRefClient,
			kPGPPrefAppendKeyFPToComment, &bAppendKeyFPReturn);
		PGPclCloseClientPrefs (PrefRefClient, FALSE);
	}

	return bAppendKeyFPReturn;
}
//END KEY INFO IN COMMENT BLOCK
PGPError EncryptSign(HINSTANCE hInst, HWND hwnd, PGPContextRef context, 
					 PGPtlsContextRef tlsContext, 
					 char *szName, char *szModule,
					 RECIPIENTDIALOGSTRUCT *prds,
					 PGPOptionListRef ioOptions,
					 PGPOptionListRef mimeOptions,
					 PGPOptionListRef *pSignOptions,
					 BOOL bEncrypt, BOOL bSign, 
					 BOOL bBinary)
{
	PGPError			err				= kPGPError_NoErr;
	PGPMemoryMgrRef		memoryMgr		= NULL;
	PGPKeyRef			signKey			= NULL;
	PGPKeySetRef		pubKeySet		= NULL;
	PGPKeySetRef		addedKeys		= NULL;
	PGPKeySetRef		recipKeySet		= NULL;
	PGPOptionListRef	options			= NULL;
	PGPOptionListRef	encryptOptions	= NULL;
	PGPOptionListRef	tempOptions		= NULL;
	PGPCipherAlgorithm  prefAlg			= kPGPCipherAlgorithm_CAST5;

	//BEGIN MORE CIPHERS SUPPORT - Disastry
	//PGPCipherAlgorithm	allowedAlgs[3];
	PGPCipherAlgorithm	allowedAlgs[8];
	//END MORE CIPHERS SUPPORT

	char *				szPassphrase	= NULL;
	char *				szConvPass		= NULL;
	PGPByte *			pPasskey		= NULL;
	PGPUInt32			nPasskeyLength	= 0;
	int					nPassphraseLen	= 0;
	int					nConvPassLen	= 0;
	int					nNumAlgs		= 0;
	BOOL				bGotPassphrase	= FALSE;
	BOOL				bGotConvPass	= FALSE;
	HWND				hwndWorking		= NULL;
	char 				szComment[256];
	char 				szWorkingTitle[256];

	//BEGIN KEY INFO IN COMMENT BLOCK - Imad R. Faiad
	BOOL				bHaveComment;
	//END KEY INFO IN COMMENT BLOCK

	UpdateWindow(hwnd);
	memoryMgr = PGPGetContextMemoryMgr(context);

	// Check for demo expiration

	if (PGPclEvalExpired(hwnd, PGPCL_ENCRYPTSIGNEXPIRED) != kPGPError_NoErr)
		return kPGPError_UserAbort;

	pubKeySet = prds->OriginalKeySetRef;
	
	err = PGPGetDefaultPrivateKey(pubKeySet, &signKey);
	if (IsPGPError(err))
	{
		PGPKeyListRef	pubKeyList = NULL;
		PGPKeyIterRef	pubKeyIter = NULL;
		
		PGPOrderKeySet(pubKeySet, kPGPTrustOrdering, &pubKeyList);
		PGPNewKeyIter(pubKeyList, &pubKeyIter);
		PGPKeyIterNext(pubKeyIter, &signKey);
		PGPFreeKeyIter(pubKeyIter);
		PGPFreeKeyList(pubKeyList);

		err = kPGPError_NoErr;
	}

	err = kPGPError_BadPassphrase;
	while (err == kPGPError_BadPassphrase)
	{
		if (IsntNull(szPassphrase))
		{
			PGPclFreeCachedPhrase(szPassphrase);
			szPassphrase = NULL;
		}

		if (IsntNull(szConvPass))
		{
			PGPclFreePhrase(szConvPass);
			szConvPass = NULL;
		}

		if (IsNull(mimeOptions))
			err = PGPBuildOptionList(context, &options, 
					PGPOLastOption(context));
		else
			err = PGPBuildOptionList(context, &options, 
					mimeOptions,
					PGPOLastOption(context));

		if (IsPGPError(err))
		{
			DisplayErrorCode(__FILE__, __LINE__, szModule, err);
			goto EncryptSignError;
		}

		err = PGPBuildOptionList(context, &encryptOptions,
				PGPOLastOption(context));

		if (IsPGPError(err))
		{
			DisplayErrorCode(__FILE__, __LINE__, szModule, err);
			goto EncryptSignError;
		}

		//BEGIN KEY INFO IN COMMENT BLOCK - Imad R. Faiad
		/*if (GetCommentString(memoryMgr, szComment, 254))
		{
			err = PGPBuildOptionList(context, &tempOptions,
					options,
					PGPOCommentString(context, szComment),
					PGPOLastOption(context));
			
			if (IsPGPError(err))
			{
				DisplayErrorCode(__FILE__, __LINE__, szModule, err);
				goto EncryptSignError;
			}

			PGPFreeOptionList(options);
			options = tempOptions;
		}*/
		//END KEY INFO IN COMMENT BLOCK

		if (bEncrypt)
		{
			if (*pSignOptions == NULL)
			{
				if (prds->dwOptions & PGPCL_ASCIIARMOR)
				{
					err = PGPBuildOptionList(context, &tempOptions,
							encryptOptions,
							PGPOArmorOutput(context, TRUE),
							PGPOLastOption(context));
					
					if (IsPGPError(err))
					{
						DisplayErrorCode(__FILE__, __LINE__, szModule, 
							err);
						goto EncryptSignError;
					}
	
					PGPFreeOptionList(encryptOptions);
					encryptOptions = tempOptions;
				}
				
				if (prds->dwOptions & PGPCL_PASSONLY)
				{
					if (!bGotConvPass)
					{
						char szPrompt[256];
						
						LoadString(hInst, IDS_CONVPASSPHRASE, szPrompt, 
							sizeof(szPrompt));
						
						err = PGPclGetPhrase(context, pubKeySet, hwnd, 
								szPrompt, &szConvPass, NULL, NULL, 0, NULL, 
								NULL, PGPCL_ENCRYPTION, NULL, NULL, 1, 0, 
								NULL, NULL,NULL);
						
						// wjb changed to 1 for min passphrase length
						if (err == kPGPError_UserAbort)
							goto EncryptSignError;
						
						nConvPassLen = strlen(szConvPass);
						bGotConvPass = TRUE;
					}
					
					GetPreferredAlgorithm(memoryMgr, &prefAlg);
					
					err = PGPBuildOptionList(context, &tempOptions,
							encryptOptions,
							PGPOConventionalEncrypt(context,
								PGPOPassphraseBuffer(context,
									szConvPass, 
									nConvPassLen),
								PGPOLastOption(context)),
							PGPOCipherAlgorithm(context, prefAlg),
							PGPOLastOption(context));
					
					if (IsPGPError(err))
					{
						DisplayErrorCode(__FILE__, __LINE__, szModule, 
							err);
						goto EncryptSignError;
					}
				}
				else
				{
					GetAllowedAlgorithms(memoryMgr, allowedAlgs, &nNumAlgs);
					recipKeySet = prds->SelectedKeySetRef;
					
					err = PGPBuildOptionList(context, &tempOptions,
							encryptOptions,
							PGPOPreferredAlgorithms(context,
								allowedAlgs, nNumAlgs ),
							PGPOEncryptToKeySet(context, recipKeySet),
							PGPOFailBelowValidity(context, 
								kPGPValidity_Unknown),
							PGPOWarnBelowValidity(context, 
								kPGPValidity_Unknown),
							PGPOLastOption(context));
					
					if (IsPGPError(err))
					{
						DisplayErrorCode(__FILE__, __LINE__, szModule, 
							err);
						goto EncryptSignError;
					}
				}
				
				PGPFreeOptionList(encryptOptions);
				encryptOptions = tempOptions;
			}
		}
		
		if (bSign)
		{
			if (*pSignOptions == NULL)
			{
				char szPrompt[256];

				if (bGotPassphrase)
					LoadString(hInst, IDS_PASSPHRASEREENTER, szPrompt, 
						sizeof(szPrompt));
				else
					LoadString(hInst, IDS_PASSPHRASEPROMPT, szPrompt, 
						sizeof(szPrompt));
				
				err = PGPclGetCachedSigningPhrase(context, tlsContext, hwnd, 
						szPrompt, bGotPassphrase, &szPassphrase, 
						pubKeySet, &signKey, NULL, NULL, prds->dwFlags,
						&pPasskey, &nPasskeyLength, &addedKeys,NULL);
				
				if (addedKeys != NULL)
				{
					PGPUInt32 numKeys;

					PGPCountKeys(addedKeys, &numKeys);
					if (numKeys > 0)
						PGPclQueryAddKeys(context, tlsContext, hwnd, 
							addedKeys, NULL);

					PGPFreeKeySet(addedKeys);
					addedKeys = NULL;
				}

				if (IsPGPError(err))
				{
					if (err != kPGPError_UserAbort)
						DisplayErrorCode(__FILE__, __LINE__, szModule, 
							err);
					goto EncryptSignError;
				}
				
				bGotPassphrase = TRUE;
				if (IsntNull(szPassphrase))
				{
					nPassphraseLen = strlen(szPassphrase);
				
					err = PGPBuildOptionList(context, pSignOptions,
							PGPOSignWithKey(context, 
								signKey, 
								PGPOPassphraseBuffer(context,
									szPassphrase, 
									nPassphraseLen),
								PGPOLastOption(context)),
							PGPOLastOption(context));
				}
				else if (IsntNull(pPasskey))
				{
					err = PGPBuildOptionList(context, pSignOptions,
							PGPOSignWithKey(context, 
								signKey, 
								PGPOPasskeyBuffer(context,
									pPasskey, 
									nPasskeyLength),
								PGPOLastOption(context)),
							PGPOLastOption(context));
				}
				
				if (IsPGPError(err))
				{
					if (err != kPGPError_UserAbort)
						DisplayErrorCode(__FILE__, __LINE__, szModule, 
							err);
					goto EncryptSignError;
				}
			}

			err = PGPBuildOptionList(context, &tempOptions,
					options,
					PGPOClearSign(context, 
						(PGPBoolean) (!bEncrypt && !bBinary)),
					PGPOLastOption(context));
			
			if (IsPGPError(err))
			{
				if (err != kPGPError_UserAbort)
					DisplayErrorCode(__FILE__, __LINE__, szModule, 
						err);
				goto EncryptSignError;
			}

			PGPFreeOptionList(options);
			options = tempOptions;
		}
		
		if (bEncrypt && !bSign)
			LoadString(hInst, IDS_WORKINGENCRYPT, szWorkingTitle, 
				sizeof(szWorkingTitle));
		else if (!bEncrypt && bSign)
			LoadString(hInst, IDS_WORKINGSIGN, szWorkingTitle, 
				sizeof(szWorkingTitle));
		else
			LoadString(hInst, IDS_WORKINGENCRYPTSIGN, szWorkingTitle, 
				sizeof(szWorkingTitle));

		hwndWorking = WorkingDlgProcThread(GetModuleHandle(szModule), 
						hInst, NULL, szWorkingTitle, "");

		if (*pSignOptions == NULL)
			PGPBuildOptionList(context, pSignOptions, 
				PGPOLastOption(context));

		//BEGIN VERSION STRING MOD - Imad R. Faiad
		SHRememberVersionHeaderString (context);
		//END VERSION STRING MOD

		//BEGIN KEY INFO IN COMMENT BLOCK - Imad R. Faiad
		bHaveComment = GetCommentString(memoryMgr, szComment, 254);

		if(bSign) {
			PGPKeyID	KeyID;
			CHAR		szID[kPGPMaxKeyIDStringSize];
			PGPByte		fingerprintBytes[256];
			UINT		u, uAlgorithm;
			BOOL		bDoKeyID, bDoFingerprint;
			PGPBoolean	abbrev;

			bDoKeyID = AppendKeyIDToComment(context);
			bDoFingerprint = AppendKeyFPToComment(context);

			GetPref64BitsKeyIDDisplay(&u);

			if (u == 1)
				abbrev = kPGPKeyIDString_Full;
			else
				abbrev = kPGPKeyIDString_Abbreviated;

			if ( (bDoKeyID) & (bDoFingerprint) ) {
				if (bHaveComment) {
					lstrcat (szComment, "\nComment: KeyID: 0x");
				}
				else {
					bHaveComment = TRUE;
					lstrcpy (szComment, "KeyID: 0x");
				}
				PGPGetKeyIDFromKey (signKey, &KeyID);
				PGPGetKeyIDString (&KeyID, abbrev, szID);
				lstrcat (szComment, &szID[2]);
				lstrcat (szComment, "\nComment: Fingerprint: ");
				PGPGetKeyPropertyBuffer(signKey, kPGPKeyPropFingerprint,
					sizeof( fingerprintBytes ), fingerprintBytes, &u);
				PGPGetKeyNumber (signKey, kPGPKeyPropAlgID, &uAlgorithm);
    	        //BEGIN RSAv4 SUPPORT MOD - Disastry
    		    //ConvertStringFingerprint (uAlgorithm, fingerprintBytes);
    		    ConvertStringFingerprint (u, fingerprintBytes);
    	        //END RSAv4 SUPPORT MOD
				lstrcat (szComment, fingerprintBytes);
			}/* if ( (bDoKeyID) & (bDoFingerprint) ) */
			else if (bDoKeyID) {
					if (bHaveComment) {
						lstrcat (szComment, "\nComment: KeyID: 0x");
					}
					else {
						bHaveComment = TRUE;
						lstrcpy (szComment, "KeyID: 0x");
					}
					PGPGetKeyIDFromKey (signKey, &KeyID);
					PGPGetKeyIDString (&KeyID, abbrev, szID);
					lstrcat (szComment, &szID[2]);
			}/* else if (DoKeyID) */
			else if (bDoFingerprint) {
					if (bHaveComment) {
					lstrcat (szComment, "\nComment: Fingerprint: ");
				}
				else {
					bHaveComment = TRUE;
					lstrcpy (szComment, "Fingerprint: ");
				}
				PGPGetKeyPropertyBuffer(signKey, kPGPKeyPropFingerprint,
					sizeof( fingerprintBytes ), fingerprintBytes, &u);
				PGPGetKeyNumber (signKey, kPGPKeyPropAlgID, &uAlgorithm);
    	        //BEGIN RSAv4 SUPPORT MOD - Disastry
    		    //ConvertStringFingerprint (uAlgorithm, fingerprintBytes);
    		    ConvertStringFingerprint (u, fingerprintBytes);
    	        //END RSAv4 SUPPORT MOD
				lstrcat (szComment, fingerprintBytes);

			}/* else if (DoFingerprint) */
		} /* if(bSign) */

		if (bHaveComment){
			err = PGPBuildOptionList(context, &tempOptions,
					options,
					PGPOCommentString(context, szComment),
					PGPOLastOption(context));
			
			if (IsPGPError(err))
			{
				DisplayErrorCode(__FILE__, __LINE__, szModule, err);
				goto EncryptSignError;
			}

			PGPFreeOptionList(options);
			options = tempOptions;
		}
		//END KEY INFO IN COMMENT BLOCK

		err = PGPEncode(context,
				ioOptions,
				PGPOEventHandler(context, EncodeEventHandler, hwndWorking),
				options,
				encryptOptions,
				*pSignOptions,
				PGPOSendNullEvents(context, 100),
				PGPODataIsASCII(context, (PGPBoolean) !bBinary),
				PGPOVersionString(context, pgpVersionHeaderString),
				PGPOAskUserForEntropy(context, TRUE),
				PGPOForYourEyesOnly(context,
					(PGPBoolean)((prds->dwOptions & PGPCL_FYEO)==PGPCL_FYEO)),
				PGPOLastOption(context));

		DestroyWindow(hwndWorking);

		if (options != NULL)
		{
			PGPFreeOptionList(options);
			options = NULL;
		}

		if (err == kPGPError_BadPassphrase)
		{
			if (encryptOptions != NULL)
			{
				PGPFreeOptionList(encryptOptions);
				encryptOptions = NULL;
			}

			PGPFreeOptionList(*pSignOptions);
			*pSignOptions = NULL;
		}
	}

	if (IsPGPError(err) && (err != kPGPError_UserAbort))
	{
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto EncryptSignError;
	}

	if (IsntPGPError(err))
	{
		if (*pSignOptions == NULL)
			PGPBuildOptionList(context, pSignOptions, 
				PGPOLastOption(context));

		PGPBuildOptionList(context, &tempOptions, 
			*pSignOptions,
			encryptOptions,
			PGPOLastOption(context));

		PGPFreeOptionList(*pSignOptions);
		PGPFreeOptionList(encryptOptions);
		*pSignOptions = tempOptions;
		encryptOptions = NULL;
	}

EncryptSignError:

	if (szPassphrase != NULL)
	{
		PGPclFreeCachedPhrase(szPassphrase);
		szPassphrase = NULL;
	}

	if (pPasskey != NULL)
	{
		PGPFreeData(pPasskey);
		pPasskey = NULL;
	}

	if (szConvPass != NULL)
	{
		PGPclFreePhrase(szConvPass);
		szConvPass = NULL;
	}

	if (encryptOptions != NULL)
		PGPFreeOptionList(encryptOptions);

	if (options != NULL)
		PGPFreeOptionList(options);

	return err;
}


PGPError EncodeEventHandler(PGPContextRef context, 
							PGPEvent *event, 
							PGPUserValue userValue)
{
	HWND			hwnd			= NULL;
	PGPError		err				= kPGPError_NoErr;

	pgpAssert(PGPRefIsValid(context));
	pgpAssert(event != NULL);

	hwnd = (HWND) userValue;

	switch (event->type)
	{
	case kPGPEvent_EntropyEvent:
		err = PGPclRandom(context, hwnd, 
				event->data.entropyData.entropyBitsNeeded);
		break;

	case kPGPEvent_NullEvent:
		{	
			PGPEventNullData *d = &event->data.nullData;
			BOOL bCancel;

			bCancel = WorkingCallback (	(HWND)userValue, 
										(unsigned long)d->bytesWritten, 
										(unsigned long)d->bytesTotal) ;

			if(bCancel)
			{
				return kPGPError_UserAbort;
			}
		}
		break;
	}

	return err;
}


void DisplayErrorCode(char *szFile, int nLine, char *szModule, int nCode)
{
	char szErrorMsg[255];

	PGPclEncDecErrorToString(nCode, szErrorMsg, 254);

#ifdef _DEBUG
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_WNDW);
	_CrtDbgReport(_CRT_ERROR, szFile, nLine, szModule, szErrorMsg);
#endif

	MessageBox(NULL, szErrorMsg, szModule, MB_ICONEXCLAMATION);
	return;
}


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
