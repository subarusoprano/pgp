/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: DecryptVerify.c,v 1.20.4.3.6.1 1999/08/06 17:55:01 dgal Exp $
____________________________________________________________________________*/

// System Headers
#include <windows.h>
#include <windowsx.h>
#include <stdio.h>
//BEGIN VERIFICATION BLOCKS IN CLIPBOARD - Imad R. Faiad
#include <malloc.h>
//END VERIFICATION BLOCKS IN CLIPBOARD
#include <assert.h>

// PGPsdk Headers
#include "pgpConfig.h"
#include "pgpKeys.h"
#include "pgpErrors.h"
#include "pgpWerr.h"
#include "pgpUtilities.h"
#include "pgpMem.h"
#include "pgpSDKPrefs.h"
#include "pgpSC.h"

// Shared Headers 
#include "PGPcl.h"
#include "SigEvent.h"
#include "Working.h"
#include "Prefs.h"
#include "DecryptVerify.h"
#include "ParseMime.h"
#include "VerificationBlock.h"
#include "WorkingResource.h"
#include "SharedStrings.h"

typedef struct _VerificationBlock VerificationBlock;

struct _VerificationBlock
{
	VerificationBlock *		next;
	VerificationBlock *		previous;
	char *					szBlockBegin;
	char *					szBlockEnd;
	void *					pOutput;
	PGPSize					outSize;
	unsigned char			bEncrypted;
	PGPBoolean				FYEO;
};

typedef struct _DecodeEventData
{
	HINSTANCE			hInst;
	HWND				hwnd;
	HWND				hwndWorking;
	PGPtlsContextRef	tlsContext;
	char *				szName;
	PGPKeySetRef		pubKeySet;
	PGPKeySetRef		recipients;
	PGPUInt32			keyCount;
	PGPKeyID			*keyIDArray;
	VerificationBlock *	pVerBlock;
//BEGIN - VERIFICATION BLOCK STRING for encrypted msgs - Disastry
	PGPBoolean			encr;
//END
} DecodeEventData;

static PGPError DecryptVerify(HINSTANCE hInst, HWND hwnd, 
							  PGPContextRef context, 
							  PGPtlsContextRef tlsContext, 
							  char *szName, char *szModule,
							  PGPOptionListRef options, BOOL bMIME,
							  VerificationBlock *pVerBlock);

PGPError DecodeEventHandler(PGPContextRef context, 
							PGPEvent *event, 
							PGPUserValue userValue);

static void DisplayErrorCode(char *szFile, 
							 int nLine, 
							 char *szModule, 
							 int nCode);
//BEGIN VERIFICATION BLOCKS IN CLIPBOARD - Imad R. Faiad
void DumpToClipboard(HWND hwnd, void* pData, DWORD dwDataSize)
{
	HANDLE hClipboardData = NULL;
	void* pClipboardBuffer = NULL;
	UINT ClipboardFormat = CF_TEXT;

	assert(pData);

	if(pData)
	{
		if(OpenClipboard(hwnd)) 
		{
			if(EmptyClipboard())
			{
				if(ClipboardFormat == CF_TEXT)
				{
					hClipboardData = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, 
						dwDataSize + 1);
				}

				if(hClipboardData)
				{
					pClipboardBuffer = 	GlobalLock(hClipboardData);

					if(pClipboardBuffer)
					{
						memcpy(pClipboardBuffer, pData, dwDataSize);
						if(ClipboardFormat == CF_TEXT)
						{
							*((char *) pClipboardBuffer + dwDataSize) = '\0';
						}
						GlobalUnlock(hClipboardData);

						SetClipboardData(ClipboardFormat, hClipboardData);
					}
				}
			}
			// Close the clipboard when we are done with it.
			CloseClipboard();
		}
	}
}
//END VERIFICATION BLOCKS IN CLIPBOARD

PGPError DecryptVerifyBuffer(HINSTANCE hInst, HWND hwnd, 
							 PGPContextRef context, 
							 PGPtlsContextRef tlsContext, 
							 char *szName, char *szModule,
							 void *pInput, DWORD dwInSize, 
							 BOOL bMIME, void **ppOutput, PGPSize *pOutSize,
							 BOOL *FYEO)
{
	PGPError			err			= kPGPError_NoErr;
	PGPOptionListRef	options		= NULL;
	VerificationBlock *	pVerBlock	= NULL;
	VerificationBlock * pTempBlock	= NULL;
	PGPMemoryMgrRef		memoryMgr	= NULL;
	VerificationBlock * pVerIndex	= NULL;
	OUTBUFFLIST	      * obl			= NULL;
	OUTBUFFLIST       * nobl		= NULL;
	BOOL				bFYEO		= FALSE;	
	//BEGIN VERIFICATION BLOCKS IN CLIPBOARD - Imad R. Faiad
	char				*vb			= NULL;
	char *ptemp;
	//END VERIFICATION BLOCKS IN CLIPBOARD

	pgpAssert(pInput != NULL);
	pgpAssert(ppOutput != NULL);
	pgpAssert(pOutSize != NULL);
	pgpAssert(szName != NULL);
	pgpAssert(szModule != NULL);
	pgpAssert(PGPRefIsValid(context));
	pgpAssert(PGPRefIsValid(tlsContext));

	memoryMgr = PGPGetContextMemoryMgr(context);

	err = PGPBuildOptionList(context, &options, 
			PGPOInputBuffer(context, pInput, dwInSize),
			PGPOLastOption(context));

	if (IsPGPError(err))
	{
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto DecryptVerifyBufferError;
	}

	pVerBlock = 
		(VerificationBlock *) PGPNewData(memoryMgr,
									sizeof(VerificationBlock),
									kPGPMemoryMgrFlags_Clear);

	pVerBlock->next = NULL;
	pVerBlock->szBlockBegin = NULL;
	pVerBlock->szBlockEnd = NULL;
	pVerBlock->pOutput = NULL;
	pVerBlock->outSize = 0;
	pVerBlock->bEncrypted = FALSE;
	pVerBlock->FYEO = FALSE;

	err = DecryptVerify(hInst, hwnd, context, tlsContext, szName, szModule, 
			options, bMIME, pVerBlock);

	*ppOutput = NULL;
	*pOutSize = 0;

	pVerIndex=pVerBlock;

	// Convert pVerBlock to OUTBUFFLIST
	//BEGIN VERIFICATION BLOCKS IN CLIPBOARD - Imad R. Faiad
	if (strcmp(szName, "The Bat!") == 0){
		vb = malloc(1);
		if (vb) vb[0]='\0';
	}
	//END VERIFICATION BLOCKS IN CLIPBOARD
	do
	{
		if (pVerIndex->szBlockBegin != NULL)
		{
			nobl=MakeOutBuffItem(&obl);
			nobl->pBuff=pVerIndex->szBlockBegin;
			nobl->dwBuffSize=strlen(pVerIndex->szBlockBegin);

			//BEGIN VERIFICATION BLOCKS IN CLIPBOARD - Imad R. Faiad
			if (vb) {
				ptemp = realloc(vb, _msize(vb) + strlen(pVerIndex->szBlockBegin));
				if (ptemp) {
					vb = ptemp;
					strcat(vb,pVerIndex->szBlockBegin);
				}
				else
					free(vb);
			}
			//END VERIFICATION BLOCKS IN CLIPBOARD
		}

		if (pVerIndex->pOutput != NULL)
		{
			nobl=MakeOutBuffItem(&obl);
			nobl->pBuff=pVerIndex->pOutput;
			nobl->dwBuffSize=strlen(pVerIndex->pOutput);
			
			if (GetSecureViewerPref((void *)context))
				nobl->FYEO = TRUE;
			else
			{
				nobl->FYEO=pVerIndex->FYEO;
				if (nobl->FYEO)
					bFYEO = TRUE;
			}

			//BEGIN VERIFICATION BLOCKS IN CLIPBOARD - Imad R. Faiad
			if (vb) {
				ptemp = realloc(vb, _msize(vb) + 6);
				if (ptemp) {
					vb = ptemp;
					strcat(vb,"<snip>");
				}
				else
					free(vb);
			}
			//END VERIFICATION BLOCKS IN CLIPBOARD
		}

		if (pVerIndex->szBlockEnd != NULL)
		{
			nobl=MakeOutBuffItem(&obl);
			nobl->pBuff=pVerIndex->szBlockEnd;
			nobl->dwBuffSize=strlen(pVerIndex->szBlockEnd);

			//BEGIN VERIFICATION BLOCKS IN CLIPBOARD - Imad R. Faiad
			if (vb) {
				ptemp = realloc(vb, _msize(vb) + strlen(pVerIndex->szBlockEnd));
				if (ptemp) {
					vb=ptemp;
					strcat(vb,pVerIndex->szBlockEnd);
				}
				else
					free(vb);
			}
			//END VERIFICATION BLOCKS IN CLIPBOARD
		}

		pTempBlock = pVerIndex;
		pVerIndex=pVerIndex->next;
		PGPFreeData(pTempBlock);
	}
	while (pVerIndex != NULL);

	// Concatinate them to ppOutput
	ConcatOutBuffList((void *)context,
		obl,
		(char **)ppOutput,
		pOutSize,
		FYEO);

	//BEGIN VERIFICATION BLOCKS IN CLIPBOARD - Imad R. Faiad
	//MessageBox(NULL,"dumping to clipboard","dumping to clipboard",MB_OK|MB_TOPMOST);
	if (vb){
		DumpToClipboard(hwnd, vb, _msize(vb));
		free(vb);
	}
	//END VERIFICATION BLOCKS IN CLIPBOARD

	/* We don't want to show the FYEO warning if the user has
	   "Always use Secure Viewer" on */

	*FYEO = bFYEO;

DecryptVerifyBufferError:

	if (options != NULL)
		PGPFreeOptionList(options);

	return err;
}


PGPError DecryptVerifyFile(HINSTANCE hInst, HWND hwnd, PGPContextRef context, 
						   PGPtlsContextRef tlsContext, 
						   char *szName, char *szModule,
						   char *szInFile, BOOL bMIME, BOOL bBinary,
						   char **pszOutFile, void **ppOutput, 
						   PGPSize *pOutSize, BOOL *FYEO)
{
	PGPError			err			= kPGPError_NoErr;
	PGPOptionListRef	options		= NULL;
	PGPFileSpecRef		inputFile	= NULL;
	PGPFileSpecRef		outputFile	= NULL;
	PGPFileSpecRef		finalFile	= NULL;
	PGPFileSpecRef		dataFile	= NULL;
	PGPUInt32			macCreator	= 0;
	PGPUInt32			macType		= 0;
	VerificationBlock *	pVerBlock	= NULL;
	VerificationBlock * pTempBlock	= NULL;
	char *				szExtension = NULL;
	char *				szOutFile	= NULL;
	OUTBUFFLIST	      * obl			= NULL;
	OUTBUFFLIST       * nobl		= NULL;
	BOOL				bFYEO		= FALSE;
	BOOL				bDoFYEO		= FALSE;

	pgpAssert(szInFile != NULL);
	pgpAssert(pszOutFile != NULL);
	pgpAssert(szName != NULL);
	pgpAssert(szModule != NULL);
	pgpAssert(PGPRefIsValid(context));
	pgpAssert(PGPRefIsValid(tlsContext));

	if (ppOutput != NULL)
		*ppOutput = NULL;

	if (pOutSize != NULL)
		*pOutSize = 0;

	err = PGPNewFileSpecFromFullPath(context, szInFile, &inputFile);
	if (IsPGPError(err))
	{
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto DecryptVerifyFileError;
	}

	szOutFile = (char *) calloc(sizeof(char), strlen(szInFile)+5);
	if (szOutFile == NULL)
	{
		err = kPGPError_OutOfMemory;
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto DecryptVerifyFileError;
	}

	strcpy(szOutFile, szInFile);
 	szExtension = strrchr(szOutFile, '.');
	if (szExtension != NULL)
	{
		if (!strcmp(szExtension, ".asc") || !strcmp(szExtension, ".pgp"))
			*szExtension = '\0';
		else
			strcat(szOutFile, ".tmp");
	}
	else
		strcat(szOutFile, ".tmp");

	SetFileAttributes(szOutFile, FILE_ATTRIBUTE_NORMAL);

	if (bBinary)
	{
		err = PGPNewFileSpecFromFullPath(context, szOutFile, &outputFile);
		if (IsPGPError(err))
		{
			DisplayErrorCode(__FILE__, __LINE__, szModule, err);
			goto DecryptVerifyFileError;
		}
		
		err = PGPBuildOptionList(context, &options, 
				PGPOInputFile(context, inputFile),
				PGPOOutputFile(context, outputFile),
				PGPOLastOption(context));
	}
	else
	{
		pVerBlock = 
			(VerificationBlock *) PGPNewData(PGPGetContextMemoryMgr(context),
									sizeof(VerificationBlock),
									kPGPMemoryMgrFlags_Clear);

		pVerBlock->next = NULL;
		pVerBlock->szBlockBegin = NULL;
		pVerBlock->szBlockEnd = NULL;
		pVerBlock->pOutput = NULL;
		pVerBlock->outSize = 0;
		pVerBlock->bEncrypted = FALSE;
		pVerBlock->FYEO = FALSE;

		err = PGPBuildOptionList(context, &options, 
				PGPOInputFile(context, inputFile),
				PGPOLastOption(context));
	}

		
	if (IsPGPError(err))
	{
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto DecryptVerifyFileError;
	}

	err = DecryptVerify(hInst, hwnd, context, tlsContext, szName, szModule, 
			options, bMIME, pVerBlock);

	if (!bBinary)
	{
		HANDLE hFile;
		DWORD dwWritten;
		BOOL bFixed = FALSE;

		hFile = CreateFile(szOutFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
					FILE_ATTRIBUTE_NORMAL, NULL);

		pTempBlock = pVerBlock;
		while (pVerBlock != NULL)
		{
			if (pVerBlock->FYEO)
				bDoFYEO = TRUE;

			pVerBlock = pVerBlock->next;
		}
		pVerBlock = pTempBlock;

		if (bDoFYEO || (GetSecureViewerPref((void *)context)))
		{
			// Convert pVerBlock to OUTBUFFLIST
			do
			{
				if (pVerBlock->szBlockBegin != NULL)
				{
					nobl=MakeOutBuffItem(&obl);
					nobl->pBuff=pVerBlock->szBlockBegin;
					nobl->dwBuffSize=strlen(pVerBlock->szBlockBegin);
				}
				
				if (pVerBlock->pOutput != NULL)
				{
					nobl=MakeOutBuffItem(&obl);
					nobl->pBuff=pVerBlock->pOutput;
					nobl->dwBuffSize=strlen(pVerBlock->pOutput);

					if (GetSecureViewerPref((void *)context))
						nobl->FYEO = TRUE;
					else
					{
						nobl->FYEO=pVerBlock->FYEO;
						if (nobl->FYEO)
							bFYEO = TRUE;
					}
				}
				
				if (pVerBlock->szBlockEnd != NULL)
				{
					nobl=MakeOutBuffItem(&obl);
					nobl->pBuff=pVerBlock->szBlockEnd;
					nobl->dwBuffSize=strlen(pVerBlock->szBlockEnd);
				}
				
				pTempBlock = pVerBlock;
				pVerBlock=pVerBlock->next;
				PGPFreeData(pTempBlock);
			}
			while (pVerBlock != NULL);
			
			// Concatinate them to ppOutput
			ConcatOutBuffList((void *)context,
				obl,
				(char **)ppOutput,
				pOutSize,
				FYEO);

			/* We don't want to show the FYEO warning if the user has
			   "Always use Secure Viewer" on */

			*FYEO = bFYEO;
		}
		else do
		{
			// Fix for Eudora 4.0.1 bug where "boundary=..." is on
			// a separate line

			if (pVerBlock->szBlockBegin != NULL)
			{
				if (!bMIME)
				{
					WriteFile(hFile, pVerBlock->szBlockBegin, 
						strlen(pVerBlock->szBlockBegin), &dwWritten, 
						NULL);
						
					WriteFile(hFile, pVerBlock->pOutput, 
						strlen((char *) pVerBlock->pOutput), &dwWritten, 
						NULL);
					
					WriteFile(hFile, pVerBlock->szBlockEnd, 
						strlen(pVerBlock->szBlockEnd), &dwWritten, NULL);
					
					PGPFreeData(pVerBlock->szBlockBegin);
					PGPFreeData(pVerBlock->pOutput);
					PGPFreeData(pVerBlock->szBlockEnd);
				}
				else
				{
					BOOL bMultiMixed = FALSE;
					BOOL bMultiAlt = FALSE;
					BOOL bFirstMimePart = FALSE;
					MimePart *pMimeList = NULL;
					
					ParseMime((char *) pVerBlock->pOutput, &pMimeList);

					if (pMimeList != NULL)
					{
						bMultiMixed = (pMimeList->nContentType ==
										ContentType_MultipartMixed);

						bMultiAlt = (pMimeList->nContentType ==
										ContentType_MultipartAlternative);

						if (bMultiMixed || bMultiAlt)
						{
							WriteFile(hFile, pMimeList->szHeader,
								pMimeList->nHeaderLength, &dwWritten, NULL);
		
							WriteFile(hFile, pMimeList->szBody,
								pMimeList->nBodyLength, &dwWritten, NULL);

							WriteFile(hFile, pMimeList->szFooter,
								pMimeList->nFooterLength, &dwWritten, NULL);
	
							if (pMimeList->nextPart != NULL)
							{
								pMimeList = pMimeList->nextPart;
								free(pMimeList->previousPart);
							}
							else
							{
								free(pMimeList);
								pMimeList = NULL;
							}
						}
					}

					bFirstMimePart = TRUE;
					while (pMimeList != NULL)
					{
						WriteFile(hFile, pMimeList->szHeader,
							pMimeList->nHeaderLength, &dwWritten, NULL);

						if (bFirstMimePart || bMultiAlt)
						{
							bFirstMimePart = FALSE;

							if (pMimeList->nContentType == 
								ContentType_TextHTML)
							{
								char szTemp[] = "<html><pre>\r\n";

								WriteFile(hFile, szTemp, strlen(szTemp), 
									&dwWritten, NULL);
							}

							if ((pMimeList->nContentType ==
								ContentType_TextPlain) ||
								(pMimeList->nContentType ==
								ContentType_TextHTML))
							{
								WriteFile(hFile, pVerBlock->szBlockBegin, 
									strlen(pVerBlock->szBlockBegin), 
									&dwWritten, NULL);
							}

							if (pMimeList->nContentType == 
								ContentType_TextHTML)
							{
								char szTemp[] = "</html>\r\n";

								WriteFile(hFile, szTemp, strlen(szTemp), 
									&dwWritten, NULL);
							}
						}
					
						WriteFile(hFile, pMimeList->szBody,
							pMimeList->nBodyLength, &dwWritten, NULL);

						if (bMultiAlt || (pMimeList->nextPart == NULL))
						{
							if (pMimeList->nContentType == 
								ContentType_TextHTML)
							{
								char szTemp[] = "<html><pre>\r\n";

								WriteFile(hFile, szTemp, strlen(szTemp), 
									&dwWritten, NULL);
							}

							if ((pMimeList->nContentType ==
								ContentType_TextPlain) ||
								(pMimeList->nContentType ==
								ContentType_TextHTML))
							{
								WriteFile(hFile, pVerBlock->szBlockEnd, 
									strlen(pVerBlock->szBlockEnd), 
									&dwWritten, NULL);
							}

							if (pMimeList->nContentType == 
								ContentType_TextHTML)
							{
								char szTemp[] = "</html>\r\n";

								WriteFile(hFile, szTemp, strlen(szTemp), 
									&dwWritten, NULL);
							}
						}

						WriteFile(hFile, pMimeList->szFooter,
							pMimeList->nFooterLength, &dwWritten, NULL);

						if (pMimeList->nextPart != NULL)
						{
							pMimeList = pMimeList->nextPart;
							free(pMimeList->previousPart);
						}
						else
						{
							free(pMimeList);
							pMimeList = NULL;
						}
					}

					PGPFreeData(pVerBlock->szBlockBegin);
					PGPFreeData(pVerBlock->pOutput);
					PGPFreeData(pVerBlock->szBlockEnd);
				}
			}
			else if (pVerBlock->pOutput != NULL)
			{
				WriteFile(hFile, pVerBlock->pOutput, 
					strlen((char *) pVerBlock->pOutput), &dwWritten, 
					NULL);
				
				PGPFreeData(pVerBlock->pOutput);
			}
				
			pTempBlock = pVerBlock;
			pVerBlock = pTempBlock->next;
			PGPFreeData(pTempBlock);
		}
		while (pVerBlock != NULL);
			
		CloseHandle(hFile);

		*pszOutFile = (char *) PGPNewData(PGPGetContextMemoryMgr(context),
									strlen(szOutFile)+1,
									kPGPMemoryMgrFlags_Clear);
		strcpy(*pszOutFile, szOutFile);
	}
	else
	{
		PGPMacBinaryToLocal(outputFile, &finalFile, &macCreator, &macType);
		if (finalFile != NULL)
			PGPGetFullPathFromFileSpec(finalFile, pszOutFile);
		else
		{
			*pszOutFile = (char *) PGPNewData(PGPGetContextMemoryMgr(context),
										strlen(szOutFile)+1,
										kPGPMemoryMgrFlags_Clear);
			strcpy(*pszOutFile, szOutFile);
		}
	}

DecryptVerifyFileError:

	if (finalFile != NULL)
		PGPFreeFileSpec(finalFile);

	if (inputFile != NULL)
		PGPFreeFileSpec(inputFile);

	if (outputFile != NULL)
		PGPFreeFileSpec(outputFile);

	if (options != NULL)
		PGPFreeOptionList(options);

	return err;
}


PGPError DecryptVerify(HINSTANCE hInst, HWND hwnd, PGPContextRef context, 
					   PGPtlsContextRef tlsContext, 
					   char *szName, char *szModule,
					   PGPOptionListRef options, BOOL bMIME,
					   VerificationBlock *pVerBlock)
{
	PGPError			err			= kPGPError_NoErr;
	PGPKeySetRef		pubKeySet	= NULL;
	PGPKeySetRef		newKeySet	= NULL;
	PGPOptionListRef	tempOptions	= NULL;
	PGPUInt32			nNumKeys	= 0;
	HWND				hwndWorking	= NULL;
	char				szWorkingTitle[256];
	DecodeEventData		decodeData;

	UpdateWindow(hwnd);

	decodeData.hInst		= hInst;
	decodeData.hwnd			= hwnd;
	decodeData.tlsContext	= tlsContext;
	decodeData.szName		= szName;
	decodeData.recipients	= NULL;
	decodeData.keyCount		= 0;
	decodeData.keyIDArray	= NULL;
	decodeData.pVerBlock	= pVerBlock;
//BEGIN - VERIFICATION BLOCK STRING for encrypted msgs - Disastry
	decodeData.encr			= 0;
//END

	err = PGPsdkLoadDefaultPrefs(context);
	if (IsPGPError(err))
	{
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto DecryptVerifyError;
	}

	err = PGPOpenDefaultKeyRings(context, (PGPKeyRingOpenFlags)0, &pubKeySet);
	if (IsPGPError(err))
	{
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto DecryptVerifyError;
	}

	decodeData.pubKeySet = pubKeySet;

	PGPNewKeySet(context, &newKeySet);

	LoadString(hInst, IDS_WORKINGDECRYPT, szWorkingTitle, 
		sizeof(szWorkingTitle));

	hwndWorking = WorkingDlgProcThread(GetModuleHandle(szModule), hInst, NULL,
					szWorkingTitle, "");
	decodeData.hwndWorking = hwndWorking;

	err = PGPDecode(context,
			options,
			PGPOPassThroughIfUnrecognized(context, (PGPBoolean) !bMIME),
			PGPOPassThroughKeys(context, TRUE),
			PGPOEventHandler(context, DecodeEventHandler, &decodeData),
			PGPOSendNullEvents(context, 100),
			PGPOImportKeysTo(context, newKeySet),
			PGPOKeySetRef(context, pubKeySet),
			PGPOLastOption(context));

	DestroyWindow(hwndWorking);

	if (IsPGPError(err) && (err != kPGPError_UserAbort))
	{
		DisplayErrorCode(__FILE__, __LINE__, szModule, err);
		goto DecryptVerifyError;
	}

	PGPCountKeys(newKeySet, &nNumKeys);
	if (nNumKeys > 0)
		PGPclQueryAddKeys(context, tlsContext, hwnd, newKeySet, NULL);

DecryptVerifyError:

	if (decodeData.recipients != NULL)
		PGPFreeKeySet(decodeData.recipients);

	if (decodeData.keyIDArray != NULL)
		free(decodeData.keyIDArray);

	if (newKeySet != NULL)
		PGPFreeKeySet(newKeySet);

	if (pubKeySet != NULL)
		PGPFreeKeySet(pubKeySet);

	return err;
}


PGPError DecodeEventHandler(PGPContextRef context, 
							PGPEvent *event, 
							PGPUserValue userValue)
{
	HWND			hwnd			= NULL;
	char *			szPassPhrase	= NULL;
	PGPByte *		pPasskey		= NULL;
	PGPUInt32		nPasskeyLength	= 0;
	static BOOL		bAlreadyAsked	= FALSE;
	char *			szName			= NULL;
	PGPMemoryMgrRef	memoryMgr		= NULL;
	PGPKeySetRef	pubKeySet		= NULL;
	PGPKeySetRef	addedKeys		= NULL;
	PGPKeySetRef	recipients		= NULL;
	PGPUInt32		keyCount		= 0;
	PGPKeyID		*keyIDArray		= NULL;
	DecodeEventData	*userData		= NULL;
	HWND			hwndWorking		= NULL;
	PGPError		err				= kPGPError_NoErr;
//	char sz[100];

	pgpAssert(PGPRefIsValid(context));
	pgpAssert(event != NULL);

	userData = (DecodeEventData *) userValue;

	hwnd			= userData->hwnd;
	hwndWorking		= userData->hwndWorking;
	szName			= userData->szName;
	pubKeySet		= userData->pubKeySet;
	recipients		= userData->recipients;
	keyCount		= userData->keyCount;
	keyIDArray		= userData->keyIDArray;

	memoryMgr = PGPGetContextMemoryMgr(context);

	switch (event->type)
	{
	case kPGPEvent_NullEvent:
		{	
			PGPEventNullData *d = &event->data.nullData;
			BOOL bCancel;

			bCancel = WorkingCallback (	hwndWorking, 
										(unsigned long)d->bytesWritten, 
										(unsigned long)d->bytesTotal) ;

			if(bCancel)
			{
				return kPGPError_UserAbort;
			}
		}
		break;

	case kPGPEvent_BeginLexEvent:
		if (userData->pVerBlock != NULL)
		{
			userData->pVerBlock->bEncrypted = FALSE;
//BEGIN - VERIFICATION BLOCK STRING for encrypted msgs - Disastry
			userData->encr = 0;
//END
		}
		break;

//BEGIN - VERIFICATION BLOCK STRING for encrypted msgs - Disastry
	case kPGPEvent_EndLexEvent: // Final event per lexical unit
			if (userData->encr) {
				//char sztemp [20];
				//sprintf(sztemp,"cipher: %i",userData->encr);
				//MessageBox(NULL,sztemp,sztemp,MB_OK|MB_TOPMOST);
				if (userData->pVerBlock->previous == NULL) {
				  if (!userData->pVerBlock->szBlockBegin)
					CreateVerificationBlock(userData->hInst, context, NULL,
						//TRUE,
						userData->encr,
						&(userData->pVerBlock->szBlockBegin),
						&(userData->pVerBlock->szBlockEnd));
				} else
				  if (!userData->pVerBlock->previous->szBlockBegin)
					CreateVerificationBlock(userData->hInst, context, NULL,
						//TRUE,
						userData->encr,
						&(userData->pVerBlock->previous->szBlockBegin),
						&(userData->pVerBlock->previous->szBlockEnd));
			}
		break;
//END

	case kPGPEvent_OutputEvent:
		if (userData->pVerBlock != NULL)
		{
			PGPEventOutputData *d = &event->data.outputData;

			// Added FYEO member for tempest viewer
			userData->pVerBlock->FYEO=d->forYourEyesOnly;

			PGPAddJobOptions(event->job,
				PGPOAllocatedOutputBuffer(context, 
					&(userData->pVerBlock->pOutput), 
					INT_MAX, 
					&(userData->pVerBlock->outSize)),
				PGPOLastOption(context));

			userData->pVerBlock->next = (VerificationBlock *) 
				PGPNewData(memoryMgr,
					sizeof(VerificationBlock),
					kPGPMemoryMgrFlags_Clear);

			userData->pVerBlock->next->previous = userData->pVerBlock;
			userData->pVerBlock = userData->pVerBlock->next;
			userData->pVerBlock->szBlockBegin = NULL;
			userData->pVerBlock->szBlockEnd = NULL;
			userData->pVerBlock->pOutput = NULL;
			userData->pVerBlock->outSize = 0;
			userData->pVerBlock->bEncrypted = FALSE;
			userData->pVerBlock->FYEO = FALSE;
		}
		break;

	case kPGPEvent_RecipientsEvent:
		{
			PGPEventRecipientsData	*eventData; 

			eventData = &(event->data.recipientsData);

			PGPIncKeySetRefCount(eventData->recipientSet);
			userData->recipients = eventData->recipientSet;
			userData->keyCount = eventData->keyCount;

			if (eventData->keyCount > 0)
			{
				UINT i;

				userData->keyIDArray =	(PGPKeyID *) 
										calloc(sizeof(PGPKeyID),
												eventData->keyCount);

				for (i=0; i<eventData->keyCount; i++)
					userData->keyIDArray[i] = eventData->keyIDArray[i];
			}
			else
				userData->keyIDArray = NULL;
		}
		break;

	case kPGPEvent_PassphraseEvent:
		{
			char szPrompt[256];
			PGPEventPassphraseData *d = &event->data.passphraseData;

			if (bAlreadyAsked)
				LoadString(userData->hInst, IDS_PASSPHRASEREENTER, szPrompt, 
					sizeof(szPrompt));
			else
				LoadString(userData->hInst, IDS_PASSPHRASEPROMPT, szPrompt, 
					sizeof(szPrompt));

			// Don't cache conventional passphrases
			if(d->fConventional)
			{
				err=PGPclGetPhrase (context,
					pubKeySet,
					hwnd,
					szPrompt,
					&szPassPhrase, 
					NULL,
					NULL, 
					0,
					NULL,
					NULL,
					PGPCL_DECRYPTION,
					NULL,NULL,
					1,0,userData->tlsContext,NULL,NULL);
			}
			else
			{
				err = PGPclGetCachedDecryptionPhrase(context, 
						userData->tlsContext, pubKeySet, hwnd, szPrompt, 
						bAlreadyAsked, &szPassPhrase, recipients, keyIDArray,
						keyCount, &pPasskey, &nPasskeyLength,  &addedKeys,NULL);
			}
			
			if (addedKeys != NULL)
			{
				PGPUInt32 numKeys;
				
				PGPCountKeys(addedKeys, &numKeys);
				if (numKeys > 0)
					PGPclQueryAddKeys(context, userData->tlsContext, hwnd, 
						addedKeys, NULL);
				
				PGPFreeKeySet(addedKeys);
				addedKeys = NULL;
			}
			
			switch (err)
			{
			case kPGPError_NoErr:
				bAlreadyAsked = TRUE;
				break;
				
			default:
				return err;
			}
			
			if (IsntNull(szPassPhrase))
			{
				err = PGPAddJobOptions(event->job,
						PGPOPassphrase(context, szPassPhrase),
						PGPOLastOption(context));
				
				PGPclFreeCachedPhrase(szPassPhrase);
				szPassPhrase = NULL;
			}
			else if (IsntNull(pPasskey))
			{
				err = PGPAddJobOptions(event->job, 
						PGPOPasskeyBuffer(context, pPasskey, nPasskeyLength),
						PGPOLastOption(context));
			}
			
			if (IsntNull(pPasskey))
			{
				PGPFreeData(pPasskey);
				pPasskey = NULL;
				nPasskeyLength = 0;
			}
		}
		break;

	case kPGPEvent_AnalyzeEvent:
		
		if (userData->pVerBlock != NULL)
		{
			if (event->data.analyzeData.sectionType == kPGPAnalyze_Encrypted)
				userData->pVerBlock->bEncrypted = TRUE;
		}
		
		
		
		//BEGIN SKIP OVER NON PGP DATA
		/*switch (event->data.analyzeData.sectionType) {
		case kPGPAnalyze_Encrypted:
			strcpy(sz,"kPGPAnalyze_Encrypted");break;
		case kPGPAnalyze_Signed:
			strcpy(sz,"kPGPAnalyze_Signed");break;
		case kPGPAnalyze_DetachedSignature:
			strcpy(sz,"kPGPAnalyze_DetachedSignature");break;
		case kPGPAnalyze_Key:
			strcpy(sz,"kPGPAnalyze_Key");break;
		case kPGPAnalyze_Unknown:
			strcpy(sz,"kPGPAnalyze_Unknown");break;
		case kPGPAnalyze_X509Certificate:
			strcpy(sz,"kPGPAnalyze_X509Certificate");break;
		}
		MessageBox(NULL,"kPGPEvent_AnalyzeEvent",sz,MB_OK);*/
		if (event->data.analyzeData.sectionType == kPGPAnalyze_Unknown) {
			return kPGPError_SkipSection;
		}
		//END SKIP OVER NON PGP DATA
		break;

	case kPGPEvent_SignatureEvent:
		{
			PGPEventSignatureData *d = &event->data.signatureData;

			if (IsNull(d->signingKey) && 
				SyncOnVerify(memoryMgr))
			{
				PGPBoolean bGotKeys;

				PGPclLookupUnknownSigner(context, pubKeySet, 
					userData->tlsContext, hwnd, event, d->signingKeyID, 
					&bGotKeys);

				if (bGotKeys)
					return kPGPError_NoErr;
			}

			if (userData->pVerBlock == NULL)
				SigEvent(hwnd, context, d, szName);
			else
			{
				if (userData->pVerBlock->previous == NULL)
					CreateVerificationBlock(userData->hInst, context, d,
						userData->pVerBlock->bEncrypted,
						&(userData->pVerBlock->szBlockBegin),
						&(userData->pVerBlock->szBlockEnd));
				else
					CreateVerificationBlock(userData->hInst, context, d,
						userData->pVerBlock->previous->bEncrypted,
						&(userData->pVerBlock->previous->szBlockBegin),
						&(userData->pVerBlock->previous->szBlockEnd));
				//BEGIN SUPPORT PGPLog IN PLUGINS - Imad R. Faiad
				if (strcmp(userData->szName, "The Bat!") == 0){
					SigEvent(hwnd, context, d, szName);
				}
				//END SUPPORT PGPLog IN PLUGINS
			}
		}
		break;

//BEGIN - VERIFICATION BLOCK STRING for encrypted msgs - Disastry
	case kPGPEvent_DecryptionEvent: // Decryption data report		
		userData->encr = event->data.decryptionData.cipherAlgorithm;
		if (userData->pVerBlock != NULL)
			userData->pVerBlock->bEncrypted = userData->encr;
			//userData->encr++;
		break;
//END

	case kPGPEvent_FinalEvent:
		if (IsntNull(szPassPhrase))
		{
			PGPclFreeCachedPhrase(szPassPhrase);
			szPassPhrase = NULL;
		}
		if (IsntNull(pPasskey))
		{
			PGPFreeData(pPasskey);
			pPasskey = NULL;
			nPasskeyLength = 0;
		}
		bAlreadyAsked = FALSE;
		break;
	}

	return err;
}


void DisplayErrorCode(char *szFile, int nLine, char *szModule, int nCode)
{
	char szErrorMsg[255];

	if (nCode == kPGPError_BadPacket)
		nCode = kPGPError_CorruptData;

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
