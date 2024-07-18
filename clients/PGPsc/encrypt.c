/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: encrypt.c,v 1.135 1999/04/13 17:29:54 wjb Exp $
____________________________________________________________________________*/
#include "precomp.h"

BOOL GetCommentLine(PGPContextRef context,
					char *comment,PGPSize size,PGPUInt32 *PrefAlg,
					PGPCipherAlgorithm *pAllowedAlgs, int *pNumAlgs)
{
	PGPPrefRef	ClientPrefRef=NULL;
	PGPPrefRef	AdminPrefRef=NULL;
	PGPError	err;
	BOOL RetVal;
	PGPMemoryMgrRef memMgr;

	memMgr=PGPGetContextMemoryMgr(context);

	RetVal=TRUE;

	*comment=0;
	*PrefAlg=kPGPCipherAlgorithm_CAST5;

#if PGP_BUSINESS_SECURITY
	err = PGPclOpenAdminPrefs (memMgr,&AdminPrefRef, PGPclIsAdminInstall());

	if (IsPGPError (err)) 
		return FALSE;	// error-out

	err=PGPGetPrefStringBuffer(AdminPrefRef,
	   kPGPPrefComments,
	   size,
	   comment);

	PGPclCloseAdminPrefs (AdminPrefRef, FALSE);
#endif	// PGP_BUSINESS_SECURITY

	err=PGPclOpenClientPrefs (memMgr,&ClientPrefRef);
	if(IsntPGPError(err))
	{
		PGPCipherAlgorithm *pData;
		PGPSize	dataLength;
		int i;

		PGPGetPrefNumber(ClientPrefRef,
			kPGPPrefPreferredAlgorithm, 
			PrefAlg);

		err = PGPGetPrefData(ClientPrefRef,
			kPGPPrefAllowedAlgorithmsList, 
			&dataLength, (void **) &pData);

		if (IsntPGPError(err))
		{
			*pNumAlgs = dataLength / sizeof(PGPCipherAlgorithm);
			//BEGIN PREFERRED ALGORITHM IN ACCORDANCE WITH ALLOWED ALGORITHMS
			for (i=0; i<*pNumAlgs; i++)
				pAllowedAlgs[i] = pData[i];

			PGPDisposePrefData(ClientPrefRef, (void *) pData);
		}
		else
			*pNumAlgs = 0;

		if(*comment==0)
		{
			PGPGetPrefStringBuffer(ClientPrefRef,
				kPGPPrefComment,
				size,
				comment);
		}
		PGPclCloseClientPrefs (ClientPrefRef, FALSE);
	}
	
	return RetVal;
}

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

//BEGIN VERSION STRING MOD - Imad R. Faiad
//	_______________________________________________
//
//  Get appropriate Version string

VOID
SCRememberVersionHeaderString ( PGPContextRef context)
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
		lstrcpy (pgpVersionHeaderString, "");;
}
//END VERSION STRING MOD
//BEGIN 64 BITS KEY ID DISPLAY MOD - Imad R. Faiad
void
SCGetPref64BitsKeyIDDisplay ( PGPUInt32 *H64BitsKeyIDDisplay )
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
PGPError GenericEncSign(MYSTATE *ms,
					PGPOptionListRef opts,
					char *OperationTarget)
{
	PGPError err;
	int UserCancel;
	PGPBoolean DataIsASCII;
	PGPUInt32 numKeys;
	PRECIPIENTDIALOGSTRUCT prds;
	PGPContextRef	context;
	char StrRes[500],szRDprompt[100],szPassTitle[100];
	PGPBoolean FYEO;

	err=kPGPError_NoErr;	
	
	context=ms->context;

	prds=ms->prds;

	// If this is first operation, put up recipient/sign dialog

	if(ms->numDone==0)
	{
		FreePhrases(ms);

		if(ms->Encrypt)
		{
			int RecipientReturn;

			LoadString (g_hinst, IDS_PGPKEYSELDLG, StrRes, sizeof(StrRes));
			strcpy(szRDprompt,ms->szAppName);
			strcat(szRDprompt,StrRes);

			prds->Version=CurrentPGPrecipVersion;
			prds->hwndParent=ms->hwndWorking;
			prds->szTitle=szRDprompt;
			prds->Context=ms->context;
			prds->tlsContext=ms->tlsContext;
			prds->OriginalKeySetRef=ms->KeySet;

			prds->dwDisableFlags|=PGPCL_DISABLE_FYEO;

			// FYEO only for clipboard or text files
			if((ms->Operation==MS_ENCRYPTCLIPBOARD) ||
				(FileHasThisExtension(OperationTarget,"txt")))
			{
				prds->dwDisableFlags&=(~PGPCL_DISABLE_FYEO);
			}

			if(!((ms->Operation==MS_ENCRYPTFILELIST)&&
				(ms->Encrypt)&&(!ms->Sign)))
				prds->dwDisableFlags|=PGPCL_DISABLE_SDA;

			RecipientReturn = PGPclRecipientDialog(prds);

			if(!RecipientReturn)
				return kPGPError_UserAbort;

			if(prds->dwOptions & PGPCL_SDA)
			{
				LoadString (g_hinst, IDS_ENTERPASSPHRASE, StrRes, sizeof(StrRes));
				strcpy(szPassTitle,ms->szAppName);
				strcat(szPassTitle,StrRes);

				LoadString (g_hinst, IDS_ENTERSDAPASS, StrRes, sizeof(StrRes));

				UserCancel = PGPclGetPhrase (context,
					ms->KeySet,
					ms->hwndWorking,
					StrRes,
					&(ms->ConvPassPhrase), 
					NULL,
					NULL, 
					0,
					NULL,
					NULL,
					PGPCL_ENCRYPTION,
					NULL,NULL,
					1,0,ms->tlsContext,NULL,szPassTitle);

				if(UserCancel)
					return kPGPError_UserAbort;
			}
			else if(prds->dwOptions & PGPCL_PASSONLY)
			{
				LoadString (g_hinst, IDS_ENTERPASSPHRASE, StrRes, sizeof(StrRes));
				strcpy(szPassTitle,ms->szAppName);
				strcat(szPassTitle,StrRes);

				LoadString (g_hinst, IDS_CONVPASSPROMPT, StrRes, sizeof(StrRes));

				UserCancel = PGPclGetPhrase (context,
					ms->KeySet,
					ms->hwndWorking,
					StrRes,
					&(ms->ConvPassPhrase), 
					NULL,
					NULL, 
					0,
					NULL,
					NULL,
					PGPCL_ENCRYPTION,
					NULL,NULL,
					1,0,ms->tlsContext,NULL,szPassTitle);

				if(UserCancel)
					return kPGPError_UserAbort;
			}

		}

		if(ms->Sign)
		{
			DWORD *lpOptions;
			PGPError err;

			LoadString (g_hinst, IDS_ENTERPASSPHRASE, StrRes, sizeof(StrRes));
			strcpy(szPassTitle,ms->szAppName);
			strcat(szPassTitle,StrRes);

			lpOptions=&(prds->dwOptions);

//BEGIN ARMOR SIGN CLIPBOARD - Disastry
			//if (ms->Encrypt || (ms->Operation==MS_ENCRYPTCLIPBOARD))
            if (ms->Encrypt)
				lpOptions=0;
            else
			if (ms->Operation==MS_ENCRYPTCLIPBOARD) {
                if (ms->Sign && !ms->Encrypt)
                    *lpOptions |= PGPCL_CLIPBOARDSIGN;
                else
				    lpOptions=0;
            }
//END ARMOR SIGN CLIPBOARD

			LoadString (g_hinst, IDS_PASSPROMPTABOVEKEY, StrRes, sizeof(StrRes));

			err=PGPclGetCachedSigningPhrase (context,
				ms->tlsContext,
				ms->hwndWorking, 
				StrRes,
				FALSE, // ForceEntry
				&ms->PassPhrase,
				ms->KeySet,
				&(ms->SignKey),
				NULL,
				lpOptions,
				prds->dwFlags,
				&ms->PassKey,
				&ms->PassKeyLen,
				NULL,szPassTitle);
			
			if(err != kPGPError_NoErr)
			{
				PGPclEncDecErrorBox(ms->hwndWorking,err);
				return kPGPError_UserAbort; // UserCancel 
			}
		}
	} //END of first operation recipient/sign dialog stuff

	ms->fileName=OperationTarget;

	if(prds->dwOptions & PGPCL_SDA)
	{
		// Self Decryptor
		err=SDA(ms);

		// Inform loop to stop processing files, since we've done 
		// them all
		ms->bDoingSDA=TRUE;

		// Don't do anything else like file wiping etc...
		return err;
	}

	// if encrypting, throw in recipients
	if(ms->Encrypt)
	{
		if(prds->dwOptions & PGPCL_PASSONLY)
		{
			int ConvPassLen;

			ConvPassLen = strlen(ms->ConvPassPhrase);

			PGPAppendOptionList(opts,
				PGPOConventionalEncrypt(context, 
					PGPOPassphraseBuffer(context,ms->ConvPassPhrase,
						ConvPassLen),
						PGPOLastOption(context) ),
				PGPOCipherAlgorithm(context,ms->PrefAlg),
				PGPOLastOption(context) );
		}
		else
		{
			PGPAppendOptionList(opts,
				PGPOEncryptToKeySet(context,prds->SelectedKeySetRef),
				PGPOLastOption(context) );
		}
	}

	if(ms->Sign)  // If signing, throw in a passphrase and key
	{
		// Use passkey if available
		if(ms->PassKey)
		{
			PGPAppendOptionList(opts,
				PGPOSignWithKey(context,ms->SignKey,
					PGPOPasskeyBuffer(context,
						ms->PassKey,ms->PassKeyLen),
					PGPOLastOption(context) ),
				PGPOLastOption(context) );
		}
		else
		{
			PGPAppendOptionList(opts,
				PGPOSignWithKey(context,ms->SignKey,
					PGPOLastOption(context) ),
				PGPOLastOption(context) );
		}
	}

	if((prds->dwOptions & PGPCL_DETACHEDSIG) &&
		!(ms->Operation==MS_ENCRYPTCLIPBOARD) && 
		(ms->Sign) && !(ms->Encrypt))
	{
		PGPAppendOptionList(opts,
			PGPODetachedSig(context,
				PGPOLastOption(context)), 
			PGPOLastOption(context));
	}
	else
		prds->dwOptions&=(~PGPCL_DETACHEDSIG);

	DataIsASCII=(ms->Operation==MS_ENCRYPTCLIPBOARD);

	// If we have text out arguments....
	if(prds->dwOptions & PGPCL_ASCIIARMOR 
//BEGIN ARMOR SIGN CLIPBOARD - Disastry
        || (ms->Operation==MS_ENCRYPTCLIPBOARD && !(ms->Encrypt))
//END ARMOR SIGN CLIPBOARD
        )
	{
		if((ms->Operation==MS_ENCRYPTCLIPBOARD) && 
			(ms->Sign) && !(ms->Encrypt) && 
			((prds->dwOptions & PGPCL_DETACHEDSIG)==0)
//BEGIN ARMOR SIGN CLIPBOARD - Disastry
            && ((prds->dwOptions & PGPCL_ASCIIARMOR)==0)
//END ARMOR SIGN CLIPBOARD
            )
		{ // Clearsign!
			PGPAppendOptionList(opts,
				PGPOClearSign(context, TRUE),
				PGPOLastOption(context));
		}
		else if(!(ms->Operation==MS_ENCRYPTCLIPBOARD) && 
			(ms->Sign) && !(ms->Encrypt) && 
			((prds->dwOptions & PGPCL_DETACHEDSIG)==0)&&
		  FileHasThisExtension(OperationTarget,"txt")) 
		{ // Clearsign a .txt file
			DataIsASCII=TRUE; // Set to ASCII input

			PGPAppendOptionList(opts,
				PGPOClearSign(context, TRUE),
				PGPOLastOption(context));
		} 
		else // Just Ascii Armor*/
		{
			PGPAppendOptionList(opts,
				PGPOArmorOutput(context, TRUE),
				PGPOLastOption(context));
		}
	}
	//BEGIN KEY INFO IN COMMENT BLOCK - Imad R. Faiad
	if(ms->Sign) {
		PGPKeyID	KeyID;
		CHAR		szID[kPGPMaxKeyIDStringSize];
		char		lcomment[256];
		PGPByte		fingerprintBytes[256];
		UINT		u, uAlgorithm;
		BOOL		bDoKeyID, bDoFingerprint;
		PGPBoolean	abbrev;

		bDoKeyID = AppendKeyIDToComment(context);
		bDoFingerprint = AppendKeyFPToComment(context);

		SCGetPref64BitsKeyIDDisplay(&u);
		if (u == 1)
			abbrev = kPGPKeyIDString_Full;
		else
			abbrev = kPGPKeyIDString_Abbreviated;

		if ( (bDoKeyID) & (bDoFingerprint) ) {
			if (*(ms->comment) != 0) {
				lstrcpy (lcomment, ms->comment);
				lstrcat (lcomment, "\nComment: KeyID: 0x");
			}
			else {
				lstrcpy (lcomment, "KeyID: 0x");
			}
			PGPGetKeyIDFromKey (ms->SignKey, &KeyID);
			PGPGetKeyIDString (&KeyID, abbrev, szID);
			lstrcat (lcomment, &szID[2]);
			lstrcat (lcomment, "\nComment: Fingerprint: ");
			PGPGetKeyPropertyBuffer(ms->SignKey, kPGPKeyPropFingerprint,
				sizeof( fingerprintBytes ), fingerprintBytes, &u);
			PGPGetKeyNumber (ms->SignKey, kPGPKeyPropAlgID, &uAlgorithm);
    	    //BEGIN RSAv4 SUPPORT MOD - Disastry
    		//ConvertStringFingerprint (uAlgorithm, fingerprintBytes);
    		ConvertStringFingerprint (u, fingerprintBytes);
    	    //END RSAv4 SUPPORT MOD
			lstrcat (lcomment, fingerprintBytes);
			*(ms->comment) = 0;
			PGPAppendOptionList(opts,
				PGPOCommentString(context,lcomment),
				PGPOLastOption(context));
		}
		else if (bDoKeyID) {
				if (*(ms->comment) != 0) {
					lstrcpy (lcomment, ms->comment);
					lstrcat (lcomment, "\nComment: KeyID: 0x");
				}
				else {
					lstrcpy (lcomment, "KeyID: 0x");
				}
				PGPGetKeyIDFromKey (ms->SignKey, &KeyID);
				PGPGetKeyIDString (&KeyID, abbrev, szID);
				lstrcat (lcomment, &szID[2]);
				*(ms->comment) = 0;
				PGPAppendOptionList(opts,
				PGPOCommentString(context,lcomment),
				PGPOLastOption(context));
		}
		else if (bDoFingerprint) {
				if (*(ms->comment) != 0) {
				lstrcpy (lcomment, ms->comment);
				lstrcat (lcomment, "\nComment: Fingerprint: ");
				}
				else {
				lstrcpy (lcomment, "Fingerprint: ");
				}
				PGPGetKeyPropertyBuffer(ms->SignKey, kPGPKeyPropFingerprint,
				sizeof( fingerprintBytes ), fingerprintBytes, &u);
			PGPGetKeyNumber (ms->SignKey, kPGPKeyPropAlgID, &uAlgorithm);
    	    //BEGIN RSAv4 SUPPORT MOD - Disastry
    		//ConvertStringFingerprint (uAlgorithm, fingerprintBytes);
    		ConvertStringFingerprint (u, fingerprintBytes);
    	    //END RSAv4 SUPPORT MOD
			lstrcat (lcomment, fingerprintBytes);
			*(ms->comment) = 0;
			PGPAppendOptionList(opts,
				PGPOCommentString(context,lcomment),
				PGPOLastOption(context));

		}
	}
	//END KEY INFO IN COMMENT BLOCK
	if(*(ms->comment)!=0)
	{
		PGPAppendOptionList(opts,
			PGPOCommentString(context,(ms->comment)),
			PGPOLastOption(context));
	}

	if(ms->Operation!=MS_ENCRYPTCLIPBOARD)
		SCSetProgressNewFilename(ms->hPrgDlg,"From '%s' To '%s'",ms->fileName,TRUE);

	if(!(ms->Operation==MS_ENCRYPTCLIPBOARD))
	{
		char outname[MAX_PATH];

		ms->fileRef=0;
		strcpy(outname,ms->fileName);

		AlterEncryptedFileName(outname,prds->dwOptions);

		LoadString (g_hinst, IDS_ENCFILENAMEPROMPT, StrRes, sizeof(StrRes));

		UserCancel=SaveOutputFile(context,
			ms->hwndWorking, 
			StrRes,
			outname,
			&(ms->fileRef),
			FALSE);

		if(UserCancel)
			return kPGPError_UserAbort;

		PGPAppendOptionList(opts,
			PGPOOutputFile(context,ms->fileRef),
			PGPOLastOption(context));
	}

	// Assume False for For Your Eyes Only
	FYEO=FALSE;

	// These are the only situations we can have FYEO
	if((ms->Operation==MS_ENCRYPTCLIPBOARD) ||
		(FileHasThisExtension(OperationTarget,"txt")))
	{
		// If the recipient dialog has selected it then we're OK
		if((prds->dwOptions & PGPCL_FYEO)==PGPCL_FYEO)
		{
			FYEO=TRUE;
		}
	}

	//BEGIN VERSION STRING MOD - Imad R. Faiad
	SCRememberVersionHeaderString (context);
	//END VERSION STRING MOD

	err = PGPEncode(context,
		opts,
		PGPOPreferredAlgorithms(context,ms->allowedAlgs,ms->nNumAlgs),
		PGPOSendNullEvents(context,75),
		PGPOEventHandler(context,myEvents,ms),
		PGPOVersionString(context,pgpVersionHeaderString),
		PGPOAskUserForEntropy(context, TRUE),
		PGPODataIsASCII(context,DataIsASCII),
		PGPOForYourEyesOnly(context,FYEO),
		PGPOLastOption(context));

	SCSetProgressBar(ms->hPrgDlg,100,TRUE);	

	if(PGPRefIsValid(prds->AddedKeys))
	{
		(void)PGPCountKeys( prds->AddedKeys, &numKeys );
		if ( numKeys > 0) 
		{	
			PGPclQueryAddKeys (context,ms->tlsContext,ms->hwndWorking,
				prds->AddedKeys,NULL);
		}
		PGPFreeKeySet (prds->AddedKeys);
	}

	return err;
}

PGPError EncryptFileListStub (MYSTATE *ms) 
{
	PGPContextRef context;
	PGPFileSpecRef inref;
	PGPOptionListRef opts;
	PGPError err;
	FILELIST *FileCurrent;
	UINT WipeReturn;

	err=kPGPError_NoErr;

	context=ms->context;
	FileCurrent=ms->ListHead;

	while(!(SCGetProgressCancel(ms->hPrgDlg))&&(FileCurrent!=0)&&(IsntPGPError(err)))
	{   
		if(FileCurrent->IsDirectory)
		{
			if(ms->prds->dwOptions & PGPCL_WIPEORIG)
				_rmdir(FileCurrent->name);

			FileCurrent=FileCurrent->next;
			continue;
		}

		// We'll ask for output file in event handler later...
		PGPNewFileSpecFromFullPath( context,
			FileCurrent->name, &inref);

		PGPBuildOptionList(context,&opts,
			PGPOInputFile(context,inref),
			PGPOLastOption(context));
	
		// For SDA's we only have to do this once, so don't
		// do it again on the second+ times
		if(!ms->bDoingSDA)
		{
			err=GenericEncSign(ms,opts,FileCurrent->name);
		}

		PGPFreeOptionList(opts);

		PGPFreeFileSpec( inref );

		if(ms->fileRef)
			PGPFreeFileSpec(ms->fileRef);

		ms->numDone++;
		FileCurrent=FileCurrent->next;				
	}

	// Do any file wiping on a second pass
	if((IsntPGPError(err))&&(ms->prds->dwOptions & PGPCL_WIPEORIG))
	{
		SCSetProgressAVI(ms->hPrgDlg,IDR_ERASEAVI);
		SCSetProgressTitle(ms->hPrgDlg,"Wiping File(s)...");

		FileCurrent=ms->ListHead;
		
		while(!(SCGetProgressCancel(ms->hPrgDlg))&&(FileCurrent!=0)&&(IsntPGPError(err)))
		{   
			if(FileCurrent->IsDirectory)
			{
				// Try to remove directory if we can. Don't
				// worry if we fail (full of new files)
				if(ms->prds->dwOptions & PGPCL_WIPEORIG)
					_rmdir(FileCurrent->name);

				FileCurrent=FileCurrent->next;
				continue;
			}

			WipeReturn=InternalFileWipe(ms->context,
				ms->hwndWorking,
				FileCurrent->name,TRUE);

			if(WipeReturn!=WIPE_OK)
			{
				if (WipeError(ms->hwndWorking,
					FileCurrent,WipeReturn))
				{
					err=kPGPError_UnknownError;
				}
			}

			FileCurrent=FileCurrent->next;
		}
	}

	return err;
}

BOOL EncryptFileList(HWND hwnd,char *szApp,
					 void *PGPsc,
					 void *PGPtls,
					 FILELIST *ListHead,
					 BOOL bEncrypt, 
					 BOOL bSign)

{
	PGPContextRef context;
	PRECIPIENTDIALOGSTRUCT prds;
	MYSTATE *ms;
	char comment[80];
	PGPUInt32 PrefAlg;
	PGPCipherAlgorithm allowedAlgs[20];
	int nNumAlgs;
	PGPtlsContextRef tls;
	PGPError err;
	char StrRes[500];

	err=kPGPError_NoErr;

	context=(PGPContextRef)PGPsc;
	tls=(PGPtlsContextRef)PGPtls;

	if(IsPGPError(PGPclEvalExpired(hwnd, PGPCL_ENCRYPTSIGNEXPIRED)))
		return FALSE;

	if(!GetCommentLine(context,comment,sizeof(comment),&PrefAlg,
		allowedAlgs, &nNumAlgs))
		return FALSE;

	prds=(PRECIPIENTDIALOGSTRUCT)
		malloc(sizeof(RECIPIENTDIALOGSTRUCT));

	if(prds)
	{
		memset(prds,0x00,sizeof(RECIPIENTDIALOGSTRUCT));

		LoadString (g_hinst, IDS_PGPKEYSELDLG, StrRes, sizeof(StrRes));

		prds->szTitle=StrRes;
		prds->dwDisableFlags=PGPCL_DISABLE_AUTOMODE;
		prds->dwOptions=PGPCL_DETACHEDSIG;

		ms=(MYSTATE *)malloc(sizeof(MYSTATE));

		if(ms)
		{
			memset(ms, 0x00, sizeof(MYSTATE) );

			ms->context=context;
			ms->tlsContext=tls;
			ms->ListHead=ListHead;
			ms->Operation=MS_ENCRYPTFILELIST;
			ms->prds=prds;
			ms->Encrypt=bEncrypt; 
			ms->Sign=bSign;
			ms->comment=comment;
			ms->PrefAlg=PrefAlg;
			ms->allowedAlgs=allowedAlgs; 
			ms->nNumAlgs=nNumAlgs;
			ms->szAppName=szApp;

			if(OpenRings(hwnd,context,&(ms->KeySet)))
			{
				err=SCProgressDialog(hwnd,DoWorkThread,ms,
						  0,"Encoding File(s)...",
						  "","",IDR_PROGAVI);

				if(prds->SelectedKeySetRef)
					PGPFreeKeySet(prds->SelectedKeySetRef);

				FreePhrases(ms);

				PGPFreeKeySet(ms->KeySet);
			}
			free(ms);
		}
		free(prds);
	}
	
	FreeFileList(ListHead);

	if(IsPGPError(err))
		return FALSE;

	return TRUE;
}

BOOL WeNeedToWordWrap(PGPContextRef context,
					  unsigned short* WordWrapThreshold)
{
	PGPPrefRef	PrefRefClient=NULL;
	PGPBoolean	bWrapReturn=TRUE;
	PGPUInt32	WrapWidth=72;
	PGPMemoryMgrRef memMgr;

	memMgr=PGPGetContextMemoryMgr(context);

	PGPclOpenClientPrefs (memMgr,&PrefRefClient);
	PGPGetPrefBoolean (PrefRefClient,
		kPGPPrefWordWrapEnable, &bWrapReturn);
	PGPGetPrefNumber (PrefRefClient, 
		kPGPPrefWordWrapWidth, &WrapWidth);
	PGPclCloseClientPrefs (PrefRefClient, FALSE);

	*WordWrapThreshold=WrapWidth;

	return bWrapReturn;
}

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


BOOL WrapIfNecessary(PGPContextRef context,
					 char **pszClipText,DWORD *dwClipSize)
{
	unsigned short WordWrapThreshold;
	char* szWrappedText;
	DWORD dwWrappedSize;

	if(WeNeedToWordWrap(context,&WordWrapThreshold))
	{
		if(TRUE == WrapBuffer(&szWrappedText, 
			*pszClipText,WordWrapThreshold))
		{	
			dwWrappedSize = strlen(szWrappedText);

			memset(*pszClipText,0x00,*dwClipSize);
			free(*pszClipText);
			*pszClipText=szWrappedText;

			*dwClipSize=dwWrappedSize;
		}
	}

	return TRUE;
}

PGPError EncryptClipboardStub (MYSTATE *ms) 
{
	PGPOptionListRef opts;
	PGPContextRef context;
	PGPError err;
	char StrRes[100];

	err=kPGPError_NoErr;

	context=ms->context;

	PGPBuildOptionList(context,&opts,
		PGPOInputBuffer(context,ms->pInput,ms->dwInputSize),
		PGPOAllocatedOutputBuffer(context,
			&(ms->pOutput),MAX_BUFFER_SIZE ,&(ms->dwOutputSize)),
		PGPOLastOption(context));

	LoadString (g_hinst, IDS_CLIPBOARD, StrRes, sizeof(StrRes));

	err=GenericEncSign(ms,opts,StrRes);

	PGPFreeOptionList(opts);

	return err;
}

BOOL EncryptClipboard(HWND hwnd,char *szApp,void *PGPsc,void *PGPtls,BOOL Encrypt,BOOL Sign)
{
	PGPContextRef context;
	PRECIPIENTDIALOGSTRUCT prds;
	char *pInput;
	DWORD dwInputSize;
	UINT ClipboardFormat;
	char comment[80];
	PGPUInt32 PrefAlg;
	PGPCipherAlgorithm allowedAlgs[20];
	int nNumAlgs;
	MYSTATE *ms;
	PGPtlsContextRef tls;
	PGPError err;
	char StrRes[500];

	// Check for files copied into clipboard from explorer
	if(OpenClipboard(hwnd)) 
	{
		if(IsClipboardFormatAvailable(CF_HDROP))
		{
			FILELIST *ListHead;
			HDROP hDrop;

			hDrop=(HDROP)GetClipboardData(CF_HDROP);
			ListHead=HDropToFileList(hDrop);

			if(ListHead!=0)
			{
				CloseClipboard();

				return EncryptFileList(hwnd,szApp,
					 PGPsc,PGPtls,ListHead,
					 Encrypt,Sign);
			}
		}
		CloseClipboard();
	}

	err=kPGPError_NoErr;

	context=(PGPContextRef)PGPsc;
	tls=(PGPtlsContextRef)PGPtls;

	if(IsPGPError(PGPclEvalExpired(hwnd, PGPCL_ENCRYPTSIGNEXPIRED)))
		return FALSE;

	if(!GetCommentLine(context,comment,sizeof(comment),&PrefAlg,
		allowedAlgs, &nNumAlgs))
		return FALSE;

	pInput=RetrieveClipboardData(hwnd, &ClipboardFormat, 
			                     &dwInputSize);

	if(!pInput)
	{
		PGPscMessageBox (hwnd,IDS_PGPERROR,IDS_NOCLIPBOARDCONTENTS,
					MB_OK|MB_ICONSTOP);
	}
	else
	{
		if((ClipboardFormat != CF_TEXT)||(*pInput==0))
		{
			PGPscMessageBox (hwnd,IDS_PGPERROR,IDS_NOCLIPBOARDTEXT,
				MB_OK|MB_ICONSTOP);
		}
		else
		{
			WrapIfNecessary(context,&pInput,&dwInputSize);

			prds=(PRECIPIENTDIALOGSTRUCT)
				malloc(sizeof(RECIPIENTDIALOGSTRUCT));

			if(prds)
			{
				memset(prds,0x00,sizeof(RECIPIENTDIALOGSTRUCT));

				LoadString (g_hinst, IDS_PGPKEYSELDLG, StrRes, sizeof(StrRes));

				prds->szTitle=StrRes;
//BEGIN ARMOR SIGN CLIPBOARD - Disastry
                if (Encrypt)
//END ARMOR SIGN CLIPBOARD
				    prds->dwOptions=PGPCL_ASCIIARMOR;
				prds->dwDisableFlags=PGPCL_DISABLE_ASCIIARMOR |
					PGPCL_DISABLE_WIPEORIG |
					PGPCL_DISABLE_AUTOMODE;

				ms=(MYSTATE *)malloc(sizeof(MYSTATE));
	
				if(ms)
				{
					memset(ms, 0x00, sizeof(MYSTATE) );

					ms->context=context;
					ms->tlsContext=tls;
					ms->pInput=pInput;
					ms->dwInputSize=dwInputSize;
					ms->Operation=MS_ENCRYPTCLIPBOARD;
					ms->prds=prds;
					ms->Encrypt=Encrypt; 
					ms->Sign=Sign;
					ms->comment=comment;
					ms->PrefAlg=PrefAlg;
					ms->allowedAlgs=allowedAlgs; 
					ms->nNumAlgs=nNumAlgs;
					ms->szAppName=szApp;

					if(OpenRings(hwnd,context,&(ms->KeySet)))
					{	
						err=SCProgressDialog(hwnd,DoWorkThread,ms,
							  0,"Encoding Clipboard...",
							  "","",IDR_PROGAVI);
	
						if(prds->SelectedKeySetRef)
							PGPFreeKeySet(prds->SelectedKeySetRef);

						FreePhrases(ms);
				
						if((ms->pOutput!=0) && (IsntPGPError(err)))
						{
							StoreClipboardData(hwnd, ms->pOutput, ms->dwOutputSize);
							memset(ms->pOutput,0x00,ms->dwOutputSize);
							PGPFreeData(ms->pOutput); // Since auto alloced by CDK
						}

						PGPFreeKeySet(ms->KeySet);
					}
					free(ms);
				}
				free(prds);
			}
		}
		memset(pInput,0x00,dwInputSize);
		free(pInput);
	}

	if(IsPGPError(err))
		return FALSE;

	return TRUE;
}


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
