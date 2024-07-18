/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.

	$Id: decrypt.c,v 1.101 1999/04/13 17:29:54 wjb Exp $
____________________________________________________________________________*/
#include "precomp.h"
//BEGIN REMOVE NON PGP BLOCKS DATA - Imad R. Faiad
PGPBoolean RemoveNonPGPBlocksData(PGPContextRef	context)
{
	PGPBoolean			b=FALSE;
	PGPPrefRef			prefRef = NULL;
	PGPError			err = kPGPError_NoErr;

	err = PGPclOpenClientPrefs(PGPGetContextMemoryMgr(context), &prefRef);

	if (IsntPGPError( err ))
			err = PGPGetPrefBoolean(prefRef, kPGPPrefRemoveNonPGPBlocksData, &b);
	PGPclCloseClientPrefs(prefRef, FALSE);

	return b;

}
//END REMOVE NON PGP BLOCKS DATA
PGPError GenericDecVer(MYSTATE *ms,
					PGPOptionListRef opts,
					char *OperationTarget)
{
	PGPError		err;
	PGPKeySetRef	AddKeySet;
	PGPUInt32		numKeys;
	PGPContextRef	context;
	//BEGIN REMOVE NON PGP BLOCKS DATA - Imad R. Faiad
	PGPBoolean		LeaveNonPGPBlocks;
	//END REMOVE NON PGP BLOCKS DATA

	err=kPGPError_NoErr;

	context=ms->context;

	// Use passphrase first if available
	if(ms->PassPhrase)
	{
		PGPAppendOptionList(opts,
			PGPOPassphraseBuffer(context,
				ms->PassPhrase, strlen(ms->PassPhrase) ),
			PGPOLastOption(context));
	}
	else if(ms->PassKey)
	{
		PGPAppendOptionList(opts,
			PGPOPasskeyBuffer(context,
				ms->PassKey,ms->PassKeyLen),
			PGPOLastOption(context));
	}

	ms->fileName=OperationTarget;
	strcpy((char *)ms->verifyName,ms->fileName);
	ms->fileRef=0;
	ms->PassCount=0;
	ms->RecipientKeySet=0;
	ms->RecipientKeyIDArray=0;
	ms->dwKeyIDCount=0;
	ms->obl=NULL;

	if(ms->Operation!=MS_DECRYPTCLIPBOARD)
		SCSetProgressNewFilename(ms->hPrgDlg,"From '%s' To '%s'",ms->fileName,TRUE);

	PGPNewKeySet( context, &AddKeySet);

	//BEGIN REMOVE NON PGP BLOCKS DATA - Imad R. Faiad

	if (ms->Operation==MS_DECRYPTCLIPBOARD)
		LeaveNonPGPBlocks = !RemoveNonPGPBlocksData(context);
	else
		LeaveNonPGPBlocks = FALSE;
	//END REMOVE NON PGP BLOCKS DATA

	err = PGPDecode( context, 
					opts,
					//BEGIN REMOVE NON PGP BLOCKS DATA - Imad R. Faiad
					//PGPOPassThroughIfUnrecognized(context,
					//	(PGPBoolean)(ms->Operation==MS_DECRYPTCLIPBOARD),
					PGPOPassThroughIfUnrecognized(context,LeaveNonPGPBlocks),
					//END REMOVE NON PGP BLOCKS DATA
					PGPOKeySetRef(context,ms->KeySet),
					PGPOEventHandler(context,myEvents, ms),
					PGPOImportKeysTo(context,AddKeySet),
					PGPOSendNullEvents(context,75),
					PGPOLastOption(context) );

	SCSetProgressBar(ms->hPrgDlg,100,TRUE);

	(void)PGPCountKeys( AddKeySet, &numKeys );
	if ( numKeys > 0) 
	{	
		PGPclQueryAddKeys (context,ms->tlsContext,ms->hwndWorking,AddKeySet,NULL);
	}
	PGPFreeKeySet (AddKeySet);

	if(PGPRefIsValid(ms->AddedKeys))
	{
		(void)PGPCountKeys( ms->AddedKeys, &numKeys );
		if ( numKeys > 0) 
		{	
			PGPclQueryAddKeys (context,ms->tlsContext,ms->hwndWorking,ms->AddedKeys,NULL);
		}
		PGPFreeKeySet (ms->AddedKeys);
	}

	if(ms->RecipientKeySet)
		PGPFreeKeySet(ms->RecipientKeySet);

	if(ms->RecipientKeyIDArray)
		free(ms->RecipientKeyIDArray);

	return err;
}

PGPError DecryptShareFile (MYSTATE *ms,char *szFile)
{
	PFLFileSpecRef		fileref;
	PGPShareFileRef		sharefileref;
	PGPOptionListRef	optionsDecode;
	PGPOptionListRef	optionsEncode;
	PGPShareRef			shares;
	PGPError			err;
	PGPMemoryMgrRef		memoryMgr;
	BOOL				UserCancel;
	PGPContextRef		context;
	RECIPIENTDIALOGSTRUCT rds;
	PRECIPIENTDIALOGSTRUCT prds=&rds;
	PGPUInt32			numKeys;
	char				StrRes[500];

	err=kPGPError_NoErr;

	context=ms->context;

	memoryMgr = PGPGetContextMemoryMgr(context);

	SCSetProgressNewFilename(ms->hPrgDlg,"From '%s' To '%s'",szFile,TRUE);

	LoadString (g_hinst, IDS_SHAREFILEINFO, StrRes, sizeof(StrRes));

	MessageBox(ms->hwndWorking,StrRes,
		JustFile(szFile),MB_OK|MB_ICONINFORMATION|MB_SETFOREGROUND);

	err = PFLNewFileSpecFromFullPath(memoryMgr, szFile, &fileref);

	if(IsntPGPError(err))
	{
		err = PGPOpenShareFile (fileref, &sharefileref);
	
		if(IsntPGPError(err))
		{
			ms->PassCount=0;
			ms->RecipientKeySet=0;
			ms->RecipientKeyIDArray=0;
			ms->dwKeyIDCount=0;

			// decrypt specified share file
			PGPBuildOptionList (context, &optionsDecode,
				PGPOKeySetRef (context, ms->KeySet),
				PGPOEventHandler (context, myEvents, ms),
				PGPOLastOption (context));
	
			err = PGPCopySharesFromFile (context, sharefileref, 
				optionsDecode, &shares);
	
			if(PGPRefIsValid(ms->AddedKeys))
			{
				(void)PGPCountKeys( ms->AddedKeys, &numKeys );
				if ( numKeys > 0) 
				{	
					PGPclQueryAddKeys (context,ms->tlsContext,ms->hwndWorking,
						ms->AddedKeys,NULL);
				}
				PGPFreeKeySet (ms->AddedKeys);
			}

			if(IsntPGPError(err))
			{
				memset(prds,0x00,sizeof(RECIPIENTDIALOGSTRUCT));

				LoadString (g_hinst, IDS_SHARERDTITLE, StrRes, sizeof(StrRes));

				prds->Version=CurrentPGPrecipVersion;
				prds->hwndParent=ms->hwndWorking;
				prds->szTitle=StrRes;
				prds->Context=context;
				prds->tlsContext=ms->tlsContext;
				prds->OriginalKeySetRef=ms->KeySet;
				prds->dwOptions=PGPCL_PASSONLY;
				prds->dwDisableFlags=PGPCL_DISABLE_ASCIIARMOR |
					PGPCL_DISABLE_WIPEORIG |
					PGPCL_DISABLE_AUTOMODE |
					PGPCL_DISABLE_FYEO |
					PGPCL_DISABLE_SDA;

				UserCancel = !(PGPclRecipientDialog(prds));

				if(!UserCancel)
				{
					if(prds->dwOptions & PGPCL_PASSONLY)
					{
						LoadString (g_hinst, IDS_SHAREPASSPROMPT, StrRes, sizeof(StrRes));

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
							1,0,ms->tlsContext,NULL,NULL);

						if(!UserCancel)
						{
							PGPBuildOptionList( context, &optionsEncode,
								PGPOConventionalEncrypt( context,
								PGPOPassphrase( context, ms->ConvPassPhrase ),
								PGPOLastOption( context ) ),
								PGPOLastOption( context ) );
						}
					}
					else
					{
							PGPBuildOptionList( context, &optionsEncode,
								PGPOEncryptToKeySet(context,prds->SelectedKeySetRef),
								PGPOLastOption( context ) );
					}
				}

				if(UserCancel)
				{
					err=kPGPError_UserAbort;
				}
				else
				{
					err = PGPCopySharesToFile( context, sharefileref, 
						optionsEncode, shares );

					if(IsntPGPError(err))
					{
						err = PGPSaveShareFile( sharefileref );
					}

					PGPFreeOptionList(optionsEncode);
				}

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

				if(ms->ConvPassPhrase)
				{
					PGPclFreePhrase(ms->ConvPassPhrase);
					ms->ConvPassPhrase=NULL;
				}

				if(prds->SelectedKeySetRef)
					PGPFreeKeySet(prds->SelectedKeySetRef);

				PGPFreeShares (shares);
			}

		if(ms->RecipientKeySet)
			PGPFreeKeySet(ms->RecipientKeySet);

		if(ms->RecipientKeyIDArray)
			free(ms->RecipientKeyIDArray);

		PGPFreeOptionList(optionsDecode);
		PGPFreeShareFile (sharefileref);
		}
	PFLFreeFileSpec (fileref);
	}

	return err;
}

PGPError MacBinaryConversion(PGPFileSpecRef fileRef)
{
	PGPError err;
	PGPUInt32 macCreator,macTypeCode;
	PGPFileSpecRef deMacifiedFSpec;

	err=kPGPError_NoErr;

	deMacifiedFSpec=0;

	err=PGPMacBinaryToLocal(fileRef,
		&deMacifiedFSpec,
		&macCreator,&macTypeCode );

	if(deMacifiedFSpec)
		PGPFreeFileSpec(deMacifiedFSpec);

	return err;
}

PGPError DecryptFileListStub (MYSTATE *ms) 
{
	PGPContextRef context;
	PGPFileSpecRef inref;
	PGPOptionListRef opts;
	FILELIST *FileCurrent;
	PGPError err;

	err=kPGPError_NoErr;

	context=ms->context;

	FileCurrent=ms->ListHead;

	while(!(SCGetProgressCancel(ms->hPrgDlg))&&(FileCurrent!=0)&&(IsntPGPError(err)))
	{    
		if(FileCurrent->IsDirectory)
		{
			FileCurrent=FileCurrent->next;
			continue;
		}

		if(FileHasThisExtension(FileCurrent->name,"shf"))
		{
			err=DecryptShareFile(ms,FileCurrent->name);
		
			FileCurrent=FileCurrent->next;			
			continue;
		}

// events handler will ask for output file later...
		PGPNewFileSpecFromFullPath( context,
			FileCurrent->name, &inref);

		PGPBuildOptionList(context,&opts,
			PGPOInputFile(context,inref),
			PGPOLastOption(context) );

		err=GenericDecVer(ms,opts,FileCurrent->name);

		PGPFreeOptionList(opts);

		if((IsntPGPError(err))&&(ms->fileRef))
		{
			err=MacBinaryConversion(ms->fileRef);

			// Try it.. if it's not, go on
			//BEGIN TYPO FIX - Imad R. Faiad
			//if(err=kPGPError_NotMacBinary)
			if(err==kPGPError_NotMacBinary)
			//END TYPO FIX
				err=kPGPError_NoErr;

			PGPclEncDecErrorBox(ms->hwndWorking,err);
		}

		PGPFreeFileSpec(inref);

		if(ms->fileRef)
			PGPFreeFileSpec(ms->fileRef);

		FileCurrent=FileCurrent->next;				
	}

	return err;
}

BOOL DecryptFileList(HWND hwnd,char *szApp,void *PGPsc,void *PGPtls,FILELIST *ListHead)
{
	PGPContextRef context;
	MYSTATE *ms;
	PGPtlsContextRef tls;
	PGPError err;
	char *pOutput;
	DWORD dwOutputSize;
	BOOL FYEO;

	err=kPGPError_NoErr;

	context=(PGPContextRef)PGPsc;
	tls=(PGPtlsContextRef)PGPtls;

	if(IsPGPError(PGPclEvalExpired(hwnd, PGPCL_ALLEXPIRED)))
		return FALSE;

	ms=(MYSTATE *)malloc(sizeof(MYSTATE));

	if(ms)
	{
		memset(ms, 0x00, sizeof(MYSTATE) );

		ms->context=context;
		ms->tlsContext=tls;
		ms->ListHead=ListHead;
		ms->Operation=MS_DECRYPTFILELIST;
		ms->szAppName=szApp;

		if(OpenRings(hwnd,context,&(ms->KeySet)))
		{
			err=SCProgressDialog(hwnd,DoWorkThread,ms,
						  0,"Decoding File(s)...",
						  "","",IDR_DECRYPTAVI);

			FreePhrases(ms);

// If we found no PGP data, warn....
			if(!(ms->FoundPGPData))
				PGPscMessageBox (hwnd,IDS_PGPERROR,IDS_NOPGPINFOINFILE,
							MB_OK|MB_ICONEXCLAMATION);

			if(!ConcatOutBuffList(context,ms->obl,&pOutput,&dwOutputSize,&FYEO))
				PGPscMessageBox (hwnd,IDS_PGPERROR,IDS_OUTOFMEM,
							MB_OK|MB_ICONSTOP);

			if(pOutput)
			{
				if((IsntPGPError(err))&&(FYEO))
				{
					TempestViewer((void *)context,hwnd,pOutput,dwOutputSize,FYEO);
				}

				memset(pOutput,0x00,dwOutputSize);
				PGPFreeData(pOutput); // Since auto alloced by CDK
			}

			PGPFreeKeySet(ms->KeySet);
		}
		free(ms);
	}
	FreeFileList(ListHead);

	if(IsPGPError(err))
		return FALSE;

	return TRUE;
}

PGPError DecryptClipboardStub (MYSTATE *ms) 
{
	PGPOptionListRef opts;
	PGPContextRef context;
	PGPError err;
	char StrRes[500];

	err=kPGPError_NoErr;

	context=ms->context;

	PGPBuildOptionList(context,&opts,
		PGPOInputBuffer(context,ms->pInput,ms->dwInputSize),
		PGPOLastOption(context) );

	LoadString (g_hinst, IDS_CLIPBOARD, StrRes, sizeof(StrRes));

	err=GenericDecVer(ms,opts,StrRes);

	PGPFreeOptionList(opts);
	
	return err;
}

BOOL DecryptClipboard(HWND hwnd,char *szApp,void *PGPsc,void *PGPtls)
{
	PGPContextRef		context;
	MYSTATE *ms;
	char *pInput;
	DWORD dwInputSize;
	UINT ClipboardFormat;
	PGPtlsContextRef tls;
	PGPError err;
	char *pOutput;
	DWORD dwOutputSize;
	BOOL FYEO;

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

				return DecryptFileList(hwnd,szApp,
					PGPsc,PGPtls,ListHead);
			}
		}
		CloseClipboard();
	}

	err=kPGPError_NoErr;

	context=(PGPContextRef)PGPsc;
	tls=(PGPtlsContextRef)PGPtls;

	if(IsPGPError(PGPclEvalExpired(hwnd, PGPCL_ALLEXPIRED)))
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
			ms=(MYSTATE *)malloc(sizeof(MYSTATE));

			if(ms)
			{
				memset(ms, 0x00, sizeof(MYSTATE) );

				ms->context=context;
				ms->tlsContext=tls;
				ms->pInput=pInput;
				ms->dwInputSize=dwInputSize;
				ms->Operation=MS_DECRYPTCLIPBOARD;
				ms->szAppName=szApp;

				if(OpenRings(hwnd,context,&(ms->KeySet)))
				{
					err=SCProgressDialog(hwnd,DoWorkThread,ms,
						  0,"Decoding Clipboard...",
						  "","",IDR_DECRYPTAVI);

					FreePhrases(ms);

// If no PGP data in clipboard, warn....
					if(!(ms->FoundPGPData))
						PGPscMessageBox (hwnd,IDS_PGPERROR,IDS_NOPGPINFOCLIPBOARD,
							MB_OK|MB_ICONEXCLAMATION);

					if(!ConcatOutBuffList(context,ms->obl,&pOutput,&dwOutputSize,&FYEO))
						PGPscMessageBox (hwnd,IDS_PGPERROR,IDS_OUTOFMEM,
							MB_OK|MB_ICONSTOP);

					if(pOutput)
					{
						if(IsntPGPError(err))
						{
							if((FYEO)||(GetSecureViewerPref(context)))
							{
								TempestViewer((void *)context,hwnd,pOutput,dwOutputSize,FYEO);
							}
							else
							{
								TextViewer(hwnd,pOutput,dwOutputSize);
							}
						}

						memset(pOutput,0x00,dwOutputSize);
						PGPFreeData(pOutput); 
					}

					PGPFreeKeySet(ms->KeySet);
				}
				free(ms);			
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
