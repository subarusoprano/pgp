/*____________________________________________________________________________
	Copyright (C) 2000 Pretty Good Privacy, Inc.
	All rights reserved.
	

	$Id: PgpHandling.c,v 1.13.6.2.2.11 2000/08/09 01:23:08 build Exp $
____________________________________________________________________________*/

/*::: MODULE OVERVIEW :::::::::::::
Purpose is to provide a staging area from which calls into regular PGP 
source code may be made. Customized to the needs of the Lotus Notes PGP 
Plug-In.

--- revision history --------
2/27/00 Version 1.1.2: Paul Ryan
+ adjustment to reconstruct the updated 6.5x-compatible version

9/26/99 Version 1.1.1: Paul Ryan
+ worked around minor bug in PGP client code (see ei_FindAndDecodePgpBlock() 
  for details)

9/12/99 Version 1.1: Paul Ryan
+ PGP 6.5.1 compatibility
+ logic enhancements
+ documentation updates

12/18/98 Version 1.0: Paul Ryan
::::::::::::::::::::::::::::::::::::*/

#include "PgpHandling.h"


//global-scope declarations
char  epc_APPNM[] = "PGP Notes Plug-In";
const int  ei_USER_ABORT = kPGPError_UserAbort;

HWND  eh_mainWnd;


//module-scope declarations
static char  mpc_PLUGIN_APP[] = "Notes", 
				mpc_MODULENM[] = "nPGPNts.dll";

static PGPContextRef  m_pgpContext;
static PGPtlsContextRef  m_pgpTlsContext;
static UINT  mui_hPurgeCacheMsg;


/** ei_InitializePgpContext( ***
Purpose is to set up the ability for this DLL to make calls into the PGP SDK 
and related functionality.

--- return -------------
RETURN: kPGPError_NoErr if no error occurred; a PGP error code otherwise.

--- revision history ---
2/27/00 PR: adjustment to support determination of an R4 client's main 
	window upon the opening of the client (due to involvement of extension 
	manager or NSF Hook driver)
9/12/99 PR: documentation adjustment
11/23/98 PR: created		*/
PGPError ei_InitializePgpContext()	{
	const char  pc_CLASSNM_NOTES[] = "NOTES", 
				pc_CLASSNM_NOTES_FRAME[] = "NOTESframe";

	HWND  h;
	char pc[ sizeof( pc_CLASSNM_NOTES_FRAME) > sizeof( pc_CLASSNM_NOTES) ? 
											sizeof( pc_CLASSNM_NOTES_FRAME) : 
											sizeof( pc_CLASSNM_NOTES)];
	PGPError  i_err;

	//if the PGP environment has already been loaded, don't do it again
	if (m_pgpContext)
		return kPGPError_NoErr;

	//create a new PGP context to use in this DLL
	if (IsPGPError( i_err = PGPNewContext( kPGPsdkAPIVersion, 
														&m_pgpContext)))	{
		if (i_err == kPGPError_FeatureNotAvailable)	{
			const char pc_EXPIRED_MSG[] = "The evaluation period for PGP "
									"has passed.\nThe Lotus Notes Plug-In "
									"will no longer function.", 
						pc_EXPIRED_TITLE[] = "PGP Plug-In Expired";

			MessageBox( eh_mainWnd, pc_EXPIRED_MSG, pc_EXPIRED_TITLE, MB_OK);
		}else
			PGPclErrorBox( eh_mainWnd, i_err);

		return i_err;
	} //if (IsPGPError(

	//initialize the Common Libraries
    if (IsPGPError( i_err = PGPclInitLibrary( m_pgpContext)))	{
        PGPclErrorBox( eh_mainWnd, i_err);
 
        return !kPGPError_NoErr;
    }

	//if this "beta" has expired, return failure
	if (PGPclIsExpired( NULL))
		return !kPGPError_NoErr;

	PGPNewTLSContext( m_pgpContext, &m_pgpTlsContext);

	//register the message to be sent when the passphrase cache should be 
	//	purged
	mui_hPurgeCacheMsg = RegisterWindowMessage( PURGEPASSPHRASECACEHMSG);

	//Store the handle of the main window associated with the rich-text 
	//	window currently being operated on by user. Loop is used because 
	//	the different releases of Notes have different window hierarchies.
	if (h = GetFocus())
		do
			if (GetClassName( h, pc, sizeof( pc)))
				if (strcmp( pc, pc_CLASSNM_NOTES) == ei_SAME || strcmp( 
								pc, pc_CLASSNM_NOTES_FRAME) == ei_SAME)	{
					eh_mainWnd = h;
					break;
				}
		while (h = GetParent( h));

	return kPGPError_NoErr;
} //ei_InitializePgpContext(


/** ei_PgpEncodeBuffer( ***


--- parameters & return ----


--- revision history -------
12/10/98 PR: created		*/
//DOC!!
PGPError ei_PgpEncodeBuffer( char *const  PC, 
								const DWORD  ul_LEN, 
								PgpEncodeContext *const  pt_context, 
								const BOOL  f_BINARY, 
								long *const  pl_lenOutput, 
								char * *const  ppc_output)	{
	PgpBasicInput  t_basics;
	long  l_lenOutput;
	PGPError  i_err;

	if (!( PC && pt_context && (pt_context->f_Sign || 
										pt_context->f_Encrypt) && ppc_output))
		return !kPGPError_NoErr;

	if (pl_lenOutput)
		*pl_lenOutput = (DWORD) NULL;
	*ppc_output = NULL;

	//fill in a structure of basic information used by PGP functions 
	//	downstream
	t_basics.h_Instance = eh_Instance;
	t_basics.h_wndMain = eh_mainWnd;
//t_basics.h_wndMain = NULL;
	t_basics.pgpContext = m_pgpContext;
	t_basics.pgpTlsContext = m_pgpTlsContext;
	t_basics.pc_AppNm = mpc_PLUGIN_APP;
	t_basics.pc_ModuleNm = mpc_MODULENM;

	i_err = i_EncryptSignBuffer( &t_basics, PC, ul_LEN, 
									&pt_context->t_recipients, NULL, 
									&pt_context->pgpUserOptions, ppc_output, 
									&l_lenOutput, pt_context->f_Encrypt, 
									pt_context->f_Sign, f_BINARY);

	if (pl_lenOutput)
		*pl_lenOutput = l_lenOutput;

	return i_err;
} //ei_PgpEncodeBuffer(


/** i_EncryptSignBuffer( ***
Purpose is to emulate the shared function EncryptSignBuffer, adding the 
option of encoding signed-only binary content with ASCII-Armor. If this 
option is not specified, the decoding stage for some reason throws an error, 
although the signature does work properly.

--- parameters & return ----

RETURN: 

--- revision history -------
12/14/98 PR: created		*/
//DOC!!
static PGPError i_EncryptSignBuffer( const PgpBasicInput *const  pt_BASICS, 
										void * pInput, 
										DWORD  dwInSize, 
										RECIPIENTDIALOGSTRUCT *const  prds,
										PGPOptionListRef  mimeOptions,
										PGPOptionListRef * pPreserveOptions,
										void * * ppOutput, 
										PGPSize * pOutSize, 
										BOOL  bEncrypt, 
										BOOL  bSign, 
										BOOL  bBinary)	{
	PGPContextRef  pgpContext;
	PGPError  i_err = kPGPError_NoErr;
	PGPMemoryMgrRef  memoryMgr;
	PGPOptionListRef  options = NULL;
	void * pFinalInput = NULL;
	long  lWrapWidth = 0;
	BOOL  bInputWrapped	= FALSE;

	PGPValidateParam( pInput && prds && prds->OriginalKeySetRef && 
									pPreserveOptions && ppOutput && pOutSize && 
									pt_BASICS && (pgpContext = 
									pt_BASICS->pgpContext));

	memoryMgr = PGPGetContextMemoryMgr( pgpContext);
	pFinalInput = pInput;

	if (!bBinary)
		if (ByDefaultWordWrap( memoryMgr, &lWrapWidth))	{
			pFinalInput = NULL;
			bInputWrapped = WrapBuffer( (char **) &pFinalInput, 
										(char *) pInput, (short) lWrapWidth);
			dwInSize = strlen( (char *) pFinalInput);
		}

	if (IsPGPError( i_err = PGPBuildOptionList( pgpContext, &options, 
									PGPOInputBuffer( pgpContext, pFinalInput, 
									dwInSize), PGPOAllocatedOutputBuffer( 
									pgpContext, ppOutput, INT_MAX, pOutSize),
									PGPOLastOption( pgpContext))))	{
		DisplayPgpError( __FILE__, __LINE__, pt_BASICS->pc_ModuleNm, i_err);
		goto errJump;
	}

	i_err = i_EncryptSign( pt_BASICS, prds, options, mimeOptions, 
													pPreserveOptions, 
													bEncrypt, bSign, bBinary);

errJump:
	if (bInputWrapped)
		free( pFinalInput);
	if (options)
		PGPFreeOptionList( options);

	return i_err;
} //i_EncryptSignBuffer(


/** i_EncryptSign( ***
Purpose is to 

--- parameters & return ----

RETURN: 

--- revision history -------
2/27/00 PR: decommissioned "SendMessage" workaround for the PGP 6.0x problem 
	(fixed in PGP 6.5) with the destruction of the progress dialog, a 
	workaround which itself began with Notes R5 to cause an invalid-pointer 
	error when closing Notes
9/12/99 PR: fixed bug of not preserving encryption keys between 
	successive discrete encoding runs throughout one entire encoding "job"
12/14/98 PR: created		*/
//DOC!!
static PGPError i_EncryptSign( const PgpBasicInput *const  pt_BASICS,
								 RECIPIENTDIALOGSTRUCT * prds,
								 PGPOptionListRef  ioOptions,
								 PGPOptionListRef  mimeOptions,
								 PGPOptionListRef * pPreserveOptions,
								 BOOL  bEncrypt, 
								 BOOL  bSign, 
								 BOOL  bBinary)	{
	PGPError  i_err = kPGPError_NoErr;
	PGPMemoryMgrRef		memoryMgr		= NULL;
	PGPKeyRef			signKey			= NULL;
	PGPKeySetRef		pubKeySet		= NULL;
	PGPKeySetRef		addedKeys		= NULL;
	PGPKeySetRef		recipKeySet		= NULL;
	PGPOptionListRef	options			= NULL;
	PGPOptionListRef	tempOptions		= NULL;
	PGPCipherAlgorithm  prefAlg			= kPGPCipherAlgorithm_CAST5;
	PGPCipherAlgorithm	allowedAlgs[8];
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
	PGPContextRef  pgpContext = pt_BASICS->pgpContext;

	UpdateWindow( pt_BASICS->h_wndMain);
	memoryMgr = PGPGetContextMemoryMgr( pgpContext);

	// Check for demo expiration
	if (PGPclEvalExpired( pt_BASICS->h_wndMain, PGPCL_ENCRYPTSIGNEXPIRED) != 
															kPGPError_NoErr)
		return kPGPError_UserAbort;

	pubKeySet = prds->OriginalKeySetRef;
	
	i_err = PGPGetDefaultPrivateKey( pubKeySet, &signKey);
	if (IsPGPError( i_err))	{
		PGPKeyListRef	pubKeyList = NULL;
		PGPKeyIterRef	pubKeyIter = NULL;
		
		PGPOrderKeySet(pubKeySet, kPGPTrustOrdering, &pubKeyList);
		PGPNewKeyIter(pubKeyList, &pubKeyIter);
		PGPKeyIterNext(pubKeyIter, &signKey);
		PGPFreeKeyIter(pubKeyIter);
		PGPFreeKeyList(pubKeyList);

		i_err = kPGPError_NoErr;
	} //if (IsPGPError( i_err)

	i_err = kPGPError_BadPassphrase;
	while (i_err == kPGPError_BadPassphrase)	{
		PGPBoolean  f_JustInitializedPreservedOptions = FALSE;

		if (IsntNull(szPassphrase))	{
			PGPclFreeCachedPhrase(szPassphrase);
			szPassphrase = NULL;
		}

		if (IsntNull(szConvPass))	{
			PGPclFreePhrase(szConvPass);
			szConvPass = NULL;
		}

		if (IsNull( mimeOptions))
			i_err = PGPBuildOptionList( pgpContext, &options, 
												PGPOLastOption( pgpContext));
		else
			i_err = PGPBuildOptionList( pgpContext, &options, mimeOptions,
												PGPOLastOption( pgpContext));

		if (IsPGPError(i_err))	{
			DisplayPgpError(__FILE__, __LINE__, pt_BASICS->pc_ModuleNm, 
																	i_err);
			goto errJump;
		}

		if (GetCommentString( memoryMgr, szComment, 254))	{
			i_err = PGPBuildOptionList( pgpContext, &tempOptions, options,
									PGPOCommentString( pgpContext, 
									szComment), PGPOLastOption( pgpContext));
			
			if (IsPGPError(i_err))	{
				DisplayPgpError(__FILE__, __LINE__, pt_BASICS->pc_ModuleNm, 
																	i_err);
				goto errJump;
			}

			PGPFreeOptionList( options);
			options = tempOptions;
		} //if (GetCommentString( memoryMgr, szComment

		//If this is a buffer of binary data and it just needs to be signed, 
		//	have it encoded with ASCII Armor. In adding this option to our 
		//	job, we employ a temporary storage mechanism to get around a 
		//	memory-leak problem in the PGP SDK that occurs when appending 
		//	options directly to the current options variable (opaque). Or at 
		//	least, that's my interpretation I've arrived at through trial & 
		//	error testing.
		if (bBinary && bSign && !bEncrypt)	{
			if (IsPGPError( i_err = PGPBuildOptionList( pgpContext, 
										&tempOptions, options, 
										PGPOArmorOutput( pgpContext, TRUE), 
										PGPOLastOption( pgpContext))))	{
				DisplayPgpError( __FILE__, __LINE__, pt_BASICS->pc_ModuleNm, 
																	i_err);
				goto errJump;
			}
			PGPFreeOptionList( options);
			options = tempOptions;
		} //if (bBinary && bSign && !bEncrypt)

		if (bEncrypt)	{
			if (prds->dwOptions & PGPCL_ASCIIARMOR)	{
				i_err = PGPBuildOptionList( pgpContext, &tempOptions,
						PGPOArmorOutput( pgpContext, TRUE),
						options,
						PGPOLastOption( pgpContext));

				if (IsPGPError( i_err))	{
					DisplayPgpError( __FILE__, __LINE__, 
											pt_BASICS->pc_ModuleNm, i_err);
					goto errJump;
				}

				PGPFreeOptionList(options);
				options = tempOptions;
			} //if (prds->dwOptions & PGPCL_ASCIIARMOR)

			//the "preserve" options are used to pass consistent options 
			//	between successive discrete encodings required in carrying 
			//	out a "single" encoding job for the user (e.g. an e-mail with 
			//	attachments)
			if (IsNull( *pPreserveOptions))	{
				if (prds->dwOptions & PGPCL_PASSONLY)	{
					if (!bGotConvPass)	{
						char szPrompt[256];

						LoadString( pt_BASICS->h_Instance, 
												IDS_CONVPASSPHRASE, 
												szPrompt, sizeof( szPrompt));

						i_err = PGPclGetPhrase( pgpContext, pubKeySet, 
											pt_BASICS->h_wndMain, szPrompt, 
											&szConvPass, NULL, NULL, 0, 
											NULL, NULL, PGPCL_ENCRYPTION, 
											NULL, NULL, 1, 0, NULL, NULL, 
											NULL);

						// wjb changed to 1 for min passphrase length
						if (i_err == kPGPError_UserAbort)
							goto errJump;
						
						nConvPassLen = strlen(szConvPass);
						bGotConvPass = TRUE;
					} //if (prds->dwOptions & PGPCL_PASSONLY)
					
					GetPreferredAlgorithm(memoryMgr, &prefAlg);

					i_err = PGPBuildOptionList( pgpContext, 
								pPreserveOptions,
								PGPOConventionalEncrypt( pgpContext,
									PGPOPassphraseBuffer( pgpContext,
										szConvPass, 
										nConvPassLen),
									PGPOLastOption( pgpContext)),
								PGPOCipherAlgorithm( pgpContext, prefAlg),
								PGPOLastOption( pgpContext));

					if (IsPGPError( i_err))	{
						DisplayPgpError( __FILE__, __LINE__, 
											pt_BASICS->pc_ModuleNm, i_err);
						goto errJump;
					}
				}else	{
					GetAllowedAlgorithms( memoryMgr, allowedAlgs, &nNumAlgs);
					recipKeySet = prds->SelectedKeySetRef;

					i_err = PGPBuildOptionList( pgpContext, 
								pPreserveOptions, PGPOPreferredAlgorithms( 
								pgpContext, allowedAlgs, nNumAlgs),
								PGPOEncryptToKeySet( pgpContext, 
								recipKeySet), PGPOFailBelowValidity( 
								pgpContext, kPGPValidity_Unknown), 
								PGPOWarnBelowValidity( pgpContext, 
								kPGPValidity_Unknown),
								PGPOLastOption( pgpContext));

					if (IsPGPError( i_err))	{
						DisplayPgpError( __FILE__, __LINE__, 
											pt_BASICS->pc_ModuleNm, i_err);
						goto errJump;
					}
				} //if (prds->dwOptions & PGPCL_PASSONLY)
			
				f_JustInitializedPreservedOptions = TRUE;
			} //if (IsNull( *pPreserveOptions)
		} //if (bEncrypt)
		
		if (bSign)	{
			if (IsNull( *pPreserveOptions) || 
										f_JustInitializedPreservedOptions)	{
				char szPrompt[256];

				f_JustInitializedPreservedOptions = FALSE;
				if (IsNull( *pPreserveOptions))
					i_err = PGPBuildOptionList( pgpContext, 
												pPreserveOptions, 
												PGPOLastOption( pgpContext));

				if (bGotPassphrase)
					LoadString(pt_BASICS->h_Instance, IDS_PASSPHRASEREENTER, 
												szPrompt, sizeof(szPrompt));
				else
					LoadString(pt_BASICS->h_Instance, IDS_PASSPHRASEPROMPT, 
												szPrompt, sizeof(szPrompt));
				
				i_err = PGPclGetCachedSigningPhrase( pgpContext, 
									pt_BASICS->pgpTlsContext, 
									pt_BASICS->h_wndMain, szPrompt, 
									bGotPassphrase, &szPassphrase, pubKeySet, 
									&signKey, NULL, NULL, prds->dwFlags,
									&pPasskey, &nPasskeyLength, &addedKeys, 
									NULL);
				if (addedKeys != NULL)	{
					PGPUInt32 numKeys;

					PGPCountKeys(addedKeys, &numKeys);
					if (numKeys > 0)
						PGPclQueryAddKeys(pgpContext, 
													pt_BASICS->pgpTlsContext, 
													pt_BASICS->h_wndMain, 
													addedKeys, NULL);

					PGPFreeKeySet(addedKeys);
					addedKeys = NULL;
				}
				if (IsPGPError(i_err))	{
					if (i_err != kPGPError_UserAbort)
						DisplayPgpError(__FILE__, __LINE__, 
											pt_BASICS->pc_ModuleNm, i_err);
					goto errJump;
				}
				
				bGotPassphrase = TRUE;
				if (IsntNull( szPassphrase))	{
					nPassphraseLen = strlen( szPassphrase);
				
					i_err = PGPBuildOptionList( pgpContext, &tempOptions, 
								*pPreserveOptions,
								PGPOSignWithKey( pgpContext, 
									signKey, 
									PGPOPassphraseBuffer( pgpContext,
										szPassphrase, 
										nPassphraseLen),
									PGPOLastOption( pgpContext)),
								PGPOLastOption( pgpContext));
				}else if (IsntNull( pPasskey))	{
					i_err = PGPBuildOptionList( pgpContext, &tempOptions, 
								*pPreserveOptions,
								PGPOSignWithKey( pgpContext, 
									signKey, 
									PGPOPasskeyBuffer( pgpContext,
										pPasskey, 
										nPasskeyLength),
									PGPOLastOption( pgpContext)),
								PGPOLastOption( pgpContext));
				} //if (IsntNull( szPassphrase)
				
				if (IsPGPError(i_err))	{
					if (i_err != kPGPError_UserAbort)
						DisplayPgpError( __FILE__, __LINE__, 
											pt_BASICS->pc_ModuleNm, i_err);
					goto errJump;
				}

				PGPFreeOptionList( *pPreserveOptions);
				*pPreserveOptions = tempOptions;
			} //if (IsNull( *pPreserveOptions) || 

			i_err = PGPBuildOptionList( pgpContext, &tempOptions, options,
								PGPOClearSign( pgpContext, 
									(PGPBoolean) (!bEncrypt && !bBinary)),
								PGPOLastOption( pgpContext));
			
			if (IsPGPError( i_err))	{
				if (i_err != kPGPError_UserAbort)
					DisplayPgpError( __FILE__, __LINE__, 
											pt_BASICS->pc_ModuleNm, i_err);
				goto errJump;
			}

			PGPFreeOptionList(options);
			options = tempOptions;
		} //if (bSign)

		if (bEncrypt && !bSign)
			LoadString( pt_BASICS->h_Instance, IDS_WORKINGENCRYPT, 
									szWorkingTitle, sizeof( szWorkingTitle));
		else if (!bEncrypt && bSign)
			LoadString( pt_BASICS->h_Instance, IDS_WORKINGSIGN, 
									szWorkingTitle, sizeof( szWorkingTitle));
		else
			LoadString( pt_BASICS->h_Instance, IDS_WORKINGENCRYPTSIGN, 
									szWorkingTitle, sizeof( szWorkingTitle));

		hwndWorking = WorkingDlgProcThread( GetModuleHandle( 
							pt_BASICS->pc_ModuleNm), pt_BASICS->h_Instance, 
							NULL, szWorkingTitle, "");

		if (IsNull( *pPreserveOptions))
			PGPBuildOptionList( pgpContext, pPreserveOptions, 
				PGPOLastOption( pgpContext));

		i_err = PGPEncode( pgpContext,
				ioOptions,
				PGPOEventHandler( pgpContext, EncodeEventHandler, 
				hwndWorking), options,
				*pPreserveOptions,
				PGPOSendNullEvents( pgpContext, 100),
				PGPODataIsASCII( pgpContext, (PGPBoolean) !bBinary),
				PGPOVersionString( pgpContext, pgpVersionHeaderString),
				PGPOAskUserForEntropy( pgpContext, TRUE),
				PGPOForYourEyesOnly( pgpContext, (PGPBoolean)
							((prds->dwOptions & PGPCL_FYEO) == PGPCL_FYEO)),
				PGPOLastOption( pgpContext));

		if (hwndWorking)
			DestroyWindow(hwndWorking);

		if (options)	{
			PGPFreeOptionList(options);
			options = NULL;
		}

		if (i_err == kPGPError_BadPassphrase)	{
			PGPFreeOptionList(*pPreserveOptions);
			*pPreserveOptions = NULL;
		}
	} //while (i_err == kPGPError_BadPassphrase)

	if (IsPGPError(i_err) && (i_err != kPGPError_UserAbort))	{
		DisplayPgpError( __FILE__, __LINE__, pt_BASICS->pc_ModuleNm, i_err);
		goto errJump;
	}

errJump:
	if (szPassphrase) {
		PGPclFreeCachedPhrase( szPassphrase);
		szPassphrase = NULL;
	}
	if (pPasskey)	{
		PGPFreeData(pPasskey);
		pPasskey = NULL;
	}
	if (szConvPass)	{
		PGPclFreePhrase(szConvPass);
		szConvPass = NULL;
	}
	if (options)
		PGPFreeOptionList(options);

	return i_err;
} //i_EncryptSign(


/** ei_PgpEncodeFile( ***


--- parameters & return ----

RETURN: 

--- revision history -------
12/15/98 PR: created		*/
//DOC!!
PGPError ei_PgpEncodeFile( PgpEncodeContext *const  pt_context, 
							char *const  pc_EXTFILENM_ORIG, 
							char *const  pc_EXTFILENM_NEW)	{
	if (!( pt_context && (pt_context->f_Sign || pt_context->f_Encrypt) && 
									pc_EXTFILENM_ORIG && pc_EXTFILENM_NEW))
		return !kPGPError_NoErr;

//return EncryptSignFile( eh_Instance, /*eh_mainWnd*/ NULL, m_pgpContext, 
	return EncryptSignFile( eh_Instance, eh_mainWnd, m_pgpContext, 
									m_pgpTlsContext, mpc_PLUGIN_APP, 
									mpc_MODULENM, pc_EXTFILENM_ORIG, 
									&pt_context->t_recipients, NULL, 
									&pt_context->pgpUserOptions, 
									pc_EXTFILENM_NEW, pt_context->f_Encrypt, 
									pt_context->f_Sign, TRUE);
} //ei_EncodeFile(


/** ei_SetUpPgpEncodeContext( ***
Purpose is to initialize a Notes Plug-In information structure for use in 
ensuing PGP encodings.

--- parameters & return ----
f_SIGN: flag telling whether content is to be signed when encoded
f_ENCRYPT: flag telling whether content is to be encrypted when encoded
pt_context: Input & Output. Pointer to the information structure used by the 
	Notes Plug-In to hold a common set of PGP contextual information through 
	the encoding process.
pf_SyncUnknownKeys: Output. Pointer to the variable in which to store whether 
	the user wishes PGP to attempt to find unknown keys via a search of 
	certificate servers listed in her preferences. Relevant only when 
	encryption is involved. Ignored if omitted.
RETURN: kPGPError_NoErr if successful; the PGP error code otherwise

--- revision history -------
9/12/99 PR
+ split out encryption-key resolution into ei_ResolveEncryptionKeys()
+ completed header documentation

12/7/98 PR: created			*/
PGPError ei_SetUpPgpEncodeContext( const BOOL  f_SIGN, 
									const BOOL  f_ENCRYPT, 
									PgpEncodeContext *const  pt_context, 
									BOOL *const  pf_SyncUnknownKeys)	{
	RECIPIENTDIALOGSTRUCT * pt_recipients;
	PGPMemoryMgrRef  t_memoryMgr;
	PGPPrefRef	pgpPreferences = NULL;
	PGPBoolean  f;
	PGPError  i_err;

	if (!( (f_SIGN || f_ENCRYPT) && pt_context))
		return !kPGPError_NoErr;

	memset( pt_context, (BYTE) NULL, sizeof( PgpEncodeContext));
	if (pf_SyncUnknownKeys)
		*pf_SyncUnknownKeys = FALSE;

	pt_context->pgpUserOptions = kPGPInvalidRef;

	if (IsPGPError( i_err = PGPsdkLoadDefaultPrefs( m_pgpContext)))	{
		PGPclEncDecErrorBox( eh_mainWnd, i_err);
		return i_err;
	}

	pt_recipients = &pt_context->t_recipients;
	if (IsPGPError( i_err = PGPOpenDefaultKeyRings( m_pgpContext, 
									kPGPKeyRingOpenFlags_Mutable, 
									&pt_recipients->OriginalKeySetRef)))	{
		PGPclEncDecErrorBox( eh_mainWnd, i_err);
		return i_err;
	}

	pt_context->f_Sign = f_SIGN;
	pt_context->f_Encrypt = f_ENCRYPT;

	if (!f_ENCRYPT)
		return kPGPError_NoErr;

	pt_recipients->Context = m_pgpContext;
	pt_recipients->tlsContext = m_pgpTlsContext;
	pt_recipients->Version = CurrentPGPrecipVersion;
	pt_recipients->hwndParent = eh_mainWnd;
	pt_recipients->dwOptions = PGPCL_ASCIIARMOR;	
	pt_recipients->dwDisableFlags = PGPCL_DISABLE_WIPEORIG |
													PGPCL_DISABLE_ASCIIARMOR;
	pt_recipients->AddedKeys = kInvalidPGPKeySetRef;

	//if necessary, determine whether the user has it set that keys not 
	//	located should be sought via certificate servers she's got specified
	if (pf_SyncUnknownKeys)	{
		t_memoryMgr = PGPGetContextMemoryMgr( m_pgpContext);
		if (i_err = PGPclOpenClientPrefs( t_memoryMgr, &pgpPreferences))
			return i_err;
		i_err = PGPGetPrefBoolean( pgpPreferences, 
											kPGPPrefKeyServerSyncUnknownKeys, 
											&f);
		if (IsntPGPError( i_err))
			*pf_SyncUnknownKeys = f;
		PGPclCloseClientPrefs( pgpPreferences, FALSE);
	} //if (pf_SyncUnknownKeys)

	return i_err;
} //ei_SetUpPgpEncodeContext(


/** ei_ResolveEncryptionKeys( ***
Purpose is to obtain, using the standard PGP client infrastructure, the 
list of encryption keys for use in ensuing encodings, based upon a set of 
e-mail addresses.

--- parameters & return ----
ppc_RECIPIENTS: pointer to a string-array list of the e-mail addresses to be 
	resolved to encryption keys
ui_RECIPIENTS: the number of e-mail addresses in the ppc_RECIPIENTS list
f_AMBIGUOUS: flag telling whether the recipients array contains addresses 
	that were derived via a prior address-resolution process which 
	encountered ambiguity vis-à-vis the input addresses and which reacted by 
	adding the ambiguous addresses to the resolved list and flipping an 
	"ambiguous" flag to notify downstream logic of the condition
pt_context: Input & Output. Pointer to the information structure used by the 
	Notes Plug-In to hold a common set of PGP contextual information through 
	the encoding process.
RETURN: kPGPError_NoErr if successful; the PGP error code otherwise

--- revision history -------
9/12/99 PR: created			*/
PGPError ei_ResolveEncryptionKeys( char * *const  ppc_RECIPIENTS, 
									const UINT  ui_RECIPIENTS, 
									const BOOL  f_AMBIGUOUS, 
									PgpEncodeContext *const  pt_context)	{
	char  pc_RECIPIENTS_DLG_TITLE[] = "PGP Notes - Encrypt Message To...";

	RECIPIENTDIALOGSTRUCT * pt_recipients;
	PGPKeySetRef  keysAdded;
	PGPUInt32  ul;
	PGPBoolean  f_aborted;

	PGPValidateParam( pt_context && pt_context->f_Encrypt && 
											ppc_RECIPIENTS && ui_RECIPIENTS);

	pt_recipients = &pt_context->t_recipients;
	pt_recipients->szTitle = pc_RECIPIENTS_DLG_TITLE;
	pt_recipients->dwNumRecipients = ui_RECIPIENTS;	
	pt_recipients->szRecipientArray = ppc_RECIPIENTS;

	//If the AddedKeys member seems to have been populated elsewhere, the 
	//	added keys are presumably keys pulled down from certificate servers. 
	//	Avoid looking up the keys again or prompting for an import before the 
	//	recipients dialog is shown by addinng the keys to the default set 
	//	(but not committing) and preserve a pointer to the keyset added so 
	//	the user may be prompted to import any keys once the recipients 
	//	dialog has been dismissed
	if ((keysAdded = pt_recipients->AddedKeys) != kInvalidPGPKeySetRef)	{
		pt_recipients->AddedKeys = kInvalidPGPKeySetRef;
		PGPCountKeys( keysAdded, &ul);
		if (ul)
			PGPAddKeys( keysAdded, pt_recipients->OriginalKeySetRef);
		else
			keysAdded = kInvalidPGPKeySetRef;
	} //if ((keysAdded

	//if ambiguity is involved in the recipients list or if <Ctrl> is 
	//	depressed, force the dialog to pop
	if (f_AMBIGUOUS || GetAsyncKeyState( VK_CONTROL) & 0x8000)
		pt_recipients->dwDisableFlags |= PGPCL_DISABLE_AUTOMODE;

	//see whom we wish to encrypt this to
	f_aborted = !PGPclRecipientDialog( pt_recipients);

	//allow the user to import any keys pulled down from certificate servers
	if (pt_recipients->AddedKeys != kInvalidPGPKeySetRef)
		if (keysAdded == kInvalidPGPKeySetRef)	{
			PGPCountKeys( keysAdded, &ul);
			if (ul)
				keysAdded = pt_recipients->AddedKeys;
		}else	{
			PGPAddKeys( pt_recipients->AddedKeys, keysAdded);
			pt_recipients->AddedKeys = kInvalidPGPKeySetRef;
		}
	if (keysAdded != kInvalidPGPKeySetRef)	{
		PGPclQueryAddKeys( pt_recipients->Context, pt_recipients->tlsContext, 
										pt_recipients->hwndParent, keysAdded, 
										pt_recipients->OriginalKeySetRef);

		PGPFreeKeySet( keysAdded);
	}

	return f_aborted ? kPGPError_UserAbort : kPGPError_NoErr;
} //ei_ResolveEncryptionKeys(


/** ef_FreePgpEncodeContext( ***
Purpose is to free PGP resources allocated for use in the encoding activities 
conducted by the Notes Plug-In.

--- parameter & return ----
pt_context: Input & Output. Pointer to the PGP contextual information used by 
	the Notes Plug-In in conducting content encodings. A successful run of 
	this procedure invalidates the information structure.
RETURN: TRUE if successful; FALSE if the pt_context pointer is obviously 
	invalid

--- revision history ------
9/12/99 PR: completed header documentation
12/15/98 PR: created			*/
PGPError ef_FreePgpEncodeContext( PgpEncodeContext *const  pt_context)	{
	RECIPIENTDIALOGSTRUCT * pt;

	if (!pt_context)
		return FALSE;

	if (PGPRefIsValid( pt_context->pgpUserOptions))
		PGPFreeOptionList( pt_context->pgpUserOptions);

	if ((pt = &pt_context->t_recipients)->SelectedKeySetRef != 
														kInvalidPGPKeySetRef)
		PGPFreeKeySet( pt->SelectedKeySetRef);
	if (pt->AddedKeys != kInvalidPGPKeySetRef)
		PGPFreeKeySet( pt->AddedKeys);
	PGPFreeKeySet( pt->OriginalKeySetRef);

	return TRUE;
} //ef_FreePgpEncodeContext(


/** ei_PgpDecodeBuffer( ***
Purpose is to conduct the PGP decoding (to ASCII or binary) of the specified 
null-terminated content string.

--- parameters & return ----
PC: pointer to the null-terminated input content to be decoded
f_BINARY: flag telling whether the PGP-encoded input should be decoded as 
	binary, not ASCII, output
ppc_output: Memory address of the pointer in which to store the address of 
	the memory buffer allocated to accommodate the null-terminated 
	PGP-decoded output. Caller is responsible for freeing this memory buffer. 
	In case of an error, the pointer is guaranteed to be null.
pul_lenOutput: Optional. Pointer to the variable in which to store the length 
	of the PGP-decoded output content. If passed in null, this functionality 
	will be ignored by the function.
RETURN: kPGPError_NoErr if no error occurred; a PGP error code otherwise.

--- revision history -------
2/27/00 PR: documentation improvement

9/12/99 PR
+ documentation adjustment wrt the decoding of binary content
+ minor logic enhancement

12/12/98 PR: created			*/
PGPError ei_PgpDecodeBuffer( const char *const  PC, 
								const BOOL  f_BINARY, 
								char * *const  ppc_output, 
								DWORD *const  pul_lenOutput)	{
	PgpBasicInput  t_basics;
	SpecialPlugInTaskInfo  t_task;
	BOOL  f_BinaryDecodeSuccessful;
	DWORD  ul_lenOutput;
	BOOL  f_dmy;
	PGPError  i_err;

	//if any of the passed-in parameters are invalid, short-circuit with 
	//	failure
	PGPValidateParam( PC && ppc_output);

	//fill in a structure of basic information used by PGP functions 
	//	downstream
	t_basics.h_Instance = eh_Instance;
//t_basics.h_wndMain = NULL;
	t_basics.h_wndMain = eh_mainWnd;
	t_basics.pgpContext = m_pgpContext;
	t_basics.pgpTlsContext = m_pgpTlsContext;
	t_basics.pc_AppNm = mpc_PLUGIN_APP;
	t_basics.pc_ModuleNm = mpc_MODULENM;

	if (f_BINARY)	{
		t_task.i_Task = mi_DECODE_BINARY;
		t_task.pf_Successful = &f_BinaryDecodeSuccessful;
	}else
		t_task.i_Task = mi_NO_TASK;

	//decode the input content
	i_err = i_DecryptVerifyBuffer( &t_basics, PC, strlen( PC), FALSE, 
													t_task, ppc_output, 
													&ul_lenOutput, &f_dmy);

	//If the content being decoded was binary and the decoding occurred 
	//	successfully, reset the "error" return to success. The "cancel" 
	//	return was used as a measure to short-circuit out of the decoding 
	//	process (to prevent unnecessary processing, I suppose, but it may be 
	//	a PGP bug workaround, I can't recall).
	if (t_task.i_Task == mi_DECODE_BINARY && f_BinaryDecodeSuccessful)	{
		_ASSERTE( i_err == kPGPError_UserAbort);
		i_err = kPGPError_NoErr;
	}

	//if requested, tell the caller the length of the PGP-decoded output 
	if (i_err == kPGPError_NoErr && pul_lenOutput)
		*pul_lenOutput = ul_lenOutput;

	return i_err;
} //ei_PgpDecodeBuffer(


/** e_FreePgpMem( ***
Purpose is to free memory objects allocated by PGP functions..

--- parameter ----------
puc: pointer to the memory object to free

--- revision history ---
11/25/98 PR: created		*/
void e_FreePgpMem( BYTE *const  puc)	{
	PGPFreeData( puc);
} //e_FreePgpMem(


/** e_ReleasePgpContext( ***
Purpose is to release all general resources involved with providing PGP 
functionality to this plug-in.

--- revision history -------
11/20/98 PR: created		*/
void e_ReleasePgpContext()	{
	PGPclPurgeCachedPassphrase( PGPCL_DECRYPTIONCACHE | PGPCL_SIGNINGCACHE);

	if (!PGPRefIsValid( m_pgpContext))
		return;

	PGPclCloseLibrary();
	PGPFreeTLSContext( m_pgpTlsContext);
	PGPFreeContext( m_pgpContext);
} //e_ReleasePgpContext(


/** ei_TestForPgpAscii( ***
Purpose is to carry out a test of whether PGP-encoded ASCII is present in the 
passed-in content.

--- parameters & return ----
PC: pointer to the content to be tested for PGP-encoded ASCII
pf_hasPgpAscii: Output. Pointer to the variable to set to indicate whether 
	PGP-encoded ASCII is present in the passed-in content.
RETURN: kPGPError_NoErr if no error occurred; a PGP error code otherwise.

--- revision history -------
9/12/99 PR: minor logic enhancement
11/23/98 PR: created		*/
PGPError ei_TestForPgpAscii( const char *const  PC, 
								BOOL *const  pf_hasPgpAscii)	{
	PgpBasicInput  t_basics;
	SpecialPlugInTaskInfo  t_task;
	BOOL  f_TestSuccessful;
	PGPError  i_err;

	//if any of the passed-in parameters are invalid, short-circuit with 
	//	failure
	PGPValidateParam( PC && pf_hasPgpAscii);
	
	//fill in a structure of basic information used by PGP functions 
	//	downstream
	t_basics.h_Instance = eh_Instance;
	t_basics.h_wndMain = eh_mainWnd;
	t_basics.pgpContext = m_pgpContext;
	t_basics.pgpTlsContext = m_pgpTlsContext;
	t_basics.pc_AppNm = mpc_PLUGIN_APP;
	t_basics.pc_ModuleNm = mpc_MODULENM;

	//fill in the structure of information describing the special task we 
	//	wish the PGP decoding mechanism to carry out
	t_task.i_Task = mi_TEST_FOR_PGP_ASCII;
	t_task.pv_return = pf_hasPgpAscii;
	t_task.pf_Successful = &f_TestSuccessful;

	//decode the input content while executing our special task
	i_err = i_DecryptVerifyBuffer( &t_basics, PC, strlen( PC), FALSE, 
													t_task, NULL, NULL, NULL);

	if (f_TestSuccessful)	{
		_ASSERTE( i_err == kPGPError_UserAbort);
		i_err = kPGPError_NoErr;
	}

	return i_err;
} //ei_TestForPgpAscii(


/** i_GetPgpAsciiCoords( ***
Purpose is to obtain coordinate information about any PGP-encoded ASCII block 
in a given string of content.

--- parameters & return ----
ppc: Input & Output. Memory address of the pointer to the string of content 
	to be analyzed for PGP-encoded ASCII. The pointer may be moved because 
	an extra two CRLFs will be appended to the content, forcing a 
	reallocation of the content buffer. Therefore the possibility exists that 
	the buffer may move.
ul_LEN_INPUT: the length of the null-terminated content buffer
pul_offsetBegin: Output. Pointer to the variable in which to store the 
	1-based offset from the beginning of the content string to the character 
	after which the first line of a PGP-encoded ASCII block begins.
pul_offsetEnd: Output. Pointer to the variable in which to store the 1-based 
	offset from the beginning of the content string to the end of the last 
	line of a PGP-encoded ASCII block.
RETURN: kPGPError_NoErr if no error occurred; a PGP error code otherwise.

--- revision history -------
9/12/99 PR
+ code adjustment to handle content offsets in a consistent manner
+ documentation adjustment
+ minor logic enhancement

11/23/98 PR: created		*/
static PGPError i_GetPgpAsciiCoords( char * *const  ppc, 
										const DWORD  ul_LEN_INPUT, 
										DWORD *const  pul_offsetBegin, 
										DWORD *const  pul_offsetEnd)	{
	PgpBasicInput  t_basics;
	SpecialPlugInTaskInfo  t_task;
	BOOL  f_TaskSuccessful;
	PgpBlockCoordInfo  t_coords;
	PGPError  i_err;

	//if any of the passed-in parameters are invalid, short-circuit with 
	//	failure
	PGPValidateParam( ppc && *ppc && ul_LEN_INPUT > 1 && pul_offsetBegin && 
															pul_offsetEnd);

	//initialize the output offset variables to a default value indicating 
	//	that no offset was found
	*pul_offsetBegin = *pul_offsetEnd = ei_NOT_FOUND;

	//Append a couple CRLFs to the input content to ensure that the content 
	//	does not end precisely with the end of a PGP-encoded ASCII block. 
	//	This measure is neccessary to allow our override of the PGP-decode 
	//	callback function to inform the i_DecryptVerifyBuffer() procedure 
	//	that the task of locating coördinates was successful. The measure 
	//	would not have been necessary if the kPGPEvent_FinalEvent pass in the 
	//	PGP-decode callback recognized the callback's return value. If it did 
	//	recoginize the return value, a combination of kPGPEvent_NullEvent and 
	//	kPGPEvent_FinalEvent could be used to determine the coördinates of a 
	//	content-ending PGP-encoded block.
	if (!( *ppc = realloc( *ppc, ul_LEN_INPUT + 2 * ei_LEN_CRLF)))
		return !kPGPError_NoErr;
	strcat( strcat( *ppc, epc_CRLF), epc_CRLF);

	//fill in a structure of basic information used by PGP functions 
	//	downstream
	t_basics.h_Instance = eh_Instance;
	t_basics.h_wndMain = eh_mainWnd;
	t_basics.pgpContext = m_pgpContext;
	t_basics.pgpTlsContext = m_pgpTlsContext;
	t_basics.pc_AppNm = mpc_PLUGIN_APP;
	t_basics.pc_ModuleNm = mpc_MODULENM;

	//fill in the structure of information describing the special task we 
	//	wish the PGP decoding mechanism to carry out
	t_task.i_Task = mi_GET_PGP_BLOCK_COORDS;
	t_task.pv_return = &t_coords;
	t_task.pf_Successful = &f_TaskSuccessful;

	//decode the input content while executing our special task
	i_err = i_DecryptVerifyBuffer( &t_basics, *ppc, strlen( *ppc), FALSE, 
													t_task, NULL, NULL, NULL);

	//If the task was successfully completed, set the offset outputs 
	//	accordingly, accounting if necessary for the trailing CRLFs appended 
	//	to the input content. Remember, ul_LEN_INPUT sizes the 
	//	null-terminated buffer, not the contained string.
	if (f_TaskSuccessful)	{
		*pul_offsetBegin = t_coords.ul_offsetBegin;
		*pul_offsetEnd = t_coords.ul_offsetEnd - (t_coords.ul_offsetEnd - 
											ei_LEN_CRLF == ul_LEN_INPUT - 1 ? 
											ei_LEN_CRLF : (DWORD) NULL);
		_ASSERTE( i_err == kPGPError_UserAbort);
		i_err = kPGPError_NoErr;
	}

	return i_err;	//probably success
} //i_GetPgpAsciiCoords(


/** ei_FindAndDecodePgpBlock( ***


--- parameters & return ----


--- revision history -------
9/26/99 PR: worked around false-error-return bug in PGPclCloseClientPrefs()
9/12/99 PR: "Bug" fixes related to returned offsets, lengths. More really the 
  enforcement of a system-wide standard with respect to offsets
1/3/99 PR: created			*/
//DOC!!
PGPError ei_FindAndDecodePgpBlock( char * *const  ppc_input, 
									const DWORD  ul_LEN_INPUT, 
									char * *const  ppc_block, 
									DWORD *const  pul_lenBlock, 
									char * *const  ppc_output, 
									int *const  pui_lenOutput)	{
	DWORD  ul_offsetBegin, ul_offsetEnd;
	char * pc_block;
	int  ui_lenOutput;
	PGPMemoryMgrRef  t_memoryMgr;
	PGPBoolean	f_CacheDecryptPassphrase = FALSE;
	PGPPrefRef	pgpPreferences = NULL;
	PGPError  i_err, i_error = kPGPError_NoErr;

	if (!( ppc_input && *ppc_input && ul_LEN_INPUT > 1 && ppc_output))
		return !kPGPError_NoErr;

	//default any return variables to null
	if (ppc_block)
		*ppc_block = NULL;
	if (pul_lenBlock)
		*pul_lenBlock = (DWORD) NULL;
	*ppc_output = NULL;
	if (pui_lenOutput)
		*pui_lenOutput = (int) NULL;

	//determine whether the user has it set that her decryption passphrase 
	//	should be cached
	t_memoryMgr = PGPGetContextMemoryMgr( m_pgpContext);
	if (i_err = PGPclOpenClientPrefs( t_memoryMgr, &pgpPreferences))
		return i_err;
	if (i_err = PGPGetPrefBoolean( pgpPreferences, 
												kPGPPrefDecryptCacheEnable, 
												&f_CacheDecryptPassphrase))
		goto errJump;

	//If the user does not want her passphrase cached, we need to override 
	//	her wishes very temporarily so that she won't be prompted twice to 
	//	enter her passphrase if this is an encrypted message. Twice because 
	//	one pass is made to get the coordinates of the PGP ASCII-Armored 
	//	block in the message, and a second time to do the actual decryption. 
	//	If the kPGPError_SkipSection return from PGPDecode()'s callback 
	//	function worked properly, this fudge would not be neccessary.
	if (!f_CacheDecryptPassphrase)	{
		//toggle on decrypt-passphrase caching
		if (i_err = PGPSetPrefBoolean( pgpPreferences, 
											kPGPPrefDecryptCacheEnable, TRUE))
			goto errJump;

		//Save the preferences file, then reopen it immediately and toggle 
		//	_off_ the decrypt-passphrase caching. This change won't be 
		//	recognized until we save the file at the end of this procedure. 
		//	If an error occurs, handle the situation as best we can.
		if (i_err = PGPclCloseClientPrefs( pgpPreferences, TRUE))	{
			PGPclCloseClientPrefs( pgpPreferences, FALSE);
			pgpPreferences = NULL;
			goto errJump;
		}
		if (i_err = PGPclOpenClientPrefs( t_memoryMgr, &pgpPreferences))	{
			pgpPreferences = NULL;
			goto errJump;
		}
		if (i_err = PGPSetPrefBoolean( pgpPreferences, 
										kPGPPrefDecryptCacheEnable, FALSE))
			goto errJump;
	} //if (!f_CacheDecryptPassphrase)

	//determine the coordinates within the textual content of the PGP-encoded 
	//	block
	if (i_err = i_GetPgpAsciiCoords( ppc_input, ul_LEN_INPUT, 
											&ul_offsetBegin, &ul_offsetEnd))
		goto errJump;

	//if no PGP-encoded ASCII block was found, short-circuit with success
	if (ul_offsetEnd == (DWORD) ei_NOT_FOUND)
		goto errJump;

	//making use of the regular-text version of the content, PGP decode just 
	//	the portion containing the PGP-encoded block
	pc_block = *ppc_input + ul_offsetBegin;
	(*ppc_input)[ ul_offsetEnd + 1] = (char) NULL;
	if (i_err = ei_PgpDecodeBuffer( pc_block, FALSE, ppc_output, 
															&ui_lenOutput))
		goto errJump;

	if (ppc_block)
		*ppc_block = pc_block;
	if (pul_lenBlock)
		*pul_lenBlock = ul_offsetEnd - ul_offsetBegin;
	if (pui_lenOutput)
		*pui_lenOutput = ui_lenOutput;

errJump:
	//if we temporarily toggled caching of the decryption passphrase on...
	if (!f_CacheDecryptPassphrase)	{
		//purge the cached passphrase, presuming there is one
		PGPclPurgeCachedPassphrase( PGPCL_DECRYPTIONCACHE);

		//save the preferences file with caching turned off
		i_error = PGPclCloseClientPrefs( pgpPreferences, TRUE);
	//else close the preferences file without saving
	}else
//workaround for false-error-return bug in PGPclCloseClientPrefs(), in 
//	CLprefs.c in the PGPcl project
		PGPclCloseClientPrefs( pgpPreferences, FALSE);
//		i_error = PGPclCloseClientPrefs( pgpPreferences, FALSE);

	//if no error occurred in the main part of the procedure, set the main 
	//	error code equal to the result of the clean-up stuff
	if (i_error && !i_err)
		i_err = i_error;

	return i_err;
} //ei_FindAndDecodePgpBlock(


/** xs_AutomaticDecryptVerify( ***
Purpose is to inform the caller whether the PGP automatic decrypt/verify 
toggle (preference) is on or off.

--- return ----------------
RETURN: VisualBasic True if the automatic decrypt/verify toggle is on; 
	VisualBasic False if the toggle is off.

--- revision history ------
11/18/98 PR: created		*/
short xs_AutomaticDecryptVerify()	{
	return AutoDecrypt( PGPGetContextMemoryMgr( m_pgpContext)) ? 
													ms_VB_TRUE : ms_VB_FALSE;
} //xs_AutomaticDecryptVerify(


/** xs_DefaultSign( ***
Purpose is to inform the caller whether the PGP toggle (preference) for 
default signing messages is on or off.

--- return ----------------
RETURN: VisualBasic True if the default-PGP sign toggle is on; VisualBasic 
	False if the toggle is off.

--- revision history ------
12/9/98 PR: created			*/
short xs_DefaultSign()	{
	return ByDefaultSign( PGPGetContextMemoryMgr( m_pgpContext)) ? 
													ms_VB_TRUE : ms_VB_FALSE;
} //xs_DefaultSign(


/** xs_DefaultEncrypt( ***
Purpose is to inform the caller whether the PGP toggle (preference) for 
default encrypting messages is on or off.

--- return ----------------
RETURN: VisualBasic True if the default-PGP encrypt toggle is on; VisualBasic 
	False if the toggle is off.

--- revision history ------
12/9/98 PR: created			*/
short xs_DefaultEncrypt()	{
	return ByDefaultEncrypt( PGPGetContextMemoryMgr( m_pgpContext)) ? 
													ms_VB_TRUE : ms_VB_FALSE;
} //xs_DefaultEncrypt(


/** i_DecryptVerifyBuffer( ***
Purpose is to emulate the DecryptVerifyBuffer() function in the shared-code 
PGP module DecryptVerify.c, enhanced only to add input needed for the special 
tasks required by this plug-in in conjunction with the mechanism for PGP 
decoding ASCII contnet.

Because almost all of the code in this procedure emulates a function whose 
internals I do not understand well, no in-line documentation is not included.

--- parameters & return ----
pt_BASICS: Pointer to a structure containing general contextual information 
	needed by this procedure and procedures downstream.
pc_INPUT: pointer to the content to be PGP decoded
ul_LEN_INPUT: the length of the content to be PGP decoded
f_MIME: flag telling whether the input message-content is in PGP/MIME format
t_TASK: information about the special plug-in task associated with this 
	decoding event
ppc_output: Optional Output. Pointer to the pointer in which to return the 
	memory address of the PGP-decoded content. Memory will be allocated by 
	this procedure to store the content; the caller is responsible for 
	freeing the allocation. Passing this parameter in as null indicates that 
	this procedure should ignore the decoded content.
pui_lenOutput: Optional Output. Pointer to the variable in which to store the 
	length of the PGP-decoded ASCII content. Pointer is used only the decoded 
	output is to be returned to the caller (i.e. the ppc_output parameter is 
	passed in non-null).
pf_ForYourEyesOnly: Optional Output. Ill-understood parameter used in the 
	original, shared-code version of this function. Not used in this plug-in, 
	and only required if the decoded output is to be returned to the caller 
	(i.e. the ppc_output parameter is passed in non-null).
RETURN: kPGPError_NoErr if no error occurred; a PGP error code otherwise.

--- revision history -------
9/12/99 PR: minor logic improvement in handling ppc_output parameter
12/12/98 PR: created		*/
//DOC!!
static PGPError i_DecryptVerifyBuffer( 
									const PgpBasicInput *const  pt_BASICS, 
									const char *const  pc_INPUT, 
									const DWORD  ul_LEN_INPUT, 
									const BOOL  f_MIME, 
									SpecialPlugInTaskInfo  t_task, 
									char * *const  ppc_output, 
									PGPSize *const pui_lenOutput,
									BOOL *const  pf_ForYourEyesOnly)	{
	const PGPContextRef  pgpCONTEXT = pt_BASICS ? pt_BASICS->pgpContext : 
																		NULL;

	PGPError  i_err;
	PGPOptionListRef  options = NULL;
	DecodeBinaryInfo  t_DecodeBinary;
	VerificationBlock *	pt_block = NULL, * pt_tmpBlock, * pt_indxBlock;
	PGPMemoryMgrRef  t_memoryMgr;
	OUTBUFFLIST * nobl, * obl = NULL;
	PGPBoolean  f_keyDecoding;

	PGPValidateParam( pc_INPUT && (ppc_output ? pui_lenOutput && 
									pf_ForYourEyesOnly : TRUE) && 
									pt_BASICS && pt_BASICS->pc_AppNm && 
									pt_BASICS->pc_ModuleNm && 
									PGPRefIsValid( pgpCONTEXT) && 
									PGPRefIsValid( pt_BASICS->pgpTlsContext));

	if (ppc_output)	{
		*ppc_output = NULL;
		*pui_lenOutput = (PGPSize) NULL;
	}

	t_memoryMgr = PGPGetContextMemoryMgr( pgpCONTEXT);

	if (IsPGPError( i_err = PGPBuildOptionList( pgpCONTEXT, &options, 
								PGPOInputBuffer( pgpCONTEXT, pc_INPUT, 
								ul_LEN_INPUT), PGPOLastOption( pgpCONTEXT))))	{
		DisplayPgpError( __FILE__, __LINE__, pt_BASICS->pc_ModuleNm, i_err);
		goto cleanUp;
	}

	//if we're decoding binary data, initialize the special-task members 
	//	so we can get back the data we need
	if (t_task.i_Task == mi_DECODE_BINARY)	{
		t_DecodeBinary.ppc_output = ppc_output;
		t_DecodeBinary.pul_lenOutput = pui_lenOutput;

		t_task.pv_return = &t_DecodeBinary;
	}else
		pt_block = (VerificationBlock *) PGPNewData( t_memoryMgr,
												sizeof( VerificationBlock),
												kPGPMemoryMgrFlags_Clear);

	i_err = i_DecryptVerify( pt_BASICS, options, f_MIME, t_task, pt_block, 
															&f_keyDecoding);

	//if we're dealing with regular ASCII decoding...
	if (t_task.i_Task != mi_DECODE_BINARY)
		//if a PGP error was thrown (probably on purpose if a special plug-in 
		//	task is involved) or if the caller doesn't want or need ASCII 
		//	output, free all the "verification" blocks allocated to this 
		//	PGP-decoding attempt, then skip past the rest of this 
		//	procedure's processing
		if (i_err || !ppc_output || f_keyDecoding)
			do {
				if (pt_block->pOutput)
					PGPFreeData( pt_block->pOutput);
				if (pt_block->szBlockBegin)
					PGPFreeData( pt_block->szBlockBegin);
				if (pt_block->szBlockEnd)
					PGPFreeData( pt_block->szBlockEnd);

				pt_tmpBlock = pt_block;
				pt_block = pt_block->next;
				PGPFreeData( pt_tmpBlock);
			} while (pt_block);
		//else carry out the normal procedure for putting together the 
		//	decoded content
		else	{
			pt_indxBlock = pt_block;

			//convert pt_block to OUTBUFFLIST
			do	{
				if (pt_indxBlock->szBlockBegin)	{
					nobl = MakeOutBuffItem( &obl);
					nobl->pBuff = pt_indxBlock->szBlockBegin;
					nobl->dwBuffSize = strlen( pt_indxBlock->szBlockBegin);
				}

				if (pt_indxBlock->pOutput)	{
					nobl = MakeOutBuffItem( &obl);
					nobl->pBuff = pt_indxBlock->pOutput;
					nobl->dwBuffSize = strlen( pt_indxBlock->pOutput);
					nobl->FYEO = pt_indxBlock->FYEO;
				}

				if (pt_indxBlock->szBlockEnd)	{
					nobl = MakeOutBuffItem( &obl);
					nobl->pBuff = pt_indxBlock->szBlockEnd;
					nobl->dwBuffSize = strlen( pt_indxBlock->szBlockEnd);
				}

				pt_tmpBlock = pt_indxBlock;
				pt_indxBlock = pt_indxBlock->next;
				PGPFreeData( pt_tmpBlock);
			} while (pt_indxBlock);

			//concatenate them to ppc_output
			ConcatOutBuffList( (void *) pgpCONTEXT, obl, ppc_output, 
										pui_lenOutput, pf_ForYourEyesOnly);
		} //if (i_err || !ppc_output || f_keyDecoding)

cleanUp:
	if (options)
		PGPFreeOptionList( options);

	return i_err;
} //i_DecryptVerifyBuffer(


/** DisplayPgpError( ***
Emulates the DisplayPgpError() function in shared-code PGP module 
DecryptVerify.c.

--- parameters ---------
pc_FILE: pointer to the name of the current source file being run
i_LINE: the line-number of the calling function in the source file being run
pc_MODULE: pointer to the name of the run-time module containing the current 
	source file
i_errCode: the code of the error being reported in this function

--- revision history ------
11/20/98 PR: created		*/
static void DisplayPgpError( const char *const  pc_FILE, 
								const int  i_LINE, 
								const char *const  pc_MODULE, 
								int  i_errCode)	{
	char pc_MSG[255];

	if (i_errCode == kPGPError_BadPacket)
		i_errCode = kPGPError_CorruptData;

	PGPclEncDecErrorToString( i_errCode, pc_MSG, sizeof( pc_MSG) - 1);

#ifdef _DEBUG
	_CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_WNDW);
	_CrtDbgReport( _CRT_ERROR, pc_FILE, i_LINE, pc_MODULE, pc_MSG);
#endif

	MessageBox( eh_mainWnd, pc_MSG, pc_MODULE, MB_ICONEXCLAMATION);
} //DisplayPgpError(


/** i_DecryptVerify( ***
Purpose is to emulate the DecryptVerify() function in the shared-code PGP 
module DecryptVerify.c, enhancing it only to override (subclass) the 
DecodeEventHandler() callback function in DecryptVerify.c in order that we 
may carry out special tasks required in this plug-in.

Because most of the code in this procedure emulates a function whose 
internals I do not understand well, in-line documentation is included only 
on code specific to the plug-in.

--- parameters & return ----
pt_BASICS: Pointer to a structure containing general contextual information 
	needed by this procedure and procedures downstream.
options: Opaque PGP storage needed by procedures downstream. Includes somehow 
	the input message-content buffer.
f_MIME: flag telling whether the input message-content is in PGP/MIME format
t_TASK: information about the special plug-in task associated with this 
	decoding event
pt_block: Output. Pointer to the PGP mechanism for obtaining output from a 
	decoding event.
pf_keyDecoding: Optional Output. Pointer to the flag in which to store 
	whether the decoding resulted in the user importing public key(s). If 
	omitted, this functionality is ignored.
RETURN: kPGPError_NoErr if no error occurred; a PGP error code otherwise.

--- revision history -------
2/27/00 PR: decommissioned "SendMessage" workaround for the PGP 6.0x problem 
	(fixed in PGP 6.5) with the destruction of the progress dialog, a 
	workaround which itself began with Notes R5 to cause an invalid-pointer 
	error when closing Notes
9/12/99 PR: added the pf_keyDecoding flag output functionality
11/23/98 PR: created		*/
static PGPError i_DecryptVerify( const PgpBasicInput *const  pt_BASICS,
									PGPOptionListRef  options,
									const BOOL  f_MIME, 
									const SpecialPlugInTaskInfo  t_TASK, 
									VerificationBlock *const  pt_block, 
									PGPBoolean *const  pf_keyDecoding)	{
	const PGPContextRef  pgpCONTEXT = pt_BASICS ? pt_BASICS->pgpContext : 
																		NULL;

	PGPError  i_err;
	PGPKeySetRef  pubKeySet = NULL,
					newKeySet = NULL;
	PGPUInt32  nNumKeys = 0;
	HWND  hwndWorking = NULL;
	char  szWorkingTitle[256];
	MyDecodeEventData  t_myDecodeData;
	DecodeEventData *const  pt_normalData = &t_myDecodeData.t_normalData;

	PGPValidateParam( pgpCONTEXT && pt_BASICS && pt_BASICS->h_Instance && 
												pt_BASICS->pgpTlsContext && 
												t_TASK.i_Task != mi_NO_TASK ? 
												(int) t_TASK.pf_Successful : 
												TRUE && options);

	if (pf_keyDecoding)
		*pf_keyDecoding = FALSE;

	UpdateWindow( pt_BASICS->h_wndMain);

	pt_normalData->h_Instance = pt_BASICS->h_Instance;
	pt_normalData->h_wndMain = pt_BASICS->h_wndMain;
	pt_normalData->pgpTlsContext = pt_BASICS->pgpTlsContext;
	pt_normalData->pc_AppNm = pt_BASICS->pc_AppNm;
	pt_normalData->pgpRecipients = NULL;
	pt_normalData->ul_keyCount = 0;
	pt_normalData->pt_keyIds = NULL;
	pt_normalData->pt_block = pt_block;

	//store a copy of the structure containing information about the special 
	//	plug-in task we've got in mind so that our decode callback procedure 
	//	can carry out the task
	t_myDecodeData.t_task = t_TASK;

	if (IsPGPError( i_err = PGPsdkLoadDefaultPrefs( pgpCONTEXT)))	{
		DisplayPgpError( __FILE__, __LINE__, pt_BASICS->pc_ModuleNm, i_err);
		return i_err;
	}

	if (IsPGPError( i_err = PGPOpenDefaultKeyRings( pgpCONTEXT, 
								(PGPKeyRingOpenFlags) NULL, &pubKeySet)))	{
		DisplayPgpError( __FILE__, __LINE__, pt_BASICS->pc_ModuleNm, i_err);
		goto cleanUp;
	}
	pt_normalData->pgpPubKeySet = pubKeySet;

	PGPNewKeySet( pgpCONTEXT, &newKeySet);

	//set up the working (progress-bar) dialog only if no special plug-in 
	//	task is involved that should be transparent to the user
	if (t_TASK.i_Task == mi_NO_TASK || t_TASK.i_Task == mi_DECODE_BINARY)	{
		LoadString( pt_BASICS->h_Instance, IDS_WORKINGDECRYPT, 
									szWorkingTitle, sizeof( szWorkingTitle));

		hwndWorking = WorkingDlgProcThread( GetModuleHandle( 
													pt_BASICS->pc_ModuleNm), 
													pt_BASICS->h_Instance, 
													NULL, szWorkingTitle, "");
	}
	pt_normalData->h_wndWorking = hwndWorking;

	//decode the message using a callback procedure that we control to 
	//	manage our special PGP tasks
	i_err = PGPDecode( pgpCONTEXT, options, PGPOPassThroughIfUnrecognized( 
							pgpCONTEXT, (PGPBoolean) !f_MIME),
							PGPOPassThroughKeys( pgpCONTEXT, TRUE),
							PGPOEventHandler( pgpCONTEXT, 
							i_DecodeEventHandlerOverride, &t_myDecodeData),
							PGPOSendNullEvents( pgpCONTEXT, 100),
							PGPOImportKeysTo( pgpCONTEXT, newKeySet),
							PGPOKeySetRef( pgpCONTEXT, pubKeySet),
							PGPOLastOption( pgpCONTEXT));

	if (hwndWorking)
		DestroyWindow( hwndWorking);

	//if the user or one of the plug-in's special tasks aborted the decoding 
	//	process, skip past the rest of the procedure's processing
	if (kPGPError_UserAbort == i_err)
		goto cleanUp;

	if (IsPGPError( i_err))	{
		DisplayPgpError( __FILE__, __LINE__, pt_BASICS->pc_ModuleNm, i_err);
		goto cleanUp;
	}

	//if the decoded content contains PGP public keys to import...
	PGPCountKeys( newKeySet, &nNumKeys);
	if (nNumKeys)	{
		//prompt the user to add the keys to her keyring
		i_err = PGPclQueryAddKeys( pgpCONTEXT, pt_BASICS->pgpTlsContext, 
									pt_BASICS->h_wndMain, newKeySet, NULL);

		//If the user didn't cancel the import process and no error occurred, 
		//	set the output flag that this was a key-import decoding (if 
		//	appropriate). If an error did occur, inform the user.
		if (kPGPError_UserAbort != i_err)
			if (IsPGPError( i_err))
				DisplayPgpError( __FILE__, __LINE__, pt_BASICS->pc_ModuleNm, 
																	i_err);
			else if (pf_keyDecoding)
				*pf_keyDecoding = TRUE;
	} //if (nNumKeys > 0)

cleanUp:
	if (pt_normalData->pgpRecipients)
		PGPFreeKeySet( pt_normalData->pgpRecipients);
	if (pt_normalData->pt_keyIds)
		free( pt_normalData->pt_keyIds);
	if (newKeySet)
		PGPFreeKeySet( newKeySet);
	if (pubKeySet)
		PGPFreeKeySet( pubKeySet);

	return i_err;
} //i_DecryptVerify(


/** i_DecodeEventHandlerOverride( ***
Purpose is to override (subclass) the DecodeEventHandler() function in 
the shared-code PGP module DecryptVerify.c. The override allows us to 
accommodate special tasks associated with PGP decoding ASCII content required 
by this plug-in.

--- parameters & return ----
pgpContext: opaque PGP contextual information
pt_event: pointer to PGP event information and surrounding PGP event data
pv_userValue: Input & Output. Pointer to caller-supplied information to be 
	passed into the PGPDecode() call. Output for the purposes of this plug-in.
RETURN: kPGPError_NoErr if no error occurred; a PGP error code otherwise.

--- revision history -------
9/12/99 PR
+ documentation re our treatment of the binary-decoding process, other 
  adjustments
+ got rid of workaround to PGP bug, now fixed, where crash would occur when 
  decoding an empty, clear-signed PGP block

12/6/98 PR: created			*/
static PGPError i_DecodeEventHandlerOverride( PGPContextRef  pgpContext, 
												PGPEvent * pt_event, 
												PGPUserValue  pv_userValue)	{
	PGPValidateParam( PGPRefIsValid( pgpContext) && pt_event);

	//if applicable, check whether this PGP decoding event is one that needs 
	//	special handling
	if (pv_userValue)	{
		SpecialPlugInTaskInfo  t_task = ((MyDecodeEventData *) 
														pv_userValue)->t_task;

		switch (pt_event->type)	{
			//if this is the start of the PGP decoding event, initialize 
			//	any special output data to default values (non-success)
			case kPGPEvent_InitialEvent:
				switch (t_task.i_Task)	{
					case mi_TEST_FOR_PGP_ASCII:
						*(BOOL *) t_task.pv_return = FALSE;
						break;

					case mi_GET_PGP_BLOCK_COORDS:
						((PgpBlockCoordInfo *) 
										t_task.pv_return)->ul_offsetBegin = 
										((PgpBlockCoordInfo *) 
										t_task.pv_return)->ul_offsetEnd = 
																ei_NOT_FOUND;
				} //switch (t_task.i_Task)
				if (t_task.i_Task != mi_NO_TASK)
					*t_task.pf_Successful = FALSE;

				break;

			//If the PGP decoding has just found a new block of content and 
			//	our task is to get the coordinates of the content's PGP 
			//	block and an ending offset has not yet been stored...
			case kPGPEvent_BeginLexEvent:	{
				PgpBlockCoordInfo * pt_coords;

				if (t_task.i_Task == mi_GET_PGP_BLOCK_COORDS && 
										(pt_coords = (PgpBlockCoordInfo *) 
										t_task.pv_return)->ul_offsetEnd == 
										(DWORD) ei_NOT_FOUND)
					//If a beginning offset has already been stored, the 
					//	current block, because it is the following block, 
					//	ipso facto points to the end of the PGP-encoded block 
					//	in the content, so set the ending offset as this 
					//	block's beginning offset. We don't subtract one 
					//	because PGP uses a zero-based offset, while we are 
					//	using a one-based offset.
					if (pt_coords->ul_offsetBegin != (DWORD) ei_NOT_FOUND)	{
						pt_coords->ul_offsetEnd = 
									pt_event->data.beginLexData.sectionOffset;

						//we can abort the decoding process since we've 
						//	accomplished our task
						*t_task.pf_Successful = TRUE;
						return kPGPError_UserAbort;
					//Else store the one-based beginning offset to the 
					//	location after which the block starts, even though we 
					//	don't know yet whether this block is PGP-encoded or 
					//	not. The ensuing Analyze event will tell us that.
					}else
						pt_coords->ul_offsetBegin = 
									pt_event->data.beginLexData.sectionOffset;

				break;
			} //case kPGPEvent_BeginLexEvent

			//The Analyze event tells us what type of content block we've 
			//	got, before the PGP SDK actually decodes it. We use this 
			//	event to help execute any special task we need to carry out 
			//	in conjunction with this decoding.
			case kPGPEvent_AnalyzeEvent:
				switch (t_task.i_Task)	{
					//if we just need to know whether the content being PGP 
					//	decoded contains any PGP-encoded blocks and the 
					//	current block is PGP-encoded, indicate that the 
					//	content does contain PGP-encoded content
					case mi_TEST_FOR_PGP_ASCII:
						if (pt_event->data.analyzeData.sectionType < 
													kPGPAnalyze_Unknown)	{
							*(BOOL *) t_task.pv_return = TRUE;

							//we can abort the decoding process since we've 
							//	accomplished our task
							*t_task.pf_Successful = TRUE;
							return kPGPError_UserAbort;
						}

						break;

					//If we need to get the coordinates of the PGP-encoded 
					//	block in the content and if this is not a PGP-encoded 
					//	block, reinitialize the beginning-offset variable in 
					//	order that the next BeginLex or Final event will know 
					//	that it doesn't need to store a corresponding ending 
					//	offset.
					case mi_GET_PGP_BLOCK_COORDS:
						if (pt_event->data.analyzeData.sectionType == 
														kPGPAnalyze_Unknown)
							((PgpBlockCoordInfo *) 
										t_task.pv_return)->ul_offsetBegin = 
										(DWORD) ei_NOT_FOUND;
						break;

					//If the content being decoded is binary and the decoded 
					//	output has been written, there's no need to continue, 
					//	so abort the rest of the decoding process. (I don't 
					//	recall what happens if we let the process continue, 
					//	but I bet it aint what we want.)
					case mi_DECODE_BINARY:
						if ( *((DecodeBinaryInfo *) 
											t_task.pv_return)->ppc_output)	{
							*t_task.pf_Successful = TRUE;
							return kPGPError_UserAbort;
						}
				} //switch (t_task.i_Task)
				break;

			//if the content being decoded is binary, hand the process a 
			//	pointer to the pointer by which the decoding process will 
			//	tell us where the buffer in which it stored the output is 
			//	located
			case kPGPEvent_OutputEvent:
				if (t_task.i_Task == mi_DECODE_BINARY)	{
					DecodeBinaryInfo *const pt = (DecodeBinaryInfo *) 
															t_task.pv_return;
					PGPAddJobOptions( pt_event->job, 
										PGPOAllocatedOutputBuffer( 
										pgpContext, pt->ppc_output, INT_MAX, 
										pt->pul_lenOutput),
										PGPOLastOption( pgpContext));

					return kPGPError_NoErr;
				}
		} //switch (pt_event->type)
	} //if (pv_userValue)

	return DecodeEventHandler( pgpContext, pt_event, pv_userValue);
} //i_DecodeEventHandlerOverride(


/** ei_PgpLookupEmailLocal( ***
Purpose is to look up a series of e-mail addresses in the user's default 
keyrings and output the success of each look up.

--- parameters & return ----
pt_CONTEXT: pointer to the information structure used by the Notes 
	Plug-In to hold a common set of PGP contextual information through the 
	encoding process
pt_node: Input & Output. Pointer to the head node of the list of e-mail 
	address information structures, each of whose e-mail addresses is to be 
	looked up for a key match. The f_found member of the information 
	structure will be set according to whether a match was found or not.
RETURN: kPGPError_NoErr if successful; a PGP error code otherwise

--- revision history -------
9/12/99 PR: created			*/
PGPError ei_PgpLookupEmailLocal( PgpEncodeContext *const  pt_CONTEXT, 
									NameFoundNode * pt_nd)	{
	PGPContextRef  ctxt;
	char * pc;
	PGPKeySetRef  keyset, result;
	PGPFilterRef  filter;
	PGPUInt32  ul;
	PGPError  i_err;

	PGPValidateParam( pt_nd && pt_CONTEXT && 
								pt_CONTEXT->t_recipients.Context && 
								pt_CONTEXT->t_recipients.OriginalKeySetRef);

	//for each e-mail address node in the list...
	ctxt = pt_CONTEXT->t_recipients.Context;
	keyset = pt_CONTEXT->t_recipients.OriginalKeySetRef;
	do	{
		//if the address is already found or null, iterate to the next node 
		//	in the list
		if (pt_nd->pt_name->f_found || !*(pc = pt_nd->pt_name->pc_nm))
			continue;

		//look up the address for a matching key
		if (IsPGPError( i_err = PGPNewUserIDEmailFilter( ctxt, pc, 
													kPGPMatchEqual, &filter)))
			break;
		i_err = PGPFilterKeySet( keyset, filter, &result);
		PGPFreeFilter( filter);
		if (IsPGPError( i_err))
			break;

		//indicate whether a key match was found for the address
		PGPCountKeys( result, &ul);
		if (ul)
			pt_nd->pt_name->f_found = TRUE;
		PGPFreeKeySet( result);
	} while (pt_nd = pt_nd->pt_next);

	return i_err;
} //ei_PgpLookupEmailLocal(


/** ei_PgpLookupEmailViaServers( ***
Purpose is to look up a series of e-mail addresses against the certificate 
servers specified in the user's PGP preferences, and to output the success of 
each look up.

--- parameters & return ----
pt_context: Input & Output. Pointer to the information structure used by the 
	Notes Plug-In to hold a common set of PGP contextual information through 
	the encoding process. The AddedKeys member of the t_recipients member of 
	the information structure may be updated by this procedure, carrying 
	an aggregate list of discovered keys among calls to this and possibly 
	other procedures.
pt_nd: Input & Output. Pointer to the head node of the list of e-mail 
	address information structures, each of whose e-mail addresses is to be 
	looked up for a key match. The f_found member of the information 
	structure will be set according to whether a match was found or not.
RETURN: kPGPError_NoErr if successful; a PGP error code otherwise

--- revision history -------
9/12/99 PR: created			*/
PGPError ei_PgpLookupEmailViaServers( PgpEncodeContext *const  pt_context, 
										NameFoundNode * pt_nd)	{
	PGPContextRef  ctxt;
	PGPtlsContextRef  tlsCtxt;
	PGPKeySetRef  mainKeyset, result = kInvalidPGPKeySetRef, 
					* p_runningSet;
	HANDLE  h_wnd;
	char * pc, pc_addr[ 0x400];
	PGPUInt32  ul;
	PGPError  i_err;

	PGPValidateParam( pt_nd && pt_context && 
								pt_context->t_recipients.Context && 
								pt_context->t_recipients.OriginalKeySetRef);

	ctxt = pt_context->t_recipients.Context;
	if (*(p_runningSet = &pt_context->t_recipients.AddedKeys) == 
														kInvalidPGPKeySetRef)
		if (IsPGPError( i_err = PGPNewKeySet( ctxt, p_runningSet)))
			return i_err;

	//for each e-mail address node in the list...
	tlsCtxt = pt_context->t_recipients.tlsContext;
	mainKeyset = pt_context->t_recipients.OriginalKeySetRef;
	h_wnd = pt_context->t_recipients.hwndParent;
	do	{
		//if the address is already found or null, iterate to the next node 
		//	in the list
		if (pt_nd->pt_name->f_found || !*(pc = pt_nd->pt_name->pc_nm))
			continue;

		//look up the address for a matching key
		sprintf( pc_addr, "%s%s%s", "<", pt_nd->pt_name->pc_nm, ">");
		if (IsPGPError( i_err = PGPclSearchServerForUserID( ctxt, tlsCtxt, 
										h_wnd, pc_addr, PGPCL_DEFAULTSERVER, 
										mainKeyset, &result)))
			goto errJump;
		
		//if a key match was found for the address, indicate this and add the 
		//	discovered key to the running set of keys. PGPAddKeys() doesn't 
		//	seem to duplicate keys, so I don't concern myself with that 
		//	potential problem.
		PGPCountKeys( result, &ul);
		if (ul)	{
			pt_nd->pt_name->f_found = TRUE;
			if (IsPGPError( i_err = PGPAddKeys( result, *p_runningSet)))
				goto errJump;
		}
		PGPFreeKeySet( result);
		result = kInvalidPGPKeySetRef;
	} while (pt_nd = pt_nd->pt_next);

errJump:
	if (result != kInvalidPGPKeySetRef)
		PGPFreeKeySet( result);

	return i_err;
} //ei_PgpLookupEmailViaServers(


