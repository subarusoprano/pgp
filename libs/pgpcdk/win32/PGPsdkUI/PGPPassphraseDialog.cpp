/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.
	
	$Id: PGPPassphraseDialog.cpp,v 1.68 1999/04/08 13:29:37 pbj Exp $
____________________________________________________________________________*/

#include "stdio.h"
#include "stdlib.h"
#include "PGPui32.h"
#include "pgpDialogs.h"
#include "pgpPassphraseUtils.h"
#include "PGPCL.h"
#include "pgpSDKUILibPriv.h"

#define MAXDECRYPTIONNAMECHAR		36

// local globals
HHOOK				hhookKeyboard;
HHOOK				hhookMouse;

HHOOK				hhookCBT;
HHOOK				hhookGetMessage;
HHOOK				hhookMsgFilter;

// global variable structure for re-entrancy
typedef struct _GPP
{
	LPSTR				pszPassPhrase;
	LPSTR				pszPassPhraseConf;
	LPSTR				szDummy;
	WNDPROC				wpOrigPhrase1Proc;  
	WNDPROC				wpOrigPhrase2Proc;  
	INT					iNextTabControl;
	BOOL				bHideText;
	//BEGIN FULL EDIT IN PASSWORD DIALOGS - Imad R. Faiad
	BOOL				bFullEdit;
	//END FULL EDIT IN PASSWORD DIALOGS
	HWND				hwndQuality;
	HWND				hwndMinQuality;
	PGPContextRef		context;
	HWND				hwndOptions;
	const CPGPPassphraseDialogOptions *options;
	HWND				hwndOptionsControl;
} GPP;

// Help IDs for passphrase dialogs
static DWORD aIds[] = 
{			
    IDC_HIDETYPING,		IDH_PGPCLPHRASE_HIDETYPING, 
	IDC_PHRASE1,		IDH_PGPCLPHRASE_PHRASE,
	IDC_PHRASE2,		IDH_PGPCLPHRASE_CONFIRMATION,
	IDC_SIGNKEYCOMBO,	IDH_PGPCLPHRASE_SIGNINGKEY,
	IDC_KEYLISTBOX,		IDH_PGPCLPHRASE_KEYLIST,
	IDC_PHRASEQUALITY,	IDH_PGPCLPHRASE_QUALITY,
	IDC_KEYNAME,		IDH_PGPCLPHRASE_KEYNAME,
	801,				IDH_TEXTOUTPUT, // Hardcoded in ClientLib
	804,				IDH_DETACHEDSIG, // Hardcoded in ClientLib
    0,0 
}; 

PGPError
PGPsdkUIErrorBox (
		HWND hWnd,
		PGPError error) 
{
	PGPError	err				= kPGPError_NoErr;
	CHAR		szMessage[512];
	char		StrRes[500];

	if (IsPGPError (error) && (error!=kPGPError_UserAbort)) 
	{
		PGPGetErrorString (error, sizeof(szMessage), szMessage);

		LoadString (gPGPsdkUILibInst, IDS_PGPERROR, StrRes, sizeof(StrRes));

		MessageBox (hWnd, szMessage, StrRes, 
			MB_OK|MB_ICONSTOP|MB_SETFOREGROUND);
	}

	return err;
}

// SetCapsLockMessageState shows or hides the caps lock message as needed.

void SetCapsLockMessageState(HWND hdlg)
{
	if (GetKeyState(VK_CAPITAL) & 1)
	{
		ShowWindow(GetDlgItem(hdlg,IDC_CAPSWARNING),SW_SHOW);
	}
	else
	{
		ShowWindow(GetDlgItem(hdlg,IDC_CAPSWARNING),SW_HIDE);
	}
}

// Help file is located in C:\Windows\System
void GetHelpDir(char *szHelp)
{
	GetSystemDirectory(szHelp,MAX_PATH);
	strcat(szHelp,"\\Pgp.hlp");
}

//	________________________________
//
//  Hook procedure for WH_MOUSE hook
  
LRESULT CALLBACK 
MouseHookProc (
		INT		iCode, 
		WPARAM	wParam, 
		LPARAM	lParam) 
{ 
	MOUSEHOOKSTRUCT* pmhs;

    if (iCode >= 0) 
	{
		pmhs = (MOUSEHOOKSTRUCT*) lParam; 
		PGPGlobalRandomPoolMouseMoved ();
	}

	return 0;
} 

//	___________________________________
//
//  Hook procedure for WH_KEYBOARD hook 

 
LRESULT CALLBACK 
GetKBHookProc (
		INT		iCode, 
		WPARAM	wParam, 
		LPARAM	lParam) 
{ 
    if (iCode >= 0) 
	{
		PGPGlobalRandomPoolAddKeystroke (wParam);
	}

	return 0;
} 
  
//	___________________________________
//
//  Hook procedure for WH_JOURNALRECORD hook 

 
LRESULT CALLBACK 
GenericHookProc (
		INT		iCode, 
		WPARAM	wParam, 
		LPARAM	lParam) 
{ 
	return 0;
} 

LRESULT CALLBACK 
CBTHookProc (
		INT		iCode, 
		WPARAM	wParam, 
		LPARAM	lParam) 
{ 
	if (iCode >= 0)
	{
		switch (iCode)
        {
			case HCBT_SETFOCUS:
				return CallNextHookEx (hhookCBT, iCode, wParam, lParam);
				break;
		}
	}

	return 0;
} 


void InitRandomKeyHook(HHOOK* phhookKeyboard, HHOOK* phhookMouse)
{
	DWORD dwPhraseThreadID;

	dwPhraseThreadID = GetCurrentThreadId ();

	// the mouse and keyboard hooks trap entropy
	*phhookMouse = SetWindowsHookEx (WH_MOUSE, 
		MouseHookProc, 
		NULL, dwPhraseThreadID);
	*phhookKeyboard = SetWindowsHookEx (WH_KEYBOARD, 
		GetKBHookProc, 
		NULL, dwPhraseThreadID);
}

void UninitRandomKeyHook(HHOOK hhookKeyboard, HHOOK hhookMouse)
{
	UnhookWindowsHookEx (hhookKeyboard);
	UnhookWindowsHookEx (hhookMouse);
}

void InstallSecurityHooks(void)
{
	DWORD dwPhraseThreadID;

	dwPhraseThreadID = GetCurrentThreadId ();

	// these are just to prevent sniffers from seeing these messages
	hhookCBT = SetWindowsHookEx (WH_CBT, 
		CBTHookProc, 
		NULL, dwPhraseThreadID);
	hhookGetMessage = SetWindowsHookEx (WH_GETMESSAGE, 
		GenericHookProc, 
		NULL, dwPhraseThreadID);
	hhookMsgFilter = SetWindowsHookEx (WH_MSGFILTER, 
		GenericHookProc, 
		NULL, dwPhraseThreadID);
}

void UninstallSecurityHooks(void)
{
	UnhookWindowsHookEx (hhookMsgFilter);
	UnhookWindowsHookEx (hhookGetMessage);
	UnhookWindowsHookEx (hhookCBT);
}

	PGPUInt32
PGPEstimatePassphraseQuality(const char *passphrase)
{
	return( pgpEstimatePassphraseQuality( passphrase ) );
}

//___________________________
//
// Secure memory allocation routines
//

VOID* 
secAlloc (PGPContextRef context, UINT uBytes) 
{
	PGPMemoryMgrRef	memmgr;

	memmgr = PGPGetContextMemoryMgr (context);
	return (PGPNewSecureData (memmgr, uBytes, 0));
}


VOID 
secFree (VOID* p) 
{
	if (p) {
		FillMemory ((char *)p,lstrlen((char *)p), '\0');
		PGPFreeData ((char *)p);
	}
}

//	__________________
//
//	Wipe edit box clean

VOID 
WipeEditBox (
		GPP *gpp,
		HWND hDlg, 
		UINT uID) 
{
	CHAR*	p;
	INT		i;

	i = SendDlgItemMessage (hDlg, uID, WM_GETTEXTLENGTH, 0, 0);
	if (i > 0) {
		p = (char *)secAlloc (gpp->context,i+1);
		if (p) {
			FillMemory (p, i, ' ');
			SendDlgItemMessage (hDlg, uID, WM_SETTEXT, 0, (LPARAM)p);
			secFree (p);
		}
	}
}

void FreePassphrases(GPP *gpp)
{
	if(gpp->pszPassPhrase)
	{
		secFree(gpp->pszPassPhrase);
		gpp->pszPassPhrase=NULL;
	}

	if(gpp->pszPassPhraseConf)
	{
		secFree(gpp->pszPassPhraseConf);
		gpp->pszPassPhraseConf=NULL;
	}

	if(gpp->szDummy)
	{
		secFree(gpp->szDummy);
		gpp->szDummy=NULL;
	}
}

void ClearPassphrases(HWND hDlg,GPP *gpp)
{
	HWND hwndPhrase1,hwndPhrase2;

	if(gpp->pszPassPhraseConf)
	{
		secFree(gpp->pszPassPhraseConf);
		gpp->pszPassPhraseConf=NULL;
	}

	if(gpp->szDummy)
	{
		secFree(gpp->szDummy);
		gpp->szDummy=NULL;
	}

	hwndPhrase1=GetDlgItem(hDlg,IDC_PHRASE1);
	hwndPhrase2=GetDlgItem(hDlg,IDC_PHRASE2);

	if(hwndPhrase1)
	{
		WipeEditBox (gpp,hDlg, IDC_PHRASE1);
		SetWindowText (hwndPhrase1, "");
	}

	if(hwndPhrase2)
	{
		WipeEditBox (gpp,hDlg, IDC_PHRASE2);
		SetWindowText (hwndPhrase2, "");
	}

	SetFocus (hwndPhrase1);
}

//	___________________________________________________
//
//	Message box routine using string table resource IDs

LRESULT 
PGPsdkUIMessageBox (
		 HWND	hWnd, 
		 INT	iCaption, 
		 INT	iMessage,
		 ULONG	ulFlags) 
{
	CHAR szCaption [128];
	CHAR szMessage [256];

	LoadString (gPGPsdkUILibInst, iCaption, szCaption, sizeof(szCaption));
	LoadString (gPGPsdkUILibInst, iMessage, szMessage, sizeof(szMessage));

	ulFlags |= MB_SETFOREGROUND;
	return (MessageBox (hWnd, szMessage, szCaption, ulFlags));
}
//BEGIN KEY ID IN DECRYPTION DIALOG LIST CONTROL - Imad R. Faiad
// This is port of a PGP 5.5.3 modification originally
// made Anonymous
//	____________________________
//
/* The original PGP 6.5.1 code is within this comment block
//	____________________________
//
//  setup key display list box

BOOL 
AddKeySetToRecipientsTable (HWND hDlg, 
							PGPKeySetRef KeySet,
							CPGPDecryptionPassphraseDialogOptions *options) 
{
	BOOL			bAtLeastOneValidSecretKey	= FALSE;
	UINT			uUnknownKeys				= 0;
	PGPKeyListRef	KeyList;
	PGPKeyIterRef	KeyIter;
	PGPKeyRef		Key;
	PGPSubKeyRef	SubKey;
	UINT			u, uIndex, uKeyBits, uAlgorithm;
	INT				iKeyDefault, iKeySelected;
	PGPBoolean		bSecret, bCanDecrypt;
	CHAR			szName[kPGPMaxUserIDSize];
	CHAR			sz[128];

	PGPOrderKeySet (KeySet, kPGPValidityOrdering, &KeyList);
	PGPNewKeyIter (KeyList, &KeyIter);

	iKeySelected = -1;
	iKeyDefault = -1;

	PGPKeyIterNext (KeyIter, &Key);
	while (Key) 
	{
		PGPGetKeyBoolean (Key, kPGPKeyPropIsSecret, &bSecret);
		PGPGetKeyBoolean (Key, kPGPKeyPropCanDecrypt, &bCanDecrypt);
		PGPGetKeyNumber (Key, kPGPKeyPropAlgID, (int *)&uAlgorithm);
		if (bSecret && bCanDecrypt) bAtLeastOneValidSecretKey = TRUE;

		// get name on key
		PGPGetPrimaryUserIDNameBuffer (Key, sizeof(szName), 
										szName, &u);
		if (u > MAXDECRYPTIONNAMECHAR) 
		{
			u = MAXDECRYPTIONNAMECHAR;
			lstrcat (szName, "...");
		}
		else 
			szName[u] = '\0';

		// append key type / size info to name
		lstrcat (szName, " (");

		switch (uAlgorithm) 
		{
			case kPGPPublicKeyAlgorithm_RSA :
				LoadString (gPGPsdkUILibInst, IDS_RSA, sz, sizeof(sz));
				lstrcat (szName, sz);
				lstrcat (szName, "/");
				PGPGetKeyNumber (Key, kPGPKeyPropBits, (int *)&uKeyBits);
				wsprintf (sz, "%i", uKeyBits);
				lstrcat (szName, sz);
				break;

			case kPGPPublicKeyAlgorithm_DSA :
				LoadString (gPGPsdkUILibInst, IDS_DH, sz, sizeof(sz));
				lstrcat (szName, sz);
				lstrcat (szName, "/");
				PGPKeyIterNextSubKey (KeyIter, &SubKey);
				if (SubKey) {
					PGPGetSubKeyNumber (SubKey, kPGPKeyPropBits, 
										(int *)&uKeyBits);
					wsprintf (sz, "%i", uKeyBits);
					lstrcat (szName, sz);
				}
				else lstrcat (szName, "???");
				break;

			default :
				LoadString (gPGPsdkUILibInst, IDS_UNKNOWN, sz, sizeof(sz));
				lstrcat (szName, sz);
				lstrcat (szName, "/");
				lstrcat (szName, sz);
				break;
		}
		lstrcat (szName, ")");

		uIndex = SendDlgItemMessage (hDlg, IDC_KEYLISTBOX, 
							LB_ADDSTRING, 0, (LPARAM)szName);
		PGPKeyIterNext (KeyIter, &Key);
	}
	PGPFreeKeyIter (KeyIter);
	PGPFreeKeyList (KeyList);

	return bAtLeastOneValidSecretKey;
}

BOOL 
InitEncryptedToKeyListBox (HWND hDlg, CPGPDecryptionPassphraseDialogOptions *options) 
{
	BOOL bAtLeastOneValidSecretKey;

	SendMessage(GetDlgItem(hDlg, IDC_KEYLISTBOX),LB_RESETCONTENT,0,0);

	if(PGPKeySetRefIsValid( options->mKeySet ))
		bAtLeastOneValidSecretKey = AddKeySetToRecipientsTable( hDlg,options->mKeySet,options );

	if(options->mNewKeys!=NULL)
		if(PGPKeySetRefIsValid( *(options->mNewKeys) ))
			AddKeySetToRecipientsTable( hDlg,*(options->mNewKeys),options );

	if( IsntNull( options->mMissingKeyIDList ) )
	{
		char MsgTxt[255];
		char StrRes[500];

		LoadString (gPGPsdkUILibInst, IDS_NUMUNKNOWNKEYS, StrRes, sizeof(StrRes));
	
		sprintf(MsgTxt,StrRes,options->mMissingKeyIDCount);

		SendDlgItemMessage (hDlg, IDC_KEYLISTBOX, LB_INSERTSTRING, -1, 
			(LPARAM)MsgTxt);
	}

	if(!bAtLeastOneValidSecretKey)
	{
		EnableWindow (GetDlgItem (hDlg, IDC_PHRASE1), FALSE);
		ShowWindow (GetDlgItem (hDlg, IDC_PHRASE1), SW_HIDE);
		EnableWindow (GetDlgItem (hDlg, IDC_HIDETYPING), FALSE);
		ShowWindow (GetDlgItem (hDlg, IDC_HIDETYPING), SW_HIDE);
		EnableWindow (GetDlgItem (hDlg, IDOK), FALSE);
		ShowWindow (GetDlgItem (hDlg, IDC_PROMPTSTRING), SW_HIDE);
		ShowWindow (GetDlgItem (hDlg, IDC_CANNOTDECRYPTTEXT),SW_SHOW);
	}
	else
	{
		EnableWindow (GetDlgItem (hDlg, IDC_PHRASE1), TRUE);
		ShowWindow (GetDlgItem (hDlg, IDC_PHRASE1), SW_SHOW);
		EnableWindow (GetDlgItem (hDlg, IDC_HIDETYPING), TRUE);
		ShowWindow (GetDlgItem (hDlg, IDC_HIDETYPING), SW_SHOW);
		EnableWindow (GetDlgItem (hDlg, IDOK), TRUE);
		ShowWindow (GetDlgItem (hDlg, IDC_PROMPTSTRING), SW_SHOW);
		ShowWindow (GetDlgItem (hDlg, IDC_CANNOTDECRYPTTEXT),SW_HIDE);
	}

	return bAtLeastOneValidSecretKey;
}*/
// My code begin here - Imad R. Faiad

//	Initialize List Control
VOID
SetupPGPListControl(HWND hWndListC)
{
	LV_COLUMN		lvC;
	INT				iNumBits;
	HIMAGELIST		hIml;
	HDC				hDC;
	HBITMAP			hBmp;

	// This was cannibalized from the FillKeyList function in KMKeyOps.c
	lvC.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lvC.fmt = LVCFMT_LEFT;
	lvC.cx = 270;  // pixel width of name column
	lvC.pszText = "Primary User ID";
	lvC.iSubItem = 0;
	ListView_InsertColumn (hWndListC, 0, &lvC);

	lvC.cx = 38;  // pixel width of key size column
	lvC.pszText = "Size";
	lvC.iSubItem = 1;
	ListView_InsertColumn (hWndListC, 1, &lvC);

	lvC.cx = 137;  // pixel width of key ID column
	lvC.pszText = "Key ID";
	lvC.iSubItem = 2;
	ListView_InsertColumn (hWndListC, 2, &lvC);

	// create image list
	hIml = ImageList_Create (16, 16, ILC_COLOR24 | ILC_MASK, 2, 0);

	// get color depth so we know which icon group to use
	hDC = GetDC (NULL);
	iNumBits = GetDeviceCaps (hDC, BITSPIXEL) * GetDeviceCaps (hDC, PLANES);
	ReleaseDC (NULL, hDC);

	// This assumes the edited icon bitmaps in the win32\shared directory.
	// If using the unedited bitmaps, change the 9 to 36 in both 
	// ImageList_Create calls and adjust the values of 
	// lvI.iImage in the InitEncryptedToKeyListBox function.
	if (iNumBits <= 8) {
		hIml = ImageList_Create (16, 16, ILC_COLOR|ILC_MASK, 13, 0);
		hBmp = LoadBitmap (gPGPsdkUILibInst, MAKEINTRESOURCE (IDB_MYADDED4));
		ImageList_AddMasked (hIml, hBmp, RGB(255, 0, 255));
		DeleteObject (hBmp);
	}
	else {
		hIml = ImageList_Create (16, 16, ILC_COLOR24|ILC_MASK, 13, 0);
		hBmp = LoadBitmap (gPGPsdkUILibInst, MAKEINTRESOURCE (IDB_MYADDED24));
		ImageList_AddMasked (hIml, hBmp, RGB(255, 0, 255));
		DeleteObject (hBmp);
	}
	ListView_SetImageList (hWndListC, hIml, LVSIL_SMALL);
}

//	____________________________
//
// Display a key in list control

VOID
SendToPGPListControl(CHAR szName[kPGPMaxUserIDSize], CHAR szKeySize[6], 
					 CHAR szKeyID[19], HWND hWndListC, LV_ITEM lvI)
{
	UINT	uIndex;

	lvI.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_STATE;
	lvI.state = 0;
	lvI.stateMask = 0;
	lvI.iItem = 0;
	lvI.iSubItem = 0;
	lvI.pszText	= szName;
	lvI.cchTextMax = 0;

	uIndex = ListView_InsertItem (hWndListC, &lvI);
	ListView_SetItemText (hWndListC, uIndex, 1, szKeySize);
	ListView_SetItemText (hWndListC, uIndex, 2, szKeyID);

	// The following lines shorten the first column by the width of 
	// the vertical scrollbar when it appears.
	// This assumes that the first column is 256 pixels wide
	// and that the list control's height is 65 dialog units.
	uIndex = ListView_GetItemCount (hWndListC);
	if (uIndex == 6) ListView_SetColumnWidth (hWndListC, 0, 
		270 - GetSystemMetrics(SM_CXVSCROLL));
}

//	____________________________
//
//  setup key display list box

BOOL 
AddKeySetToRecipientsTable (HWND hDlg, 
							PGPKeySetRef KeySet,
							CPGPDecryptionPassphraseDialogOptions *options) 
{
	BOOL			bAtLeastOneValidSecretKey	= FALSE;
	UINT			uUnknownKeys				= 0;
	PGPKeyListRef	KeyList;
	PGPKeyIterRef	KeyIter;
	PGPKeyRef		Key;
	PGPSubKeyRef	SubKey;
	UINT			u, uKeyBits, uAlgorithm;
	INT				iKeyDefault, iKeySelected;
	PGPBoolean		bSecret, bRevoked, bExpired, bCanDecrypt;
	CHAR			szName[kPGPMaxUserIDSize];
	CHAR			szKeyID[20];
	CHAR			szKeySize[6]; // room to grow for the terminally paranoid
	HWND			hWndListC;
	LV_ITEM			lvI;
	PGPKeyID		KeyID;
	CHAR			szID[kPGPMaxKeyIDStringSize];
	PGPError		err;


	hWndListC = GetDlgItem (hDlg, IDC_KEYLISTBOX);
	SetupPGPListControl (hWndListC);

	szKeySize[0] = '\0';
	lstrcat(szKeySize, "???");  // default keysize return value

	PGPOrderKeySet (KeySet, kPGPValidityOrdering, &KeyList);
	PGPNewKeyIter (KeyList, &KeyIter);

	iKeySelected = -1;
	iKeyDefault = -1;

	PGPKeyIterNext (KeyIter, &Key);
	while (Key) 
	{
		PGPGetKeyBoolean (Key, kPGPKeyPropIsSecret, &bSecret);
		PGPGetKeyBoolean (Key, kPGPKeyPropCanDecrypt, &bCanDecrypt);
		PGPGetKeyBoolean (Key, kPGPKeyPropIsRevoked, &bRevoked);
		PGPGetKeyBoolean (Key, kPGPKeyPropIsExpired, &bExpired);
		PGPGetKeyNumber (Key, kPGPKeyPropAlgID, (int *)&uAlgorithm);
		if (bSecret && &bCanDecrypt) bAtLeastOneValidSecretKey = TRUE;

		// get name on key
		PGPGetPrimaryUserIDNameBuffer (Key, sizeof(szName), 
										szName, &u);

		// get key ID
		PGPGetKeyIDFromKey (Key, &KeyID);
		PGPGetKeyIDString (&KeyID, kPGPKeyIDString_Full, szID);
		lstrcpyn (szKeyID, szID, 19);

		lvI.iImage = 8;

		// get key type and size
		switch (uAlgorithm){
		case kPGPPublicKeyAlgorithm_RSA :
			PGPGetKeyNumber (Key, kPGPKeyPropBits, (int *) &uKeyBits);
			wsprintf (szKeySize, "%i", uKeyBits);
			if (bSecret) {
				if (bRevoked) lvI.iImage = 2; // RSA revoked key
				else if (bExpired) lvI.iImage = 3; // RSA expired key
				else lvI.iImage = 0;  // blue RSA key
			}
			else lvI.iImage = 1; // RSA gray key (not on secring)
			break;

		case kPGPPublicKeyAlgorithm_DSA :
			PGPKeyIterNextSubKey (KeyIter, &SubKey);
			if (SubKey) {
				PGPGetSubKeyNumber (SubKey, kPGPKeyPropBits, (int *) &uKeyBits);
				wsprintf (szKeySize, "%i", uKeyBits);
			}
			if (bSecret) {
				if (bRevoked) lvI.iImage = 6; // DH revoked key
				else if (bExpired) lvI.iImage = 7; // DH expired key
				else lvI.iImage = 4;  // gold DH key
			}
			else lvI.iImage = 5; // DH gray key (not on secring)
			break;

		//BEGIN ElGamal Sign SUPPORT - Imad R. Faiad
		case kPGPPublicKeyAlgorithm_ElGamalSE :
			PGPGetKeyNumber (Key, kPGPKeyPropBits, (int *) &uKeyBits);
			wsprintf (szKeySize, "%i", uKeyBits);
			if (bSecret) {
				if (bRevoked) lvI.iImage = 11; // Elg revoked key
				else if (bExpired) lvI.iImage = 12; // Elg expired key
				else lvI.iImage = 9;  // Blue Elg key
			}
			else lvI.iImage = 10; // Elg gray key (not on secring)
			break;
		//END ElGamal Sign SUPPORT

		default :
			lvI.iImage = 8; // question mark
			break;
		}
		// send known key to list control and move to next key
		SendToPGPListControl(szName, szKeySize, szKeyID, 
							hWndListC, lvI);

		PGPKeyIterNext (KeyIter, &Key);
	}

	PGPFreeKeyIter (KeyIter);
	PGPFreeKeyList (KeyList);

	strcpy(szKeySize, "???");// <<<Insert to reset unknown keysize

		for (u=0; u<options->mMissingKeyIDCount; u++) {

		err = PGPGetKeyByKeyID (options->mKeySet, 
								&(options->mMissingKeyIDList[u]),
								kPGPPublicKeyAlgorithm_Invalid, 
								&Key);
			
		if (!PGPRefIsValid (Key) || IsPGPError (err)) {

			err = PGPGetKeyByKeyID (options->mKeySet, 
									&(options->mMissingKeyIDList[u]),
									kPGPPublicKeyAlgorithm_ElGamal, 
									&Key);
	
			if (!PGPRefIsValid (Key) || IsPGPError (err)) {
				PGPGetKeyIDString (&options->mMissingKeyIDList[u], kPGPKeyIDString_Full, szKeyID);
				lvI.iImage = 8;  // question mark
				SendToPGPListControl ("Unknown Key", szKeySize, szKeyID, 
									hWndListC, lvI);
			}
		}
	}


	return bAtLeastOneValidSecretKey;
}


BOOL 
InitEncryptedToKeyListBox (HWND hDlg, CPGPDecryptionPassphraseDialogOptions *options) 
{
	BOOL bAtLeastOneValidSecretKey;

	SendMessage(GetDlgItem(hDlg, IDC_KEYLISTBOX),LVM_DELETEALLITEMS,0,0);

	if(PGPKeySetRefIsValid( options->mKeySet ))
		bAtLeastOneValidSecretKey = AddKeySetToRecipientsTable( hDlg,options->mKeySet,options );

	if(options->mNewKeys!=NULL)
		if(PGPKeySetRefIsValid( *(options->mNewKeys) ))
			AddKeySetToRecipientsTable( hDlg,*(options->mNewKeys),options );

	if(!bAtLeastOneValidSecretKey)
	{
		EnableWindow (GetDlgItem (hDlg, IDC_PHRASE1), FALSE);
		ShowWindow (GetDlgItem (hDlg, IDC_PHRASE1), SW_HIDE);
		EnableWindow (GetDlgItem (hDlg, IDC_HIDETYPING), FALSE);
		ShowWindow (GetDlgItem (hDlg, IDC_HIDETYPING), SW_HIDE);
		//BEGIN FULL EDIT IN PASSWORD DIALOGS - Imad R. Faiad
		EnableWindow (GetDlgItem (hDlg, IDC_FULLEDIT), FALSE);
		ShowWindow (GetDlgItem (hDlg, IDC_FULLEDIT), SW_HIDE);
		//END FULL EDIT IN PASSWORD DIALOGS
		EnableWindow (GetDlgItem (hDlg, IDOK), FALSE);
		ShowWindow (GetDlgItem (hDlg, IDC_PROMPTSTRING), SW_HIDE);
		ShowWindow (GetDlgItem (hDlg, IDC_CANNOTDECRYPTTEXT),SW_SHOW);
	}
	else
	{
		EnableWindow (GetDlgItem (hDlg, IDC_PHRASE1), TRUE);
		ShowWindow (GetDlgItem (hDlg, IDC_PHRASE1), SW_SHOW);
		EnableWindow (GetDlgItem (hDlg, IDC_HIDETYPING), TRUE);
		ShowWindow (GetDlgItem (hDlg, IDC_HIDETYPING), SW_SHOW);
		//BEGIN FULL EDIT IN PASSWORD DIALOGS - Imad R. Faiad
		EnableWindow (GetDlgItem (hDlg, IDC_FULLEDIT), TRUE);
		ShowWindow (GetDlgItem (hDlg, IDC_FULLEDIT), SW_SHOW);
		//END FULL EDIT IN PASSWORD DIALOGS
		EnableWindow (GetDlgItem (hDlg, IDOK), TRUE);
		ShowWindow (GetDlgItem (hDlg, IDC_PROMPTSTRING), SW_SHOW);
		ShowWindow (GetDlgItem (hDlg, IDC_CANNOTDECRYPTTEXT),SW_HIDE);
	}

	return bAtLeastOneValidSecretKey;
}
//END KEY ID IN DECRYPTION DIALOG LIST CONTROL

//	____________________________
//
//  Truncate text string

VOID
TruncateKeyText (HDC	hdc, 
				 LPSTR	pszOrig, 
				 LPSTR	szInfo, 
				 INT	iXmax, 
				 LPSTR	pszTrunc) 
{
	SIZE	s;
	INT		l, iW;

	GetTextExtentPoint32 (hdc, szInfo, lstrlen (szInfo), &s);
	iXmax -= s.cx;

	if (iXmax <= 0) {
		lstrcpy (pszTrunc, "");
		return;
	}

	lstrcpy (pszTrunc, pszOrig);
	GetTextExtentPoint32 (hdc, pszOrig, lstrlen (pszOrig), &s);
	iW = s.cx + 4;

	l = lstrlen (pszOrig);
	if (l < 3) {
		if (iW > iXmax) lstrcpy (pszTrunc, "");
	}
	else {
		l = lstrlen (pszOrig) - 3;
		while ((iW > iXmax) && (l >= 0)) {
			lstrcpy (&pszTrunc[l], "...");
			GetTextExtentPoint32 (hdc, pszTrunc, lstrlen (pszTrunc), &s);
			iW = s.cx + 4;
			l--;
		}	
		if (l < 0) lstrcpy (pszTrunc, "");
	}

	lstrcat (pszTrunc, szInfo);
	
}
//BEGIN KEY ID IN SIGNING KEY COMBO BOX - Imad R. Faiad
//	_______________________________________________
//
//  Construct string representation of number of key bits

VOID 
GetKeyBitsString (
		PGPKeySetRef	KeySet, 
		PGPKeyRef		Key, 
		LPSTR			sz, 
		UINT			u) 
{
	UINT uAlg;
	UINT uKeyBits, uSubKeyBits;
	PGPSubKeyRef SubKey;
	PGPKeyListRef KeyList;
	PGPKeyIterRef KeyIter;
	PGPError err;
	CHAR szbuf[32];

	PGPGetKeyNumber (Key, kPGPKeyPropAlgID, (int *)&uAlg);
	switch (uAlg) {
	case kPGPPublicKeyAlgorithm_RSA :
		PGPGetKeyNumber (Key, kPGPKeyPropBits, (int *)&uKeyBits);
		wsprintf (szbuf, "%i", uKeyBits);
		lstrcpyn (sz, szbuf, u);
		break;

	case kPGPPublicKeyAlgorithm_DSA :
	//BEGIN ElGamal Sign SUPPORT - Imad R. Faiad
	case kPGPPublicKeyAlgorithm_ElGamalSE :
	//BEGIN ElGamal Sign SUPPORT
		// key key bits
		err = PGPGetKeyNumber (Key, kPGPKeyPropBits, (int *)&uKeyBits);
		wsprintf (szbuf, "%i", uKeyBits);

		// now try to get subkey bits
		PGPOrderKeySet (KeySet, kPGPAnyOrdering, &KeyList);
		PGPNewKeyIter (KeyList, &KeyIter);
		PGPKeyIterSeek (KeyIter, Key);
		PGPKeyIterNextSubKey (KeyIter, &SubKey);
		if (SubKey) {
			PGPGetSubKeyNumber (SubKey, kPGPKeyPropBits, (int *)&uSubKeyBits);
			wsprintf (szbuf, "%i/%i", uSubKeyBits, uKeyBits);
		}
		PGPFreeKeyIter (KeyIter);
		PGPFreeKeyList (KeyList);

		lstrcpyn (sz, szbuf, u);
		break;

	default :
		LoadString (gPGPsdkUILibInst, IDS_UNKNOWN, sz, u);
		break;
	}
}


void MyGetKeyString(HDC hdc,INT iComboWidth,PGPKeySetRef	KeySet,PGPKeyRef Key,char *szNameFinal)
{
	CHAR			sz1[32],sz2[32];
	CHAR			szName[kPGPMaxUserIDSize];
	PGPUInt32		uAlgorithm;
	UINT			u;
	PGPKeyID	KeyID;
	CHAR		szID[kPGPMaxKeyIDStringSize];

	PGPGetKeyNumber (Key, kPGPKeyPropAlgID, (int *)&uAlgorithm);

	// get key type / size info to append to name
	lstrcpy (sz2, "   (");
	switch (uAlgorithm) 
	{
		case kPGPPublicKeyAlgorithm_RSA :
			LoadString (gPGPsdkUILibInst, IDS_RSA, sz1, sizeof(sz1));
			lstrcat (sz2, sz1);
			lstrcat (sz2, "/");
			GetKeyBitsString (KeySet, Key, sz1, sizeof(sz1));
			lstrcat (sz2, sz1);
			lstrcat (sz2, ") - ");
			PGPGetKeyIDFromKey (Key, &KeyID);
			PGPGetKeyIDString (&KeyID, kPGPKeyIDString_Full, szID);
			lstrcpyn (sz1, szID, 19);
			
			lstrcat (sz2, sz1);
			break;

		case kPGPPublicKeyAlgorithm_DSA :
			LoadString (gPGPsdkUILibInst, IDS_DSS, sz1, sizeof(sz1));
			lstrcat (sz2, sz1);
			lstrcat (sz2, "/");
			GetKeyBitsString (KeySet, Key, sz1, sizeof(sz1));
			lstrcat (sz2, sz1);
			lstrcat (sz2, ") - ");
			PGPGetKeyIDFromKey (Key, &KeyID);
			PGPGetKeyIDString (&KeyID, kPGPKeyIDString_Full, szID);
			lstrcpyn (sz1, szID, 19);
			lstrcat (sz2, sz1);
			break;

		//BEGIN ElGamal Sign SUPPORT - Imad R. Faiad
		case kPGPPublicKeyAlgorithm_ElGamalSE :
			LoadString (gPGPsdkUILibInst, IDS_ELGAMAL, sz1, sizeof(sz1));
			lstrcat (sz2, sz1);
			lstrcat (sz2, "/");
			GetKeyBitsString (KeySet, Key, sz1, sizeof(sz1));
			lstrcat (sz2, sz1);
			lstrcat (sz2, ") - ");
			PGPGetKeyIDFromKey (Key, &KeyID);
			PGPGetKeyIDString (&KeyID, kPGPKeyIDString_Full, szID);
			lstrcpyn (sz1, szID, 19);
			lstrcat (sz2, sz1);
			break;
		//END ElGamal Sign SUPPORT

		default :
			LoadString (gPGPsdkUILibInst, IDS_UNKNOWN, sz1, sizeof(sz1));
			lstrcat (sz2, sz1);
			lstrcat (sz2, "/");
			lstrcat (sz2, sz1);
			lstrcat (sz2, ")");
			break;
	}
		


	// get name on key
	PGPGetPrimaryUserIDNameBuffer (Key, sizeof(szName),szName, &u);
	TruncateKeyText (hdc, szName, sz2, iComboWidth, szNameFinal);
}
//END KEY ID IN SIGNING KEY COMBO BOX
void GetKeyString(HDC hdc,INT iComboWidth,PGPKeyRef Key,char *szNameFinal)
{
	CHAR			sz1[64],sz2[64];
	CHAR			szName[kPGPMaxUserIDSize];
	PGPUInt32		uAlgorithm,uKeyBits;
	UINT			u;
	//BEGIN KEY ID IN SIGNING KEY COMBO BOX - Imad R. Faiad
	PGPKeyID	KeyID;
	CHAR		szID[kPGPMaxKeyIDStringSize];
	//END KEY ID IN SIGNING KEY COMBO BOX

	PGPGetKeyNumber (Key, kPGPKeyPropAlgID, (int *)&uAlgorithm);

	// get key type / size info to append to name
	lstrcpy (sz2, "   (");
	switch (uAlgorithm) 
	{
		case kPGPPublicKeyAlgorithm_RSA :
			LoadString (gPGPsdkUILibInst, IDS_RSA, sz1, sizeof(sz1));
			lstrcat (sz2, sz1);
			lstrcat (sz2, "/");
			PGPGetKeyNumber (Key, kPGPKeyPropBits, (int *)&uKeyBits);
			//BEGIN KEY ID IN SIGNING KEY COMBO BOX - Imad R. Faiad
			//wsprintf (sz1, "%i", uKeyBits);
			wsprintf (sz1, "%i) - ", uKeyBits);
			lstrcat (sz2, sz1);
			PGPGetKeyIDFromKey (Key, &KeyID);
			PGPGetKeyIDString (&KeyID, kPGPKeyIDString_Full, szID);
			lstrcpyn (sz1, szID, 19);
			//END KEY ID IN SIGNING KEY COMBO BOX
			lstrcat (sz2, sz1);
			break;

		case kPGPPublicKeyAlgorithm_DSA :
			LoadString (gPGPsdkUILibInst, IDS_DSS, sz1, sizeof(sz1));
			lstrcat (sz2, sz1);
			lstrcat (sz2, "/");
			PGPGetKeyNumber (Key, kPGPKeyPropBits, (int *)&uKeyBits);
			//BEGIN KEY ID IN SIGNING KEY COMBO BOX - Imad R. Faiad
			//wsprintf (sz1, "%i", uKeyBits);
			wsprintf (sz1, "%i) - ", uKeyBits);
			lstrcat (sz2, sz1);
			PGPGetKeyIDFromKey (Key, &KeyID);
			PGPGetKeyIDString (&KeyID, kPGPKeyIDString_Full, szID);
			lstrcpyn (sz1, szID, 19);
			//END KEY ID IN SIGNING KEY COMBO BOX
			lstrcat (sz2, sz1);
			break;


		//BEGIN ElGamal Sign SUPPORT - Imad R. Faiad
		case kPGPPublicKeyAlgorithm_ElGamalSE :
			LoadString (gPGPsdkUILibInst, IDS_ELGAMAL, sz1, sizeof(sz1));
			lstrcat (sz2, sz1);
			lstrcat (sz2, "/");
			PGPGetKeyNumber (Key, kPGPKeyPropBits, (int *)&uKeyBits);
			//BEGIN KEY ID IN SIGNING KEY COMBO BOX - Imad R. Faiad
			//wsprintf (sz1, "%i", uKeyBits);
			wsprintf (sz1, "%i) - ", uKeyBits);
			lstrcat (sz2, sz1);
			PGPGetKeyIDFromKey (Key, &KeyID);
			PGPGetKeyIDString (&KeyID, kPGPKeyIDString_Full, szID);
			lstrcpyn (sz1, szID, 19);
			//END KEY ID IN SIGNING KEY COMBO BOX
			lstrcat (sz2, sz1);
			break;
		//END ElGamal Sign SUPPORT
		default :
			LoadString (gPGPsdkUILibInst, IDS_UNKNOWN, sz1, sizeof(sz1));
			lstrcat (sz2, sz1);
			lstrcat (sz2, "/");
			lstrcat (sz2, sz1);
			//BEGIN KEY ID IN SIGNING KEY COMBO BOX - Imad R. Faiad
			lstrcat (sz2, ")");
			//END KEY ID IN SIGNING KEY COMBO BOX
			break;
	}

	//BEGIN KEY ID IN SIGNING KEY COMBO BOX - Imad R. Faiad
	//lstrcat (sz2, ")");
	//END KEY ID IN SIGNING KEY COMBO BOX

	// get name on key
	PGPGetPrimaryUserIDNameBuffer (Key, sizeof(szName),szName, &u);
	TruncateKeyText (hdc, szName, sz2, iComboWidth, szNameFinal);
}


//	____________________________
//
//  setup keyselection combo box

BOOL 
InitSigningKeyComboBox (HWND hDlg, CPGPKeySetPassphraseDialogOptions *options) 
{
	PGPKeyListRef	KeyList;
	PGPKeyIterRef	KeyIter;
	PGPKeyRef		Key;
	PGPKeyRef		KeyDefault;
	UINT			uIndex;
	INT				iKeyDefault, iKeySelected;
	PGPBoolean		bSecret, bRevoked, bExpired, bCanSign;
	BOOL			bAtLeastOneSecretKey;
	CHAR			szNameFinal[kPGPMaxUserIDSize];
	HDC				hdc;
	RECT			rc;
	INT				iComboWidth;
	HFONT			hFont;

	PGPOrderKeySet (options->mKeySet, kPGPValidityOrdering, &KeyList);
	PGPNewKeyIter (KeyList, &KeyIter);
	PGPGetDefaultPrivateKey (options->mKeySet, &KeyDefault);

	SendDlgItemMessage (hDlg, IDC_SIGNKEYCOMBO, CB_GETDROPPEDCONTROLRECT,
						0, (LPARAM)&rc);
	iComboWidth = rc.right-rc.left - GetSystemMetrics (SM_CXVSCROLL);
	hdc = GetDC (GetDlgItem (hDlg, IDC_SIGNKEYCOMBO));
	hFont = (HFONT)GetStockObject (DEFAULT_GUI_FONT);
	SelectObject (hdc, hFont);

	iKeySelected = -1;
	iKeyDefault = 0;

	bAtLeastOneSecretKey = FALSE;

	PGPKeyIterNext (KeyIter, &Key);
	while (Key) {
		PGPGetKeyBoolean (Key, kPGPKeyPropIsSecret, &bSecret);
		if (bSecret) {
			PGPGetKeyBoolean (Key, kPGPKeyPropIsRevoked, (unsigned char *)&bRevoked);
			PGPGetKeyBoolean (Key, kPGPKeyPropIsExpired, (unsigned char *)&bExpired);
			PGPGetKeyBoolean (Key, kPGPKeyPropCanSign, (unsigned char *)&bCanSign);
			if (!bRevoked && !bExpired && bCanSign) {
				bAtLeastOneSecretKey = TRUE;

				//BEGIN KEY ID IN SIGNING KEY COMBO BOX - Imad R. Faiad
				MyGetKeyString(hdc,iComboWidth,options->mKeySet,Key,szNameFinal);
				//GetKeyString(hdc,iComboWidth,Key,szNameFinal);
				//END KEY ID IN SIGNING KEY COMBO BOX

				uIndex = SendDlgItemMessage (hDlg, IDC_SIGNKEYCOMBO, 
								CB_ADDSTRING, 0, (LPARAM)szNameFinal);
				if (uIndex != CB_ERR) {
					SendDlgItemMessage (hDlg, IDC_SIGNKEYCOMBO, 
								CB_SETITEMDATA, uIndex, (LPARAM)Key);
					if (options->mDefaultKey) {
						if (Key == options->mDefaultKey) 
							iKeySelected = uIndex;
					}
					if (Key == KeyDefault) iKeyDefault = uIndex;
				}
			}
		}
		PGPKeyIterNext (KeyIter, &Key);
	}
	PGPFreeKeyIter (KeyIter);
	PGPFreeKeyList (KeyList);

	if (iKeySelected == -1) iKeySelected = iKeyDefault;
	SendDlgItemMessage (hDlg, IDC_SIGNKEYCOMBO, CB_SETCURSEL, 
							iKeySelected, 0);

	ReleaseDC (GetDlgItem (hDlg, IDC_SIGNKEYCOMBO), hdc);

	return (bAtLeastOneSecretKey);

}

BOOL PassphraseLengthAndQualityOK(HWND hwnd,
								  CPGPPassphraseDialogOptions *options,
								  char *Passphrase)
{
	if(options->mMinPassphraseLength!=0)
	{
		if(strlen(Passphrase)<options->mMinPassphraseLength)
		{
			PGPsdkUIMessageBox (hwnd,
				IDS_PGPERROR,IDS_PASSNOTLONG,
				MB_OK|MB_ICONSTOP);

			return FALSE;
		}
	}

	if(options->mMinPassphraseQuality!=0)
	{
		if(PGPEstimatePassphraseQuality(Passphrase)<options->mMinPassphraseQuality)
		{
			PGPsdkUIMessageBox (hwnd,
				IDS_PGPERROR,IDS_PASSNOTQUALITY,
				MB_OK|MB_ICONSTOP);

			return FALSE;
		}
	}

	return TRUE;
}

//	______________________________________________________________
//
//  Enable or disable passphrase edit box on basis of selected key

VOID 
EnablePassPhraseControl (HWND hDlg) 
{
	PGPKeyRef	Key;
	PGPBoolean	bNeedsPhrase,bShared;
	BOOL		bEnabled;
	INT			i;

	bEnabled = FALSE;

	i = SendDlgItemMessage (hDlg, IDC_SIGNKEYCOMBO, CB_GETCURSEL, 0, 0);
	if (i != CB_ERR) 
	{					
		Key = (PGPKeyRef)SendDlgItemMessage (hDlg, IDC_SIGNKEYCOMBO, 
											CB_GETITEMDATA, i, 0);
		if (Key) 
		{
			PGPGetKeyBoolean(Key, kPGPKeyPropNeedsPassphrase, &bNeedsPhrase);
			PGPGetKeyBoolean(Key, kPGPKeyPropIsSecretShared, &bShared);

			if(bShared)
			{
				EnableWindow (GetDlgItem (hDlg, IDC_PHRASE1), FALSE);
				ShowWindow (GetDlgItem (hDlg, IDC_PHRASE1), SW_HIDE);
				EnableWindow (GetDlgItem (hDlg, IDC_HIDETYPING), FALSE);
				ShowWindow (GetDlgItem (hDlg, IDC_HIDETYPING), SW_HIDE);
				//BEGIN FULL EDIT IN PASSWORD DIALOGS - Imad R. Faiad
				EnableWindow (GetDlgItem (hDlg, IDC_FULLEDIT), FALSE);
				ShowWindow (GetDlgItem (hDlg, IDC_FULLEDIT), SW_HIDE);
				//END FULL EDIT IN PASSWORD DIALOGS
				ShowWindow (GetDlgItem (hDlg, IDC_PROMPTSTRING), SW_HIDE);
				ShowWindow (GetDlgItem (hDlg, IDC_SPLITINFO),SW_SHOW);
			}
			else
			{
				if (bNeedsPhrase) bEnabled = TRUE;

				if (!bEnabled) 
					SetDlgItemText (hDlg, IDC_PHRASE1, "");

				EnableWindow (GetDlgItem (hDlg, IDC_PHRASE1), bEnabled);
				ShowWindow (GetDlgItem (hDlg, IDC_PHRASE1), SW_SHOW);
				EnableWindow (GetDlgItem (hDlg, IDC_HIDETYPING), bEnabled);
				ShowWindow (GetDlgItem (hDlg, IDC_HIDETYPING), SW_SHOW);
				//BEGIN FULL EDIT IN PASSWORD DIALOGS - Imad R. Faiad
				EnableWindow (GetDlgItem (hDlg, IDC_FULLEDIT), bEnabled);
				ShowWindow (GetDlgItem (hDlg, IDC_FULLEDIT), SW_SHOW);
				//END FULL EDIT IN PASSWORD DIALOGS
				ShowWindow (GetDlgItem (hDlg, IDC_PROMPTSTRING), SW_SHOW);
				ShowWindow (GetDlgItem (hDlg, IDC_SPLITINFO),SW_HIDE);
			}
		}
	}
}

//	____________________________
//
//  search keys for matching phrase

PGPError 
ValidateSigningPhrase (HWND hDlg, 
				GPP *gpp, 
				LPSTR pszPhrase, 
				PGPKeyRef key) 
{
	CHAR	szName[kPGPMaxUserIDSize];
	CHAR	sz[128];
	//BEGIN KEY INFO IN FOUND KEY DIALOG - Imad R. Faiad
	//CHAR	sz2[kPGPMaxUserIDSize + 128];
	PGPUInt32	uAlgorithm;
	PGPKeyID	KeyID;
	CHAR		szKeyType[10];
	CHAR		szKeySize[15];
	CHAR		szKeyID[kPGPMaxKeyIDStringSize];
	CHAR		sz2[kPGPMaxUserIDSize + kPGPMaxKeyIDStringSize + 128 + 25];
	//END KEY INFO IN FOUND KEY DIALOG
	PGPSize	size;
	CPGPSigningPassphraseDialogOptions *options;

	options=(CPGPSigningPassphraseDialogOptions *)gpp->options;

	// does phrase match selected key ?
	if (PGPPassphraseIsValid (key, 
			PGPOPassphrase (gpp->context, pszPhrase),
			PGPOLastOption (gpp->context))) {
		*(options->mPassphraseKeyPtr) = key;
		return kPGPError_NoErr;
	}

	if(options->mFindMatchingKey)
	{
		// does phrase match any private key ?
		key=GetKeyForPassphrase(options->mKeySet,
			//BEGIN SUBKEY PASSPHRASE MOD - Disastry
            0,0,
			//END SUBKEY PASSPHRASE MOD
			pszPhrase,TRUE);

		if (key!=NULL) 
		{
			// ask user to use other key

			//BEGIN KEY INFO IN FOUND KEY DIALOG - Imad R. Faiad
			//LoadString (gPGPsdkUILibInst, IDS_FOUNDMATCHFORPHRASE, sz, sizeof(sz));
			PGPGetPrimaryUserIDNameBuffer (key, sizeof(szName), szName, &size);

			PGPGetKeyNumber (key, kPGPKeyPropAlgID, (int *)&uAlgorithm);

			switch (uAlgorithm) 
			{
			case kPGPPublicKeyAlgorithm_RSA :
				LoadString (gPGPsdkUILibInst, IDS_RSA, szKeyType, sizeof(szKeyType));
				break;
			case kPGPPublicKeyAlgorithm_DSA :
				LoadString (gPGPsdkUILibInst, IDS_DSS, szKeyType, sizeof(szKeyType));
				break;
			case kPGPPublicKeyAlgorithm_ElGamalSE :
				strcpy(szKeyType,"ElGamal");
				break;
			default :
				LoadString (gPGPsdkUILibInst, IDS_UNKNOWN, szKeyType, sizeof(szKeyType));
				break;
			}
			
			GetKeyBitsString (options->mKeySet, key, szKeySize, sizeof(szKeySize));
			
			PGPGetKeyIDFromKey (key, &KeyID);
			PGPGetKeyIDString (&KeyID, kPGPKeyIDString_Full, szKeyID);

			wsprintf (sz2,
				"The key with user ID\n\n%s\nKeyID: %s\nType/Size:%s/%s\nmatches the passphrase.\n\nSign with this key instead?",
				szName, szKeyID, szKeyType,szKeySize );
			//wsprintf (sz2, sz, szName);
			//END KEY INFO IN FOUND KEY DIALOG

			LoadString (gPGPsdkUILibInst, IDS_PGP, sz, sizeof(sz));
			if (MessageBox (hDlg, sz2, sz, MB_ICONQUESTION|MB_YESNO) == IDYES) 
			{
				*(options->mPassphraseKeyPtr) = key;
				return kPGPError_NoErr;
			}
			return kPGPError_BadPassphrase;
		}
	}

	// phrase doesn't match any key
	PGPsdkUIMessageBox (hDlg,
		IDS_PGPERROR,IDS_BADPASSREENTER,
		MB_OK|MB_ICONSTOP);

	LoadString (gPGPsdkUILibInst, IDS_WRONGPHRASE, sz, sizeof (sz));
	SetDlgItemText (hDlg, IDC_PROMPTSTRING, sz);
	
	return kPGPError_BadPassphrase;

}
//BEGIN TYPO FIX - Imad R. Faiad
// CommonPhraseMsgProc (
BOOL CommonPhraseMsgProc (
//END TYPO FIX
		HWND	hwnd, 
		UINT	uMsg, 
		WPARAM	wParam, 
		LPARAM	lParam) 
{
    switch (uMsg) 
	{
		case WM_CONTEXTMENU:
		{
			char szHelpFile[MAX_PATH+1];

			GetHelpDir(szHelpFile);

			WinHelp ((HWND) wParam, szHelpFile, HELP_CONTEXTMENU, 
				(DWORD) (LPVOID) aIds); 
			return TRUE;
		}

		case WM_KEYUP:
		{
			SetCapsLockMessageState(GetParent(hwnd));
			break;
		}

//		case WM_RBUTTONDOWN :
//		case WM_CONTEXTMENU :
		case WM_LBUTTONDBLCLK :
		case WM_MOUSEMOVE :
		case WM_COPY :
		case WM_CUT :
 		case WM_PASTE :
		case WM_CLEAR :
		//BEGIN FULL EDIT IN PASSWORD DIALOGS - Imad R. Faiad
		{
			GPP *gpp;			

			gpp=(GPP *)GetWindowLong (GetParent(hwnd), GWL_USERDATA);

			if (gpp->bFullEdit)
				return FALSE;
			else
				return TRUE;
		}
		//END FULL EDIT IN PASSWORD DIALOGS

		case WM_LBUTTONDOWN :
			if (GetKeyState (VK_SHIFT) & 0x8000) return TRUE;
			break;

		case WM_PAINT :
		{
			GPP *gpp;

			gpp=(GPP *)GetWindowLong (GetParent(hwnd), GWL_USERDATA);

			if (wParam) 
			{
				SetBkColor ((HDC)wParam, GetSysColor (COLOR_WINDOW));
				if (gpp->bHideText) 
					SetTextColor ((HDC)wParam, GetSysColor (COLOR_WINDOW));
				else 
					SetTextColor ((HDC)wParam, GetSysColor (COLOR_WINDOWTEXT));
			}
			break; 
		}

		case WM_KEYDOWN :
			if (GetKeyState (VK_SHIFT) & 0x8000) 
			{
				switch (wParam) 
				{
					case VK_HOME :
					case VK_END :
					case VK_UP :
					case VK_DOWN :
					case VK_LEFT :
					case VK_RIGHT :
					case VK_NEXT :
					case VK_PRIOR :
						//BEGIN FULL EDIT IN PASSWORD DIALOGS - Imad R. Faiad
						//return TRUE;
						{
							GPP *gpp;
							gpp=(GPP *)GetWindowLong (GetParent(hwnd), GWL_USERDATA);
							if (gpp->bFullEdit)
								return FALSE;
							else
								return TRUE;
						}
						//END FULL EDIT IN PASSWORD DIALOGS
				}
			}
			break;

		case WM_SETFOCUS :
			SendMessage (hwnd, EM_SETSEL, 0xFFFF, 0xFFFF);
			break;
	}
    return FALSE; 
} 

//	______________________________________
//
//  Passphrase edit box subclass procedure

LRESULT APIENTRY 
PhraseSubclassProc (
		HWND	hWnd, 
		UINT	uMsg, 
		WPARAM	wParam, 
		LPARAM	lParam) 
{
	UINT				uQuality;
	CHAR *				szBuf;
	LRESULT				lResult;
	BOOL				OKactive;
	GPP					 *gpp;

	gpp=(GPP *)GetWindowLong (GetParent(hWnd), GWL_USERDATA);

	if (CommonPhraseMsgProc (hWnd, uMsg, wParam, lParam)) return 0;

	switch (uMsg) 
	{
		case WM_GETTEXT :
		{
			if (!gpp->pszPassPhrase) return 0;
			lParam = (LPARAM)gpp->pszPassPhrase;
			break;
		}

		case WM_CHAR :
		{
			if (wParam == VK_TAB) 
			{
				if (GetKeyState (VK_SHIFT) & 0x8000) 
					SetFocus (GetDlgItem (GetParent (hWnd), IDC_HIDETYPING));
				else 
					SetFocus (GetDlgItem (GetParent (hWnd), gpp->iNextTabControl));
			}
			else 
			{
				OKactive=TRUE;

				lResult = CallWindowProc (gpp->wpOrigPhrase1Proc, 
					hWnd, uMsg, wParam, lParam); 

				// Get our passphrase in secure memory
				szBuf=(char *)secAlloc(gpp->context,1024);
				CallWindowProc (gpp->wpOrigPhrase1Proc, 
					hWnd, WM_GETTEXT, 1024, (LPARAM)szBuf); 

				// Estimate its quality
				uQuality=pgpEstimatePassphraseQuality(szBuf);
/*
				// Check length for setting OK to TRUE
				if(options->mMinPassphraseLength!=0)
				{
					if(strlen(szBuf)<options->mMinPassphraseLength)
					{
						OKactive=FALSE;
					}
				}
*/
				// Free the passphrase
				memset (szBuf, 0, sizeof(szBuf));
				secFree(szBuf);

				// Check Quality for setting OK to TRUE
				if(gpp->options->mMinPassphraseQuality!=0)
				{
					if(uQuality<gpp->options->mMinPassphraseQuality)
					{
						OKactive=FALSE;
					}
				}
	
				if(gpp->hwndQuality)
				{
					// Set new quality
					SendMessage (gpp->hwndQuality, PBM_SETPOS, uQuality, 0);
				}

				// Enable/disable OK
				EnableWindow (GetDlgItem (GetParent(hWnd), IDOK), OKactive);
				return lResult;
			}
			break;
		}
	}
    return CallWindowProc (gpp->wpOrigPhrase1Proc, 
		hWnd, uMsg, wParam, lParam); 
} 

//	______________________________________
//
//  Passphrase edit box subclass procedure

LRESULT APIENTRY 
PhraseConfirmSubclassProc (
		HWND	hWnd, 
		UINT	uMsg, 
		WPARAM	wParam, 
		LPARAM	lParam) 
{
	GPP *gpp;

	gpp=(GPP *)GetWindowLong (GetParent(hWnd), GWL_USERDATA);

	if (CommonPhraseMsgProc (hWnd, uMsg, wParam, lParam)) return 0;

	switch (uMsg) 
	{
		case WM_GETTEXT :
			if (!gpp->pszPassPhraseConf) return 0;
			lParam = (LPARAM)gpp->pszPassPhraseConf;
			break;

		case WM_CHAR :
			if (wParam == VK_TAB) 
			{
				if (GetKeyState (VK_SHIFT) & 0x8000) 
					SetFocus (GetDlgItem (GetParent (hWnd), IDC_PHRASE2));
				else SetFocus (GetDlgItem (GetParent (hWnd), IDOK));
			}
			break;
	}

    return CallWindowProc(gpp->wpOrigPhrase2Proc, 
		hWnd, uMsg, wParam, lParam); 
} 

BOOL CALLBACK 
DoCommonCalls (
		HWND	hDlg, 
		UINT	uMsg, 
		WPARAM	wParam,
		LPARAM	lParam) 
{
	GPP *gpp;

	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			CPGPPassphraseDialogOptions *options;

			SetWindowLong (hDlg, GWL_USERDATA, lParam);
			gpp=(GPP *)lParam;

			options = (CPGPPassphraseDialogOptions *)gpp->options;

			if(options->mWindowTitle)
				SetWindowText(hDlg,options->mWindowTitle);

			if(options->mPrompt)
				SetDlgItemText (hDlg, IDC_PROMPTSTRING, options->mPrompt);

			gpp->bHideText = TRUE;
			CheckDlgButton (hDlg, IDC_HIDETYPING, BST_CHECKED);

			gpp->bFullEdit = FALSE;
			CheckDlgButton (hDlg, IDC_FULLEDIT, BST_UNCHECKED);

			SetCapsLockMessageState(hDlg);

			SetForegroundWindow (hDlg);

			// Force focus to passphrase box
			SetFocus(GetDlgItem(hDlg, IDC_PHRASE1));
			break;
		}

		case WM_KEYUP:
		{
			SetCapsLockMessageState(hDlg);
			break;
		}

		case WM_HELP:
		{
			char szHelpFile[MAX_PATH+1];

			GetHelpDir(szHelpFile);

			WinHelp ((HWND)(((LPHELPINFO) lParam)->hItemHandle), szHelpFile, 
			 HELP_WM_HELP, (DWORD) (LPSTR) aIds); 
			break; 
		}

		case WM_CONTEXTMENU:
		{
			char szHelpFile[MAX_PATH+1];

			GetHelpDir(szHelpFile);

			WinHelp ((HWND) wParam, szHelpFile, HELP_CONTEXTMENU, 
				(DWORD) (LPVOID) aIds); 
			break; 
		}

		case WM_QUIT:
		case WM_CLOSE:
		case WM_DESTROY: 
		{
			HWND hwndPhrase1,hwndPhrase2;

			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);

			ClearPassphrases(hDlg,gpp);

			hwndPhrase1=GetDlgItem(hDlg, IDC_PHRASE1);
			hwndPhrase2=GetDlgItem(hDlg, IDC_PHRASE2);

			if(hwndPhrase1)
			{
				SetWindowLong (hwndPhrase1,
					   GWL_WNDPROC, 
					   (LONG)gpp->wpOrigPhrase1Proc);
			}

			if(hwndPhrase2)
			{
				SetWindowLong (hwndPhrase2, 
					   GWL_WNDPROC, 
					   (LONG)gpp->wpOrigPhrase2Proc);
			}

			EndDialog(hDlg,kPGPError_UserAbort);
			break;
		}

		case WM_CTLCOLOREDIT:
		{
			HWND hwndPhrase1,hwndPhrase2;

			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);

			hwndPhrase1=GetDlgItem(hDlg, IDC_PHRASE1);
			hwndPhrase2=GetDlgItem(hDlg, IDC_PHRASE2);

			if(lParam==0)
				break;

			if (((HWND)lParam == hwndPhrase1) ||
				((HWND)lParam == hwndPhrase2)) 
			{
				SetBkColor ((HDC)wParam, GetSysColor (COLOR_WINDOW));
				if (gpp->bHideText) 
					SetTextColor ((HDC)wParam, GetSysColor (COLOR_WINDOW));
				else 
					SetTextColor ((HDC)wParam, 
							  GetSysColor (COLOR_WINDOWTEXT));
				return (BOOL)CreateSolidBrush (GetSysColor (COLOR_WINDOW));
			}
			break;
		}

		case WM_COMMAND:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);

			switch(LOWORD (wParam)) 
			{
				case IDCANCEL:
					EndDialog (hDlg, kPGPError_UserAbort);
					break;

				case IDC_FULLEDIT :
					if (IsDlgButtonChecked (hDlg, IDC_FULLEDIT) == BST_CHECKED) 
						gpp->bFullEdit = TRUE;
					else 
						gpp->bFullEdit = FALSE;
					break;

				case IDC_HIDETYPING :
				{
					HWND hwndPhrase1,hwndPhrase2;
	
					hwndPhrase1=GetDlgItem(hDlg, IDC_PHRASE1);
					hwndPhrase2=GetDlgItem(hDlg, IDC_PHRASE2);

					if (IsDlgButtonChecked (hDlg, IDC_HIDETYPING)
							== BST_CHECKED) 
						gpp->bHideText = TRUE;
					else 
						gpp->bHideText = FALSE;

					if(hwndPhrase1!=NULL)
						InvalidateRect (hwndPhrase1, NULL, TRUE);

					if(hwndPhrase2!=NULL)
						InvalidateRect (hwndPhrase2, NULL, TRUE);
					break;
				}
			}
			break;	
		}
	}

	return FALSE;
}

HWND DisplayOptions(HWND hDlg,PGPOptionListRef options,int y)
{
	if(options==NULL)
	{
		return NULL;
	}
	else
	{
		RECT rc;

		GetWindowRect(hDlg,&rc);

		SetWindowPos (hDlg, 
			NULL, 0, 0,
			rc.right-rc.left,rc.bottom-rc.top+45,
				SWP_NOMOVE|SWP_NOZORDER);

		return CreateOptionsControl(hDlg,
			options,
			10,y,
			200,71);
	}
}

// ****************************************************************************
// ****************************************************************************

//	________________________
//
//  Dialog Message procedure

BOOL CALLBACK 
pgpPassphraseDlgProc (
		HWND	hDlg, 
		UINT	uMsg, 
		WPARAM	wParam,
		LPARAM	lParam) 
{
	CPGPPassphraseDialogOptions *options;
	GPP				*gpp;
	INT				i;
	BOOL			Common;

	Common=DoCommonCalls (hDlg,uMsg,wParam,lParam); 

	if(Common)
		return Common;

	switch (uMsg) 
	{
		case WM_INITDIALOG:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPPassphraseDialogOptions *)
				gpp->options;
	
			gpp->iNextTabControl = IDOK;

			gpp->wpOrigPhrase1Proc = (WNDPROC) SetWindowLong (
				GetDlgItem (hDlg, IDC_PHRASE1), 
				GWL_WNDPROC, 
				(LONG) PhraseSubclassProc); 

			gpp->hwndOptionsControl=DisplayOptions(hDlg,options->mDialogOptions,107);
			return FALSE;
		}

		case WM_COMMAND:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPPassphraseDialogOptions *)
				gpp->options;
	
			switch(LOWORD (wParam)) 
			{
				case IDOK: 
				{
					FreePassphrases(gpp);

					i = SendDlgItemMessage (hDlg, IDC_PHRASE1, 
						WM_GETTEXTLENGTH, 0, 0) +1;

					gpp->szDummy = (char *)secAlloc (gpp->context, i);

					if(gpp->szDummy)
					{
						gpp->pszPassPhrase = (char *)secAlloc (gpp->context, i);

						if (gpp->pszPassPhrase) 
						{
							GetDlgItemText (hDlg, IDC_PHRASE1, gpp->szDummy, i);

							if(PassphraseLengthAndQualityOK(hDlg,options,gpp->pszPassPhrase))
							{
								ClearPassphrases(hDlg,gpp);
								SaveOptionSettings(gpp->hwndOptionsControl);
								EndDialog (hDlg, kPGPError_NoErr);
								break;
							}
							// Passphrase quality not enough
							ClearPassphrases(hDlg,gpp);
							FreePassphrases(gpp);
							break;
						}
					}
						
					// Couldn't allocate passphrases
					ClearPassphrases(hDlg,gpp);
					FreePassphrases(gpp);
					EndDialog (hDlg, kPGPError_OutOfMemory);
					break;
				}
			}
			break;
		}
	}
	return FALSE;
}

// Just a simple decryption
	PGPError
pgpPassphraseDialogPlatform(
	PGPContextRef					context,
	CPGPPassphraseDialogOptions 	*options)
{
	if (options->mTextUI) {
		return pgpPassphraseCL(context, options);
	} else {
		PGPError err;
		GPP	gpp;
		memset(&gpp,0x00,sizeof(GPP));
		gpp.context=context;
		gpp.options=options;
		
		InitRandomKeyHook(&hhookKeyboard, &hhookMouse);
		InstallSecurityHooks();
		
		err = DialogBoxParam (gPGPsdkUILibInst, 
							  MAKEINTRESOURCE (IDD_PASSPHRASE), 
							  options->mHwndParent,
							  (DLGPROC)pgpPassphraseDlgProc, (LPARAM)&gpp);
		
		*(options->mPassphrasePtr)=gpp.pszPassPhrase;
		
		UninstallSecurityHooks();
		UninitRandomKeyHook(hhookKeyboard, hhookMouse);
		
		return(err);
	}
}

//	________________________
//
//  Dialog Message procedure

static PGPBoolean Working=FALSE;

//BEGIN KEY ID IN DECRYPTION DIALOG LIST CONTROL - Imad R. Faiad
// 
/* The old code is withing this comment block
BOOL CALLBACK 
pgpDecryptionPassphraseDlgProc (
		HWND	hDlg, 
		UINT	uMsg, 
		WPARAM	wParam,
		LPARAM	lParam) 
{
	CPGPDecryptionPassphraseDialogOptions *options;
	GPP				*gpp;
	INT				i;
	DWORD			Common;

	Common=DoCommonCalls (hDlg,uMsg,wParam,lParam); 

	if(Common)
		return Common;

	switch (uMsg) 
	{
		case WM_INITDIALOG:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPDecryptionPassphraseDialogOptions *)
				gpp->options;

			gpp->iNextTabControl = IDOK;

			InitEncryptedToKeyListBox (hDlg, options);

			gpp->wpOrigPhrase1Proc = (WNDPROC) SetWindowLong (
				GetDlgItem (hDlg, IDC_PHRASE1), 
				GWL_WNDPROC, 
				(LONG) PhraseSubclassProc); 

			gpp->hwndOptionsControl=DisplayOptions(hDlg,options->mDialogOptions,200);

			return FALSE;
		}


		case WM_COMMAND:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPDecryptionPassphraseDialogOptions *)
				gpp->options;

			switch(LOWORD (wParam)) 
			{

				case IDC_KEYLISTBOX:
				{
					if(HIWORD(wParam)==LBN_DBLCLK)
					{
						if(!Working)
						{
							Working=TRUE;

							if(IsntNull(options->mMissingKeyIDList))
							{
								PGPError	err;
								PGPBoolean	haveNewKeys;

								err=options->SearchForMissingKeys( hDlg, &haveNewKeys );

								PGPsdkUIErrorBox (hDlg,err);
								
								if( haveNewKeys )
								{
									InitEncryptedToKeyListBox (hDlg, options);
								}
							}
					
							Working=FALSE;
						}
					}
					break;
				}

				case IDOK: 
				{
					FreePassphrases(gpp);

					i = SendDlgItemMessage (hDlg, IDC_PHRASE1, 
						WM_GETTEXTLENGTH, 0, 0) +1;

					gpp->szDummy = (char *)secAlloc (gpp->context, i);

					if(gpp->szDummy)
					{
						gpp->pszPassPhrase = (char *)secAlloc (gpp->context, i);

						if (gpp->pszPassPhrase) 
						{
							CHAR sz[256];

							GetDlgItemText (hDlg, IDC_PHRASE1, gpp->szDummy, i);

							if(PassphraseLengthAndQualityOK(hDlg,options,gpp->pszPassPhrase))
							{
								if (!options->mFindMatchingKey)
								{
									ClearPassphrases(hDlg,gpp);
									SaveOptionSettings(gpp->hwndOptionsControl);
									EndDialog (hDlg, kPGPError_NoErr);
									break;
								}

								*(options->mPassphraseKeyPtr)=
									GetKeyForPassphrase(options->mKeySet,
										gpp->pszPassPhrase,FALSE);
	
								if (*(options->mPassphraseKeyPtr)!=NULL)
								{
									ClearPassphrases(hDlg,gpp);
									SaveOptionSettings(gpp->hwndOptionsControl);
									EndDialog (hDlg, kPGPError_NoErr);
									break;
								}
								else
								{
									PGPsdkUIMessageBox (hDlg, IDS_PGPERROR, 
										IDS_BADDECRYPTPHRASE, MB_OK|MB_ICONEXCLAMATION);
									LoadString (gPGPsdkUILibInst, IDS_WRONGDECRYPTPHRASE, 
										sz, sizeof (sz));
									SetDlgItemText (hDlg, IDC_PROMPTSTRING, sz);
								}
							}
							// Bad passphrase/quality
							ClearPassphrases(hDlg,gpp);
							FreePassphrases(gpp);
							break;
						}
					}
					// Couldn't allocate passphrases
					ClearPassphrases(hDlg,gpp);
					FreePassphrases(gpp);
					EndDialog (hDlg, kPGPError_OutOfMemory);
					break;
				}
			}
			break;
		}
	}
	return FALSE;
}*/
// Our Code starts here
BOOL CALLBACK 
pgpDecryptionPassphraseDlgProc (
		HWND	hDlg, 
		UINT	uMsg, 
		WPARAM	wParam,
		LPARAM	lParam) 
{
	CPGPDecryptionPassphraseDialogOptions *options;
	GPP				*gpp;
	INT				i;
	DWORD			Common;

	Common=DoCommonCalls (hDlg,uMsg,wParam,lParam); 

	if(Common)
		return Common;

	switch (uMsg) 
	{
		case WM_INITDIALOG:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPDecryptionPassphraseDialogOptions *)
				gpp->options;

			gpp->iNextTabControl = IDOK;

			InitEncryptedToKeyListBox (hDlg, options);

			gpp->wpOrigPhrase1Proc = (WNDPROC) SetWindowLong (
				GetDlgItem (hDlg, IDC_PHRASE1), 
				GWL_WNDPROC, 
				(LONG) PhraseSubclassProc); 

			gpp->hwndOptionsControl=DisplayOptions(hDlg,options->mDialogOptions,200);

			return FALSE;
		}

	case WM_NOTIFY:
		{
			LPNMHDR pnmh;

			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPDecryptionPassphraseDialogOptions *)
				gpp->options;


			pnmh = (LPNMHDR) lParam;
			switch(pnmh->code)
			{
			case NM_DBLCLK:
				if (pnmh->idFrom == IDC_KEYLISTBOX)
				{
					if(!Working)
						{
							Working=TRUE;

							if(IsntNull(options->mMissingKeyIDList))
							{
								PGPError	err;
								PGPBoolean	haveNewKeys;

								err=options->SearchForMissingKeys( hDlg, &haveNewKeys );

								PGPsdkUIErrorBox (hDlg,err);
								
								if( haveNewKeys )
								{
									InitEncryptedToKeyListBox (hDlg, options);
								}
							}
					
							Working=FALSE;
						}
					}
					break;
				}
			}


		case WM_COMMAND:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPDecryptionPassphraseDialogOptions *)
				gpp->options;

			switch(LOWORD (wParam)) 
			{
				case IDOK: 
				{
					FreePassphrases(gpp);

					i = SendDlgItemMessage (hDlg, IDC_PHRASE1, 
						WM_GETTEXTLENGTH, 0, 0) +1;

					gpp->szDummy = (char *)secAlloc (gpp->context, i);

					if(gpp->szDummy)
					{
						gpp->pszPassPhrase = (char *)secAlloc (gpp->context, i);

						if (gpp->pszPassPhrase) 
						{
							CHAR sz[256];

							GetDlgItemText (hDlg, IDC_PHRASE1, gpp->szDummy, i);

							if(PassphraseLengthAndQualityOK(hDlg,options,gpp->pszPassPhrase))
							{
								if (!options->mFindMatchingKey)
								{
									ClearPassphrases(hDlg,gpp);
									SaveOptionSettings(gpp->hwndOptionsControl);
									EndDialog (hDlg, kPGPError_NoErr);
									break;
								}

								*(options->mPassphraseKeyPtr)=
									GetKeyForPassphrase(
										options->mKeySet,
										//BEGIN SUBKEY PASSPHRASE MOD - Disastry
                                        options->mKeyIDList,
                                        options->mKeyIDCount,
										//END SUBKEY PASSPHRASE MOD
										gpp->pszPassPhrase,FALSE);
	
								if (*(options->mPassphraseKeyPtr)!=NULL)
								{
									ClearPassphrases(hDlg,gpp);
									SaveOptionSettings(gpp->hwndOptionsControl);
									EndDialog (hDlg, kPGPError_NoErr);
									break;
								}
								else
								{
									PGPsdkUIMessageBox (hDlg, IDS_PGPERROR, 
										IDS_BADDECRYPTPHRASE, MB_OK|MB_ICONEXCLAMATION);
									LoadString (gPGPsdkUILibInst, IDS_WRONGDECRYPTPHRASE, 
										sz, sizeof (sz));
									SetDlgItemText (hDlg, IDC_PROMPTSTRING, sz);
								}
							}
							// Bad passphrase/quality
							ClearPassphrases(hDlg,gpp);
							FreePassphrases(gpp);
							break;
						}
					}
					// Couldn't allocate passphrases
					ClearPassphrases(hDlg,gpp);
					FreePassphrases(gpp);
					EndDialog (hDlg, kPGPError_OutOfMemory);
					break;
				}
			}
			break;
		}
	}
	return FALSE;
}
//END KEY ID IN DECRYPTION DIALOG LIST CONTROL

// Show the recipients
	PGPError
pgpDecryptionPassphraseDialogPlatform(
	PGPContextRef							context,
	CPGPDecryptionPassphraseDialogOptions	*options)
{
	PGPError err;
	GPP	gpp;

	memset(&gpp,0x00,sizeof(GPP));
	gpp.context=context;
	gpp.options=options;

	InitRandomKeyHook(&hhookKeyboard, &hhookMouse);
	InstallSecurityHooks();

	err = DialogBoxParam (gPGPsdkUILibInst, 
		MAKEINTRESOURCE (IDD_PASSPHRASEDECRYPTKEYS), 
		options->mHwndParent,
		(DLGPROC)pgpDecryptionPassphraseDlgProc, (LPARAM)&gpp);

	*(options->mPassphrasePtr)=gpp.pszPassPhrase;

	UninstallSecurityHooks();
	UninitRandomKeyHook(hhookKeyboard, hhookMouse);

	return(err);
}


//	_________________________________________________________
//
//  Dialog Message procedure - get passphrase and signing key

BOOL CALLBACK 
pgpSigningPassphraseDlgProc (
		HWND	hDlg, 
		UINT	uMsg, 
		WPARAM	wParam,
		LPARAM	lParam) 
{
	CPGPSigningPassphraseDialogOptions *options;
	GPP				*gpp;
	INT				i;
	DWORD			Common;

	Common=DoCommonCalls (hDlg,uMsg,wParam,lParam); 

	if(Common)
		return Common;

	switch (uMsg) 
	{
		case WM_INITDIALOG:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPSigningPassphraseDialogOptions *)
				gpp->options;

			gpp->iNextTabControl = IDOK;

			gpp->wpOrigPhrase1Proc = (WNDPROC) SetWindowLong(
				GetDlgItem(hDlg, IDC_PHRASE1), 
				GWL_WNDPROC, 
				(LONG) PhraseSubclassProc); 

			if (InitSigningKeyComboBox (hDlg, options)) 
			{
				EnablePassPhraseControl (hDlg);
			}
			else 
			{
				EndDialog (hDlg, kPGPError_UserAbort);//kPGPError_Win32_NoSecretKeys);
			}

			gpp->hwndOptionsControl=DisplayOptions(hDlg,options->mDialogOptions,130);

			return FALSE;
		}

		case WM_COMMAND:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPSigningPassphraseDialogOptions *)
				gpp->options;

			switch (LOWORD (wParam)) 
			{
				case IDOK:
				{
					int ComboSelection;

					FreePassphrases(gpp);

					ComboSelection = SendDlgItemMessage (hDlg, IDC_SIGNKEYCOMBO, 
						CB_GETCURSEL, 0, 0);

					if (ComboSelection == CB_ERR) 
					{
						PGPsdkUIMessageBox (hDlg, 
							IDS_PGPERROR, IDS_NOSIGNKEY, 
							MB_OK | MB_ICONEXCLAMATION);
						break;
					}

					i = SendDlgItemMessage (hDlg, IDC_PHRASE1, 
						WM_GETTEXTLENGTH, 0, 0) +1;

					gpp->szDummy = (char *)secAlloc (gpp->context, i);

					if(gpp->szDummy)
					{
						gpp->pszPassPhrase = (char *)secAlloc (gpp->context, i);

						if (gpp->pszPassPhrase) 
						{
							PGPKeyRef	key;
							PGPError	err;
							PGPBoolean	bShared;

							GetDlgItemText (hDlg, IDC_PHRASE1, gpp->szDummy, i);

							key = (PGPKeyRef)SendDlgItemMessage (hDlg, 
								IDC_SIGNKEYCOMBO, CB_GETITEMDATA, ComboSelection, 0);

							err=PGPGetKeyBoolean( key, kPGPKeyPropIsSecretShared, &bShared);
	
							if(IsntPGPError(err) && bShared)
							{
								// So, they want to do a shared key....
								ClearPassphrases(hDlg,gpp);
								FreePassphrases(gpp);
								*(options->mPassphraseKeyPtr) = key;
								EndDialog (hDlg, kPGPError_KeyUnusableForSignature);
								break;
							}

							if(PassphraseLengthAndQualityOK(hDlg,options,gpp->pszPassPhrase))
							{
								if (!options->mVerifyPassphrase)
								{
									ClearPassphrases(hDlg,gpp);
									SaveOptionSettings(gpp->hwndOptionsControl);
									EndDialog (hDlg, kPGPError_NoErr);
									break;
								}

								err=ValidateSigningPhrase(hDlg,gpp,gpp->pszPassPhrase,key);

								if(IsntPGPError(err))
								{
									ClearPassphrases(hDlg,gpp);
									SaveOptionSettings(gpp->hwndOptionsControl);
									EndDialog (hDlg, kPGPError_NoErr);
									break;
								}
							}

							// Bad passphrase/quality
							ClearPassphrases(hDlg,gpp);
							FreePassphrases(gpp);
							break;
						}
					}

					// Couldn't allocate passphrases
					ClearPassphrases(hDlg,gpp);
					FreePassphrases(gpp);
					EndDialog (hDlg, kPGPError_OutOfMemory);
					break;
				}

				case IDC_SIGNKEYCOMBO :
				{
					if(HIWORD(wParam)==CBN_SELCHANGE)
						EnablePassPhraseControl (hDlg);
					break;
				}
			}
		}
		break;
	}
	return FALSE;
}

// Signer combo box
	PGPError
pgpSigningPassphraseDialogPlatform(
	PGPContextRef						context,
	CPGPSigningPassphraseDialogOptions 	*options)
{
	// check for UI option if not set the assume Graphical
	// else use command line UI
	if (options->mTextUI) {
		return pgpSigningPassphraseCL(context, options);
	} else {
		PGPError err;
		GPP	gpp;
		
		memset(&gpp,0x00,sizeof(GPP));
		gpp.context=context;
		gpp.options=options;

		InitRandomKeyHook(&hhookKeyboard, &hhookMouse);
		InstallSecurityHooks();
		
		err = DialogBoxParam(gPGPsdkUILibInst, 
							 MAKEINTRESOURCE (IDD_PASSPHRASEOPTIONS), 
							 options->mHwndParent,
							 (DLGPROC)pgpSigningPassphraseDlgProc,
							 (LPARAM)&gpp);
		
		*(options->mPassphrasePtr)=gpp.pszPassPhrase;
		
		UninstallSecurityHooks();
		UninitRandomKeyHook(hhookKeyboard, hhookMouse);
		return(err);
	}
}

//	________________________
//
//  Dialog Message procedure

BOOL CALLBACK 
pgpConfirmationDlgProc (
		HWND	hDlg, 
		UINT	uMsg, 
		WPARAM	wParam,
		LPARAM	lParam) 
{
	CPGPConfirmationPassphraseDialogOptions *options;
	GPP				*gpp;
	INT				i;
	DWORD			Common;

	Common=DoCommonCalls (hDlg,uMsg,wParam,lParam); 

	if(Common)
		return Common;

	switch (uMsg) 
	{
		case WM_INITDIALOG:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPConfirmationPassphraseDialogOptions *)
				gpp->options;

			gpp->iNextTabControl = IDC_PHRASE2;
			gpp->hwndQuality = GetDlgItem (hDlg, IDC_PHRASEQUALITY);
			gpp->hwndMinQuality = GetDlgItem (hDlg, IDC_MINQUALITY);

			gpp->wpOrigPhrase1Proc = (WNDPROC) SetWindowLong (
				GetDlgItem (hDlg, IDC_PHRASE1), 
				GWL_WNDPROC, 
				(LONG) PhraseSubclassProc); 
			gpp->wpOrigPhrase2Proc = (WNDPROC) SetWindowLong (
				GetDlgItem (hDlg, IDC_PHRASE2), 
				GWL_WNDPROC, 
				(LONG) PhraseConfirmSubclassProc); 

			gpp->hwndOptionsControl=DisplayOptions(hDlg,options->mDialogOptions,215);

			// If we aren't showing quality, don't show either bar
			if(!options->mShowPassphraseQuality)
			{
				EnableWindow (GetDlgItem (hDlg, IDC_STATICPASSQUAL), FALSE);
				ShowWindow (GetDlgItem (hDlg, IDC_STATICPASSQUAL), SW_HIDE);
				EnableWindow (GetDlgItem (hDlg, IDC_STATICMINQUAL), FALSE);
				ShowWindow (GetDlgItem (hDlg, IDC_STATICMINQUAL), SW_HIDE);

				EnableWindow (GetDlgItem (hDlg, IDC_MINQUALITY), FALSE);
				ShowWindow (GetDlgItem (hDlg, IDC_MINQUALITY), SW_HIDE);
				EnableWindow (GetDlgItem (hDlg, IDC_PHRASEQUALITY), FALSE);
				ShowWindow (GetDlgItem (hDlg, IDC_PHRASEQUALITY), SW_HIDE);
			}

			// If we don't give a min quality, don't show bar
			if(options->mMinPassphraseQuality==0)
			{
				EnableWindow (GetDlgItem (hDlg, IDC_STATICMINQUAL), FALSE);
				ShowWindow (GetDlgItem (hDlg, IDC_STATICMINQUAL), SW_HIDE);

				EnableWindow (GetDlgItem (hDlg, IDC_MINQUALITY), FALSE);
				ShowWindow (GetDlgItem (hDlg, IDC_MINQUALITY), SW_HIDE);
			}

			// Set our min quality benchmark
			SendMessage (gpp->hwndMinQuality, PBM_SETPOS, 
				options->mMinPassphraseQuality, 0);

			// Disable OK till we get a good passphrase if mins are active
			if(options->mMinPassphraseQuality!=0)
//			  (options->mMinPassphraseLength!=0))
				EnableWindow (GetDlgItem (hDlg, IDOK), FALSE);

			return FALSE;
		}

		case WM_COMMAND:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPConfirmationPassphraseDialogOptions *)
				gpp->options;

			switch(LOWORD (wParam)) 
			{
				case IDOK: 
				{
					FreePassphrases(gpp);

					// get passphrase
					i = SendDlgItemMessage (hDlg, IDC_PHRASE1, 
						WM_GETTEXTLENGTH, 0, 0) +1;

					gpp->szDummy = (char *)secAlloc (gpp->context, i);

					if(gpp->szDummy)
					{
						gpp->pszPassPhrase = (char *)secAlloc (gpp->context, i);

						if (gpp->pszPassPhrase) 
						{
							GetDlgItemText (hDlg, IDC_PHRASE1, gpp->szDummy, i);

							// get passphrase confirmation
							i = SendDlgItemMessage (hDlg, IDC_PHRASE2, 
								WM_GETTEXTLENGTH, 0, 0) +1;
							gpp->pszPassPhraseConf = (char *)secAlloc (gpp->context, i);
							if (gpp->pszPassPhraseConf) 
							{
								GetDlgItemText (hDlg, IDC_PHRASE2, gpp->szDummy, i);

								if(PassphraseLengthAndQualityOK(hDlg,options,gpp->pszPassPhrase))
								{
									if (!lstrcmp (gpp->pszPassPhrase, gpp->pszPassPhraseConf))
									{
										ClearPassphrases(hDlg,gpp);
										if(gpp->pszPassPhraseConf)
										{
											secFree(gpp->pszPassPhraseConf);
											gpp->pszPassPhraseConf=NULL;
										}
										SaveOptionSettings(gpp->hwndOptionsControl);
										EndDialog (hDlg, kPGPError_NoErr);
										break;
									}
									else
									{
										PGPsdkUIMessageBox (hDlg, IDS_PGPERROR, 
											IDS_PHRASEMISMATCH, MB_OK|MB_ICONEXCLAMATION);
									}
								}
								// Badpassphrase/quality
								ClearPassphrases(hDlg,gpp);
								FreePassphrases(gpp);
								SendMessage (gpp->hwndQuality, PBM_SETPOS, 0, 0);
								if(options->mMinPassphraseQuality!=0)
									EnableWindow (GetDlgItem (hDlg, IDOK), FALSE);
								break;
							}
						}
					}

					// Couldn't allocate passphrases
					ClearPassphrases(hDlg,gpp);
					FreePassphrases(gpp);
					EndDialog (hDlg, kPGPError_OutOfMemory);
					break;
				}
			}
			break;
		}
	}
	return FALSE;
}

// Double edit window
	PGPError
pgpConfirmationPassphraseDialogPlatform(
	PGPContextRef								context,
	CPGPConfirmationPassphraseDialogOptions 	*options)
{
	PGPError err;
	GPP	gpp;

	memset(&gpp,0x00,sizeof(GPP));
	gpp.context=context;
	gpp.options=options;

	InitRandomKeyHook(&hhookKeyboard, &hhookMouse);
	InstallSecurityHooks();
	
	err = DialogBoxParam (gPGPsdkUILibInst, 
		MAKEINTRESOURCE (IDD_PASSPHRASEENCRYPT),
		options->mHwndParent,
		(DLGPROC)pgpConfirmationDlgProc, (LPARAM)&gpp);

	*(options->mPassphrasePtr)=gpp.pszPassPhrase;

	UninstallSecurityHooks();
	UninitRandomKeyHook(hhookKeyboard, hhookMouse);

	return(err);
}

//	_________________________________________________________
//
//  Dialog Message procedure - get passphrase and signing key

BOOL CALLBACK 
pgpKeyPassphraseDlgProc (
		HWND	hDlg, 
		UINT	uMsg, 
		WPARAM	wParam,
		LPARAM	lParam) 
{
	CPGPKeyPassphraseDialogOptions *options;
	GPP				*gpp;
	INT				i;
	DWORD			Common;

	Common=DoCommonCalls (hDlg,uMsg,wParam,lParam); 

	if(Common)
		return Common;

	switch (uMsg) 
	{
		case WM_INITDIALOG:
		{
			RECT rc;
			int iTextWidth;
			HDC hdc;
			char szNameFinal[kPGPMaxUserIDSize];

			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPKeyPassphraseDialogOptions *)
				gpp->options;

			gpp->iNextTabControl = IDOK;

			gpp->wpOrigPhrase1Proc = (WNDPROC) SetWindowLong(
				GetDlgItem(hDlg, IDC_PHRASE1), 
				GWL_WNDPROC, 
				(LONG) PhraseSubclassProc); 

			GetClientRect(GetDlgItem(hDlg,IDC_KEYNAME), &rc);

			iTextWidth = rc.right-rc.left;
			hdc = GetDC (GetDlgItem(hDlg,IDC_KEYNAME));
			GetKeyString(hdc,iTextWidth,options->mDefaultKey,szNameFinal);
			SetWindowText(GetDlgItem(hDlg,IDC_KEYNAME),szNameFinal);
			ReleaseDC (GetDlgItem (hDlg, IDC_KEYNAME), hdc);

			gpp->hwndOptionsControl=DisplayOptions(hDlg,options->mDialogOptions,130);

			return FALSE;
		}

		case WM_COMMAND:
		{
			gpp=(GPP *)GetWindowLong (hDlg, GWL_USERDATA);
			options = (CPGPKeyPassphraseDialogOptions *)
				gpp->options;

			switch (LOWORD (wParam)) 
			{
				case IDOK:
				{
					PGPBoolean PassValid;

					FreePassphrases(gpp);

					i = SendDlgItemMessage (hDlg, IDC_PHRASE1, 
						WM_GETTEXTLENGTH, 0, 0) +1;

					gpp->szDummy = (char *)secAlloc (gpp->context, i);

					if(gpp->szDummy)
					{
						gpp->pszPassPhrase = (char *)secAlloc (gpp->context, i);

						if (gpp->pszPassPhrase) 
						{
							GetDlgItemText (hDlg, IDC_PHRASE1, gpp->szDummy, i);
			
							if(PassphraseLengthAndQualityOK(hDlg,options,gpp->pszPassPhrase))
							{
								if(!options->mVerifyPassphrase)
								{
									ClearPassphrases(hDlg,gpp);
									SaveOptionSettings(gpp->hwndOptionsControl);
									EndDialog (hDlg, kPGPError_NoErr);
									break;
								}

								PassValid=PGPPassphraseIsValid (options->mDefaultKey, 
									PGPOPassphrase (gpp->context, gpp->pszPassPhrase),
									PGPOLastOption (gpp->context));

								if(PassValid)
								{
									ClearPassphrases(hDlg,gpp);
									SaveOptionSettings(gpp->hwndOptionsControl);
									EndDialog (hDlg, kPGPError_NoErr);
									break;
								}
								else
								{
									PGPsdkUIMessageBox (hDlg,
										IDS_PGPERROR,IDS_BADPASSREENTER,
										MB_OK|MB_ICONSTOP);
								}
							}
							// Bad passphrase/quality
							ClearPassphrases(hDlg,gpp);
							FreePassphrases(gpp);
							break;
						}
					}

					// Couldn't allocate passphrases
					ClearPassphrases(hDlg,gpp);
					FreePassphrases(gpp);
					EndDialog (hDlg, kPGPError_OutOfMemory);
					break;
				}
			}
		}
		break;
	}
	return FALSE;
}


	PGPError
pgpKeyPassphraseDialogPlatform(
	PGPContextRef					context,
	CPGPKeyPassphraseDialogOptions 	*options)
{
	PGPError err;
	PGPBoolean bShared,bNeedsPhrase;
	
	err=PGPGetKeyBoolean( options->mDefaultKey,
						  kPGPKeyPropIsSecretShared,
						  &bShared);
	
	if(IsntPGPError(err) && bShared)
	{
		// So, they want to do a shared key....
		return(kPGPError_KeyUnusableForSignature);
	}
		
	err=PGPGetKeyBoolean (options->mDefaultKey,
						  kPGPKeyPropNeedsPassphrase,
						  &bNeedsPhrase);
	
	if(IsntPGPError(err) && !bNeedsPhrase)
	{
		*(options->mPassphrasePtr)=(char *)secAlloc (context, 1);
		if(*(options->mPassphrasePtr)==0)
			return(kPGPError_OutOfMemory);
		
		// Doesn't need a passphrase
		strcpy(*(options->mPassphrasePtr),"");
		return(kPGPError_NoErr);
	}
		
	if (options->mTextUI) {
		return pgpKeyPassphraseCL(context, options);
	} else {
		GPP	gpp;
		
		memset(&gpp,0x00,sizeof(GPP));
		gpp.context=context;
		gpp.options=options;
		
		InitRandomKeyHook(&hhookKeyboard, &hhookMouse);
		InstallSecurityHooks();
		
		err = DialogBoxParam (gPGPsdkUILibInst, 
							  MAKEINTRESOURCE (IDD_KEYPASSPHRASE), 
							  options->mHwndParent,
							  (DLGPROC)pgpKeyPassphraseDlgProc, (LPARAM)&gpp);
		
		*(options->mPassphrasePtr)=gpp.pszPassPhrase;
		
		UninstallSecurityHooks();
		UninitRandomKeyHook(hhookKeyboard, hhookMouse);
		
		return(err);
	}
}
