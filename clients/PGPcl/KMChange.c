/*____________________________________________________________________________
	Copyright (C) 1998 Network Associates, Inc.
	All rights reserved.
	
	KMChange.c - handle dialog for changing key passphrase
	
	$Id: KMChange.c,v 1.20 1998/12/16 21:07:18 pbj Exp $

____________________________________________________________________________*/
#include "pgpPFLConfig.h"

// project header files
#include "pgpkmx.h"

// pgp header files
#include "pgpAdminPrefs.h"

// external globals
extern HINSTANCE	g_hInst;

// local globals
static BOOL			sbChangingPhrase;

//	___________________________________________________
//
//  Change Passphrase of split key and all subkeys

static PGPError 
sChangePhraseSplit (
		PGPContextRef	context,
		PGPKeySetRef	keyset,
		PGPKeyRef		key, 
		PGPByte*		passkey,
		PGPSize			sizePasskey,
		LPSTR			szNew) 
{
	UINT			u;
	PGPKeyListRef	keylist;
	PGPKeyIterRef	keyiter;
	PGPSubKeyRef	subkey;
	PGPError		err;
	//BEGIN SUBKEY PASSPHRASE MOD - Disastry
	PGPError		errsub = kPGPError_NoErr;
	//END SUBKEY PASSPHRASE MOD
    PGPBoolean v3 = TRUE;

	err = PGPChangePassphrase (key, 
			PGPOPasskeyBuffer (context, passkey, sizePasskey),
			PGPOPassphrase (context, szNew), 
			PGPOLastOption (context));
	if (IsPGPError (err)) return err;

	PGPGetKeyNumber (key, kPGPKeyPropAlgID, &u);
	switch (u) {
	case kPGPPublicKeyAlgorithm_RSA :
		//BEGIN RSAv4 SUPPORT MOD - Disastry
		if (IsPGPError(PGPGetKeyBoolean (key, kPGPKeyPropIsV3, &v3)))
			v3 = TRUE;
		if (v3)
		//END RSAv4 SUPPORT MOD
			break;
		// else fall through

	case kPGPPublicKeyAlgorithm_DSA :
		PGPOrderKeySet (keyset, kPGPAnyOrdering, &keylist);
		PGPNewKeyIter (keylist, &keyiter);
		PGPKeyIterSeek (keyiter, key);
		PGPKeyIterNextSubKey (keyiter, &subkey);
		while (subkey) {
			err = PGPChangeSubKeyPassphrase (subkey, 
						PGPOPasskeyBuffer (context, passkey, sizePasskey),
						PGPOPassphrase (context, szNew),
						PGPOLastOption (context));
			PGPKeyIterNextSubKey (keyiter, &subkey);
	        //BEGIN SUBKEY PASSPHRASE MOD - Disastry
            if (err && !errsub)
                errsub = err;
	        //END SUBKEY PASSPHRASE MOD
		}
	    //BEGIN SUBKEY PASSPHRASE MOD - Disastry
        if (errsub && !err)
            err = errsub;
        if (err == kPGPError_BadPassphrase)
            /* maybe its better to define new error: kPGPError_BadSubKeyPassphrase */
            err = kPGPError_TroubleKeySubKey;
	    //END SUBKEY PASSPHRASE MOD
		PGPFreeKeyIter (keyiter);
		PGPFreeKeyList (keylist);
		break;

	default :
		break;
	}

	return err;
}

//	___________________________________________________
//
//  Change Passphrase of normal key and all subkeys

static PGPError 
sChangePhraseNormal (
		PGPContextRef	context,
		PGPKeySetRef	keyset,
		PGPKeyRef		key, 
		LPSTR			szOld,
		LPSTR			szNew) 
{
	UINT			u;
	PGPKeyListRef	keylist;
	PGPKeyIterRef	keyiter;
	PGPSubKeyRef	subkey;
	PGPError		err;
	//BEGIN SUBKEY PASSPHRASE MOD - Disastry
	PGPError		errsub = kPGPError_NoErr;
	//END SUBKEY PASSPHRASE MOD
    PGPBoolean v3;

	err = PGPChangePassphrase (key, 
			PGPOPassphrase (context, szOld),
			PGPOPassphrase (context, szNew), 
			PGPOLastOption (context));
	if (IsPGPError (err)) return err;

	PGPGetKeyNumber (key, kPGPKeyPropAlgID, &u);
	switch (u) {
	case kPGPPublicKeyAlgorithm_RSA :
		//BEGIN RSAv4 SUPPORT MOD - Disastry
		if (IsPGPError(PGPGetKeyBoolean (key, kPGPKeyPropIsV3, &v3)))
			v3 = TRUE;
		if (v3)
		//END RSAv4 SUPPORT MOD
			break;
		// else fall through

	case kPGPPublicKeyAlgorithm_DSA :
		PGPOrderKeySet (keyset, kPGPAnyOrdering, &keylist);
		PGPNewKeyIter (keylist, &keyiter);
		PGPKeyIterSeek (keyiter, key);
		PGPKeyIterNextSubKey (keyiter, &subkey);
		while (subkey) {
			err = PGPChangeSubKeyPassphrase (subkey, 
						PGPOPassphrase (context, szOld),
						PGPOPassphrase (context, szNew),
						PGPOLastOption (context));
			PGPKeyIterNextSubKey (keyiter, &subkey);
	        //BEGIN SUBKEY PASSPHRASE MOD - Disastry
            if (err && !errsub)
                errsub = err;
	        //END SUBKEY PASSPHRASE MOD
		}
	    //BEGIN SUBKEY PASSPHRASE MOD - Disastry
        if (errsub && !err)
            err = errsub;
        if (err == kPGPError_BadPassphrase)
            /* maybe its better to define new error: kPGPError_BadSubKeyPassphrase */
            err = kPGPError_TroubleKeySubKey;
	    //END SUBKEY PASSPHRASE MOD
		PGPFreeKeyIter (keyiter);
		PGPFreeKeyList (keylist);
		break;

	default :
		break;
	}

	return err;
}

//	___________________________________________________
//
//  Change passphrase on key 

BOOL 
KMChangePhrase (
		HWND				hwndParent, 
		PKEYMAN				pKM,
		PGPContextRef		context,
		PGPtlsContextRef	tlsContext,
		PGPKeySetRef		keyset,
		PGPKeyRef			key) 
{
	LPSTR		pszOldPhrase		= NULL;
	LPSTR		pszNewPhrase		= NULL;
	PGPByte*	pPasskey			= NULL;
	PGPPrefRef	prefs				= kInvalidPGPPrefRef;
	INT			iMinPhraseLength	= 0;
	INT			iMinPhraseQuality	= 0;

	CHAR		szPrompt[64];
	PGPSize		sizePasskey;
	PGPError	err;
	BOOL		bSplit;
#if PGP_BUSINESS_SECURITY
	PGPBoolean	b;
	PGPUInt32	u;
#endif

	if (!sbChangingPhrase) {
		sbChangingPhrase = TRUE;

	// minimum passphrase length
#if PGP_BUSINESS_SECURITY
		err = PGPclOpenAdminPrefs (
				PGPGetContextMemoryMgr (context), 
				&prefs, PGPclIsAdminInstall ()); CKERR;

		b = FALSE;
		err = PGPGetPrefBoolean (prefs, kPGPPrefEnforceMinChars, &b); CKERR;
		if (b) {
			err = PGPGetPrefNumber (prefs, kPGPPrefMinChars, &u); CKERR;
			iMinPhraseLength = (INT)u;
		}
#endif 

	// minimum passphrase quality
#if PGP_BUSINESS_SECURITY
		b = FALSE;
		PGPGetPrefBoolean (prefs, kPGPPrefEnforceMinQuality, &b); CKERR;
		if (b) {
			err = PGPGetPrefNumber (prefs, kPGPPrefMinQuality, &u); CKERR;
			iMinPhraseQuality = (INT)u;
		}
#endif 

		err = KMGetKeyPhrase (
			context,
			tlsContext,
			hwndParent, 
			NULL,
			keyset,
			key,
			&pszOldPhrase,
			&pPasskey,
			&sizePasskey);

		if (IsntPGPError (err)) {

			LoadString (g_hInst, IDS_NEWPHRASEPROMPT, 
							szPrompt, sizeof(szPrompt));
			err = KMGetConfirmationPhrase (
				context, 
				hwndParent,
				szPrompt,
				keyset,
				iMinPhraseLength,
				iMinPhraseQuality,
				&pszNewPhrase);

			if (IsntPGPError (err)) {
				if (pszOldPhrase) bSplit = FALSE;
				else bSplit = TRUE;

				if (bSplit) {
					err = sChangePhraseSplit (
						context,
						keyset,
						key,
						pPasskey,
						sizePasskey, 
						pszNewPhrase);
				}
				else {
					err = sChangePhraseNormal (
						context,
						keyset,
						key,
						pszOldPhrase, 
						pszNewPhrase);
				}
			}
		}

		if (pszOldPhrase)
			KMFreePhrase (pszOldPhrase);
		if (pszNewPhrase)
			KMFreePhrase (pszNewPhrase);
		if (pPasskey)
			KMFreePasskey (pPasskey, sizePasskey);

        //BEGIN SUBKEY PASSPHRASE MOD - Disastry
		if (err == kPGPError_TroubleKeySubKey) {
	        //KMMessageBox (hwndParent, IDS_CAPTION, IDS_sometthing,
		    //				MB_OK|MB_ICONEXCLAMATION);
		    MessageBox (hwndParent, "Subkey(s) have different passphrase(s)\n"
							    "Subkey passphrase(s) not changed\n",
                                "PGP", MB_OK|MB_ICONEXCLAMATION);
			err = kPGPError_NoErr;
		}
        //END SUBKEY PASSPHRASE MOD
		if (IsPGPError (err))
			PGPclErrorBox (hwndParent, err);
		else {
			PGPclNotifyPurgePassphraseCache (
					PGPCL_DECRYPTIONCACHE|PGPCL_SIGNINGCACHE, 0);
			if (bSplit)
				KMMessageBox (hwndParent, IDS_PGP, IDS_KEYRECONSTITUTED, 
								MB_OK|MB_ICONINFORMATION);
			else
				KMMessageBox (hwndParent, IDS_PGP, IDS_PHRASECHANGED, 
								MB_OK|MB_ICONINFORMATION);
		}

	}

#if PGP_BUSINESS_SECURITY
done :
	if (PGPPrefRefIsValid (prefs))
		PGPclCloseAdminPrefs (prefs, FALSE);
#endif

	sbChangingPhrase = FALSE;

    PGPclErrorBox (hwndParent, err);

	return (IsntPGPError (err));
}
