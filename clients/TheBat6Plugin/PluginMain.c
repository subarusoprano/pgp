// System Headers
#include <windows.h>
#include <windowsx.h>

// PGPsdk Headers
#include "pgpConfig.h"
#include "pgpErrors.h"
#include "pgpUtilities.h"
#include "pgpEncode.h"
#include "pgpTLS.h"
#include "pgpSDKprefs.h"

// Shared Headers
#include "PGPcl.h"
#include "..\PGPsc\ClVwClip.h"
#include "addkey.h"
#include "EncryptSign.h"
#include "DecryptVerify.h"
#include "BlockUtils.h"
#include "pgpVersionHeader.h"

#include <stdio.h>

// Project Headers
#include "PluginMain.h"
#include "Prefs.h"

// Global Variables
HINSTANCE			g_hinst				= NULL;
PGPContextRef		g_pgpContext		= kPGPInvalidRef;
PGPtlsContextRef	g_tlsContext		= kPGPInvalidRef;
UINT				g_nPurgeCacheMsg	= 0;
HWND				g_hwndHidden		= NULL;


//extern char pgpVersionHeaderString[] = "";
//extern char  pgpVersionHeaderString[];


#define MAX_BUFFER_SIZE 500000

#define EMSR_OK 0
#define EMSR_UNKNOWN_FAIL -1

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */


long WINAPI pgp60_init(void)
{
	long returnValue = EMSR_OK;
	PGPError error;

	// Initialize the PGPsdk for the plugin
	error = PGPNewContext( kPGPsdkAPIVersion, &g_pgpContext );

	if( IsPGPError(error) )
	{
	  if (error != kPGPError_FeatureNotAvailable)
	  {
            PGPclErrorBox (NULL, error);
 	  }
          returnValue = EMSR_UNKNOWN_FAIL;
	}

	// Initialize the Common Libraries
	error = PGPclInitLibrary (g_pgpContext);


        if (IsPGPError (error)) 
    	{
          PGPclErrorBox (NULL, error);
          returnValue = EMSR_UNKNOWN_FAIL;
        }

	// has this beta version expired?
	if(PGPclIsExpired(NULL))
	{
		PGPclCloseLibrary();
		PGPFreeContext(g_pgpContext);
		g_pgpContext = NULL;
	
		return EMSR_UNKNOWN_FAIL;
	}

	PGPNewTLSContext( g_pgpContext, &g_tlsContext );

	// Register the passphrase cache purge message

	g_nPurgeCacheMsg = RegisterWindowMessage(PURGEPASSPHRASECACEHMSG);

	// Create a hidden window to catch messages

//	g_hwndHidden = CreateHiddenWindow();

	return (returnValue);
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

long WINAPI pgp60_config(void)
{
	PGPclPreferences (g_pgpContext, NULL, 2, NULL);

	return (EMSR_OK);
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */


long WINAPI pgp60_launch_keys(void)
{
		char szPath[MAX_PATH];
		char *szPGPkeys="PGPkeys /s";
		PGPError error = kPGPError_NoErr;

		error = PGPclGetPGPPath (szPath, sizeof(szPath));

		if( IsntPGPError(error) )
		{
			// '/s' keeps it from showing that 
			// damn splash screen
			strcat(szPath, szPGPkeys);
			// run it...
			WinExec(szPath, SW_SHOW);
		}
		else
		{
			char *szError="Unable to locate the PGPkeys application";

			MessageBox(NULL, 
				szError, 
				0, 
				MB_OK);
		}
	

		return (EMSR_OK);
}



/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

long WINAPI pgp60_finish(void)
{

	if( PGPRefIsValid(g_tlsContext) )
	{
		PGPFreeTLSContext(g_tlsContext);
	}

	if( PGPRefIsValid(g_pgpContext) )
	{
		PGPclCloseLibrary();
		PGPFreeContext(g_pgpContext);
	}
	
	return (EMSR_OK); 
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

long WINAPI pgp60_add_key(
		    HWND   hWndParent,
		    char* szBuffer,
                    DWORD dwInSize)
{
 return (AddKeyBuffer(hWndParent, g_pgpContext, g_tlsContext, szBuffer, dwInSize));
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

long WINAPI pgp60_encode(HWND   hWndParent,
                    char** Rcpts,
                    DWORD  nRcpts,
                    BOOL   bEncrypt,
                    BOOL   bSign,
                    char*  Source,
                    DWORD  srcSize,
                    char** Dest,
                    DWORD* ResultSize,
		    BOOL   bBinary)
{


	BOOL ReturnValue = EMSR_UNKNOWN_FAIL;
	void* pOutput = NULL;
	long outSize = 0;
	PGPError error = kPGPError_NoErr;
	PGPOptionListRef userOptions = kPGPInvalidRef;
	PRECIPIENTDIALOGSTRUCT prds = NULL;

	// allocate a recipient dialog structure
	prds = (PRECIPIENTDIALOGSTRUCT) calloc(sizeof(RECIPIENTDIALOGSTRUCT), 1);
	if (!prds)
	{
		PGPclErrorBox(hWndParent, kPGPError_OutOfMemory);
		return EMSR_UNKNOWN_FAIL;
	}

	error = PGPsdkLoadDefaultPrefs(g_pgpContext);
	if (IsPGPError(error))
	{
		PGPclEncDecErrorBox(hWndParent, error);
		return EMSR_UNKNOWN_FAIL;
	}

	error = PGPOpenDefaultKeyRings(g_pgpContext, (PGPKeyRingOpenFlags)0, 
				&(prds->OriginalKeySetRef));

	if (IsPGPError(error))
	{
		PGPclEncDecErrorBox(hWndParent, error);
		return EMSR_UNKNOWN_FAIL;
	}
	SHRememberVersionHeaderString ( g_pgpContext);

	if(prds && bEncrypt)
	{
		char *szTitle="Encrypt Message To...";	// title for recipient dialog
		UINT recipientReturn	= FALSE;	// recipient dialog result


		if( IsntPGPError(error) )
		{
			prds->Context			= g_pgpContext;
			prds->tlsContext		= g_tlsContext;
			prds->Version			= CurrentPGPrecipVersion;
			prds->hwndParent		= hWndParent;
			prds->szTitle			= szTitle;
			prds->dwOptions			= PGPCL_ASCIIARMOR;	

			prds->dwDisableFlags	= PGPCL_DISABLE_WIPEORIG |
									  PGPCL_DISABLE_ASCIIARMOR;

			prds->dwNumRecipients	= nRcpts;	
			prds->szRecipientArray	= Rcpts;

			// If shift is pressed, force the dialog to pop.
			if (GetAsyncKeyState( VK_CONTROL) & 0x8000)
				prds->dwDisableFlags|=PGPCL_DISABLE_AUTOMODE;

			// See who we wish to encrypt this to
			recipientReturn = PGPclRecipientDialog( prds );
		}

		if (prds->AddedKeys != NULL)
		{
			PGPUInt32 numKeys;

			PGPCountKeys(prds->AddedKeys, &numKeys);
			if (numKeys > 0)
				PGPclQueryAddKeys(g_pgpContext, g_tlsContext, 
					hWndParent, prds->AddedKeys, NULL);

			PGPFreeKeySet(prds->AddedKeys);
			prds->AddedKeys = NULL;
		}

		if (!recipientReturn)
		{
			if (prds->SelectedKeySetRef != NULL)
				PGPFreeKeySet(prds->SelectedKeySetRef);
			PGPFreeKeySet(prds->OriginalKeySetRef);
			free(prds);
			return EMSR_UNKNOWN_FAIL;
		}
	}

	if( IsntPGPError(error) )
	{
	  char *szExe = "The Bat!";
	  char *szDll = "batpgp65.dll";
	  if ((!bBinary) && (Source[srcSize])){
		  char *tempBuf;

		  tempBuf = malloc(srcSize+1);
		  if (tempBuf == NULL) {
			  PGPclErrorBox(hWndParent, kPGPError_OutOfMemory);
			  return EMSR_UNKNOWN_FAIL;
		  }
		  memset (tempBuf, 0x00, srcSize+1);
		  memcpy (tempBuf, Source, srcSize);
		  error = EncryptSignBuffer(g_hinst, hWndParent,
					g_pgpContext, g_tlsContext, szExe, szDll,
					tempBuf, srcSize, prds, NULL, &userOptions, &pOutput,
					&outSize, bEncrypt, bSign, bBinary);
		  memset (tempBuf, 0x00, srcSize+1);
		  free(tempBuf);
	  }
	  else
		  error = EncryptSignBuffer(g_hinst, hWndParent,
					g_pgpContext, g_tlsContext, szExe, szDll,
					Source, srcSize, prds, NULL, &userOptions, &pOutput,
					&outSize, bEncrypt, bSign, bBinary);
	}
	else
	{
		PGPclEncDecErrorBox(hWndParent, error);
	}

	if( IsntPGPError(error) )
	{
		if( pOutput )
		{
		  *Dest = pOutput;
		  *ResultSize = outSize;
	 	  ReturnValue = EMSR_OK;
		}
	}
	
	if( PGPRefIsValid(userOptions) )
	{
		PGPFreeOptionList(userOptions);
	}

	if (prds)
	{
		if (prds->SelectedKeySetRef != NULL)
			PGPFreeKeySet(prds->SelectedKeySetRef);
		PGPFreeKeySet(prds->OriginalKeySetRef);
		free(prds);
	}

	return ReturnValue;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

long WINAPI pgp60_decode(HWND hwndParent,
                    char*  Source,
                    DWORD  srcSize,
                    char** Dest,
                    DWORD* ResultSize,
		    BOOL*  FYEO)
{
	BOOL ReturnValue = EMSR_UNKNOWN_FAIL;
	void* pOutput = NULL;
	long outSize = 0;
	PGPError error;
	ulong start, size;
	BOOL bPGP = FALSE;
 	char *szExe = "The Bat!";
	char *szDll = "batpgp65.dll";

	error = DecryptVerifyBuffer(g_hinst, hwndParent, g_pgpContext,
				g_tlsContext, szExe, szDll, Source, srcSize, 
				FALSE, &pOutput, &outSize, FYEO);

	bPGP = (FindEncryptedBlock(Source, srcSize, &start, &size) ||
			FindSignedBlock(Source, srcSize, &start, &size));
			
 
	if( IsntPGPError(error) )
	{
	  *ResultSize = outSize;
	  *Dest = pOutput;
	  ReturnValue = EMSR_OK;


		AddKeyBuffer(hwndParent, g_pgpContext, 
			g_tlsContext, pOutput, outSize);
		//TextViewer(hwndParent,pOutput,outSize);
	}


	return ReturnValue;
}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

void WINAPI pgp60_free(void *m)
{
  PGPFreeData(m);
}


BOOL WINAPI pgp60_defencrypt(void)
{
  PGPMemoryMgrRef memoryMgr;
  memoryMgr = PGPGetContextMemoryMgr(g_pgpContext);
  return(ByDefaultEncrypt(memoryMgr));
}

BOOL WINAPI pgp60_defsign(void)
{
  PGPMemoryMgrRef memoryMgr;
  memoryMgr = PGPGetContextMemoryMgr(g_pgpContext);
  return(ByDefaultSign(memoryMgr));
}

