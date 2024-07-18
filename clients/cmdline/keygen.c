/*____________________________________________________________________________
    keymgmt.c

    Copyright(C) 1998,1999 Network Associates, Inc.
    All rights reserved.

	PGP 6.5 Command Line 

    use the PGP SDK to generate a key.

    $Id: keygen.c,v 1.16.6.2.2.1.4.9 1999/10/01 00:10:21 sluu Exp $
____________________________________________________________________________*/

#include <stdio.h>

#include "pgpBase.h"
#include "pgpKeys.h"
#include "pgpErrors.h"
#include "pgpUserInterface.h"
#include "pgpUtilities.h"
#include "pgpEnv.h"
#include "pgpContext.h"
#include "pgpSDKPrefs.h"
#include "pgpFeatures.h"

#include "usuals.h"
#include "pgp.h"
#include "globals.h"
#include "prototypes.h"

#include "language.h"
#include "config.h"


void GetRSAStatus(PGPBoolean *haveRSAAlgorithm, 
				  PGPBoolean *canGenerateKeys, 
				  PGPBoolean *isBSAFE, 
				  PGPBoolean *isRSAREF, 
				  PGPBoolean *isCAPI,
				  PGPBoolean *isPGPRSA,
				  char		 *copyright)
{
    PGPError  err;
    PGPUInt32 numAlgs;

    *haveRSAAlgorithm = FALSE;
    *canGenerateKeys  = FALSE;
    *isBSAFE		  = FALSE;
    *isRSAREF		  = FALSE;
    *isCAPI			  = FALSE;
	*isPGPRSA		  = FALSE;
	*copyright		  = '\0';

    err = PGPCountPublicKeyAlgorithms( &numAlgs );
    if( IsntPGPError( err ) )
    {
        PGPUInt32 algIndex;

        for( algIndex = 0; algIndex < numAlgs; algIndex++ )
        {
            PGPPublicKeyAlgorithmInfo algInfo;

            err = PGPGetIndexedPublicKeyAlgorithmInfo( algIndex, &algInfo );
            if( IsntPGPError( err ) &&
                    algInfo.algID == kPGPPublicKeyAlgorithm_RSA )
            {
                *haveRSAAlgorithm = TRUE;
                *canGenerateKeys = algInfo.canGenerate;

				if (strstr(algInfo.info.longName, "BSAFE") != NULL)
				{
					*isBSAFE = TRUE;
					strcpy(copyright, algInfo.info.copyright);
				}
				else if (strstr(algInfo.info.longName, "CAPI") != NULL)
				{
					*isCAPI = TRUE;
					strcpy(copyright, 
						"Uses the Enhanced CAPI Provider for RSA support" );
				}
				else if (strstr(algInfo.info.longName, "RSAREF") != NULL)
				{
					*isRSAREF = TRUE; 
					strcpy(copyright, algInfo.info.copyright);
				}
				else if (strstr(algInfo.info.longName, "PGP") != NULL)
				{
					*isPGPRSA = TRUE;
					strcpy(copyright, "");
				}
                break;					   
            }
        }
    }
	if (*isBSAFE == FALSE && *isCAPI == FALSE && *isRSAREF
		== FALSE && *isPGPRSA == FALSE)
	{
		strcpy(copyright,"DSS/DH only support");
	}
}

/*
   Get a passphrase from the user.  Note: this function allocates
   the new passphrase, but the caller is responsible for freeing
   it with PGPFreeData() then removing it from the leaks list using
   pgpRemoveFromPointerList( );
 */

PGPError pgpPassphraseDialogCmdline( struct pgpmainBones *mainbPtr,
PGPBoolean confirm, const char *prompt, char **passphrasePtr)
{
        PGPContextRef context = mainbPtr->pgpContext;
        struct pgpfileBones *filebPtr = mainbPtr->filebPtr;
		struct pgpenvBones *envbPtr=mainbPtr->envbPtr;
        PGPMemoryMgrRef mmgr = PGPGetContextMemoryMgr( context );
        PGPError err;
        char *pass1;
        char *pass2;
        PGPUInt32 attempts = 1;

        pgpAssertAddrValid( passphrasePtr, char * );
        *passphrasePtr = NULL;

        pass1 = PGPNewSecureData( mmgr, kMaxPassPhraseLength+1, 0 );
        if( pass1 == NULL)
            return kPGPError_OutOfMemory;
        pass2 = PGPNewSecureData( mmgr, kMaxPassPhraseLength+1, 0 );
        if( pass2 == NULL)
        {
            PGPFreeData(pass1);
            return kPGPError_OutOfMemory;
        }

        pgpAppendToPointerList( mainbPtr->leaks, pass1 );
        pgpAppendToPointerList( mainbPtr->leaks, pass2 );

        for (;;)
        {
            if( filebPtr->pgpout ) {
                if( prompt && *prompt != '\0')
                    fputs( prompt, filebPtr->pgpout);
                fprintf( filebPtr->pgpout, LANG("\nEnter pass phrase: "));
                fflush( filebPtr->pgpout );
            }

            /* hmm... how do i specify what fd to read from? */
			pgpTtyGetString( pass1, kMaxPassPhraseLength, envbPtr->bShowpass ? stdout : NULL);

            if( confirm ) {
                if( filebPtr->pgpout ) {
                    fprintf( filebPtr->pgpout,
                            LANG("\nEnter same pass phrase again: "));
                    fflush( filebPtr->pgpout );
                }
				pgpTtyGetString( pass2, kMaxPassPhraseLength, envbPtr->bShowpass ? stdout : NULL);

                if (strcmp(pass1,pass2)==0)
                    break;
                fprintf(filebPtr->pgpout,
LANG("\n\007Error: Pass phrases were different.  Try again."));
               fflush( filebPtr->pgpout );
            }
            else break;
        }    /* for */

        *passphrasePtr = pass1;
        err = PGPFreeData(pass2);
        pgpRemoveFromPointerList( mainbPtr->leaks, pass2 );

        fprintf(filebPtr->pgpout, "\n");
        pgpAssertNoErr(err);
        return kPGPError_NoErr;
}


PGPError genhandler(PGPContextRef context, struct PGPEvent *event,
        PGPUserValue userValue)
{
    struct pgpmainBones *mainbPtr = (struct pgpmainBones *)userValue;
    struct pgpfileBones *filebPtr = mainbPtr->filebPtr;
    PGPEnv *env = pgpContextGetEnvironment( context );
    PGPUInt32 need;
    PGPError err;
    PGPInt32 pri;
    PGPInt32 verbose = pgpenvGetInt( env, PGPENV_VERBOSE, &pri, &err );
    PGPBoolean compatible = mainbPtr->envbPtr->compatible;

    switch ( event->type ) {

        case kPGPEvent_EntropyEvent:
			{
				/* how much entropy do we need?*/
#if PGP_UNIX || PGP_WIN32
				PGPFlags	featureFlags;
#endif /* PGP_UNIX || PGP_WIN32 */

				need = event->data.entropyData.entropyBitsNeeded;
				if(verbose)
					fprintf( filebPtr->pgpout,
							LANG("event %d: entropy needed: %d\n"),
							event->type, need);

				/* usually equals this...*/
				/*need = PGPGlobalRandomPoolGetMinimumEntropy()*/
				/*    - PGPGlobalRandomPoolGetEntropy();*/

#if PGP_UNIX || PGP_WIN32
				err = PGPGetFeatureFlags(kPGPFeatures_GeneralSelector, 
					&featureFlags);
				if(IsntPGPError(err) &&	
					PGPFeatureExists(featureFlags, kPGPFeatureMask_RngHardware))
				{
					fprintf(filebPtr->pgpout,
		"Required entropy provided by hardware random number generator!\n");
				}
				else
				{
					err =  pgpAcquireEntropy(filebPtr, need);
				}

#else /* !PGP_UNIX && !PGP_WIN32 */
				err = PGPCollectRandomDataDialog( context, need,
						PGPOLastOption( context ) );
#endif /* PGP_UNIX || PGP_WIN32 */

				if( IsPGPError( err ) ) {
					if(!compatible)
						pgpShowError(filebPtr, err,__FILE__,__LINE__);
					return err;
				}
			}
            break;

        case kPGPEvent_KeyGenEvent:
            fprintf( filebPtr->pgpout,"%c", event->data.keyGenData.state);
            fflush( filebPtr->pgpout );
            break;

        default:
            /* ignore the event...*/
            if(verbose)
                fprintf( filebPtr->pgpout, LANG("event %d: unknown\n"),
                         event->type);
            err = 0;
    }
    return err;
}

PGPError askMasterKeySize(struct pgpfileBones *filebPtr,
        PGPPublicKeyAlgorithm sigalg, char *sigalgstr, PGPSize *numbits)
{
    int i;
    char scratch[8];
    PGPError err;

    for(i=0;i<3;i++) {
        if( sigalg == kPGPPublicKeyAlgorithm_DSA ) {

            fprintf(filebPtr->pgpout,
                    LANG("Pick your DSS ``master key'' size:\n"
					"1)  1024 bits- Maximum size (Recommended)\n"
					"Choose 1 or enter desired number of bits: "));
            pgpTtyGetString(scratch, 5, filebPtr->pgpout);

            if(strlen(scratch)==1) {
				if(*scratch == '1')
					*numbits=1024;
				else
					*numbits = -1;
            } else
                *numbits = atoi( scratch );
            if( *numbits & 0x3f ) {
                /* DSA keys must be multiple of 64 bits. round up a little.*/
                *numbits += (64 - ( *numbits & 0x3f ));
            }
            if( *numbits >= 768 && *numbits <= 1024) {
                err = kPGPError_NoErr;
                goto done;
            }
            fprintf(filebPtr->pgpout, 
                    LANG("\nKey size must range from 768-1024 bits.\n"));
        } else {
            /* RSA key size limited to no more than 2048 bits in sdk */
         fprintf(filebPtr->pgpout, LANG("Pick your %s key size:\n"
         "1)  1024 bits- High commercial grade, secure for many years\n"
         "2)  2048 bits- \"Military\" grade, secure for forseeable future\n"
         "Choose 1, 2, or enter desired number of bits: "), sigalgstr);

            pgpTtyGetString(scratch, 5, filebPtr->pgpout);

            if(strlen(scratch)==1) {
                if(*scratch == '1')
                    *numbits=1024;
                else if(*scratch == '2')
                    *numbits=2048;
				else
					*numbits = -1;
            } 
			else
                *numbits = atoi( scratch );
			//BEGIN RSA KEYSIZE MOD - Imad R. Faiad
            //if( *numbits >= 768 && *numbits <= 2048) {
			if( *numbits >= 768 && *numbits <= 16384) {
			//END RSA KEYSIZE MOD
                err = kPGPError_NoErr;
                goto done;
            }
			//BEGIN RSA KEYSIZE MOD - Imad R. Faiad
            //fprintf(filebPtr->pgpout,
                    //LANG("\nKey size must range from 768-2048 bits.\n"));
			
            fprintf(filebPtr->pgpout,
                    LANG("\nKey size must range from 768-16384 bits.\n"));
			//END RSA KEYSIZE MOD
        }
        fprintf(filebPtr->pgpout, LANG("\nInvalid response\n\n"));
    }

    err = kPGPError_UserAbort;
done:
    return err;
}

PGPError askKeySize(struct pgpfileBones *filebPtr,
        PGPPublicKeyAlgorithm alg, char *algstr, PGPSize *numbits)
{
    int i;
    char scratch[8];
    for(i=0;i<3;i++) {

        fprintf(filebPtr->pgpout, LANG("Pick your %s key size:\n"
"1)  1024 bits- High commercial grade, secure for many years\n"
"2)  2048 bits- \"Military\" grade, secure for forseeable future\n"
"3)  3072 bits- Archival grade, slow, highest security\n"
"Choose 1, 2, 3, or enter desired number of bits: "), algstr);

        pgpTtyGetString(scratch, 5, filebPtr->pgpout);

        if(strlen(scratch)==1) {
            if(*scratch == '1')
                *numbits=1024;
            else if(*scratch == '2')
                *numbits=2048;
            else if(*scratch == '3')
                *numbits=3072;
			else
				*numbits=-1;
        } else
            *numbits = atoi( scratch );
		//BEGIN DH KEYSIZE MOD - Imad R. Faiad
        //if( *numbits >= 768 && *numbits <= 4096)
		if( *numbits >= 768 && *numbits <= 8192)
            return kPGPError_NoErr;
        fprintf( filebPtr->pgpout,
                LANG("\nKey size must range from 768-8192 bits.\n"));
		//END DH KEYSIZE MOD
        fprintf( filebPtr->pgpout, LANG("\nInvalid response\n"));
    }

    return kPGPError_UserAbort;
}

PGPError askKeyValidityPeriod( struct pgpfileBones *filebPtr,
        const char *keytype,
        PGPSize deflt, PGPSize maximum, PGPSize *validfor )
{
    char scratch[8];
    int i;
    for( i=0; i<3; i++ ) {
       fprintf( filebPtr->pgpout,
       LANG("\nEnter the validity period of your %s key in days from 0 - %d\n"
       "0 is forever (the default is %d): "), keytype, maximum, deflt);
       fflush( filebPtr->pgpout );
        pgpTtyGetString(scratch, 6 , filebPtr->pgpout);
        if(strlen(scratch)==0)
            *validfor=deflt;
        else
            *validfor=atoi(scratch);

        if(*validfor >= 0 && *validfor <= maximum)
            return kPGPError_NoErr;

        fprintf( filebPtr->pgpout,
LANG("Validity must be between 0 and %d days!\n"), maximum);
    }
    return kPGPError_UserAbort;
}

PGPError askWhetherSubKey( struct pgpfileBones *filebPtr, PGPBoolean
        *encOnly )
{
    PGPBoolean ok=FALSE;
    char scratch[8];
    *encOnly=FALSE;
    while(!ok) {
        /* ask whether to generate a new signing key or to generate a*/
        /* new encryption key for an existing signing key.*/
        fprintf( filebPtr->pgpout,
LANG("Choose the type of key you want to generate\n"
"1) Generate a new signing key (default)\n"
"2) Generate an encryption key for an existing signing key\n"
"Choose 1 or 2: "));
        fflush( filebPtr->pgpout );
        pgpTtyGetString(scratch, 5, filebPtr->pgpout);
        if(strlen(scratch)!=1)
            scratch[1]='\0';
        switch( scratch[0] ) {
            case '\0':
            case '1':
                ok=TRUE;
                break;
            case '2':
                *encOnly=TRUE;
                ok=TRUE;
                break;
            default:
                fprintf( filebPtr->pgpout, LANG("Invalid response\n"));
        }
    }
    return kPGPError_NoErr;
}

PGPError askForMasterKey( struct pgpmainBones *mainbPtr, PGPKeyRef *mykey)
{
    struct pgpfileBones *filebPtr = mainbPtr->filebPtr;
    PGPEnv *env = filebPtr->envbPtr->m_env;
    PGPError err;
    PGPInt32 pri;
    char useridstr[kPGPMaxUserIDSize];
    const char *myName = pgpenvGetCString( env, PGPENV_MYNAME, &pri );
    PGPInt32 verbose = pgpenvGetInt( env, PGPENV_VERBOSE, &pri, &err );
    PGPBoolean canencrypt;
    PGPBoolean cansign = FALSE;
    PGPBoolean isdisabled = FALSE;
    PGPKeySetRef myset = NULL;
    PGPKeyListRef mylist = NULL;
    PGPKeyIterRef myiter = NULL;

    fprintf( filebPtr->pgpout, LANG("\n"));

    if ( myName != NULL && *myName != '\0' && pri >= PGPENV_PRI_CONFIG ) {
        strcpy(useridstr, myName);
    } else {
        fprintf( filebPtr->pgpout,
                LANG("Enter the user ID of your existing master key: ") );
        fflush( filebPtr->pgpout );
        pgpTtyGetString(useridstr, kPGPMaxUserIDSize-1 , filebPtr->pgpout);
    }

    err = pgpGetMatchingKeySet(mainbPtr, useridstr,
            kMatch_NotDisabled | kMatch_NotExpired | kMatch_NotKeyServer,
            &myset );

    pgpAssertNoErr(err);

    err = PGPOrderKeySet( myset, kPGPAnyOrdering, &mylist );
    pgpAssertNoErr(err);

    err = PGPNewKeyIter( mylist, &myiter );
    pgpAssertNoErr(err);
    err = PGPKeyIterRewind( myiter );
    pgpAssertNoErr(err);
    err = PGPKeyIterNext( myiter, mykey);

    if( IsPGPError(err))
        goto done;

    while( *mykey != NULL )  {
        /* simply choose the first key with the needed properties.
           matches MYNAME and is not disabled and is a signing key, but is
           not an encryption key.. */

        err = PGPGetKeyBoolean( *mykey, kPGPKeyPropIsDisabled, &isdisabled );
        pgpAssertNoErr(err);
        err = PGPGetKeyBoolean( *mykey, kPGPKeyPropCanEncrypt, &canencrypt );
        pgpAssertNoErr(err);
        err = PGPGetKeyBoolean( *mykey, kPGPKeyPropCanSign, &cansign );
        pgpAssertNoErr(err);

        if( cansign ) {
            if( verbose )
                pgpShowKeyBrief( filebPtr, *mykey );
            if( isdisabled )
                goto next;
            /* it's okay to have one that can already encrypt.
              if( canencrypt )
                  goto next;
             */
            break;
        }
next:
        err = PGPKeyIterNext( myiter, mykey);
    }

done:
    if(myiter)
        PGPFreeKeyIter( myiter );
    if(mylist)
        PGPFreeKeyList( mylist );
    if(myset)
        PGPFreeKeySet( myset );

    if( !cansign ) {
        *mykey = NULL;
        return kPGPError_SecretKeyNotFound;
    }

    return kPGPError_NoErr;
}

PGPError pgpGetKeyRemainingValidityDays( PGPKeyRef key, PGPInt32 *days )
{
    PGPError err;
    PGPTime now,expyTime;

    now = PGPGetTime();
    err = PGPGetKeyTime( key, kPGPKeyPropExpiration, &expyTime );
    pgpAssertNoErr(err);

    if( ( expyTime - now ) < 0 )
        return kPGPError_KeyExpired;

    *days = ( expyTime - now ) / 86400;

    if( *days > kMaxKeyExpirationDays )
        *days = kPGPExpirationTime_Never;

    return kPGPError_NoErr;
}

PGPError askUserIDString( struct pgpfileBones *filebPtr, char *useridstr )
{
    struct pgpenvBones *envbPtr=filebPtr->envbPtr;
    PGPEnv *env = envbPtr->m_env;
    PGPInt32 pri;
    const char *myname = pgpenvGetCString( env, PGPENV_MYNAME, &pri );
    int i;

    if ( myname != NULL && *myname != '\0' && pri > PGPENV_PRI_CONFIG ) {
        strcpy(useridstr, myname);
        return kPGPError_NoErr;
    }

    for(i=0; i<3; i++) {
        fprintf(  filebPtr->pgpout,
                LANG(
"\nYou need a user ID for your public key.  The desired form for this\n"
"user ID is your name, followed by your E-mail address enclosed in\n"
"<angle brackets>, if you have an E-mail address.\n"
"For example:  John Q. Smith <jqsmith@nai.com>\n") );
        fprintf( filebPtr->pgpout,
                LANG("Enter a user ID for your public key: ") );
        fflush( filebPtr->pgpout );
        pgpTtyGetString(useridstr, kPGPMaxUserIDSize-1 , filebPtr->pgpout);
        if( strlen(useridstr) > 0 )
            return kPGPError_NoErr;
        fprintf( filebPtr->pgpout, LANG("\nInvalid response.\n"));
    }
    return kPGPError_UserAbort;
}

/*
  Do a key pair generation, and write them out to the keyring files.
  sigbitsstr is a decimal string, the desired bitcount for the DSA component.
  encbitsstr is a decimal string, the desired bitcount for the ElGamal
  component.

  If the 2.6.2 compatibility bit is FALSE, activate advanced features to
  ask for master and/or subkey generation.
 */

int dokeygen(struct pgpmainBones *mainbPtr,char *sigbitsstr, char
        *encbitsstr )
{
    PGPContextRef context = mainbPtr->pgpContext;
    char useridstr[kPGPMaxUserIDSize];
    PGPSize sigbits,encbits;
    struct pgpfileBones *filebPtr=mainbPtr->filebPtr;
    struct pgpenvBones *envbPtr=mainbPtr->envbPtr;
    PGPEnv *env = envbPtr->m_env;
    PGPError err;
    char *passphrase;
    PGPInt32 pri;
    PGPBoolean signOnly = FALSE, encOnly = FALSE;
    PGPBoolean batchmode = pgpenvGetInt( env, PGPENV_BATCHMODE, &pri, &err );
    PGPBoolean compatible = envbPtr->compatible;
    PGPPublicKeyAlgorithm sigalg,encalg;
    PGPSize sigvalidfor,encvalidfor;
    char *sigalgstr, *encalgstr;
    PGPUInt32 signeed = 0, encneed = 0;
    PGPKeySetRef keyringset = NULL;
    PGPKeyRef masterkey = NULL;
    PGPSubKeyRef subkey = NULL;
    PGPBoolean needsfree = FALSE;
    PGPBoolean haveRSAAlgorithm;
    PGPBoolean canGenerateKeys;
    PGPBoolean isBSAFE = FALSE;
    PGPBoolean isRSAREF = FALSE;
    PGPBoolean isCAPI  = FALSE;
	PGPBoolean isPGPRSA = FALSE;


	PGPBoolean		bADKEnabled = FALSE;
	PGPKeySetRef	tmpKeySet = kPGPInvalidRef;
	PGPKeySetRef	adkKeySet = kPGPInvalidRef;
	PGPKeyIterRef	keyIter = kPGPInvalidRef;
	PGPKeyListRef	keyList = kPGPInvalidRef;

#if PGP_UNIX || PGP_WIN32
	PGPFlags	featureFlags;
#endif /* PGP_UNIX || PGP_WIN32 */

	char	   copyright[255];

    /* pgp -kg [sigbits [encbits]] */
    /* Assumption: the following dialog makes sense for the case:
       generate signing key only. */

    sigalg = kPGPPublicKeyAlgorithm_DSA;
    encalg = kPGPPublicKeyAlgorithm_ElGamal;

    if(compatible) {
        sigalgstr = "DSS/DH";
        encalgstr = "DSS/DH";
    } else {
        sigalgstr = "DSS";
        encalgstr = "DH";
    }

    err = PGPOpenDefaultKeyRings( context,
            kPGPKeyRingOpenFlags_Create|kPGPKeyRingOpenFlags_Mutable,
            &keyringset );

    if( IsPGPError(err) ) {
        fprintf( filebPtr->pgpout, LANG("Can't open key rings\n"));
        return -1;
    }



	/*
	 *	Check to see if ADK is enabled
	 */
	if(envbPtr->pszADKKey != NULL)
	{
		PGPKeyRef		adkKey = kPGPInvalidRef;
		PGPUInt32		uAlgorithm = 0;
	
		mainbPtr->workingRingSet = keyringset;
		
		err = pgpGetMatchingKeySet(mainbPtr, envbPtr->pszADKKey,
				kMatch_NotDisabled | kMatch_NotExpired | kMatch_NotKeyServer,
				&tmpKeySet); 
		CHKERR(ex);

		/* get first key from keyring, making sure it isn't a RSA key */
		err = PGPOrderKeySet(tmpKeySet, kPGPAnyOrdering, &keyList);
		CHKERR(ex);

		err = PGPNewKeyIter(keyList, &keyIter);   CHKERR(ex);

		err = PGPKeyIterRewind(keyIter);  CHKERR(ex);
		
		err = PGPKeyIterNext(keyIter, &adkKey);
		pgpAssertNoErr(err);

		if(IsntPGPError(err) && adkKey != kPGPInvalidRef)
		{
			PGPBoolean	bCanEncrypt = FALSE;

			PGPGetKeyNumber(adkKey, kPGPKeyPropAlgID, (int *)&uAlgorithm);

			switch(uAlgorithm) 
			{
				case kPGPPublicKeyAlgorithm_DSA :
					/*
					 *	Make sure that key can encrypt
					 */
					err = PGPGetKeyBoolean(adkKey, kPGPKeyPropCanEncrypt,
												&bCanEncrypt);
					CHKERR(ex);
					if(bCanEncrypt == FALSE)
					{
						fprintf(filebPtr->pgpout,
		LANG("Error, specified ADK key is a sign-only key!"));
						err = kPGPError_BadParams;  CHKERR(ex);
					}
					err = PGPNewSingletonKeySet(adkKey, &adkKeySet);
					CHKERR(ex);
					bADKEnabled = TRUE;
					break;

				case kPGPPublicKeyAlgorithm_RSA :
				default:
					fprintf(filebPtr->pgpout,
					"Error, ADK key must be a Diffie-Hellman key!\n");
					err = kPGPError_BadParams;
					goto ex;
			}									  
		}
		else
		{
			fprintf(filebPtr->pgpout,
				"Error, unable to find ADK key!\n");
			err = kPGPError_BadParams;
			goto ex;
		}
	}

    GetRSAStatus( &haveRSAAlgorithm, &canGenerateKeys, &isBSAFE, 
		&isRSAREF, &isCAPI, &isPGPRSA, copyright );

	if(bADKEnabled == TRUE)
	{
		/*
		 *	If ADKKEY is valid, don't allow RSA key generation
		 */
		if(haveRSAAlgorithm)
			fprintf(filebPtr->pgpout,
			LANG("Incoming ADK key set, disabling RSA key gen!\n"));
		haveRSAAlgorithm = FALSE;

	}

    if( haveRSAAlgorithm && canGenerateKeys && !compatible ) {
        char scratch[8];
        PGPBoolean ok=FALSE;
        while(!ok) {
            fputs(
             LANG("Choose the public-key algorithm to use with your new key\n"
                  "1) DSS/DH (a.k.a. DSA/ElGamal) (default)\n"
                  "2) RSA\nChoose 1 or 2: "), filebPtr->pgpout);
            pgpTtyGetString(scratch, 5, filebPtr->pgpout);

            if(strlen(scratch)!=1)
                scratch[1]='\0';
            switch( scratch[0] ) {
                case '\0':
                case '1':
                    ok=TRUE;
                    break;
                case '2':

#ifdef TRY_RSA_MASTER_SUBKEY
                    sigalg = kPGPPublicKeyAlgorithm_RSASignOnly;
                    encalg = kPGPPublicKeyAlgorithm_RSAEncryptOnly;
                    sigalgstr = LANG("RSA Sign");
                    encalgstr = LANG("RSA Encrypt");
#else
                    sigalg = kPGPPublicKeyAlgorithm_RSA;
                    encalg = kPGPPublicKeyAlgorithm_RSA;
                    sigalgstr = "RSA";
                    encalgstr = "RSA";
#endif
                    ok=TRUE;
                    break;
                default:
                    fprintf( filebPtr->pgpout, LANG("Invalid response\n"));
            }
        }
    }

    if( !compatible ) {
        if(encalg != kPGPPublicKeyAlgorithm_RSA
            && encalg != kPGPPublicKeyAlgorithm_RSASignOnly
            && encalg != kPGPPublicKeyAlgorithm_RSAEncryptOnly)
        {

            err = askWhetherSubKey( filebPtr, &encOnly );
            if( IsPGPError(err) )
                goto ex;
        }

        if( encOnly ) {
            PGPInt32 algnum;

            mainbPtr->workingRingSet = keyringset;
            /*mainbPtr->workingGroupSet = NULL;*/
            err = askForMasterKey( mainbPtr, &masterkey);
            if( IsPGPError(err) )
                goto ex;

            PGPGetKeyNumber( masterkey, kPGPKeyPropAlgID, &algnum );
            sigalg = algnum;
            switch( sigalg ) {
                case kPGPPublicKeyAlgorithm_DSA:
                    break;

                case kPGPPublicKeyAlgorithm_RSASignOnly:
                    if( haveRSAAlgorithm && canGenerateKeys ) {
                        encalg = kPGPPublicKeyAlgorithm_RSAEncryptOnly;
                        encalgstr = LANG("RSA Encrypt-only");
                        break;
                    }

                case kPGPPublicKeyAlgorithm_RSA:
                    if( haveRSAAlgorithm ) {
                        fprintf( filebPtr->pgpout,
                          LANG("error: That key doesn't require a subkey\n"));

                        err = kPGPError_ItemAlreadyExists;
                        /* hmm... don't need a subkey.*/
                        goto ex;
                    }

                default:
                    fprintf( filebPtr->pgpout,
                            LANG("error: Unknown public key algorithm\n"));
                    err = kPGPError_BadParams;
                    goto ex;
            }

            err = pgpGetKeyRemainingValidityDays( masterkey, &sigvalidfor );
            pgpAssertNoErr(err);

            err = pgpGetValidPassphrase( mainbPtr, masterkey, &passphrase,
                    &needsfree );

            if( IsPGPError(err) )
                goto ex;

            signeed = 0;

            /* must have: default encbits, sigalg, encalg, signeed,
               sigvalidfor, passphrase*/
            goto encr;
        }
    }

    if (sigbitsstr && *sigbitsstr) {
        sigbits = atoi( sigbitsstr );
        if( sigbits < 768 )
            goto ex;
    } else {
        if(compatible) {
            err = askKeySize( filebPtr, encalg, encalgstr, &encbits );
            if( err == kPGPError_UserAbort )
                goto ex;
            if( encbits > 1024 )
                sigbits = 1024;
            else
                sigbits = encbits;
            fprintf( filebPtr->pgpout, LANG("Generating a %d-bit %s key.\n"),
                    encbits, encalgstr);

        } else {
            err = askMasterKeySize( filebPtr, sigalg, sigalgstr, &sigbits );
            if( err == kPGPError_UserAbort )
                goto ex;
            encbits = sigbits;

            fprintf( filebPtr->pgpout, LANG("Generating a %d-bit %s key.\n"),
                    sigbits, sigalgstr);
        }
    }

    /* ( !encOnly )*/
    {
        err = askUserIDString( filebPtr, useridstr );
        if( err == kPGPError_UserAbort )
            goto ex;

        sigvalidfor=0;
        if(!compatible) {
            err = askKeyValidityPeriod( filebPtr, LANG("signing"), 0,
                    kMaxKeyExpirationDays, &sigvalidfor );

            if( IsPGPError(err) )
                goto ex;
        }

        fprintf( filebPtr->pgpout,
LANG("\nYou need a pass phrase to protect your %s secret key.\n"
"Your pass phrase can be any sentence or phrase and may have many\n"
"words, spaces, punctuation, or any other printable characters.\n"),
            sigalgstr);

        err = pgpPassphraseDialogCmdline( mainbPtr, TRUE, NULL, &passphrase);
        needsfree = TRUE;

        if( IsPGPError( err ) ) {
            pgpShowError( filebPtr, err, __FILE__,__LINE__ );
            goto ex;
        }

        if( sigalg == kPGPPublicKeyAlgorithm_DSA )
            sigbits = (encbits > kMaxDSS_Bits ? kMaxDSS_Bits : encbits);
        else
            sigbits = encbits;

        if( !compatible && encalg != kPGPPublicKeyAlgorithm_RSA
                && encalg != kPGPPublicKeyAlgorithm_RSAEncryptOnly
                && encalg != kPGPPublicKeyAlgorithm_RSASignOnly)
        {
          fprintf( filebPtr->pgpout,
           LANG("\nPGP will generate a signing key. Do you also require an \n"
            "encryption key? (Y/n) "));
            fflush( filebPtr->pgpout );
            signOnly = !getyesno(filebPtr, 'y', batchmode);
        }

        signeed = PGPGetKeyEntropyNeeded( context,
                PGPOKeyGenParams( context, sigalg, sigbits ),
                PGPOLastOption( context ));
    }

encr:
    /* must have: default encbits, sigalg, encalg, signeed, sigvalidfor,
       passphrase*/

    if( !compatible ) {
        if(signOnly)
            encneed = 0;
        else if(encalg != kPGPPublicKeyAlgorithm_RSA
                && encalg != kPGPPublicKeyAlgorithm_RSAEncryptOnly
                && encalg != kPGPPublicKeyAlgorithm_RSASignOnly)
        {
            err = askKeySize( filebPtr, encalg, encalgstr, &encbits );
            if( err == kPGPError_UserAbort )
                goto ex;

            err = askKeyValidityPeriod( filebPtr, LANG("encryption"),
                    sigvalidfor, (sigvalidfor == 0 ?
                            kMaxKeyExpirationDays : sigvalidfor),
                    &encvalidfor );

            if(encvalidfor == 0)
                encvalidfor = kPGPExpirationTime_Never;
        }
    }

    encneed = PGPGetKeyEntropyNeeded( context,
            PGPOKeyGenParams( context, encalg, encbits ),
            PGPOLastOption( context ));

    fprintf( filebPtr->pgpout,
            LANG("\n\nNote that key generation is a lengthy process.\n") );

#if PGP_UNIX || PGP_WIN32
	err = PGPGetFeatureFlags(kPGPFeatures_GeneralSelector, &featureFlags);
	if(IsntPGPError(err) &&	
		PGPFeatureExists(featureFlags, kPGPFeatureMask_RngHardware))
	{
		fprintf(filebPtr->pgpout,
"Required entropy provided by hardware random number generator!\n");
	}
	else
	{
		err =  pgpAcquireEntropy(filebPtr, signeed+encneed);
	}
#else /* !PGP_UNIX && !PGP_WIN32 */
    err = PGPCollectRandomDataDialog( context, signeed+encneed,
            PGPOLastOption( context ) );

#endif /* PGP_UNIX || PGP_WIN32 */

    if( IsPGPError( err ) ) {
        if(!compatible)
            pgpShowError( filebPtr, err ,__FILE__,__LINE__);
        goto ex;
    }

    if( !encOnly ) {
        /* generate the master key*/

		if(sigvalidfor == 0)
            sigvalidfor = kPGPExpirationTime_Never;
        err = PGPGenerateKey ( context, &masterkey,
                PGPOKeySetRef( context, keyringset ),
                PGPOKeyGenParams( context, sigalg, sigbits ),
                PGPOKeyGenName( context, useridstr, strlen(useridstr) ),
                PGPOExpiration( context, sigvalidfor ),
                PGPOPassphrase( context, passphrase ),
				bADKEnabled ?
				PGPOAdditionalRecipientRequestKeySet(context,
					adkKeySet, (PGPByte)(envbPtr->bEnforceADK ?
					ENFORCE_ADK : 0x00)) :
				PGPONullOption(context),
                PGPOEventHandler( context, genhandler, (PGPUserValue)
                        mainbPtr ),
                PGPOLastOption( context ));
        if( IsPGPError( err ) ) {
            if(!compatible)
                pgpShowError( filebPtr, err ,__FILE__,__LINE__);
            goto ex;
        }

        /* set this key's trust to axiomatic*/
        err = PGPSetKeyAxiomatic( masterkey, PGPOLastOption( context));
        pgpAssertNoErr(err);

        if(!compatible) {
            /* make this the default signing key (unless MYNAME overrides)*/
            fprintf( filebPtr->pgpout,
                    LANG("\nMake this the default signing key? (Y/n) "));
            fflush(filebPtr->pgpout);
            if(getyesno(filebPtr, 'y', batchmode))
                err = PGPSetDefaultPrivateKey(masterkey);
        } else
            err = PGPSetDefaultPrivateKey(masterkey);
        pgpAssertNoErr(err);
        err = PGPsdkSavePrefs( context );
        pgpAssertNoErr(err);
    }

#ifndef TRY_RSA_MASTER_SUBKEY
    if( sigalg == kPGPPublicKeyAlgorithm_RSA )
        goto commit;
#endif

    if( !signOnly ) {
        /* generate the sub key*/

        if(encvalidfor == 0)
            encvalidfor = kPGPExpirationTime_Never;
        err = PGPGenerateSubKey ( context, &subkey,
                PGPOKeyGenMasterKey( context, masterkey ),
                PGPOKeyGenParams( context, encalg, encbits ),
                PGPOExpiration( context, encvalidfor ),
                PGPOPassphrase( context, passphrase ),
                PGPOEventHandler( context, genhandler, (PGPUserValue)
                        mainbPtr ),
                PGPOLastOption( context ));
        if( IsPGPError(err) ) {
            if(!compatible)
                pgpShowError( filebPtr, err,0,0); /*__FILE__,__LINE__);*/
            goto ex;
        }
    }

commit:
    err = PGPCommitKeyRingChanges( keyringset );

    if( IsntPGPError(err))
        fprintf( filebPtr->pgpout, LANG("\nKey generation completed.\n"));

ex:
	if(IsPGPError(err))
	{
		if(!compatible)
			pgpShowError(filebPtr, err, __FILE__, __LINE__);
	}
	if(keyList != kPGPInvalidRef)
		PGPFreeKeyList(keyList);
	if(keyIter != kPGPInvalidRef)
		PGPFreeKeyIter(keyIter);
	if(tmpKeySet != kPGPInvalidRef)
		PGPFreeKeySet(tmpKeySet);
	if(adkKeySet != kPGPInvalidRef)
		PGPFreeKeySet(adkKeySet);
    if( keyringset ) {
        PGPFreeKeySet( keyringset );
        mainbPtr->workingRingSet = NULL;
    }
    if( passphrase && needsfree ) {
        PGPFreeData(passphrase);
        pgpRemoveFromPointerList( mainbPtr->leaks, passphrase );
    }

    return err;
}