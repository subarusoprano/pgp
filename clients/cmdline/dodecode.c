/*____________________________________________________________________________
    dodeocde.c

    Copyright(C) 1998,1999 Network Associates, Inc.
    All rights reserved.

	PGP 6.5 Command Line 

    uses the PGP SDK to decode messages.

    $Id: dodecode.c,v 1.14.14.8 1999/11/09 01:49:09 sluu Exp $
____________________________________________________________________________*/

#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include "pgpBase.h"
#include "pgpKeys.h"
#include "pgpErrors.h"
#include "pgpUserInterface.h"
#include "pgpUtilities.h"

#include "config.h"
#include "usuals.h"
#include "language.h"
#include "pgp.h"
#include "globals.h"
#include "fileio.h"
#include "exitcodes.h"
#include "prototypes.h"


 /* input: is a key iter positioned at a particular key.
    returns: the number of userids associated with the key.
    side-effects: the positioned userid is reuturned undefined.
  */

PGPError pgpCountKeyUserIDs( PGPKeyIterRef keyiter, PGPUInt32 *numuserids )
{
    PGPError err;
    PGPUserIDRef userid;
    *numuserids = 0;

    /* list all userids associated with the key. */
    err = PGPKeyIterRewindUserID( keyiter );
    if(err)
        return err;

    err = PGPKeyIterNextUserID( keyiter, &userid);
    pgpAssertNoErr(err);
    if( userid ) {
        while( userid ) {
            (*numuserids)++;
            err = PGPKeyIterNextUserID( keyiter, &userid);
        }
    }
    return kPGPError_NoErr;
}

PGPError addHandler(PGPContextRef context, struct PGPEvent *event,
        PGPUserValue userValue)
{
    struct pgpmainBones *mainbPtr = (struct pgpmainBones *)userValue;
    struct pgpfileBones *filebPtr = mainbPtr->filebPtr;
    struct pgpenvBones *envbPtr = mainbPtr->envbPtr;
    PGPEnv *env = envbPtr->m_env;
    PGPJobRef job = event->job;

	static PGPUInt16	lastEvent = 0;

    PGPError err;
    PGPInt32 pri;
    PGPInt32 verbose = pgpenvGetInt( env, PGPENV_VERBOSE, &pri, &err );
    PGPBoolean quietmode = pgpenvGetInt( env, PGPENV_NOOUT, &pri, &err);
    PGPInt32 batchmode = pgpenvGetInt( env, PGPENV_BATCHMODE, &pri, &err );

    /* get the event type*/
    switch ( event->type ) {
        case kPGPEvent_FinalEvent:
            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: final\n"),
                        event->type);

                        err = kPGPError_NoErr;

            /* finish adding any keys*/
            addToWorkingRingSetFinish( mainbPtr );

			/*
			 *	Check to see if last event was kPGPEvent_InitialEvent,
			 *	if yes, indicates file was not encrypted/signed
			 */
			if(lastEvent == kPGPEvent_InitialEvent)
			{
				fprintf(filebPtr->pgpout,
					LANG("File is not a PGP file!\n"));
			}
            break;

        case kPGPEvent_InitialEvent:
			lastEvent = kPGPEvent_InitialEvent;
            if( verbose )
                fprintf( filebPtr->pgpout, LANG("\nevent %d: initial\n"),
                        event->type);
            /* set up whatever we need to here*/
            err = kPGPError_NoErr;
            break;

        case kPGPEvent_BeginLexEvent:
			lastEvent = kPGPEvent_BeginLexEvent;
            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: BeginLex\n"),
                        event->type);
            err = kPGPError_NoErr;
            break;

        case kPGPEvent_EndLexEvent:
			lastEvent = kPGPEvent_EndLexEvent;
			if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: EndLex\n"),
                        event->type);
            err = kPGPError_NoErr;

            break;

        case kPGPEvent_AnalyzeEvent:
			lastEvent = kPGPEvent_AnalyzeEvent;
            if (quietmode) {
                err = kPGPError_NoErr;
                break;
            }

            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: Analyze\n"),
                        event->type);

            switch ( event->data.analyzeData.sectionType ) {
                case kPGPAnalyze_Encrypted:
                    fprintf( filebPtr->pgpout, LANG("File is encrypted.  "));
                    break;
                case kPGPAnalyze_Signed:
                    fprintf( filebPtr->pgpout, LANG("File is signed.  "));
                    break;
                case kPGPAnalyze_DetachedSignature:
                    fprintf( filebPtr->pgpout, LANG(
                            "File '%s' has signature, but with no text.\n"),
                            mainbPtr->plainfilename);

                    break;
                case kPGPAnalyze_Key:
					/*
                    fprintf( filebPtr->pgpout,
                      LANG( "File '%s' contains keys.\n"),
                      mainbPtr->plainfilename );
					*/

                    break;
                case kPGPAnalyze_Unknown:
                default:
                    fprintf( filebPtr->pgpout,
                            LANG("Unable to analyze event.\n"));

                    break;
            }
            err = kPGPError_NoErr;
            break;

        case kPGPEvent_KeyFoundEvent:
            {
				lastEvent = kPGPEvent_KeyFoundEvent;
                if(verbose) {
                    fprintf( filebPtr->pgpout,
                            LANG("\nevent %d: key found\n"),
                            event->type);

                    fprintf( filebPtr->pgpout, LANG("%08lx\n"),
                            event->data.keyFoundData.keySet );

                }
                addToWorkingRingSet( mainbPtr,
                        event->data.keyFoundData.keySet, FALSE );
            }
            break;

        case kPGPEvent_DetachedSignatureEvent:
        case kPGPEvent_SignatureEvent:
        case kPGPEvent_DecryptionEvent:
        case kPGPEvent_OutputEvent:
        case kPGPEvent_RecipientsEvent:
        case kPGPEvent_PassphraseEvent:
            break;

        case kPGPEvent_ErrorEvent:
			lastEvent = kPGPEvent_ErrorEvent;
            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: error %d\n"),
                        event->type,event->data.errorData.error);
            if( event->data.errorData.error ) {
                err = PGPAddJobOptions( job,
                        PGPOAppendOutput(context, FALSE),
                        PGPOLastOption( context ) );
                pgpAssertNoErr(err);
            }
            
            if(errno == ENOSPC)
                fprintf(filebPtr->pgpout,
                        LANG("Error: No space left on device.\n"));

            err = 0;
            break;

        case kPGPEvent_WarningEvent:
			lastEvent = kPGPEvent_WarningEvent;

            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: warning %d\n"),
                        event->type,event->data.warningData.warning);
            /*if( event->data.warningData.warning == kPGPError_KeyInvalid )*/
            err = 0;
            break;

        default:
            /* ignore the event...*/
            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: unknown\n"),
                        event->type);
            err = 0;
    }
    return err;
}


PGPError decHandler(PGPContextRef context, struct PGPEvent *event,
        PGPUserValue userValue)
{
    struct pgpmainBones *mainbPtr = (struct pgpmainBones *)userValue;
    struct pgpfileBones *filebPtr = mainbPtr->filebPtr;
    struct pgpenvBones *envbPtr = mainbPtr->envbPtr;
    PGPEnv *env = envbPtr->m_env;
    PGPJobRef job = event->job;

	static PGPUInt16	lastEvent = 0;

    PGPError err;
    PGPInt32 pri;
    PGPInt32 verbose = pgpenvGetInt( env, PGPENV_VERBOSE, &pri, &err );
    PGPBoolean quietmode = pgpenvGetInt( env, PGPENV_NOOUT, &pri, &err);
    PGPInt32 batchmode = pgpenvGetInt( env, PGPENV_BATCHMODE, &pri, &err );

    /* get the event type*/
    switch ( event->type ) {
        case kPGPEvent_FinalEvent:
            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: final\n"),
                        event->type);

                        err = kPGPError_NoErr;

            /* finish adding any keys*/
            addToWorkingRingSetFinish( mainbPtr );

			/*
			 *	Check to see if last event was kPGPEvent_InitialEvent,
			 *	if yes, indicates file was not encrypted/signed
			 */
			if(lastEvent == kPGPEvent_InitialEvent)
			{
				fprintf(filebPtr->pgpout,
					LANG("File is not a PGP file!\n"));
			}
            break;

        case kPGPEvent_InitialEvent:
			lastEvent = kPGPEvent_InitialEvent;
            if( verbose )
                fprintf( filebPtr->pgpout, LANG("\nevent %d: initial\n"),
                        event->type);
            /* set up whatever we need to here*/
            err = kPGPError_NoErr;
            break;

        case kPGPEvent_BeginLexEvent:
			lastEvent = kPGPEvent_BeginLexEvent;
            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: BeginLex\n"),
                        event->type);
            err = kPGPError_NoErr;
            break;

        case kPGPEvent_EndLexEvent:
			lastEvent = kPGPEvent_EndLexEvent;
			if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: EndLex\n"),
                        event->type);
            err = kPGPError_NoErr;

            break;

        case kPGPEvent_AnalyzeEvent:
			lastEvent = kPGPEvent_AnalyzeEvent;
            if (quietmode) {
                err = kPGPError_NoErr;
                break;
            }

            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: Analyze\n"),
                        event->type);

            switch ( event->data.analyzeData.sectionType ) {
                case kPGPAnalyze_Encrypted:
                    fprintf( filebPtr->pgpout, LANG("File is encrypted.  "));
                    break;
                case kPGPAnalyze_Signed:
                    fprintf( filebPtr->pgpout, LANG("File is signed.  "));
                    break;
                case kPGPAnalyze_DetachedSignature:
                    fprintf( filebPtr->pgpout, LANG(
                            "File '%s' has signature, but with no text.\n"),
                            mainbPtr->plainfilename);

                    break;
                case kPGPAnalyze_Key:
                    /*fprintf( filebPtr->pgpout,
                      LANG( "File '%s' contains keys.\n"),
                      mainbPtr->plainfilename );*/

                    break;
                case kPGPAnalyze_Unknown:
                default:
                    fprintf( filebPtr->pgpout,
                            LANG("Unable to analyze event.\n"));

                    break;
            }
            err = kPGPError_NoErr;
            break;

        case kPGPEvent_RecipientsEvent:
            {
                PGPKeySetRef keyset =
                    event->data.recipientsData.recipientSet;

                PGPKeyRef key = NULL;
                PGPKeyListRef keylist = NULL;
                PGPKeyIterRef keyiter = NULL;
				PGPBoolean		bFoundSecretKey = FALSE;
				lastEvent = kPGPEvent_RecipientsEvent;

                if( verbose )
                    fprintf( filebPtr->pgpout,
                            LANG("event %d: Recipients\n"),
                            event->type);

                err = kPGPError_NoErr;
                if( event->data.recipientsData.conventionalPassphraseCount
                        < 1)
                {
                    if (!quietmode) {
                        fprintf( filebPtr->pgpout,
                            LANG("Secret key is required to read it.\n"));
                    }
                    err = PGPOrderKeySet( keyset, kPGPAnyOrdering,
                            &keylist );
                    pgpAssertNoErr(err);
                    err = PGPNewKeyIter( keylist, &keyiter );
                    pgpAssertNoErr(err);
                    err = PGPKeyIterRewindUserID( keyiter );
                    pgpAssertNoErr(err);
                    err = PGPKeyIterNext( keyiter, &key);

                    if ( IsPGPError(err) ) {
                        err = kPGPError_NoDecryptionKeyFound;
                        fprintf(filebPtr->pgpout,
LANG("You do not have the secret key needed to decrypt this file.\n"));
                    }
                    else {
                        while( key != NULL )
                        {
                            PGPBoolean issecret;
                            err = PGPGetKeyBoolean( key, kPGPKeyPropIsSecret,
                                &issecret);
                            pgpAssertNoErr(err);

                            if (issecret || verbose) {

								/* found at least one secret key */
								if(issecret)
								{
									bFoundSecretKey = TRUE;
								}
                                if (issecret && quietmode) {
                                    err = pgpShowKeyUserID(filebPtr, key);
                                    pgpAssertNoErr(err);
                                }
                                else {
                                    err = pgpShowKeyBrief(filebPtr, key);
                                    pgpAssertNoErr(err);
                                }
                            }
                            err = PGPKeyIterNext( keyiter, &key);
                            /*if err, there are no more*/
                        }
						if(!bFoundSecretKey)
						{
							err = kPGPError_NoDecryptionKeyFound;
							fprintf(filebPtr->pgpout,
	LANG("You do not have the secret key needed to decrypt this file.\n"));
						}
                    }
                    if(keyiter)
                        PGPFreeKeyIter(keyiter);
                    if(keylist)
                        PGPFreeKeyList(keylist);
                    if(err == kPGPError_EndOfIteration)
                        err = kPGPError_NoErr;
                }
            }
            break;

        case kPGPEvent_PassphraseEvent:
            {
                PGPBoolean mine=FALSE;
                char *passphrase;

				lastEvent = kPGPEvent_PassphraseEvent;

                if( verbose )
                    fprintf( filebPtr->pgpout,
                            LANG("event %d: Passphrase\n"), event->type);

                /* when this event occurs, try any passphrases already
                   stored first, then try each one until we get a
                   hit. once they're used up, ask the user directly. */

                err = pgpNextPassphrase( envbPtr->passwds, &passphrase );
                if( err == kPGPError_EndOfIteration )
                    err = kPGPError_MissingPassphrase;

                if(!batchmode && passphrase == NULL) {
                    mine=TRUE;

                    if( event->data.passphraseData.fConventional ) {
                        fprintf( filebPtr->pgpout, LANG(
"You need a pass phrase to decrypt this file.\n") );
                    } else {
                        fprintf( filebPtr->pgpout, LANG(
"You need a pass phrase to unlock your secret key.\n") );
                    }

                    err = pgpPassphraseDialogCmdline( mainbPtr, FALSE,
                            NULL, &passphrase);

                }
                if( IsntPGPError(err)) {
                    err = PGPAddJobOptions( job,
                            PGPOPassphrase( context, passphrase ),
                            PGPOLastOption( context ) );
                    pgpAssertNoErr(err);
                }
                if(mine) {
                    PGPFreeData( passphrase );
                    pgpRemoveFromPointerList( mainbPtr->leaks, passphrase );
                }
            }
            break;

        case kPGPEvent_KeyFoundEvent:
            {
				PGPKeySetRef	tmpKeySet = kPGPInvalidRef;
				lastEvent = kPGPEvent_KeyFoundEvent;
                if(verbose) {
                    fprintf( filebPtr->pgpout,
                            LANG("\nevent %d: key found\n"),
                            event->type);

                    fprintf( filebPtr->pgpout, LANG("%08lx\n"),
                            event->data.keyFoundData.keySet );

                }
				tmpKeySet = mainbPtr->workingRingSet;

                err = addToWorkingRingSet( mainbPtr,
                        event->data.keyFoundData.keySet, TRUE );

				mainbPtr->workingRingSet = tmpKeySet;

            }
            break;

        case kPGPEvent_DetachedSignatureEvent:
            {
				PGPBoolean	bUseDefault = TRUE;
                PGPFileSpecRef plainFileSpec;
				lastEvent = kPGPEvent_DetachedSignatureEvent;

                if(verbose)
                    fprintf( filebPtr->pgpout,
                            LANG("\nevent %d: detached signature\n"),
                            event->type);

                /* if separate signature, need to communicate that*/
                /* to the output routines...*/
                mainbPtr->separateSignature = TRUE;

		/* check to see if input file is specified on cmd line */
		if(mainbPtr->recipients && *mainbPtr->recipients != NULL)
		{
			/*
			 *	Check to see if file exists, if not, use default
			 */
			if(fileExists(*mainbPtr->recipients))
			{
				strcpy(mainbPtr->plainfilename,
					*mainbPtr->recipients);
				bUseDefault = FALSE;
			}
			else
			{
				fprintf(filebPtr->pgpout,
			LANG("WARNING: File %s does not exist, using default.\n"),
			*mainbPtr->recipients);
			}
		}

		if(bUseDefault)
		{
                	dropExtension( filebPtr, mainbPtr->plainfilename );
		}
                if (!quietmode) fprintf( filebPtr->pgpout,
                        LANG("Text is assumed to be in file '%s'.\n"),
                        mainbPtr->plainfilename);

                err = PGPNewFileSpecFromFullPath(context,
                        mainbPtr->plainfilename, &plainFileSpec);

                err = PGPAddJobOptions( job,
                        PGPODetachedSig( context,
                                PGPOInputFile(context, plainFileSpec),
                                PGPOLastOption( context )),
                        PGPOLastOption( context ) );
                pgpAssertNoErr(err);
                PGPFreeFileSpec(plainFileSpec);
            }
            break;

        case kPGPEvent_SignatureEvent:
            {
                PGPUserIDRef userid;
                char useridstr[ kPGPMaxUserIDSize ];
                PGPSize actual;
				lastEvent = kPGPEvent_InitialEvent;

                if( verbose )
                    fprintf( filebPtr->pgpout, LANG("event %d: Signature\n"),
                            event->type);

                if( event->data.signatureData.checked )
                {
                    /* so we have a Key.*/
                    pgpAssertAddrValid(
                            event->data.signatureData.signingKey, PGPKeyRef);

                    err = PGPGetPrimaryUserID(
                            event->data.signatureData.signingKey, &userid);

                    pgpAssertNoErr(err);

                    err = PGPGetUserIDStringBuffer( userid,
                            kPGPUserIDPropName, 256, useridstr, &actual );

                    pgpAssertNoErr(err);

                    if( event->data.signatureData.verified ) {
                        fprintf(  filebPtr->pgpout,
                                LANG("Good signature from user \"%s\".\n"),
                                useridstr );
						mainbPtr->signatureChecked = TRUE;

                    } else {
                        fprintf(  filebPtr->pgpout, LANG(
"WARNING: Bad signature, doesn't match file contents!\n"));
                        fprintf(  filebPtr->pgpout, LANG(
"\nBad signature from user \"%s\".\n"), useridstr );
						err = kPGPError_BadSignature;
						break;

                    }
                } else {
                    char kstr[kPGPMaxKeyIDStringSize];

                    /* if we don't have the public key, we cant check
                       the signature.*/

                    err = pgpGetKeyIDStringCompat(
                            &event->data.signatureData.signingKeyID, TRUE,
                            envbPtr->compatible, kstr );

                    sprintf( useridstr, LANG("(KeyID: %s)"), kstr);

                    fprintf( filebPtr->pgpout,
                            LANG("signature not checked.\n"));

                }

                fprintf( filebPtr->pgpout, LANG("Signature made %s\n"),
                        ctdate(&(event->data.signatureData.creationTime)) );


                if( event->data.signatureData.keyRevoked) {
                    fprintf( filebPtr->pgpout,
                            LANG("signing key is revoked.\n"));
                }
                if( event->data.signatureData.keyDisabled) {
                    fprintf( filebPtr->pgpout,
                            LANG("signing key is disabled.\n"));
                }
                if( event->data.signatureData.keyExpired) {
                    fprintf( filebPtr->pgpout,
                            LANG("signing key is expired.\n"));
                }
                if( !event->data.signatureData.keyMeetsValidityThreshold ) {
                    fprintf( filebPtr->pgpout,
                            LANG("key does not meet validity threshold.\n"));
                }
                switch( event->data.signatureData.keyValidity ) {
                    case kPGPValidity_Unknown:
                    case kPGPValidity_Invalid:
                    case kPGPValidity_Marginal:

                        fprintf( filebPtr->pgpout, LANG("\n\
WARNING:  Because this public key is not certified with a trusted\n\
signature, it is not known with high confidence that this public key\n\
actually belongs to: \"%s\".\n"), useridstr);

                        break;
                    case kPGPValidity_Complete:
                    default:
                        break;
                }
#if 0
                /* XXX the sdk doesn't export this functionality.

                   When the -b field is present we want to dump the
                   signature to a separate file on decode events.
                   This requires that we know the original name of the
                   input file so we can append a .sig to it as the sig
                   output.  We always output in binary - no ascii output
                   was present in 262 for signatures.  - Anselm Jan 25 98

                   if( -b flag ) {
                       err = PGPNewFileSpecFromFullPath(context,
                            mainbPtr->plainfilename, &plainFileSpec);

                    pgpFixBeforeShip("encode the signature");

                    event->data.signatureData.signature
                    pgpFixBeforeShip("and output to a .sig file");
                    }
                 */
#endif
            }
            err = kPGPError_NoErr;
            break;

        case kPGPEvent_DecryptionEvent:
			lastEvent = kPGPEvent_DecryptionEvent;
            if( verbose )
            {
                fprintf( filebPtr->pgpout, LANG("event %d: Decryption\n"),
                        event->type);

                fprintf( filebPtr->pgpout, LANG("symmetric cipher used: "));
                switch( event->data.decryptionData.cipherAlgorithm ) {
                    case kPGPCipherAlgorithm_IDEA:
                        fprintf( filebPtr->pgpout, "IDEA\n");
                        break;
                    case kPGPCipherAlgorithm_3DES:
                        fprintf( filebPtr->pgpout, "3DES\n");
                        break;
                    case kPGPCipherAlgorithm_CAST5:
                        fprintf( filebPtr->pgpout, "CAST5\n");
                        break;
//BEGIN MORE CIPHERS SUPPORT - Disastry
                    case kPGPCipherAlgorithm_BLOWFISH:
                        fprintf( filebPtr->pgpout, "BLOWFISH\n");
                        break;
                    case kPGPCipherAlgorithm_AES128:
                        fprintf( filebPtr->pgpout, "AES128\n");
                        break;
                    case kPGPCipherAlgorithm_AES192:
                        fprintf( filebPtr->pgpout, "AES192\n");
                        break;
                    case kPGPCipherAlgorithm_AES256:
                        fprintf( filebPtr->pgpout, "AES256\n");
                        break;
                    case kPGPCipherAlgorithm_Twofish256:
                        fprintf( filebPtr->pgpout, "Twofish256\n");
                        break;
//END MORE CIPHERS SUPPORT

                    default:
                        fprintf( filebPtr->pgpout, LANG("unknown\n"));
                        break;
                }
            }
            err = kPGPError_NoErr;
            break;

        case kPGPEvent_OutputEvent:
			lastEvent = kPGPEvent_OutputEvent;
            if( verbose )
            {
                fprintf( filebPtr->pgpout,
                        LANG("event %d: Output options\n"), event->type);
                fprintf( filebPtr->pgpout, LANG("typecode: %04x\n"),
                        event->data.outputData.messageType );

                if( event->data.outputData.forYourEyesOnly ){
                    fprintf( filebPtr->pgpout, LANG("for your eyes only\n"));
                } else
                    fprintf( filebPtr->pgpout, LANG("suggested name: %s\n"),
                            event->data.outputData.suggestedName );
            }

            if( event->data.outputData.forYourEyesOnly ){

                fprintf(filebPtr->pgpout, LANG(
"\n\nThis message is marked \"For your eyes only\".  Display now (Y/n)? "));

                if (!batchmode && getyesno(filebPtr, 'y', 0)) {

                    /*
                       If the buffer is too small, tough luck. Sorry. Try
                       recompiling PGP with a larger fyeo-buffer. See
                       HUGE_MORE_BUFFER in config.h
                     */
                    pgpAssert( mainbPtr->fyeoBuffer == NULL );

                    err = PGPAddJobOptions( job,
                            PGPOAllocatedOutputBuffer( context,
                                    (void **)&mainbPtr->fyeoBuffer,
                                    kMaxMoreBufferLength,
                                    &mainbPtr->fyeoBufferLength ),
                            PGPOAppendOutput(context, TRUE),
                            PGPOLastOption( context ) );
                    pgpAssertNoErr(err);

                    /*
                       So this will actually get displayed when the
                       decode is finished.  he knows to display it if
                       the fyeo buffer is not NULL.
                     */

                } else {
                    err = PGPAddJobOptions( job,
                            PGPODiscardOutput( context, TRUE),
                            PGPOLastOption( context ) );
                    pgpAssertNoErr(err);
                }

            } else {
                int errorLvl;
                char *decodefilename = tempFile( filebPtr, TMP_WIPE,
                        &errorLvl );
                pgpAssertAddrValid( decodefilename, char );

                /* check to see if need to restore the original file name,
                   the memory allocated here is freed in args.c */
                if(mainbPtr->argsbPtr->preserveFileName)
                {
                    PGPUInt16   len = strlen(event->data.outputData.suggestedName) + 1;
                    mainbPtr->argsbPtr->outputFileName = malloc(sizeof(char) * len);
                    if(mainbPtr->argsbPtr->outputFileName)
                        strcpy(mainbPtr->argsbPtr->outputFileName,
                                event->data.outputData.suggestedName);
                    else
                    {
                        err = kPGPError_OutOfMemory;
                        break;
                    }
                }

                if( decodefilename ) {
                    PGPError er2;
                    PGPFileSpecRef resultFileSpec = NULL;

                    err = PGPNewFileSpecFromFullPath(context,
                            decodefilename, &resultFileSpec);
                    pgpAssertNoErr(err);

                    err = PGPAddJobOptions( job,
                            PGPOOutputFile( context, resultFileSpec ),
                            PGPOLastOption( context ) );
                    pgpAssertNoErr(err);

                    er2 = PGPFreeFileSpec(resultFileSpec);
                    pgpAssertNoErr(er2);

                    er2 = pgpAppendToFileNameList(
                            mainbPtr->decodefilenames, decodefilename );

                    pgpAssertNoErr(er2);
                }
            }
            err = 0;
            break;

        case kPGPEvent_ErrorEvent:
			lastEvent = kPGPEvent_ErrorEvent;
            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: error %d\n"),
                        event->type,event->data.errorData.error);
            if( event->data.errorData.error ) {
                err = PGPAddJobOptions( job,
                        PGPOAppendOutput(context, FALSE),
                        PGPOLastOption( context ) );
                pgpAssertNoErr(err);
            }
            
            if(errno == ENOSPC)
                fprintf(filebPtr->pgpout,
                        LANG("Error: No space left on device.\n"));

            err = 0;
            break;

        case kPGPEvent_WarningEvent:
			lastEvent = kPGPEvent_WarningEvent;

            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: warning %d\n"),
                        event->type,event->data.warningData.warning);
            /*if( event->data.warningData.warning == kPGPError_KeyInvalid )*/
            err = 0;
            break;

        default:
            /* ignore the event...*/
            if( verbose )
                fprintf( filebPtr->pgpout, LANG("event %d: unknown\n"),
                        event->type);
            err = 0;
    }
    return err;
}


int pgpDoDecode(struct pgpmainBones *mainbPtr, char *workfilename,
        int *perrorLvl )
{
    PGPContextRef context = mainbPtr->pgpContext;
    struct pgpfileBones *filebPtr = mainbPtr->filebPtr;
    struct pgpenvBones *envbPtr = mainbPtr->envbPtr;
    PGPEnv *env = envbPtr->m_env;

    PGPFileSpecRef workFileSpec = NULL;
    PGPError err,er2;
    PGPInt32 pri;

    err = PGPNewFileSpecFromFullPath(context, workfilename, &workFileSpec);
    pgpAssertNoErr(err);

        /*
           in case there are keys in the input, open the keyrings
           mutable+create.
         */

	err = PGPOpenDefaultKeyRings( context, kPGPKeyRingOpenFlags_None,
									&mainbPtr->workingRingSet );

	if(IsPGPError(err))
	{
		fprintf(filebPtr->pgpout,
			LANG("Error: Unable to open default key rings."));
		goto done;
	}

    /* should we add all the passphrases we know of to the job options??*/
    err = pgpRewindPassphrase( envbPtr->passwds );
    pgpAssertNoErr(err);

    if (envbPtr->moreFlag) {
      /* -m option specified on cmdline */
 
        fprintf(filebPtr->pgpout, "moreflag");

        pgpAssert( mainbPtr->fyeoBuffer == NULL );

        err = PGPDecode( context,
            PGPOInputFile( context, workFileSpec ),
            PGPOKeySetRef( context, mainbPtr->workingRingSet ),
            PGPOSendEventIfKeyFound( context, TRUE ),
            PGPOPassThroughIfUnrecognized( context, envbPtr->passThrough ),
            PGPOEventHandler( context, decHandler, (PGPUserValue) mainbPtr),
            PGPOAllocatedOutputBuffer( context,
                  (void **)&mainbPtr->fyeoBuffer,
                   kMaxMoreBufferLength,
                   &mainbPtr->fyeoBufferLength ),
            PGPOAppendOutput(context, TRUE),
            PGPOLastOption( context ) );
            pgpAssertNoErr(err);
    }
    else {

        err = PGPDecode( context,
            PGPOInputFile( context, workFileSpec ),
            PGPOKeySetRef( context, mainbPtr->workingRingSet ),
            PGPOSendEventIfKeyFound( context, TRUE ),
            PGPOPassThroughIfUnrecognized( context, envbPtr->passThrough ),
            PGPOEventHandler( context, decHandler, (PGPUserValue) mainbPtr),
            PGPOLastOption( context ) );
    }
    if( IsPGPError(err) )
        pgpShowError( filebPtr, err, 0,0);
    else
    if ( mainbPtr->fyeoBuffer ) {
        err = moreBuffer( filebPtr, mainbPtr->fyeoBuffer,
                mainbPtr->fyeoBufferLength );
        PGPFreeData(mainbPtr->fyeoBuffer);
        mainbPtr->fyeoBuffer=NULL;
    }

    er2 = PGPFreeKeySet( mainbPtr->workingRingSet );
    pgpAssertNoErr(er2);
    mainbPtr->workingRingSet = NULL;

done:
    er2 = PGPFreeFileSpec(workFileSpec);
    pgpAssertNoErr(er2);

    if (pgpenvGetInt( env, PGPENV_BATCHMODE, &pri, &er2 ) &&
            !mainbPtr->signatureChecked)

        *perrorLvl=1; /* alternate success, file did not have sig. */
    else
        *perrorLvl=EXIT_OK;
    return err;
}

