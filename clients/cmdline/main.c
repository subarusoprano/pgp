/*____________________________________________________________________________
    PGP 6.0 command line

    Copyright(C) 1998,1999 Network Associates, Inc.
    All rights reserved.

    main entry point.
    $Id: main.c,v 1.29.6.1.2.1.4.4 1999/08/21 00:29:02 sluu Exp $
____________________________________________________________________________*/

#include <stdio.h>
#include <string.h>
#if PGP_WIN32
#include <windows.h>
#include <direct.h>
#endif
#if PGP_UNIX
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include "pgpBase.h"
#include "pgpPFLErrors.h"
#include "pgpUtilities.h"
#include "pgpFileSpec.h"
#include "pgpUtilitiesPriv.h"
#include "pgpSDKPrefs.h"

#include "pgp.h"
#include "usuals.h"
#include "stubs.h"
#include "globals.h"
#include "prototypes.h"
#include "language.h"

#include "fileio.h"


struct pgpmainBones _pgp_mainBones;
static char		copyright[255] = "";


void initMainBones( struct pgpmainBones *mainbPtr, PGPContextRef context )
{
	 PGPBoolean haveRSAAlgorithm = FALSE;
	 PGPBoolean canGenerateKeys = FALSE;
	 PGPBoolean isBSAFE = FALSE;
	 PGPBoolean isRSAREF = FALSE;
	 PGPBoolean isCAPI = FALSE;
	 PGPBoolean	isPGPRSA = FALSE;


     mainbPtr->pgpContext = context;

     PGPSetContextUserValue( context, (PGPUserValue)mainbPtr );
        /* enables any of our callback functions to find the mainbPtr */

     /* Global filenames and system-wide file extensions... */
     mainbPtr->relVersion = LANG("6.5.8ckt http://www.ipgpp.com/");  /* release version */

	 GetRSAStatus( &haveRSAAlgorithm, &canGenerateKeys, 
				   &isBSAFE, &isRSAREF, &isCAPI, &isPGPRSA, copyright);

	 mainbPtr->signonLegalese = copyright;

     mainbPtr->signatureChecked = FALSE;
     mainbPtr->deArmorOnly = FALSE;
     mainbPtr->decryptMode = FALSE;
     mainbPtr->separateSignature = FALSE;

     mainbPtr->fyeoBuffer = NULL; /* for-your-eyes-only buffer*/
     mainbPtr->fyeoBufferLength = 0;

     mainbPtr->recipients = NULL;

     mainbPtr->workingRingSet = NULL;
     mainbPtr->workingGroupSet = NULL;
     mainbPtr->workingKeyServer = NULL;

#ifdef WIN32
	 mainbPtr->mainThreadHandle = GetMainThreadHandle();
#endif /* WIN32 */

     initEnvBones(mainbPtr);
     initFileBones(mainbPtr);
     initArgsBones(mainbPtr);

     pgpNewFileNameList( context, &mainbPtr->decodefilenames );
     pgpNewPointerList( context, &mainbPtr->leaks );
}

static
PGPError pgpInitSDKPrefsDir( PGPContextRef context )
{
    char            *pszTemp = NULL;
    char            rootPath[MAX_PATH] = {'\0'};
    char            filename[MAX_PATH] = {'\0'};
    FILE            *fp = NULL;
    PGPUInt16       len = 0;
    PGPError        err = kPGPError_NoErr;
    PGPKeySetRef    keyset = kPGPInvalidRef;

#ifdef PGP_UNIX
    PFLFileSpecRef  dirspec = kPGPInvalidRef;
    PGPMemoryMgrRef mmgr = kPGPInvalidRef;
    PFLFileSpecRef  sdkpflPrefs = kPGPInvalidRef;
    PGPBoolean	    exists = FALSE;
    
    err = PGPNewMemoryMgr(0, &mmgr);
    if(IsPGPError(err))
        return err;

    err = pgpGetPrefsSpec( mmgr, &sdkpflPrefs );
    if(IsPGPError(err)) 
    {
        PGPFreeMemoryMgr(mmgr);
        return err;
    }

    err = PFLGetParentDirectory(sdkpflPrefs, &dirspec);
    if(IsPGPError(err))
    {
        PFLFreeFileSpec(sdkpflPrefs);
        PGPFreeMemoryMgr(mmgr);
        return err;
    }
    err = PFLFileSpecExists(dirspec, &exists);
    pgpAssertNoErr(err);

    if(!exists) /* need to create directory */
    {
        char    *dirname;

        err = PFLGetFullPathFromFileSpec( dirspec, &dirname );
        pgpAssertNoErr(err);
        if(mkdir(dirname, 0700) == -1)
        {
            fprintf(stderr, LANG("mkdir (%s) failed..\n\n"), dirname);
            err = kPGPError_CantOpenFile;
        }
        PGPFreeData(dirname);
    }
    if(dirspec != kPGPInvalidRef)
        PGPFreeFileSpec(dirspec);
    if(sdkpflPrefs != kPGPInvalidRef)
        PFLFreeFileSpec(sdkpflPrefs);
    if(mmgr != kPGPInvalidRef)
        PGPFreeMemoryMgr(mmgr);


#endif /* PGP_UNIX */

    err = PGPsdkLoadDefaultPrefs(context);
    pgpAssertNoErr(err);
    err = PGPOpenDefaultKeyRings(context, 
                    kPGPKeyRingOpenFlags_Create | 
                    kPGPKeyRingOpenFlags_Mutable, &keyset);
    if(IsntPGPError(err))
    {
        PGPFreeKeySet(keyset);
    }
    else
        return err;

    /* now check to see if configuration file exists, if not, create it */
    buildFileName(filename, "pgp.cfg");
    if((fp = fopen(filename, "r")) != NULL)
        fclose(fp);
    else
    {
        /* file doesn't exist, create it */
        touchFile(filename, 0600);
    }
    return err;
}

int main(int argc,char *argv[])
{
    struct pgpmainBones *mainbPtr = &_pgp_mainBones;
    struct pgpargsBones *argsbPtr;
    struct pgpfileBones *filebPtr;
    struct pgpenvBones *envbPtr;
    PGPContextRef mainContext;
    int errorLvl = 0, status;
    PGPError err = PGPsdkInit();
    pgpAssertNoErr(err);

    err = PGPsdkNetworkLibInit();
    pgpAssertNoErr(err);

    err = PGPNewContext( kPGPsdkAPIVersion, &mainContext );
    pgpAssertNoErr(err);

    err = pgpInitSDKPrefsDir( mainContext );
    pgpAssertNoErr(err);

    initMainBones( mainbPtr, mainContext );

    signonMsg(mainbPtr);

    /* link the context and initialize what used to be the global
       variables. */
    argsbPtr = mainbPtr->argsbPtr;
    filebPtr = mainbPtr->filebPtr;
    envbPtr = mainbPtr->envbPtr;
    err = pgpParseArgs( mainbPtr, argc, argv, &errorLvl);
    /* parse the arguments */
    if(err != 0)
        goto ex;

    if (argsbPtr->keyFlag && argsbPtr->keyChar == '\0') {
        keyUsage(filebPtr,&errorLvl);
        goto ex;
    }

    if (argsbPtr->groupFlag && argsbPtr->groupChar == '\0') {
        groupUsage(filebPtr,&errorLvl);
        goto ex;
    }

    /*
     * Write to stdout if explicitly asked to, or in filter mode and
     * no explicit file name was given.
     */
    mainbPtr->outputStdout = argsbPtr->outputFileName ?
        strcmp(argsbPtr->outputFileName, "-") == 0 : envbPtr->filterMode;

#if 1
    /* At request of Peter Simons, use stderr always. Sounds reasonable. */
    /* JIS: Put this code back in... removing it broke too many things */
    if (!mainbPtr->outputStdout)
        filebPtr->pgpout = stdout;
#endif

#if defined(PGP_UNIX) || defined(VMS)
    umask(077); /* Make files default to private */
#endif

    initSignals(); /* Catch signals */

    /* get our groups...*/
    err = pgpInitializeWorkingGroupSet( mainbPtr );

    if (argsbPtr->keyFlag) {
        status = doKeyOpt( mainbPtr, argsbPtr->keyChar, &errorLvl );
        if (status < 0) {
            userError(filebPtr,&errorLvl);
            goto ex;
        }
        errorLvl=status;
        goto ex;
    }

    if(argsbPtr->groupFlag) {
        status = doGroupOpt( mainbPtr, argsbPtr->groupChar, &errorLvl );
        if( status < 0 ) {
            userError(filebPtr,&errorLvl);
            goto ex;
        }
        errorLvl=status;
        goto ex;
    }

    err = pgpProcessArgs(mainbPtr, &errorLvl);

ex:
    err = pgpFinalizeWorkingGroupSet( mainbPtr );

    pgpTearDown( mainbPtr, &errorLvl );

    exit(errorLvl);
    /*NOTREACHED*/
    return errorLvl;
}

#ifdef WIN32
PGPUInt32 GetMainThreadHandle()
{
	PGPUInt32	tmpHandle = (PGPUInt32)GetCurrentThread();
	PGPUInt32	handleCurrentProcess = (PGPUInt32)GetCurrentProcess();
	PGPUInt32	retHandle = 0;

	if(DuplicateHandle( (HANDLE)handleCurrentProcess,	/* handle to the source process */
						(HANDLE)tmpHandle,				/* handle to duplicate */
						(HANDLE)handleCurrentProcess,	/* handle to process to duplicate to */
						(HANDLE *)&retHandle,				/* pointer to duplicate handle */
						0,					/* access for duplicate handle */
						FALSE,					/* handle inheritance flag */
						DUPLICATE_SAME_ACCESS	/* optional actions */
						))
	{
		return retHandle;
	}
	else
		return -1;
}
#endif /* WIN32 */
