/*____________________________________________________________________________
	Copyright (C) 1997 Network Associates Inc. and affiliated companies.
	All rights reserved.
	
	


	$Id: SaveOpen.c,v 1.23.12.3 1999/12/14 03:43:19 wjb Exp $



____________________________________________________________________________*/
#include "precomp.h"

BOOL AlterEncryptedFileName(char *FileName,DWORD Actions)
{
	char DefaultExtension[5] = ".pgp";

	if((Actions & PGPCL_DETACHEDSIG) == PGPCL_DETACHEDSIG)
	{
		strcpy(DefaultExtension, ".sig");
	}
	else
	{
		if((Actions & PGPCL_ASCIIARMOR) == PGPCL_ASCIIARMOR)
		{
			strcpy(DefaultExtension, ".asc");
		}
	}

	strcat(FileName, DefaultExtension);

	return TRUE;
}

BOOL AlterDecryptedFileName(char *FileName,char *SuggestedName)
{
	char *p;

	p = strrchr(FileName, '\\');

	if(p!=0)
		*(p+1)=0;
	else
		*FileName=0;

	strcat(FileName,SuggestedName);

	return TRUE;
}

BOOL  SaveOutputFile(PGPContextRef Context,
					 HWND hwnd, 
					 char *Title,
					 char *InputFile, 
					 PGPFileSpecRef *pOutputFileRef,
					 BOOL Force)
{
	char *p;
	BOOL UserCancel = FALSE;
	OPENFILENAME SaveFileName;
	FILE *ftest;
	char StrRes[500];
	BOOL bAskUser;

	char FinalFile[MAX_PATH]="\0";
	char DefaultExtension[MAX_PATH] = "\0";
	int FileStart = 0, FileExtensionStart = 0;

	bAskUser=FALSE;

	strcpy(FinalFile, InputFile);

	if((p = strrchr(FinalFile, '\\')))
		FileStart = p - FinalFile + 1;

	if((p = strrchr(FinalFile, '.')))
	{
		FileExtensionStart = p - FinalFile + 1;
		strcpy(DefaultExtension,p); // Save old extension
								// it might get stripped
	}

	//BEGIN ASCII ARMOR PARSER VULNERABILITY - Imad R. Faiad
	//if it's a .dll file we should prompt the user just in case
	if (!(stricmp(DefaultExtension,".dll"))) bAskUser=TRUE;
	//END ASCII ARMOR PARSER VULNERABILITY

	ftest=fopen(FinalFile,"rb");

	// If we could open the file, we need to ask the user
	if(ftest!=0)
	{
		fclose(ftest);
		bAskUser=TRUE;
	}
	else
	{
		// File doesn't exist, but can we create it?
		ftest=fopen(FinalFile,"wb");

		if(ftest==0)
		{
			// No, we can't
			bAskUser=TRUE;
		}
		else
		{
			// We can create the file. Close it and erase it
			fclose(ftest);
			remove(FinalFile);
		}
	}

	// Ask the user
	if(Force||bAskUser)
	{
		LoadString (g_hinst, IDS_SAVEFILTER, StrRes, sizeof(StrRes));
		while (p = strrchr (StrRes, '@')) *p = '\0';

		SaveFileName.lStructSize=sizeof(SaveFileName); 
		SaveFileName.hwndOwner=hwnd; 
	    SaveFileName.hInstance=NULL; 
	    SaveFileName.lpstrFilter=StrRes;
		SaveFileName.lpstrCustomFilter=NULL; 
	    SaveFileName.nMaxCustFilter=0; 
		SaveFileName.nFilterIndex=1; 
  	    SaveFileName.lpstrFile=FinalFile; 
	    SaveFileName.nMaxFile=MAX_PATH; 
	    SaveFileName.lpstrFileTitle=NULL; 
		SaveFileName.nMaxFileTitle=0; 
		SaveFileName.lpstrInitialDir=NULL; 
		SaveFileName.lpstrTitle=Title; 
		SaveFileName.Flags= OFN_OVERWRITEPROMPT | 
							OFN_HIDEREADONLY | 
							OFN_NOREADONLYRETURN;
#ifdef WIN32
		SaveFileName.Flags=SaveFileName.Flags | OFN_EXPLORER;
#endif
		SaveFileName.nFileOffset=FileStart; 
		SaveFileName.nFileExtension=FileExtensionStart; 
		SaveFileName.lpstrDefExt=DefaultExtension; 
		SaveFileName.lCustData=(long)NULL; 
		SaveFileName.lpfnHook=NULL;
		SaveFileName.lpTemplateName=NULL; 

		UserCancel = !GetSaveFileName(&SaveFileName);
	}

	// We'll likely always have some kind of extension
	if(DefaultExtension[0]!=0)
	{
		p = strrchr(FinalFile, '.');

		if(p)
		{
			// Extension found
			if(!stricmp(DefaultExtension,p))
			{
				// They are the same. Woohoo! Do nothing
				;
			}
			else
			{
				// They are different. Must be that 
				// pesky hide extensions option.
				strcat(FinalFile,DefaultExtension);

				ftest=fopen(FinalFile,"rb");

				// If we could open the file, we need to ask the user
				if(ftest!=0)
				{
					fclose(ftest);
					MessageBox(hwnd,
						FinalFile,"PGP Error -- File exists",
						MB_OK|MB_ICONSTOP|MB_SETFOREGROUND);

					return TRUE;
				}
			}
		}
		else
		{
			// No extension found
			strcat(FinalFile,DefaultExtension);

			ftest=fopen(FinalFile,"rb");

			// If we could open the file, we need to ask the user
			if(ftest!=0)
			{
				fclose(ftest);
				MessageBox(hwnd,
					FinalFile,"PGP Error -- File exists",
					MB_OK|MB_ICONSTOP|MB_SETFOREGROUND);

				return TRUE;
			}
		}
	}

	if(!UserCancel)
	{
		PGPNewFileSpecFromFullPath(Context,FinalFile,pOutputFileRef);
	}

	return(UserCancel);
}

BOOL GetOriginalFileRef(HWND hwnd,PGPContextRef context,
						char *InputFile,
						char *OutputFile,
						PGPFileSpecRef *OriginalFileRef,
						HWND hwndWorking)
{
	char OriginalFile[MAX_PATH + 1], *p;
	char *pDefaultExtension;
	unsigned short FileStart, FileExtensionStart;
	BOOL UserCancel = FALSE;
	OPENFILENAME OriginalFileName;
	FILE *ftest;
	char StrRes[500];
	char StrRes2[500];

	assert(InputFile);
	assert(OriginalFileRef);

	strcpy(OriginalFile, InputFile);

	if((p = strrchr(OriginalFile, '\\')))
		FileStart = p - OriginalFile + 1;
	else
		FileStart = 0;

	// Get rid of the .sig extension

	if((p = strrchr(OriginalFile, '.')))
	{
		*p = '\0';
	}

	ftest=fopen(OriginalFile,"rb");
	if(ftest!=0)
	{
		fclose(ftest);
		strcpy(OutputFile,OriginalFile);
		PGPNewFileSpecFromFullPath( context,OriginalFile, OriginalFileRef);
		return FALSE;
	}

	// Don't add any default extensions to the file

	pDefaultExtension=0;
	FileExtensionStart=strlen(OriginalFile);

	LoadString (g_hinst, IDS_SAVEFILTER, StrRes, sizeof(StrRes));
	while (p = strrchr (StrRes, '@')) *p = '\0';

	LoadString (g_hinst, IDS_SELSIGNFILE, StrRes2, sizeof(StrRes2));

	OriginalFileName.lStructSize=sizeof(OriginalFileName); 
    OriginalFileName.hwndOwner=hwnd; 
    OriginalFileName.hInstance=NULL; 
    OriginalFileName.lpstrFilter=StrRes; 
    OriginalFileName.lpstrCustomFilter=NULL; 
    OriginalFileName.nMaxCustFilter=0; 
    OriginalFileName.nFilterIndex=1; 
    OriginalFileName.lpstrFile=OriginalFile; 
    OriginalFileName.nMaxFile=MAX_PATH; 
    OriginalFileName.lpstrFileTitle=NULL; 
    OriginalFileName.nMaxFileTitle=0; 
    OriginalFileName.lpstrInitialDir=NULL; 
    OriginalFileName.lpstrTitle=StrRes2; 
    OriginalFileName.Flags=OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
						   OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
#ifdef WIN32
	OriginalFileName.Flags=OriginalFileName.Flags | OFN_EXPLORER;
#endif
    OriginalFileName.nFileOffset=FileStart; 
    OriginalFileName.nFileExtension=FileExtensionStart; 
    OriginalFileName.lpstrDefExt=pDefaultExtension; 
    OriginalFileName.lCustData=(long)NULL; 
    OriginalFileName.lpfnHook=NULL;
    OriginalFileName.lpTemplateName=NULL; 

	if(GetOpenFileName(&OriginalFileName))
	{
		strcpy(OutputFile,OriginalFile);
		PGPNewFileSpecFromFullPath( context,OriginalFile, OriginalFileRef);
	}
	else
		UserCancel = TRUE;

	return(UserCancel);
}


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/

