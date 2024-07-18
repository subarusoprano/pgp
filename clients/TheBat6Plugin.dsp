# Microsoft Developer Studio Project File - Name="TheBat6Plugin" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=TheBat6Plugin - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "TheBat6Plugin.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "TheBat6Plugin.mak" CFG="TheBat6Plugin - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "TheBat6Plugin - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "TheBat6Plugin - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "TheBat6Plugin - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "TheBat6Plugin/Release"
# PROP Intermediate_Dir "TheBat6Plugin/Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\shared" /I "include" /I "shared" /I "..\shared" /I "..\..\..\libs\pgpcdk\pub\include" /I "..\..\..\libs\pgpcdk\win32" /I "..\..\..\libs\pfl\common" /I "..\..\..\libs\pfl\win32" /I "..\..\..\libs\pfl\common\prefs" /I "..\..\..\libs\pfl\common\file" /D UNFINISHED_CODE_ALLOWED=0 /D PGP_DEBUG=0 /D PGP_WIN32=1 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo /o"./Release/TheBat6Plugin.bsc"
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 ..\..\..\libs\pfl\win32\pflCommon\Release\pflCommon.lib ..\..\..\libs\pgpcdk\win32\pgpsdknetworklib\release\pgpsdknl.lib pgpcl\release\pgpcl.lib pgpsc\release\pgpsc.lib comctl32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386 /out:"TheBat6Plugin/Release/batpgp65.dll"
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "TheBat6Plugin - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "TheBat6Plugin/Debug"
# PROP Intermediate_Dir "TheBat6Plugin/Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\shared" /I "include" /I "shared" /I "..\..\..\libs\pgpcdk\pub\include" /I "..\..\..\libs\pgpcdk\win32" /I "..\..\..\libs\pfl\common" /I "..\..\..\libs\pfl\win32" /I "..\..\..\libs\pfl\common\prefs" /I "..\..\..\libs\pfl\common\file" /D "_DEBUG" /D UNFINISHED_CODE_ALLOWED=1 /D PGP_DEBUG=1 /D PGP_WIN32=1 /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 ..\..\..\libs\pfl\win32\pflCommon\Debug\pflCommon.lib ..\..\..\libs\pgpcdk\win32\pgpsdknetworklib\debug\pgpsdknl.lib pgpcl\debug\pgpcl.lib pgpsc\debug\pgpsc.lib comctl32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /out:"TheBat6Plugin/Debug/batpgp65.dll" /pdbtype:sept
# SUBTRACT LINK32 /pdb:none /incremental:no

!ENDIF 

# Begin Target

# Name "TheBat6Plugin - Win32 Release"
# Name "TheBat6Plugin - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "c;cpp"
# Begin Source File

SOURCE=.\shared\AddKey.c
# End Source File
# Begin Source File

SOURCE=.\shared\BlockUtils.c
# End Source File
# Begin Source File

SOURCE=.\shared\DecryptVerify.c
# End Source File
# Begin Source File

SOURCE=.\shared\EncryptSign.c
# End Source File
# Begin Source File

SOURCE=.\shared\ParseMime.c
# End Source File
# Begin Source File

SOURCE=.\TheBat6Plugin\PGPplugin.def
# End Source File
# Begin Source File

SOURCE=..\shared\pgpVersionHeader.c
# End Source File
# Begin Source File

SOURCE=.\TheBat6Plugin\PluginMain.c
# ADD CPP /Yc"windows.h"
# End Source File
# Begin Source File

SOURCE=.\shared\Prefs.c
# End Source File
# Begin Source File

SOURCE=.\shared\SigEvent.c
# End Source File
# Begin Source File

SOURCE=.\shared\VerificationBlock.c
# End Source File
# Begin Source File

SOURCE=.\shared\Working.c
# End Source File
# End Group
# Begin Group "Project Header Files"

# PROP Default_Filter "h"
# Begin Source File

SOURCE=.\shared\BlockUtils.h
# End Source File
# Begin Source File

SOURCE=.\TheBat6Plugin\DisplayMessage.h
# End Source File
# Begin Source File

SOURCE=.\TheBat6Plugin\MapFile.h
# End Source File
# Begin Source File

SOURCE=.\include\pgpkm.h
# End Source File
# Begin Source File

SOURCE=.\include\pgpphras.h
# End Source File
# Begin Source File

SOURCE=.\include\PGPRecip.h
# End Source File
# Begin Source File

SOURCE=.\INCLUDE\PGPsc.h
# End Source File
# Begin Source File

SOURCE=.\TheBat6Plugin\PluginMain.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;bmp"
# End Group
# Begin Group "Library Header Files"

# PROP Default_Filter "h"
# Begin Source File

SOURCE=..\..\..\libs\pfl\common\pflContext.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pfl\common\prefs\pflPrefs.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pfl\common\prefs\pflPrefTypes.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pfl\common\pflTypes.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pfl\common\pgpBase.h
# End Source File
# Begin Source File

SOURCE=..\shared\pgpBuildFlags.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\pub\include\pgpCFB.h
# End Source File
# Begin Source File

SOURCE=..\shared\pgpClientPrefs.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\win32\pgpConfig.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pfl\common\pgpDebug.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\pub\include\pgpEncode.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\pub\include\pgpErrors.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\pub\include\pgpHash.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\pub\include\pgpKeys.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pfl\common\pgpLeaks.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pfl\common\pgpMem.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pfl\win32\pgpPFLConfig.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pfl\common\pgpPFLErrors.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\pub\include\pgpPubTypes.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\pub\include\pgpSDKPrefs.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\pub\include\pgpSymmetricCipher.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pfl\common\pgpTypes.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\pub\include\pgpUtilities.h
# End Source File
# Begin Source File

SOURCE=.\include\PGPversion.h
# End Source File
# Begin Source File

SOURCE=.\INCLUDE\pgpWerr.h
# End Source File
# End Group
# End Target
# End Project
