# Microsoft Developer Studio Project File - Name="PGPsdkUI" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=PGPsdkUI - Win32 Debug Auth Only
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "PGPsdkUI.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "PGPsdkUI.mak" CFG="PGPsdkUI - Win32 Debug Auth Only"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "PGPsdkUI - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PGPsdkUI - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PGPsdkUI - Win32 Release Auth Only" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PGPsdkUI - Win32 Debug Auth Only" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "PGPsdkUI - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\..\pfl\win32" /I "..\..\..\pfl\common" /I "..\..\..\pfl\common\file" /I "..\..\..\pfl\common\prefs" /I "..\..\..\pfl\common\util" /I ".." /I "..\..\pub\include" /I "..\..\priv\include" /I "..\..\priv\include\opaque" /I "..\..\priv\crypto\bignum" /I "..\..\priv\crypto\cipher" /I "..\..\priv\crypto\compress" /I "..\..\priv\crypto\hash" /I "..\..\priv\crypto\pipe\crypt" /I "..\..\priv\crypto\pipe\file" /I "..\..\priv\crypto\pipe\parser" /I "..\..\priv\crypto\pipe\sig" /I "..\..\priv\crypto\pipe\text" /I "..\..\priv\crypto\pipe\utils" /I "..\..\priv\crypto\random" /I "..\..\priv\debug" /I "..\..\priv\keys\keydb" /I "..\..\priv\keys\keys" /I "..\..\priv\keys\pubkey" /I "..\..\priv\regexp" /I "..\..\priv\utilities\errors" /I "..\..\priv\utilities" /I "..\..\priv\utilities\helper" /I "..\..\priv\utilities\utils" /I "..\..\priv\utilities\prefs" /I "..\..\priv\clientlib" /I "..\..\priv\encrypt" /I "..\..\..\pfl\common\sorting" /I "..\..\priv\ui" /D _WIN32_IE=0x0300 /D PGP_DEBUG=0 /D PGP_WIN32=1 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ../pgpcdk/release/pgp_sdk.lib ../pgpsdkNetworkLib/release/pgpsdkNL.lib comctl32.lib /nologo /base:"0x12000000" /subsystem:windows /dll /machine:I386
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Desc=Building static library
PostBuild_Cmds=rename .\Release\PGPsdkUILibDLLMain.obj  PGPsdkUILibDLLMain.ob1    	lib  /nologo /out:.\Release\PGPsdkUIStatic.lib  .\Release\*.obj	rename     .\Release\PGPsdkUILibDLLMain.ob1 PGPsdkUILibDLLMain.obj
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PGPsdkUI - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\..\pfl\win32" /I "..\..\..\pfl\common" /I "..\..\..\pfl\common\file" /I "..\..\..\pfl\common\prefs" /I "..\..\..\pfl\common\util" /I ".." /I "..\..\pub\include" /I "..\..\priv\include" /I "..\..\priv\include\opaque" /I "..\..\priv\crypto\bignum" /I "..\..\priv\crypto\cipher" /I "..\..\priv\crypto\compress" /I "..\..\priv\crypto\hash" /I "..\..\priv\crypto\pipe\crypt" /I "..\..\priv\crypto\pipe\file" /I "..\..\priv\crypto\pipe\parser" /I "..\..\priv\crypto\pipe\sig" /I "..\..\priv\crypto\pipe\text" /I "..\..\priv\crypto\pipe\utils" /I "..\..\priv\crypto\random" /I "..\..\priv\debug" /I "..\..\priv\keys\keydb" /I "..\..\priv\keys\keys" /I "..\..\priv\keys\pubkey" /I "..\..\priv\regexp" /I "..\..\priv\utilities\errors" /I "..\..\priv\utilities" /I "..\..\priv\utilities\helper" /I "..\..\priv\utilities\utils" /I "..\..\priv\utilities\prefs" /I "..\..\priv\clientlib" /I "..\..\priv\encrypt" /I "..\..\..\pfl\common\sorting" /I "..\..\priv\ui" /D _WIN32_IE=0x0300 /D UNFINISHED_CODE_ALLOWED=1 /D PGP_DEBUG=1 /D PGP_WIN32=1 /D "_DEBUG" /D "NEEDPROTOS" /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ../pgpcdk/debug/pgp_sdk.lib ../pgpsdkNetworkLib/debug/pgpsdkNL.lib comctl32.lib /nologo /base:"0x12000000" /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Desc=Building static library
PostBuild_Cmds=rename .\Debug\PGPsdkUILibDLLMain.obj  PGPsdkUILibDLLMain.ob1    	lib  /nologo /out:.\Debug\PGPsdkUIStatic.lib  .\Debug\*.obj	rename     .\Debug\PGPsdkUILibDLLMain.ob1 PGPsdkUILibDLLMain.obj
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PGPsdkUI - Win32 Release Auth Only"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "PGPsdkUI"
# PROP BASE Intermediate_Dir "PGPsdkUI"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release\Authentication"
# PROP Intermediate_Dir "Release\Authentication"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "..\..\..\pfl\win32" /I "..\..\..\pfl\common" /I "..\..\..\pfl\common\file" /I "..\..\..\pfl\common\prefs" /I "..\..\..\pfl\common\util" /I ".." /I "..\..\pub\include" /I "..\..\priv\include" /I "..\..\priv\include\opaque" /I "..\..\priv\crypto\bignum" /I "..\..\priv\crypto\cipher" /I "..\..\priv\crypto\compress" /I "..\..\priv\crypto\hash" /I "..\..\priv\crypto\pipe\crypt" /I "..\..\priv\crypto\pipe\file" /I "..\..\priv\crypto\pipe\parser" /I "..\..\priv\crypto\pipe\sig" /I "..\..\priv\crypto\pipe\text" /I "..\..\priv\crypto\pipe\utils" /I "..\..\priv\crypto\random" /I "..\..\priv\debug" /I "..\..\priv\keys\keydb" /I "..\..\priv\keys\keys" /I "..\..\priv\keys\pubkey" /I "..\..\priv\regexp" /I "..\..\priv\utilities\errors" /I "..\..\priv\utilities" /I "..\..\priv\utilities\helper" /I "..\..\priv\utilities\utils" /I "..\..\priv\utilities\prefs" /I "..\..\priv\clientlib" /I "..\..\priv\encrypt" /I "..\..\..\pfl\common\sorting" /I "..\..\priv\ui" /D PGP_DEBUG=0 /D PGP_WIN32=1 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\..\pfl\win32" /I "..\..\..\pfl\common" /I "..\..\..\pfl\common\file" /I "..\..\..\pfl\common\prefs" /I "..\..\..\pfl\common\util" /I ".." /I "..\..\pub\include" /I "..\..\priv\include" /I "..\..\priv\include\opaque" /I "..\..\priv\crypto\bignum" /I "..\..\priv\crypto\cipher" /I "..\..\priv\crypto\compress" /I "..\..\priv\crypto\hash" /I "..\..\priv\crypto\pipe\crypt" /I "..\..\priv\crypto\pipe\file" /I "..\..\priv\crypto\pipe\parser" /I "..\..\priv\crypto\pipe\sig" /I "..\..\priv\crypto\pipe\text" /I "..\..\priv\crypto\pipe\utils" /I "..\..\priv\crypto\random" /I "..\..\priv\debug" /I "..\..\priv\keys\keydb" /I "..\..\priv\keys\keys" /I "..\..\priv\keys\pubkey" /I "..\..\priv\regexp" /I "..\..\priv\utilities\errors" /I "..\..\priv\utilities" /I "..\..\priv\utilities\helper" /I "..\..\priv\utilities\utils" /I "..\..\priv\utilities\prefs" /I "..\..\priv\clientlib" /I "..\..\priv\encrypt" /I "..\..\..\pfl\common\sorting" /I "..\..\priv\ui" /D _WIN32_IE=0x0300 /D PGP_ENCRYPT_DISABLE=1 /D PGP_DECRYPT_DISABLE=1 /D PGP_DEBUG=0 /D PGP_WIN32=1 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ../pgpcdk/release/pgp_sdk.lib ../pgpsdkNetworkLib/release/pgpsdkNL.lib comctl32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ../pgpcdk/release/Authentication/pgp_sdk_ltd.lib ../pgpsdkNetworkLib/release/Authentication/pgpsdkNLLtd.lib comctl32.lib /nologo /base:"0x12000000" /subsystem:windows /dll /machine:I386 /out:"Release\Authentication/PGPsdkUILtd.dll"
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Desc=Building static library
PostBuild_Cmds=rename .\Release\Authentication\PGPsdkUILibDLLMain.obj    PGPsdkUILibDLLMain.ob1  	lib  /nologo   /out:.\Release\Authentication\PGPsdkUILtdStatic.lib    .\Release\Authentication\*.obj	rename     .\Release\Authentication\PGPsdkUILibDLLMain.ob1 PGPsdkUILibDLLMain.obj
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PGPsdkUI - Win32 Debug Auth Only"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "PGPsdkUI"
# PROP BASE Intermediate_Dir "PGPsdkUI"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug\Authentication"
# PROP Intermediate_Dir "Debug\Authentication"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /I "..\..\..\pfl\win32" /I "..\..\..\pfl\common" /I "..\..\..\pfl\common\file" /I "..\..\..\pfl\common\prefs" /I "..\..\..\pfl\common\util" /I ".." /I "..\..\pub\include" /I "..\..\priv\include" /I "..\..\priv\include\opaque" /I "..\..\priv\crypto\bignum" /I "..\..\priv\crypto\cipher" /I "..\..\priv\crypto\compress" /I "..\..\priv\crypto\hash" /I "..\..\priv\crypto\pipe\crypt" /I "..\..\priv\crypto\pipe\file" /I "..\..\priv\crypto\pipe\parser" /I "..\..\priv\crypto\pipe\sig" /I "..\..\priv\crypto\pipe\text" /I "..\..\priv\crypto\pipe\utils" /I "..\..\priv\crypto\random" /I "..\..\priv\debug" /I "..\..\priv\keys\keydb" /I "..\..\priv\keys\keys" /I "..\..\priv\keys\pubkey" /I "..\..\priv\regexp" /I "..\..\priv\utilities\errors" /I "..\..\priv\utilities" /I "..\..\priv\utilities\helper" /I "..\..\priv\utilities\utils" /I "..\..\priv\utilities\prefs" /I "..\..\priv\clientlib" /I "..\..\priv\encrypt" /I "..\..\..\pfl\common\sorting" /I "..\..\priv\ui" /D UNFINISHED_CODE_ALLOWED=1 /D PGP_DEBUG=1 /D PGP_WIN32=1 /D "_DEBUG" /D "NEEDPROTOS" /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\..\pfl\win32" /I "..\..\..\pfl\common" /I "..\..\..\pfl\common\file" /I "..\..\..\pfl\common\prefs" /I "..\..\..\pfl\common\util" /I ".." /I "..\..\pub\include" /I "..\..\priv\include" /I "..\..\priv\include\opaque" /I "..\..\priv\crypto\bignum" /I "..\..\priv\crypto\cipher" /I "..\..\priv\crypto\compress" /I "..\..\priv\crypto\hash" /I "..\..\priv\crypto\pipe\crypt" /I "..\..\priv\crypto\pipe\file" /I "..\..\priv\crypto\pipe\parser" /I "..\..\priv\crypto\pipe\sig" /I "..\..\priv\crypto\pipe\text" /I "..\..\priv\crypto\pipe\utils" /I "..\..\priv\crypto\random" /I "..\..\priv\debug" /I "..\..\priv\keys\keydb" /I "..\..\priv\keys\keys" /I "..\..\priv\keys\pubkey" /I "..\..\priv\regexp" /I "..\..\priv\utilities\errors" /I "..\..\priv\utilities" /I "..\..\priv\utilities\helper" /I "..\..\priv\utilities\utils" /I "..\..\priv\utilities\prefs" /I "..\..\priv\clientlib" /I "..\..\priv\encrypt" /I "..\..\..\pfl\common\sorting" /I "..\..\priv\ui" /D _WIN32_IE=0x0300 /D PGP_ENCRYPT_DISABLE=1 /D PGP_DECRYPT_DISABLE=1 /D UNFINISHED_CODE_ALLOWED=1 /D PGP_DEBUG=1 /D PGP_WIN32=1 /D "_DEBUG" /D "NEEDPROTOS" /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ../pgpcdk/debug/pgp_sdk.lib ../pgpsdkNetworkLib/debug/pgpsdkNL.lib comctl32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ../pgpcdk/debug/authentication/pgp_sdk_ltd.lib ../pgpsdkNetworkLib/debug/authentication/pgpsdkNLLtd.lib comctl32.lib /nologo /base:"0x12000000" /subsystem:windows /dll /debug /machine:I386 /out:"Debug\Authentication/PGPsdkUILtd.dll" /pdbtype:sept
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Desc=Building static library
PostBuild_Cmds=rename .\Debug\Authentication\PGPsdkUILibDLLMain.obj    PGPsdkUILibDLLMain.ob1  	lib  /nologo   /out:.\Debug\Authentication\PGPsdkUILtdStatic.lib  .\Debug\Authentication\*.obj  	rename   .\Debug\Authentication\PGPsdkUILibDLLMain.ob1 PGPsdkUILibDLLMain.obj
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "PGPsdkUI - Win32 Release"
# Name "PGPsdkUI - Win32 Debug"
# Name "PGPsdkUI - Win32 Release Auth Only"
# Name "PGPsdkUI - Win32 Debug Auth Only"
# Begin Group "Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\pgpCLUtils.c
# End Source File
# Begin Source File

SOURCE=.\PGPCollectRandomDataCL.cpp
# End Source File
# Begin Source File

SOURCE=.\PGPCollectRandomDataDialog.cpp
# End Source File
# Begin Source File

SOURCE=..\..\..\pfl\common\pgpDebug.c
# End Source File
# Begin Source File

SOURCE=..\..\priv\ui\pgpDialogOptions.c
# End Source File
# Begin Source File

SOURCE=..\..\priv\ui\pgpDialogs.cpp
# End Source File
# Begin Source File

SOURCE=..\..\priv\ui\pgpDialogs.h
# End Source File
# Begin Source File

SOURCE=..\..\..\pfl\common\file\pgpFileSpec.c
# End Source File
# Begin Source File

SOURCE=..\..\..\pfl\common\file\pgpFileSpecStd.c
# End Source File
# Begin Source File

SOURCE=..\..\..\pfl\common\file\pgpFileSpecVTBL.c
# End Source File
# Begin Source File

SOURCE=..\..\..\pfl\common\file\pgpFileSpecWin32.c
# End Source File
# Begin Source File

SOURCE=.\pgpKBNT.c
# End Source File
# Begin Source File

SOURCE=..\..\priv\ui\pgpKeyServerDialogCommon.cpp
# End Source File
# Begin Source File

SOURCE=.\PGPKeyServerDialogs.cpp
# End Source File
# Begin Source File

SOURCE=..\..\..\pfl\common\pgpLeaks.c
# End Source File
# Begin Source File

SOURCE=..\..\..\pfl\common\pgpMem.c
# End Source File
# Begin Source File

SOURCE=..\..\priv\utilities\pgpOptionList.c
# End Source File
# Begin Source File

SOURCE=.\PGPOptionsDialog.cpp
# End Source File
# Begin Source File

SOURCE=.\PGPPassphraseCL.cpp
# End Source File
# Begin Source File

SOURCE=.\PGPPassphraseDialog.cpp
# End Source File
# Begin Source File

SOURCE=..\..\..\pfl\common\util\pgpPassphraseUtils.c
# End Source File
# Begin Source File

SOURCE=.\PGPRecipientDialog.cpp
# End Source File
# Begin Source File

SOURCE=..\..\priv\ui\pgpRecipientDialogCommon.cpp
# End Source File
# Begin Source File

SOURCE=.\PGPsdkUI.def
# End Source File
# Begin Source File

SOURCE=..\..\priv\ui\pgpSDKUILib.c
# End Source File
# Begin Source File

SOURCE=.\PGPsdkUILibDLLMain.c
# End Source File
# Begin Source File

SOURCE=..\..\..\pfl\common\util\pgpStrings.c
# End Source File
# Begin Source File

SOURCE=..\..\pub\include\pgpUserInterface.h
# End Source File
# Begin Source File

SOURCE=.\RDdrag.c
# End Source File
# Begin Source File

SOURCE=.\RDdraw.c
# End Source File
# Begin Source File

SOURCE=.\RDkeyDB.c
# End Source File
# Begin Source File

SOURCE=.\RDlstmng.c
# End Source File
# Begin Source File

SOURCE=.\RDlstsrt.c
# End Source File
# Begin Source File

SOURCE=.\RDlstsub.c
# End Source File
# Begin Source File

SOURCE=.\RDmain.c
# End Source File
# Begin Source File

SOURCE=.\RDmove.c
# End Source File
# Begin Source File

SOURCE=.\RDproc.c
# End Source File
# Begin Source File

SOURCE=.\RDserver.c
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "*.rc"
# Begin Source File

SOURCE=.\Res\dlgicon.ico
# End Source File
# Begin Source File

SOURCE=..\..\..\..\clients\pgp\win32\shared\images24.bmp
# End Source File
# Begin Source File

SOURCE=..\..\..\..\clients\pgp\win32\shared\images4.bmp
# End Source File
# Begin Source File

SOURCE=.\PGPui.rc
# End Source File
# End Group
# Begin Source File

SOURCE=".\Res\5-myadded24.bmp"
# End Source File
# Begin Source File

SOURCE=".\Res\5-myadded4.bmp"
# End Source File
# Begin Source File

SOURCE=.\Res\closelock.ico
# End Source File
# Begin Source File

SOURCE=.\Res\images24.bmp
# End Source File
# Begin Source File

SOURCE=.\Res\images4.bmp
# End Source File
# Begin Source File

SOURCE=.\Res\openlock.ico
# End Source File
# End Target
# End Project
