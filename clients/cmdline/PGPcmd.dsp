# Microsoft Developer Studio Project File - Name="PGPcmd" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=PGPcmd - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "PGPcmd.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "PGPcmd.mak" CFG="PGPcmd - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "PGPcmd - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "PGPcmd - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "PGPcmd - Win32 Release"

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
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\..\libs\pgpcdk\win32\pgpsdkui" /I "..\..\..\libs\pgpcdk\priv\utilities" /I "..\..\..\libs\pgpcdk\priv\include\opaque" /I "..\..\..\libs\pgpcdk\priv\utilities\utils" /I "..\..\..\libs\pgpcdk\pub\include" /I "..\..\..\libs\pgpcdk\win32" /I "..\..\..\libs\pfl\common" /I "..\..\..\libs\pfl\win32" /I "..\shared" /I "..\..\..\libs\pfl\common\prefs" /I "..\..\..\libs\pfl\common\file" /I "..\..\..\libs\pfl\common\util" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D UNFINISHED_CODE_ALLOWED=1 /D PGP_DEBUG=0 /D PGP_WIN32=1 /D "RANDOM_DEVICE_UNSUPPORTED" /D PGP_INTEL_RNG_SUPPORT=0 /U "MYGUI" /FR /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 .\pflCommon.lib .\pgpsdkstatic.lib .\pgpsdknlstatic.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:console /machine:I386 /out:"Release/PGP.exe"
# SUBTRACT LINK32 /nodefaultlib
# Begin Special Build Tool
SOURCE="$(InputPath)"
PreLink_Desc=copying static libraries
PreLink_Cmds=copy   ..\..\..\libs\pgpcdk\win32\pgpcdk\release\pgpsdkstatic.lib   .\  	copy   ..\..\..\libs\pfl\win32\pflcommon\release\pflCommon.lib   .\  	copy   ..\..\..\libs\pgpcdk\win32\pgpsdknetworklib\release\pgpsdknlstatic.lib   .\ 	copy   ..\..\..\libs\pgpcdk\priv\external\win32\intelrng\lib\sec32ipi.lib   .\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PGPcmd - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "PGPcmd__"
# PROP BASE Intermediate_Dir "PGPcmd__"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\..\libs\pgpcdk\win32\pgpsdkui" /I "..\..\..\libs\pgpcdk\priv\utilities" /I "..\..\..\libs\pgpcdk\priv\include\opaque" /I "..\..\..\libs\pgpcdk\priv\utilities\utils" /I "..\..\..\libs\pgpcdk\pub\include" /I "..\..\..\libs\pgpcdk\win32" /I "..\..\..\libs\pfl\common" /I "..\..\..\libs\pfl\win32" /I "..\shared" /I "..\..\..\libs\pfl\common\prefs" /I "..\..\..\libs\pfl\common\file" /I "..\..\..\libs\pfl\common\util" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D UNFINISHED_CODE_ALLOWED=1 /D PGP_DEBUG=1 /D PGP_WIN32=1 /D "RANDOM_DEVICE_UNSUPPORTED" /FR /YX /FD /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib ..\..\..\libs\pfl\win32\pflcommon\debug\pflCommon.lib ..\..\..\libs\pgpcdk\win32\pgpcdk\debug\pgpsdkstatic.lib ..\..\..\libs\pgpcdk\win32\pgpsdknetworklib\debug\pgpsdknlstatic.lib /nologo /subsystem:console /debug /machine:I386 /out:"Debug/PGP.exe" /pdbtype:sept
# SUBTRACT LINK32 /nodefaultlib

!ENDIF 

# Begin Target

# Name "PGPcmd - Win32 Release"
# Name "PGPcmd - Win32 Debug"
# Begin Source File

SOURCE=.\args.c
# End Source File
# Begin Source File

SOURCE=.\config.c
# End Source File
# Begin Source File

SOURCE=.\dodecode.c
# End Source File
# Begin Source File

SOURCE=.\doencode.c
# End Source File
# Begin Source File

SOURCE=.\fileio.c
# End Source File
# Begin Source File

SOURCE=.\getopt.c
# End Source File
# Begin Source File

SOURCE=.\groups.c
# End Source File
# Begin Source File

SOURCE=.\keyadd.c
# End Source File
# Begin Source File

SOURCE=.\keyedit.c
# End Source File
# Begin Source File

SOURCE=.\keyexport.c
# End Source File
# Begin Source File

SOURCE=.\keygen.c
# End Source File
# Begin Source File

SOURCE=.\keymaint.c
# End Source File
# Begin Source File

SOURCE=.\keyremove.c
# End Source File
# Begin Source File

SOURCE=.\keyrevoke.c
# End Source File
# Begin Source File

SOURCE=.\keysign.c
# End Source File
# Begin Source File

SOURCE=.\keyview.c
# End Source File
# Begin Source File

SOURCE=.\lists.c
# End Source File
# Begin Source File

SOURCE=.\main.c
# End Source File
# Begin Source File

SOURCE=.\match.c
# End Source File
# Begin Source File

SOURCE=.\misc.c
# End Source File
# Begin Source File

SOURCE=.\more.c
# End Source File
# Begin Source File

SOURCE=.\pgp.c
# End Source File
# Begin Source File

SOURCE=.\pgpAcquireEntropy.c
# End Source File
# Begin Source File

SOURCE=..\..\..\LIBS\PGPCDK\PRIV\CRYPTO\BIGNUM\pgpBigNum.c
# End Source File
# Begin Source File

SOURCE=..\shared\pgpClientErrors.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\win32\PGPsdkUI\pgpCLUtils.c
# End Source File
# Begin Source File

SOURCE=..\shared\pgpDiskWiper.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libs\pgpcdk\win32\PGPsdkUI\pgpKBNT.c
# End Source File
# Begin Source File

SOURCE=.\pgpLanguage.c
# End Source File
# End Target
# End Project
