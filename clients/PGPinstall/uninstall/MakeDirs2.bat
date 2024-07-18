rem @echo off

if EXIST "Setup Files" rmdir /Q /S "Setup Files"

MKDIR "Setup Files"
MKDIR "Setup Files\Compressed Files"
MKDIR "Setup Files\Compressed Files\0009-English"
MKDIR "Setup Files\Compressed Files\0009-English\Intel 32"
MKDIR "Setup Files\Compressed Files\0009-English\OS Independent"
MKDIR "Setup Files\Compressed Files\Language Independent"
MKDIR "Setup Files\Compressed Files\Language Independent\Intel 32"
MKDIR "Setup Files\Compressed Files\Language Independent\OS Independent"
MKDIR "Setup Files\Uncompressed Files"
MKDIR "Setup Files\Uncompressed Files\0009-English"
MKDIR "Setup Files\Uncompressed Files\0009-English\Intel 32"
MKDIR "Setup Files\Uncompressed Files\0009-English\OS Independent"

set PGPBASEDIR=..\..\..\..\..
set LIBSDIR=%PGPBASEDIR%\libs
set PGPNETDIR=%PGPBASEDIR%\clients\net\win32
set PGPDISKDIR=%PGPBASEDIR%\clients\disk\win32
set RELEASEDIR=..\..\PGPClient\Release
set INSTALLDIR="Setup Files\Compressed Files\0009-English\Intel 32"

copy %LIBSDIR%\pfl\win32\InstallDLL\Release\install.dll	%INSTALLDIR%
copy %PGPBASEDIR%\clients\disk\win32\PGPDiskInstallHelper\Release\PGPDskIH.dll %INSTALLDIR%

set PGPBASEDIR=
set LIBSDIR=
set PGPNETDIR=
set PGPDISKDIR=
set RELEASEDIR=
set INSTALLDIR=
