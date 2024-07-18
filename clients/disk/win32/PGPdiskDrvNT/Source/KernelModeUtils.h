//////////////////////////////////////////////////////////////////////////////
// KernelModeUtils.h
//
// Declarations for KernelModeUtils.cpp.
//////////////////////////////////////////////////////////////////////////////

// $Id: KernelModeUtils.h,v 1.3 1998/12/14 18:59:40 nryan Exp $

// Copyright (C) 1998 by Network Associates, Inc.
// All rights reserved.

#ifndef Included_KernelModeUtils_h	// [
#define Included_KernelModeUtils_h

#include "DualErr.h"


////////
// Types
////////

// NameAssoc is used by the debug routines to associate strings to constants.

typedef struct NameAssoc
{
	PGPUInt32	func;
	LPCSTR		name;

} NameAssoc;


/////////////////////
// Exported functions
/////////////////////

DualErr		UniToAnsi(KUstring *uniString, LPSTR *string);

DualErr		AssignToUni(KUstring *outUniString, 
				PUNICODE_STRING inUniString);
DualErr		AssignToUni(KUstring *outUniString, 
				LPCWSTR inUniString);
DualErr		AssignToUni(KUstring *outUniString, 
				LPCSTR inString);

DualErr		AppendToUni(KUstring *outUniString, 
				PUNICODE_STRING inUniString);
DualErr		AppendToUni(KUstring *outUniString, 
				LPCWSTR inUniString);
DualErr		AppendToUni(KUstring *outUniString, 
				LPCSTR inString);

DualErr		PrependToUni(KUstring *outUniString, 
				PUNICODE_STRING inUniString);
DualErr		PrependToUni(KUstring *outUniString, 
				LPCWSTR inUniString);
DualErr		PrependToUni(KUstring *outUniString, 
				LPCSTR inString);

LPCSTR		GetName(NameAssoc nameTable[], PGPUInt32 n, PGPUInt32 func);
LPCSTR		GetADPacketName(PGPUInt32 code);
LPCSTR		GetIOCTLFunctionName(PGPUInt32 ioctlCode);
LPCSTR		GetIRPMajorFunctionName(PGPUInt8 majorFunc);

DualErr		MakePathToDrive(PGPUInt8 drive, KUstring *outPath);
PGPBoolean	IsValidDeviceName(PUNICODE_STRING deviceName);

PGPBoolean	IsFileInUseByReader(LPCSTR path);
PGPBoolean	IsFileInUseByWriter(LPCSTR path);
PGPBoolean	IsFileInUse(LPCSTR path);

PGPBoolean	IsThisAnNT5Machine();
//BEGIN RIP OF THE WIN XP DDK DEFINES AND TYPEDEFS WHICH MAY BE NEEDED - Imad R. Faiad
#if (_WIN32_WINNT < 0x0510)
#define IOCTL_DISK_GET_PARTITION_INFO_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0012, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_SET_PARTITION_INFO_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0013, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_GET_DRIVE_LAYOUT_EX      CTL_CODE(IOCTL_DISK_BASE, 0x0014, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_SET_DRIVE_LAYOUT_EX      CTL_CODE(IOCTL_DISK_BASE, 0x0015, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_CREATE_DISK              CTL_CODE(IOCTL_DISK_BASE, 0x0016, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_GET_LENGTH_INFO          CTL_CODE(IOCTL_DISK_BASE, 0x0017, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_DISK_GET_DRIVE_GEOMETRY_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0028, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_UPDATE_DRIVE_SIZE        CTL_CODE(IOCTL_DISK_BASE, 0x0032, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_GROW_PARTITION           CTL_CODE(IOCTL_DISK_BASE, 0x0034, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_DISK_GET_CACHE_INFORMATION    CTL_CODE(IOCTL_DISK_BASE, 0x0035, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_DISK_SET_CACHE_INFORMATION    CTL_CODE(IOCTL_DISK_BASE, 0x0036, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_GET_WRITE_CACHE_STATE    CTL_CODE(IOCTL_DISK_BASE, 0x0037, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_DISK_DELETE_DRIVE_LAYOUT      CTL_CODE(IOCTL_DISK_BASE, 0x0040, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_FORMAT_DRIVE				CTL_CODE(IOCTL_DISK_BASE, 0x00f3, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_SENSE_DEVICE				CTL_CODE(IOCTL_DISK_BASE, 0x00f8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_UPDATE_PROPERTIES		CTL_CODE(IOCTL_DISK_BASE, 0x0050, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_PERFORMANCE_OFF			CTL_CODE(IOCTL_DISK_BASE, 0x0018, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STORAGE_BREAK_RESERVATION       CTL_CODE(IOCTL_STORAGE_BASE, 0x0405, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_STORAGE_GET_HOTPLUG_INFO        CTL_CODE(IOCTL_STORAGE_BASE, 0x0305, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STORAGE_SET_HOTPLUG_INFO        CTL_CODE(IOCTL_STORAGE_BASE, 0x0306, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER CTL_CODE(IOCTL_STORAGE_BASE, 0x0304, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STORAGE_BREAK_RESERVATION       CTL_CODE(IOCTL_STORAGE_BASE, 0x0405, METHOD_BUFFERED, FILE_READ_ACCESS)


typedef enum _PARTITION_STYLE {
    PARTITION_STYLE_MBR,
    PARTITION_STYLE_GPT
} PARTITION_STYLE;

typedef unsigned __int64 ULONG64, *PULONG64;

typedef struct _PARTITION_INFORMATION_MBR {
    UCHAR   PartitionType;
    BOOLEAN BootIndicator;
    BOOLEAN RecognizedPartition;
    ULONG   HiddenSectors;
} PARTITION_INFORMATION_MBR, *PPARTITION_INFORMATION_MBR;

typedef struct _PARTITION_INFORMATION_GPT {
    GUID    PartitionType;
    GUID    PartitionId;
    ULONG64 Attributes;
    WCHAR   Name[36];
} PARTITION_INFORMATION_GPT, *PPARTITION_INFORMATION_GPT;

typedef struct _PARTITION_INFORMATION_EX {
    PARTITION_STYLE PartitionStyle;
    LARGE_INTEGER   StartingOffset;
    LARGE_INTEGER   PartitionLength;
    ULONG           PartitionNumber;
    BOOLEAN         RewritePartition;
    union {
        PARTITION_INFORMATION_MBR Mbr;
        PARTITION_INFORMATION_GPT Gpt;
    };
} PARTITION_INFORMATION_EX, *PPARTITION_INFORMATION_EX;

typedef struct _GET_LENGTH_INFORMATION {
    LARGE_INTEGER Length;
} GET_LENGTH_INFORMATION, *PGET_LENGTH_INFORMATION;

#endif // (_WIN32_WINNT < 0x0510)
//END RIP OF THE WIN XP DDK DEFINES AND TYPEDEFS WHICH MAY BE NEEDED
#endif	// ] Included_KernelModeUtils_h
