//////////////////////////////////////////////////////////////////////////////
// VolFile.cpp
//
// Implementation of class VolFile.
//////////////////////////////////////////////////////////////////////////////

// $Id: VolFile.cpp,v 1.4.10.2 1999/08/19 08:35:17 nryan Exp $

// Copyright (C) 1998 by Network Associates, Inc.
// All rights reserved.

#define	__w64
#include <vdw.h>

#include "Required.h"
#include "UtilityFunctions.h"

#include "VolFile.h"


////////////////////////////////////////
// Class VolFile public member functions
////////////////////////////////////////

// The Class VolFile default constructor.

VolFile::VolFile() : File(), Volume()
{
	mDevExtInfo = (PGPUInt32) this;
}

// The VolFile destructor unmounts the VolFile.

VolFile::~VolFile()
{
	if (Mounted())
		Unmount();
}

void 
VolFile::GetDriveLayout(PDRIVE_LAYOUT_INFORMATION pDLI)
{
	pgpAssertAddrValid(pDLI, DRIVE_LAYOUT_INFORMATION);

	pDLI->PartitionCount = 1;
	pDLI->Signature = 0;

	GetPartitionInfo(&pDLI->PartitionEntry[0]);
}

// GetGeometry returns fake geometry for the drive.

void 
VolFile::GetGeometry(PDISK_GEOMETRY pGeom)
{
	pgpAssertAddrValid(pGeom, DISK_GEOMETRY);

	pGeom->Cylinders.QuadPart	= mBlocksDisk;
	pGeom->MediaType			= FixedMedia;
	pGeom->TracksPerCylinder	= 1;
	pGeom->SectorsPerTrack		= 1;
	pGeom->BytesPerSector		= kDefaultBlockSize;
}

// GetPartitionInfo returns fake partition information for the drive.

void 
VolFile::GetPartitionInfo(PPARTITION_INFORMATION pPI)
{
	pgpAssertAddrValid(pPI, PARTITION_INFORMATION);

	pPI->StartingOffset.QuadPart	= kDefaultBlockSize;
	pPI->PartitionLength.QuadPart	= mBlocksDisk * kDefaultBlockSize;
	pPI->HiddenSectors				= 0;
	pPI->PartitionNumber			= 1;
	pPI->PartitionType				= PARTITION_ENTRY_UNUSED; // like I know
	pPI->BootIndicator				= FALSE;
	pPI->RecognizedPartition		= TRUE;
	pPI->RewritePartition			= FALSE;
}
//BEGIN PGPDISK WINDOWS XP EXPLORER HACK - Imad R. Faiad
void 
VolFile::GetPartitionInfoEX(PPARTITION_INFORMATION_EX pPIx)
{
	pgpAssertAddrValid(pPIx, PARTITION_INFORMATION_EX);


	pPIx->PartitionStyle			= PARTITION_STYLE_MBR;
	pPIx->StartingOffset.QuadPart	= kDefaultBlockSize;
	pPIx->PartitionLength.QuadPart	= mBlocksDisk * kDefaultBlockSize;
	pPIx->PartitionNumber			= 1;
	pPIx->RewritePartition			= FALSE;
	pPIx->Mbr.PartitionType			= PARTITION_ENTRY_UNUSED; // like I know
	pPIx->Mbr.BootIndicator			= FALSE;
	pPIx->Mbr.RecognizedPartition	= TRUE;
	pPIx->Mbr.HiddenSectors			= 0;
}

void
VolFile::GetLengthInfo(PGET_LENGTH_INFORMATION pLI)
{
	pgpAssertAddrValid(pLI, PGET_LENGTH_INFORMATION);
	pLI->Length.QuadPart	= mBlocksDisk * kDefaultBlockSize;
}
//END PGPDISK WINDOWS XP EXPLORER HACK
// Mount will mount the volume file specified by 'path'.

DualErr 
VolFile::Mount(
	LPCSTR		path, 
	LPCSTR		deviceName, 
	PGPUInt64	blocksHeader, 
	PGPUInt64	blocksDisk, 
	PGPUInt8	drive, 
	PGPBoolean	mountReadOnly)
{
	DualErr derr;

	pgpAssertStrValid(path);
	pgpAssertStrValid(deviceName);

	pgpAssert(blocksDisk > 0);
	pgpAssert(Unmounted());

	// Initialize our data members.
	mBlocksDisk		= blocksDisk;
	mBlocksHeader	= blocksHeader;

	// Open the file.
	derr = Open(path, kOF_MustExist | kOF_DenyWrite | kOF_VirtualVolume | 
		(mountReadOnly ? kOF_ReadOnly : NULL));

	// Attempt the mount.
	if (derr.IsntError())
	{
		derr = Volume::Mount(deviceName, drive, mountReadOnly);
	}

	// Cleanup in case of error.
	if (derr.IsError())
	{
		if (Opened())
			Close();
	}

	return derr;
}

// Unmount unmounts a mounted volume file. It calls down to Volume::Unmount
// to do the job, then closes the file.

DualErr 
VolFile::Unmount(PGPBoolean isThisEmergency)
{
	DualErr derr;

	pgpAssert(Mounted());

	derr = Volume::Unmount(isThisEmergency);

	if (derr.IsntError())
	{
		DualErr afterFact = Close();
		pgpAssert(afterFact.IsntError());
	}

	return derr;
}

// Read performs a read request on the mounted volume.

DualErr 
VolFile::Read(PGPUInt8 *buf, PGPUInt64 pos, PGPUInt32 nBytes)
{
	DualErr derr;

	pgpAssertAddrValid(buf, PGPUInt8);
	pgpAssert(nBytes > 0);
	pgpAssert(Mounted());

	// Out of bounds?
	if (pos + nBytes > mBlocksDisk * kDefaultBlockSize)
		derr = DualErr(kPGDMinorError_OOBFileRequest);

	// Call down the request.
	if (derr.IsntError())
	{
		derr = File::Read(buf, pos + mBlocksHeader*kDefaultBlockSize, nBytes);
	}

	return derr;
}

// Write performs a write request on the mounted volume. Note how Write
// accounts for the bias introduced by the size of the volume file header.

DualErr 
VolFile::Write(PGPUInt8 *buf, PGPUInt64 pos, PGPUInt32 nBytes)
{
	DualErr derr;

	pgpAssertAddrValid(buf, PGPUInt8);
	pgpAssert(nBytes > 0);
	pgpAssert(Mounted());

	// Out of bounds?
	if (pos + nBytes > mBlocksDisk * kDefaultBlockSize)
		derr = DualErr(kPGDMinorError_OOBFileRequest);

	// Call down the request.
	if (derr.IsntError())
	{
		derr = File::Write(buf, pos + mBlocksHeader*kDefaultBlockSize, 
			nBytes);
	}

	return derr;
}
