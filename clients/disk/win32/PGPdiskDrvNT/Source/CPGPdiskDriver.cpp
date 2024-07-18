//////////////////////////////////////////////////////////////////////////////
// CPGPdiskDriver.cpp
//
// Definition of class CPGPdiskDriver.
//////////////////////////////////////////////////////////////////////////////

// $Id: CPGPdiskDriver.cpp,v 1.4.10.2 1999/10/01 19:32:44 nryan Exp $

// Copyright (C) 1998 by Network Associates, Inc.
// All rights reserved.

#define VDW_MAIN

#pragma warning(disable:4244)
#define	__w64
#include <vdw.h>
#pragma warning(default:4244)

#include "Required.h"
#include "PGPdiskVersion.h"
#include "UtilityFunctions.h"

#include "CPGPdiskDriver.h"
#include "CPGPdiskInterface.h"
#include "Globals.h"
#include "Function.h"
#include "KernelModeUtils.h"

DECLARE_DRIVER_CLASS(CPGPdiskDriver, NULL)


//////////////////////////////////
// Global variables for the driver
//////////////////////////////////

CPGPdiskInterface *Interface;		// pointer to the interface object


///////////////////////////////////////////////
// Class CPGPdiskDriver public member functions
///////////////////////////////////////////////

// DriverEntry is called when the driver is started.

NTSTATUS 
CPGPdiskDriver::DriverEntry(PUNICODE_STRING RegistryPath)
{
	NTSTATUS	status				= STATUS_SUCCESS;
	PGPBoolean	createdInterface	= FALSE;

	__try
	{
		// Disable unloads on release builds (long story).
	#if !PGP_DEBUG
		DisableUnload();
	#endif // PGP_DEBUG

		// Set default pool tag for all 'new' allocations.
		SetPoolTag(kPGPdiskMemPoolTag);

		//BEGIN FIX FOR DRIVERWORKS 1.5+ - Imad R. Faiad
		// Create interface object for app communication.
		//Interface = new CPGPdiskInterface(this);
		Interface = new (NonPagedPool) CPGPdiskInterface(this);
		//END FIX FOR DRIVERWORKS 1.5+
		createdInterface = IsntNull(Interface);

		if (!createdInterface)
		{
			mInitErr = DualErr(kPGDMinorError_OutOfMemory);
			status = STATUS_INSUFFICIENT_RESOURCES;
		}

		// Did it construct successfully?
		if (mInitErr.IsntError())
		{
			mInitErr = Interface->mInitErr;

			if (mInitErr.IsError())
				status = STATUS_INSUFFICIENT_RESOURCES;
		}

		// All code from here on refers to the interface class object.
		if (mInitErr.IsntError())
		{
			//BEGIN FIX-UP FOR COMPILE WITH WIN2KDDK - Imad R. Faiad
			//To compile with win2kddk set WIN2KDDK to 1
			//otherwise set it to 0 for an NT4DDK compile
			

			//DriverObject()->MajorFunction[IRP_MJ_PNP_POWER] =
				//DriverObject()->MajorFunction[IRP_MJ_SET_POWER];
#if (_WIN32_WINNT >= 0x0500)
			DriverObject()->MajorFunction[IRP_MJ_PNP_POWER] =
				DriverObject()->MajorFunction[IRP_MJ_SYSTEM_CONTROL];
#else
			
			DriverObject()->MajorFunction[IRP_MJ_PNP_POWER] =
				DriverObject()->MajorFunction[IRP_MJ_SET_POWER];
#endif
			EnableDispatchFilter(TRUE);

			DebugOut("PGPdisk Driver v%s loaded.\n", kVersionTextString);
			DebugOut("Copyright (C) 1998 Network Associates, Inc.\n\n");
		}
		else
		{
			DebugOut("PGPdisk Driver v%s failed to load.\n\n", 
				kVersionTextString);

			if (createdInterface)
			{
				delete Interface;
				Interface = NULL;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) 
	{
		Interface->ReportError(kPGDMajorError_KModeExceptionOccured);

		// Don't leave this hanging if we refuse to unload.
		if (createdInterface)
		{
			delete Interface;
			Interface = NULL;
		}

		mInitErr = DualErr(kPGDMinorError_KModeExceptionOccured);
		status = STATUS_INSUFFICIENT_RESOURCES;
	}

	return status;
}

// Unload is called when the driver is being unloaded.

VOID 
CPGPdiskDriver::Unload()
{
	// DON'T call base class Unload(), it has a bug because it assumes all
	// devices created by the driver were created only by class KDevice, and
	// makes things blow up if that isn't so.

	__try
	{
		DebugOut("PGPdisk Driver v%s unloading.\n\n", kVersionTextString);

		Interface->UnmountAllPGPdisks();

		// Delete interface object.
		if (IsntNull(Interface))
		{
			delete Interface;
			Interface = NULL;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) 
	{
		Interface->ReportError(kPGDMajorError_KModeExceptionOccured);
	}
}

// DispatchPGPdiskRequest dispatches an IRP destined for a PGPdisk.

NTSTATUS 
CPGPdiskDriver::DispatchPGPdiskRequest(
	KIrp		I, 
	PGPdisk		*pPGD, 
	PGPBoolean	*irpNeedsCompletion)
{
	DualErr		derr;
	NTSTATUS	status	= STATUS_SUCCESS;

	pgpAssertAddrValid(pPGD, PGPdisk);
	pgpAssertAddrValid(irpNeedsCompletion, PGPBoolean);

	I.Information() = 0;
	(* irpNeedsCompletion) = TRUE;

	DebugOut("\nPGPdisk: Seeing IRP %X which is an %s\n", 
		(PIRP) I, GetIRPMajorFunctionName(I.MajorFunction()));

	switch (I.MajorFunction())
	{
	case IRP_MJ_CLOSE:
	case IRP_MJ_CREATE:
	case IRP_MJ_FLUSH_BUFFERS:
	case IRP_MJ_SHUTDOWN:

		DebugOut("PGPdisk: Acknowledging an %s\n", 
			GetIRPMajorFunctionName(I.MajorFunction()));

		status = STATUS_SUCCESS;
		break;

	case IRP_MJ_READ:
	case IRP_MJ_WRITE:

		DebugOut("PGPdisk: Scheduling an %s\n", 
			GetIRPMajorFunctionName(I.MajorFunction()));

		// Reset inactivity timer on reads/writes.
		if ((I.MajorFunction() == IRP_MJ_READ) || 
			(I.MajorFunction() == IRP_MJ_WRITE))
		{
			Interface->mSecondsInactive = 0;
		}

		// Queue the IRP to the thread.
		derr = pPGD->GetThread()->QueueIrpForProcessing(I);

		if (derr.IsntError())
		{
			// If succeeded, report pending.
			status = STATUS_PENDING;
		}
		else
		{
			// If failed, report error.
			status = STATUS_INSUFFICIENT_RESOURCES;
		}
		break;

	case IRP_MJ_DEVICE_CONTROL:
		status = pPGD->GetThread()->ProcessIrpMjDeviceControl(I);
		break;

	default:
		DebugOut("\nPGPdisk: Rejecting a %s\n", 
			GetIRPMajorFunctionName(I.MajorFunction()));

		break;
	}

	// Complete if not pending.
	if (status != STATUS_PENDING)
	{
		I.Complete(status);
		(* irpNeedsCompletion) = FALSE;
	}

	return status;
}

// DispatchFilter is called so we can route IRPs correctly.

NTSTATUS 
CPGPdiskDriver::DispatchFilter(
	KDevice					*pDevice, 
	KIrp					I, 
	NTSTATUS(KDevice::*func)(KIrp))
{
	NTSTATUS		status				= STATUS_SUCCESS;
	PDEVICE_OBJECT	pDevObj;
	PGPBoolean		irpNeedsCompletion	= TRUE;

	__try
	{
		pDevObj = I.DeviceObject();
		pgpAssertAddrValid(pDevObj, DEVICE_OBJECT);

		// PGPdisk device objects are dispatched separately from class
		// KDevice device objects. This routine assumes all the
		// FILE_VIRTUAL_VOLUME type objects created in this driver will be
		// PGPdisks only.

		if (pDevObj->Characteristics & FILE_VIRTUAL_VOLUME)
		{
			if (IsntNull(pDevice))
			{
				status = DispatchPGPdiskRequest(I, (PGPdisk *) pDevice, 
					&irpNeedsCompletion);
			}
			else
			{
				status = STATUS_VOLUME_DISMOUNTED;
			}
		}
		else
		{
			status = (pDevice->*func)(I);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) 
	{
		Interface->ReportError(kPGDMajorError_KModeExceptionOccured);

		// We don't exit with uncompleted IRPs.
		if (irpNeedsCompletion)
			status = I.Complete(STATUS_DEVICE_DATA_ERROR);
	}

	return status;
}
