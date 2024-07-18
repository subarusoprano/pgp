//////////////////////////////////////////////////////////////////////////////
// CPGPdiskInterfaceHooks.cpp
//
// Functions for hooking system devices and services.
//////////////////////////////////////////////////////////////////////////////

// $Id: CPGPdiskInterfaceHooks.cpp,v 1.4.10.3 1999/10/01 19:32:44 nryan Exp $

// Copyright (C) 1998 by Network Associates, Inc.
// All rights reserved.

#define	__w64
#include <vdw.h>
#include <kfilter.cpp>

#include "Required.h"

#include "CPGPdiskInterface.h"
#include "CPGPdiskInterfaceHooks.h"
#include "Globals.h"
#include "KernelModeUtils.h"


////////////
// Constants
////////////

static LPCWSTR	kKeyboardDeviceName	= L"\\Device\\KeyboardClass0";
static LPCWSTR	kMouseDeviceName	= L"\\Device\\PointerClass0";


/////////////////////////////////////////////////////
// Class KeyboardFilterDevice public member functions
/////////////////////////////////////////////////////

// The KeyboardFilterDevice default constructor.

KeyboardFilterDevice::KeyboardFilterDevice() :
	KFilterDevice(kKeyboardDeviceName, FILE_DEVICE_KEYBOARD, DO_BUFFERED_IO)
{
	mCurrentStackLocation = NULL;
	mNumOutstandingIrps = 0;

	if (!NT_SUCCESS(m_ConstructorStatus))
	{
		mInitErr = DualErr(kPGDMinorError_DeviceConstructFailed, 
			m_ConstructorStatus);
	}
}

// The KeyboardFilterDevice destructor.

KeyboardFilterDevice::~KeyboardFilterDevice()
{
	// If we have one outstanding IRP, we are OK. If we have more than one, 
	// we're screwed. Bugcheck. This could be fixed with a lot of work, but
	// unloading is only allowed on debug builds, so who cares?

	if (mNumOutstandingIrps == 1)
	{
		mNumOutstandingIrps = 0;

		mCurrentStackLocation->CompletionRoutine = NULL;
		mCurrentStackLocation->Control &= ~SL_INVOKE_ON_CANCEL & 
			~SL_INVOKE_ON_SUCCESS & ~SL_INVOKE_ON_ERROR;

		mCurrentStackLocation = NULL;
	}
	else if (mNumOutstandingIrps > 1)
	{
		KeBugCheck(kPGPdiskBugCheckCode);
	}
}

// Read is called to read keypresses. Zero the inactivity timer.

NTSTATUS 
KeyboardFilterDevice::Read(KIrp I)
{
	mCurrentStackLocation = I.NextStackLocation();
	mNumOutstandingIrps++;

	return PassThrough(I, TRUE, NULL);
}

// OnIrpComplete is called after the keyboard returns data.

NTSTATUS 
KeyboardFilterDevice::OnIrpComplete(KIrp I, PVOID Context)
{
	mNumOutstandingIrps--;
	mCurrentStackLocation = NULL;

	Interface->mSecondsInactive = 0;

	return KFilterDevice::OnIrpComplete(I, Context);
}


//////////////////////////////////////////////////
// Class MouseFilterDevice public member functions
//////////////////////////////////////////////////

// The MouseFilterDevice default constructor.

MouseFilterDevice::MouseFilterDevice() :
	KFilterDevice(kMouseDeviceName, FILE_DEVICE_MOUSE, DO_BUFFERED_IO)
{
	mCurrentStackLocation = NULL;
	mNumOutstandingIrps = 0;

	if (!NT_SUCCESS(m_ConstructorStatus))
	{
		mInitErr = DualErr(kPGDMinorError_DeviceConstructFailed, 
			m_ConstructorStatus);
	}
}

// The MouseFilterDevice destructor.

MouseFilterDevice::~MouseFilterDevice()
{
	// If we have one outstanding IRP, we are OK. If we have more than one, 
	// we're screwed. Bugcheck. This could be fixed with a lot of work, but
	// unloading is only allowed on debug builds, so who cares?

	if (mNumOutstandingIrps == 1)
	{
		mNumOutstandingIrps = 0;

		mCurrentStackLocation->CompletionRoutine = NULL;
		mCurrentStackLocation->Control &= ~SL_INVOKE_ON_CANCEL & 
			~SL_INVOKE_ON_SUCCESS & ~SL_INVOKE_ON_ERROR;

		mCurrentStackLocation = NULL;
	}
	else if (mNumOutstandingIrps > 1)
	{
		KeBugCheck(kPGPdiskBugCheckCode);
	}
}

// Read is called to read keypresses. Zero the inactivity timer.

NTSTATUS 
MouseFilterDevice::Read(KIrp I)
{
	mCurrentStackLocation = I.NextStackLocation();
	mNumOutstandingIrps++;

	return PassThrough(I, TRUE, NULL);
}

// OnIrpComplete is called after the mouse returns data. Look for button
// presses.

NTSTATUS 
MouseFilterDevice::OnIrpComplete(KIrp I, PVOID Context)
{
	PMOUSE_INPUT_DATA pMID;
	
	mNumOutstandingIrps--;
	mCurrentStackLocation = NULL;

	pMID = (PMOUSE_INPUT_DATA) I.IoctlBuffer();
	pgpAssertAddrValid(pMID, MOUSE_INPUT_DATA);

	if (pMID->Buttons != 0)
		Interface->mSecondsInactive = 0;

	return KFilterDevice::OnIrpComplete(I, Context);
}


///////////////////////////////////////
// Initialization and cleanup functions
///////////////////////////////////////

// SetupSystemHooks installs our system hooks.

DualErr 
CPGPdiskInterface::SetupSystemHooks()
{
	DualErr derr;

	// Neither of these hooks are critical so don't report errors on a
	// failure to create.

	if (!IsThisAnNT5Machine())
	{
		//BEGIN FIX FOR DRIVERWORKS 1.5+ - Imad R. Faiad
		//mKeyboardFilter = new KeyboardFilterDevice();
		mKeyboardFilter = new (NonPagedPool) KeyboardFilterDevice();
		//END FIX FOR DRIVERWORKS 1.5+
		mCreatedKeyboardFilter = IsntNull(mKeyboardFilter);

		//BEGIN FIX FOR DRIVERWORKS 1.5+ - Imad R. Faiad
		//mMouseFilter = new MouseFilterDevice();
		mMouseFilter = new (NonPagedPool) MouseFilterDevice();
		//END FIX FOR DRIVERWORKS 1.5+
		mCreatedMouseFilter = IsntNull(mMouseFilter);
	}

	return derr;
}

// DeleteSystemHooks deletes our system hooks.

void 
CPGPdiskInterface::DeleteSystemHooks()
{
	if (mCreatedMouseFilter)
	{
		delete mMouseFilter;
		mMouseFilter = NULL;
	}

	if (mCreatedKeyboardFilter)
	{
		delete mKeyboardFilter;
		mKeyboardFilter = NULL;
	}
}
