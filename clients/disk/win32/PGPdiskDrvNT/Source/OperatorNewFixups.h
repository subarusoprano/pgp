//////////////////////////////////////////////////////////////////////////////
// OperatorNewFixups.h
//
// Extra definitions for operator new.
//////////////////////////////////////////////////////////////////////////////

// $Id: OperatorNewFixups.h,v 1.3 1998/12/14 18:59:43 nryan Exp $

// Copyright (C) 1998 by Network Associates, Inc.
// All rights reserved.

#ifndef Included_OperatorNewFixups_h	// [
#define Included_OperatorNewFixups_h


//////////
// Externs
//////////

extern ULONG __Pool_Tag__;


/////////////////////////////
// New without pool specifier
/////////////////////////////

// Why not provide a default specifier and save everyone from rewriting their
// shared code Vireo? What the dil-e-o?
//BEGIN FIX FOR DRIVERWORKS 1.5+ - Imad R. Faiad
//This operator override is no longer needed
//as it is now defined in DriverWorks 1.5 - Imad R. Faiad
/*inline 
void * 
__cdecl 
operator new(unsigned int nSize)
{
#if DBG
		return ExAllocatePoolWithTag(NonPagedPool, nSize, __Pool_Tag__);
#else
		return ExAllocatePool(NonPagedPool, nSize);
#endif
};*/
//END FIX FOR DRIVERWORKS 1.5+

////////////////
// Placement New
////////////////

inline 
void * 
__cdecl 
operator new(unsigned int nSize, void *pMem)
{
	return pMem;			// all too easy!
}

#endif // ] Included_OperatorNewFixups_h
