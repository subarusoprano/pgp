///////////////////////////////////////////////////
//
//	ISEC Header File ( Interface for SECurity )
//
//  This file defines the interface set for the each
//  of the security primitives that are available.
//
/******************************************************************************
INTEL CONFIDENTIAL
Copyright (c) 1998 Intel Corporation.  All rights reserved.

The source code contained or described herein and all documents related to the 
source code ("Material") are owned by Intel Corporation or its suppliers or 
licensors.  Title to the Material remains with Intel Corporation or its 
suppliers and licensors.  The Material contains trade secrets and proprietary 
and confidential information of Intel or its suppliers and licensors.  The 
Material is protected by worldwide copyright and trade secret laws and treaty 
provisions.  No part of the Material may be used, copied, reproduced, modified,
published, uploaded, posted, transmitted, distributed, or disclosed in any way
without Intel's prior express written permission.

No license under any patent, copyright, trade secret or other intellectual 
property right is granted to or conferred upon you by disclosure or delivery of
the Materials, either expressly, by implication, inducement, estoppel or 
otherwise.  Any license under such intellectual property rights must be 
express and approved by Intel in writing.
******************************************************************************/

#ifndef _ISEC_H_
#define _ISEC_H_

#include "DefTypes.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus


/*-----------------------------------------------------------------------------

  IsdGetCapability

  This function allows the caller to query the specific capabilities and
  features supported by this implementation.

  Parameters:
  Index (input) -   Index value representing the specific information desired.
                    See DefTypes.h for valid index values.

  Value (output) -  32-bit buffer to receive the requested information.  This
                    value should be ignored if the return value is not 
                    ISD_EOK.

  Return Value:
  ISD_EOK -     The function executed successfully.
  ISD_EINPUT -  The supplied Index value is not supported by this
                inplementation.
  ISD_EUNKNOWN -The function failed for an unspecified reason.

-----------------------------------------------------------------------------*/
__declspec( dllexport ) 
ISDRETURN IsdGetCapability(uint32 Index, uint32* Value);


/*-----------------------------------------------------------------------------

  IsdGetStatistic

  This function allows the caller to retrieve operational statistics.

  Parameters:
  Index (input) -   An index value representing the specific information
                    desired.  See DefTypes.h for valid Index values.

  Value (output) -  32-bit buffer to receive the requested information.  This
                    value should be ignored if the return value is not 
                    ISD_EOK.

  Return Value:
  ISD_EOK -     The function executed successfully.
  ISD_EINPUT -  The supplied Index value is not supported by this
                inplementation.
  ISD_EUNKNOWN -The function failed for an unspecified reason.

-----------------------------------------------------------------------------*/
__declspec( dllexport ) 
ISDRETURN IsdGetStatistic(uint32 Index, uint32* Value);


/*-----------------------------------------------------------------------------

  IsdGetRandomNumber

  This function generates a 32-bit random number, and returns it in the
  caller-supplied buffer.

  Parameters:
  RandomNumber (output) -   32-bit buffer to accept the generated random
                            number.  This value should be ignored if the return
                            value is not ISD_EOK;

  Return Value:
  ISD_EOK       -   The function executed successfully.
  ISD_ENOTAVAIL -   The service is not supported by this implementation.
  ISD_EDISABLED -   Use of all random number generators has been disabled.
  ISD_ETESTFAIL -   None of the avail. RNGs have passed self-test, and may not
                    be used.
  ISD_EUNKNOWN  -   The function failed for an unspecified reason.

-----------------------------------------------------------------------------*/
__declspec( dllexport )
ISDRETURN IsdGetRandomNumber(uint32* RandomNumber);


/*-----------------------------------------------------------------------------

  IsdTestRandomGenerator

  This function initiates and runs a FIPS 140-1 test on the random number
  generator(s).

  Parameters:
  None.

  Return Value:
  ISD_EOK       -   The function executed successfully, and all tests passed.
  ISD_ENOTAVAIL -   The service is not supported by this implementation.
  ISD_EDISABLED -   Use of all random number generators has been disabled.
  ISD_ETESTFAIL -   The function executed successfully, but none of the
                    RNGs currently accessible to the driver passed all required
                    tests..
  ISD_EUNKNOWN  -   The function failed to execute successfully for an 
                    unspecified reason.

-----------------------------------------------------------------------------*/
__declspec( dllexport )
ISDRETURN IsdTestRandomGenerator(void);


#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus

#endif //!_ISEC_H_
