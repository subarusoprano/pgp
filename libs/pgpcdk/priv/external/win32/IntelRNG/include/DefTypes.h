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
#ifndef __DEFTYPES_PSD_
#define __DEFTYPES_PSD_

//////////////////////////////////////////////
// Internal basic types
//////////////////////////////////////////////

// Integeral types
typedef unsigned __int64 uint64, * puint64;
typedef unsigned __int32 uint32, * puint32;
typedef unsigned __int16 uint16, * puint16;
typedef unsigned __int8	 uint8,  * puint8;
typedef __int64 int64, * pint64;
typedef __int32 int32, * pint32;
typedef __int16 int16, * pint16;
typedef __int8	int8,  * pint8;
typedef unsigned __int8  bool8, *pbool8;


//Define TRUE/FALSE for the bool8 type
#ifdef TRUE
#undef TRUE
#endif //TRUE
#define TRUE	1

#ifdef FALSE
#undef FALSE
#endif //FALSE
#define FALSE	0


//////////////////////////////////////////////
// Function execution/return status
//////////////////////////////////////////////

// return type
typedef uint32 ISDRETURN;

// Generic return values
#define ISD_EOK				0x0000	// The function executed successfully.
#define ISD_ENOTAVAIL		0x0001	// This service is not supported by this implementation.
#define ISD_EDISABLED		0x0002	// This service is supported, but is currently disabled.
#define ISD_EFAIL           0x0003  // The data returned is not valid (rng timeout or IO error)
#define ISD_EINPUT          0x0004  // Input Parameter error or Index out of range
#define ISD_EUNKNOWN		0xffff	// The function failed to execute successfully (if no specific reasons can be identified).
#define ISD_ETESTFAIL		0x0010	// The function executed, but one or more tests failed.


//Index values for retrieving capability information
#define ISD_MAJORVER            0x00000001  //Driver major version
#define ISD_MINORVER            0x00000002  //Driver minor version
#define ISD_RNGS_SUPPORTED      0x00000003  //Number of RNGs supported
#define ISD_RNGS_FAILED         0x00000004  //Number of RNGs failed self-test
#define ISD_RNG_ENABLED         0x00000005  //Is use of the RNG(s) enabled?

//Index values for retrieving statistics information
#define ISD_GETRANDOMNUMBER     0x00000001  //Number of times the function has been called
#define ISD_TESTRANDOMGENERATOR 0x00000002  //Number of times the function has been called


#endif //__DEFTYPES_PSD_

