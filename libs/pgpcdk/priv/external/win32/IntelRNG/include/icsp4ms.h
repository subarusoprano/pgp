/*-----------------------------------------------------------------------
 *                     File: icsp4ms.h 
 *
 * Copyright (c) 1998 Intel Corporation. All rights reserved.
 *-----------------------------------------------------------------------
 * INTEL CONFIDENTIAL
 * 
 * The source code contained or described herein and all documents related to the 
 * source code ("Material") are owned by Intel Corporation or its suppliers or 
 * licensors.  Title to the Material remains with Intel Corporation or its 
 * suppliers and licensors.  The Material contains trade secrets and proprietary 
 * and confidential information of Intel or its suppliers and licensors.  The 
 * Material is protected by worldwide copyright and trade secret laws and treaty 
 * provisions.  No part of the Material may be used, copied, reproduced, modified,
 * published, uploaded, posted, transmitted, distributed, or disclosed in any way
 * without Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual 
 * property right is granted to or conferred upon you by disclosure or delivery of
 * the Materials, either expressly, by implication, inducement, estoppel or 
 * otherwise.  Any license under such intellectual property rights must be 
 * express and approved by Intel in writing.
 */

/* Intel Chipset CSP type */
#define PROV_INTEL_SEC       22 

/* Intel Chipset CSP name */
#define INTEL_DEF_PROV_A     "Intel Hardware Cryptographic Service Provider"
#define INTEL_DEF_PROV_W     L"Intel Hardware Cryptographic Service Provider"
#ifdef UNICODE
#define INTEL_DEF_PROV       INTEL_DEF_PROV_W
#else
#define INTEL_DEF_PROV       INTEL_DEF_PROV_A
#endif