/*
 * FreeRTOS PKCS #11 V1.0.3
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */
#ifndef _DEMO_HELPER_FUNCTIONS_
#define _DEMO_HELPER_FUNCTIONS_

/**
 * @file demo_helpers.h
 * @brief Common functions used between the PKCS #11 demos.
 */

/* PKCS #11 include. */
#include "core_pkcs11.h"

/* mbed TLS include. */
#include "mbedtls/pk.h"

/*
 * @brief demo label for the device certificate.
 */
#define pkcs11demoCERT_LABEL           "Device Cert"

/*
 * @brief demo label for the device private key.
 */
#define pkcs11demoPRIVATE_KEY_LABEL    "Device Priv TLS Key"

/*
 * @brief demo label for the device public key.
 */
#define pkcs11demoPUBLIC_KEY_LABEL     "Device Pub TLS Key"


/*
 * @brief This function contains standard setup code for PKCS #11. See the
 * "management_and_rng.c" file for the demo code explaining this section
 * of cryptoki.
 *
 * @param[in] pxSession          Pointer to an uninitialized PKCS #11 session handle.
 *                               This will be initialized by vStart.
 * @param[in] ppxSlotId          Pointer to a CK_SLOT_ID pointer.
 *                               A valid slot will be set by vStart.
 *
 */
void vStart( CK_SESSION_HANDLE * pxSession,
             CK_SLOT_ID ** ppxSlotId );
/*-----------------------------------------------------------*/

/* @brief This function contains standard tear down code for PKCS #11. See the
 * "management_and_rng.c" file for the demo code explaining this section
 * of cryptoki.
 *
 * @param[in] xSession           PKCS #11 session handle to uninitialized.
 * @param[in] ppxSlotId          PKCS #11 slot to close.
 */
void vEnd( CK_SESSION_HANDLE xSession,
           CK_SLOT_ID * pxSlotId );
/*-----------------------------------------------------------*/

/*
 * @brief This function is simply a helper function to print the raw hex values
 * of an EC public key. It's explanation is not within the scope of the demos
 * and is sparsely commented.
 *
 * @param[in] pcDescription         Description message
 * @param[in] pucData               Hex contents to print (Public key)
 * @param[in] ulDataLength          Lenghth of pucData
 *
 */
void vWriteHexBytesToConsole( char * pcDescription,
                              CK_BYTE * pucData,
                              CK_ULONG ulDataLength );
/*-----------------------------------------------------------*/

/*
 * @brief This function is simply a helper function to export the raw hex values
 * of an EC public key into a buffer. It's explanation is not within the
 * scope of the demos and is sparsely commented.
 */
CK_RV vExportPublicKey( CK_SESSION_HANDLE xSession,
                        CK_OBJECT_HANDLE xPublicKeyHandle,
                        CK_BYTE ** ppucDerPublicKey,
                        CK_ULONG * pulDerPublicKeyLength );
/*-----------------------------------------------------------*/

#endif /* _DEMO_HELPER_FUNCTIONS_ */