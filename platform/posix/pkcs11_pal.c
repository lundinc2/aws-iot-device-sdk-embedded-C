/*
 * corePKCS11 PAL for Linux V2.0.0
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

/**
 * @file pkcs11_pal.c
 * @brief Linux file save and read implementation
 * for PKCS #11 based on mbedTLS with for software keys. This
 * file deviates from the FreeRTOS style standard for some function names and
 * data types in order to maintain compliance with the PKCS #11 standard.
 */

/*-----------------------------------------------------------*/

#include "iot_pkcs11_config.h"
#include "iot_pkcs11.h"

/* C runtime includes. */
#include <string.h>
#include <stdio.h>

/**
 * @ingroup pkcs11_macros
 * @brief Macros for managing PKCS #11 objects in flash.
 *
 */
#define pkcs11palFILE_NAME_CLIENT_CERTIFICATE    "FreeRTOS_P11_Certificate.dat"       /**< The file name of the Certificate object. */
#define pkcs11palFILE_NAME_KEY                   "FreeRTOS_P11_Key.dat"               /**< The file name of the Key object. */
#define pkcs11palFILE_CODE_SIGN_PUBLIC_KEY       "FreeRTOS_P11_CodeSignKey.dat"       /**< The file name of the Code Sign Key object. */

/**
 * @ingroup pkcs11_enums
 * @brief Enums for managing PKCS #11 object types.
 *
 */
enum eObjectHandles
{
    eInvalidHandle = 0,       /**< According to PKCS #11 spec, 0 is never a valid object handle. */
    eAwsDevicePrivateKey = 1, /**< Private Key. */
    eAwsDevicePublicKey,      /**< Public Key. */
    eAwsDeviceCertificate,    /**< Certificate. */
    eAwsCodeSigningKey        /**< Code Signing Key. */
};

/*-----------------------------------------------------------*/

/**
 * @brief Checks to see if a file exists
 *
 * @param[in] pcFileName         The name of the file to check for existance.
 *
 * @returns pdTRUE if the file exists, pdFALSE if not.
 */
static CK_RV prvFileExists( const char * pcFileName )
{
    FILE * pxFile;
    CK_RV xReturn = CKR_OK;

    /* fopen returns NULL if the file does not exist. */
    pxFile = fopen( pcFileName, "r" );

    if( pxFile == NULL )
    {
        xReturn = CKR_OBJECT_HANDLE_INVALID;
    }
    else
    {
        ( void ) fclose( pxFile );
    }

    return xReturn;
}

/**
 * @brief Checks to see if a file exists
 *
 * @param[in] pcLabel            The PKCS #11 label to convert to a file name
 * @param[out] pcFileName        The name of the file to check for existance.
 * @param[out] pHandle           The type of the PKCS #11 object.
 *
 */
void prvLabelToFilenameHandle( uint8_t * pcLabel,
                               char ** pcFileName,
                               CK_OBJECT_HANDLE_PTR pHandle )
{
    if( pcLabel != NULL )
    {
        /* Translate from the PKCS#11 label to local storage file name. */
        if( 0 == memcmp( pcLabel,
                         &pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                         sizeof( pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS ) ) )
        {
            *pcFileName = pkcs11palFILE_NAME_CLIENT_CERTIFICATE;
            *pHandle = eAwsDeviceCertificate;
        }
        else if( 0 == memcmp( pcLabel,
                              &pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                              sizeof( pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) ) )
        {
            *pcFileName = pkcs11palFILE_NAME_KEY;
            *pHandle = eAwsDevicePrivateKey;
        }
        else if( 0 == memcmp( pcLabel,
                              &pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                              sizeof( pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS ) ) )
        {
            *pcFileName = pkcs11palFILE_NAME_KEY;
            *pHandle = eAwsDevicePublicKey;
        }
        else if( 0 == memcmp( pcLabel,
                              &pkcs11configLABEL_CODE_VERIFICATION_KEY,
                              sizeof( pkcs11configLABEL_CODE_VERIFICATION_KEY ) ) )
        {
            *pcFileName = pkcs11palFILE_CODE_SIGN_PUBLIC_KEY;
            *pHandle = eAwsCodeSigningKey;
        }
        else
        {
            *pcFileName = NULL;
            *pHandle = eInvalidHandle;
        }
    }
}

/*-----------------------------------------------------------*/

CK_RV PKCS11_PAL_Initialize( void )
{
    return CKR_OK;
}

CK_OBJECT_HANDLE PKCS11_PAL_SaveObject( CK_ATTRIBUTE_PTR pxLabel,
                                        uint8_t * pucData,
                                        uint32_t ulDataSize )
{
    uint32_t ulStatus = 0;
    FILE * pxFile;
    size_t ulBytesWritten;
    char * pcFileName = NULL;
    CK_OBJECT_HANDLE xHandle = eInvalidHandle;

    /* Converts a label to its respective filename and handle. */
    prvLabelToFilenameHandle( pxLabel->pValue,
                              &pcFileName,
                              &xHandle );

    if( pcFileName != NULL )
    {
        /* Overwrite the file every time it is saved. */
        pxFile = fOpen( pcFileName, "w" );

        if( NULL == pxFile )
        {
            ulStatus = GetLastError();
            LogError( ( "PKCS #11 PAL was unable to save object to file. "
                        "The PAL was unable to open a file with name %s in write mode.", pcFileName ) );
            xHandle = eInvalidHandle;
        }
        else
        {
           ulBytesWritten = fwrite( pucData, sizeof( uint8_t ), ulDataSize, pxFile );

           if( ulBytesWritten != ulDataSize )
           {
                LogError( ( "PKCS #11 PAL was unable to save object to file. "
                            "Expected to write %d bytes, but wrote %d bytes.", ulDataSize, ulBytesWritten ) );
                xHandle = eInvalidHandle;
           }
        }

        if( NULL != pxFile )
        {
            ( void ) fclose( pxFile );
        }
    }

    return xHandle;
}

/*-----------------------------------------------------------*/


CK_OBJECT_HANDLE PKCS11_PAL_FindObject( uint8_t * pLabel,
                                        uint8_t usLength )
{
    ( void ) usLength;

    CK_OBJECT_HANDLE xHandle = eInvalidHandle;
    char * pcFileName = NULL;

    prvLabelToFilenameHandle( pLabel,
                              &pcFileName,
                              &xHandle );

    if( CKR_OK != prvFileExists( pcFileName ) )
    {
        xHandle = eInvalidHandle;
    }

    return xHandle;
}
/*-----------------------------------------------------------*/

CK_RV PKCS11_PAL_GetObjectValue( CK_OBJECT_HANDLE xHandle,
                                 uint8_t ** ppucData,
                                 uint32_t * pulDataSize,
                                 CK_BBOOL * pIsPrivate )
{
    CK_RV xReturn = CKR_OK;
    FILE * pxFile;
    size_t ulSize = 0;
    char * pcFileName = NULL;


    if( xHandle == eAwsDeviceCertificate )
    {
        pcFileName = pkcs11palFILE_NAME_CLIENT_CERTIFICATE;
        *pIsPrivate = CK_FALSE;
    }
    else if( xHandle == eAwsDevicePrivateKey )
    {
        pcFileName = pkcs11palFILE_NAME_KEY;
        *pIsPrivate = CK_TRUE;
    }
    else if( xHandle == eAwsDevicePublicKey )
    {
        /* Public and private key are stored together in same file. */
        pcFileName = pkcs11palFILE_NAME_KEY;
        *pIsPrivate = CK_FALSE;
    }
    else if( xHandle == eAwsCodeSigningKey )
    {
        pcFileName = pkcs11palFILE_CODE_SIGN_PUBLIC_KEY;
        *pIsPrivate = CK_FALSE;
    }
    else
    {
        xReturn = CKR_KEY_HANDLE_INVALID;
    }

    if( pcFileName != NULL )
    {
        pxFile = fopen( pcFileName, "r");

        if( NULL == pxFile )
        {
            LogError( ( "PKCS #11 PAL failed to get object value. "
                        "Could not open file named %s for reading.", pcFileName ) );
        }
        else
        {
            fseek(f, 0, SEEK_END);
            *pulDataSize = ftell(f);
            fseek(f, 0, SEEK_SET);

            *ppucData = PCKS11_MALLOC( *pulDataSize );

            if( NULL == *ppucData )
            {
                xReturn = CKR_HOST_MEMORY;
            }

        }

        if( CKR_OK == xReturn )
        {
            ulSize = fread(*ppucData, sizeof( uint8_t ), *pulDataSize, pxFile );
            if( ulSize != *pulDataSize )
            {
                LogError(( "PKCS #11 PAL Failed to get object value. Expected to read %d from %s but received %d", *pulDataSize, pcFileName, ulSize ) );
                xReturn = CKR_FUNCTION_FAILED;
            }
        }

        if( NULL != pxFile )
        {
            fclose( pxFile );
        }
    }

    return ulReturn;
}

/*-----------------------------------------------------------*/

void PKCS11_PAL_GetObjectValueCleanup( uint8_t * pucData,
                                       uint32_t ulDataSize )
{
    /* Unused parameters. */
    ( void ) ulDataSize;

    if( NULL != pucData )
    {
        PKCS11_FREE( pucData );
    }
}

/*-----------------------------------------------------------*/
