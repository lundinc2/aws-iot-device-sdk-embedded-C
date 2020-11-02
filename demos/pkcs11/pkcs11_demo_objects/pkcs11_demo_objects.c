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

/* Standard include. */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* Logging configuration for the PKCS #11 library. */
#ifndef LIBRARY_LOG_NAME
    #define LIBRARY_LOG_NAME    "PKCS11_DEMO"
#endif

#ifndef LIBRARY_LOG_LEVEL
    #define LIBRARY_LOG_LEVEL    LOG_INFO
#endif

/* PKCS #11 includes. */
#include "core_pkcs11_config.h"
#include "core_pkcs11.h"
#include "pkcs11.h"

/* mbed TLS includes. */
#include "mbedtls/pk.h"

/* Demo includes. */
#include "demo_helpers.h"

/* RSA certificate that has been generated off the device.
 * This key will be used as an example for importing an object onto the device.
 * This is useful when the device itself cannot create credentials or for storing
 * a well known CA certificate.
 */
#define pkcs11demo_RSA_CERTIFICATE                                       \
    ""                                                                   \
    "-----BEGIN CERTIFICATE-----\n" \
    "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\n" \
    "xg07nhvDeydwB48xXrPQ1KutrRyh\n" \
    "-----END CERTIFICATE-----"

/* This function can be found in 
 * FreeRTOS/FreeRTOS-Plus/Source/FreeRTOS-Plus-PKCS11/3rdparty/mbedtls_utils/mbedtls_utils.c.
 * It will be used to convert the RSA certificate from PEM format 
 * to DER format. */
extern int convert_pem_to_der( const unsigned char * pucInput,
                               size_t xLen,
                               unsigned char * pucOutput,
                               size_t * pxOlen );
/*-----------------------------------------------------------*/


/**
 * prvObjectImporting covers how to import a RSA certificate that was
 * not generated by the Cryptoki library.
 *
 */
static void prvObjectImporting( void );

/**
 * prvObjectGeneration covers how to create a public key and private key pair
 * with Cryptoki defined attributes using C_GenerateKeyPair.
 *
 * Note: The "sign-verify.c" demo has a dependency on the objects created
 * in this function, and will not work without first running this function.
 */
static void prvObjectGeneration( void );


/**
 * This function details how to use the PKCS #11 "Object" functions to
 * manage the objects abstracted by cryptoki.
 *
 * http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
 * please consult the standard for more information.
 *
 * The standard has grouped the functions presented in this demo as:
 * Object Management Functions.
 *
 */
void vPKCS11ObjectDemo( void )
{
    LogInfo( ( "Starting PKCS #11 Objects Demo." ) );

    /* PKCS #11 defines objects as "An item that is stored on a token. May be
     * data, a certificate, or a key." This demo will show how to create objects
     * that are managed by Cryptoki. */
    prvObjectImporting();
    prvObjectGeneration();
    LogInfo( ( "Finished PKCS #11 Objects Demo." ) );
}

static void prvObjectImporting( void )
{
    LogInfo( ( "---------Importing Objects---------" ) );
    LogInfo( ( "Importing RSA Certificate..." ) );

    /* Helper variables and variables that have been covered. */
    CK_RV xResult = CKR_OK;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_SLOT_ID * pxSlotId = 0;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    uint8_t * pucDerObject = NULL;
    int32_t lConversionReturn = 0;
    size_t xDerLen = 0;
    CK_BBOOL xTokenStorage = CK_TRUE;
    CK_OBJECT_HANDLE xCertHandle = CK_INVALID_HANDLE;
    CK_BYTE xSubject[] = "TestSubject";


    /* The PKCS11_CertificateTemplate_t is a custom struct defined in "core_pkcs11.h"
     * in order to make it easier to import a certificate. This struct will be
     * populated with the parameters necessary to import the certificate into the
     * Cryptoki library.
     */
    PKCS11_CertificateTemplate_t xCertificateTemplate;

    /* The object class is specified as a certificate to help the Cryptoki library
     * parse the arguments. 
     */
    CK_OBJECT_CLASS xCertificateClass = CKO_CERTIFICATE;
    
    /* The certificate type is an x509 certificate, which is the only type 
     * supported by this stack. To read more about x509 certificates one can
     * read the following:
     *
     * https://en.wikipedia.org/wiki/X.509
     * https://www.ssl.com/faqs/what-is-an-x-509-certificate/
     *
     */
    CK_CERTIFICATE_TYPE xCertificateType = CKC_X_509;

    /* The label will help the application identify which object it would like 
     * to access.
     */
    CK_BYTE pucLabel[] = pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS;

    /* Specify certificate class. */
    xCertificateTemplate.xObjectClass.type = CKA_CLASS;
    xCertificateTemplate.xObjectClass.pValue = &xCertificateClass;
    xCertificateTemplate.xObjectClass.ulValueLen = sizeof( xCertificateClass );

    /* Specify certificate subject. */
    xCertificateTemplate.xSubject.type = CKA_SUBJECT;
    xCertificateTemplate.xSubject.pValue = xSubject;
    xCertificateTemplate.xSubject.ulValueLen = strlen( ( const char * ) xSubject );

    /* Point to contents of certificate. */
    xCertificateTemplate.xValue.type = CKA_VALUE;
    xCertificateTemplate.xValue.pValue = ( CK_VOID_PTR ) pkcs11demo_RSA_CERTIFICATE;
    xCertificateTemplate.xValue.ulValueLen = ( CK_ULONG ) sizeof( pkcs11demo_RSA_CERTIFICATE );
    
    /* Specify certificate label. */
    xCertificateTemplate.xLabel.type = CKA_LABEL;
    xCertificateTemplate.xLabel.pValue = ( CK_VOID_PTR ) pucLabel;
    xCertificateTemplate.xLabel.ulValueLen = strlen( ( const char * ) pucLabel );
    
    /* Specify certificate type as x509. */
    xCertificateTemplate.xCertificateType.type = CKA_CERTIFICATE_TYPE;
    xCertificateTemplate.xCertificateType.pValue = &xCertificateType;
    xCertificateTemplate.xCertificateType.ulValueLen = sizeof( CK_CERTIFICATE_TYPE );

    /* Specify that the certificate should be on a token. */
    xCertificateTemplate.xTokenObject.type = CKA_TOKEN;
    xCertificateTemplate.xTokenObject.pValue = &xTokenStorage;
    xCertificateTemplate.xTokenObject.ulValueLen = sizeof( xTokenStorage );

    vStart( &hSession, &pxSlotId );

    /* Ensure the Cryptoki library has the necessary functions implemented. */
    xResult = C_GetFunctionList( &pxFunctionList );
    assert( xResult == CKR_OK );
    assert( pxFunctionList->C_CreateObject != NULL );

    /* Convert the certificate to DER format if it was in PEM. The DER key
     * should be about 3/4 the size of the PEM key, so mallocing the PEM key
     * size is sufficient. */
    pucDerObject = malloc( xCertificateTemplate.xValue.ulValueLen );
    assert( pucDerObject != NULL );

    xDerLen = xCertificateTemplate.xValue.ulValueLen;
    lConversionReturn = convert_pem_to_der( xCertificateTemplate.xValue.pValue,
                                            xCertificateTemplate.xValue.ulValueLen,
                                            pucDerObject,
                                            &xDerLen );

    assert( 0 == lConversionReturn );

    /* Set the template pointers to refer to the DER converted objects. */
    xCertificateTemplate.xValue.pValue = pucDerObject;
    xCertificateTemplate.xValue.ulValueLen = xDerLen;

    /* Create an object using the encoded client certificate. */
    LogInfo( ( "Creating x509 certificate with label: %s ",
                pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS ) );

    /* Once the Cryptoki library has finished importing the new x509 certificate
     * a CK_OBJECT_HANDLE is associated with it. The application can now use this
     * to refer to the object in following operations.
     *
     * xCertHandle in the below example will have it's value modified to
     * be the CK_OBJECT_HANDLE.
     *
     * Compare the hard coded x509, in PEM format, with the DER formatted
     * x509 certificate that is created by the Cryptoki library, with the following
     * OpenSSL command:
     * "$ openssl x509 -in FreeRTOS_P11_Certificate.dat -inform der -text"
     *
     * See this explanation for the difference between the PEM format and the
     * DER format:
     * https://stackoverflow.com/questions/22743415/what-are-the-differences-between-pem-cer-and-der/22743616
     *
     */
    xResult = pxFunctionList->C_CreateObject( hSession,
                                              ( CK_ATTRIBUTE_PTR ) &xCertificateTemplate,
                                              sizeof( xCertificateTemplate ) / sizeof( CK_ATTRIBUTE ),
                                              &xCertHandle );

    assert( xResult == CKR_OK );
    assert( xCertHandle != CK_INVALID_HANDLE );

    LogInfo( ( "FreeRTOS_P11_Certificate.dat has been created in the current " \
                    " directory" ) );

    free( pucDerObject );
    vEnd( hSession, pxSlotId );
    LogInfo( ( "Finished Importing RSA Certificate." ) );
    LogInfo( ( "---------Finished Importing Objects---------" ) );
}

static void prvObjectGeneration( void )
{
    LogInfo( ( "---------Generating Objects---------" ) );

    /* Helper variables. */
    CK_RV xResult = CKR_OK;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_SLOT_ID * pxSlotId = 0;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_BYTE * pxDerPublicKey = NULL;
    CK_ULONG ulDerPublicKeyLength = 0;
    CK_BBOOL xTrue = CK_TRUE;

    /* Specify the mechanism to use in the key pair generation. Mechanisms are
     * previously explained in the "mechanims_and_digests.c" demo. */
    CK_MECHANISM xMechanism =
    {
        CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0
    };

    /* The EC curve used in this demo will be the named EC curve prime256v1.
     * For further explanations of EC Cryptography please see the following:
     * https://en.wikipedia.org/wiki/Elliptic-curve_cryptography
     * https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography
     */
    CK_BYTE xEcParams[] = pkcs11DER_ENCODED_OID_P256;

    /* Specify the key type to be EC. */
    CK_KEY_TYPE xKeyType = CKK_EC;

    /* Object handles are a token specific identifier for an object. They are
     * used so the application's sessions can specify which object to interact
     * with. Non-zero values are valid, 0 is always invalid, and is defined as
     * CK_INVALID_HANDLE
     *
     * The lifetime of the handle is not necessarily the same as the lifetime of
     * the object.
     */
    CK_OBJECT_HANDLE xPrivateKeyHandle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE xPublicKeyHandle = CK_INVALID_HANDLE;


    /* Labels are application defined strings that are used to identify an
     * object. It should not be NULL terminated. */
    CK_BYTE pucPublicKeyLabel[] = { pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS };
    CK_BYTE pucPrivateKeyLabel[] = { pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS };

    /* CK_ATTTRIBUTE's contain an attribute type, a value, and the length of
     * the value. An array of CK_ATTRIBUTEs is called a template. They are used
     * for creating, searching, and manipulating for objects. The order of the
     * template does not matter.
     *
     * In the below template we are creating a public key:
     *      Specify the key type as EC.
     *      The key will be able to verify a message.
     *      Specify the EC Curve.
     *      Assign a label to the object that will be created.
     */
    CK_ATTRIBUTE xPublicKeyTemplate[] =
    {
        { CKA_KEY_TYPE,  &xKeyType, sizeof( xKeyType )              },
        { CKA_VERIFY,    &xTrue,    sizeof( xTrue )                 },
        { CKA_EC_PARAMS, xEcParams, sizeof( xEcParams )             },
        { CKA_LABEL,     pucPublicKeyLabel,    sizeof( pucPublicKeyLabel ) - 1 }
    };

    /* In the below template we are creating a private key:
     *      The key type is EC.
     *      The key is a token object.
     *      The key will be a private key.
     *      The key will be able to sign messages.
     *      Assign a label to the object that will be created.
     */
    CK_ATTRIBUTE xPrivateKeyTemplate[] =
    {
        { CKA_KEY_TYPE, &xKeyType,          sizeof( xKeyType )               },
        { CKA_TOKEN,    &xTrue,             sizeof( xTrue )                  },
        { CKA_PRIVATE,  &xTrue,             sizeof( xTrue )                  },
        { CKA_SIGN,     &xTrue,             sizeof( xTrue )                  },
        { CKA_LABEL,    pucPrivateKeyLabel, sizeof( pucPrivateKeyLabel ) - 1 }
    };

    vStart( &hSession, &pxSlotId );

    xResult = C_GetFunctionList( &pxFunctionList );
    assert( xResult == CKR_OK );

    LogInfo( ( "Creating private key with label: %s ",
                    pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) );
    LogInfo( ( "Creating public key with label: %s ",
                    pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS ) );

    /* This function will generate a new EC private and public key pair. You can
     * use " $openssl ec -inform der -in FreeRTOS_P11_Key.dat -text " to see
     * the structure of the keys that were generated.
     */
    xResult = pxFunctionList->C_GenerateKeyPair( hSession,
                                                 &xMechanism,
                                                 xPublicKeyTemplate,
                                                 sizeof( xPublicKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                 xPrivateKeyTemplate,
                                                 sizeof( xPrivateKeyTemplate ) / sizeof( CK_ATTRIBUTE ),
                                                 &xPublicKeyHandle,
                                                 &xPrivateKeyHandle );
    assert( xResult == CKR_OK );
    LogInfo( ( "FreeRTOS_P11_Key.dat has been created in the " \
                    "current directory" ) );
    LogInfo( ( "Extracting public key bytes..." ) );

    /* Export public key as hex bytes and print the hex representation of the
     * public key. */
    vExportPublicKey( hSession,
                      xPublicKeyHandle,
                      &pxDerPublicKey,
                      &ulDerPublicKeyLength );
    vWriteHexBytesToConsole( "Public Key in Hex Format",
                             pxDerPublicKey,
                             ulDerPublicKeyLength );
    LogInfo( ( "---------Finished Generating Objects---------" ) );
    vEnd( hSession, pxSlotId );
}

/**
 * @brief Entry point of demo.
 *
 * The example shown above uses PKCS #11 APIs to interact with objects.
 */
int main( int argc,
          char ** argv )
{
    vPKCS11ObjectDemo();
}
