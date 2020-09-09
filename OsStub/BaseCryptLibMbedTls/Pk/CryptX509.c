/** @file
  X.509 Certificate Handler Wrapper Implementation over OpenSSL.

Copyright (c) 2010 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/rsa.h>

/**
  Construct a X509 object from DER-encoded certificate data.

  If Cert is NULL, then return FALSE.
  If SingleX509Cert is NULL, then return FALSE.

  @param[in]  Cert            Pointer to the DER-encoded certificate data.
  @param[in]  CertSize        The size of certificate data in bytes.
  @param[out] SingleX509Cert  The generated X509 object.

  @retval     TRUE            The X509 object generation succeeded.
  @retval     FALSE           The operation failed.

**/
BOOLEAN
EFIAPI
X509ConstructCertificate (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize,
  OUT  UINT8        **SingleX509Cert
  )
{
  return FALSE;
}

STATIC
BOOLEAN
EFIAPI
X509ConstructCertificateStackV (
  IN OUT  UINT8    **X509Stack,
  IN      VA_LIST  Args
  )
{
  UINT8* Cert;
  UINTN CertSize;
  INT32 Index;
  INT32 Ret;

  if (X509Stack == NULL) {
    return FALSE;
  }

  Ret = 0;
  mbedtls_x509_crt *Crt = (mbedtls_x509_crt *)*X509Stack;
  if (Crt == NULL) {
    Crt = AllocatePool(sizeof(mbedtls_x509_crt));
    if (Crt == NULL) {
      return FALSE;
    }
    mbedtls_x509_crt_init(Crt);
    *X509Stack = (UINT8 *)Crt;
  }

  for (Index = 0; ; Index++) {
    //
    // If Cert is NULL, then it is the end of the list.
    //
    Cert = VA_ARG (Args, UINT8 *);
    if (Cert == NULL) {
      break;
    }

    CertSize = VA_ARG (Args, UINTN);
    if (CertSize == 0) {
      break;
    }

    Ret = mbedtls_x509_crt_parse_der(Crt, Cert, CertSize);

    if (Ret != 0) {
      break;
    }
  }
  return Ret == 0;
}

/**
  Construct a X509 stack object from a list of DER-encoded certificate data.

  If X509Stack is NULL, then return FALSE.

  @param[in, out]  X509Stack  On input, pointer to an existing or NULL X509 stack object.
                              On output, pointer to the X509 stack object with new
                              inserted X509 certificate.
  @param           ...        A list of DER-encoded single certificate data followed
                              by certificate size. A NULL terminates the list. The
                              pairs are the arguments to X509ConstructCertificate().

  @retval     TRUE            The X509 stack construction succeeded.
  @retval     FALSE           The construction operation failed.

**/
BOOLEAN
EFIAPI
X509ConstructCertificateStack (
  IN OUT  UINT8  **X509Stack,
  ...
  )
{
  VA_LIST  Args;
  BOOLEAN  Result;

  VA_START (Args, X509Stack);
  Result = X509ConstructCertificateStackV (X509Stack, Args);
  VA_END (Args);
  return Result;
}

/**
  Release the specified X509 object.

  If X509Cert is NULL, then return FALSE.

  @param[in]  X509Cert  Pointer to the X509 object to be released.

**/
VOID
EFIAPI
X509Free (
  IN  VOID  *X509Cert
  )
{
  if (X509Cert) {
    mbedtls_x509_crt_free(X509Cert);
    FreePool(X509Cert);
  }
}

/**
  Release the specified X509 stack object.

  If X509Stack is NULL, then return FALSE.

  @param[in]  X509Stack  Pointer to the X509 stack object to be released.

**/
VOID
EFIAPI
X509StackFree (
  IN  VOID  *X509Stack
  )
{
}

/**
  Retrieve the subject bytes from one X.509 certificate.

  @param[in]      Cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize     Size of the X509 certificate in bytes.
  @param[out]     CertSubject  Pointer to the retrieved certificate subject bytes.
  @param[in, out] SubjectSize  The size in bytes of the CertSubject buffer on input,
                               and the size of buffer returned CertSubject on output.

  If Cert is NULL, then return FALSE.
  If SubjectSize is NULL, then return FALSE.

  @retval  TRUE   The certificate subject retrieved successfully.
  @retval  FALSE  Invalid certificate, or the SubjectSize is too small for the result.
                  The SubjectSize will be updated with the required size.

**/
BOOLEAN
EFIAPI
X509GetSubjectName (
  IN      CONST UINT8  *Cert,
  IN      UINTN        CertSize,
  OUT     UINT8        *CertSubject,
  IN OUT  UINTN        *SubjectSize
  )
{
  return FALSE;
}

/**
  Retrieve the common name (CN) string from one X.509 certificate.

  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[out]     CommonName       Buffer to contain the retrieved certificate common
                                   name string. At most CommonNameSize bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  CommonNameSize   The size in bytes of the CommonName buffer on input,
                                   and the size of buffer returned CommonName on output.
                                   If CommonName is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate CommonName retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If CommonNameSize is NULL.
                                   If CommonName is not NULL and *CommonNameSize is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no CommonName entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the CommonName is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   CommonNameSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
RETURN_STATUS
EFIAPI
X509GetCommonName (
  IN      CONST UINT8  *Cert,
  IN      UINTN        CertSize,
  OUT     CHAR8        *CommonName,  OPTIONAL
  IN OUT  UINTN        *CommonNameSize
  )
{
  return RETURN_UNSUPPORTED;
}

/**
  Retrieve the organization name (O) string from one X.509 certificate.

  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[out]     NameBuffer       Buffer to contain the retrieved certificate organization
                                   name string. At most NameBufferSize bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  NameBufferSize   The size in bytes of the Name buffer on input,
                                   and the size of buffer returned Name on output.
                                   If NameBuffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate Organization Name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If NameBufferSize is NULL.
                                   If NameBuffer is not NULL and *CommonNameSize is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no Organization Name entry exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the NameBuffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   CommonNameSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
RETURN_STATUS
EFIAPI
X509GetOrganizationName (
  IN      CONST UINT8   *Cert,
  IN      UINTN         CertSize,
  OUT     CHAR8         *NameBuffer,  OPTIONAL
  IN OUT  UINTN         *NameBufferSize
  )
{
  return RETURN_UNSUPPORTED;
}

/**
  Retrieve the RSA Public Key from one DER-encoded X509 certificate.

  @param[in]  Cert         Pointer to the DER-encoded X509 certificate.
  @param[in]  CertSize     Size of the X509 certificate in bytes.
  @param[out] RsaContext   Pointer to new-generated RSA context which contain the retrieved
                           RSA public key component. Use RsaFree() function to free the
                           resource.

  If Cert is NULL, then return FALSE.
  If RsaContext is NULL, then return FALSE.

  @retval  TRUE   RSA Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve RSA public key from X509 certificate.

**/
BOOLEAN
EFIAPI
RsaGetPublicKeyFromX509 (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize,
  OUT  VOID         **RsaContext
  )
{
  mbedtls_x509_crt    crt;
  mbedtls_rsa_context *rsa;
  INT32               Ret;

  mbedtls_x509_crt_init (&crt);

  if (mbedtls_x509_crt_parse_der (&crt, Cert, CertSize) != 0) {
    return FALSE;
  }

  if (mbedtls_pk_get_type (&crt.pk) != MBEDTLS_PK_RSA) {
    mbedtls_x509_crt_free (&crt);
    return FALSE;
  }

  rsa = RsaNew ();
  if (rsa == NULL) {
    mbedtls_x509_crt_free (&crt);
    return FALSE;
  }
  Ret = mbedtls_rsa_copy (rsa, mbedtls_pk_rsa (crt.pk));
  if (Ret != 0) {
      RsaFree (rsa);
      mbedtls_x509_crt_free (&crt);
      return FALSE;
  }
  mbedtls_x509_crt_free (&crt);

  *RsaContext = rsa;
  return TRUE;
}

/**
  Retrieve the EC Public Key from one DER-encoded X509 certificate.

  @param[in]  Cert         Pointer to the DER-encoded X509 certificate.
  @param[in]  CertSize     Size of the X509 certificate in bytes.
  @param[out] EcContext    Pointer to new-generated EC context which contain the retrieved
                           EC public key component. Use EcFree() function to free the
                           resource.

  If Cert is NULL, then return FALSE.
  If EcContext is NULL, then return FALSE.

  @retval  TRUE   EC Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve EC public key from X509 certificate.

**/
BOOLEAN
EFIAPI
EcGetPublicKeyFromX509 (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize,
  OUT  VOID         **EcDsaContext
  )
{
  mbedtls_x509_crt       crt;
  mbedtls_ecdsa_context* ecdsa;
  INT32                  Ret;

  mbedtls_x509_crt_init(&crt);

  if (mbedtls_x509_crt_parse_der(&crt, Cert, CertSize) != 0) {
    return FALSE;
  }

  if (mbedtls_pk_get_type(&crt.pk) != MBEDTLS_PK_ECKEY) {
    mbedtls_x509_crt_free(&crt);
    return FALSE;
  }

  ecdsa = AllocateZeroPool(sizeof(mbedtls_ecdsa_context));
  if (ecdsa == NULL) {
    mbedtls_x509_crt_free(&crt);
    return FALSE;
  }
  mbedtls_ecdsa_init(ecdsa);

  Ret = mbedtls_ecdsa_from_keypair (ecdsa, mbedtls_pk_ec(crt.pk));
  if (Ret != 0) {
    mbedtls_ecdsa_free(ecdsa);
    FreePool(ecdsa);
    mbedtls_x509_crt_free(&crt);
    return FALSE;
  }
  mbedtls_x509_crt_free(&crt);

  *EcDsaContext = ecdsa;
  return TRUE;
}

/**
  Verify one X509 certificate was issued by the trusted CA.

  @param[in]      Cert         Pointer to the DER-encoded X509 certificate to be verified.
  @param[in]      CertSize     Size of the X509 certificate in bytes.
  @param[in]      CACert       Pointer to the DER-encoded trusted CA certificate.
  @param[in]      CACertSize   Size of the CA Certificate in bytes.

  If Cert is NULL, then return FALSE.
  If CACert is NULL, then return FALSE.

  @retval  TRUE   The certificate was issued by the trusted CA.
  @retval  FALSE  Invalid certificate or the certificate was not issued by the given
                  trusted CA.

**/
BOOLEAN
EFIAPI
X509VerifyCert (
  IN  CONST UINT8  *Cert,
  IN  UINTN        CertSize,
  IN  CONST UINT8  *CACert,
  IN  UINTN        CACertSize
  )
{
  INT32 Ret;
  mbedtls_x509_crt Ca, End;
  UINT32  VFlag = 0;
  mbedtls_x509_crt_profile Profile = {0};

  if (Cert == NULL || CACert == NULL) {
    return FALSE;
  }

  CopyMem(&Profile, &mbedtls_x509_crt_profile_default, sizeof(mbedtls_x509_crt_profile));

  mbedtls_x509_crt_init(&Ca);
  mbedtls_x509_crt_init(&End);

  Ret = mbedtls_x509_crt_parse_der(&Ca, CACert, CACertSize);

  if (Ret == 0) {
    Ret = mbedtls_x509_crt_parse_der(&End, Cert, CertSize);
  }

  if (Ret == 0) {
    Ret = mbedtls_x509_crt_verify_with_profile(&End, &Ca, NULL, &Profile, NULL, &VFlag, NULL, NULL);
  }

  mbedtls_x509_crt_free(&Ca);
  mbedtls_x509_crt_free(&End);

  return Ret == 0;
}

/**
  Verify one X509 certificate was issued by the trusted CA.

  @param[in]      CertChain         One or more ASN.1 DER-encoded X.509 certificates
                                    where the first certificate is signed by the Root
                                    Certificate or is the Root Cerificate itself. and
                                    subsequent cerificate is signed by the preceding
                                    cerificate.
  @param[in]      CertChainLength   Total length of the certificate chain, in bytes.

  @param[in]      RootCert          Trusted Root Certificate buffer

  @param[in]      RootCertLength    Trusted Root Certificate buffer length

  @retval  TRUE   All cerificates was issued by the first certificate in X509Certchain.
  @retval  FALSE  Invalid certificate or the certificate was not issued by the given
                  trusted CA.
**/
BOOLEAN
EFIAPI
X509VerifyCertChain (
  IN UINT8 *  RootCert,
  IN UINTN    RootCertLength,
  IN UINT8 *  CertChain,
  IN UINTN    CertChainLength
  )
{
  UINTN   Asn1Len;
  UINTN   PrecedingCertLen;
  UINT8   *PrecedingCert;
  UINTN   CurrentCertLen;
  UINT8   *CurrentCert;
  UINT8   *TmpPtr;
  UINT32  Ret;
  BOOLEAN VerifyFlag;

  VerifyFlag = FALSE;
  PrecedingCert = RootCert;
  PrecedingCertLen = RootCertLength;

  CurrentCert = CertChain;

  //
  // Get Current certificate from Certificates buffer and Verify with preciding cert
  //
  do {
    TmpPtr = CurrentCert;
    Ret = mbedtls_asn1_get_tag (&TmpPtr, CertChain + CertChainLength, &Asn1Len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (Ret != 0) {
      break;
    }

    CurrentCertLen = Asn1Len + (TmpPtr - CurrentCert);

    if (X509VerifyCert (CurrentCert, CurrentCertLen, PrecedingCert, PrecedingCertLen) == FALSE) {
      VerifyFlag = FALSE;
      break;
    } else {
      VerifyFlag = TRUE;
    }

    //
    // Save preceding certificate
    //
    PrecedingCert = CurrentCert;
    PrecedingCertLen = CurrentCertLen;

    //
    // Move current certificate to next;
    //
    CurrentCert = CurrentCert + CurrentCertLen;
  } while (1);

  return VerifyFlag;
}


/**
  Get one X509 certificate from CertChain.

  @param[in]      CertChain         One or more ASN.1 DER-encoded X.509 certificates
                                    where the first certificate is signed by the Root
                                    Certificate or is the Root Cerificate itself. and
                                    subsequent cerificate is signed by the preceding
                                    cerificate.
  @param[in]      CertChainLength   Total length of the certificate chain, in bytes.

  @param[in]      CertIndex         Index of certificate.

  @param[out]     Cert              The certificate at the index of CertChain.
  @param[out]     CertLength        The length certificate at the index of CertChain.

  @retval  TRUE   Success.
  @retval  FALSE  Failed to get certificate from certificate chain.
**/
BOOLEAN
EFIAPI
X509GetCertFromCertChain (
  IN UINT8  *CertChain,
  IN UINTN  CertChainLength,
  IN INT32  CertIndex,
  OUT UINT8 **Cert,
  OUT UINTN *CertLength)
{

  UINTN Asn1Len;
  INT32 CurrentIndex;
  UINTN CurrentCertLen;
  UINT8 *CurrentCert;
  UINT8 *TmpPtr;
  INT32 Ret;

  //
  // Check input parameters.
  //
  if ((CertChain == NULL) || (Cert == NULL) ||
      (CertIndex < -1) || (CertLength == NULL)) {
    return FALSE;
  }

  CurrentCert = CertChain;
  CurrentIndex = -1;

  //
  // Traverse the certificate chain
  //
  while (TRUE) {
    //
    // Get asn1 tag len
    //
    TmpPtr = CurrentCert;
    Ret = mbedtls_asn1_get_tag (&TmpPtr, CertChain + CertChainLength, &Asn1Len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (Ret != 0) {
      break;
    }

    CurrentCertLen = Asn1Len + (TmpPtr - CurrentCert);
    CurrentIndex ++;

    if (CurrentIndex == CertIndex) {
      *Cert = CurrentCert;
      *CertLength = CurrentCertLen;
      return TRUE;
    }

    //
    // Move to next
    //
    CurrentCert = CurrentCert + CurrentCertLen;
  }

  //
  // If CertIndex is -1, Return the last certificate
  //
  if (CertIndex == -1 && CurrentIndex >= 0) {
    *Cert = CurrentCert - CurrentCertLen;
    *CertLength = CurrentCertLen;
    return TRUE;
  }

  return FALSE;
}


/**
  Retrieve the TBSCertificate from one given X.509 certificate.

  @param[in]      Cert         Pointer to the given DER-encoded X509 certificate.
  @param[in]      CertSize     Size of the X509 certificate in bytes.
  @param[out]     TBSCert      DER-Encoded To-Be-Signed certificate.
  @param[out]     TBSCertSize  Size of the TBS certificate in bytes.

  If Cert is NULL, then return FALSE.
  If TBSCert is NULL, then return FALSE.
  If TBSCertSize is NULL, then return FALSE.

  @retval  TRUE   The TBSCertificate was retrieved successfully.
  @retval  FALSE  Invalid X.509 certificate.

**/
BOOLEAN
EFIAPI
X509GetTBSCert (
  IN  CONST UINT8  *Cert,
  IN  UINTN        CertSize,
  OUT UINT8        **TBSCert,
  OUT UINTN        *TBSCertSize
  )
{
  return FALSE;
}
