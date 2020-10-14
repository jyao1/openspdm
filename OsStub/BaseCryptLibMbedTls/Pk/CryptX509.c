/** @file
  X.509 Certificate Handler Wrapper Implementation over OpenSSL.

Copyright (c) 2010 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>

///
/// OID
///
STATIC CONST UINT8 OID_commonName[] = {
  0x55, 0x04, 0x03
};
STATIC CONST UINT8 OID_organizationName[] = {
  0x55, 0x04, 0x0A
};
STATIC CONST UINT8 OID_extKeyUsage[] = {
  0x55, 0x1D, 0x25
};

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
  mbedtls_x509_crt  *MbedTlsCert;
  INT32            Ret;

  if (Cert == NULL || SingleX509Cert == NULL || CertSize == 0) {
    return FALSE;
  }

  MbedTlsCert = AllocatePool (sizeof(mbedtls_x509_crt));
  if (MbedTlsCert == NULL) {
    return FALSE;
  }

  mbedtls_x509_crt_init(MbedTlsCert);

  *SingleX509Cert = (UINT8 *)(VOID *)MbedTlsCert;
  Ret = mbedtls_x509_crt_parse_der(MbedTlsCert, Cert, CertSize);

  return Ret == 0;
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
  if (X509Stack == NULL) {
    return ;
  }

  mbedtls_x509_crt_free(X509Stack);
}

/**
  Retrieve the tag and length of the tag.

  @param p     The position in the ASN.1 data
  @param end   End of data
  @param len   The variable that will receive the length
  @param tag   The expected tag

  @retval      TRUE   Get tag successful
  @retval      FALSe  Failed to get tag or tag not match
**/
BOOLEAN
EFIAPI
Asn1GetTag (
  UINT8 **Ptr,
  UINT8 *End,
  UINTN *Length,
  int   Tag
  )
{
  if (mbedtls_asn1_get_tag (Ptr, End, Length, Tag) == 0) {
    return TRUE;
  } else {
    return FALSE;
  }
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
  mbedtls_x509_crt Crt;
  INT32 Ret;
  if (Cert == NULL) {
    return FALSE;
  }


  mbedtls_x509_crt_init(&Crt);

  Ret = mbedtls_x509_crt_parse_der(&Crt, Cert, CertSize);

  if (Ret == 0) {
    if (CertSubject != NULL) {
      CopyMem(CertSubject, Crt.subject_raw.p, Crt.subject_raw.len);
    }
    *SubjectSize = Crt.subject_raw.len;
  }
  mbedtls_x509_crt_free(&Crt);

  return Ret == 0;
}

RETURN_STATUS
EFIAPI
InternalX509GetNIDName (
  IN      mbedtls_x509_name     *Name,
  IN      UINT8         *Oid,
  IN      UINTN         OidSize,
  IN OUT  CHAR8         *CommonName,  OPTIONAL
  IN OUT  UINTN         *CommonNameSize)
{
  mbedtls_asn1_named_data *data;
  data = mbedtls_asn1_find_named_data(Name, Oid, OidSize);
  if (data != NULL) {

    if (*CommonNameSize <= data->val.len) {
      *CommonNameSize = data->val.len + 1;
      return RETURN_BUFFER_TOO_SMALL;
    }
    if (CommonName != NULL) {
      CopyMem(CommonName, data->val.p, data->val.len);
      CommonName[data->val.len] = '\0';
    }
    *CommonNameSize = data->val.len + 1;
    return RETURN_SUCCESS;
  } else {
    return RETURN_NOT_FOUND;
  }
}

RETURN_STATUS
EFIAPI
InternalX509GetSubjectNIDName (
  IN      CONST UINT8   *Cert,
  IN      UINTN         CertSize,
  IN      UINT8         *Oid,
  IN      UINTN         OidSize,
  OUT     CHAR8         *CommonName,  OPTIONAL
  IN OUT  UINTN         *CommonNameSize
  )
{
  mbedtls_x509_crt Crt;
  INT32 Ret;
  mbedtls_x509_name *Name;
  RETURN_STATUS ReturnStatus;

  if (Cert == NULL) {
    return FALSE;
  }

  ReturnStatus = RETURN_INVALID_PARAMETER;

  mbedtls_x509_crt_init(&Crt);

  Ret = mbedtls_x509_crt_parse_der(&Crt, Cert, CertSize);

  if (Ret == 0) {
    Name = &(Crt.subject);
    ReturnStatus = InternalX509GetNIDName(Name, Oid, OidSize, CommonName, CommonNameSize);
  }

  mbedtls_x509_crt_free(&Crt);

  return ReturnStatus;
}

RETURN_STATUS
EFIAPI
InternalX509GetIssuerNIDName (
  IN      CONST UINT8   *Cert,
  IN      UINTN         CertSize,
  IN      UINT8         *Oid,
  IN      UINTN         OidSize,
  OUT     CHAR8         *CommonName,  OPTIONAL
  IN OUT  UINTN         *CommonNameSize
  )
{
  mbedtls_x509_crt Crt;
  INT32 Ret;
  mbedtls_x509_name *Name;
  RETURN_STATUS ReturnStatus;

  if (Cert == NULL) {
    return FALSE;
  }

  ReturnStatus = RETURN_INVALID_PARAMETER;

  mbedtls_x509_crt_init(&Crt);

  Ret = mbedtls_x509_crt_parse_der(&Crt, Cert, CertSize);

  if (Ret == 0) {
    Name = &(Crt.issuer);
    ReturnStatus = InternalX509GetNIDName(Name, Oid, OidSize, CommonName, CommonNameSize);
  }

  mbedtls_x509_crt_free(&Crt);

  return ReturnStatus;
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
  return InternalX509GetSubjectNIDName (Cert, CertSize, (UINT8 *)OID_commonName, sizeof (OID_commonName), CommonName, CommonNameSize);
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
  return InternalX509GetSubjectNIDName (Cert, CertSize, (UINT8 *)OID_organizationName, sizeof (OID_organizationName), NameBuffer, NameBufferSize);
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
  @param[out] EcContext    Pointer to new-generated EC DSA context which contain the retrieved
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
  OUT  VOID         **EcContext
  )
{
  mbedtls_x509_crt       crt;
  mbedtls_ecdh_context   *ecdh;
  INT32                  Ret;

  mbedtls_x509_crt_init(&crt);

  if (mbedtls_x509_crt_parse_der(&crt, Cert, CertSize) != 0) {
    return FALSE;
  }

  if (mbedtls_pk_get_type(&crt.pk) != MBEDTLS_PK_ECKEY) {
    mbedtls_x509_crt_free(&crt);
    return FALSE;
  }

  ecdh = AllocateZeroPool(sizeof(mbedtls_ecdh_context));
  if (ecdh == NULL) {
    mbedtls_x509_crt_free(&crt);
    return FALSE;
  }
  mbedtls_ecdh_init(ecdh);

  Ret = mbedtls_ecdh_get_params (ecdh, mbedtls_pk_ec(crt.pk), MBEDTLS_ECDH_OURS);
  if (Ret != 0) {
    mbedtls_ecdh_free(ecdh);
    FreePool(ecdh);
    mbedtls_x509_crt_free(&crt);
    return FALSE;
  }
  mbedtls_x509_crt_free(&crt);

  *EcContext = ecdh;
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


/**
  Retrieve the version from one X.509 certificate.

  If Cert is NULL, then return FALSE.
  If CertSize is 0, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      Cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize     Size of the X509 certificate in bytes.
  @param[out]     Version      Pointer to the retrieved version integer.

  @retval RETURN_SUCCESS           The certificate version retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If  Cert is NULL or CertSize is Zero.
  @retval RETURN_UNSUPPORTED       The operation is not supported.

**/
RETURN_STATUS
EFIAPI
X509GetVersion (
  IN      CONST UINT8   *Cert,
  IN      UINTN         CertSize,
  OUT     UINTN          *Version
  )
{
  mbedtls_x509_crt Crt;
  INT32 Ret;
  RETURN_STATUS ReturnStatus;

  if (Cert == NULL) {
    return FALSE;
  }

  ReturnStatus = RETURN_INVALID_PARAMETER;

  mbedtls_x509_crt_init(&Crt);

  Ret = mbedtls_x509_crt_parse_der(&Crt, Cert, CertSize);

  if (Ret == 0) {
    *Version = Crt.version - 1;
    ReturnStatus = RETURN_SUCCESS;
  }

  mbedtls_x509_crt_free(&Crt);

  return ReturnStatus;
}

/**
  Retrieve the serialNumber from one X.509 certificate.

  If Cert is NULL, then return FALSE.
  If CertSize is 0, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      Cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize     Size of the X509 certificate in bytes.
  @param[out]     SerialNumber  Pointer to the retrieved certificate SerialNumber bytes.
  @param[in, out] SerialNumberSize  The size in bytes of the SerialNumber buffer on input,
                               and the size of buffer returned SerialNumber on output.

  @retval RETURN_SUCCESS           The certificate serialNumber retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL or CertSize is Zero.
                                   If SerialNumberSize is NULL.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SerialNumber exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the SerialNumber is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   SerialNumberSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
RETURN_STATUS
EFIAPI
X509GetSerialNumber (
  IN      CONST UINT8   *Cert,
  IN      UINTN         CertSize,
  OUT     UINT8         *SerialNumber,  OPTIONAL
  IN OUT  UINTN         *SerialNumberSize
  )
{
  mbedtls_x509_crt Crt;
  INT32 Ret;
  RETURN_STATUS ReturnStatus;

  if (Cert == NULL) {
    return FALSE;
  }

  ReturnStatus = RETURN_INVALID_PARAMETER;

  mbedtls_x509_crt_init(&Crt);

  Ret = mbedtls_x509_crt_parse_der(&Crt, Cert, CertSize);

  if (Ret == 0) {
    if (*SerialNumberSize <= Crt.serial.len) {
      *SerialNumberSize = Crt.serial.len + 1;
      ReturnStatus = RETURN_BUFFER_TOO_SMALL;
      goto Cleanup;
    }
    if (SerialNumber != NULL) {
      CopyMem(SerialNumber, Crt.serial.p, Crt.serial.len);
      SerialNumber[Crt.serial.len] = '\0';
    }
    *SerialNumberSize = Crt.serial.len + 1;
    ReturnStatus = RETURN_SUCCESS;
  }
Cleanup:
  mbedtls_x509_crt_free(&Crt);

  return ReturnStatus;
}

/**
  Retrieve the issuer bytes from one X.509 certificate.

  If Cert is NULL, then return FALSE.
  If CertIssuerSize is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      Cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize     Size of the X509 certificate in bytes.
  @param[out]     CertIssuer  Pointer to the retrieved certificate subject bytes.
  @param[in, out] CertIssuerSize  The size in bytes of the CertIssuer buffer on input,
                               and the size of buffer returned CertSubject on output.

  @retval  TRUE   The certificate issuer retrieved successfully.
  @retval  FALSE  Invalid certificate, or the CertIssuerSize is too small for the result.
                  The CertIssuerSize will be updated with the required size.
  @retval  FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
X509GetIssuerName (
  IN      CONST UINT8  *Cert,
  IN      UINTN        CertSize,
  OUT     UINT8        *CertIssuer,
  IN OUT  UINTN        *CertIssuerSize
  )
{
  mbedtls_x509_crt Crt;
  INT32 Ret;
  BOOLEAN Status;

  if (Cert == NULL) {
    return FALSE;
  }

  Status = FALSE;

  mbedtls_x509_crt_init(&Crt);

  Ret = mbedtls_x509_crt_parse_der(&Crt, Cert, CertSize);

  if (Ret == 0) {
    if (*CertIssuerSize < Crt.serial.len) {
      *CertIssuerSize = Crt.serial.len;
      Status = FALSE;
      goto Cleanup;
    }
    if (CertIssuer != NULL) {
      CopyMem(CertIssuer, Crt.serial.p, Crt.serial.len);
    }
    *CertIssuerSize = Crt.serial.len;
    Status = TRUE;
  }

Cleanup:
  mbedtls_x509_crt_free(&Crt);

  return Status;
}

/**
  Retrieve the issuer common name (CN) string from one X.509 certificate.

  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[out]     CommonName       Buffer to contain the retrieved certificate issuer common
                                   name string. At most CommonNameSize bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  CommonNameSize   The size in bytes of the CommonName buffer on input,
                                   and the size of buffer returned CommonName on output.
                                   If CommonName is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate Issuer CommonName retrieved successfully.
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
X509GetIssuerCommonName (
  IN      CONST UINT8  *Cert,
  IN      UINTN        CertSize,
  OUT     CHAR8        *CommonName,  OPTIONAL
  IN OUT  UINTN        *CommonNameSize
  )
{
  return InternalX509GetIssuerNIDName (Cert, CertSize, (UINT8 *)OID_commonName, sizeof (OID_commonName), CommonName, CommonNameSize);
}

/**
  Retrieve the issuer organization name (O) string from one X.509 certificate.

  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[out]     NameBuffer       Buffer to contain the retrieved certificate issuer organization
                                   name string. At most NameBufferSize bytes will be
                                   written and the string will be null terminated. May be
                                   NULL in order to determine the size buffer needed.
  @param[in,out]  NameBufferSize   The size in bytes of the Name buffer on input,
                                   and the size of buffer returned Name on output.
                                   If NameBuffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.

  @retval RETURN_SUCCESS           The certificate issuer Organization Name retrieved successfully.
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
X509GetIssuerOrganizationName (
  IN      CONST UINT8   *Cert,
  IN      UINTN         CertSize,
  OUT     CHAR8         *NameBuffer,  OPTIONAL
  IN OUT  UINTN         *NameBufferSize
  )
{
return InternalX509GetIssuerNIDName (Cert, CertSize, (UINT8 *)OID_organizationName, sizeof (OID_organizationName), NameBuffer, NameBufferSize);
}

/**
  Retrieve the Signature Algorithm from one X.509 certificate.

  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[out]     Oid              Signature Algorithm Object identifier buffer.
  @param[in,out]  OidSize          Signature Algorithm Object identifier buffer size

  @retval RETURN_SUCCESS           The certificate Extension data retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If OidSize is NULL.
                                   If Oid is not NULL and *OidSize is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SignatureType.
  @retval RETURN_BUFFER_TOO_SMALL  If the Oid is NULL. The required buffer size
                                   is returned in the OidSize.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
RETURN_STATUS
EFIAPI
X509GetSignatureAlgorithm (
  IN CONST UINT8      *Cert,
  IN      UINTN       CertSize,
  OUT     UINT8       *Oid,  OPTIONAL
  IN OUT  UINTN       *OidSize
  )
{
  mbedtls_x509_crt    Crt;
  INT32               Ret;
  RETURN_STATUS       ReturnStatus;

  if (Cert == NULL || CertSize == 0 || OidSize == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  ReturnStatus = RETURN_INVALID_PARAMETER;

  mbedtls_x509_crt_init(&Crt);

  Ret = mbedtls_x509_crt_parse_der(&Crt, Cert, CertSize);

  if (Ret == 0) {
    if (*OidSize < Crt.sig_oid.len) {
      *OidSize = Crt.serial.len;
      ReturnStatus = RETURN_BUFFER_TOO_SMALL;
      goto Cleanup;
    }
    if (Oid != NULL) {
      CopyMem(Oid, Crt.sig_oid.p, Crt.sig_oid.len);
    }
    *OidSize = Crt.sig_oid.len;
    ReturnStatus = RETURN_SUCCESS;
  }

Cleanup:
  mbedtls_x509_crt_free(&Crt);

  return ReturnStatus;
}


/**
 Find first Extension data match with given OID

  @param[in]      Start             Pointer to the DER-encoded Extensions Data
  @param[in]      End               Extensions Data size in bytes
  @param[in ]     Oid               OID for match
  @param[in ]     OidSize           OID size in bytes
  @param[out]     FindExtensionData output matched extension data.
  @param[out]     FindExtensionDataLen matched extension data size.

 **/
STATIC
RETURN_STATUS
InternalX509FindExtensionData (
  UINT8 *Start,
  UINT8 *End,
  UINT8 *Oid,
  UINTN OidSize,
  UINT8 **FindExtensionData,
  UINTN *FindExtensionDataLen
  )
{
  UINT8   *Ptr;
  UINT8   *ExtensionPtr;
  size_t  ObjLen;
  INT32   Ret;
  RETURN_STATUS ReturnStatus;
  size_t FindExtensionLen;
  size_t HeaderLen;

  ReturnStatus = RETURN_INVALID_PARAMETER;
  Ptr = Start;

  Ret = 0;

  while (TRUE) {
    /*
    * Extension  ::=  SEQUENCE  {
    *      extnID      OBJECT IDENTIFIER,
    *      critical    BOOLEAN DEFAULT FALSE,
    *      extnValue   OCTET STRING  }
    */
    ExtensionPtr = Ptr;
    Ret = mbedtls_asn1_get_tag(&Ptr, End, &ObjLen, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (Ret == 0) {
      HeaderLen = (size_t)(Ptr - ExtensionPtr);
      FindExtensionLen = ObjLen;
      // Get Object Identifier
      Ret = mbedtls_asn1_get_tag(&Ptr, End, &ObjLen, MBEDTLS_ASN1_OID);
    } else {
      break;
    }

    if (Ret == 0 && CompareMem(Ptr, Oid, OidSize) == 0) {
      Ptr += ObjLen;

      Ret = mbedtls_asn1_get_tag(&Ptr, End, &ObjLen, MBEDTLS_ASN1_BOOLEAN);
      if (Ret == 0) {
        Ptr += ObjLen;
      }

      Ret = mbedtls_asn1_get_tag(&Ptr, End, &ObjLen, MBEDTLS_ASN1_OCTET_STRING);
    } else {
      Ret = 1;
    }

    if (Ret == 0) {
      *FindExtensionData = Ptr;
      *FindExtensionDataLen = ObjLen;
      ReturnStatus = RETURN_SUCCESS;
      break;
    }

    // move to next
    Ptr = ExtensionPtr + HeaderLen + FindExtensionLen;
    Ret = 0;
  }

  return ReturnStatus;
}

/**
  Retrieve Extension data from one X.509 certificate.

  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[in]      Oid              Object identifier buffer
  @param[in]      OidSize          Object identifier buffer size
  @param[out]     ExtensionData    Extension bytes.
  @param[in, out] ExtensionDataSize Extension bytes size.

  @retval RETURN_SUCCESS           The certificate Extension data retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If ExtensionDataSize is NULL.
                                   If ExtensionData is not NULL and *ExtensionDataSize is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no Extension entry match Oid.
  @retval RETURN_BUFFER_TOO_SMALL  If the ExtensionData is NULL. The required buffer size
                                   is returned in the ExtensionDataSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
RETURN_STATUS
EFIAPI
X509GetExtensionData (
  IN    CONST UINT8 *Cert,
  IN    UINTN       CertSize,
  IN    UINT8       *Oid,
  IN    UINTN       OidSize,
  OUT   UINT8       *ExtensionData,
  IN OUT UINTN      *ExtensionDataSize
  )
{
  mbedtls_x509_crt Crt;
  INT32 Ret;
  RETURN_STATUS ReturnStatus;
  UINT8         *Ptr;
  UINT8         *End;
  size_t        ObjLen;

  if (Cert == NULL ||
    CertSize == 0 ||
    Oid == NULL ||
    OidSize == 0 ||
    ExtensionDataSize == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  ReturnStatus = RETURN_INVALID_PARAMETER;

  mbedtls_x509_crt_init(&Crt);

  Ret = mbedtls_x509_crt_parse_der(&Crt, Cert, CertSize);

  if (Ret == 0) {
    Ptr = Crt.v3_ext.p;
    End = Crt.v3_ext.p + Crt.v3_ext.len;
    Ret = mbedtls_asn1_get_tag(&Ptr, End, &ObjLen, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  }

  if (Ret == 0) {
      ReturnStatus = InternalX509FindExtensionData(Ptr, End, Oid, OidSize, &Ptr, &ObjLen);
  }

  if (ReturnStatus == RETURN_SUCCESS) {
    if (*ExtensionDataSize < ObjLen) {
      *ExtensionDataSize = ObjLen;
      ReturnStatus = RETURN_BUFFER_TOO_SMALL;
      goto Cleanup;
    }
    if (Oid != NULL) {
      CopyMem(ExtensionData, Ptr, ObjLen);
    }
    *ExtensionDataSize = ObjLen;
    ReturnStatus = RETURN_SUCCESS;
  }

Cleanup:
  mbedtls_x509_crt_free(&Crt);

  return ReturnStatus;
}

/**
  Retrieve the Validity from one X.509 certificate

  If Cert is NULL, then return FALSE.
  If CertIssuerSize is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      Cert         Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize     Size of the X509 certificate in bytes.
  @param[out]     From         notBefore Pointer to DateTime object.
  @param[in,out]  FromSize     notBefore DateTime object size.
  @param[out]     To           notAfter Pointer to DateTime object.
  @param[in,out]  ToSize       notAfter DateTime object size.

  Note: X509CompareDateTime to compare DateTime oject
        x509SetDateTime to get a DateTime object from a DateTimeStr

  @retval  TRUE   The certificate Validity retrieved successfully.
  @retval  FALSE  Invalid certificate, or Validity retrieve failed.
  @retval  FALSE  This interface is not supported.
**/
BOOLEAN
EFIAPI
X509GetValidity  (
  IN    CONST UINT8 *Cert,
  IN    UINTN       CertSize,
  IN    UINT8       *From,
  IN OUT UINTN      *FromSize,
  IN    UINT8       *To,
  IN OUT UINTN      *ToSize
  )
{
  mbedtls_x509_crt Crt;
  INT32      Ret;
  BOOLEAN    Status;
  UINTN      TSize;
  UINTN      FSize;

  if (Cert == NULL) {
    return FALSE;
  }

  Status = FALSE;

  mbedtls_x509_crt_init(&Crt);

  Ret = mbedtls_x509_crt_parse_der(&Crt, Cert, CertSize);

  if (Ret == 0) {

    FSize = sizeof (mbedtls_x509_time);
    if (*FromSize < FSize) {
      *FromSize = FSize;
      goto _Exit;
    }
    *FromSize = FSize;
    if (From != NULL) {
      CopyMem(From, &(Crt.valid_from), FSize);
    }

    TSize = sizeof (mbedtls_x509_time);
    if (*ToSize < TSize) {
      *ToSize = TSize;
      goto _Exit;
    }
    *ToSize = TSize;
    if (To != NULL) {
      CopyMem(To, &(Crt.valid_to), sizeof (mbedtls_x509_time));
    }
    Status = TRUE;
  }

_Exit:
  mbedtls_x509_crt_free(&Crt);

  return Status;
}

/**
  Retrieve the Key Usage from one X.509 certificate.

  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[out]     Usage            Key Usage

  @retval  TRUE   The certificate Extended Key Usage retrieved successfully.
  @retval  FALSE  Invalid certificate, or Usage is NULL
  @retval  FALSE  This interface is not supported.
**/
BOOLEAN
EFIAPI
X509GetKeyUsage (
  IN    CONST UINT8 *Cert,
  IN    UINTN        CertSize,
  OUT   UINTN        *Usage
  )
{
  mbedtls_x509_crt Crt;
  INT32         Ret;
  BOOLEAN       Status;

  if (Cert == NULL) {
    return FALSE;
  }

  Status = FALSE;

  mbedtls_x509_crt_init(&Crt);

  Ret = mbedtls_x509_crt_parse_der(&Crt, Cert, CertSize);

  if (Ret == 0) {
    *Usage = Crt.key_usage;
    Status = TRUE;
  }
  mbedtls_x509_crt_free(&Crt);

  return Status;
}

/**
  Retrieve the Extended Key Usage from one X.509 certificate.

  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[out]     Usage            Key Usage bytes.
  @param[in, out] UsageSize        Key Usage buffer sizs in bytes.

  @retval RETURN_SUCCESS           The Usage bytes retrieve successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If CertSize is NULL.
                                   If Usage is not NULL and *UsageSize is 0.
                                   If Cert is invalid.
  @retval RETURN_BUFFER_TOO_SMALL  If the Usage is NULL. The required buffer size
                                   is returned in the UsageSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
RETURN_STATUS
EFIAPI
X509GetExtendedKeyUsage (
  IN    CONST UINT8   *Cert,
  IN    UINTN         CertSize,
  OUT   UINT8         *Usage,
  OUT   UINTN         *UsageSize
  )
{
  RETURN_STATUS ReturnStatus;

  if (Cert == NULL || CertSize == 0 || UsageSize == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  ReturnStatus = X509GetExtensionData((UINT8 *)Cert, CertSize, (UINT8*)OID_extKeyUsage, sizeof (OID_extKeyUsage), Usage, UsageSize);

  return ReturnStatus;
}

/**
  Return 0 if before <= after, 1 otherwise
**/
STATIC
INTN
InternalX509CheckTime (
  CONST mbedtls_x509_time *Before,
  const mbedtls_x509_time *After
  )
{
  if( Before->year  > After->year )
    return( 1 );

  if( Before->year == After->year &&
    Before->mon   > After->mon )
    return( 1 );

  if( Before->year == After->year &&
    Before->mon  == After->mon  &&
    Before->day   > After->day )
    return( 1 );

  if( Before->year == After->year &&
    Before->mon  == After->mon  &&
    Before->day  == After->day  &&
    Before->hour  > After->hour )
    return( 1 );

  if( Before->year == After->year &&
    Before->mon  == After->mon  &&
    Before->day  == After->day  &&
    Before->hour == After->hour &&
    Before->min   > After->min  )
    return( 1 );

  if( Before->year == After->year &&
    Before->mon  == After->mon  &&
    Before->day  == After->day  &&
    Before->hour == After->hour &&
    Before->min  == After->min  &&
    Before->sec   > After->sec  )
    return( 1 );

  return( 0 );
}

STATIC
INT32
InternalAtoI(CHAR8 *PStart, CHAR8 *PEnd) {
  CHAR8 *P = PStart;
  INT32 K = 0;
  while (P < PEnd) {
    ///
    /// k = k * 2³ + k * 2¹ = k * 8 + k * 2 = k * 10
    ///
    K = (K << 3) + (K << 1) + (*P) - '0';
    P++;
  }
  return K;
}

/**
  Format a DateTime object into DataTime Buffer

  If DateTimeStr is NULL, then return FALSE.
  If DateTimeSize is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in]      DateTimeStr      DateTime string like YYYYMMDDhhmmssZ
                                   Ref: https://www.w3.org/TR/NOTE-datetime
                                   Z stand for UTC time
  @param[in,out]  DateTime         Pointer to a DateTime object.
  @param[in,out]  DateTimeSize     DateTime object buffer size.

  @retval RETURN_SUCCESS           The DateTime object create successfully.
  @retval RETURN_INVALID_PARAMETER If DateTimeStr is NULL.
                                   If DateTimeSize is NULL.
                                   If DateTime is not NULL and *DateTimeSize is 0.
                                   If Year Month Day Hour Minute Second combination is invalid datetime.
  @retval RETURN_BUFFER_TOO_SMALL  If the DateTime is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   DateTimeSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
RETURN_STATUS
EFIAPI
X509SetDateTime (
  CHAR8         *DateTimeStr,
  IN OUT VOID   *DateTime,
  IN OUT UINTN  *DateTimeSize
  )
{
  mbedtls_x509_time Dt;

  INT32 Year;
  INT32 Month;
  INT32 Day;
  INT32 Hour;
  INT32 Minute;
  INT32 Second;
  RETURN_STATUS ReturnStatus;
  CHAR8 *P;

  P = DateTimeStr;

  Year = InternalAtoI(P, P + 4);
  P += 4;
  Month = InternalAtoI(P, P + 2);
  P += 2;
  Day = InternalAtoI(P, P + 2);
  P += 2;
  Hour = InternalAtoI(P, P + 2);
  P += 2;
  Minute = InternalAtoI(P, P + 2);
  P += 2;
  Second = InternalAtoI(P, P + 2);
  P += 2;
  Dt.year = (int)Year;
  Dt.mon = (int)Month;
  Dt.day = (int)Day;
  Dt.hour = (int)Hour;
  Dt.min = (int)Minute;
  Dt.sec = (int)Second;

  if (*DateTimeSize < sizeof (mbedtls_x509_time)) {
    *DateTimeSize = sizeof (mbedtls_x509_time);
    ReturnStatus = RETURN_BUFFER_TOO_SMALL;
    goto Cleanup;
  }
  if (DateTime != NULL) {
    CopyMem(DateTime, &Dt, sizeof (mbedtls_x509_time));
  }
  *DateTimeSize = sizeof (mbedtls_x509_time);
  ReturnStatus = RETURN_SUCCESS;
Cleanup:
  return ReturnStatus;
}

/**
  Compare DateTime1 object and DateTime2 object.

  If DateTime1 is NULL, then return -2.
  If DateTime2 is NULL, then return -2.
  If DateTime1 == DateTime2, then return 0
  If DateTime1 > DateTime2, then return 1
  If DateTime1 < DateTime2, then return -1

  @param[in]      DateTime1         Pointer to a DateTime Ojbect
  @param[in]      DateTime2         Pointer to a DateTime Object

  @retval  0      If DateTime1 == DateTime2
  @retval  1      If DateTime1 > DateTime2
  @retval  -1     If DateTime1 < DateTime2
**/
INTN
EFIAPI
X509CompareDateTime (
  IN    VOID   *DateTime1,
  IN    VOID   *DateTime2
  )
{
  if (DateTime1 == NULL || DateTime2 == NULL) {
    return -2;
  }
  if (CompareMem (DateTime2, DateTime1, sizeof (mbedtls_x509_time)) == 0) {
    return 0;
  }
  if(InternalX509CheckTime ((mbedtls_x509_time*)DateTime1, (mbedtls_x509_time*)DateTime2) == 0) {
    return -1;
  } else {
    return 1;
  }
}
