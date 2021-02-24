/** @file
  SPDM Crypto library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_CRYPTO_LIB_H__
#define __SPDM_CRYPTO_LIB_H__

#include "SpdmLibConfig.h"

#include <Base.h>
#include <IndustryStandard/Spdm.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>

#define MAX_DHE_KEY_SIZE    512
#define MAX_ASYM_KEY_SIZE   512
#define MAX_HASH_SIZE       64
#define MAX_AEAD_KEY_SIZE   32
#define MAX_AEAD_IV_SIZE    12

/**
  Computes the hash of a input data buffer.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
typedef
BOOLEAN
(EFIAPI *HASH_ALL) (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  );

/**
  Computes the HMAC of a input data buffer.

  This function performs the HMAC of a given data buffer, and return the hash value.

  @param  Data                         Pointer to the buffer containing the data to be HMACed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  Key                          Pointer to the user-supplied key.
  @param  KeySize                      Key size in bytes.
  @param  HashValue                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
typedef
BOOLEAN
(EFIAPI *HMAC_ALL) (
  IN   CONST VOID   *Data,
  IN   UINTN        DataSize,
  IN   CONST UINT8  *Key,
  IN   UINTN        KeySize,
  OUT  UINT8        *HmacValue
  );

/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand.

  @param  Prk                          Pointer to the user-supplied key.
  @param  PrkSize                      Key size in bytes.
  @param  Info                         Pointer to the application specific info.
  @param  InfoSize                     Info size in bytes.
  @param  Out                          Pointer to buffer to receive hkdf value.
  @param  OutSize                      Size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
typedef
BOOLEAN
(EFIAPI *HKDF_EXPAND) (
  IN   CONST UINT8  *Prk,
  IN   UINTN        PrkSize,
  IN   CONST UINT8  *Info,
  IN   UINTN        InfoSize,
  OUT  UINT8        *Out,
  IN   UINTN        OutSize
  );

/**
  Retrieve the asymmetric Public Key from one DER-encoded X509 certificate.

  @param  Cert                         Pointer to the DER-encoded X509 certificate.
  @param  CertSize                     Size of the X509 certificate in bytes.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
typedef
BOOLEAN
(EFIAPI *ASYM_GET_PUBLIC_KEY_FROM_X509) (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize,
  OUT  VOID         **Context
  );

/**
  Release the specified asymmetric context.

  @param  Context                      Pointer to the asymmetric context to be released.
**/
typedef
VOID
(EFIAPI *ASYM_FREE) (
  IN  VOID         *Context
  );

/**
  Verifies the asymmetric signature.

  @param  Context                      Pointer to asymmetric context for signature verification.
  @param  HashNid                      hash NID
  @param  Message                      Pointer to octet message to be checked (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to asymmetric signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
typedef
BOOLEAN
(EFIAPI *ASYM_VERIFY) (
  IN  VOID         *Context,
  IN  UINTN        HashNid,
  IN  CONST UINT8  *Message,
  IN  UINTN        MessageSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  );

/**
  Retrieve the Private Key from the password-protected PEM key data.

  @param  PemData                      Pointer to the PEM-encoded key data to be retrieved.
  @param  PemSize                      Size of the PEM key data in bytes.
  @param  Password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
typedef
BOOLEAN
(EFIAPI *ASYM_GET_PRIVATE_KEY_FROM_PEM) (
  IN   CONST UINT8  *PemData,
  IN   UINTN        PemSize,
  IN   CONST CHAR8  *Password,
  OUT  VOID         **Context
  );

/**
  Carries out the signature generation.

  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  @param  Context                      Pointer to asymmetric context for signature generation.
  @param  HashNid                      hash NID
  @param  Message                      Pointer to octet message to be signed (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to buffer to receive signature.
  @param  SigSize                      On input, the size of Signature buffer in bytes.
                                       On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.
**/
typedef
BOOLEAN
(EFIAPI *ASYM_SIGN) (
  IN      VOID         *Context,
  IN      UINTN        HashNid,
  IN      CONST UINT8  *Message,
  IN      UINTN        MessageSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) Context for subsequent use.

  @param Nid cipher NID

  @return  Pointer to the Diffie-Hellman Context that has been initialized.
**/
typedef
VOID *
(EFIAPI *DHE_NEW_BY_NID) (
  IN UINTN  Nid
  );

/**
  Generates DHE public key.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter PublicKey and PublicKeySize. DH context is updated accordingly.
  If the PublicKey buffer is too small to hold the public key, FALSE is returned and
  PublicKeySize is set to the required buffer size to obtain the public key.

  @param  Context                      Pointer to the DHE context.
  @param  PublicKey                    Pointer to the buffer to receive generated public key.
  @param  PublicKeySize                On input, the size of PublicKey buffer in bytes.
                                       On output, the size of data returned in PublicKey buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  PublicKeySize is not large enough.
**/
typedef
BOOLEAN
(EFIAPI *DHE_GENERATE_KEY) (
  IN OUT  VOID   *Context,
  OUT     UINT8  *PublicKey,
  IN OUT  UINTN  *PublicKeySize
  );

/**
  Computes exchanged common key.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  Context                      Pointer to the DHE context.
  @param  PeerPublicKey                Pointer to the peer's public key.
  @param  PeerPublicKeySize            Size of peer's public key in bytes.
  @param  Key                          Pointer to the buffer to receive generated key.
  @param  KeySize                      On input, the size of Key buffer in bytes.
                                       On output, the size of data returned in Key buffer in bytes.

  @retval TRUE   DHE exchanged key generation succeeded.
  @retval FALSE  DHE exchanged key generation failed.
  @retval FALSE  KeySize is not large enough.
**/
typedef
BOOLEAN
(EFIAPI *DHE_COMPUTE_KEY) (
  IN OUT  VOID         *Context,
  IN      CONST UINT8  *PeerPublic,
  IN      UINTN        PeerPublicSize,
  OUT     UINT8        *Key,
  IN OUT  UINTN        *KeySize
  );

/**
  Release the specified DHE context.

  @param  Context                      Pointer to the DHE context to be released.
**/
typedef
VOID
(EFIAPI *DHE_FREE) (
  IN  VOID  *Context
  );

/**
  Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD).

  @param  Key                          Pointer to the encryption key.
  @param  KeySize                      Size of the encryption key in bytes.
  @param  Iv                           Pointer to the IV value.
  @param  IvSize                       Size of the IV value in bytes.
  @param  AData                        Pointer to the additional authenticated data (AAD).
  @param  ADataSize                    Size of the additional authenticated data (AAD) in bytes.
  @param  DataIn                       Pointer to the input data buffer to be encrypted.
  @param  DataInSize                   Size of the input data buffer in bytes.
  @param  TagOut                       Pointer to a buffer that receives the authentication tag output.
  @param  TagSize                      Size of the authentication tag in bytes.
  @param  DataOut                      Pointer to a buffer that receives the encryption output.
  @param  DataOutSize                  Size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated encryption succeeded.
  @retval FALSE  AEAD authenticated encryption failed.
**/
typedef
BOOLEAN
(EFIAPI *AEAD_ENCRYPT) (
  IN   CONST UINT8* Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8* Iv,
  IN   UINTN        IvSize,
  IN   CONST UINT8* AData,
  IN   UINTN        ADataSize,
  IN   CONST UINT8* DataIn,
  IN   UINTN        DataInSize,
  OUT  UINT8*       TagOut,
  IN   UINTN        TagSize,
  OUT  UINT8*       DataOut,
  OUT  UINTN*       DataOutSize
  );

/**
  Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD).

  @param  Key                          Pointer to the encryption key.
  @param  KeySize                      Size of the encryption key in bytes.
  @param  Iv                           Pointer to the IV value.
  @param  IvSize                       Size of the IV value in bytes.
  @param  AData                        Pointer to the additional authenticated data (AAD).
  @param  ADataSize                    Size of the additional authenticated data (AAD) in bytes.
  @param  DataIn                       Pointer to the input data buffer to be decrypted.
  @param  DataInSize                   Size of the input data buffer in bytes.
  @param  Tag                          Pointer to a buffer that contains the authentication tag.
  @param  TagSize                      Size of the authentication tag in bytes.
  @param  DataOut                      Pointer to a buffer that receives the decryption output.
  @param  DataOutSize                  Size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated decryption succeeded.
  @retval FALSE  AEAD authenticated decryption failed.
**/
typedef
BOOLEAN
(EFIAPI *AEAD_DECRYPT) (
  IN   CONST UINT8* Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8* Iv,
  IN   UINTN        IvSize,
  IN   CONST UINT8* AData,
  IN   UINTN        ADataSize,
  IN   CONST UINT8* DataIn,
  IN   UINTN        DataInSize,
  IN   CONST UINT8* Tag,
  IN   UINTN        TagSize,
  OUT  UINT8*       DataOut,
  OUT  UINTN*       DataOutSize
  );

/**
  This function returns the SPDM hash algorithm size.

  @param  BaseHashAlgo                  SPDM BaseHashAlgo

  @return SPDM hash algorithm size.
**/
UINT32
EFIAPI
GetSpdmHashSize (
  IN      UINT32       BaseHashAlgo
  );

/**
  Computes the hash of a input data buffer, based upon the negotiated hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
BOOLEAN
EFIAPI
SpdmHashAll (
  IN   UINT32                       BaseHashAlgo,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  );

/**
  This function returns the SPDM measurement hash algorithm size.

  @param  MeasurementHashAlgo          SPDM MeasurementHashAlgo

  @return SPDM measurement hash algorithm size.
  @return 0xFFFFFFFF for RAW_BIT_STREAM_ONLY.
**/
UINT32
EFIAPI
GetSpdmMeasurementHashSize (
  IN   UINT32                       MeasurementHashAlgo
  );

/**
  Computes the hash of a input data buffer, based upon the negotiated measurement hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  MeasurementHashAlgo          SPDM MeasurementHashAlgo
  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
BOOLEAN
EFIAPI
SpdmMeasurementHashAll (
  IN   UINT32                       MeasurementHashAlgo,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  );

/**
  Computes the HMAC of a input data buffer, based upon the negotiated HMAC algorithm.

  This function performs the HMAC of a given data buffer, and return the hash value.

  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Data                         Pointer to the buffer containing the data to be HMACed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  Key                          Pointer to the user-supplied key.
  @param  KeySize                      Key size in bytes.
  @param  HashValue                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
BOOLEAN
EFIAPI
SpdmHmacAll (
  IN   UINT32                       BaseHashAlgo,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  IN   CONST UINT8                  *Key,
  IN   UINTN                        KeySize,
  OUT  UINT8                        *HmacValue
  );

/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Prk                          Pointer to the user-supplied key.
  @param  PrkSize                      Key size in bytes.
  @param  Info                         Pointer to the application specific info.
  @param  InfoSize                     Info size in bytes.
  @param  Out                          Pointer to buffer to receive hkdf value.
  @param  OutSize                      Size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
BOOLEAN
EFIAPI
SpdmHkdfExpand (
  IN   UINT32                       BaseHashAlgo,
  IN   CONST UINT8                  *Prk,
  IN   UINTN                        PrkSize,
  IN   CONST UINT8                  *Info,
  IN   UINTN                        InfoSize,
  OUT  UINT8                        *Out,
  IN   UINTN                        OutSize
  );

/**
  This function returns the SPDM asymmetric algorithm size.

  @param  BaseAsymAlgo                 SPDM BaseHashAlgo

  @return SPDM asymmetric algorithm size.
**/
UINT32
EFIAPI
GetSpdmAsymSignatureSize (
  IN   UINT32                       BaseAsymAlgo
  );

/**
  Retrieve the asymmetric Public Key from one DER-encoded X509 certificate,
  based upon negotiated asymmetric algorithm.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo
  @param  Cert                         Pointer to the DER-encoded X509 certificate.
  @param  CertSize                     Size of the X509 certificate in bytes.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
BOOLEAN
EFIAPI
SpdmAsymGetPublicKeyFromX509 (
  IN   UINT32                       BaseAsymAlgo,
  IN   CONST UINT8                  *Cert,
  IN   UINTN                        CertSize,
  OUT  VOID                         **Context
  );

/**
  Release the specified asymmetric context,
  based upon negotiated asymmetric algorithm.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo
  @param  Context                      Pointer to the asymmetric context to be released.
**/
VOID
EFIAPI
SpdmAsymFree (
  IN   UINT32                       BaseAsymAlgo,
  IN   VOID                         *Context
  );

/**
  Verifies the asymmetric signature,
  based upon negotiated asymmetric algorithm.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo
  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Context                      Pointer to asymmetric context for signature verification.
  @param  Message                      Pointer to octet message to be checked (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to asymmetric signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
BOOLEAN
EFIAPI
SpdmAsymVerify (
  IN   UINT32                       BaseAsymAlgo,
  IN   UINT32                       BaseHashAlgo,
  IN   VOID                         *Context,
  IN   CONST UINT8                  *Message,
  IN   UINTN                        MessageSize,
  IN   CONST UINT8                  *Signature,
  IN   UINTN                        SigSize
  );

/**
  Retrieve the Private Key from the password-protected PEM key data.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo
  @param  PemData                      Pointer to the PEM-encoded key data to be retrieved.
  @param  PemSize                      Size of the PEM key data in bytes.
  @param  Password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
BOOLEAN
EFIAPI
SpdmAsymGetPrivateKeyFromPem (
  IN   UINT32                       BaseAsymAlgo,
  IN   CONST UINT8                  *PemData,
  IN   UINTN                        PemSize,
  IN   CONST CHAR8                  *Password,
  OUT  VOID                         **Context
  );

/**
  Carries out the signature generation.

  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo
  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Context                      Pointer to asymmetric context for signature generation.
  @param  Message                      Pointer to octet message to be signed (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to buffer to receive signature.
  @param  SigSize                      On input, the size of Signature buffer in bytes.
                                       On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.
**/
BOOLEAN
EFIAPI
SpdmAsymSign (
  IN      UINT32                       BaseAsymAlgo,
  IN      UINT32                       BaseHashAlgo,
  IN      VOID                         *Context,
  IN      CONST UINT8                  *Message,
  IN      UINTN                        MessageSize,
  OUT     UINT8                        *Signature,
  IN OUT  UINTN                        *SigSize
  );

/**
  This function returns the SPDM requester asymmetric algorithm size.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg

  @return SPDM requester asymmetric algorithm size.
**/
UINT32
EFIAPI
GetSpdmReqAsymSignatureSize (
  IN   UINT16                       ReqBaseAsymAlg
  );

/**
  Retrieve the asymmetric Public Key from one DER-encoded X509 certificate,
  based upon negotiated requester asymmetric algorithm.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg
  @param  Cert                         Pointer to the DER-encoded X509 certificate.
  @param  CertSize                     Size of the X509 certificate in bytes.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
BOOLEAN
EFIAPI
SpdmReqAsymGetPublicKeyFromX509 (
  IN   UINT16                       ReqBaseAsymAlg,
  IN   CONST UINT8                  *Cert,
  IN   UINTN                        CertSize,
  OUT  VOID                         **Context
  );

/**
  Release the specified asymmetric context,
  based upon negotiated requester asymmetric algorithm.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg
  @param  Context                      Pointer to the asymmetric context to be released.
**/
VOID
EFIAPI
SpdmReqAsymFree (
  IN   UINT16                       ReqBaseAsymAlg,
  IN   VOID                         *Context
  );

/**
  Verifies the asymmetric signature,
  based upon negotiated requester asymmetric algorithm.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg
  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Context                      Pointer to asymmetric context for signature verification.
  @param  Message                      Pointer to octet message to be checked (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to asymmetric signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
BOOLEAN
EFIAPI
SpdmReqAsymVerify (
  IN   UINT16                       ReqBaseAsymAlg,
  IN   UINT32                       BaseHashAlgo,
  IN   VOID                         *Context,
  IN   CONST UINT8                  *Message,
  IN   UINTN                        MessageSize,
  IN   CONST UINT8                  *Signature,
  IN   UINTN                        SigSize
  );

/**
  Retrieve the Private Key from the password-protected PEM key data.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg
  @param  PemData                      Pointer to the PEM-encoded key data to be retrieved.
  @param  PemSize                      Size of the PEM key data in bytes.
  @param  Password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
BOOLEAN
EFIAPI
SpdmReqAsymGetPrivateKeyFromPem (
  IN   UINT16                       ReqBaseAsymAlg,
  IN   CONST UINT8                  *PemData,
  IN   UINTN                        PemSize,
  IN   CONST CHAR8                  *Password,
  OUT  VOID                         **Context
  );

/**
  Carries out the signature generation.

  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg
  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Context                      Pointer to asymmetric context for signature generation.
  @param  Message                      Pointer to octet message to be signed (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to buffer to receive signature.
  @param  SigSize                      On input, the size of Signature buffer in bytes.
                                       On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.
**/
BOOLEAN
EFIAPI
SpdmReqAsymSign (
  IN      UINT16                       ReqBaseAsymAlg,
  IN      UINT32                       BaseHashAlgo,
  IN      VOID                         *Context,
  IN      CONST UINT8                  *Message,
  IN      UINTN                        MessageSize,
  OUT     UINT8                        *Signature,
  IN OUT  UINTN                        *SigSize
  );

/**
  This function returns the SPDM DHE algorithm key size.

  @param  DHENamedGroup                SPDM DHENamedGroup

  @return SPDM DHE algorithm key size.
**/
UINT32
EFIAPI
GetSpdmDhePubKeySize (
  IN   UINT16                       DHENamedGroup
  );

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) Context for subsequent use,
  based upon negotiated DHE algorithm.
  
  @param  DHENamedGroup                SPDM DHENamedGroup

  @return  Pointer to the Diffie-Hellman Context that has been initialized.
**/
VOID *
EFIAPI
SpdmDheNew (
  IN   UINT16                       DHENamedGroup
  );

/**
  Release the specified DHE context,
  based upon negotiated DHE algorithm.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  Context                      Pointer to the DHE context to be released.
**/
VOID
EFIAPI
SpdmDheFree (
  IN   UINT16                       DHENamedGroup,
  IN   VOID                         *Context
  );

/**
  Generates DHE public key,
  based upon negotiated DHE algorithm.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter PublicKey and PublicKeySize. DH context is updated accordingly.
  If the PublicKey buffer is too small to hold the public key, FALSE is returned and
  PublicKeySize is set to the required buffer size to obtain the public key.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  Context                      Pointer to the DHE context.
  @param  PublicKey                    Pointer to the buffer to receive generated public key.
  @param  PublicKeySize                On input, the size of PublicKey buffer in bytes.
                                       On output, the size of data returned in PublicKey buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  PublicKeySize is not large enough.
**/
BOOLEAN
EFIAPI
SpdmDheGenerateKey (
  IN      UINT16                       DHENamedGroup,
  IN OUT  VOID                         *Context,
  OUT     UINT8                        *PublicKey,
  IN OUT  UINTN                        *PublicKeySize
  );

/**
  Computes exchanged common key,
  based upon negotiated DHE algorithm.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  Context                      Pointer to the DHE context.
  @param  PeerPublicKey                Pointer to the peer's public key.
  @param  PeerPublicKeySize            Size of peer's public key in bytes.
  @param  Key                          Pointer to the buffer to receive generated key.
  @param  KeySize                      On input, the size of Key buffer in bytes.
                                       On output, the size of data returned in Key buffer in bytes.

  @retval TRUE   DHE exchanged key generation succeeded.
  @retval FALSE  DHE exchanged key generation failed.
  @retval FALSE  KeySize is not large enough.
**/
BOOLEAN
EFIAPI
SpdmDheComputeKey (
  IN      UINT16                       DHENamedGroup,
  IN OUT  VOID                         *Context,
  IN      CONST UINT8                  *PeerPublic,
  IN      UINTN                        PeerPublicSize,
  OUT     UINT8                        *Key,
  IN OUT  UINTN                        *KeySize
  );

/**
  This function returns the SPDM AEAD algorithm key size.

  @param  AEADCipherSuite              SPDM AEADCipherSuite

  @return SPDM AEAD algorithm key size.
**/
UINT32
EFIAPI
GetSpdmAeadKeySize (
  IN   UINT16                       AEADCipherSuite
  );

/**
  This function returns the SPDM AEAD algorithm iv size.

  @param  AEADCipherSuite              SPDM AEADCipherSuite

  @return SPDM AEAD algorithm iv size.
**/
UINT32
EFIAPI
GetSpdmAeadIvSize (
  IN   UINT16                       AEADCipherSuite
  );

/**
  This function returns the SPDM AEAD algorithm tag size.

  @param  AEADCipherSuite              SPDM AEADCipherSuite

  @return SPDM AEAD algorithm tag size.
**/
UINT32
EFIAPI
GetSpdmAeadTagSize (
  IN   UINT16                       AEADCipherSuite
  );

/**
  This function returns the SPDM AEAD algorithm block size.

  @param  AEADCipherSuite              SPDM AEADCipherSuite

  @return SPDM AEAD algorithm block size.
**/
UINT32
EFIAPI
GetSpdmAeadBlockSize (
  IN   UINT16                       AEADCipherSuite
  );

/**
  Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  AEADCipherSuite              SPDM AEADCipherSuite
  @param  Key                          Pointer to the encryption key.
  @param  KeySize                      Size of the encryption key in bytes.
  @param  Iv                           Pointer to the IV value.
  @param  IvSize                       Size of the IV value in bytes.
  @param  AData                        Pointer to the additional authenticated data (AAD).
  @param  ADataSize                    Size of the additional authenticated data (AAD) in bytes.
  @param  DataIn                       Pointer to the input data buffer to be encrypted.
  @param  DataInSize                   Size of the input data buffer in bytes.
  @param  TagOut                       Pointer to a buffer that receives the authentication tag output.
  @param  TagSize                      Size of the authentication tag in bytes.
  @param  DataOut                      Pointer to a buffer that receives the encryption output.
  @param  DataOutSize                  Size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated encryption succeeded.
  @retval FALSE  AEAD authenticated encryption failed.
**/
BOOLEAN
EFIAPI
SpdmAeadEncryption (
  IN   UINT16                       AEADCipherSuite,
  IN   CONST UINT8*                 Key,
  IN   UINTN                        KeySize,
  IN   CONST UINT8*                 Iv,
  IN   UINTN                        IvSize,
  IN   CONST UINT8*                 AData,
  IN   UINTN                        ADataSize,
  IN   CONST UINT8*                 DataIn,
  IN   UINTN                        DataInSize,
  OUT  UINT8*                       TagOut,
  IN   UINTN                        TagSize,
  OUT  UINT8*                       DataOut,
  OUT  UINTN*                       DataOutSize
  );

/**
  Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  AEADCipherSuite              SPDM AEADCipherSuite
  @param  Key                          Pointer to the encryption key.
  @param  KeySize                      Size of the encryption key in bytes.
  @param  Iv                           Pointer to the IV value.
  @param  IvSize                       Size of the IV value in bytes.
  @param  AData                        Pointer to the additional authenticated data (AAD).
  @param  ADataSize                    Size of the additional authenticated data (AAD) in bytes.
  @param  DataIn                       Pointer to the input data buffer to be decrypted.
  @param  DataInSize                   Size of the input data buffer in bytes.
  @param  Tag                          Pointer to a buffer that contains the authentication tag.
  @param  TagSize                      Size of the authentication tag in bytes.
  @param  DataOut                      Pointer to a buffer that receives the decryption output.
  @param  DataOutSize                  Size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated decryption succeeded.
  @retval FALSE  AEAD authenticated decryption failed.
**/
BOOLEAN
EFIAPI
SpdmAeadDecryption (
  IN   UINT16                       AEADCipherSuite,
  IN   CONST UINT8*                 Key,
  IN   UINTN                        KeySize,
  IN   CONST UINT8*                 Iv,
  IN   UINTN                        IvSize,
  IN   CONST UINT8*                 AData,
  IN   UINTN                        ADataSize,
  IN   CONST UINT8*                 DataIn,
  IN   UINTN                        DataInSize,
  IN   CONST UINT8*                 Tag,
  IN   UINTN                        TagSize,
  OUT  UINT8*                       DataOut,
  OUT  UINTN*                       DataOutSize
  );

/**
  Generates a random byte stream of the specified size.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Size                         Size of random bytes to generate.
  @param  Rand                         Pointer to buffer to receive random value.
**/
VOID
EFIAPI
SpdmGetRandomNumber (
  IN  UINTN                     Size,
  OUT UINT8                     *Rand
  );

/**
  Certificate Check for SPDM leaf cert.

  @param[in]  Cert            Pointer to the DER-encoded certificate data.
  @param[in]  CertSize        The size of certificate data in bytes.

  @retval  TRUE   Success.
  @retval  FALSE  Certificate is not valid
**/
BOOLEAN
EFIAPI
SpdmX509CertificateCheck (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize
  );

/**
  Retrieve the SubjectAltName from SubjectAltName Bytes.

  @param[in]      Buffer           Pointer to subjectAltName oct bytes.
  @param[in]      Len              Size of Buffer in bytes.
  @param[out]     NameBuffer       Buffer to contain the retrieved certificate
                                   SubjectAltName. At most NameBufferSize bytes will be
                                   written. Maybe NULL in order to determine the size
                                   buffer needed.
  @param[in,out]  NameBufferSize   The size in bytes of the Name buffer on input,
                                   and the size of buffer returned Name on output.
                                   If NameBuffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.
  @param[out]     Oid              OID of otherName
  @param[in,out]  OidSize          the buffersize for required OID

  @retval RETURN_SUCCESS           The certificate Organization Name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If NameBufferSize is NULL.
                                   If NameBuffer is not NULL and *CommonNameSize is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the NameBuffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   NameBufferSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
RETURN_STATUS
EFIAPI
SpdmGetDMTFSubjectAltNameFromBytes (
  IN      CONST UINT8   *Buffer,
  IN      INTN          Len,
  OUT     CHAR8         *NameBuffer,  OPTIONAL
  IN OUT  UINTN         *NameBufferSize,
  OUT     UINT8         *Oid,         OPTIONAL
  IN OUT  UINTN         *OidSize
  );

/**
  Retrieve the SubjectAltName from one X.509 certificate.

  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[out]     NameBuffer       Buffer to contain the retrieved certificate
                                   SubjectAltName. At most NameBufferSize bytes will be
                                   written. Maybe NULL in order to determine the size
                                   buffer needed.
  @param[in,out]  NameBufferSize   The size in bytes of the Name buffer on input,
                                   and the size of buffer returned Name on output.
                                   If NameBuffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.
  @param[out]     Oid              OID of otherName
  @param[in,out]  OidSize          the buffersize for required OID

  @retval RETURN_SUCCESS           The certificate Organization Name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If NameBufferSize is NULL.
                                   If NameBuffer is not NULL and *CommonNameSize is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the NameBuffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   NameBufferSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
RETURN_STATUS
EFIAPI
SpdmGetDMTFSubjectAltName (
  IN      CONST UINT8   *Cert,
  IN      INTN          CertSize,
  OUT     CHAR8         *NameBuffer,  OPTIONAL
  IN OUT  UINTN         *NameBufferSize,
  OUT     UINT8         *Oid,         OPTIONAL
  IN OUT  UINTN         *OidSize
  );

/**
  This function verifies the integrity of certificate chain data without SPDM_CERT_CHAIN header.

  @param  CertChainData          The certificate chain data without SPDM_CERT_CHAIN header.
  @param  CertChainDataSize      Size in bytes of the certificate chain data.

  @retval TRUE  certificate chain data integrity verification pass.
  @retval FALSE certificate chain data integrity verification fail.
**/
BOOLEAN
EFIAPI
SpdmVerifyCertChainData (
  IN UINT8                        *CertChainData,
  IN UINTN                        CertChainDataSize
  );

/**
  This function verifies the integrity of certificate chain buffer including SPDM_CERT_CHAIN header.

  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  CertChainBuffer              The certificate chain buffer including SPDM_CERT_CHAIN header.
  @param  CertChainBufferSize          Size in bytes of the certificate chain buffer.

  @retval TRUE  certificate chain buffer integrity verification pass.
  @retval FALSE certificate chain buffer integrity verification fail.
**/
BOOLEAN
EFIAPI
SpdmVerifyCertificateChainBuffer (
  IN UINT32                       BaseHashAlgo,
  IN VOID                         *CertChainBuffer,
  IN UINTN                        CertChainBufferSize
  );

#endif