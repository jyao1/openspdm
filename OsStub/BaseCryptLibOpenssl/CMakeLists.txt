cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/OsStub/Include
                    ${PROJECT_SOURCE_DIR}/OsStub/BaseCryptLibOpenssl
                    ${PROJECT_SOURCE_DIR}/OsStub/OpensslLib/Include
                    ${PROJECT_SOURCE_DIR}/OsStub/OpensslLib/openssl/include
                    ${PROJECT_SOURCE_DIR}/OsStub/OpensslLib/openssl/crypto/include
)

SET(src_BaseCryptLibOpenssl
    Cipher/CryptAeadAesCcm.c
    Cipher/CryptAeadAesGcm.c
    Cipher/CryptAeadChaCha20Poly1305.c
    Cipher/CryptAeadSm4Gcm
    Cipher/CryptAes.c
    Hash/CryptSha256.c
    Hash/CryptSha512.c
    Hash/CryptSha3.c
    Hash/CryptSm3.c
    Hmac/CryptHmacSha256.c
    Kdf/CryptHkdf.c
    Mac/CryptCmacAes.c
    Mac/CryptGmacAes.c
    Pem/CryptPem.c
    Pk/CryptEc.c
    Pk/CryptEd.c
    Pk/CryptDh.c
    Pk/CryptSm2.c
    Pk/CryptPkcs1Oaep.c
    Pk/CryptPkcs7Sign.c
    Pk/CryptPkcs7VerifyBase.c
    Pk/CryptPkcs7VerifyCommon.c
    Pk/CryptPkcs7VerifyEku.c
    Pk/CryptRsaBasic.c
    Pk/CryptRsaExt.c
    Pk/CryptX509.c
    Rand/CryptRand.c
    SysCall/CrtWrapperHost.c
)

ADD_LIBRARY(BaseCryptLibOpenssl STATIC ${src_BaseCryptLibOpenssl})
