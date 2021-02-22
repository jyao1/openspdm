cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-incompatible-pointer-types -Wno-pointer-sign")
endif()

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/OsStub/Include
                    ${PROJECT_SOURCE_DIR}/OsStub/BaseCryptLibMbedTls
                    ${PROJECT_SOURCE_DIR}/OsStub/MbedTlsLib/Include
                    ${PROJECT_SOURCE_DIR}/OsStub/MbedTlsLib/Include/mbedtls
                    ${PROJECT_SOURCE_DIR}/OsStub/MbedTlsLib/mbedtls/include
                    ${PROJECT_SOURCE_DIR}/OsStub/MbedTlsLib/mbedtls/include/mbedtls
)

SET(src_BaseCryptLibMbedTls
    Cipher/CryptAeadAesCcm.c
    Cipher/CryptAeadAesGcm.c
    Cipher/CryptAeadChaCha20Poly1305.c
    Cipher/CryptAeadSm4Gcm.c
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
    Pk/CryptRsaBasic.c
    Pk/CryptRsaExt.c
    Pk/CryptX509.c
    Pk/CryptPkcs7Sign.c
    Pk/CryptPkcs7VerifyCommon.c
    Rand/CryptRand.c
    SysCall/BaseMemAllocation.c
    SysCall/CrtWrapperHost.c
    SysCall/TimerWrapperHost.c
)

ADD_LIBRARY(BaseCryptLibMbedTls STATIC ${src_BaseCryptLibMbedTls})
