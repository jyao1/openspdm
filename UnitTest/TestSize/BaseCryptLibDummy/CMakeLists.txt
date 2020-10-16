cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-incompatible-pointer-types -Wno-pointer-sign")
endif()

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestSize/BaseCryptLibDummy
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/OsStub/Include                   
)

SET(src_BaseCryptLibDummy
    Cipher/CryptAeadAesCcm.c
    Cipher/CryptAeadAesGcm.c
    Cipher/CryptAeadChaCha20Poly1305.c
    Hash/CryptSha256.c
    Hash/CryptSha512.c
    Hmac/CryptHmacSha256.c
    Kdf/CryptHkdf.c
    Mac/CryptCmacAes.c
    Mac/CryptGmacAes.c
    Pem/CryptPem.c
    Pk/CryptEc.c
    Pk/CryptDh.c
    Pk/CryptRsaBasic.c
    Pk/CryptRsaExt.c
    Pk/CryptX509.c
    Pk/CryptPkcs7Sign.c
    Pk/CryptPkcs7VerifyCommon.c
    Rand/CryptRand.c
)

ADD_LIBRARY(BaseCryptLibDummy STATIC ${src_BaseCryptLibDummy})
