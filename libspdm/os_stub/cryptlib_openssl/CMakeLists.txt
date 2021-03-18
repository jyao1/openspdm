cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/../libspdm/os_stub/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/os_stub/cryptlib_openssl
                    ${PROJECT_SOURCE_DIR}/../libspdm/os_stub/openssllib/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/os_stub/openssllib/openssl/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/os_stub/openssllib/openssl/crypto/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/os_stub/openssllib/openssl
)

SET(src_cryptlib_openssl
    cipher/aead_aes_gcm.c
    cipher/aead_chacha20_poly1305.c
    cipher/aead_sm4_gcm.c
    hash/sha256.c
    hash/sha512.c
    hash/sha3.c
    hash/sm3.c
    hmac/hmac_sha.c
    kdf/hkdf.c
    pem/pem.c
    pk/ec.c
    pk/ecd.c
    pk/ecx.c
    pk/dh.c
    pk/sm2.c
    pk/rsa_basic.c
    pk/rsa_ext.c
    pk/x509.c
    rand/rand.c
    sys_call/crt_wrapper_host.c
)

ADD_LIBRARY(cryptlib_openssl STATIC ${src_cryptlib_openssl})
