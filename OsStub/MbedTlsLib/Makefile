## @file
#  SPDM library.
#
#  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

#
# Platform Macro Definition
#

!INCLUDE $(WORKSPACE)\MakeFile.Flags

#
# Module Macro Definition
#
MODULE_NAME = MbedTlsLib

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\OsStub\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\OsStub\$(MODULE_NAME)

CC_FLAGS = $(CC_FLAGS) $(MBEDTLS_FLAGS)

!IF "$(ARCH)" == "X64"
CC_FLAGS = $(CC_FLAGS) -DEFIX64
!ELSEIF "$(ARCH)" == "Ia32"
CC_FLAGS = $(CC_FLAGS) -DEFI32
!ELSE
!ERROR Unknown ARCH!
!ENDIF

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\aes.obj \
    $(OUTPUT_DIR)\aesni.obj \
    $(OUTPUT_DIR)\arc4.obj \
    $(OUTPUT_DIR)\aria.obj \
    $(OUTPUT_DIR)\asn1parse.obj \
    $(OUTPUT_DIR)\asn1write.obj \
    $(OUTPUT_DIR)\base64.obj \
    $(OUTPUT_DIR)\bignum.obj \
    $(OUTPUT_DIR)\blowfish.obj \
    $(OUTPUT_DIR)\camellia.obj \
    $(OUTPUT_DIR)\ccm.obj \
    $(OUTPUT_DIR)\certs.obj \
    $(OUTPUT_DIR)\chacha20.obj \
    $(OUTPUT_DIR)\chachapoly.obj \
    $(OUTPUT_DIR)\cipher.obj \
    $(OUTPUT_DIR)\cipher_wrap.obj \
    $(OUTPUT_DIR)\cmac.obj \
    $(OUTPUT_DIR)\ctr_drbg.obj \
    $(OUTPUT_DIR)\debug.obj \
    $(OUTPUT_DIR)\des.obj \
    $(OUTPUT_DIR)\dhm.obj \
    $(OUTPUT_DIR)\ecdh.obj \
    $(OUTPUT_DIR)\ecdsa.obj \
    $(OUTPUT_DIR)\ecjpake.obj \
    $(OUTPUT_DIR)\ecp.obj \
    $(OUTPUT_DIR)\ecp_curves.obj \
    $(OUTPUT_DIR)\entropy.obj \
    $(OUTPUT_DIR)\error.obj \
    $(OUTPUT_DIR)\gcm.obj \
    $(OUTPUT_DIR)\havege.obj \
    $(OUTPUT_DIR)\hkdf.obj \
    $(OUTPUT_DIR)\hmac_drbg.obj \
    $(OUTPUT_DIR)\md.obj \
    $(OUTPUT_DIR)\md2.obj \
    $(OUTPUT_DIR)\md4.obj \
    $(OUTPUT_DIR)\md5.obj \
    $(OUTPUT_DIR)\md_wrap.obj \
    $(OUTPUT_DIR)\memory_buffer_alloc.obj \
    $(OUTPUT_DIR)\nist_kw.obj \
    $(OUTPUT_DIR)\oid.obj \
    $(OUTPUT_DIR)\padlock.obj \
    $(OUTPUT_DIR)\pem.obj \
    $(OUTPUT_DIR)\pk.obj \
    $(OUTPUT_DIR)\pkcs11.obj \
    $(OUTPUT_DIR)\pkcs12.obj \
    $(OUTPUT_DIR)\pkcs5.obj \
    $(OUTPUT_DIR)\pkparse.obj \
    $(OUTPUT_DIR)\pkwrite.obj \
    $(OUTPUT_DIR)\pk_wrap.obj \
    $(OUTPUT_DIR)\poly1305.obj \
    $(OUTPUT_DIR)\ripemd160.obj \
    $(OUTPUT_DIR)\rsa.obj \
    $(OUTPUT_DIR)\rsa_internal.obj \
    $(OUTPUT_DIR)\sha1.obj \
    $(OUTPUT_DIR)\sha256.obj \
    $(OUTPUT_DIR)\sha512.obj \
    $(OUTPUT_DIR)\ssl_cache.obj \
    $(OUTPUT_DIR)\ssl_ciphersuites.obj \
    $(OUTPUT_DIR)\ssl_cli.obj \
    $(OUTPUT_DIR)\ssl_cookie.obj \
    $(OUTPUT_DIR)\ssl_srv.obj \
    $(OUTPUT_DIR)\ssl_ticket.obj \
    $(OUTPUT_DIR)\ssl_tls.obj \
    $(OUTPUT_DIR)\threading.obj \
    $(OUTPUT_DIR)\version.obj \
    $(OUTPUT_DIR)\version_features.obj \
    $(OUTPUT_DIR)\x509.obj \
    $(OUTPUT_DIR)\x509write_crt.obj \
    $(OUTPUT_DIR)\x509write_csr.obj \
    $(OUTPUT_DIR)\x509_create.obj \
    $(OUTPUT_DIR)\x509_crl.obj \
    $(OUTPUT_DIR)\x509_crt.obj \
    $(OUTPUT_DIR)\x509_csr.obj \
    $(OUTPUT_DIR)\xtea.obj \

INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH) \
    -I$(WORKSPACE)\OsStub\Include \
    -I$(WORKSPACE)\OsStub\MbedTlsLib\Include \
    -I$(WORKSPACE)\OsStub\MbedTlsLib\Include\mbedtls \
    -I$(WORKSPACE)\OsStub\MbedTlsLib\mbedtls\include \
    -I$(WORKSPACE)\OsStub\MbedTlsLib\mbedtls\include\mbedtls \

#
# Overridable Target Macro Definitions
#
INIT_TARGET = init
CODA_TARGET = $(OUTPUT_DIR)\$(MODULE_NAME).lib

#
# Default target, which will build dependent libraries in addition to source files
#

all: mbuild

#
# ModuleTarget
#

mbuild: $(INIT_TARGET) $(CODA_TARGET)

#
# Initialization target: print build information and create necessary directories
#
init:
	-@if not exist $(OUTPUT_DIR) $(MD) $(OUTPUT_DIR)

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\aes.obj : $(SOURCE_DIR)\mbedtls/library/aes.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/aes.c

$(OUTPUT_DIR)\aesni.obj : $(SOURCE_DIR)\mbedtls/library/aesni.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/aesni.c

$(OUTPUT_DIR)\arc4.obj : $(SOURCE_DIR)\mbedtls/library/arc4.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/arc4.c

$(OUTPUT_DIR)\aria.obj : $(SOURCE_DIR)\mbedtls/library/aria.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/aria.c

$(OUTPUT_DIR)\asn1parse.obj : $(SOURCE_DIR)\mbedtls/library/asn1parse.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/asn1parse.c

$(OUTPUT_DIR)\asn1write.obj : $(SOURCE_DIR)\mbedtls/library/asn1write.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/asn1write.c

$(OUTPUT_DIR)\base64.obj : $(SOURCE_DIR)\mbedtls/library/base64.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/base64.c

$(OUTPUT_DIR)\bignum.obj : $(SOURCE_DIR)\mbedtls/library/bignum.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/bignum.c

$(OUTPUT_DIR)\blowfish.obj : $(SOURCE_DIR)\mbedtls/library/blowfish.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/blowfish.c

$(OUTPUT_DIR)\camellia.obj : $(SOURCE_DIR)\mbedtls/library/camellia.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/camellia.c

$(OUTPUT_DIR)\ccm.obj : $(SOURCE_DIR)\mbedtls/library/ccm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ccm.c

$(OUTPUT_DIR)\certs.obj : $(SOURCE_DIR)\mbedtls/library/certs.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/certs.c

$(OUTPUT_DIR)\chacha20.obj : $(SOURCE_DIR)\mbedtls/library/chacha20.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/chacha20.c

$(OUTPUT_DIR)\chachapoly.obj : $(SOURCE_DIR)\mbedtls/library/chachapoly.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/chachapoly.c

$(OUTPUT_DIR)\cipher.obj : $(SOURCE_DIR)\mbedtls/library/cipher.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/cipher.c

$(OUTPUT_DIR)\cipher_wrap.obj : $(SOURCE_DIR)\mbedtls/library/cipher_wrap.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/cipher_wrap.c

$(OUTPUT_DIR)\cmac.obj : $(SOURCE_DIR)\mbedtls/library/cmac.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/cmac.c

$(OUTPUT_DIR)\ctr_drbg.obj : $(SOURCE_DIR)\mbedtls/library/ctr_drbg.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ctr_drbg.c

$(OUTPUT_DIR)\debug.obj : $(SOURCE_DIR)\mbedtls/library/debug.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/debug.c

$(OUTPUT_DIR)\des.obj : $(SOURCE_DIR)\mbedtls/library/des.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/des.c

$(OUTPUT_DIR)\dhm.obj : $(SOURCE_DIR)\mbedtls/library/dhm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/dhm.c

$(OUTPUT_DIR)\ecdh.obj : $(SOURCE_DIR)\mbedtls/library/ecdh.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ecdh.c

$(OUTPUT_DIR)\ecdsa.obj : $(SOURCE_DIR)\mbedtls/library/ecdsa.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ecdsa.c

$(OUTPUT_DIR)\ecjpake.obj : $(SOURCE_DIR)\mbedtls/library/ecjpake.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ecjpake.c

$(OUTPUT_DIR)\ecp.obj : $(SOURCE_DIR)\mbedtls/library/ecp.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ecp.c

$(OUTPUT_DIR)\ecp_curves.obj : $(SOURCE_DIR)\mbedtls/library/ecp_curves.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ecp_curves.c

$(OUTPUT_DIR)\entropy.obj : $(SOURCE_DIR)\mbedtls/library/entropy.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/entropy.c

$(OUTPUT_DIR)\error.obj : $(SOURCE_DIR)\mbedtls/library/error.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/error.c

$(OUTPUT_DIR)\gcm.obj : $(SOURCE_DIR)\mbedtls/library/gcm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/gcm.c

$(OUTPUT_DIR)\havege.obj : $(SOURCE_DIR)\mbedtls/library/havege.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/havege.c

$(OUTPUT_DIR)\hkdf.obj : $(SOURCE_DIR)\mbedtls/library/hkdf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/hkdf.c

$(OUTPUT_DIR)\hmac_drbg.obj : $(SOURCE_DIR)\mbedtls/library/hmac_drbg.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/hmac_drbg.c

$(OUTPUT_DIR)\md.obj : $(SOURCE_DIR)\mbedtls/library/md.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/md.c

$(OUTPUT_DIR)\md2.obj : $(SOURCE_DIR)\mbedtls/library/md2.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/md2.c

$(OUTPUT_DIR)\md4.obj : $(SOURCE_DIR)\mbedtls/library/md4.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/md4.c

$(OUTPUT_DIR)\md5.obj : $(SOURCE_DIR)\mbedtls/library/md5.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/md5.c

$(OUTPUT_DIR)\md_wrap.obj : $(SOURCE_DIR)\mbedtls/library/md_wrap.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/md_wrap.c

$(OUTPUT_DIR)\memory_buffer_alloc.obj : $(SOURCE_DIR)\mbedtls/library/memory_buffer_alloc.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/memory_buffer_alloc.c

$(OUTPUT_DIR)\nist_kw.obj : $(SOURCE_DIR)\mbedtls/library/nist_kw.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/nist_kw.c

$(OUTPUT_DIR)\oid.obj : $(SOURCE_DIR)\mbedtls/library/oid.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/oid.c

$(OUTPUT_DIR)\padlock.obj : $(SOURCE_DIR)\mbedtls/library/padlock.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/padlock.c

$(OUTPUT_DIR)\pem.obj : $(SOURCE_DIR)\mbedtls/library/pem.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/pem.c

$(OUTPUT_DIR)\pk.obj : $(SOURCE_DIR)\mbedtls/library/pk.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/pk.c

$(OUTPUT_DIR)\pkcs11.obj : $(SOURCE_DIR)\mbedtls/library/pkcs11.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/pkcs11.c

$(OUTPUT_DIR)\pkcs12.obj : $(SOURCE_DIR)\mbedtls/library/pkcs12.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/pkcs12.c

$(OUTPUT_DIR)\pkcs5.obj : $(SOURCE_DIR)\mbedtls/library/pkcs5.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/pkcs5.c

$(OUTPUT_DIR)\pkparse.obj : $(SOURCE_DIR)\mbedtls/library/pkparse.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/pkparse.c

$(OUTPUT_DIR)\pkwrite.obj : $(SOURCE_DIR)\mbedtls/library/pkwrite.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/pkwrite.c

$(OUTPUT_DIR)\pk_wrap.obj : $(SOURCE_DIR)\mbedtls/library/pk_wrap.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/pk_wrap.c

$(OUTPUT_DIR)\poly1305.obj : $(SOURCE_DIR)\mbedtls/library/poly1305.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/poly1305.c

$(OUTPUT_DIR)\ripemd160.obj : $(SOURCE_DIR)\mbedtls/library/ripemd160.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ripemd160.c

$(OUTPUT_DIR)\rsa.obj : $(SOURCE_DIR)\mbedtls/library/rsa.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/rsa.c

$(OUTPUT_DIR)\rsa_internal.obj : $(SOURCE_DIR)\mbedtls/library/rsa_internal.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/rsa_internal.c

$(OUTPUT_DIR)\sha1.obj : $(SOURCE_DIR)\mbedtls/library/sha1.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/sha1.c

$(OUTPUT_DIR)\sha256.obj : $(SOURCE_DIR)\mbedtls/library/sha256.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/sha256.c

$(OUTPUT_DIR)\sha512.obj : $(SOURCE_DIR)\mbedtls/library/sha512.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/sha512.c

$(OUTPUT_DIR)\ssl_cache.obj : $(SOURCE_DIR)\mbedtls/library/ssl_cache.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ssl_cache.c

$(OUTPUT_DIR)\ssl_ciphersuites.obj : $(SOURCE_DIR)\mbedtls/library/ssl_ciphersuites.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ssl_ciphersuites.c

$(OUTPUT_DIR)\ssl_cli.obj : $(SOURCE_DIR)\mbedtls/library/ssl_cli.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ssl_cli.c

$(OUTPUT_DIR)\ssl_cookie.obj : $(SOURCE_DIR)\mbedtls/library/ssl_cookie.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ssl_cookie.c

$(OUTPUT_DIR)\ssl_srv.obj : $(SOURCE_DIR)\mbedtls/library/ssl_srv.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ssl_srv.c

$(OUTPUT_DIR)\ssl_ticket.obj : $(SOURCE_DIR)\mbedtls/library/ssl_ticket.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ssl_ticket.c

$(OUTPUT_DIR)\ssl_tls.obj : $(SOURCE_DIR)\mbedtls/library/ssl_tls.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/ssl_tls.c

$(OUTPUT_DIR)\threading.obj : $(SOURCE_DIR)\mbedtls/library/threading.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/threading.c

$(OUTPUT_DIR)\version.obj : $(SOURCE_DIR)\mbedtls/library/version.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/version.c

$(OUTPUT_DIR)\version_features.obj : $(SOURCE_DIR)\mbedtls/library/version_features.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/version_features.c

$(OUTPUT_DIR)\x509.obj : $(SOURCE_DIR)\mbedtls/library/x509.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/x509.c

$(OUTPUT_DIR)\x509write_crt.obj : $(SOURCE_DIR)\mbedtls/library/x509write_crt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/x509write_crt.c

$(OUTPUT_DIR)\x509write_csr.obj : $(SOURCE_DIR)\mbedtls/library/x509write_csr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/x509write_csr.c

$(OUTPUT_DIR)\x509_create.obj : $(SOURCE_DIR)\mbedtls/library/x509_create.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/x509_create.c

$(OUTPUT_DIR)\x509_crl.obj : $(SOURCE_DIR)\mbedtls/library/x509_crl.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/x509_crl.c

$(OUTPUT_DIR)\x509_crt.obj : $(SOURCE_DIR)\mbedtls/library/x509_crt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/x509_crt.c

$(OUTPUT_DIR)\x509_csr.obj : $(SOURCE_DIR)\mbedtls/library/x509_csr.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/x509_csr.c

$(OUTPUT_DIR)\xtea.obj : $(SOURCE_DIR)\mbedtls/library/xtea.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\mbedtls/library/xtea.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	$(SLINK) $(SLINK_FLAGS) $(OUTPUT_DIR)\*.obj $(SLINK_OBJ_FLAG)$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


