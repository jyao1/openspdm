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

MBEDTLS_FLAGS = /DMBEDTLS_PLATFORM_NO_STD_FUNCTIONS /DMBEDTLS_PLATFORM_MEMORY /DMBEDTLS_PLATFORM_FPRINTF_ALT /DMBEDTLS_PLATFORM_PRINTF_ALT /DMBEDTLS_PLATFORM_SNPRINTF_ALT /UMBEDTLS_FS_IO
CC_FLAGS = $(CC_FLAGS) $(MBEDTLS_FLAGS) /wd4244 /wd4132 /wd4245 /wd4310 /wd4701 /wd4127

!IF "$(ARCH)" == "X64"
CC_FLAGS = $(CC_FLAGS) /DEFIX64
!ELSEIF "$(ARCH)" == "Ia32"
CC_FLAGS = $(CC_FLAGS) /DEFI32
!ELSE
!ERROR Unknown ARCH!
!ENDIF

#
# Build Macro
#
SOURCE_FILES =  \
	$(SOURCE_DIR)\mbedtls\library\aes.c \
	$(SOURCE_DIR)\mbedtls\library\aesni.c \
	$(SOURCE_DIR)\mbedtls\library\arc4.c \
	$(SOURCE_DIR)\mbedtls\library\aria.c \
	$(SOURCE_DIR)\mbedtls\library\asn1parse.c \
	$(SOURCE_DIR)\mbedtls\library\asn1write.c \
	$(SOURCE_DIR)\mbedtls\library\base64.c \
	$(SOURCE_DIR)\mbedtls\library\bignum.c \
	$(SOURCE_DIR)\mbedtls\library\bignum.c \
	$(SOURCE_DIR)\mbedtls\library\blowfish.c \
	$(SOURCE_DIR)\mbedtls\library\camellia.c \
	$(SOURCE_DIR)\mbedtls\library\ccm.c \
	$(SOURCE_DIR)\mbedtls\library\certs.c \
	$(SOURCE_DIR)\mbedtls\library\chacha20.c \
	$(SOURCE_DIR)\mbedtls\library\chachapoly.c \
	$(SOURCE_DIR)\mbedtls\library\cipher.c \
	$(SOURCE_DIR)\mbedtls\library\cipher_wrap.c \
	$(SOURCE_DIR)\mbedtls\library\cmac.c \
	$(SOURCE_DIR)\mbedtls\library\ctr_drbg.c \
	$(SOURCE_DIR)\mbedtls\library\debug.c \
	$(SOURCE_DIR)\mbedtls\library\des.c \
	$(SOURCE_DIR)\mbedtls\library\dhm.c \
	$(SOURCE_DIR)\mbedtls\library\ecdh.c \
	$(SOURCE_DIR)\mbedtls\library\ecdsa.c \
	$(SOURCE_DIR)\mbedtls\library\ecjpake.c \
	$(SOURCE_DIR)\mbedtls\library\ecp.c \
	$(SOURCE_DIR)\mbedtls\library\ecp_curves.c \
	$(SOURCE_DIR)\mbedtls\library\entropy.c \
	$(SOURCE_DIR)\mbedtls\library\error.c \
	$(SOURCE_DIR)\mbedtls\library\gcm.c \
	$(SOURCE_DIR)\mbedtls\library\havege.c \
	$(SOURCE_DIR)\mbedtls\library\hkdf.c \
	$(SOURCE_DIR)\mbedtls\library\hmac_drbg.c \
	$(SOURCE_DIR)\mbedtls\library\md.c \
	$(SOURCE_DIR)\mbedtls\library\md2.c \
	$(SOURCE_DIR)\mbedtls\library\md4.c \
	$(SOURCE_DIR)\mbedtls\library\md5.c \
	$(SOURCE_DIR)\mbedtls\library\md_wrap.c \
	$(SOURCE_DIR)\mbedtls\library\memory_buffer_alloc.c \
	$(SOURCE_DIR)\mbedtls\library\nist_kw.c \
	$(SOURCE_DIR)\mbedtls\library\oid.c \
	$(SOURCE_DIR)\mbedtls\library\padlock.c \
	$(SOURCE_DIR)\mbedtls\library\pem.c \
	$(SOURCE_DIR)\mbedtls\library\pk.c \
	$(SOURCE_DIR)\mbedtls\library\pkcs11.c \
	$(SOURCE_DIR)\mbedtls\library\pkcs12.c \
	$(SOURCE_DIR)\mbedtls\library\pkcs5.c \
	$(SOURCE_DIR)\mbedtls\library\pkparse.c \
	$(SOURCE_DIR)\mbedtls\library\pkwrite.c \
	$(SOURCE_DIR)\mbedtls\library\pk_wrap.c \
	$(SOURCE_DIR)\mbedtls\library\poly1305.c \
	$(SOURCE_DIR)\mbedtls\library\ripemd160.c \
	$(SOURCE_DIR)\mbedtls\library\rsa.c \
	$(SOURCE_DIR)\mbedtls\library\rsa_internal.c \
	$(SOURCE_DIR)\mbedtls\library\sha1.c \
	$(SOURCE_DIR)\mbedtls\library\sha256.c \
	$(SOURCE_DIR)\mbedtls\library\sha512.c \
	$(SOURCE_DIR)\mbedtls\library\ssl_cache.c \
	$(SOURCE_DIR)\mbedtls\library\ssl_ciphersuites.c \
	$(SOURCE_DIR)\mbedtls\library\ssl_cli.c \
	$(SOURCE_DIR)\mbedtls\library\ssl_cookie.c \
	$(SOURCE_DIR)\mbedtls\library\ssl_srv.c \
	$(SOURCE_DIR)\mbedtls\library\ssl_ticket.c \
	$(SOURCE_DIR)\mbedtls\library\ssl_tls.c \
	$(SOURCE_DIR)\mbedtls\library\threading.c \
	$(SOURCE_DIR)\mbedtls\library\version.c \
	$(SOURCE_DIR)\mbedtls\library\version_features.c \
	$(SOURCE_DIR)\mbedtls\library\x509.c \
	$(SOURCE_DIR)\mbedtls\library\x509write_crt.c \
	$(SOURCE_DIR)\mbedtls\library\x509write_csr.c \
	$(SOURCE_DIR)\mbedtls\library\x509_create.c \
	$(SOURCE_DIR)\mbedtls\library\x509_crl.c \
	$(SOURCE_DIR)\mbedtls\library\x509_crt.c \
	$(SOURCE_DIR)\mbedtls\library\x509_csr.c \
	$(SOURCE_DIR)\mbedtls\library\xtea.c \


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
    /I$(SOURCE_DIR) \
    /I$(WORKSPACE)\Include \
    /I$(WORKSPACE)\Include\Hal \
    /I$(WORKSPACE)\Include\Hal\$(ARCH) \
    /I$(WORKSPACE)\OsStub\Include \
    /I$(WORKSPACE)\OsStub\MbedTlsLib\mbedtls\include

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
$(OBJECT_FILES):  $(SOURCE_FILES)
	"$(CC)" /Fo$(OUTPUT_DIR)\.\ $(CC_FLAGS) $(INC) $(SOURCE_FILES)

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	"$(SLINK)" $(SLINK_FLAGS) $(OBJECT_FILES) /OUT:$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


