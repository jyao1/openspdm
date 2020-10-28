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

include $(WORKSPACE)/GNUmakefile.Flags

#
# Module Macro Definition
#
MODULE_NAME = MbedTlsLib

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)/Build
BIN_DIR = $(BUILD_DIR)/$(TARGET)_$(TOOLCHAIN)/$(ARCH)
OUTPUT_DIR = $(BIN_DIR)/OsStub/$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)/OsStub/$(MODULE_NAME)

CC_FLAGS += $(MBEDTLS_FLAGS) -DNO_MSABI_VA_FUNCS

ifeq ("$(ARCH)","X64")
    CC_FLAGS += -DEFIX64
else ifeq ("$(ARCH)","Ia32")
    CC_FLAGS += -DEFI32
else ifeq ("$(ARCH)","ARM")
    CC_FLAGS += 
endif

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)/aes.o \
    $(OUTPUT_DIR)/aesni.o \
    $(OUTPUT_DIR)/arc4.o \
    $(OUTPUT_DIR)/aria.o \
    $(OUTPUT_DIR)/asn1parse.o \
    $(OUTPUT_DIR)/asn1write.o \
    $(OUTPUT_DIR)/base64.o \
    $(OUTPUT_DIR)/bignum.o \
    $(OUTPUT_DIR)/blowfish.o \
    $(OUTPUT_DIR)/camellia.o \
    $(OUTPUT_DIR)/ccm.o \
    $(OUTPUT_DIR)/certs.o \
    $(OUTPUT_DIR)/chacha20.o \
    $(OUTPUT_DIR)/chachapoly.o \
    $(OUTPUT_DIR)/cipher.o \
    $(OUTPUT_DIR)/cipher_wrap.o \
    $(OUTPUT_DIR)/cmac.o \
    $(OUTPUT_DIR)/ctr_drbg.o \
    $(OUTPUT_DIR)/debug.o \
    $(OUTPUT_DIR)/des.o \
    $(OUTPUT_DIR)/dhm.o \
    $(OUTPUT_DIR)/ecdh.o \
    $(OUTPUT_DIR)/ecdsa.o \
    $(OUTPUT_DIR)/ecjpake.o \
    $(OUTPUT_DIR)/ecp.o \
    $(OUTPUT_DIR)/ecp_curves.o \
    $(OUTPUT_DIR)/entropy.o \
    $(OUTPUT_DIR)/error.o \
    $(OUTPUT_DIR)/gcm.o \
    $(OUTPUT_DIR)/havege.o \
    $(OUTPUT_DIR)/hkdf.o \
    $(OUTPUT_DIR)/hmac_drbg.o \
    $(OUTPUT_DIR)/md.o \
    $(OUTPUT_DIR)/md2.o \
    $(OUTPUT_DIR)/md4.o \
    $(OUTPUT_DIR)/md5.o \
    $(OUTPUT_DIR)/md_wrap.o \
    $(OUTPUT_DIR)/memory_buffer_alloc.o \
    $(OUTPUT_DIR)/nist_kw.o \
    $(OUTPUT_DIR)/oid.o \
    $(OUTPUT_DIR)/padlock.o \
    $(OUTPUT_DIR)/pem.o \
    $(OUTPUT_DIR)/pk.o \
    $(OUTPUT_DIR)/pkcs11.o \
    $(OUTPUT_DIR)/pkcs12.o \
    $(OUTPUT_DIR)/pkcs5.o \
    $(OUTPUT_DIR)/pkparse.o \
    $(OUTPUT_DIR)/pkwrite.o \
    $(OUTPUT_DIR)/pk_wrap.o \
    $(OUTPUT_DIR)/poly1305.o \
    $(OUTPUT_DIR)/ripemd160.o \
    $(OUTPUT_DIR)/rsa.o \
    $(OUTPUT_DIR)/rsa_internal.o \
    $(OUTPUT_DIR)/sha1.o \
    $(OUTPUT_DIR)/sha256.o \
    $(OUTPUT_DIR)/sha512.o \
    $(OUTPUT_DIR)/ssl_cache.o \
    $(OUTPUT_DIR)/ssl_ciphersuites.o \
    $(OUTPUT_DIR)/ssl_cli.o \
    $(OUTPUT_DIR)/ssl_cookie.o \
    $(OUTPUT_DIR)/ssl_srv.o \
    $(OUTPUT_DIR)/ssl_ticket.o \
    $(OUTPUT_DIR)/ssl_tls.o \
    $(OUTPUT_DIR)/threading.o \
    $(OUTPUT_DIR)/version.o \
    $(OUTPUT_DIR)/version_features.o \
    $(OUTPUT_DIR)/x509.o \
    $(OUTPUT_DIR)/x509write_crt.o \
    $(OUTPUT_DIR)/x509write_csr.o \
    $(OUTPUT_DIR)/x509_create.o \
    $(OUTPUT_DIR)/x509_crl.o \
    $(OUTPUT_DIR)/x509_crt.o \
    $(OUTPUT_DIR)/x509_csr.o \
    $(OUTPUT_DIR)/xtea.o \

INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)/Include \
    -I$(WORKSPACE)/Include/Hal \
    -I$(WORKSPACE)/Include/Hal/$(ARCH) \
    -I$(WORKSPACE)/OsStub/Include \
    -I$(WORKSPACE)/OsStub/MbedTlsLib/Include \
    -I$(WORKSPACE)/OsStub/MbedTlsLib/Include/mbedtls \
    -I$(WORKSPACE)/OsStub/MbedTlsLib/mbedtls/include \
    -I$(WORKSPACE)/OsStub/MbedTlsLib/mbedtls/include/mbedtls \

#
# Overridable Target Macro Definitions
#
INIT_TARGET = init
CODA_TARGET = $(OUTPUT_DIR)/$(MODULE_NAME).a

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
	-@$(MD) $(OUTPUT_DIR)
#
# Individual Object Build Targets
#
$(OUTPUT_DIR)/aes.o : $(SOURCE_DIR)/mbedtls/library/aes.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/aesni.o : $(SOURCE_DIR)/mbedtls/library/aesni.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/arc4.o : $(SOURCE_DIR)/mbedtls/library/arc4.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/aria.o : $(SOURCE_DIR)/mbedtls/library/aria.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/asn1parse.o : $(SOURCE_DIR)/mbedtls/library/asn1parse.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/asn1write.o : $(SOURCE_DIR)/mbedtls/library/asn1write.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/base64.o : $(SOURCE_DIR)/mbedtls/library/base64.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/bignum.o : $(SOURCE_DIR)/mbedtls/library/bignum.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/blowfish.o : $(SOURCE_DIR)/mbedtls/library/blowfish.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/camellia.o : $(SOURCE_DIR)/mbedtls/library/camellia.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ccm.o : $(SOURCE_DIR)/mbedtls/library/ccm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/certs.o : $(SOURCE_DIR)/mbedtls/library/certs.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/chacha20.o : $(SOURCE_DIR)/mbedtls/library/chacha20.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/chachapoly.o : $(SOURCE_DIR)/mbedtls/library/chachapoly.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/cipher.o : $(SOURCE_DIR)/mbedtls/library/cipher.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/cipher_wrap.o : $(SOURCE_DIR)/mbedtls/library/cipher_wrap.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/cmac.o : $(SOURCE_DIR)/mbedtls/library/cmac.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ctr_drbg.o : $(SOURCE_DIR)/mbedtls/library/ctr_drbg.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/debug.o : $(SOURCE_DIR)/mbedtls/library/debug.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/des.o : $(SOURCE_DIR)/mbedtls/library/des.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/dhm.o : $(SOURCE_DIR)/mbedtls/library/dhm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ecdh.o : $(SOURCE_DIR)/mbedtls/library/ecdh.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ecdsa.o : $(SOURCE_DIR)/mbedtls/library/ecdsa.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ecjpake.o : $(SOURCE_DIR)/mbedtls/library/ecjpake.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ecp.o : $(SOURCE_DIR)/mbedtls/library/ecp.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ecp_curves.o : $(SOURCE_DIR)/mbedtls/library/ecp_curves.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/entropy.o : $(SOURCE_DIR)/mbedtls/library/entropy.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/error.o : $(SOURCE_DIR)/mbedtls/library/error.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/gcm.o : $(SOURCE_DIR)/mbedtls/library/gcm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/havege.o : $(SOURCE_DIR)/mbedtls/library/havege.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/hkdf.o : $(SOURCE_DIR)/mbedtls/library/hkdf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/hmac_drbg.o : $(SOURCE_DIR)/mbedtls/library/hmac_drbg.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/md.o : $(SOURCE_DIR)/mbedtls/library/md.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/md2.o : $(SOURCE_DIR)/mbedtls/library/md2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/md4.o : $(SOURCE_DIR)/mbedtls/library/md4.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/md5.o : $(SOURCE_DIR)/mbedtls/library/md5.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/md_wrap.o : $(SOURCE_DIR)/mbedtls/library/md_wrap.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/memory_buffer_alloc.o : $(SOURCE_DIR)/mbedtls/library/memory_buffer_alloc.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/nist_kw.o : $(SOURCE_DIR)/mbedtls/library/nist_kw.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/oid.o : $(SOURCE_DIR)/mbedtls/library/oid.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/padlock.o : $(SOURCE_DIR)/mbedtls/library/padlock.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/pem.o : $(SOURCE_DIR)/mbedtls/library/pem.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/pk.o : $(SOURCE_DIR)/mbedtls/library/pk.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/pkcs11.o : $(SOURCE_DIR)/mbedtls/library/pkcs11.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/pkcs12.o : $(SOURCE_DIR)/mbedtls/library/pkcs12.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/pkcs5.o : $(SOURCE_DIR)/mbedtls/library/pkcs5.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/pkparse.o : $(SOURCE_DIR)/mbedtls/library/pkparse.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/pkwrite.o : $(SOURCE_DIR)/mbedtls/library/pkwrite.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/pk_wrap.o : $(SOURCE_DIR)/mbedtls/library/pk_wrap.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/poly1305.o : $(SOURCE_DIR)/mbedtls/library/poly1305.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ripemd160.o : $(SOURCE_DIR)/mbedtls/library/ripemd160.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/rsa.o : $(SOURCE_DIR)/mbedtls/library/rsa.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/rsa_internal.o : $(SOURCE_DIR)/mbedtls/library/rsa_internal.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/sha1.o : $(SOURCE_DIR)/mbedtls/library/sha1.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/sha256.o : $(SOURCE_DIR)/mbedtls/library/sha256.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/sha512.o : $(SOURCE_DIR)/mbedtls/library/sha512.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ssl_cache.o : $(SOURCE_DIR)/mbedtls/library/ssl_cache.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ssl_ciphersuites.o : $(SOURCE_DIR)/mbedtls/library/ssl_ciphersuites.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ssl_cli.o : $(SOURCE_DIR)/mbedtls/library/ssl_cli.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ssl_cookie.o : $(SOURCE_DIR)/mbedtls/library/ssl_cookie.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ssl_srv.o : $(SOURCE_DIR)/mbedtls/library/ssl_srv.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ssl_ticket.o : $(SOURCE_DIR)/mbedtls/library/ssl_ticket.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/ssl_tls.o : $(SOURCE_DIR)/mbedtls/library/ssl_tls.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/threading.o : $(SOURCE_DIR)/mbedtls/library/threading.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/version.o : $(SOURCE_DIR)/mbedtls/library/version.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/version_features.o : $(SOURCE_DIR)/mbedtls/library/version_features.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/x509.o : $(SOURCE_DIR)/mbedtls/library/x509.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/x509write_crt.o : $(SOURCE_DIR)/mbedtls/library/x509write_crt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/x509write_csr.o : $(SOURCE_DIR)/mbedtls/library/x509write_csr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/x509_create.o : $(SOURCE_DIR)/mbedtls/library/x509_create.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/x509_crl.o : $(SOURCE_DIR)/mbedtls/library/x509_crl.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/x509_crt.o : $(SOURCE_DIR)/mbedtls/library/x509_crt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/x509_csr.o : $(SOURCE_DIR)/mbedtls/library/x509_csr.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/xtea.o : $(SOURCE_DIR)/mbedtls/library/xtea.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


