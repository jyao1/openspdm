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
MODULE_NAME = BaseCryptLibOpenssl

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)/Build
BIN_DIR = $(BUILD_DIR)/$(TARGET)_$(TOOLCHAIN)/$(ARCH)
OUTPUT_DIR = $(BIN_DIR)/OsStub/$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)/OsStub/$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)/Cipher/CryptAeadAesCcm.o \
    $(OUTPUT_DIR)/Cipher/CryptAeadAesGcm.o \
    $(OUTPUT_DIR)/Cipher/CryptAeadChaCha20Poly1305.o \
    $(OUTPUT_DIR)/Cipher/CryptAeadSm4Gcm.o \
    $(OUTPUT_DIR)/Cipher/CryptAes.o \
    $(OUTPUT_DIR)/Hash/CryptSha256.o \
    $(OUTPUT_DIR)/Hash/CryptSha512.o \
    $(OUTPUT_DIR)/Hash/CryptSha3.o \
    $(OUTPUT_DIR)/Hash/CryptSm3.o \
    $(OUTPUT_DIR)/Hmac/CryptHmacSha256.o \
    $(OUTPUT_DIR)/Kdf/CryptHkdf.o \
    $(OUTPUT_DIR)/Mac/CryptCmacAes.o \
    $(OUTPUT_DIR)/Mac/CryptGmacAes.o \
    $(OUTPUT_DIR)/Pem/CryptPem.o \
    $(OUTPUT_DIR)/Pk/CryptDh.o \
    $(OUTPUT_DIR)/Pk/CryptEc.o \
    $(OUTPUT_DIR)/Pk/CryptEd.o \
    $(OUTPUT_DIR)/Pk/CryptSm2.o \
    $(OUTPUT_DIR)/Pk/CryptPkcs1Oaep.o \
    $(OUTPUT_DIR)/Pk/CryptPkcs7Sign.o \
    $(OUTPUT_DIR)/Pk/CryptPkcs7VerifyBase.o \
    $(OUTPUT_DIR)/Pk/CryptPkcs7VerifyCommon.o \
    $(OUTPUT_DIR)/Pk/CryptPkcs7VerifyEku.o \
    $(OUTPUT_DIR)/Pk/CryptRsaBasic.o \
    $(OUTPUT_DIR)/Pk/CryptRsaExt.o \
    $(OUTPUT_DIR)/Pk/CryptX509.o \
    $(OUTPUT_DIR)/Rand/CryptRand.o \
    $(OUTPUT_DIR)/SysCall/CrtWrapperHost.o \

INC =  \
    -I$(SOURCE_DIR)\
    -I$(WORKSPACE)/Include \
    -I$(WORKSPACE)/Include/Hal \
    -I$(WORKSPACE)/Include/Hal/$(ARCH) \
    -I$(WORKSPACE)/OsStub/Include \
    -I$(WORKSPACE)/OsStub/OpensslLib/Include \
    -I$(WORKSPACE)/OsStub/OpensslLib/openssl/include \
    -I$(WORKSPACE)/OsStub/OpensslLib/openssl/crypto/include \
    -I$(WORKSPACE)/OsStub/OpensslLib/openssl

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
	-@$(MD) $(OUTPUT_DIR)/Cipher
	-@$(MD) $(OUTPUT_DIR)/Hash
	-@$(MD) $(OUTPUT_DIR)/Hmac
	-@$(MD) $(OUTPUT_DIR)/Kdf
	-@$(MD) $(OUTPUT_DIR)/Mac
	-@$(MD) $(OUTPUT_DIR)/Pem
	-@$(MD) $(OUTPUT_DIR)/Pk
	-@$(MD) $(OUTPUT_DIR)/Rand
	-@$(MD) $(OUTPUT_DIR)/SysCall

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)/Cipher/CryptAeadAesCcm.o : $(SOURCE_DIR)/Cipher/CryptAeadAesCcm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Cipher/CryptAeadAesGcm.o : $(SOURCE_DIR)/Cipher/CryptAeadAesGcm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Cipher/CryptAeadChaCha20Poly1305.o : $(SOURCE_DIR)/Cipher/CryptAeadChaCha20Poly1305.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Cipher/CryptAeadSm4Gcm.o : $(SOURCE_DIR)/Cipher/CryptAeadSm4Gcm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Cipher/CryptAes.o : $(SOURCE_DIR)/Cipher/CryptAes.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Hash/CryptSha256.o : $(SOURCE_DIR)/Hash/CryptSha256.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Hash/CryptSha512.o : $(SOURCE_DIR)/Hash/CryptSha512.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Hash/CryptSha3.o : $(SOURCE_DIR)/Hash/CryptSha3.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Hash/CryptSm3.o : $(SOURCE_DIR)/Hash/CryptSm3.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Hmac/CryptHmacSha256.o : $(SOURCE_DIR)/Hmac/CryptHmacSha256.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Kdf/CryptHkdf.o : $(SOURCE_DIR)/Kdf/CryptHkdf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Mac/CryptCmacAes.o : $(SOURCE_DIR)/Mac/CryptCmacAes.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Mac/CryptGmacAes.o : $(SOURCE_DIR)/Mac/CryptGmacAes.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pem/CryptPem.o : $(SOURCE_DIR)/Pem/CryptPem.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptEc.o : $(SOURCE_DIR)/Pk/CryptEc.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptEd.o : $(SOURCE_DIR)/Pk/CryptEd.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptDh.o : $(SOURCE_DIR)/Pk/CryptDh.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptSm2.o : $(SOURCE_DIR)/Pk/CryptSm2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptPkcs1Oaep.o : $(SOURCE_DIR)/Pk/CryptPkcs1Oaep.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptPkcs7Sign.o : $(SOURCE_DIR)/Pk/CryptPkcs7Sign.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptPkcs7VerifyBase.o : $(SOURCE_DIR)/Pk/CryptPkcs7VerifyBase.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptPkcs7VerifyCommon.o : $(SOURCE_DIR)/Pk/CryptPkcs7VerifyCommon.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptPkcs7VerifyEku.o : $(SOURCE_DIR)/Pk/CryptPkcs7VerifyEku.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptRsaBasic.o : $(SOURCE_DIR)/Pk/CryptRsaBasic.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptRsaExt.o : $(SOURCE_DIR)/Pk/CryptRsaExt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Pk/CryptX509.o : $(SOURCE_DIR)/Pk/CryptX509.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/Rand/CryptRand.o : $(SOURCE_DIR)/Rand/CryptRand.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SysCall/CrtWrapperHost.o : $(SOURCE_DIR)/SysCall/CrtWrapperHost.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


