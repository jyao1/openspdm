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
MODULE_NAME = BaseCryptLibDummy

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\UnitTest\TestSize\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\UnitTest\TestSize\$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\CryptAeadAesCcm.obj \
    $(OUTPUT_DIR)\CryptAeadAesGcm.obj \
    $(OUTPUT_DIR)\CryptAeadChaCha20Poly1305.obj \
    $(OUTPUT_DIR)\CryptSha256.obj \
    $(OUTPUT_DIR)\CryptSha512.obj \
    $(OUTPUT_DIR)\CryptHmacSha256.obj \
    $(OUTPUT_DIR)\CryptHkdf.obj \
    $(OUTPUT_DIR)\CryptCmacAes.obj \
    $(OUTPUT_DIR)\CryptGmacAes.obj \
    $(OUTPUT_DIR)\CryptPem.obj \
    $(OUTPUT_DIR)\CryptDh.obj \
    $(OUTPUT_DIR)\CryptEc.obj \
    $(OUTPUT_DIR)\CryptRsaBasic.obj \
    $(OUTPUT_DIR)\CryptRsaExt.obj \
    $(OUTPUT_DIR)\CryptX509.obj \
    $(OUTPUT_DIR)\CryptPkcs7Sign.obj \
    $(OUTPUT_DIR)\CryptPkcs7VerifyCommon.obj \
    $(OUTPUT_DIR)\CryptRand.obj \

INC =  \
    -I$(SOURCE_DIR)\
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH) \
    -I$(WORKSPACE)\OsStub\Include \

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
$(OUTPUT_DIR)\CryptAeadAesCcm.obj : $(SOURCE_DIR)\Cipher/CryptAeadAesCcm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Cipher/CryptAeadAesCcm.c

$(OUTPUT_DIR)\CryptAeadAesGcm.obj : $(SOURCE_DIR)\Cipher/CryptAeadAesGcm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Cipher/CryptAeadAesGcm.c

$(OUTPUT_DIR)\CryptAeadChaCha20Poly1305.obj : $(SOURCE_DIR)\Cipher/CryptAeadChaCha20Poly1305.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Cipher/CryptAeadChaCha20Poly1305.c

$(OUTPUT_DIR)\CryptSha256.obj : $(SOURCE_DIR)\Hash/CryptSha256.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Hash/CryptSha256.c

$(OUTPUT_DIR)\CryptSha512.obj : $(SOURCE_DIR)\Hash/CryptSha512.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Hash/CryptSha512.c

$(OUTPUT_DIR)\CryptHmacSha256.obj : $(SOURCE_DIR)\Hmac/CryptHmacSha256.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Hmac/CryptHmacSha256.c

$(OUTPUT_DIR)\CryptHkdf.obj : $(SOURCE_DIR)\Kdf/CryptHkdf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Kdf/CryptHkdf.c

$(OUTPUT_DIR)\CryptCmacAes.obj : $(SOURCE_DIR)\Mac/CryptCmacAes.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Mac/CryptCmacAes.c

$(OUTPUT_DIR)\CryptGmacAes.obj : $(SOURCE_DIR)\Mac/CryptGmacAes.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Mac/CryptGmacAes.c

$(OUTPUT_DIR)\CryptPem.obj : $(SOURCE_DIR)\Pem/CryptPem.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pem/CryptPem.c

$(OUTPUT_DIR)\CryptEc.obj : $(SOURCE_DIR)\Pk/CryptEc.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk/CryptEc.c

$(OUTPUT_DIR)\CryptDh.obj : $(SOURCE_DIR)\Pk/CryptDh.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk/CryptDh.c

$(OUTPUT_DIR)\CryptRsaBasic.obj : $(SOURCE_DIR)\Pk/CryptRsaBasic.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk/CryptRsaBasic.c

$(OUTPUT_DIR)\CryptRsaExt.obj : $(SOURCE_DIR)\Pk/CryptRsaExt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk/CryptRsaExt.c

$(OUTPUT_DIR)\CryptX509.obj : $(SOURCE_DIR)\Pk/CryptX509.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk/CryptX509.c

$(OUTPUT_DIR)\CryptPkcs7Sign.obj : $(SOURCE_DIR)\Pk/CryptPkcs7Sign.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk/CryptPkcs7Sign.c

$(OUTPUT_DIR)\CryptPkcs7VerifyCommon.obj : $(SOURCE_DIR)\Pk/CryptPkcs7VerifyCommon.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk/CryptPkcs7VerifyCommon.c

$(OUTPUT_DIR)\CryptRand.obj : $(SOURCE_DIR)\Rand/CryptRand.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Rand/CryptRand.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	$(SLINK) $(SLINK_FLAGS) $(OBJECT_FILES) $(SLINK_OBJ_FLAG)$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


