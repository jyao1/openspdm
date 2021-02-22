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
MODULE_NAME = BaseCryptLibOpenssl

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\OsStub\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\OsStub\$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\Cipher\CryptAeadAesCcm.obj \
    $(OUTPUT_DIR)\Cipher\CryptAeadAesGcm.obj \
    $(OUTPUT_DIR)\Cipher\CryptAeadChaCha20Poly1305.obj \
    $(OUTPUT_DIR)\Cipher\CryptAeadSm4Gcm.obj \
    $(OUTPUT_DIR)\Cipher\CryptAes.obj \
    $(OUTPUT_DIR)\Hash\CryptSha256.obj \
    $(OUTPUT_DIR)\Hash\CryptSha512.obj \
    $(OUTPUT_DIR)\Hash\CryptSha3.obj \
    $(OUTPUT_DIR)\Hash\CryptSm3.obj \
    $(OUTPUT_DIR)\Hmac\CryptHmacSha256.obj \
    $(OUTPUT_DIR)\Kdf\CryptHkdf.obj \
    $(OUTPUT_DIR)\Mac\CryptCmacAes.obj \
    $(OUTPUT_DIR)\Mac\CryptGmacAes.obj \
    $(OUTPUT_DIR)\Pem\CryptPem.obj \
    $(OUTPUT_DIR)\Pk\CryptDh.obj \
    $(OUTPUT_DIR)\Pk\CryptEc.obj \
    $(OUTPUT_DIR)\Pk\CryptEd.obj \
    $(OUTPUT_DIR)\Pk\CryptSm2.obj \
    $(OUTPUT_DIR)\Pk\CryptPkcs1Oaep.obj \
    $(OUTPUT_DIR)\Pk\CryptPkcs7Sign.obj \
    $(OUTPUT_DIR)\Pk\CryptPkcs7VerifyBase.obj \
    $(OUTPUT_DIR)\Pk\CryptPkcs7VerifyCommon.obj \
    $(OUTPUT_DIR)\Pk\CryptPkcs7VerifyEku.obj \
    $(OUTPUT_DIR)\Pk\CryptRsaBasic.obj \
    $(OUTPUT_DIR)\Pk\CryptRsaExt.obj \
    $(OUTPUT_DIR)\Pk\CryptX509.obj \
    $(OUTPUT_DIR)\Rand\CryptRand.obj \
    $(OUTPUT_DIR)\SysCall\CrtWrapperHost.obj \

INC =  \
    -I$(SOURCE_DIR)\
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH) \
    -I$(WORKSPACE)\OsStub\Include \
    -I$(WORKSPACE)\OsStub\OpensslLib\Include \
    -I$(WORKSPACE)\OsStub\OpensslLib\openssl\include \
    -I$(WORKSPACE)\OsStub\OpensslLib\openssl\crypto\include \
    -I$(WORKSPACE)\OsStub\OpensslLib\openssl

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
	-@if not exist $(OUTPUT_DIR)\Cipher $(MD) $(OUTPUT_DIR)\Cipher
	-@if not exist $(OUTPUT_DIR)\Hash $(MD) $(OUTPUT_DIR)\Hash
	-@if not exist $(OUTPUT_DIR)\Hmac $(MD) $(OUTPUT_DIR)\Hmac
	-@if not exist $(OUTPUT_DIR)\Kdf $(MD) $(OUTPUT_DIR)\Kdf
	-@if not exist $(OUTPUT_DIR)\Mac $(MD) $(OUTPUT_DIR)\Mac
	-@if not exist $(OUTPUT_DIR)\Pem $(MD) $(OUTPUT_DIR)\Pem
	-@if not exist $(OUTPUT_DIR)\Pk $(MD) $(OUTPUT_DIR)\Pk
	-@if not exist $(OUTPUT_DIR)\Rand $(MD) $(OUTPUT_DIR)\Rand
	-@if not exist $(OUTPUT_DIR)\SysCall $(MD) $(OUTPUT_DIR)\SysCall

#
# Individual Object Build Targets
#
$(OUTPUT_DIR)\Cipher\CryptAeadAesCcm.obj : $(SOURCE_DIR)\Cipher\CryptAeadAesCcm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Cipher\CryptAeadAesCcm.c

$(OUTPUT_DIR)\Cipher\CryptAeadAesGcm.obj : $(SOURCE_DIR)\Cipher\CryptAeadAesGcm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Cipher\CryptAeadAesGcm.c

$(OUTPUT_DIR)\Cipher\CryptAeadChaCha20Poly1305.obj : $(SOURCE_DIR)\Cipher\CryptAeadChaCha20Poly1305.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Cipher\CryptAeadChaCha20Poly1305.c

$(OUTPUT_DIR)\Cipher\CryptAeadSm4Gcm.obj : $(SOURCE_DIR)\Cipher\CryptAeadSm4Gcm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Cipher\CryptAeadSm4Gcm.c

$(OUTPUT_DIR)\Cipher\CryptAes.obj : $(SOURCE_DIR)\Cipher\CryptAes.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Cipher\CryptAes.c

$(OUTPUT_DIR)\Hash\CryptSha256.obj : $(SOURCE_DIR)\Hash\CryptSha256.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Hash\CryptSha256.c

$(OUTPUT_DIR)\Hash\CryptSha512.obj : $(SOURCE_DIR)\Hash\CryptSha512.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Hash\CryptSha512.c

$(OUTPUT_DIR)\Hash\CryptSha3.obj : $(SOURCE_DIR)\Hash\CryptSha3.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Hash\CryptSha3.c

$(OUTPUT_DIR)\Hash\CryptSm3.obj : $(SOURCE_DIR)\Hash\CryptSm3.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Hash\CryptSm3.c

$(OUTPUT_DIR)\Hmac\CryptHmacSha256.obj : $(SOURCE_DIR)\Hmac\CryptHmacSha256.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Hmac\CryptHmacSha256.c

$(OUTPUT_DIR)\Kdf\CryptHkdf.obj : $(SOURCE_DIR)\Kdf\CryptHkdf.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Kdf\CryptHkdf.c

$(OUTPUT_DIR)\Mac\CryptCmacAes.obj : $(SOURCE_DIR)\Mac\CryptCmacAes.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Mac\CryptCmacAes.c

$(OUTPUT_DIR)\Mac\CryptGmacAes.obj : $(SOURCE_DIR)\Mac\CryptGmacAes.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Mac\CryptGmacAes.c

$(OUTPUT_DIR)\Pem\CryptPem.obj : $(SOURCE_DIR)\Pem\CryptPem.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pem\CryptPem.c

$(OUTPUT_DIR)\Pk\CryptEc.obj : $(SOURCE_DIR)\Pk\CryptEc.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptEc.c

$(OUTPUT_DIR)\Pk\CryptEd.obj : $(SOURCE_DIR)\Pk\CryptEd.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptEd.c

$(OUTPUT_DIR)\Pk\CryptDh.obj : $(SOURCE_DIR)\Pk\CryptDh.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptDh.c

$(OUTPUT_DIR)\Pk\CryptSm2.obj : $(SOURCE_DIR)\Pk\CryptSm2.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptSm2.c

$(OUTPUT_DIR)\Pk\CryptPkcs1Oaep.obj : $(SOURCE_DIR)\Pk\CryptPkcs1Oaep.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptPkcs1Oaep.c

$(OUTPUT_DIR)\Pk\CryptPkcs7Sign.obj : $(SOURCE_DIR)\Pk\CryptPkcs7Sign.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptPkcs7Sign.c

$(OUTPUT_DIR)\Pk\CryptPkcs7VerifyBase.obj : $(SOURCE_DIR)\Pk\CryptPkcs7VerifyBase.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptPkcs7VerifyBase.c

$(OUTPUT_DIR)\Pk\CryptPkcs7VerifyCommon.obj : $(SOURCE_DIR)\Pk\CryptPkcs7VerifyCommon.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptPkcs7VerifyCommon.c

$(OUTPUT_DIR)\Pk\CryptPkcs7VerifyEku.obj : $(SOURCE_DIR)\Pk\CryptPkcs7VerifyEku.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptPkcs7VerifyEku.c

$(OUTPUT_DIR)\Pk\CryptRsaBasic.obj : $(SOURCE_DIR)\Pk\CryptRsaBasic.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptRsaBasic.c

$(OUTPUT_DIR)\Pk\CryptRsaExt.obj : $(SOURCE_DIR)\Pk\CryptRsaExt.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptRsaExt.c

$(OUTPUT_DIR)\Pk\CryptX509.obj : $(SOURCE_DIR)\Pk\CryptX509.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Pk\CryptX509.c

$(OUTPUT_DIR)\Rand\CryptRand.obj : $(SOURCE_DIR)\Rand\CryptRand.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\Rand\CryptRand.c

$(OUTPUT_DIR)\SysCall\CrtWrapperHost.obj : $(SOURCE_DIR)\SysCall\CrtWrapperHost.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SysCall\CrtWrapperHost.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	$(SLINK) $(SLINK_FLAGS) $(OBJECT_FILES) $(SLINK_OBJ_FLAG)$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


