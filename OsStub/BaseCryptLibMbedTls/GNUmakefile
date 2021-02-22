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
MODULE_NAME = BaseCryptLibMbedTls

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)/Build
BIN_DIR = $(BUILD_DIR)/$(TARGET)_$(TOOLCHAIN)/$(ARCH)
OUTPUT_DIR = $(BIN_DIR)/OsStub/$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)/OsStub/$(MODULE_NAME)

CC_FLAGS += -Wno-incompatible-pointer-types -Wno-pointer-sign

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)/CryptAeadAesCcm.o \
    $(OUTPUT_DIR)/CryptAeadAesGcm.o \
    $(OUTPUT_DIR)/CryptAeadChaCha20Poly1305.o \
    $(OUTPUT_DIR)/CryptAeadSm4Gcm.o \
    $(OUTPUT_DIR)/CryptSha256.o \
    $(OUTPUT_DIR)/CryptSha512.o \
    $(OUTPUT_DIR)/CryptSha3.o \
    $(OUTPUT_DIR)/CryptSm3.o \
    $(OUTPUT_DIR)/CryptHmacSha256.o \
    $(OUTPUT_DIR)/CryptHkdf.o \
    $(OUTPUT_DIR)/CryptCmacAes.o \
    $(OUTPUT_DIR)/CryptGmacAes.o \
    $(OUTPUT_DIR)/CryptPem.o \
    $(OUTPUT_DIR)/CryptDh.o \
    $(OUTPUT_DIR)/CryptEc.o \
    $(OUTPUT_DIR)/CryptEd.o \
    $(OUTPUT_DIR)/CryptSm2.o \
    $(OUTPUT_DIR)/CryptRsaBasic.o \
    $(OUTPUT_DIR)/CryptRsaExt.o \
    $(OUTPUT_DIR)/CryptX509.o \
    $(OUTPUT_DIR)/CryptPkcs7Sign.o \
    $(OUTPUT_DIR)/CryptPkcs7VerifyCommon.o \
    $(OUTPUT_DIR)/CryptRand.o \
    $(OUTPUT_DIR)/BaseMemAllocation.o \
    $(OUTPUT_DIR)/CrtWrapperHost.o \
    $(OUTPUT_DIR)/TimerWrapperHost.o \

INC =  \
    -I$(SOURCE_DIR)\
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
$(OUTPUT_DIR)/CryptAeadAesCcm.o : $(SOURCE_DIR)/Cipher/CryptAeadAesCcm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptAeadAesGcm.o : $(SOURCE_DIR)/Cipher/CryptAeadAesGcm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptAeadChaCha20Poly1305.o : $(SOURCE_DIR)/Cipher/CryptAeadChaCha20Poly1305.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptAeadSm4Gcm.o : $(SOURCE_DIR)/Cipher/CryptAeadSm4Gcm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptSha256.o : $(SOURCE_DIR)/Hash/CryptSha256.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptSha512.o : $(SOURCE_DIR)/Hash/CryptSha512.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptSha3.o : $(SOURCE_DIR)/Hash/CryptSha3.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptSm3.o : $(SOURCE_DIR)/Hash/CryptSm3.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptHmacSha256.o : $(SOURCE_DIR)/Hmac/CryptHmacSha256.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptHkdf.o : $(SOURCE_DIR)/Kdf/CryptHkdf.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptCmacAes.o : $(SOURCE_DIR)/Mac/CryptCmacAes.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptGmacAes.o : $(SOURCE_DIR)/Mac/CryptGmacAes.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptPem.o : $(SOURCE_DIR)/Pem/CryptPem.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptEc.o : $(SOURCE_DIR)/Pk/CryptEc.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptEd.o : $(SOURCE_DIR)/Pk/CryptEd.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptDh.o : $(SOURCE_DIR)/Pk/CryptDh.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptSm2.o : $(SOURCE_DIR)/Pk/CryptSm2.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptRsaBasic.o : $(SOURCE_DIR)/Pk/CryptRsaBasic.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptRsaExt.o : $(SOURCE_DIR)/Pk/CryptRsaExt.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptX509.o : $(SOURCE_DIR)/Pk/CryptX509.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptPkcs7Sign.o : $(SOURCE_DIR)/Pk/CryptPkcs7Sign.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptPkcs7VerifyCommon.o : $(SOURCE_DIR)/Pk/CryptPkcs7VerifyCommon.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CryptRand.o : $(SOURCE_DIR)/Rand/CryptRand.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/BaseMemAllocation.o : $(SOURCE_DIR)/SysCall/BaseMemAllocation.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/CrtWrapperHost.o : $(SOURCE_DIR)/SysCall/CrtWrapperHost.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/TimerWrapperHost.o : $(SOURCE_DIR)/SysCall/TimerWrapperHost.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


