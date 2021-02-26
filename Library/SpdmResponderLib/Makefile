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
MODULE_NAME = SpdmResponderLib

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)\Build
BIN_DIR = $(BUILD_DIR)\$(TARGET)_$(TOOLCHAIN)\$(ARCH)
OUTPUT_DIR = $(BIN_DIR)\Library\$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)\Library\$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)\SpdmResponderLibAlgorithm.obj \
    $(OUTPUT_DIR)\SpdmResponderLibCapability.obj \
    $(OUTPUT_DIR)\SpdmResponderLibCertificate.obj \
    $(OUTPUT_DIR)\SpdmResponderLibChallengeAuth.obj \
    $(OUTPUT_DIR)\SpdmResponderLibCommunication.obj \
    $(OUTPUT_DIR)\SpdmResponderLibDigest.obj \
    $(OUTPUT_DIR)\SpdmResponderLibEncapChallenge.obj \
    $(OUTPUT_DIR)\SpdmResponderLibEncapGetCertificate.obj \
    $(OUTPUT_DIR)\SpdmResponderLibEncapGetDigest.obj \
    $(OUTPUT_DIR)\SpdmResponderLibEncapKeyUpdate.obj \
    $(OUTPUT_DIR)\SpdmResponderLibEncapResponse.obj \
    $(OUTPUT_DIR)\SpdmResponderLibEndSession.obj \
    $(OUTPUT_DIR)\SpdmResponderLibError.obj \
    $(OUTPUT_DIR)\SpdmResponderLibFinish.obj \
    $(OUTPUT_DIR)\SpdmResponderLibHeartbeat.obj \
    $(OUTPUT_DIR)\SpdmResponderLibKeyExchange.obj \
    $(OUTPUT_DIR)\SpdmResponderLibKeyUpdate.obj \
    $(OUTPUT_DIR)\SpdmResponderLibMeasurement.obj \
    $(OUTPUT_DIR)\SpdmResponderLibPskExchange.obj \
    $(OUTPUT_DIR)\SpdmResponderLibPskFinish.obj \
    $(OUTPUT_DIR)\SpdmResponderLibReceiveSend.obj \
    $(OUTPUT_DIR)\SpdmResponderLibVersion.obj \
    $(OUTPUT_DIR)\SpdmResponderLibHandleResponseState.obj \
	$(OUTPUT_DIR)\SpdmResponderLibRespondIfReady.obj \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)\Library\SpdmCommonLib \
    -I$(WORKSPACE)\Include \
    -I$(WORKSPACE)\Include\Hal \
    -I$(WORKSPACE)\Include\Hal\$(ARCH)

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
$(OUTPUT_DIR)\SpdmResponderLibAlgorithm.obj : $(SOURCE_DIR)\SpdmResponderLibAlgorithm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibAlgorithm.c

$(OUTPUT_DIR)\SpdmResponderLibCapability.obj : $(SOURCE_DIR)\SpdmResponderLibCapability.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibCapability.c

$(OUTPUT_DIR)\SpdmResponderLibCertificate.obj : $(SOURCE_DIR)\SpdmResponderLibCertificate.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibCertificate.c

$(OUTPUT_DIR)\SpdmResponderLibChallengeAuth.obj : $(SOURCE_DIR)\SpdmResponderLibChallengeAuth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibChallengeAuth.c

$(OUTPUT_DIR)\SpdmResponderLibCommunication.obj : $(SOURCE_DIR)\SpdmResponderLibCommunication.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibCommunication.c

$(OUTPUT_DIR)\SpdmResponderLibDigest.obj : $(SOURCE_DIR)\SpdmResponderLibDigest.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibDigest.c

$(OUTPUT_DIR)\SpdmResponderLibEncapChallenge.obj : $(SOURCE_DIR)\SpdmResponderLibEncapChallenge.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibEncapChallenge.c

$(OUTPUT_DIR)\SpdmResponderLibEncapGetCertificate.obj : $(SOURCE_DIR)\SpdmResponderLibEncapGetCertificate.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibEncapGetCertificate.c

$(OUTPUT_DIR)\SpdmResponderLibEncapGetDigest.obj : $(SOURCE_DIR)\SpdmResponderLibEncapGetDigest.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibEncapGetDigest.c

$(OUTPUT_DIR)\SpdmResponderLibEncapKeyUpdate.obj : $(SOURCE_DIR)\SpdmResponderLibEncapKeyUpdate.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibEncapKeyUpdate.c

$(OUTPUT_DIR)\SpdmResponderLibEncapResponse.obj : $(SOURCE_DIR)\SpdmResponderLibEncapResponse.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibEncapResponse.c

$(OUTPUT_DIR)\SpdmResponderLibEndSession.obj : $(SOURCE_DIR)\SpdmResponderLibEndSession.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibEndSession.c

$(OUTPUT_DIR)\SpdmResponderLibError.obj : $(SOURCE_DIR)\SpdmResponderLibError.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibError.c

$(OUTPUT_DIR)\SpdmResponderLibFinish.obj : $(SOURCE_DIR)\SpdmResponderLibFinish.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibFinish.c

$(OUTPUT_DIR)\SpdmResponderLibHeartbeat.obj : $(SOURCE_DIR)\SpdmResponderLibHeartbeat.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibHeartbeat.c

$(OUTPUT_DIR)\SpdmResponderLibKeyExchange.obj : $(SOURCE_DIR)\SpdmResponderLibKeyExchange.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibKeyExchange.c

$(OUTPUT_DIR)\SpdmResponderLibKeyUpdate.obj : $(SOURCE_DIR)\SpdmResponderLibKeyUpdate.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibKeyUpdate.c

$(OUTPUT_DIR)\SpdmResponderLibMeasurement.obj : $(SOURCE_DIR)\SpdmResponderLibMeasurement.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibMeasurement.c

$(OUTPUT_DIR)\SpdmResponderLibPskExchange.obj : $(SOURCE_DIR)\SpdmResponderLibPskExchange.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibPskExchange.c

$(OUTPUT_DIR)\SpdmResponderLibPskFinish.obj : $(SOURCE_DIR)\SpdmResponderLibPskFinish.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibPskFinish.c

$(OUTPUT_DIR)\SpdmResponderLibReceiveSend.obj : $(SOURCE_DIR)\SpdmResponderLibReceiveSend.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibReceiveSend.c

$(OUTPUT_DIR)\SpdmResponderLibVersion.obj : $(SOURCE_DIR)\SpdmResponderLibVersion.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibVersion.c

$(OUTPUT_DIR)\SpdmResponderLibHandleResponseState.obj : $(SOURCE_DIR)\SpdmResponderLibHandleResponseState.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibHandleResponseState.c

$(OUTPUT_DIR)\SpdmResponderLibRespondIfReady.obj : $(SOURCE_DIR)\SpdmResponderLibRespondIfReady.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmResponderLibRespondIfReady.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	$(SLINK) $(SLINK_FLAGS) $(OBJECT_FILES) $(SLINK_OBJ_FLAG)$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


