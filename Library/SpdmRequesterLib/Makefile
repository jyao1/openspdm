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
MODULE_NAME = SpdmRequesterLib

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
    $(OUTPUT_DIR)\SpdmRequesterLibChallenge.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibCommunication.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibEncapCertificate.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibEncapChallengeAuth.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibEncapDigest.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibEncapError.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibEncapKeyUpdate.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibEncapRequest.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibEndSession.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibFinish.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibGetCapability.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibGetCertificate.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibGetDigest.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibGetMeasurement.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibGetVersion.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibHandleErrorResponse.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibHeartbeat.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibKeyExchange.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibKeyUpdate.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibNegotiateAlgorithm.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibPskExchange.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibPskFinish.obj \
    $(OUTPUT_DIR)\SpdmRequesterLibSendReceive.obj \


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
$(OUTPUT_DIR)\SpdmRequesterLibChallenge.obj : $(SOURCE_DIR)\SpdmRequesterLibChallenge.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibChallenge.c

$(OUTPUT_DIR)\SpdmRequesterLibCommunication.obj : $(SOURCE_DIR)\SpdmRequesterLibCommunication.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibCommunication.c

$(OUTPUT_DIR)\SpdmRequesterLibEncapCertificate.obj : $(SOURCE_DIR)\SpdmRequesterLibEncapCertificate.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibEncapCertificate.c

$(OUTPUT_DIR)\SpdmRequesterLibEncapChallengeAuth.obj : $(SOURCE_DIR)\SpdmRequesterLibEncapChallengeAuth.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibEncapChallengeAuth.c

$(OUTPUT_DIR)\SpdmRequesterLibEncapDigest.obj : $(SOURCE_DIR)\SpdmRequesterLibEncapDigest.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibEncapDigest.c

$(OUTPUT_DIR)\SpdmRequesterLibEncapError.obj : $(SOURCE_DIR)\SpdmRequesterLibEncapError.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibEncapError.c

$(OUTPUT_DIR)\SpdmRequesterLibEncapKeyUpdate.obj : $(SOURCE_DIR)\SpdmRequesterLibEncapKeyUpdate.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibEncapKeyUpdate.c

$(OUTPUT_DIR)\SpdmRequesterLibEncapRequest.obj : $(SOURCE_DIR)\SpdmRequesterLibEncapRequest.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibEncapRequest.c

$(OUTPUT_DIR)\SpdmRequesterLibEndSession.obj : $(SOURCE_DIR)\SpdmRequesterLibEndSession.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibEndSession.c

$(OUTPUT_DIR)\SpdmRequesterLibFinish.obj : $(SOURCE_DIR)\SpdmRequesterLibFinish.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibFinish.c

$(OUTPUT_DIR)\SpdmRequesterLibGetCapability.obj : $(SOURCE_DIR)\SpdmRequesterLibGetCapability.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibGetCapability.c

$(OUTPUT_DIR)\SpdmRequesterLibGetCertificate.obj : $(SOURCE_DIR)\SpdmRequesterLibGetCertificate.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibGetCertificate.c

$(OUTPUT_DIR)\SpdmRequesterLibGetDigest.obj : $(SOURCE_DIR)\SpdmRequesterLibGetDigest.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibGetDigest.c

$(OUTPUT_DIR)\SpdmRequesterLibGetMeasurement.obj : $(SOURCE_DIR)\SpdmRequesterLibGetMeasurement.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibGetMeasurement.c

$(OUTPUT_DIR)\SpdmRequesterLibGetVersion.obj : $(SOURCE_DIR)\SpdmRequesterLibGetVersion.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibGetVersion.c

$(OUTPUT_DIR)\SpdmRequesterLibHandleErrorResponse.obj : $(SOURCE_DIR)\SpdmRequesterLibHandleErrorResponse.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibHandleErrorResponse.c

$(OUTPUT_DIR)\SpdmRequesterLibHeartbeat.obj : $(SOURCE_DIR)\SpdmRequesterLibHeartbeat.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibHeartbeat.c

$(OUTPUT_DIR)\SpdmRequesterLibKeyExchange.obj : $(SOURCE_DIR)\SpdmRequesterLibKeyExchange.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibKeyExchange.c

$(OUTPUT_DIR)\SpdmRequesterLibKeyUpdate.obj : $(SOURCE_DIR)\SpdmRequesterLibKeyUpdate.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibKeyUpdate.c

$(OUTPUT_DIR)\SpdmRequesterLibNegotiateAlgorithm.obj : $(SOURCE_DIR)\SpdmRequesterLibNegotiateAlgorithm.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibNegotiateAlgorithm.c

$(OUTPUT_DIR)\SpdmRequesterLibPskExchange.obj : $(SOURCE_DIR)\SpdmRequesterLibPskExchange.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibPskExchange.c

$(OUTPUT_DIR)\SpdmRequesterLibPskFinish.obj : $(SOURCE_DIR)\SpdmRequesterLibPskFinish.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibPskFinish.c

$(OUTPUT_DIR)\SpdmRequesterLibSendReceive.obj : $(SOURCE_DIR)\SpdmRequesterLibSendReceive.c
	$(CC) $(CC_FLAGS) $(CC_OBJ_FLAG)$@ $(INC) $(SOURCE_DIR)\SpdmRequesterLibSendReceive.c

$(OUTPUT_DIR)\$(MODULE_NAME).lib : $(OBJECT_FILES)
	$(SLINK) $(SLINK_FLAGS) $(OBJECT_FILES) $(SLINK_OBJ_FLAG)$@

#
# clean all intermediate files
#
clean:
	-@if exist $(OUTPUT_DIR) $(RD) $(OUTPUT_DIR)
	$(RM) *.pdb *.idb > NUL 2>&1


