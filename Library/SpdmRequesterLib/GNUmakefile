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
MODULE_NAME = SpdmRequesterLib

#
# Build Directory Macro Definition
#
BUILD_DIR = $(WORKSPACE)/Build
BIN_DIR = $(BUILD_DIR)/$(TARGET)_$(TOOLCHAIN)/$(ARCH)
OUTPUT_DIR = $(BIN_DIR)/Library/$(MODULE_NAME)

SOURCE_DIR = $(WORKSPACE)/Library/$(MODULE_NAME)

#
# Build Macro
#

OBJECT_FILES =  \
    $(OUTPUT_DIR)/SpdmRequesterLibChallenge.o \
    $(OUTPUT_DIR)/SpdmRequesterLibCommunication.o \
    $(OUTPUT_DIR)/SpdmRequesterLibEncapCertificate.o \
    $(OUTPUT_DIR)/SpdmRequesterLibEncapChallengeAuth.o \
    $(OUTPUT_DIR)/SpdmRequesterLibEncapDigest.o \
    $(OUTPUT_DIR)/SpdmRequesterLibEncapError.o \
    $(OUTPUT_DIR)/SpdmRequesterLibEncapKeyUpdate.o \
    $(OUTPUT_DIR)/SpdmRequesterLibEncapRequest.o \
    $(OUTPUT_DIR)/SpdmRequesterLibEndSession.o \
    $(OUTPUT_DIR)/SpdmRequesterLibFinish.o \
    $(OUTPUT_DIR)/SpdmRequesterLibGetCapability.o \
    $(OUTPUT_DIR)/SpdmRequesterLibGetCertificate.o \
    $(OUTPUT_DIR)/SpdmRequesterLibGetDigest.o \
    $(OUTPUT_DIR)/SpdmRequesterLibGetMeasurement.o \
    $(OUTPUT_DIR)/SpdmRequesterLibGetVersion.o \
    $(OUTPUT_DIR)/SpdmRequesterLibHandleErrorResponse.o \
    $(OUTPUT_DIR)/SpdmRequesterLibHeartbeat.o \
    $(OUTPUT_DIR)/SpdmRequesterLibKeyExchange.o \
    $(OUTPUT_DIR)/SpdmRequesterLibKeyUpdate.o \
    $(OUTPUT_DIR)/SpdmRequesterLibNegotiateAlgorithm.o \
    $(OUTPUT_DIR)/SpdmRequesterLibPskExchange.o \
    $(OUTPUT_DIR)/SpdmRequesterLibPskFinish.o \
    $(OUTPUT_DIR)/SpdmRequesterLibSendReceive.o \


INC =  \
    -I$(SOURCE_DIR) \
    -I$(WORKSPACE)/Library/SpdmCommonLib \
    -I$(WORKSPACE)/Include \
    -I$(WORKSPACE)/Include/Hal \
    -I$(WORKSPACE)/Include/Hal/$(ARCH)

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
$(OUTPUT_DIR)/SpdmRequesterLibChallenge.o : $(SOURCE_DIR)/SpdmRequesterLibChallenge.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibCommunication.o : $(SOURCE_DIR)/SpdmRequesterLibCommunication.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibEncapCertificate.o : $(SOURCE_DIR)/SpdmRequesterLibEncapCertificate.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibEncapChallengeAuth.o : $(SOURCE_DIR)/SpdmRequesterLibEncapChallengeAuth.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibEncapDigest.o : $(SOURCE_DIR)/SpdmRequesterLibEncapDigest.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibEncapError.o : $(SOURCE_DIR)/SpdmRequesterLibEncapError.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibEncapKeyUpdate.o : $(SOURCE_DIR)/SpdmRequesterLibEncapKeyUpdate.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibEncapRequest.o : $(SOURCE_DIR)/SpdmRequesterLibEncapRequest.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibEndSession.o : $(SOURCE_DIR)/SpdmRequesterLibEndSession.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibFinish.o : $(SOURCE_DIR)/SpdmRequesterLibFinish.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibGetCapability.o : $(SOURCE_DIR)/SpdmRequesterLibGetCapability.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibGetCertificate.o : $(SOURCE_DIR)/SpdmRequesterLibGetCertificate.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibGetDigest.o : $(SOURCE_DIR)/SpdmRequesterLibGetDigest.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibGetMeasurement.o : $(SOURCE_DIR)/SpdmRequesterLibGetMeasurement.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibGetVersion.o : $(SOURCE_DIR)/SpdmRequesterLibGetVersion.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibHandleErrorResponse.o : $(SOURCE_DIR)/SpdmRequesterLibHandleErrorResponse.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibHeartbeat.o : $(SOURCE_DIR)/SpdmRequesterLibHeartbeat.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibKeyExchange.o : $(SOURCE_DIR)/SpdmRequesterLibKeyExchange.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibKeyUpdate.o : $(SOURCE_DIR)/SpdmRequesterLibKeyUpdate.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibNegotiateAlgorithm.o : $(SOURCE_DIR)/SpdmRequesterLibNegotiateAlgorithm.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibPskExchange.o : $(SOURCE_DIR)/SpdmRequesterLibPskExchange.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibPskFinish.o : $(SOURCE_DIR)/SpdmRequesterLibPskFinish.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/SpdmRequesterLibSendReceive.o : $(SOURCE_DIR)/SpdmRequesterLibSendReceive.c
	$(CC) $(CC_FLAGS) -o $@ $(INC) $^

$(OUTPUT_DIR)/$(MODULE_NAME).a : $(OBJECT_FILES)
	$(RM) $(OUTPUT_DIR)/$(MODULE_NAME).a
	$(SLINK) cr $@ $(SLINK_FLAGS) $^ $(SLINK_FLAGS2)

#
# clean all intermediate files
#
clean:
	$(RD) $(OUTPUT_DIR)


